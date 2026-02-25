<?php if (!defined('VB_ENTRY')) die('Access denied.');
/*========================================================================*\
|| ###################################################################### ||
|| # vBulletin 5.6.0
|| # ------------------------------------------------------------------ # ||
|| # Copyright 2000-2020 MH Sub I, LLC dba vBulletin. All Rights Reserved.  # ||
|| # This file may not be redistributed in whole or significant part.   # ||
|| # ----------------- VBULLETIN IS NOT FREE SOFTWARE ----------------- # ||
|| # http://www.vbulletin.com | http://www.vbulletin.com/license.html   # ||
|| ###################################################################### ||
\*========================================================================*/

class GoogleLogin_Library_ExternalLogin extends vB_Library_ExternalLogin
{
	protected $productid = "googlelogin";

	protected $enabled;
	protected $register_enabled;
	protected $client_id = "";
	protected $client_secret = "";
	protected $googleClient = null;
	protected $googleOAuthService = null;
	protected $startup_errors = array();

	protected $do_log = true; // On during debug

	public function __construct()
	{
		parent::__construct();

		$options = vB::getDatastore()->getValue('options');
		$this->enabled = !empty($options['googlelogin_enabled']);
		$this->register_enabled = !empty($options['googlelogin_register_enabled']);
		$this->client_id = (!empty($options['googlelogin_client_id']) ? $options['googlelogin_client_id'] : "");
		$this->client_secret =  (!empty($options['googlelogin_client_secret']) ? $options['googlelogin_client_secret'] : "");

		if (!empty($this->client_id) AND !empty($this->client_secret))
		{
			require_once(__DIR__ . "/../vendor/autoload.php");

			try
			{
				$this->googleClient = new Google_Client(['client_id' => $this->client_id]);
				/*
					So far, it seems like we don't need the secret to verify id_tokens & pull
					id's (sub) from the id_token.

					If we need them, we can set it via:
						$this->googleClient->setClientId($this->client_id);
						$this->googleClient->setClientSecret($this->client_secret);

					or via downloading the client_secrets.json file from the API Console as
					described in
						https://developers.google.com/api-client-library/php/auth/web-app#creatingcred
					&
						https://developers.google.com/api-client-library/php/auth/web-app#creatingclient
					.

				 */
			}
			catch (Exception $e)
			{
				$this->googleClient = null;
				$this->enabled = false;
				$this->startup_errors[] = $e;
				$this->log("exception: " . print_r($e, true));
			}
		}
	}

	private function log($error)
	{
		if ($this->do_log)
		{
			$trace = debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS);
			$caller = array_shift($trace);

			error_log(
				"FILE:" . $caller['file'] . " "
					. (!empty($caller['class'])?$caller['class'] . "::" : "")
					. $caller['function'] . "() @ LINE " . $caller['line']
				. "\n" .
				$error

			);

		}
	}

	private function verifyUserIdToken($id_token)
	{
		if (!is_null($this->googleClient))
		{
			/*
				This try catch is here to catch any google client from leaking out.
				E.g. "SSL certificate problem: unable to get local issuer certificate" cURL error
			 */
			try
			{
				$check = $this->googleClient->verifyIdToken($id_token);
			}
			catch (Exception $e)
			{
				$this->log("exception: " . print_r($e, true));
			}

			if ($check)
			{
				return $check;
			}
			else
			{
				return false;
			}
		}

		return false;
	}

	public function getStaticUserIdFromIDToken($id_token)
	{
		/*
			The id_token expires/refreshes and is not reliable as a
			permanent/static ID parameter that we can store.
		 */

		/*
			Some possible solution references
			https://stackoverflow.com/questions/8311836/how-to-identify-a-google-oauth2-user
			https://stackoverflow.com/questions/28521239/how-to-get-user-information-with-google-api-php-sdk

			We'll wanna go with a solution that requires minimal/no changes to the vendor dependencies
		 */

		if (empty($id_token))
		{
			// Google client will use the *current* id_token if one isn't provided.
			// Just return empty so we can't be tricked somehow.
			return "";
		}

		$check = null;
		try
		{
			$check = $this->googleClient->verifyIdToken($id_token);
		}
		catch (Exception $e)
		{
			$this->log("exception: " . print_r($e, true));
		}

		if ($check)
		{
			/*
				Google's JS handles the oauth2 (e.g.
					https://accounts.google.com/o/oauth2/iframerpc?action=issueToken&response_type=token%20id_token
				) and makes the id_token available on frontend. OUR JS then sends this id_token to us, and we MUST
				verify it before we can trust it, because really anyone could've passed over an id_token to us,
				not just google and our JS. However, not everyone can *sign* the id_token using google's keys,
				which is why we can trust it after verification:
				https://developers.google.com/api-client-library/php/guide/aaa_idtoken

				Once it's been decoded & verified by google client (which handles pulling google's public key and
				doing all of the signature checks for us, and does NOT require another oauth2 call to google server
				for this), we have a number of fields available in the payload.

				https://developers.google.com/identity/sign-in/web/backend-auth
				Of these fields, apparently "sub" is the userid.
			 */

			return $check['sub'];
		}

		return "";
	}

	public function getLinkedVBUseridFromIdToken($id_token, $access_token = "")
	{
		$result = array(
			'success' => false,
		);

		// We need additional information to potentially save them for future registration,
		// so pull the full payload & extract the ID.
		//$external_userid = $this->getStaticUserIdFromIDToken($id_token);
		$payload = $this->verifyUserIdToken($id_token);
		if (!empty($payload['sub']))
		{
			$external_userid = $payload['sub'];
			$userAuth = $this->getUserAuthRecord($external_userid);
		}
		else
		{
			$external_userid = "";
		}

		if (!empty($userAuth['userid']))
		{
			$result = array(
				'success' => true,
				'userid' => $userAuth['userid'],
			);
		}
		else
		{
			$result = array(
				'sucess' => false,
				'error' => 'googlelogin_no_oauth_user_found',
				'external_userid' => $external_userid,
			);

			// Store this for a registration attempt later.
			if (!empty($external_userid) AND $this->register_enabled)
			{
				// Try to get the profile URL if we have an access_token .
				if (!empty($access_token))
				{
					$this->googleClient->setAccessToken($access_token);
					// This access token is from the frontend and it already has the default "profile" scope.
					//$this->googleClient->addScope(array('https://www.googleapis.com/auth/userinfo.profile'));
					$httpClient = $this->googleClient->authorize();
					$payload2 = null;
					if (!empty($httpClient))
					{
						// Reference: https://github.com/google/google-api-php-client#making-http-requests-directly
						// Discovery: https://www.googleapis.com/discovery/v1/apis/oauth2/v1/rest

						//$res = $httpClient->get('https://www.googleapis.com/oauth2/v1/userinfo');
						$res = $httpClient->get('https://www.googleapis.com/userinfo/v2/me');
						$payload2 = json_decode($res->getBody(), true);
					}
					// Not every user has a "link". Also doublecheck that the access_token & id_token were for the same user.
					if (!empty($payload2['link']) AND
						$payload2['id'] == $external_userid
					)
					{
						$payload['link'] = $payload2['link'];
					}
				}
				$additional_params = array();
				$expectedUserInfo = array(
					'email' => '',
					'name' => '',
					'picture' => '',
					'link' => '', // if the user doesn't have a plus page, this might not exist.
					//'locale',
				);
				foreach ($expectedUserInfo AS $__key => $__default)
				{
					if (isset($payload[$__key]))
					{
						$additional_params[$__key] = $payload[$__key];
					}
					else
					{
						$additional_params[$__key] = $__default;
					}
				}

				if (!empty($additional_params))
				{
					$userAuth = array();
					$nonce = $this->getNonce();
					$additional_params['googlelogin_saved'] = $nonce;
					$additional_params['external_userid'] = $external_userid;
					$userAuth['additional_params'] = $additional_params;
					$saved = $this->updateSessionAuthRecord($userAuth);
					$result['googlelogin_saved'] = $nonce;
				}


			}
		}


		return $result;
	}

	public function linkCurrentUserWithApp($params = array())
	{
		$result = array(
			'success' => false,
		);
		$external_userid = $this->getStaticUserIdFromIDToken($params['id_token']);
		if (empty($external_userid))
		{
			$result['error'] = "googlelogin_error_check_auth_popup";
			return $result;
		}

		$userAuth = array(
			//'token' => "unused",
			//'token_secret' => "unused",
			'external_userid' => $external_userid,
		);

		if (!$this->checkExternalUseridAvailability($userAuth['external_userid']))
		{
			$result['error'] = 'externallogin_extid_notunique';
			return $result;
		}

		// grab current userid
		$userAuth['userid'] =  vB::getCurrentSession()->get('userid');
		if (empty($userAuth['userid']))
		{
			$result['error'] = 'googlelogin_error_not_loggedin';
			return $result;
		}

		$check = $this->saveUserLink($userAuth);


		$result = array(
			'success' => true,
		);

		return $result;
	}

	public function saveUserLink($userAuth)
	{
		if (
			!empty($userAuth['userid']) AND
			!empty($userAuth['external_userid'])
		)
		{
			$check = $this->updateUserAuthRecord($userAuth);
			if ($check['result'])
			{
				// delete the sessionauth record that was temporarily holding registration data.
				$this->deleteSessionAuthRecord();
			}

			return $check['result'];
		}

		return false;
	}

	public function getClientId()
	{
		return $this->client_id;
	}

	public function checkEnabled()
	{
		$enabled = (!empty($this->enabled) AND !empty($this->client_id) AND !empty($this->client_secret));
		return array(
			'enabled' => $enabled,
			'register_enabled' => ($enabled AND $this->register_enabled),
		);
	}

	public function forgetRegistrationData()
	{
		return $this->deleteSessionAuthRecord();
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 101013 $
|| #######################################################################
\*=========================================================================*/
