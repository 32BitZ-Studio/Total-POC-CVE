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

class TwitterLogin_Library_ExternalLogin extends vB_Library_ExternalLogin_OAuth
{
	protected $productid = "twitterlogin";
	protected $url_verify_credentials;
	protected $enabled;
	protected $register_enabled;

	public function __construct()
	{
		parent::__construct();

		// todo: can any of these fetched via oauth discovery?
		$this->url_request_token = "https://api.twitter.com/oauth/request_token";
		$this->url_authenticate = "https://api.twitter.com/oauth/authenticate";
		$this->url_access_token = "https://api.twitter.com/oauth/access_token";

		// other API endpoints
		$this->url_verify_credentials = "https://api.twitter.com/1.1/account/verify_credentials.json";

		$options = vB::getDatastore()->getValue('options');
		$this->enabled = !empty($options['twitterlogin_enabled']);
		$this->register_enabled = !empty($options['twitterlogin_register_enabled']);
		$this->oauth_consumer_key = (!empty($options['twitterlogin_consumer_key']) ? $options['twitterlogin_consumer_key'] : "");
		$this->oauth_consumer_secret =  (!empty($options['twitterlogin_consumer_secret']) ? $options['twitterlogin_consumer_secret'] : "");
	}

	public function checkEnabled()
	{
		$enabled = (!empty($this->enabled) AND !empty($this->oauth_consumer_key) AND !empty($this->oauth_consumer_secret));
		return array(
			'enabled' => $enabled,
			'register_enabled' => ($enabled AND $this->register_enabled),
		);
	}

	protected function parseRequestError($statusCode, $responseBody)
	{

		if ($this->do_log)
		{
			error_log(
					__CLASS__ . "->" . __FUNCTION__ . "() @ LINE " . __LINE__
					. "\n" . "statusCode: " . print_r($statusCode, true)
					. "\n" . "responseBody: " . print_r($responseBody, true)
			);
		}

		/*
			I wasn't able to trigger the rate limit (although most are supposed to be 15 api calls / 15 minutes / user.
			This handling is based on https://developer.twitter.com/en/docs/basics/response-codes
		 */

		if ($statusCode != 200)
		{
			$this->error = 'unknown_error';
			if (
				$statusCode == 420 AND strpos($responseBody, "Enhance Your Calm") !== false  OR
				$statusCode == 429 AND strpos($responseBody, "Too Many Requests") !== false  OR
				isset($responseBody['errors']['code']) AND $responseBody['errors']['code'] == 88
			)
			{
				// rate limit errors.
				$this->error = 'twitterlogin_error_ratelimit_tryagain_later';
			}
			else if (isset($responseBody['errors']['code']))
			{
				switch ($responseBody['errors']['code'])
				{
					// auth failures
					case 32:	// Could not authenticate you
					case 50:	// User not found
					case 89:	// Invalid or expired token
					case 99:	// Unable to verify your credentials
					case 135:	// Could not authenticate you (timestamp out of bounds)
					case 215:	// Bad authentication data
					case 231:	// User must verify login
						// probably best to just retry after double checking credentials
						$this->error = 'twitterlogin_error_invalid_token';
						break;
					// connectivity errors
					case 130:	// Over capacity
					case 131:	// Internal error
					case 226: 	// Accidentally tripped spam detection
						// Connection errors.. maybe try again later?
						$this->error = 'twitterlogin_error_tryagain_later';
						break;
					// todo: do we need this?
					case 63: // User has been suspended.
					case 64: // Your account is suspended and is not permitted to access this feature
					case 326: 	// To protect our users from spam and other malicious activity, this account is temporarily locked
						$this->error = 'twitterlogin_error_account_issue';
						break;
				}
			}
		}
		else
		{
			$this->error = "";
		}
	}
	private function parseTwitterResponseBody($data)
	{
		if (empty($data) OR is_array($data))
		{
			return $data;
		}

		$data= (string) $data;
		//$data = $this->cleanTwitterBodyForJsonDecode($data);
		$json_decoded = json_decode($data, true);
		if (empty($json_decoded))
		{
			// twitter api claims to return json, but sometimes(?) it's just url encoded.
			$decoded_array = array();
			parse_str($data, $decoded_array);
			if (!empty($decoded_array))
			{
				return $decoded_array;
			}
		}
		else
		{
			return $json_decoded;
		}

		return $data;
	}

	private function cleanTwitterBodyForJsonDecode($data)
	{
		// Apparently twitter sometimes has weird unseen characters or BOM that will kill php's json-decode.
		// https://stackoverflow.com/a/20845642

		// remove unwanted chars
		for ($i = 0; $i <= 31; ++$i) {
			$data = str_replace(chr($i), "", $data);
		}
		$data = str_replace(chr(127), "", $data);

		// Remove BOM
		if (0 === strpos(bin2hex($data), 'efbbbf')) {
			$data = substr($data, 3);
		}

		return trim($data);
	}

	protected function parseResponseBody($body)
	{
		if (!empty($body))
		{
			if (!is_array($body))
			{
				// twitter api returns json
				$body = $this->parseTwitterResponseBody($body);
			}
		}

		return $body;
	}

	public function getLoginPage($origin = "", $redirectTo = "")
	{
		// If we have a userid, assume that they're trying to link an account to twitter.
		// If we don't have a userid, assume that it's someone trying to login via twitter, and they
		// had previously linked their accounts already
		$userid = vB::getCurrentSession()->get('userid');
		$libid = $this->getLoginLibraryId();
		// limit brute-forcing against userauth table.
		$verify_token_nonce = $this->getNonce();



		if ($userid OR $origin == "user-setting")
		{
			// If they hit this page, they most likely came from the profile settings.
			// todo: fetch this more systematically?
			$returnToUrl = vB::getDatastore()->getOption('frontendurl') . '/settings/account' . "#twitterlogin_linkaccount";

			$urlSuffix =  "/twitterlogin/auth_callback?libid={$libid}&userid={$userid}&nonce={$verify_token_nonce}";
		}
		else if ($origin == "register")
		{
			// frontend provides the .../register URL (with its own "return to" urlpath query param)
			// that user should be redirected to after they log in on twitter.
			if (!empty($redirectTo))
			{
				$returnToUrl = $redirectTo;
			}
			else
			{
				// per above, this shouldn't happen normally unless JS failed somehow.
				$returnToUrl = vB::getDatastore()->getOption('frontendurl') . "?debug=twitter_register_missing_redirect";
			}
			$urlSuffix =  "/twitterlogin/auth_callback?libid={$libid}&register=true&nonce={$verify_token_nonce}";
		}
		else // login
		{
			/*
				Redirect them back to wherever they were.
				Frontend (see twitterlogin_javascript template) provides the URL that the user was on previously.
				For best UX user should be redirected back to whatever page they were looking at as a guest after they
				login via twitter.
			 */
			if (!empty($redirectTo))
			{
				$returnToUrl = $redirectTo;
			}
			else
			{
				// per above, this shouldn't happen normally unless JS failed somehow.
				$returnToUrl = vB::getDatastore()->getOption('frontendurl') . "?debug=twitter_login_guest";
			}
			$urlSuffix =  "/twitterlogin/auth_callback?libid={$libid}&guest=true&nonce={$verify_token_nonce}";
		}

		// note, oauth_callback  will be rawurlencoded by the oauth wrapper.
		$oauth_callback = vB::getDatastore()->getOption('frontendurl') . $urlSuffix;
		// routes without classes can't go through buildURL
		//vB5_Route::buildUrl('twitterlogin_authenticate_callback|fullurl');


		if ($this->do_log)
		{
			error_log(
					__CLASS__ . "->" . __FUNCTION__ . "() @ LINE " . __LINE__
					. "\n" . "oauth_callback: " . print_r($oauth_callback, true)
					. "\n" . "userid: " . print_r($userid, true)
			);
		}

		/*
			Your application should examine the HTTP status of the response.
			Any value other than 200 indicates a failure.
			The body of the response will contain the oauth_token, oauth_token_secret,
			and oauth_callback_confirmed parameters.
			Your application should verify that oauth_callback_confirmed is true and
			store the other two values for the next steps.
		 */
		$response = $this->fetchRequestToken($oauth_callback);

		$statusCode = $response['headers']['http-response']['statuscode'];
		if (
			$statusCode == 200 AND
			!empty($response['body']['oauth_token']) AND
			!empty($response['body']['oauth_token_secret']) AND
			!empty($response['body']['oauth_callback_confirmed'])
		)
		{
			$userAuth = array();
			$userAuth['token'] = $response['body']['oauth_token'];
			$userAuth['token_secret'] = $response['body']['oauth_token_secret'];
			// todo: append instead of replace?
			$userAuth['additional_params'] = array(
				'verify_token_nonce' => $verify_token_nonce,
				'return_to_url' => $returnToUrl,
			);

			$saved = $this->updateSessionAuthRecord($userAuth);

			$result = array(
				'success' => true,
				'url' => $this->url_authenticate . "?oauth_token=" . $userAuth['token'],
			);
		}
		else
		{
			// We hit an issue. Not sure what we can do about it other than telling the user to try again later.
			// todo: clear userauth?
			if (!empty($this->error) AND $this->error != 'unknown_error')
			{
				$result['error'] = $this->error;
			}
			else
			{
				$result['error'] = 'twitterlogin_error_tryagain_later';
			}
			$result['success'] = false;
		}


		return $result;
	}

	public function fetchAndStoreTwitterInfoForRegistration($requestTokenParams = array(), $accessTokenParams = array())
	{
		if (empty($accessTokenParams))
		{
			$response = $this->convertRequestTokenToAccessToken($requestTokenParams);
			if ($response['success'] === false)
			{
				return $response;
			}

			$userAuth = $response['authrecord'];
			$userAuth['token'] = $response['oauth_token'];
			$userAuth['token_secret'] = $response['oauth_token_secret'];
		}
		else
		{
			$userAuth = $accessTokenParams;
		}

		// we have an updated oauth token+secret, so we have to
		// set it before we make new requests
		$this->setOAuthTokenAndSecret($userAuth);

		// based on fetchExternalUserid()
		$params = array(
			'include_entities' => true,
			'skip_status' => true,
			/*
				To get the email from the user, a few stars have to line up.
				First, if it's false (and sometimes just whenever) having the
				include_email param set causes the oauth verification to fail
				on their end.
				Furthermore, if you want it to be set to true, it actually has
				to be a string "true" instead of boolean, reference:
				https://twittercommunity.com/t/account-verify-credentials-not-return-email/81626/11

				Lastly, the forum app must have requested this "additional permission", and the
				twitter user in question must have supplied and verified their email.

				If any of these isn't true, email will not be passed back.
			 */
			'include_email' => "true",
		);
		$response = $this->doGETRequest($this->url_verify_credentials, $params);
		if ($this->do_log)
		{
			error_log(
				__CLASS__ . "->" . __FUNCTION__ . "() @ LINE " . __LINE__
				. "\n" . "response: " . print_r($response, true)
			);
		}
		if (!empty($response['body']))
		{
			if (!is_array($response['body']))
			{
				// twitter api returns json
				$response['body'] = $this->parseTwitterResponseBody($response['body']);
			}
		}

		$result = array();
		$result['success'] = false;
		// Check for request errors.
		if (!empty($this->error))
		{
			$result['error'] = $this->error;
			return $result;
		}

		$statusCode = $response['headers']['http-response']['statuscode'];
		if (
			$statusCode == 200 AND
			!empty($response['body']['id_str'])
		)
		{
			$additional_params = array();
			$external_userid = $response['body']['id_str'];
			if (!$this->checkExternalUseridAvailability($external_userid))
			{
				// todo: link back to register page here?
				$result['error'] = 'externallogin_extid_notunique';
				return $result;
			}


			$result['success'] = true;
			$additional_params['external_userid'] = $external_userid;

			// Store these values temporarily in the session auth (since this is for registration, we won't have
			// access to a userid to use the more permanent userauth records).
			// We will pick it up and store it during user creation later.
			/*
				https://developer.twitter.com/en/docs/accounts-and-users/manage-account-settings/api-reference/get-account-verify_credentials

				Some useful points of data
					name
					screen_name
					email (may not work ATM)
					location
					description
			 */
			$additional_params['external_userid'] = $external_userid;
			$additional_params['name'] = $response['body']['name'];
			$additional_params['screen_name'] = $response['body']['screen_name'];
			$additional_params['email'] = ( isset($response['body']['email']) ? $response['body']['email'] : '' );
			$additional_params['profile_image_url_https'] = $response['body']['profile_image_url_https'];
			$additional_params['twitterlogin_register_nonce'] = $this->getNonce();

			if (empty($userAuth['additional_params']))
			{
				$userAuth['additional_params'] = array();
			}
			$this->cleanUpUserauthAfterConvertingGuestToken($userAuth);
			$userAuth['additional_params'] = $additional_params + $userAuth['additional_params'];
			$saved = $this->updateSessionAuthRecord($userAuth);

			// pass back data for controller to redirect back to registration page
			if (isset($userAuth['additional_params']['return_to_url']))
			{
				$result['return_to_url'] = $userAuth['additional_params']['return_to_url'];
			}
			$result['twitterlogin_saved'] = $additional_params['twitterlogin_register_nonce'];
		}
		else
		{
			// if we got this far, we don't actually know what happened, because we didn't catch it in
			// $this->error above (set by parseRequestErrors() called by do[GET|POST]Request()
			// Just blame the most likely generic issue
			$result['error'] = 'twitterlogin_error_invalid_token';
		}

		return $result;
	}

	protected function fetchExternalUserid($userAuth)
	{
		/*
			https://developer.twitter.com/en/docs/accounts-and-users/manage-account-settings/api-reference/get-account-verify_credentials
		 */
		$params = array(
			'include_entities' => true,
			'skip_status' => true,
			// Warning: Having include_email param set to false can cause oauth verify to fail.
			// For true, apparently it needs to be explicitly string "true", not boolean.
			//'include_email' => false,
		);
		$response = $this->doGETRequest($this->url_verify_credentials, $params);


		if ($this->do_log)
		{
			error_log(
				__CLASS__ . "->" . __FUNCTION__ . "() @ LINE " . __LINE__
				. "\n" . "response: " . print_r($response, true)
			);
		}


		if (!empty($response['body']))
		{
			if (!is_array($response['body']))
			{
				// twitter api returns json
				$response['body'] = $this->parseTwitterResponseBody($response['body']);
			}
		}

		$statusCode = $response['headers']['http-response']['statuscode'];
		if (
			$statusCode == 200 AND
			!empty($response['body']['id_str'])
		)
		{
			return $response['body']['id_str'];
		}
		else
		{
			return '';
		}
	}

	protected function cleanUpUserauthBeforeLinking(&$userAuth)
	{
		unset($userAuth['additional_params']['verify_token_nonce']);
	}

	protected function cleanUpUserauthAfterConvertingGuestToken(&$userAuth)
	{
		unset($userAuth['additional_params']['verify_token_nonce']);
	}

	protected function checkLinkSuccess($userAuth)
	{
		return !empty($userAuth['external_userid']);
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
