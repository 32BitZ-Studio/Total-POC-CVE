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

class GoogleLogin_Api_ExternalLogin extends vB_Api_ExternalLogin
{
	protected $disableWhiteList = array(
		// required to show login button template
		'getState',
		'showExternalLoginButton',
		// called by login button template
		'getClientId',
		// called by google dialog closing to log user into forum via their google account
		'verifyAuthAndLogin',
	);

	public function __construct()
	{
		parent::__construct();
		$this->library = vB_Library::instance('googlelogin:ExternalLogin');
	}

	public function getClientId()
	{
		/*
			So generally we don't want to reveal api keys, but the usage of google JS Api requires that we
			expose the client id in the source for initializing...
			Also note, for normal vboptions we could access them from templates directly, but for some reason
			I couldn't get vb:raw/var to output the client id, so I added this convenience function.
		 */
		return array(
			"client_id" => $this->library->getClientId(),
		);
	}

	public function getRegistrationData($googlelogin_saved)
	{

		/*
			The nonce check is mostly meant to help ensure that the user requested that their google account
			be added during this specific session/flow, not at a previous point (e.g. a different person
			on a shared computer).
			This might need more refinement, however.
		 */
		$authRecord = $this->library->getSessionAuthRecord();
		if (!empty($authRecord) AND
			!empty($authRecord['additional_params']['googlelogin_saved']) AND
			($authRecord['additional_params']['googlelogin_saved'] == $googlelogin_saved)
		)
		{
			$result = array(
				'found'           => true,
				'username'        => $authRecord['additional_params']['name'],
				'email'           => $authRecord['additional_params']['email'],
				'external_userid' => $authRecord['additional_params']['external_userid'],
				'picture'         => $authRecord['additional_params']['picture'],
				'url'             => $authRecord['additional_params']['link'],
				'return_to_url'   => $authRecord['additional_params']['return_to_url']
			);
		}
		else
		{
			$result = array(
				'found'           => false,
			);
		}

		return $result;
	}

	public function verifyAuthAndLogin($id_token, $access_token = "", $url = "", $donotlogin = false)
	{
		/*
			We only make a call from this server to google iff the id_token is verified (which is
			done mostly offline via Google's PHP library after it fetches Google's public key).
			As such, I don't believe this is a brute force or ddos vector, see notes below for
			verifyAuthAndLinkUser()
		 */
		$check = $this->library->getLinkedVBUseridFromIdToken($id_token, $access_token);
		if ($check['success'] AND !empty($check['userid']))
		{
			if (!$donotlogin)
			{
				// log in using userid
				$result = $this->library->loginUser($check['userid']);
				return ($check + $result);
			}
			else
			{
				$result = array(
					'error' => 'externallogin_extid_notunique',
				);
				return ($check + $result);
			}
		}
		else if ($check['error'] == 'googlelogin_no_oauth_user_found' AND
			!empty($check['googlelogin_saved'])
		)
		{
			$frontendUrl = vB::getDatastore()->getOption('frontendurl');
			$registrationUrl = $frontendUrl . "/register";
			if (!empty($url))
			{
				// remove scheme and make redirect is on the same site before appending it.
				$frontendUrlParts = parse_url($frontendUrl);
				$frontendUrlCheck = $frontendUrlParts['host'] . $frontendUrlParts['path'];
				$returnUrlParts = parse_url($url);
				$returnUrlCheck = $returnUrlParts['host'] . $returnUrlParts['path'];

				if (strpos($returnUrlCheck, $frontendUrlCheck) === 0)
				{
					$registrationUrl .= "?urlpath=" . base64_encode($url);
				}
			}
			$registrationUrl = $this->addRemoveGoogleLoginSavedParamToURL($registrationUrl, $check['googlelogin_saved']);
			$check['registration_url'] = $registrationUrl;
			$check['error'] = array('googlelogin_no_oauth_user_found_register_x', $registrationUrl);
		}

		return $check;
	}

	private function addRemoveGoogleLoginSavedParamToURL($url, $googlelogin_saved = null)
	{
		$url_parts = parse_url($url);
		$queryString = $url_parts['query'];
		$query = array();
		parse_str($queryString, $query);
		unset($query['googlelogin_saved']);
		if (!empty($googlelogin_saved))
		{
			$query['googlelogin_saved'] = $googlelogin_saved;
		}
		foreach ($query AS $__key => $__val)
		{
			$query[$__key] = $__key . "=" . $__val;
		}
		$url = $url_parts['scheme'] . "://" . $url_parts['host'] . $url_parts['path'] . '?' . implode('&', $query);

		return $url;
	}

	public function verifyAuthAndLinkUser($id_token)
	{
		/*
			Note: This API currently does not make another call to google servers (except for
			Google's public key if it expired or was lost from memory/cache, but that's handled
			by Google's PHP library and I'm not 100% clear on the mechanisms).
			We just invoke the library to verify the id_token signature via their public key to
			see if it's trustworthy or not.

			If they wanted to brute force against this API, they could've just downloaded the
			Google's PHP library (or made their own verification implementation per their specs)
			and use it that way, and what'd they'd get is public profile information embedded in
			the id_token, and the id_token itself which *could* be used to make public-data API
			requests that don't require our secret while masquerading as us (since our client ID
			is not kept secret), which I don't see as a real issue.
		 */


		$linkResult = $this->library->linkCurrentUserWithApp(array('id_token' => $id_token));

		return $linkResult;
	}

	public function unlinkUser()
	{
		// TODO: also revoke app access, but that requires requesting offline access & storing access_token + refresh_token
		// for each user.
		// Currently we attempt to revoke access via google's JS API, which invokes the google login popup. If they failed to
		// log in for whatever reason, we still forget their account on our end, and instruct them via a pop-up message to
		// manually revoke application access via their google account settings. This is probably sufficient for now, but
		// if we ever decide to store the access_token & refresh_token for additional features (e.g. sharing on google+)
		// we should update the flow to automatically revoke via backend instead of requiring additional user action.

		$this->library->unlinkCurrentUserFromApp();

		$result = array(
			'success' => true,
		);

		return $result;
	}


	public function getState()
	{
		$userAuth = $this->library->getUserAuthRecord();

		$enabled = $this->library->checkEnabled();

		return array(
			"enabled" => $enabled['enabled'],
			"register_enabled" => $enabled['register_enabled'],
			"external_userid" => !empty($userAuth['external_userid']) ? $userAuth['external_userid'] : '',
		);
	}

	public function forgetRegistrationData($url = "")
	{
		if (!empty($url))
		{
			$url = $this->addRemoveGoogleLoginSavedParamToURL($url, null);
		}
		$this->library->forgetRegistrationData();

		return array(
			'success' => true,
			'url' => $url,
		);
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 101013 $
|| #######################################################################
\*=========================================================================*/
