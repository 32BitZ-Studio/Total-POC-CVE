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

class TwitterLogin_Api_ExternalLogin extends vB_Api_ExternalLogin
{
	protected $disableWhiteList = array(
		// required to show login button template
		'getState',
		'showExternalLoginButton',
		// called by login button template
		'fetchTwitterLinkUrl',
		// called by twitter dialog redirection to log user into forum via their twitter account
		'verifyAuthAndLogin',
	);

	public function __construct()
	{
		parent::__construct();
		$this->library = vB_Library::instance('TwitterLogin:ExternalLogin');
	}

	public function fetchTwitterLinkUrl($origin = "", $redirectTo = "")
	{
		$result = array();

		$loginUrl = $this->library->getLoginPage($origin, $redirectTo);
		if ($loginUrl['success'] AND !empty($loginUrl['url']))
		{
			$result['url'] = $loginUrl['url'];
		}
		else
		{
			$result['error'] = $loginUrl['error'];
		}



		return $result;
	}

	public function unlinkUser()
	{
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

	public function forgetRegistrationData($twitterlogin_saved, $url)
	{
		$authRecord = $this->library->getSessionAuthRecord();
		if (!empty($authRecord) AND
			!empty($authRecord['additional_params']['twitterlogin_register_nonce']) AND
			($authRecord['additional_params']['twitterlogin_register_nonce'] == $twitterlogin_saved)
			OR true
		)
		{
			$this->library->forgetRegistrationData();

			$url = $this->addRemoveTwitterloginSavedParamToURL($url);

			return array(
				'success' => true,
				'url' => $url,
			);
		}
		return array(
			'success' => false,
			'error' => "twitterlogin_saved not found",
		);
	}

	private function addRemoveTwitterloginSavedParamToURL($url, $twitterlogin_saved = null)
	{
		$url_parts = parse_url($url);
		$queryString = $url_parts['query'];
		$query = array();
		parse_str($queryString, $query);
		unset($query['twitterlogin_saved']);
		if (!empty($twitterlogin_saved))
		{
			$query['twitterlogin_saved'] = $twitterlogin_saved;
		}
		foreach ($query AS $__key => $__val)
		{
			$query[$__key] = $__key . "=" . $__val;
		}
		$url = $url_parts['scheme'] . "://" . $url_parts['host'] . $url_parts['path'] . '?' . implode('&', $query);

		return $url;
	}

	public function getRegistrationData($twitterlogin_saved)
	{
		/*
			The nonce check is mostly meant to help ensure that the user requested that their twitter account
			be added during this specific session/flow, not at a previous point (e.g. a different person
			on a shared computer).
			This might need more refinement, however.
		 */
		$authRecord = $this->library->getSessionAuthRecord();
		if (!empty($authRecord) AND
			!empty($authRecord['additional_params']['twitterlogin_register_nonce']) AND
			($authRecord['additional_params']['twitterlogin_register_nonce'] == $twitterlogin_saved)
		)
		{
			$result = array(
				'found'           => true,
				'username'        => $authRecord['additional_params']['screen_name'],
				'email'           => $authRecord['additional_params']['email'],
				'external_userid' =>  $authRecord['additional_params']['external_userid'],
				'return_to_url'   =>  $authRecord['additional_params']['return_to_url'],
				'profile_image_url_https' => $authRecord['additional_params']['profile_image_url_https'],
				'url'             => "https://twitter.com/" . $authRecord['additional_params']['screen_name'],
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

	public function verifyAuthForvBRegistration($libid, $oauth_token, $oauth_verifier, $nonce, $denied = null)
	{
		$generic_error_phrase = 'twitterlogin_error_invalid_token';
		if (!$this->checkCallbackParams($libid, $oauth_token, $oauth_verifier, $nonce))
		{
			if (!empty($denied))
			{
				return array(
					'error' => 'twitterlogin_error_need_app_auth',
				);
			}

			return array(
				'error' => $generic_error_phrase,
			);
		}

		/*
			If we got this far, assume everything's green and the user has authenticated us.
			Convert the request token into an access token, get the twitter userid, save it to
			userauth.external_userid, & this user can start using twitter to log in!
			probably.
		 */
		$params = array(
			'oauth_token' => $oauth_token,
			'oauth_verifier' => $oauth_verifier,
		);



		$check = $this->library->fetchAndStoreTwitterInfoForRegistration($params);

		if (!empty($check['return_to_url']) AND !empty($check['twitterlogin_saved']))
		{
			$check['return_to_url'] = $this->addRemoveTwitterloginSavedParamToURL($check['return_to_url'], $check['twitterlogin_saved']);
		}

		return $check;
	}

	public function verifyAuthAndLogin($libid, $oauth_token, $oauth_verifier, $nonce, $denied = null)
	{
		$generic_error_phrase = 'twitterlogin_error_invalid_token';
		if (!$this->checkCallbackParams($libid, $oauth_token, $oauth_verifier, $nonce))
		{
			if (!empty($denied))
			{
				return array(
					'error' => 'twitterlogin_error_need_app_auth',
				);
			}
			return array(
				'error' => $generic_error_phrase,
			);
		}

		/*
			If we got this far, assume everything's green and the user has authenticated us.
			Convert the request token into an access token, get the twitter userid, save it to
			userauth.external_userid, & this user can start using twitter to log in!
			probably.
		 */
		$params = array(
			'oauth_token' => $oauth_token,
			'oauth_verifier' => $oauth_verifier,
		);
		$check = $this->library->getLinkedVBUseridFromRequestTokens($params);
		if ($check['success'] AND !empty($check['userid']))
		{
			// log in using userid
			$result = $this->library->loginUser($check['userid']);
			return ($check + $result);
		}
		else if ($check['error'] == 'no_oauth_user_found' AND
			!empty($check['external_userid']) AND
			!empty($check['userauth'])
		)
		{
			// store this for auto-linking and append a link to registration page.
			$check2 = $this->library->fetchAndStoreTwitterInfoForRegistration(array(), $check['userauth']);


			if (!empty($check2['twitterlogin_saved']))
			{
				$frontendUrl = vB::getDatastore()->getOption('frontendurl');
				$registrationUrl = $frontendUrl . "/register";
				if (!empty($check2['return_to_url']))
				{
					// remove scheme and make redirect is on the same site before appending it.
					$frontendUrlParts = parse_url($frontendUrl);
					$frontendUrlCheck = $frontendUrlParts['host'] . $frontendUrlParts['path'];
					$returnUrlParts = parse_url($check2['return_to_url']);
					$returnUrlCheck = $returnUrlParts['host'] . $returnUrlParts['path'];

					if (strpos($returnUrlCheck, $frontendUrlCheck) === 0)
					{
						$registrationUrl .= "?urlpath=" . base64_encode($check2['return_to_url']);
					}
				}
				$registrationUrl = $this->addRemoveTwitterloginSavedParamToURL($registrationUrl, $check2['twitterlogin_saved']);
				$check['error'] = array('twitterlogin_no_oauth_user_found_register_x', $registrationUrl);
			}
		}

		return $check;
	}

	private function checkCallbackParams($libid, $oauth_token, $oauth_verifier, $nonce)
	{
		/*
			This was originally to mitigate brute force attacks against the userauth table
			when we used to use that instead of sessionauth.
			Limit brute force attacks vs. any existing records by verifying that
			additional_params.verify_token_nonce matches nonce
		 */

		$authRecord = $this->library->getSessionAuthRecord($oauth_token);
		if (empty($authRecord))
		{
			/*
				We have no idea what happened here. Either callback URL is incorrect or the
				initial get request token failed badly and we shouldn't ever have gotten to
				the auth step, but somehow did, or something else entirely.
				We don't know how to recover from this
			 */
			return false;
		}

		if ($authRecord['loginlibraryid'] != $libid OR
			// todo, is there a need to one-way hash the nonce check?
			empty($authRecord['additional_params']['verify_token_nonce']) OR
			$authRecord['additional_params']['verify_token_nonce'] != $nonce
		)
		{
			/*
				Again, not sure how we got here, but they supplied us with the wrong
				library or userid and the token does NOT match up.
				Suspect foul play, and generic error up.
			 */
			return false;
		}


		return true;
	}

	public function verifyAuthAndLinkUser($libid, $oauth_token, $oauth_verifier, $nonce, $denied = null)
	{
		$generic_error_phrase = 'twitterlogin_error_invalid_token';

		$userAuth = $this->library->getUserAuthRecord();
		if (!empty($userAuth['external_userid']))
		{
			/*
				no bueno, someone might be trying to brute force our tokens or
				overwrite an existing token	in an unsupported way.
				todo: wait, how *do* we refresh the token? Unlink first?
			 */
			return array(
				'error' => $generic_error_phrase,
			);
		}

		if (!$this->checkCallbackParams($libid, $oauth_token, $oauth_verifier, $nonce))
		{
			if (!empty($denied))
			{
				return array(
					'error' => 'twitterlogin_error_need_app_auth',
				);
			}
			return array(
				'error' => $generic_error_phrase,
			);
		}

		/*
			If we got this far, assume everything's green and the user has authenticated us.
			Convert the request token into an access token, get the twitter userid, save it to
			userauth.external_userid, & this user can start using twitter to log in!
			probably.
		 */
		$params = array(
			'oauth_token' => $oauth_token,
			'oauth_verifier' => $oauth_verifier,
		);
		$linkResult = $this->library->linkCurrentUserWithApp($params);

		return $linkResult;
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 101013 $
|| #######################################################################
\*=========================================================================*/
