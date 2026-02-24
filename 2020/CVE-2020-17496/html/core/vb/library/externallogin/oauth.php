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

/**
 * @package vBLibrary
 *
 */

/**
 * vB_Library_Auth
 *
 * @package vBLibrary
 * @access public
 */
class vB_Library_ExternalLogin_OAuth extends vB_Library_ExternalLogin
{
	protected $package = "vB_OAuth";

	/*
		End points for getting the request token & converting the request token to an access token via oauth
	 */
	protected $url_request_token; // first init to get a "request" token, which can later be converted into an "access" token
	protected $url_authenticate; // user will login on this page, and be redirected to oauth_callback
	protected $url_access_token; // convert request token to access token via params passed into oauth_callback

	// your (consumer's) URL that can accept oauth_token & oauth_verifier
	protected $oauth_callback;

	protected $http_method = "POST";
	// get these from https://apps.twitter.com/app/{your app ID}/keys
	protected $oauth_consumer_key; // API Key
	protected $oauth_consumer_secret; // API Secret

	// User specific
	protected $oauth_token;	// user token
	protected $oauth_token_secret; // user token secret

	protected $oauth_signature_method = "HMAC-SHA1";
	protected $oauth_timestamp;
	protected $oauth_version = "1.0";
	protected $oauth_nonce;

	protected $debug_mode = false;
	protected $do_log = false;

	protected $error = "";

	/*
	protected $required_oauth_params = array(
		// https://oauth.net/core/1.0/#auth_step1
		'request_token' => array(
			'oauth_consumer_key' => true,
			'oauth_signature_method' => true,
			//'oauth_signature', // generated using these values & appended later.
			'oauth_timestamp' => true,
			'oauth_nonce' => true,
			'oauth_version' => false, // optional
			// and any additional params defined by service provider.
		),
		// https://oauth.net/core/1.0/#auth_step2
		'authenticate' => array(
			'oauth_consumer_key' => true,
			'oauth_signature_method' => true,
			//'oauth_signature', // generated using these values & appended later.
			'oauth_timestamp' => true,
			'oauth_nonce' => true,
			'oauth_version' => false, // optional
			'oauth_token' => false, // optional, though service provider may declare this required
			'oauth_callback' => false, // optional
			// and any additional params defined by service provider.
		),
		// https://oauth.net/core/1.0/#auth_step3
		'access_token' => array(
			'oauth_consumer_key' => true,
			'oauth_token' => true,
			'oauth_signature_method' => true,
			//'oauth_signature', // generated using these values & appended later.
			'oauth_timestamp' => true,
			'oauth_nonce' => true,
			'oauth_version' => false, // optional
			// and any additional params defined by service provider.
		),
	);
	*/

	public function __construct()
	{
		parent::__construct();

		$this->getAndSetCurrentUserData();
	}

	protected function getAndSetCurrentUserData()
	{
		$this->clearOAuthTokenAndSecret();
		$userAuth = $this->getUserAuthRecord();
		$this->setOAuthTokenAndSecret($userAuth);
	}

	protected function clearOAuthTokenAndSecret()
	{
		// clear some user-associated data from memory.
		$this->oauth_token = "";
		$this->oauth_token_secret = "";
	}

	protected function setOAuthTokenAndSecret($userAuth)
	{
		$this->oauth_token = $userAuth['token'];
		$this->oauth_token_secret = $userAuth['token_secret'];
	}

	/**
	 * Convert a pair of request token+secret (linked to an app) to an "access" token+secret
	 * (linked to a 3rd-party/twitter user).
	 * Note that this function "consumed" the sessionauth record.
	 *
	 * @param	Array     $params    Array with 'oauth_token' & 'oauth_verifier', which are
	 *			                     usually supplied by the 3rd party (when they redirect the
	 *			                     user back to us via the oauth_callback) as query params.
	 *
	 * @return	Array
	 *				- Bool   'success'
	 *			    if success is false:
	 *				- String 'error'  error phrasetitle
	 *			    if success is true:
	 *				- Array  'postresponse'  curl post response array
	 *				- String 'oauth_token'
	 *				- String 'oauth_token_secret'
	 *				- Array  'authrecord'
	 */
	protected function convertRequestTokenToAccessToken($params)
	{
		/*
			For oauth, the redirect after 3rd party login will have oauth_token & oauth_verifier
			which we can use to convert the request token into an access token.
		 */
		if (empty($params['oauth_token']) OR empty($params['oauth_verifier']))
		{
			$this->clearOAuthTokenAndSecret();
			return array(
				'success' => false,
				'error' => "missing_oauth_token_or_verifier",
			);
		}

		$url = $this->url_access_token;
		// fetch secret via "request" token that was saved previously.
		$authrecord = $this->getSessionAuthRecord($params['oauth_token']);

		if (empty($authrecord))
		{
			$this->clearOAuthTokenAndSecret();
			// we can't continue without the secret.
			return array(
				'success' => false,
				'error' => "missing_userauth_record",
			);
		}

		$this->setOAuthTokenAndSecret($authrecord);

		$postParams = array(
			'oauth_verifier' => $params['oauth_verifier'],
		);

		/*
			A successful response contains the oauth_token, oauth_token_secret parameters.
			The token and token secret should be stored and used for future authenticated
			requests to the Twitter API. To determine the identity of the user, use GET
			account / verify_credentials.
		 */
		$response = $this->doPOSTRequest($url, $postParams);
		$statusCode = $response['headers']['http-response']['statuscode'];

		if (
			$statusCode == 200 AND
			!empty($response['body']['oauth_token']) AND
			!empty($response['body']['oauth_token_secret'])
		)
		{

			$result = array(
				'success' => true,
				'postresponse' => $response,
				'oauth_token' => $response['body']['oauth_token'],
				'oauth_token_secret' => $response['body']['oauth_token_secret'],
				'authrecord' => $authrecord,
			);
		}
		else
		{
			// todo: clear userauth?
			if (!empty($this->error))
			{
				$result['error'] = $this->error;
			}
			else
			{
				$result['error'] = 'unknown_error';
			}
			$result['success'] = false;
		}

		// delete the sessionauth record, its token & secret have been consumed & can't be reused.
		$this->deleteSessionAuthRecord();

		return $result;
	}

	protected function parseRequestError($statusCode, $responseBody)
	{
		if ($statusCode != 200)
		{
			$this->error = 'unknown_error';
		}
		else
		{
			$this->error = "";
		}
	}

	/**
	 *  Convert request token to access token, fetch external userid (using plugin implemented
	 *  fetchAndSetExternalUserid() function) and update userauth record to link the app with
	 *  the current user.
	 */
	public function linkCurrentUserWithApp($params = array())
	{
		$response = $this->convertRequestTokenToAccessToken($params);
		if ($response['success'] === false)
		{
			return $response;
		}
		$result = array(
			'success' => false,
		);

		$userAuth = $response['authrecord'];
		$userAuth['token'] = $response['oauth_token'];
		$userAuth['token_secret'] = $response['oauth_token_secret'];

		// we have an updated oauth token+secret, so we have to
		// set it before we make new requests
		$this->setOAuthTokenAndSecret($userAuth);

		// Verify request & get the userid, and save the useruath
		$userAuth['external_userid'] = $this->fetchExternalUserid($userAuth);

		// Check for request errors.
		if (!empty($this->error))
		{
			$result['error'] = $this->error;
			return $result;
		}

		if (!$this->checkExternalUseridAvailability($userAuth['external_userid']))
		{
			$result['error'] = 'externallogin_extid_notunique';
			return $result;
		}

		// grab current userid
		$userAuth['userid'] =  vB::getCurrentSession()->get('userid');
		$this->cleanUpUserauthBeforeLinking($userAuth);

		$result = array(
			'success' => $this->checkLinkSuccess($userAuth),
		);
		if (isset($userAuth['additional_params']['return_to_url']))
		{
			$result['return_to_url'] = $userAuth['additional_params']['return_to_url'];
			// consume it so subsequent uses don't accidentally return to this url.
			unset($userAuth['additional_params']['return_to_url']);
		}
		$this->saveUserLink($userAuth);

		return $result;
	}

	public function getLinkedVBUseridFromRequestTokens($params)
	{
		$response = $this->convertRequestTokenToAccessToken($params);
		if ($response['success'] === false)
		{
			return $response;
		}

		$userAuth = $response['authrecord'];
		$userAuth['token'] = $response['oauth_token'];
		$userAuth['token_secret'] = $response['oauth_token_secret'];
		$statusCode = $postresponse['headers']['http-response']['statuscode'];

		// we have an updated oauth token+secret, so we have to
		// set it before we make new requests
		$this->setOAuthTokenAndSecret($userAuth);
		// Verify request & get the userid.
		$ext_id = $this->fetchExternalUserid($userAuth);

		if (empty($ext_id))
		{
			return array(
				'success' => false,
				'error' => "failed_verify_token",
			);
		}

		// working token + secret that we just converted above. This data represents
		// a permitted third party user, so it can be useful to auto-link the user
		// if they haven't already made a connection. It also holds additional_params
		// that might be used to redirect back to whatever page the user was on, for example.
		$oldUserAuth = $userAuth;
		// a userAuth record storing an existing connection. If we don't have this
		// this third party user doesn't have an existing link with a vb user.
		$userAuth = $this->getUserAuthRecord($ext_id);
		if (empty($userAuth['userid']))
		{
			$result = array(
				'success' => false,
				'error' => "no_oauth_user_found",
				'userauth' => $oldUserAuth,
				'external_userid' => $ext_id,
			);
		}
		else
		{
			$result = array(
				'success' => true,
				'userid' => $userAuth['userid'],
			);

			// Fetch new return_to_url and overwrite if necessary
			$userAuth['additional_params'] = ($oldUserAuth['additional_params'] + $userAuth['additional_params']);
			if (isset($userAuth['additional_params']['return_to_url']))
			{
				$result['return_to_url'] = $userAuth['additional_params']['return_to_url'];
				// consume it so subsequent uses don't accidentally return to this url.
				unset($userAuth['additional_params']['return_to_url']);
			}
		}
		$this->cleanUpUserauthAfterConvertingGuestToken($userAuth);
		$check = $this->updateUserAuthRecord($userAuth);

		return $result;
	}

	protected function fetchExternalUserid($userAuth)
	{
		return '';
	}

	protected function cleanUpUserauthBeforeLinking(&$userAuth)
	{
		// do any modifications (e.g. to additional_params) to
		// your package's userauth record here before it's
		// saved & your user is linked with your package platform.
	}

	protected function cleanUpUserauthAfterConvertingGuestToken(&$userAuth)
	{
		// do any modifications (e.g. to additional_params) to
		// your package's userauth record here before it's
		// saved & current user is logged into the matched user record.
	}

	protected function getParameterString($params = array())
	{
		$percentEncodedParams = array();
		foreach ($params AS $key => $value)
		{
			if (!empty($value))
			{
				$percentEncodedParams[rawurlencode($key)] = rawurlencode($key). "=" . rawurlencode($value);
			}
		}
		ksort($percentEncodedParams, SORT_NATURAL);

		$paramString = implode("&", $percentEncodedParams);

		return $paramString;
	}

	private function generateAuthHeader($url, $parameters = array())
	{
		/*
			https://developer.twitter.com/en/docs/basics/authentication/guides/authorizing-a-request
			https://developer.twitter.com/en/docs/basics/authentication/guides/creating-a-signature.html
			https://oauth.net/core/1.0/#auth_header
			https://oauth.net/core/1.0/#signing_process
		 */


		$oauth_params = array(
			// 'realm' // optional
			// making this part of params instead, as it's not always used, so it should be set every time it's
			// needed rather than unsetting after each use.
			//'oauth_callback' => $this->oauth_callback,
			'oauth_consumer_key' => $this->oauth_consumer_key,
			'oauth_nonce' => $this->getNonce(),
			//'oauth_signature', // generated here.
			'oauth_signature_method' => $this->oauth_signature_method,
			'oauth_timestamp' => time(),
			'oauth_token' => $this->oauth_token,
			'oauth_version' => $this->oauth_version,
		);

		if (!empty($parameters['oauth_params']))
		{
			// callback is required by twitter for certain calls, namely the first auth
			// https://developer.twitter.com/en/docs/basics/authentication/api-reference/request_token
			// but is optional otherwise.
			$oauth_params['oauth_callback'] = $parameters['oauth_params'];
		}

		if (empty($this->oauth_token))
		{
			// if user hasn't authorized us yet, we have no token.
			unset($oauth_params['oauth_token']);
		}

		$parameters = array_merge($parameters, $oauth_params); // oauth_param overwrites any "accidentally" specified in params.
		$parameterString = $this->getParameterString($parameters);

		/*
		https://developer.twitter.com/en/docs/basics/authentication/guides/creating-a-signature.html

		apparently URL should be % encoded per RFC 3986, which urlencode() does not do, but rawurlencode() does.
		 */
		$signature_base_string = $this->http_method . "&" . rawurlencode($url) . "&" . rawurlencode($parameterString);

		/*
			"
			Note that there are some flows, such as when obtaining a request token,
			where the token secret is not yet known. In this case, the signing key
			should consist of the percent encoded consumer secret followed by an
			ampersand character ‘&’.
			"
		 */
		$signing_key = rawurlencode($this->oauth_consumer_secret) . "&";
		if (!empty($this->oauth_token_secret))
		{
			$signing_key .=  rawurlencode($this->oauth_token_secret);
		}

		// make sure this matches $this->oauth_signature_method
		$raw_output = true;
		$oauth_signature_binary = hash_hmac("sha1", $signature_base_string, $signing_key, $raw_output);
		$oauth_signature = base64_encode($oauth_signature_binary);

		$oauth_params['oauth_signature'] = $oauth_signature;
		ksort($oauth_params, SORT_NATURAL);
		$authHeaderArray = array();
		foreach ($oauth_params AS $key => $value)
		{
			if (!empty($value))
			{
				$authHeaderArray[] = rawurlencode($key) . '="' . rawurlencode($value) . '"';
			}
		}

		$authHeader = "OAuth " . implode(", ", $authHeaderArray);

		if ($this->do_log)
		{
			error_log(
				__CLASS__ . "->" . __FUNCTION__ . "() @ LINE " . __LINE__
				. "\n" . "url: " . print_r($url, true)
				. "\n" . "parameters: " . print_r($parameters, true)
				. "\n" . "signing_key: " . print_r($signing_key, true)
				. "\n" . "signature_base_string: " . print_r($signature_base_string, true)
				//. "\n" . "oauth_signature (without base64 encoding): " . print_r($oauth_signature_binary, true)
				. "\n" . "oauth_signature: " . print_r($oauth_signature, true)
				. "\n" . "authHeaderArray: " . print_r($authHeaderArray, true)
				. "\n" . "authHeader: " . print_r($authHeader, true)
			);
		}

		return $authHeader;
	}

	final protected function clearError()
	{
		$this->error = "";
	}

	protected function doPOSTRequest($url, $parameters)
	{
		$this->clearError();
		$this->http_method = "POST";
		$httpHeaders = array(
			'Authorization: ' . $this->generateAuthHeader($url, $parameters),
			'Content-Type: application/x-www-form-urlencoded', // oauth1 spec
			//'Content-Type: application/json',
		);

		$urlEncodedPostData = http_build_query($parameters, "", "&", PHP_QUERY_RFC3986);

		$vurl = vB::getUrlLoader(true);

		//no idea if this is actually needed, but I don't want to muck with prior behavior here.
		$vurl->setOption(vB_Utility_Url::CLOSECONNECTION, 1);
		$vurl->setOption(vB_Utility_Url::HTTPHEADER, $httpHeaders);
		$vurl->setOption(vB_Utility_Url::HEADER, 1);
		$vurl->setOption(vB_Utility_Url::TIMEOUT, 5);
		$response = $vurl->post($url, $urlEncodedPostData);

		if ($this->do_log)
		{
			error_log(
					__CLASS__ . "->" . __FUNCTION__ . "() @ LINE " . __LINE__
					. "\n" . "urlEncodedPostData: " . print_r($urlEncodedPostData, true)
					. "\n" . "response: " . print_r($response, true)
			);
		}

		$response['body'] = $this->parseResponseBody($response['body']);
		$this->parseRequestError($response['headers']['http-response']['statuscode'], $response['body']);

		return $response;
	}

	protected function parseResponseBody($body)
	{
		/*
		// json_decode may fail due to platform specific weirdness, e.g. BOM marks,
		// not actually JSON, etc. Let the extensions deal with it by themselves.
		$body = json_decode($response['body'], true);
		if (!empty($body))
		{
			$response['body'] = $body;
		}
		*/
		return $body;
	}

	protected function doGETRequest($url, $parameters)
	{
		$this->clearError();
		$this->http_method = "GET";
		$httpHeaders = array(
			'Authorization: ' . $this->generateAuthHeader($url, $parameters),
			'Content-Type: application/x-www-form-urlencoded',
		);

		$urlEncodedPostData = http_build_query($parameters, "", "&", PHP_QUERY_RFC3986);

		$vurl = vB::getUrlLoader(true);

		//no idea if this is actually needed, but I don't want to muck with prior behavior here.
		$vurl->setOption(vB_Utility_Url::CLOSECONNECTION, 1);
		$vurl->setOption(vB_Utility_Url::HTTPHEADER, $httpHeaders);
		$vurl->setOption(vB_Utility_Url::HEADER, 1);
		$vurl->setOption(vB_Utility_Url::TIMEOUT, 5);
		$response = $vurl->get($url . "?" . $urlEncodedPostData);

		if ($this->do_log)
		{
			error_log(
					__CLASS__ . "->" . __FUNCTION__ . "() @ LINE " . __LINE__
					. "\n" . "urlEncodedPostData: " . print_r($urlEncodedPostData, true)
					. "\n" . "response: " . print_r($response, true)
			);
		}

		$response['body'] = $this->parseResponseBody($response['body']);
		$this->parseRequestError($response['headers']['http-response']['statuscode'], $response['body']);

		return $response;
	}

	protected function fetchRequestToken($oauth_callback)
	{
		$url = $this->url_request_token;
		// we should clear the user data, because when we're getting a request token we shouldn't have
		// any user-specific access token.
		$this->clearOAuthTokenAndSecret();

		return $this->doPOSTRequest($url, array('oauth_callback' => $oauth_callback));
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 102889 $
|| #######################################################################
\*=========================================================================*/
