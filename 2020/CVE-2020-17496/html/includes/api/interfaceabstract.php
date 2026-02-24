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

abstract class Api_InterfaceAbstract
{
	const API_COLLAPSED = 'Collapsed';
	const API_LIGHT = 'light';
	const API_TEST = 'Test';

	private static $instance;

	/*
	 * Defines whether we are using the API in test mode
	 * @var bool
	 */
	private static $test = false;

	/*
	 * Defines whether we are using the API in light mode
	 * @var bool
	 */
	private static $light = false;
	/**
	 * Turns on/off the test mode in API
	 * @param bool $on
	 */
	public static function setTest($on)
	{
		self::$test = $on;
	}

	/**
	 * Turns on/off the light mode in API
	 * @param bool $on
	 */
	public static function setLight($on = true)
	{
		self::$light = $on;
	}

	public static function instance($type = NULL)
	{
		if (self::$test)
		{
			$type = self::API_TEST;
		}
		else if (self::$light)
		{
			$type = self::API_LIGHT;
		}
		else if ($type === NULL)
		{
			$type = self::API_COLLAPSED;
		}

		if (!isset(self::$instance[$type]))
		{
			$c = 'Api_Interface_' . ucfirst($type);
			if (class_exists($c))
			{
				self::$instance[$type] = new $c;
				self::$instance[$type]->init();
			}
			else
			{
				throw new Exception("Couldn't find $type interface");
			}
		}

		return self::$instance[$type];
	}

	// prevent users to clone the instance
	public function __clone()
	{
		trigger_error('Clone is not allowed.', E_USER_ERROR);
	}

	/**
	 * Initialized method. This method is to prevent nested construct calls. See VBV-1862
	 */
	public function init()
	{

	}

	/**
	 *
	 * @param string $controller
	 * @param string $method
	 * @param array $arguments
	 * @return array
	 */
	// This method is currently dealign with both indexed and associative arrays.
	// Indexed arrays are sent by template calls.
	// @todo: make sure all API methods exposed to the template can handle indexed arrays
	abstract public function callApi($controller, $method, array $arguments = array(), $useNamedParams = false);

	public function relay($file)
	{
		throw new Exception('relay only implemented in collapsed mode');
	}

	/**
	 *	Handles inializing the vB session
	 *
	 *	This includes checking for a session cookie, checking the "rememberme" cookie
	 *	and doing the facebook redirect if rememberme is flagged as "facebook" and we
	 *	fail to initialize the user (there is a chicken and egg problem with inializing
	 *	a facebook user since we generate an auth token via JS but that won't run until
	 *	the user loads a page so we need to fake load a page to make FB work when a user
	 *	initially hits the site). This only occurs for get requests as we will lose post data in this process.
	 *
	 *	We also handle updating the rememberme and session cookies as needed.
	 *
	 *	This does not handle things like updating lastvisit.
	 *	We want to skip this for the "light" session used for some AJAX calls.
	 */
	protected function createSession($request, $options)
	{
		$restoreSessionInfo = array();
		$sessionhash = vB5_Cookie::get('sessionhash', vB5_Cookie::TYPE_STRING);
		if (
			empty($sessionhash) AND
			!empty($_REQUEST['s']) AND
			$_REQUEST['routestring'] == 'filedata/fetch'
		)
		{
			/*
				The "s" parameter is set on URLs by vB_Api_vB4 calls (MAPI). The client apparently has
				no way to set cookies on image fetch calls, without another way to identify the requester
				images that are not visible to guests would not load on the mobile apps.
				We take a cue from vB4 behavior & pass in a sessionhash via URL, eating any risks associated
				with leaking the sessionhash as part of a URL (assuming that filedata/fetch does NOT refresh
				session lifetime). VBV-18021, VBV-14697
			 */
			$sessionhash = (string) $_REQUEST['s'];
			/*
				On the android app (possibly also on iOS app), the agent strings are different between the
				api showthread call & the filedata/fetch call, which causes the vB_Session::fetchStoredSession()'s
				idhash check to fail (see vB_Session_Web::createSessionIdHash() on how it's generated).

				To get around that, if we're missing the cookie & are using the "s" sessionhash, also signal for
				a try-again checking the apiclient record with the current IP & apiaccesstoken to validate
				the client instead of via agent string.

				To minimize any potential damage from spoofing, let's only pass this through for
				filedata/fetch requests.
			 */
			$restoreSessionInfo['tryagain_apiclient'] = true;
			// webAPI (loaded downstream of applicationlight::fetchImage()) always checks for timeout.
		}
		$restoreSessionInfo['userid'] = vB5_Cookie::get('userid', vB5_Cookie::TYPE_STRING);
		$restoreSessionInfo['remembermetoken'] = vB5_Cookie::get('password', vB5_Cookie::TYPE_STRING);
		$remembermetokenOrig = $restoreSessionInfo['remembermetoken'];

		$retry = false;
		if ($restoreSessionInfo['remembermetoken'] == 'facebook-retry')
		{
			$restoreSessionInfo['remembermetoken'] = 'facebook';
			$retry = true;
		}

		if($options['facebookactive'] AND $options['facebookappid'])
		{
			//this is not a vB cookie so it doesn't use our prefix -- which the cookie class adds automatically
			$cookie_name = 'fbsr_' .  $options['facebookappid'];
			$restoreSessionInfo['fb_signed_request'] = isset($_COOKIE[$cookie_name]) ? strval($_COOKIE[$cookie_name]) : '';
		}

		$session = $request->createSessionNew($sessionhash, $restoreSessionInfo);
		if ($session['sessionhash'] !== $sessionhash)
		{
			vB5_Cookie::set('sessionhash', $session['sessionhash'], 0, true);
		}

		//redirect to handle a stale FB cookie when doing a FB "remember me".
		//only do it once to prevent redirect loops -- don't try this with
		//posts since we'd lose the post data in that case
		//
		//Some notes on the JS code (don't want them in the JS inself to avoid
		//increasing what gets sent to the browser).
		//1) This code is deliberately designed to avoid using subsystems that
		//	would increase the processing time for something that doesn't need it
		//	(we even avoid initializing JQUERY here).  This is the reason it is
		//	inline and not in a template.
		//2) The code inits the FB system which will create update the cookie
		//	if it is able to validate the user.  The cookie is what we are after.
		//	We use getLoginStatus instead of setting status to true because
		//	the latter introduces a race condition were we can do the redirect
		//	before the we've fully initialized and updated the cookie.  The
		//	explicit call to getLoginStatus allows us to redirect when the
		//	status is obtained.
		//3) If we fail to update the cookie we catch that when we try to
		//	create the vb session (which is why we only allow one retry)
		//4) The JS here should *never* prompt the user, assuming the FB
		//	docs are correct.
		//5) If the FB version is changed it needs to changed in the
		//	FB library class and the facebook.js file
		if(
			strtolower($_SERVER['REQUEST_METHOD']) == 'get' AND
			vB::getCurrentSession()->get('userid') == 0 AND
			$options['facebookactive'] AND
			$options['facebookappid'] AND
			$restoreSessionInfo['remembermetoken'] == 'facebook'
		)
		{
			if (!$retry)
			{
				//if this isn't a retry, then do a redirect
				vB5_Auth::setRememberMeCookies('facebook-retry', $restoreSessionInfo['userid']);
				$fbredirect = "
					<!DOCTYPE html>
					<html>
					<head>
						<script type='text/javascript' src='//connect.facebook.net/en_US/sdk.js'></script>
						<script type='text/javascript'>
							FB.init({
								appId   : '$options[facebookappid]',
								version : 'v3.3',
								status  : false,
								cookie  : true,
								xfbml   : false
							});

							FB.getLoginStatus(function(response)
							{
								window.top.location.reload(true);
							});
						</script>
					</head>
					<body></body>
					</html>
				";
				echo $fbredirect;
				exit;
			}
			else
			{
				//we tried and failed to log in via FB.  That probably means that the user
				//is logged out of facebook.  Let's kill the autolog in so that we stop
				//trying to connect via FB
				vB5_Auth::setRememberMeCookies('', '', 0);
			}
		}

		//if we have an existing token and if we got a token back from the session that is different then we
		//need to update the token in the browser.  We shouldn't get a token back if we didn't pass one in but
		//we shouldn't depend on that behavior.
		if ($session['remembermetoken'] AND $session['remembermetoken'] != $remembermetokenOrig)
		{
			vB5_Auth::setRememberMeCookies($session['remembermetoken'], $restoreSessionInfo['userid']);
		}

		//what we were calling session is an array and not the session object.
		//let's get that.
		$session = vB::getCurrentSession();

		// Try to set cpsession hash to session object if exists
		$session->setCpsessionHash(vB5_Cookie::get('cpsession', vB5_Cookie::TYPE_STRING));

		return $session;
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 101516 $
|| #######################################################################
\*=========================================================================*/
