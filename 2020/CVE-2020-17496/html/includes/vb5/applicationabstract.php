<?php
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

abstract class vB5_ApplicationAbstract
{
	protected static $instance;
	protected $router = NULL;
	protected static $needCharset = false;

	const ON_FIRE_MESSAGE = <<<EOD
<head>
	<title>System Error</title>
</head>
<body>
	<h1> A System Error has occured.</h1>
	<p> The software is experiencing a systems error.</p>
	<p> You should attempt to repeat your last action. If this error occurs again, please contact the {{{site_administrator}}}.</p>
</body>
EOD;

	public static function instance()
	{
		if (!isset(self::$instance))
		{
			throw new vB5_Exception('Application hasn\'t been initialized!');
		}

		return self::$instance;
	}

	public static function init($configFile)
	{
		$config = vB5_Config::instance();
		$config->loadConfigFile($configFile);

		require_once($config->core_path . '/vb/vb.php');
		vB::init();


		if (!defined('VB_ENTRY'))
		{
			define('VB_ENTRY', 1);
		}

		set_exception_handler(array('vB5_ApplicationAbstract','handleException'));
	}

	/**
	 * Replacing meta tag from the header.xml with header in the requests. See VBV-6361
	 *
	 */
	protected static function setHeaders()
	{
		// add no cache directive if it's set in options
		// redirect to install page if there's no database
		try
		{
			if (headers_sent())
			{
				self::$needCharset = true;
			}
			else
			{
				header('Content-Type: text/html; charset=' . $charset = vB5_String::getCharset());
			}

			$api = Api_InterfaceAbstract::instance();
			$options = $api->callApi('options', 'fetchValues', array(array(
				'nocacheheaders',
				'clickjackingheaders',
				'header_contentsecuritypolicy',
			)));

			if (!empty($options['nocacheheaders']))
			{
				header("Expires: Fri, 01 Jan 1990 00:00:00 GMT");
				header("Cache-Control: no-cache, no-store, max-age=0, must-revalidate");
				header("Pragma: no-cache");
			}


			// apply anti clickjacking / anti ui redress header settings

			$router = self::$instance->router;
			$controller = $router->getController();
			$action = $router->getAction();
			$allowvBulletinFrames = (
				($controller == 'auth' AND $action == 'actionLoginform') OR
				($controller == 'auth' AND $action == 'actionLogin') OR
				($controller == 'relay' AND $action == 'admincp') OR
				($controller == 'relay' AND $action == 'modcp') OR
				// for admin/mod cp login.php
				($controller == 'relay' AND $action == 'legacy') OR
				// upload to server via the ckeditor toolbar image button (upload tab -> send to server)
				($controller == 'uploader' AND $action == 'actionCkeditorinsertimage')
			);

			switch ($options['clickjackingheaders'])
			{
				case '0':
					// don't send the headers
					break;

				case '1':
					// deny all
					if ($allowvBulletinFrames)
					{
						// we're configured to deny all, but we still need to allow framing
						// from the same origin for the instances where we use it, namely
						// the Admin CP and the login form
						header('X-Frame-Options: sameorigin');
						header("Content-Security-Policy: frame-ancestors 'self'");
					}
					else
					{
						header('X-Frame-Options: deny');
						header("Content-Security-Policy: frame-ancestors 'none'");
					}
					break;

				case '2':
					// same origin
					header('X-Frame-Options: sameorigin');
					header("Content-Security-Policy: frame-ancestors 'self'");
					break;

				default:
					// don't send headers
					break;
			}


			// send Content-Security-Policy header if the option has been populated
			if (!empty($options['header_contentsecuritypolicy']))
			{
				if ($allowvBulletinFrames)
				{
					// we need to allow framing for the admin cp and login form
					$csp = $options['header_contentsecuritypolicy'];
					$directives = explode(';', $csp);
					$cspChanged = false;

					foreach ($directives AS $k => $directive)
					{
						// a frame-ancestors directive is present
						if (stripos($directive, 'frame-ancestors') !== false)
						{
							if (stripos($directive, "'none'") !== false)
							{
								// change 'none' to 'self'
								$directives[$k] = str_replace("'none'", "'self'", $directive);
								$cspChanged = true;
							}
						}
					}

					if ($cspChanged)
					{
						$csp = implode(';', $directives);
					}

					header('Content-Security-Policy: ' . $csp);
				}
				else
				{
					header('Content-Security-Policy: ' . $options['header_contentsecuritypolicy']);
				}
			}
		}
		catch (Exception $e)
		{
			if ($e->getMessage() == 'no_vb5_database')
			{
				header('Location: ' . vB5_Template_Options::instance()->get('options.bburl') . '/install/index.php');
				exit;
			}
			else
			{
				vB5_ApplicationAbstract::handleException($e, true);
			}
		}
	}

	public function getRouter()
	{
		return $this->router;
	}

	/**
	 *	Attempt to determine what charset the browser is posting
	 *
	 *	The HTTP/HTML standards make this difficult so we look at a number
	 *	of different things to try to figure it out.
	 *
	 *	@return string the charset string for the request or the empty
	 *		string if it could not be determined.
	 */
	protected function getRequestCharset()
	{
		$charset = '';

		//AJAX is always via UTF-8.  And there probably isn't any header value
		//that is going to explicilty indicate that fact.  So we assume that
		//if we have the Ajax header that its utf-8
		if(self::isAjax())
		{
			$charset = 'utf-8';
		}

		//magic form parameter.  Must be explicitly added to the form but
		//if it added (correctly) the browser will fill it in with the form
		//character set on post see
		//https://www.w3.org/TR/html5/forms.html#attr-fe-name-charset
		else if (!empty($_REQUEST['_charset_']))
		{
			$charset = $_REQUEST['_charset_'];
		}

		//attempt to look it up from the content-type header.  This will
		//almost certainly fail if we are dealing with a form post or ajax call
		else
		{
			if (isset($_SERVER["CONTENT_TYPE"]) AND $_SERVER["CONTENT_TYPE"])
			{
				$pos = stripos($_SERVER["CONTENT_TYPE"], 'CHARSET');
				if ($pos !== false)
				{
					$requestcharset = substr($_SERVER["CONTENT_TYPE"], $pos);
					$temp = explode('=', $requestcharset);
					if (!empty($temp[1]))
					{
						$charset = trim($temp[1]);
					}
				}
			}
		}

		return $charset;
	}

	/**
	 *	Is this an AJAX request.
	 *
	 *	Note that this can be easily spoofed.  Do not rely on for
	 *	anything with security implications.
	 */
	protected static function isAjax()
	{
		return (isset($_SERVER['HTTP_X_REQUESTED_WITH']) AND $_SERVER['HTTP_X_REQUESTED_WITH'] == 'XMLHttpRequest');
	}

	/**
	 *	Convert the PHP input superglobals to the vBulletin charset if it is
	 *	different from what the request charset is.  This is most likely
	 *	on an AJAX request.
	 */
	protected function convertInputArrayCharset()
	{
		$requestcharset = $this->getRequestCharset();

		if ($requestcharset AND !vB5_String::isVbCharset($requestcharset))
		{
			$boardCharset = vB5_String::getCharset();
			$routestring = isset($_REQUEST['routestring']) ? $_REQUEST['routestring'] : null;
			$_COOKIE = vB5_String::toCharset($_COOKIE, $requestcharset, $boardCharset);
			$_GET = vB5_String::toCharset($_GET, $requestcharset, $boardCharset);
			$_POST = vB5_String::toCharset($_POST, $requestcharset, $boardCharset);
			$_REQUEST = vB5_String::toCharset($_REQUEST, $requestcharset, $boardCharset);
			$_FILES = vB5_String::toCharset($_FILES, $requestcharset, $boardCharset);

			if ($routestring !== null)
			{
				// Preserve the utf-8 encoded route string
				$_REQUEST['routestring'] = $routestring;

				if (isset($_GET['routestring']))
				{
					$_GET['routestring'] = $routestring;
				}

				if (isset($_POST['routestring']))
				{
					$_POST['routestring'] = $routestring;
				}
			}
		}
	}

	/**
	 * Displays a vB page for exceptions
	 *
	 *	@param	mixed 	exception
	 *
	 *	@param	bool 	Bypass API and display simple error message
	 */
	public static function handleException($exception, $simple = false)
	{
		if (self::isAjax())
		{
			self::handleExceptionAjax($exception);
		}

		//if we get an exception while processing the error, trying to
		//handle that exception normally doesn't seem likely to succeed.
		try
		{
			$config = vB5_Config::instance();
			$api = Api_InterfaceAbstract::instance();

			if ($config->debug)
			{
				$message = $exception->getMessage();

				if (!$simple)
				{
					$phrase = $api->callApi('phrase', 'fetch', array('phrase' => $message));
					if (!empty($phrase) AND empty($phrase['errors']))
					{
						$message = array_pop($phrase);
					}
				}

				$error = array(
					'message' => $message,
					'file' => $exception->getFile(),
					'line' => $exception->getLine(),
					'trace' => $exception->getTrace(),
				);
			}
			else
			{
				$error = false;
			}

			$normalErrorResponse = true;
			//on a 404 error give 3rd party add ons a chance to do something
			if ($exception instanceof vB5_Exception_404)
			{
				$path = self::instance()->getRouter()->getPath();
				$api->invokeHook('hookFrontendOn404', array('path' => $path, 'normalErrorResponse' => &$normalErrorResponse));
			}

			if($normalErrorResponse)
			{
				if (!headers_sent())
				{
					// Set HTTP Headers
					if ($exception instanceof vB5_Exception_404)
					{
						$options = vB5_Template_Options::instance();
						if ($options->get('options.redirect_404_to_root') == '1')
						{
							self::handlePermanentRedirect($options->get('options.frontendurl'));
						}
						else
						{
							http_response_code(404);

							// if it's a 404, let's have a slightly more appropriate
							// error message than pm_ajax_error_desc
							if (!$error)
							{
								$error = array('message' => $exception->getMessage());
							}
						}
					}
					else
					{
						http_response_code(500);
					}
				}

				self::showErrorPage($error, $simple);
			}
		}
		catch(Exception $e)
		{
			//just bail as gracefully as possible.
			$error = array(
				'message' => $exception->getMessage(),
				'file' => $exception->getFile(),
				'line' => $exception->getLine(),
				'trace' => $exception->getTrace()
			);
			self::minErrorPage($error);
		}

		die();
	}


	/**
	 *	Returning an error message
	 */
	private static function handleExceptionAjax($e)
	{
		if($e instanceof vB5_Exception_Api)
		{
			$result = array('errors' => $e->getErrors());
		}
		else
		{
			$errors = array(array('unexpected_error', $e->getMessage()));
			$config = vB5_Config::instance();
			if ($config->debug)
			{
				$trace = '## ' . $e->getFile() . '(' . $e->getLine() . ") Exception Thrown \n" . $e->getTraceAsString();
				$errors[] = array("exception_trace", $trace);
			}
			$result = array('errors' => $errors);
		}

		echo self::prepJsonSend($result);
		die();
	}

	/**
	 * Displays a vB page for no_permission exception
	 *
	 *	@param	mixed 	exception
	 */
	public static function handleNoPermission($minimal = false)
	{
		http_response_code(403);

		$page = array();
		$page['routeInfo'] = self::getRouteInfo();
		$page['ignore_np_notices'] = self::getIgnoreNPNotices();

		//We want the simplest possible page.
		$templater = new vB5_Template('no_permission_page');
		$templater->registerGlobal('page', $page);
		$templater->registerGlobal('minimal', $minimal);
		echo self::getPreheader() . $templater->render();

		die();
	}

	/**
	 * Displays a vB page for banned users
	 *
	 *	@param	mixed 	exception
	 */
	public static function handleBannedUsers($bannedInfo)
	{
		http_response_code(403);
		self::showBannedPage($bannedInfo);
		die();
	}

	public static function handlePermanentRedirect($url)
	{
		$api = Api_InterfaceAbstract::instance();
		$canusesitebuilder = $api->callApi('user', 'hasPermissions', array('adminpermissions', 'canusesitebuilder'));

		$timeout = vB5_Template_Options::instance()->get('options.301cachelifetime');
		if($canusesitebuilder OR ($timeout <= 0))
		{
			header("Cache-Control: no-cache, no-store, max-age=0, must-revalidate");
		}
		else
		{
			header("Cache-Control: max-age=" . ($timeout * 60 * 60 * 24) . ", must-revalidate");
		}
		header('Location: ' . $url, true, 301);
		exit;
	}

	protected static function minErrorPage($error, $exception = null, $trace = null)
	{
		self::setCharset();

		$config = vB5_Config::instance();

		if ($config->debug)
		{
			if (!empty($error) AND is_array($error))
			{
				echo "Error :" . $error['message'] . ' on line ' . $error['line'] . ' in ' . $error['file'] . "<br />\n";
			}

			if (!empty($trace))
			{
				foreach ($trace as $key => $step)
				{
					$line = "Step $key: " . $step['function'] . '() called' ;

					if (!empty($step['line']))
					{
						$line .= ' on line ' . $step['line'];
					}

					if (!empty($step['file']))
					{
						$line .= ' in ' . $step['file'];
					}

					echo "$line <br />\n";
				}

			}
			if (!empty($exception))
			{
				echo "Exception " . $exception->getMessage() . " on line " . $exception->getLine() . " in " . $exception->getFile() . "<br />\n";
			}
		}
		else
		{
			static::echoOnFireMessage();
		}
		die();
	}

	private static function echoOnFireMessage()
	{
		/*
			If things are on fire (ex. DB is down), and debug mode is not enabled, this gets called.
		*/

		$siteadmin = 'site administrator';
		/*
			TODO: Do we want a new frontend config value for this instead of the DB technicalemail?
		 */
		try
		{
			$backendConfig = vB::getConfig();
			if ($backendConfig AND !empty($backendConfig['Database']['technicalemail']))
			{
				$siteadmin = "<a href=\"mailto:" . $backendConfig['Database']['technicalemail'] . "\">site administrator</a>";
			}
		}
		catch(Exception $e)
		{
			// if fetching the config failed because things are really going down, let's just output the message without fuss.
		}

		echo str_replace('{{{site_administrator}}}', $siteadmin, vB5_ApplicationAbstract::ON_FIRE_MESSAGE);
	}

	protected static function setCharset()
	{
		if (headers_sent())
		{
			// This only works if the preheader template is rendered after this call.
			self::$needCharset = true;
		}
		else
		{
			// ATM I don't see a need to support any other content types, as this is
			// used in a myriad of error handler pages which just displays a message
			// or trace at most. But it wouldn't be too difficult to just add a param to
			// this function to set the content-type appropriately here.
			header('Content-Type: text/html; charset=' . $charset = vB5_String::getCharset());
		}
	}

	/**
	 * Shim function to handle some differences between the existing error message
	 * and the API error format
	 */
	public static function showApiError($errors)
	{
		$newError = array();

		//we only currently handle one error.  Let's take the first (should fix this)
		$newError['message'] = $errors[0];

		//we should attempt to pull out and do something with the stack trace if it exists,
		//but currently the template expects an array rather than the already formatted string
		//that we have and getting into the fixing the template is going to require more work
		//than we currently should be doing.


		self::showErrorPage($newError);
	}

	/**
	 *	Show an error response.
	 *
	 *	@param array $error
	 *	* string|array message -- standard phrase (string or array with params)
	 *	* array trace -- array of stack trace lines (optional)
	 *	* string file -- the file name (optional)
	 *	* string line -- the file line (optional)
	 */
	public static function showErrorPage($error, $simple = false)
	{
		//We want the simplest possible page.
		static $inHandler = false;

		//This block is to prevent error loops. If an error occurs while rendering the page we'll wind up here.
		if ($inHandler OR $simple)
		{
			self::minErrorPage($error);
		}

		$inHandler = true;
		$trace = debug_backtrace(false);

		try
		{
			$page = array();
			$page['routeInfo'] = self::getRouteInfo();
			$page['ignore_np_notices'] = self::getIgnoreNPNotices();

			$templater = new vB5_Template('error_page');
			$templater->registerGlobal('page', $page);
			$templater->register('error', $error);

			$output = self::getPreheader() . $templater->render();
			//not sure what the purpose is here -- output will always have some kind of value, even if its
			if ($output)
			{
				echo $output;
			}
			else
			{
				self::minErrorPage($error, null, $error['trace']);
			}
		}
		catch(Error $e)
		{
			self::minErrorPage($error, $e, $trace);
		}
		catch(Exception $e)
		{
			self::minErrorPage($error, $e, $trace);
		}
	}

	public static function handleFormError($error, $url)
	{
		self::showErrorForm($error, $url);
		die();
	}

	protected static function showErrorForm($error, $url)
	{
		$page = array();
		$page['routeInfo'] = self::getRouteInfo();
		$page['ignore_np_notices'] = self::getIgnoreNPNotices();

		//We want the simplest possible page.
		$templater = new vB5_Template('error_page_form');

		$templater->registerGlobal('page', $page);
		// check to see if any arguments were passed in
		$args = array();
		if(is_array($error))
		{
			$args = is_array($error[1]) ? $error[1] : array($error[1]);
			$error = $error[0];
		}
		$templater->register('error', $error);
		$templater->register('args', $args);
		$templater->register('url', $url);
		echo self::getPreheader() . $templater->render();
	}

	public static function checkState($route = array())
	{
		$response = Api_InterfaceAbstract::instance()->callApi('state', 'checkBeforeView', array('route' => $route));
		if ($response)
		{
			if (self::isAjax())
			{
				if(isset($response['errors']))
				{
					$output = self::prepJsonSend($response);
				}
				else
				{
					/*
						Note, $response['msg'] is the fully rendered error message rather than a phrase title, which
						is usually not what our JS expects.
						Note that sometimes, the message can have HTML in it. For example, when the forum is closed,
						the default "message" (fetched from the 'bbclosedreason' site option) has HTML.
					 */

					$output = self::prepJsonSend(array('error' => array('error_x', $response['msg']), 'state' => $response['state']));
				}

				echo $output;
			}
			else
			{
				if(isset($response['errors']))
				{
					self::showApiError($response['errors']);
				}
				else
				{
					self::showMsgPage($response['title'], $response['msg'], $response['state']);
				}
			}
			die();
		}
	}

	/**
	 * Show a simple and clear message page which contains no widget
	 *
	 * @param string $title Page title. HTML will be escaped.
	 * @param string $msg Message to display. HTML is allowed and the caller must make sure it's valid.
	 * @param string $state The state of the site
	 */
	public static function showMsgPage($title = '', $msg = '', $state = '')
	{
		$page = array();
		$page['routeInfo'] = self::getRouteInfo();
		$page['ignore_np_notices'] = self::getIgnoreNPNotices();

		$page['title'] = $title;
		$page['state'] = $state;

		//We want the simplest possible page.
		$templater = new vB5_Template('message_page');
		$templater->register('page', $page);
		$templater->register('message', $msg);

		echo self::getPreheader() . $templater->render();
	}

	/**
	 * Same as showMsgPage(), but uses the message_page_bare template which uses the minimalistic
	 * bare_header & bare_footer templates.
	 *
	 * @param string $title Page title. HTML will be escaped.
	 * @param string $msg Message to display. HTML is allowed and the caller must make sure it's valid.
	 * @param string $state The state of the site
	 */
	public static function showMsgPageBare($title = '', $msg = '', $state = '')
	{
		$page = array();
		$page['routeInfo'] = self::getRouteInfo();
		$page['ignore_np_notices'] = self::getIgnoreNPNotices();

		$page['title'] = $title;
		$page['state'] = $state;

		//We want the simplest possible page.
		$templater = new vB5_Template('message_page_bare');
		$templater->register('page', $page);
		$templater->register('message', $msg);

		echo self::getPreheader() . $templater->render();
	}

	protected static function showBannedPage($bannedInfo)
	{
		//We want the simplest possible page.
		$page = array();
		$page['routeInfo'] = self::getRouteInfo();
		$page['ignore_np_notices'] = self::getIgnoreNPNotices();

		$templater = new vB5_Template('banned_page');
		$templater->registerGlobal('page', $page);
		$templater->register('bannedInfo', $bannedInfo);
		echo self::getPreheader() . $templater->render();
	}


	/*
	 *	We currently need these is a lot of places so let's keep it DRY
	 */

	/*
	 *	Public because we need this outside of this file.
	 */
	public static function getPreheader()
	{
		// This is called here in case any of the many handleXError()
		// functions forgot to set the charset in the header.
		self::setCharset();

		$templater = new vB5_Template('preheader');

		if (self::$needCharset)
		{
			$templater->register('charset', vB5_String::getTempCharset());
		}
		else
		{
			$templater->register('charset', false);
		}

		$html = $templater->render();
		Api_InterfaceAbstract::instance()->invokeHook('hookFrontendPreheader', array('preheaderHtml' => &$html));

		return $html;
	}

	protected static function getRouteInfo()
	{
			$router = vB5_ApplicationAbstract::instance()->getRouter();
			if (!empty($router))
			{
				$arguments = $router->getArguments();
				return array(
					'routeId' => $router->getRouteId(),
					'arguments' => $arguments,
					'queryParameters' => $router->getQueryParameters()
				);
			}

			return array();
	}

	public static function getIgnoreNPNotices()
	{
		$cookiekey = vB5_Config::instance()->cookie_prefix . 'np_notices_displayed';
		if(isset($_COOKIE[$cookiekey]))
		{
			return explode(',', $_COOKIE[$cookiekey]);
		}
		else
		{
			return array();
		}
	}

	final public static function checkCSRF()
	{
		/*
			Keep this function in sync with vB_Api_State::checkCSRF()
		 */

		$response = Api_InterfaceAbstract::instance()->callApi('state', 'checkCSRF');
		if (!empty($response))
		{
			throw new vB5_Exception($response['error']);
		}

		return true;
	}


	//centralize some basic backend functions that get used by both the controllers
	//and the application light interface

	/**
	 * Internal function for sending JSON.  Sets the headers and other things for
	 * sending as JSON but returns the output to be sent.  Allows for some things
	 * to be done between generating the output and sending it -- things like
	 * setting the content-length header that requires
	 *
	 * @param	mixed	The data (usually an array) to send
	 */
	private static function prepJsonSend($data)
	{
		//This function needs to be kept in sync with the implmentation in applicationlight.php
		if (headers_sent($file, $line))
		{
			throw new Exception("Cannot send response, headers already sent. File: $file Line: $line");
		}

		// We need to convert $data charset if we're not using UTF-8
		if (vB5_String::getTempCharset() != 'UTF-8')
		{
			$data = vB5_String::toCharset($data, vB5_String::getTempCharset(), 'UTF-8');
		}

		//If this is IE9, IE10, or IE11 -- we also need to work around the deliberate attempt to break "is IE" logic by the
		//IE dev team -- we need to send type "text/plain". Yes, we know that's not the standard.
		if (isset($_SERVER['HTTP_USER_AGENT']) && ((strpos($_SERVER['HTTP_USER_AGENT'], 'Trident') !== false)))
		{
			header('Content-type: text/plain; charset=UTF-8');
		}
		else
		{
			header('Content-type: application/json; charset=UTF-8');
		}

		// IE will cache ajax requests, and we need to prevent this - VBV-148
		header('Cache-Control: max-age=0,no-cache,no-store,post-check=0,pre-check=0');
		header('Expires: Sat, 1 Jan 2000 01:00:00 GMT');
		header("Last-Modified: " . gmdate("D, d M Y H:i:s") . " GMT");
		header("Pragma: no-cache");

		return vB5_String::jsonEncode($data);
	}

	/**
	 * Sends the response as a JSON encoded string
	 *
	 * @param	mixed	The data (usually an array) to send
	 */
	public function sendAsJson($data)
	{
		$output = self::prepJsonSend($data);
		echo $output;
	}

	/**
	 * Attempts to close the connection to the browser without
	 * terminating the PHP script.  This is heavily environment specific and
	 * somewhat fragile.
	 * Currently only used by sendAsJsonAndCloseConnection().
	 *
	 * @param	String	Content to echo back to the browser along with the
	 * 					headers to signal connection termination.
	 */
	public function outputToBrowserAndCloseConnection($output)
	{
		ignore_user_abort(true);
		@set_time_limit(0);

		//This will attempt to close the connection. It will work for mod_php. I'm
		//not sure if it works for basic fastcgi, though we will try unless the server is IIS.
		//The logic of that exception goes *way* back and I don't want to change it
		//without some testing. We do not attempt it for php-fpm since we have a
		//better way of doing business.
		//
		//Note that setting the Content-Length header can cause problems, particularly
		//with bad versions of apache mod_deflate so that we only want to set it
		//if absolutely necesary.
		if (!function_exists('fastcgi_finish_request'))
		{
			// browser will think there is no more data if content-length is what is returned
			// regardless of how long the script continues to execute, apart from IIS + CGI
			$sapi_name = php_sapi_name();
			if (!(strpos($_SERVER['SERVER_SOFTWARE'], 'Microsoft-IIS') !== false AND strpos($sapi_name, 'cgi') !== false))
			{
				$outputLength = strlen($output);
				header('Content-Length: ' . $outputLength);
				header('Connection: Close');
			}
		}

		echo $output;

		// ob_end_flush and flush are needed for the browser to think the request is complete
		if (ob_get_level())
		{
			ob_end_flush();
		}
		flush();

		//this is intended to make the detach functionality work for people running php-fpm.
		if (function_exists('fastcgi_finish_request'))
		{
			fastcgi_finish_request();
		}

		// If we keep any sessions open, then there's a possibility that it
		// could needlessly block the next handling. We should always try
		// to close writing to the session asap so we don't maintain a write
		// lock on it.
		// However, leaving this commented out until we can get a handle on
		// what shutdown processes may *actually* write to the session.
		// In practice, this condition was never hit. But rather, the server's
		// utilization of persistent connections forced multiple subsequent
		// requests to use the same socket/thread & block each other.
		/*
		if(session_status() == PHP_SESSION_ACTIVE)
		{
			// http://konrness.com/php5/how-to-prevent-blocking-php-requests/
			// We need to close this session so any lengthy post-close processing doesn't block the next request.
			// Without this multiple ajax requests each with long post-close processing can block each other.
			session_write_close();
		}
		*/

	}

	/**
	 * Sends the response as a JSON encoded string
	 * Attempts to close the connection to the browser without
	 * terminating the PHP script.  This is heavily environment specific and
	 * somewhat fragile.
	 *
	 * @param	mixed	The data (usually an array) to send -- if data is an
	 * 	array function will add an "note" field indicating that the
	 * 	data was returned prior to processing (which can obscure errors)
	 * 	Parameter defaults to an empty array if there is no real data to
	 * 	send (which is common when terminating before substantial processing)
	 */
	public function sendAsJsonAndCloseConnection($responseToSendAsJson = array())
	{
		//send a note to help people debugging know that the call
		//will appear to succeed regardless of what actually happens.
		if (is_array($responseToSendAsJson) AND !isset($responseToSendAsJson['note']))
		{
			$responseToSendAsJson['note'] = 'Returned before processing';
		}
		$output = self::prepJsonSend($responseToSendAsJson);

		return $this->outputToBrowserAndCloseConnection($output);
	}


	public function allowRedirectToUrl($url)
	{
		if (empty($url))
		{
			return false;
		}

		$options = vB5_Template_Options::instance();

		if ($options->get('options.redirect_whitelist_disable'))
		{
			return true;
		}

		$foundurl = false;

		if ($urlinfo = @vB5_String::parseUrl($url))
		{
			if (!$urlinfo['scheme'])
			{
				$foundurl = true; // Relative redirect.
			}
			else
			{
				$whitelist = array();
				if ($options->get('options.redirect_whitelist'))
				{
					$whitelist = explode("\n", trim($options->get('options.redirect_whitelist')));
				}

				// Add the base and core urls to the whitelist
				$baseinfo = @vB5_String::parseUrl($options->get('options.frontendurl'));
				$coreinfo = @vB5_String::parseUrl($options->get('options.bburl'));

				$baseurl = "{$baseinfo['scheme']}://{$baseinfo['host']}";
				$coreurl = "{$coreinfo['scheme']}://{$coreinfo['host']}";

				array_unshift($whitelist, strtolower($baseurl));
				array_unshift($whitelist, strtolower($coreurl));

				$vburl = strtolower($url);
				foreach ($whitelist AS $urlx)
				{
					$urlx = trim($urlx);
					if ($vburl == strtolower($urlx) OR strpos($vburl, strtolower($urlx) . '/', 0) === 0)
					{
						$foundurl = true;
						break;
					}
				}
			}
		}

		return $foundurl;
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 103671 $
|| #######################################################################
\*=========================================================================*/
