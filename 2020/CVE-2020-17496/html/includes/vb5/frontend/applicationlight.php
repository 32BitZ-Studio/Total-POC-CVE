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

/**
 * Light version of the application, for fixed routes like getting phrases, options, etc. At the time of writing this, the
 * biggest improvement is skipping the route parsing. There's a lot of processing needed for handling forum-type, channel-type urls
 * that isn't needed for the static routes.
 *
 * @package		vBulletin presentation
 */

class vB5_Frontend_ApplicationLight extends vB5_ApplicationAbstract
{
	//This is just the array of routing-type information.  It defines how the request will be processed.
	protected $application = array();

	//This defines the routes that can be handled by this class.
	protected static $quickRoutes = array
	(
		'ajax/loaddata' => array(
			'handler'     => 'loadData',
			'requirePost' => true,
		),
		'ajax/api/options/fetchValues' => array(
			'handler'     => 'fetchOptions',
			'requirePost' => true,
		),
		'filedata/fetch' => array(
			'handler'     => 'fetchImage',
			'requirePost' => false,
		),
		'external' => array(
			'controller'     => 'external',
			'callcontroller' => true,
			'method'         => 'output',
			'requirePost'    => false,
		),
	);

	/**
	 * @var array Quick routes that match the beginning of the route string
	 */
	protected static $quickRoutePrefixMatch = array(
		// note, keep this before ajax/api. More specific routes should come before
		// less specific ones, to allow the prefix check to work correctly, see constructor.
		'ajax/apidetach' => array(
			'handler'     => 'handleAjaxApiDetached',
			'requirePost' => true,
		),
		'ajax/api' => array(
			'handler'     => 'handleAjaxApi',
			'requirePost' => true,
		),
		'ajax/render' => array(
			'handler'     => 'callRender',
			'requirePost' => true,
		),
	);

	protected $userid;
	protected $languageid;

	/** Tells whether this class can process this request
	 *
	 * @return bool
	 */
	public static function isQuickRoute()
	{
		if (empty($_REQUEST['routestring']))
		{
			return false;
		}

		if (isset(self::$quickRoutes[$_REQUEST['routestring']]))
		{
			return true;
		}

		foreach (self::$quickRoutePrefixMatch AS $prefix => $route)
		{
			if (substr($_REQUEST['routestring'], 0, strlen($prefix)) == $prefix)
			{
				return true;
			}
		}

		return false;
	}

	/**Standard constructor. We only access applications through init() **/
	protected function __construct()
	{
		if (empty($_REQUEST['routestring']))
		{
			return false;
		}

		if (isset(self::$quickRoutes[$_REQUEST['routestring']]))
		{
			$this->application = self::$quickRoutes[$_REQUEST['routestring']];
			return true;
		}

		foreach (self::$quickRoutePrefixMatch AS $prefix => $route)
		{
			if (substr($_REQUEST['routestring'], 0, strlen($prefix)) == $prefix)
			{
				$this->application = $route;
				return true;
			}
		}

		return false;
	}

	/**
	 * This is the standard way to initialize an application
	 *
	 * @param 	string	location of the configuration file
	 *
	 * @return this application object
	 */
	public static function init($configFile)
	{
		self::$instance = new vB5_Frontend_ApplicationLight();

		$config = vB5_Config::instance();
		$config->loadConfigFile($configFile);
		$corePath = vB5_Config::instance()->core_path;
		//this will be set by vb::init
		//define('CWD', $corePath);
		define('CSRF_PROTECTION', true);
		define('VB_AREA', 'Presentation');
		require_once ($corePath . "/vb/vb.php");
		vB::init();
		vB::setRequest(new vB_Request_WebApi());

		self::$instance->convertInputArrayCharset();

		return self::$instance;
	}

	/**
	 * Executes the application. Normally this means to get some data. We usually return in json format.
	 *
	 * @return bool
	 * @throws vB_Exception_Api
	 */
	public function execute()
	{
		if (empty($this->application))
		{
			throw new vB_Exception_Api('invalid_request');
		}

		// These handlers must require POST request method, but POST requests can accept parameters passed in via
		// both the post body ($_POST) and querystring in the url ($_GET)
		if ($this->application['requirePost'])
		{
			if (strtoupper($_SERVER['REQUEST_METHOD']) !== 'POST')
			{
				throw new vB5_Exception('Incorrect HTTP Method. Please use a POST request.');
			}

			// Also require a CSRF token check.
			static::checkCSRF();
		}

		$serverData = array_merge($_GET, $_POST);

		if (!empty($this->application['handler']) AND method_exists($this, $this->application['handler']))
		{
			$app = $this->application['handler'];
			call_user_func(array($this, $app), $serverData);

			return true;
		}
		else if ($this->application['callcontroller'])
		{
			$response = $this->callController(
				$this->application['controller'],
				$this->application['method']
			);

			// using an array will let us have more control on the response.
			// we can easily extend to support printing different kind of outputs.
			echo $response['response'];

			return true;
		}
		else
		{
			//We need to create a session
			$result = Api_InterfaceAbstract::instance()->callApi(
				$this->application['controller'],
				$this->application['method'],
				$serverData,
				true
			);
		}

		$controller = new vB5_Frontend_Controller();
		$controller->sendAsJson($result);

		return true;
	}

	/**
	 * Calls a controller action and returns the response.
	 *
	 * @param 	string 	Controller name.
	 * @param 	string 	Controller action.
	 *
	 * @return 	array 	Information of controller call:
	 *					- Response => the result from calling the controller action.
	 *
	 */
	private function callController($controller, $action)
	{
		$controller = ucfirst(strtolower($controller));
		$action = ucfirst(strtolower($action));
		$controllerClass = 'vB5_Frontend_Controller_' . $controller;
		$controllerMethod = 'action' . $action;

		if (class_exists($controllerClass) AND method_exists($controllerClass, $controllerMethod))
		{
			$controller = new $controllerClass();
			return array('response' => $controller->$controllerMethod());
		}

		return array('response' => '');
	}

	protected function loadData($serverData)
	{
		$options = $serverData['options'] ?? array();
		$phrases = $serverData['phrases'] ?? array();

		$api = Api_InterfaceAbstract::instance(Api_InterfaceAbstract::API_LIGHT);

		$phraseValues = $api->callApi(
			'phrase',
			'getPhrases',
			array($phrases)
		);

		if(isset($phraseValues['errors']))
		{
			$this->sendAsJson($phraseValues);
			return;
		}

		$optionValues = $api->callApi(
			'options',
			'fetchValues',
			array($options)
		);

		//it's just this side of possible that we'll have an option called "errors"
		//and unlike phrases we don't correctly return this as a subfield of the result.
		if(isset($optionValues['errors']) AND is_array($optionValues['errors']))
		{
			$this->sendAsJson($optionValues);
			return;
		}

		$this->sendAsJson(array(
			'phrases' => $phraseValues['phrases'],
			'options' => $optionValues,
		));
	}


	/**
	 * This gets option data from an ajax request.
	 *
	 * @param array Array of server data (from $_POST and/or $_GET, see execute())
	 */
	protected function fetchOptions($serverData)
	{
		$options = $serverData['options'] ?? array();

		$result = Api_Interface_Collapsed::callApiStatic(
			'options',
			'fetchStatic',
			array(
				'options' => $options,
			),
			true
		);

		$this->sendAsJson($result);
	}

	/**
	 * Renders a template from an ajax call
	 *
	 * @param array Array of server data (from $_POST and/or $_GET, see execute())
	 */
	protected function callRender($serverData)
	{
		$routeInfo = explode('/', $serverData['routestring']);

		if (count($routeInfo) < 3)
		{
			throw new vB5_Exception_Api('ajax', 'render', array(), 'invalid_request');
		}

		$templateName = $routeInfo[2];
		if ($templateName == 'widget_php')
		{
			$result = array(
				'template' => '',
				'css_links' => array(),
			);
		}
		else
		{
			$this->router = new vB5_Frontend_Routing();
			$this->router->setRouteInfo(array(
				'action'          => 'actionRender',
				'arguments'       => $serverData,
				'template'        => $templateName,
				// this use of $_GET appears to be fine,
				// since it's setting the route query params
				// not sending the data to the template
				// render
				'queryParameters' => $_GET,
			));
			Api_InterfaceAbstract::setLight();
			$result = vB5_Template::staticRenderAjax($templateName, $serverData);
		}

		$this->sendAsJson($result);
	}

	/**
	 * This handles an ajax api call.
	 *
	 * @param array Array of server data (from $_POST and/or $_GET, see execute())
	 */
	protected function handleAjaxApi($serverData)
	{
		$routeInfo = explode('/', $serverData['routestring']);

		if (count($routeInfo) < 4)
		{
			throw new vB5_Exception_Api('ajax', 'api', array(), 'invalid_request');
		}

		//we use : to delineate packages in controller names, but that's a reserved
		//character in the url structure so we use periods in URLs.
		$controller = str_replace('.', ':', $routeInfo[2]);

		$this->sendAsJson(Api_InterfaceAbstract::instance(Api_InterfaceAbstract::API_LIGHT)->callApi(
			$controller,
			$routeInfo[3],
			$serverData,
			true
		));
	}

	/**
	 * This handles an ajax api call, detatched from the current request
	 *
	 * @param array Array of server data (from $_POST and/or $_GET, see execute())
	 */
	protected function handleAjaxApiDetached($serverData)
	{
		// Keep this function in sync with vB5_Frontend_Controller::sendAsJsonAndCloseConnection()
		// TODO: Make the controller function public and have this call it.
		// The main reason I didn't do this now is because there are some differences between this class's
		// sendAsJson() & the controller, and the changes were starting to get a bit too big for this particular
		// JIRA than I was comfortable with.

		//make sure this is a valid request before detaching.
		$routeInfo = explode('/', $serverData['routestring']);
		if (count($routeInfo) < 4)
		{
			throw new vB5_Exception_Api('ajax', 'apidetach', array(), 'invalid_request');
		}

		//if we don't get the api before we close the connection we can end up failing
		//to set cookies, which will cause the entire call to fail.  That is bad.
		$api = Api_InterfaceAbstract::instance(Api_InterfaceAbstract::API_LIGHT);

		$this->sendAsJsonAndCloseConnection();
		//we use : to delineate packages in controller names, but that's a reserved
		//character in the url structure so we use periods in URLs.
		$controller = str_replace('.', ':', $routeInfo[2]);

		//don't do anything with the return, we've already let the broswer go.
		$api->callApi(
			$controller,
			$routeInfo[3],
			$serverData,
			true
		);
	}

	/**
	 * Outputs an attachment
	 *
	 * @param array Array of server data (from $_POST and/or $_GET, see execute())
	 */
	protected function fetchImage($serverData)
	{
		$api = Api_InterfaceAbstract::instance('light');

		$request = array(
			'id'          => 0,
			'type'        => '',
			'includeData' => true,
		);

		if (isset($serverData['type']) AND !empty($serverData['type']))
		{
			$request['type'] = $serverData['type'];
		}
		else if (!empty($serverData['thumb']) AND intval($serverData['thumb']))
		{
			$request['type'] = 'thumb';
		}

		$isAttachment = false;
		$fileInfo = array();
		if (!empty($serverData['id']) AND intval($serverData['id']))
		{
			// Don't put an intval() call in an if condition and then subsequently
			// *use* the non-intval'ed value. Normally, you'd use intval to
			// typecast *before* the if condition.
			$request['id'] = intval($serverData['id']);

			set_error_handler(array($this, 'handleImageError'), E_ALL | E_STRICT ) ;

			// we can have type photo nodes coming in via the id parameter
			// when text.previewimage is used in article listings or the
			// content slider module.
			$nodeInfo = $api->callApi('node', 'getNode', array('nodeid' => $request['id']));
			if(!isset($nodeInfo['errors']))
			{
				$contentType = $api->callApi('contenttype', 'fetchContentTypeClassFromId', array('contenttypeid' => $nodeInfo['contenttypeid']));
				if ($contentType == 'Photo')
				{
					$fileInfo = $api->callApi('content_photo', 'fetchImageByPhotoid', $request);
				}
				else
				{
					$fileInfo = $api->callApi('content_attach', 'fetchImage', $request);
					$isAttachment = true;
				}
			}
		}
		else if (!empty($serverData['filedataid']) AND intval($serverData['filedataid']))
		{
			// Don't put an intval() call in an if condition and then subsequently
			// *use* the non-intval'ed value. Normally, you'd use intval to
			// typecast *before* the if condition.
			$request['id'] = intval($serverData['filedataid']);

			if (!empty($serverData['attachmentnodeid']))
			{
				$request['attachmentnodeid'] = (int) $serverData['attachmentnodeid'];
				/*
					$isAttachment note :
					This is used by the edit form (contententry_panel_attachments_item &
					editor_gallery_photoblock templates), so I think we can skip the "is
					this a photo or attachment" check and skip incrementing the view count.
				 */
			}

			set_error_handler(array($this, 'handleImageError'), E_ALL | E_STRICT ) ;
			$fileInfo = $api->callApi('filedata', 'fetchImageByFiledataid', $request);
		}
		else if (!empty($serverData['photoid']) AND intval($serverData['photoid']))
		{
			// Don't put an intval() call in an if condition and then subsequently
			// *use* the non-intval'ed value. Normally, you'd use intval to
			// typecast *before* the if condition.
			$request['id'] = intval($serverData['photoid']);
			$fileInfo = $api->callApi('content_photo', 'fetchImageByPhotoid', $request);
		}
		else if (!empty($serverData['linkid']) AND intval($serverData['linkid']))
		{
			// Don't put an intval() call in an if condition and then subsequently
			// *use* the non-intval'ed value. Normally, you'd use intval to
			// typecast *before* the if condition.
			$request['id'] = intval($serverData['linkid']);
			$request['includeData'] = false;
			set_error_handler(array($this, 'handleImageError'), E_ALL | E_STRICT ) ;
			$fileInfo = $api->callApi('content_link', 'fetchImageByLinkId', $request);
		}
		else if (!empty($serverData['attachid']) AND intval($serverData['attachid']))
		{
			// Don't put an intval() call in an if condition and then subsequently
			// *use* the non-intval'ed value. Normally, you'd use intval to
			// typecast *before* the if condition.
			$request['id'] = intval($serverData['attachid']);
			set_error_handler(array($this, 'handleImageError'), E_ALL | E_STRICT ) ;
			$fileInfo = $api->callApi('content_attach', 'fetchImage', $request);
			$isAttachment = true;
		}
		else if (!empty($serverData['channelid']) AND intval($serverData['channelid']))
		{
			// Don't put an intval() call in an if condition and then subsequently
			// *use* the non-intval'ed value. Normally, you'd use intval to
			// typecast *before* the if condition.
			$request['id'] = intval($serverData['channelid']);
			set_error_handler(array($this, 'handleImageError'), E_ALL | E_STRICT ) ;
			$fileInfo = $api->callApi('content_channel', 'fetchChannelIcon', $request);
		}

		if (!empty($fileInfo['filedata']))
		{
			header('ETag: "' . $fileInfo['filedataid'] . '"');
			header('Accept-Ranges: bytes');
			header('Content-Transfer-Encoding: binary');

			$fileInfo['extension'] = strtolower($fileInfo['extension']);
			if (in_array($fileInfo['extension'], array('jpg', 'jpe', 'jpeg', 'gif', 'png')))
			{
				header('Content-Disposition: inline; filename="image_' . $fileInfo['filedataid'] .  '.' . $fileInfo['extension'] . '"');
			}
			else
			{
				$attachInfo = $api->callApi('content_attach', 'fetchAttachByFiledataids', array('filedataids' => array($fileInfo['filedataid'])));

				// force files to be downloaded because of a possible XSS issue in IE
				header('Content-Disposition: attachment; filename="' . $attachInfo[$fileInfo['filedataid']]['filename'] . '"');
			}

			// set up the output; either the full file or a range of bytes
			$output = '';
			if (isset($_SERVER['HTTP_RANGE']))
			{
				// output a specific range of bytes

				// set the default range to the whole file
				$rangeStart = 0;
				$rangeEnd = $fileInfo['filesize'] - 1;
				$multipleRanges = false;

				// parse the range header
				if (preg_match('#bytes\s*=\s*(\d+)\s*-\s*(\d*)(\D?.*)#i', $_SERVER['HTTP_RANGE'], $matches))
				{
					$rangeStart = (int) $matches[1];
					if (!empty($matches[2]))
					{
						$rangeEnd = (int) $matches[2];
					}
					$multipleRanges = (!empty($matches[3]) AND strpos($matches[3], ',') !== false);
				}

				$rangeLength = $rangeEnd - $rangeStart + 1;

				$isValidRange = (
					$rangeLength > 0
					AND
					$rangeLength <= $fileInfo['filesize']
					AND
					$rangeStart >= 0
					AND
					$rangeStart < $fileInfo['filesize'] - 1
					AND
					$rangeEnd > 0
					AND
					$rangeEnd < $fileInfo['filesize']
					AND
					$rangeStart < $rangeEnd
					AND
					!$multipleRanges
				);

				header('Cache-Control: public, must-revalidate, max-age=0');
				header('Pragma: no-cache');
				header('Last-Modified: ' . gmdate('D, d M Y H:i:s', $fileInfo['dateline']) . ' GMT');

				if ($isValidRange)
				{
					header('HTTP/1.1 206 Partial Content');
					header('Content-Length: ' . $rangeLength);
					header('Content-Range: bytes ' . $rangeStart . '-' . $rangeEnd . '/' . $fileInfo['filesize']);
					if ($rangeStart == 0 AND $rangeLength == $fileInfo['filesize'])
					{
						$output = $fileInfo['filedata'];
					}
					else
					{
						// substr acts on bytes, not characters in the data.
						// mbstring.func_overload can mess with that, but it's deprecated and shouldn't be used.
						$output = substr($fileInfo['filedata'], $rangeStart, $rangeLength);
					}
				}
				else
				{
					header('HTTP/1.1 416 Requested Range Not Satisfiable');
					header('Content-Length: 0');
					header('Content-Range: bytes 0-' . ($fileInfo['filesize'] - 1) . '/' . $fileInfo['filesize']);
					$output = '';
				}
			}
			else
			{
				// output the entire file
				header('Content-Length: ' . $fileInfo['filesize']);
				header('Cache-control: max-age=31536000, private');
				header('Expires: ' . gmdate("D, d M Y H:i:s", time() + 31536000) . ' GMT');
				header('Pragma:');
				header('Last-Modified: ' . gmdate('D, d M Y H:i:s', $fileInfo['dateline']) . ' GMT');
				$output = $fileInfo['filedata'];
			}

			// Attachment type headers specified in the Admin CP
			// do this right before sending output so the headers can
			// potentially override ones we've already set
			foreach ($fileInfo['headers'] AS $header)
			{
				header($header);
			}

			echo $output;

			// Attachment view tracking. If below process takes too long, we'll want to send the output & close the connection
			// to browser via $this->outputToBrowserAndCloseConnection($output) instead of echo $output above.
			$options = $api->callApi('options', 'fetchStatic', array('attachmentviewstrack'));
			$doAttachIncrement = !empty($options['attachmentviewstrack']);
			if ($isAttachment AND $doAttachIncrement)
			{
				// If we're serving the file in chunks, only increment once.
				// For simplicity, let's increment at the start, though incrementing at the end
				// might make more sense (in case the file is very large and download is cancelled)
				if (!isset($_SERVER['HTTP_RANGE']) OR
					(
						!empty($isValidRange) AND isset($rangeStart) AND $rangeStart== 0
					)
				)
				{
					// Currently if $isAttachment is true $request['id'] is set, and is the attachment's nodeid.
					$assertor = vB::getDbAssertor();
					$assertor->assertQuery('vBForum:incrementAttachCounter', array('nodeid' => $request['id']));
				}
			}

		}
		else
		{
			$this->invalidFileResult($api);
		}
	}

	private function invalidFileResult($api)
	{
		$apiresult = $api->callApi('phrase', 'renderPhrases', array(array('invalid_file_specified' => 'invalid_file_specified')));
		if (!isset($apiresult['errors']))
		{
			$error = $apiresult['phrases']['invalid_file_specified'];
		}
		else
		{
			//if we can't look up the phrase let's return *something*
			$error = "Invalid File Specified";
		}

		header("Content-Type: text/plain");
		header("Content-Length: " . strlen($error));
		http_response_code(404);
		echo $error;
		exit;
	}

	/**
	 * Handle and error for an image
	 *
	 * If it's a fatal error we will display the invalid file response.  Otherwise we'll attempt
	 * to supress any output and hope for the best (since any messages will screw up the image)
	 * In either case if we would normally display/log the message we will attempt to mimic
	 * that behavior.
	 */
	public function handleImageError($errno, $errstr, $errfile, $errline)
	{
		//Note that not all of these error codes are trappable and therefore
		//many cannot actually occur here.  They are listed for completeness
		//and possible future proofing if that changes.
		$label = "";
		$fatal = false;
		switch($errno)
		{
			case E_STRICT:
				$label = "Strict standards";
				break;

			case E_DEPRECATED:
			case E_USER_DEPRECATED:
				$label = "Notice";
				break;

			case E_WARNING:
			case E_CORE_WARNING:
			case E_USER_WARNING:
			case E_COMPILE_WARNING:
				$label = "Warning";
				break;

			case E_NOTICE:
			case E_USER_NOTICE:
				$label = "Notice";
				break;

			case E_ERROR:
			case E_PARSE:
			case E_CORE_ERROR:
			case E_COMPILE_ERROR:
			case E_USER_ERROR:
			case E_RECOVERABLE_ERROR:
				$label = "Fatal error";
				$fatal = true;
				break;

			//if we don't know what the error type is, php added it after 5.6
			//we'll punt to the system error handler because we simply don't know
			//what we are dealing with.  This risks leaking the path on files, but
			//that's not as bad as exiting on a warning or not exiting on a fatal error
			default:
				return false;
				break;
		}

		//php changed the way dispay_errors is reported in version 5.2.  We probably don't
		//have to care about the old way, but this covers all of the bases.
		$display_errors = in_array(strtolower(ini_get('display_errors')), array('on', '1'));
		if ((error_reporting() & $errno) AND $display_errors)
		{
			$message = "$label: $errstr in $errfile on line $errline";

			//try to mimic the logging behavior of the default function
			if(ini_get('log_errors'))
			{
				error_log($message);
			}
		}

		if ($fatal)
		{
			$api = Api_InterfaceAbstract::instance('light');
			$this->invalidFileResult($api);
		}

		//we've got this -- no need to bother the default handler
		return true;
	}

	/**
	 * Displays a vB page for exceptions
	 *
	 *	@param	mixed 	exception
	 *	@param	bool 	Bypass API and display simple error message
	 */
	public static function handleException($exception, $simple = false)
	{
		$config = vB5_Config::instance();

		if ($config->debug)
		{
			echo "Exception ". $exception->getMessage() . ' in file ' . $exception->getFile() . ", line " . $exception->getLine() .
				"<br />\n". $exception->getTrace();
		}

		if (!headers_sent())
		{
			// Set HTTP Headers
			if ($exception instanceof vB5_Exception_404)
			{
				http_response_code(404);
			}
			else
			{
				http_response_code(500);
			}
		}
		die();
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 103812 $
|| #######################################################################
\*=========================================================================*/
