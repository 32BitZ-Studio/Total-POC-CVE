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

abstract class vB_Api
{
	use vB_Trait_NoSerialize;

	/**
	 * We want API subclasses to access the instances only through getters
	 * @var array
	 */
	private static $instancesRaw;
	private static $instances;
	private static $wrappers;
	// configuration

	/**
	 * Indicates whether the API was disabled
	 * @var bool
	 */
	protected $disabled = false;

	/**
	 * Contains white listed methods which act as normal when API is disabled
	 * no matter of special scenarios like forum closed, password expiry, ip ban and others.
	 *
	 * @var array $disableWhiteList
	 */
	protected $disableWhiteList = array();

	/**
	 * Contains white listed methods which return a false response when API is disabled
	 * in special scenarios like forum closed, password expiry, ip ban and others.
	 *
	 * @var array $disableFalseReturnOnly
	 */
	protected $disableFalseReturnOnly = array();

	/**
	 * API Controller
	 *
	 * @var string
	 */
	protected $controller;

	/**
	 * Database object.
	 *
	 * @var	 vB_Database
	 */
	protected $db;


	public static function getApiClassName($controller)
	{
		list($c, $package) = self::getApiClassNameInternal($controller);
		return $c;
	}

	protected static function getApiClassNameInternal($controller)
	{
		/*
			Keep this in sync with vB_Library::getLibraryClassNameInternal()
		 */
		$values = explode(':', $controller);
		$package = '';
		if(count($values) == 1)
		{
			$c = 'vB_Api_' . ucfirst(strtolower($controller));
		}
		else
		{
			list($package, $controller) = $values;
			// todo: class names might have uppercases to help with readability, but
			// productid/package-name may be in lowercase.
			// Iff productid is always in lowercase this strtolower is OK to do,
			// but if we allow uppercases & allow case to define uniqueness of products,
			// this is NOT ok.
			// This is here to do stuff like call TwitterLogin:ExternalLogin API for the
			// twitterlogin package.
			$package = strtolower($package);
			$c = ucfirst($package) . '_Api_' . ucfirst(strtolower($controller));
		}

		return array($c, $package);
	}

	protected static function getApiClass($controller, $errorCheck = true)
	{
		if (!$controller)
		{
			//The error originally referred to php 5.2, but the minumum requirement for vB5 is php 5.3
			throw new Exception("The API should be called as vB_Api::instance('Name'), not vB_Api_Name::instance()");
		}
		else
		{
			list($c, $package) = self::getApiClassNameInternal($controller);
			if($package)
			{
				$products = vB::getDatastore()->getValue('products');
				if(empty($products[$package]))
				{
					throw new vB_Exception_Api('api_class_product_x_is_disabled', array($controller, $package));
				}
			}
			// Need to bypass this if not internal as calls may be to a custom API extension class.
			if ($errorCheck)
			{
				if (!class_exists($c))
				{
					throw new Exception(sprintf("Can't find class %s", htmlspecialchars($c)));
				}

				if (!is_subclass_of($c, 'vB_Api'))
				{
					throw new Exception(sprintf('Class %s is not a subclass of vB_Api', htmlspecialchars($c)));
				}
			}

			//we don't always check the instanceof case
			//vB_Api_Extension techncially inherits from vB_Api, but it probably shouldn't
			//calling it via vB_Api::instance() doesn't work anyway and it would be worse if it
			//actually did.
			if (
				strcasecmp($c, 'vB_Api_LogWrapper') == 0 OR
				strcasecmp($c, 'vB_Api_Wrapper') == 0 OR
				strcasecmp($c, 'vB_Api_Extensions') == 0
			)
			{
				throw new Exception(sprintf('Class %s is not a valid API class', htmlspecialchars($c)));
			}
		}

		return $c;
	}

	/**
	 *	Wrap the api object with the log wrapper class if needed.
	 */
	private static function wrapLoggerIfNeeded($controller, $api_object)
	{
		//only check the options once
		static $needLog = NULL;
		if (is_null($needLog))
		{
			$config = vB::getConfig();
			$needLog = (!empty($config['Misc']['debuglogging']));
		}

		if ($needLog)
		{
			return new vB_Api_Logwrapper($controller,  $api_object);
		}
		else
		{
			return $api_object;
		}
	}

	/**
	 * Returns an instance of the API object which doesn't handle exceptions
	 * This should only be used in other API objects, not for clients of the API
	 * @param string $controller -- name of the API controller to load
	 * @param bool $refresh_cache -- true if we want to force the cache to update with a new api object
	 *   primarily intended for testing
	 * @return vB_Api
	 */
	public static function instanceInternal($controller, $refresh_cache = false)
	{
		$c = self::getApiClass($controller);

		if (!isset(self::$instances[$c]) OR $refresh_cache)
		{
			if (!isset(self::$instancesRaw[$c]) OR $refresh_cache)
			{
				self::$instancesRaw[$c] = new $c;
				self::$instancesRaw[$c]->setController($controller);
			}

			self::$instances[$c] = self::wrapLoggerIfNeeded($controller, self::$instancesRaw[$c]);
		}

		return self::$instances[$c];
	}

	/**
	 * Returns an instance of the API object which translates exceptions to an array
	 * Use this method for API clients.
	 * @param string $controller -- name of the API controller to load
	 * @param bool $refresh_cache -- true if we want to force the cache to update with a new api object
	 *   primarily intended for testing
	 * @return vB_Api
	 */
	public static function instance($controller, $refresh_cache = false)
	{
		$c = self::getApiClass($controller, false);

		if (!isset(self::$wrappers[$c]) OR $refresh_cache)
		{
			if (!isset(self::$instancesRaw[$c]) OR $refresh_cache)
			{
				if (class_exists($c))
				{
					self::$instancesRaw[$c] = new $c;
					self::$instancesRaw[$c]->setController($controller);
				}
				else
				{
					self::$instancesRaw[$c] = new vB_Api_Null();
				}
			}

			self::$wrappers[$c] = new vB_Api_Wrapper($controller, self::$instancesRaw[$c]);
			self::$wrappers[$c] = self::wrapLoggerIfNeeded($controller, self::$wrappers[$c]);
		}

		return self::$wrappers[$c];
	}


	/**
	*	Clears all previously loaded API objects.
	*
	* Intended for use in tests where the loading pattern can cause issues
	*	with objects that cache thier own data.
	*
	*/
	public static function clearCache()
	{
		self::$wrappers = array();
		self::$instances = array();
		self::$instancesRaw = array();
		vB_Api_Extensions::resetExtensions();
	}

	/**
	 * Call the given api function by name with a named arguments list.
	 * Used primarily to translate REST requests into API calls.
	 *
	 * @param string $method -- the name of the method to call
	 * @param array $args -- The list of args to call.  This is a name => value map that will
	 *   be matched up to the names of the API method.  Order is not important.  The names are
	 *   case sensitive.
	 *
	 * @return The return of the method or an error if the method doesn't exist, or is
	 *   static, a constructor or destructor, or otherwise shouldn't be callable as
	 *   and API method.  It is also an error if the value of a paramater is not provided
	 *   and that parameter doesn't have a default value.
	 */
	public function callNamed()
	{
		list ($method, $args) = func_get_args();

		if (!is_callable(array($this, $method)))
		{
			// if the method does not exist, an extension might define it
			return;
		}

		$reflection = new ReflectionMethod($this, $method);

		if(
			$reflection->isConstructor() OR
			$reflection->isDestructor() OR
			$reflection->isStatic() OR
			$method == "callNamed"
		)
		{
			//todo return error message
			return;
		}

		$php_args = array();
		foreach($reflection->getParameters() as $param)
		{
			// the param value can be null, so don't use isset
			if(array_key_exists($param->getName(), $args))
			{
				$php_args[] = &$args[$param->getName()];
			}
			else
			{
				if ($param->isDefaultValueAvailable())
				{
					$php_args[] = $param->getDefaultValue();
				}
				else
				{
					throw new Exception('Required argument missing: ' . htmlspecialchars($param->getName()));
				}
			}
		}

		return $reflection->invokeArgs($this, $php_args);
	}

	/**
	 * Returns vb5 api method name.
	 * May alter request array.
	 * @param string $method -- vb4 method name
	 * @param array $request -- $_REQUEST array for this api request
	 * @return string
	 */
	public static function map_vb4_input_to_vb5($method, &$request)
	{
		if(array_key_exists($method, vB_Api::$vb4_input_mappings))
		{
			$mapping = vB_Api::$vb4_input_mappings[$method];
			if(array_key_exists('request_mappings', $mapping))
			{
				$request_mappings = $mapping['request_mappings'];
				foreach($request_mappings as $mapping_from => $mapping_to)
				{
					if(!empty($request[$mapping_from]))
					{
						$request[$mapping_to] = $request[$mapping_from];
						unset($request[$mapping_from]);
					}
				}
			}

			if(array_key_exists('method', $mapping))
			{
				return $mapping['method'];
			}
		}
		else if (strpos($method, "cms.") === 0)
		{
			// CMS method.
			return vB_Api::cms_vb4_to_vb5_method_mapping($method, $request);
		}
		return vB_Api::default_vb4_to_vb5_method_mapping($method);
	}

	private static $vb4_input_mappings = array(
		'blog.post_comment' => array(
			'method' => 'vb4_blog.post_comment'
		),
		'blog.post_postcomment' => array(
			'method' => 'vb4_blog.post_postcomment'
		),
		'blog.post_updateblog' => array(
			'method' => 'vb4_blog.post_updateblog'
		),
		'blog.post_newblog' => array(
			'method' => 'vb4_blog.post_newblog'
		),
		'blog.post_editblog' => array(
			'method' => 'vb4_blog.post_editblog'
		),
		'blog_list' => array(
			'method' => 'vb4_blog.bloglist'
		),
		'api_init' => array(
			'method' => 'api.init'
		),
		'api_cmssectionlist' => array(
			'method' => 'Vb4_Cms.sectionlist',
		),
		'api_cmscategorylist' => array(
			'method' => 'Vb4_Cms.categorylist',
		),
		/*
		// These can no longer be mapped directly to vB_Api_User::login/logout
		// due to additional processing of devicetoken that may be required
		// for mapi calls.
		'login_login' => array(
			'method' => 'user.login',
			'request_mappings' => array(
				'vb_login_username' => 'username',
				'vb_login_password' => 'password',
				'vb_login_md5password' => 'md5password',
				'vb_login_md5password_utf' => 'md5passwordutf'
			)
		),
		'login_logout' => array(
			'method' => 'user.logout'
		),
		*/
		'get_vbfromfacebook' => array(
			'method' => 'vb4_facebook.getVbfromfacebook',
		),
	);

	private static function cms_vb4_to_vb5_method_mapping($method, &$request)
	{
		define('VB_API_CMS', true); // I don't think we use this in vB5. TODO: remove

		/*
			CMS method calls look like... (depends on the call...)


			cms.class_{nodeid}_function [_other?]


			cms.content_{nodeid}_view[_contentpagenum]
			cms.list_category_{categoryid}
		 */
		// Based roughly on vB4's api.php
		list($controller, $segment2, $segment3, $segment4) = explode("_", $method);
		$controller = str_replace("cms.", "", $controller);
		$controller = strtolower($controller); // standardize to lowercase just in case.

		$action = "call";

		// convert path segments to function params
		switch($controller)
		{
			case 'list':
				$action = strtolower($segment2);
				switch($action)
				{
					case 'category':
						// list_category_[categoryid]
						$request['categoryid'] = intval($segment3);
						break;
					case 'section':
						$request['sectionid'] = intval($segment3);
						break;
					case 'author':
						$request['userid'] = intval($segment3);
						break;
					default:
						break;
				}
				break;
			case 'content':
			default:
				$nodeid = intval($segment2);
				if ($nodeid == 1)
				{
					// Special case - Seems like this might be hard coded in the client for the "front page",
					// or we're missing something in the api_init return that tells the client what nodeid
					// the "front page" is...
					// For now, intercept & replace with article channel nodeid
					// TODO: Check if this is truly necessary with mobile team
					$articlesRootChannelId = vB_Api::instanceInternal('content_channel')->fetchChannelIdByGUID(vB_Channel::DEFAULT_ARTICLE_PARENT);
					$nodeid = $articlesRootChannelId;
				}

				$action = strtolower($segment3);

				// cms.content_{nodeid}_view_{contentpagenum}
				$request['nodeid'] = intval($nodeid);

				if (!empty($segment4) AND is_numeric($segment4))
				{
					$request['contentpagenum'] = intval($segment4);
				}
				break;
		}


		$action = strtolower($action);

		/*
			Not really sure if this is the best way to go about it, but I don't
			want to create multiple classes for the different vB4 CMS controllers,
			so I'll just group them all in the vb4_cms class.
		 */
		$className = "Vb4_Cms";
		$functionName = ucfirst($controller) . "_" . ucfirst($action);

		return $className . "." . $functionName;
	}

	private static function default_vb4_to_vb5_method_mapping($method)
	{
		$methodsegments = explode("_", $method);
		$methodsegments[0] = "VB4_" . $methodsegments[0];
		if(count($methodsegments) < 2)
		{
			$methodsegments[] = "call";
		}
		elseif(count($methodsegments) > 2)
		{
			// Handle strangeness
		}
		return implode(".", $methodsegments);
	}

	/**
	 * Alters the output array in any way necessary to interface correctly
	 * with vb4.
	 * @param string $method -- vb4 method name
	 * @param array $data -- output array from vb5
	 */
	public static function map_vb5_output_to_vb4($method, &$data)
	{
		if(strstr($method, "login_login"))
		{
			$copy_data = $data;
			$copy_data['dbsessionhash'] = $copy_data['sessionhash'];
			unset($copy_data['sessionhash']);
			$data = array();
			$data["session"] = $copy_data;
			unset($copy_data);
			$data["response"]["errormessage"][0] = "redirect_login";
		}

		if(strstr($method, "login_logout"))
		{
			$copy_data = $data;
			$copy_data['dbsessionhash'] = $copy_data['sessionhash'];
			unset($copy_data['sessionhash']);
			$data = array();
			$data["session"] = $copy_data;
			unset($copy_data);
			$data["response"]["errormessage"][0] = "cookieclear";
		}

		self::remove_nulls($data);
	}

	private static function remove_nulls(&$data)
	{
		foreach ($data as $key => &$value)
		{
			if (is_array($value))
			{
				self::remove_nulls($value);
			}
			else if ($value === null)
			{
				$value = '';
			}
		}
	}


	/**
	 * Alters the error array in any way necessary to interface correctly with vb4.
	 * @param string $method -- vb4 method name
	 * @param array $data -- error array from vb5
	 */
	public static function map_vb5_errors_to_vb4($method, &$data)
	{
		if(strstr($method,"api_init"))
		{
			$data = array();
			$data["response"]["errormessage"] = array("apiclientinfomissing");
		}
		else if(strstr($method, "login_login"))
		{
			if (isset($data[0]) AND $data[0] == "badlogin_no_privacy_consent")
			{
				$data = array();
				$data["response"]["errormessage"] = array("badlogin_no_privacy_consent");
			}
			else
			{
				$data = array();
				$data["response"]["errormessage"] = array("badlogin");
			}
		}
		else if(strstr($method, "forumdisplay"))
		{
			if($data[0][0] == 'invalid_node_id')
			{
				$data = array();
				$data["response"]["errormessage"] = array("invalidid");
			}
			else
			{
				$data = array();
				$data["response"]["errormessage"] = array("invalidid");
			}
		}
		else if(strstr($method, "private_showpm"))
		{
			$data = array();
			$data["response"]["errormessage"] = array("invalidid");
		}

		else if(strstr($method, "showthread"))
		{
			if($data[0][0] == 'invalid_node_id')
			{
				$data = array();
				$data["response"]["errormessage"] = array("invalidid");
			}
			else
			{
				$data = array();
				$data["response"]["errormessage"] = array("invalidid");
			}
		}

		else if(strstr($method, "register_fbconnect"))
		{
			if($data[0][0] == 'invalid_password_specified')
			{
				$data = array();
				$data["response"]["errormessage"] = array("usernotloggedin");
			}
		}
	}

	// THIS CODE IS WAS EXTRACTED FROM DIFFERENT FILES OF VB4 BOOTSTRAP AND IS DUPLICATED
	protected function __construct()
	{
		// This is a dummy object $vbulletin just to avoid rewriting all code
		global $vbulletin;

		if (empty($vbulletin))
		{
			$vbulletin = vB::get_registry();
		}
		if (empty($vbulletin->db) AND class_exists('vB') AND !empty(vB::$db))
		{
			$vbulletin->db = vB::$db;
		}
	}

	/**
	 * This method checks whether the API method is enabled.
	 * For extensions check make sure $controller property is already set.
	 *
	 * @param 	string	name of the function being called
	 * @param	option flag to clear the static value. This is only passed when running unit tests
	 */
	public function checkApiState($method)
	{
		$closed = vB_Api::instanceInternal('state')->checkBeforeView();

		$response = true;
		if ($closed !== FALSE)
		{
			if ($this->isDisableFalseReturnOnly($method))
			{
				$response = false;
			}
			else if (!$this->isWhiteListed($method))
			{
				throw new vB_Exception_Api_Disabled($closed['msg']);
			}
		}

		return $response;
	}

	/**
	 *	Checks if method is white listed when API is disabled.
	 *
	 * @param 	string 	API method to check.
	 * @return 	bool 	Indicates whether method is or is not a white list.
	 */
	protected function isWhiteListed($method)
	{
		if (!is_string($method))
		{
			return false;
		}

		// extensions check
		if($elist = vB_Api_Extensions::getExtensions($this->controller))
		{
			foreach ($elist AS $class)
			{
				if (in_array($method, $class->disableWhiteList))
				{
					return true;
				}
			}
		}

		return (in_array($method, $this->disableWhiteList));
	}

	/**
	 *	Checks if method returns false response only when API is disabled.
	 *
	 * @param 	string 	API method to check.
	 * @return 	bool 	Indicates whether method returns false response only.
	 */
	protected function isDisableFalseReturnOnly($method)
	{
		if (!is_string($method))
		{
			return false;
		}

		// extensions check
		if($elist = vB_Api_Extensions::getExtensions($this->controller))
		{
			foreach ($elist AS $class)
			{
				if (in_array($method, $class->disableFalseReturnOnly))
				{
					return true;
				}
			}
		}

		return (in_array($method, $this->disableFalseReturnOnly));
	}

	/**
	 * Replaces special characters in a given string with dashes to make the string SEO friendly
	 *
	 * @param	string	The string to be converted
	 */
	protected function toSeoFriendly($str)
	{
		if (!empty($str))
		{
			return vB_String::getUrlIdent($str);
		}
		return $str;
	}

	/**
	 * Determines if the calling user has the given admin permission, and if not throws an exception
	 *
	 * Checks for:
	 * 	* A valid CP Session
	 * 	* The passed adminpermission.
	 *
	 * @param	string	The admin permission to check
	 * @return none
	 * @throws inlinemodauth_required -- The current session is not a mod/admin session
	 * @throws nopermission_loggedin -- The user does not have the given permission
	 * @throws no_permission -- The user is not logged in at all.
	 */
	protected function checkHasAdminPermission($adminPermission)
	{
		$value = $this->hasAdminPermissionInternal($adminPermission);
		if ($value !== true)
		{
			throw new vB_Exception_Api($value);
		}
	}

	/**
	 *	Determines if the calling user has the given admin permission
	 *
	 *	Useful if you need to know if the calling user but do not care why they do not
	 *	have that permission.  Generally useful if there is a behavior difference
	 *	between admins and non admins, but the call can be processed for either.
	 *
	 * 	@param	string	The admin permission to check
	 *	@return boolean true if checks pass, false otherwise
	 */
	protected function hasAdminPermission($adminPermission)
	{
		$value = $this->hasAdminPermissionInternal($adminPermission);
		return ($value === true);
	}


	/**
	 * Internal function to power the previous cover functions
	 *
	 *
	 * 	@param	string	The admin permission to check
	 */
	private function hasAdminPermissionInternal($adminPermission)
	{
		$session = vB::getCurrentSession();
		if (!$session->validateCpsession())
		{
			return 'inlinemodauth_required';
		}

		if (!vB::getUserContext()->hasAdminPermission($adminPermission))
		{
			$user = &$session->fetch_userinfo();

			//not sure this is required, since I don't think we can pass the validateCpsession
			//call without being logged in.  However its not worth changing at the moment.
			if ($user['userid'] > 0)
			{
				return array(
					'nopermission_loggedin',
					$user['username'],
					vB_Template_Runtime::fetchStyleVar('right'),
					$user['securitytoken'],
					vB::getDatastore()->getOption('frontendurl')
				);
			}
			else
			{
				return 'no_permission';
			}
		}

		return true;
	}


	/**
	 * Determines if the calling user has the given admin permission, and if not throws an exception
	 *
	 * @param	string	The admin permission to check
	 */
	protected function checkIsLoggedIn()
	{
		$userId = (int) vB::getUserContext()->fetchUserId();
		if ($userId < 1)
		{
			throw new vB_Exception_Api('not_logged_no_permission');
		}
	}

	/**
	 * Set controller
	 * @param 	string 	Controller name
	 *
	 */
	protected function setController($controller)
	{
		if (!is_string($controller))
		{
			throw new vB_Exception_Api('invalid_controller');
		}

		$this->controller = $controller;
	}

	protected function inDebugMode()
	{
		static $debugMode;
		if (is_null($debugMode))
		{
			$vb5_config = &vB::getConfig();
			$debugMode = (bool) $vb5_config['Misc']['debug'];
		}

		return $debugMode;
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
