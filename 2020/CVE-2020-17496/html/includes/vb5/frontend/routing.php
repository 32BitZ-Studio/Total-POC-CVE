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

class vB5_Frontend_Routing
{
	protected $routeId;
	protected $routeGuid;
	protected $controller;
	protected $action;
	protected $template;
	protected $arguments;
	protected $queryParameters;
	protected $pageKey;
	protected $breadcrumbs;
	protected $headlinks;

	protected $whitelist = array('actionLoginForm', 'actionLogin');

	private $path = null;

	protected function processQueryString()
	{
		if (!isset($_SERVER['QUERY_STRING']))
		{
			$_SERVER['QUERY_STRING'] = '';
		}

		parse_str($_SERVER['QUERY_STRING'], $params);

		if (isset($params['styleid']))
		{
			$styleid = intval($params['styleid']);
			$styleid = $styleid > 0 ? $styleid : 1;
			vB5_Cookie::set('userstyleid', $styleid, 0, false);
			$prefix = vB5_Config::instance()->cookie_prefix;
			$_COOKIE[$prefix . 'userstyleid'] = $styleid; // set it for the rest of this request as well
		}
	}

	public function getPath()
	{
		//cache path because we make changes that prevent this code from running
		//correctly a second time.
		if(is_null($this->path))
		{
			if (isset($_GET['routestring']))
			{
				$path = $_GET['routestring'];

				// remove it from $_GET
				unset($_GET['routestring']);

				// remove it from $_SERVER
				parse_str($_SERVER['QUERY_STRING'], $queryStringParameters);
				unset($queryStringParameters['routestring']);

				// Additional parameters of http_build_query() is required. See VBV-6272.
				$_SERVER['QUERY_STRING'] = http_build_query($queryStringParameters, '', '&');
			}
			else if (isset($_SERVER['PATH_INFO']))
			{
				$path = $_SERVER['PATH_INFO'];
			}
			else
			{
				$path = '';
			}

			if (strlen($path) AND $path[0] == '/')
			{
				$path = substr($path, 1);
			}

			$this->path = $path;
		}

		return $this->path;
	}

	public function setRoutes()
	{
		$this->processQueryString();

		$path = $this->getPath();

		//If there is an invalid image, js, or css request we wind up here. We can't process any of them
		if (strlen($path) > 2 )
		{
			//windows will strip trailing whitespace and trailing periods off a file before looking it
			//up.  This allows malicious users to skip this check rather trivially.  Let's at least make
			//it harder on them.
			$path = rtrim($path, " \t\n\r\0\x0B.");

			$ext = strtolower(pathinfo($path, PATHINFO_EXTENSION));
			if (
				($ext == 'gif') OR
				($ext == 'png') OR
				($ext == 'jpg') OR
				($ext == 'css') OR
				($ext == 'js')
			)
			{
				http_response_code(404);
				die('');
			}
		}

		try
		{
			$message = ''; // Start with no error.
			$api = Api_InterfaceAbstract::instance();
			$route = $api->callApi('route', 'getRoute', array('pathInfo' => $path, 'queryString' => $_SERVER['QUERY_STRING']));
		}
		catch (Exception $e)
		{
			$message = $e->getMessage();

			if ($message != 'no_vb5_database')
			{
				/* Some other exception happened */
				vB5_ApplicationAbstract::handleException($e, true);
			}
		}

		if (isset($route['errors']))
		{
			$message = $route['errors'][0][1];

			if ($message != 'no_vb5_database')
			{
				/* Some other exception happened */
				throw new vB5_Exception($message);
			}
		}

		if ($message == 'no_vb5_database')
		{
			/* Seem we dont have a valid vB5 database */
			// TODO: as we removed baseurl from config.php, we need to find a way redirecting user to installer correctly.
			header('Location: core/install/index.php');
			exit;
		}

		if (!empty($route))
		{
			if (isset($route['redirect']))
			{
				$url = $route['redirect'];
				if (stripos($url, 'http:') !== 0 OR stripos($url, 'https:') !== 0)
				{
					//the redirect url *shouldn't start with a slash -- it should either be
					//fully qualified *or* it should be relative to the base url.  But we'
					//aren't entirely consistant about that in the routing so let's make it
					//work either way.
					// $url can be an empty string if we're redirecting to the homepage route
					if($url != '' AND $url[0] != '/')
					{
						$url = '/' . $url;
					}

					$url = vB5_Template_Options::instance()->get('options.frontendurl') . $url;
				}

				vB5_ApplicationAbstract::handlePermanentRedirect($url);
			}
			else if (isset($route['internal_error']))
			{
				vB5_ApplicationAbstract::handleException($route['internal_error']);
			}
			else if (isset($route['banned_info']))
			{
				vB5_ApplicationAbstract::handleBannedUsers($route['banned_info']);
			}
			else if (isset($route['no_permission']))
			{
				vB5_ApplicationAbstract::handleNoPermission();
			}
			else if (isset($route['forum_closed']))
			{
				// Use 'bbclosedreason' as state param here to match the one specified in vB_Api_State::checkBeforeView()
				vB5_ApplicationAbstract::showMsgPage('', $route['forum_closed'], 'bbclosedreason');
				die();
			}
			else
			{
				$this->routeId         = $route['routeid'];
				$this->routeGuid       = $route['routeguid'];
				$this->controller      = str_replace(':', '.', $route['controller']);
				$this->action          = $route['action'];
				$this->template        = $route['template'];
				$this->arguments       = $route['arguments'];
				$this->queryParameters = $route['queryParameters'];
				$this->pageKey         = $route['pageKey'];

				if (!empty($route['userAction']) AND is_array($route['userAction']))
				{
					$this->userAction['action'] = array_shift($route['userAction']);
					$this->userAction['params'] = $route['userAction'];
				}
				else
				{
					$this->userAction = false;
				}

				$this->breadcrumbs = $route['breadcrumbs'];
				$this->headlinks = $route['headlinks'];

				if (!in_array($this->action, $this->whitelist))
				{
					/*
						Check products for controller:action whitelists.
						The reason why we have the whitelist structured by
						{controller} => {actions[]}
						is so that no product can blanket-whitelist all actions.
						This doesn't prevent a package from whitelisting another package's
						actions, but at least they'll have to intentionally & explicitly
						do so by providing both the controller & action.

						We're just using in_array() instead of trying to microoptimize for isset().
						Even if in_array() is O(n), we're really not expecting n > 0 (per controller,
						not the total actions across all controllers).
						Quick benchmarking indicates that the performance difference would only
						be measurable above noise when a controller subarray holds more than 50
						or so actions, and the difference would be 10's of microseconds at most,
						which IMO is not worth the developmental confusion that requiring the
						actions be keys instead of values would cause.
					 */
					$whitelistedByProduct = false;
					$whitelistedControllersAndActions = array();
					vB::getHooks()->invoke('hookGetRoutingControllerActionWhitelist', array(
						'whitelist' => &$whitelistedControllersAndActions,
					));
					$controllerLC = strtolower($this->controller);
					$actionLC = strtolower($this->action);
					if (
						!empty($whitelistedControllersAndActions) AND
						isset($whitelistedControllersAndActions[$controllerLC])
					)
					{
						$whitelistedByProduct = in_array($actionLC, $whitelistedControllersAndActions[$controllerLC]);
					}

					if (!$whitelistedByProduct)
					{
						vB5_ApplicationAbstract::checkState($route);
					}
				}

				return;
			}
		}
		else
		{
			// if no route was matched, try to parse route as /controller/method
			$stripped_path = preg_replace('/[^a-z0-9\/-_.]+/i', '', trim(strval($path), '/'));
			if (strpos($stripped_path, '/'))
			{
				list($controller, $method) = explode('/', strtolower($stripped_path), 2);
			}
			else
			{
				$controller = strtolower($stripped_path);
				$method = 'index';
			}

			$controller = preg_replace_callback('#(?:^|-)(.)#', function($matches)
			{
				return strtoupper($matches[1]);
			}, strtolower($controller));

			$method = preg_replace_callback('#(?:^|-)(.)#', function($matches)
			{
				return strtoupper($matches[1]);
			}, strtolower($method));

			$controllerClass = self::getControllerClassFromName($controller);
			$controllerMethod = 'action' . $method;

			if (class_exists($controllerClass) AND method_exists($controllerClass, $controllerMethod))
			{
				$this->controller = strtolower($controller);
				$this->action = $controllerMethod;
				$this->template = '';
				$this->arguments = array();
				$this->queryParameters = array();
				if (!in_array($this->action, $this->whitelist))
				{
					vB5_ApplicationAbstract::checkState(array('controller' => $this->controller, 'action' => $this->action));
				}
				return;
			}
		}

		//this could be a legacy file that we need to proxy.  The relay controller will handle
		//cases where this is not a valid file.  Only handle files in the "root directory".  We'll
		//handle deeper paths via more standard routes.
		if (strpos($path, '/') === false AND strpos($path, '\\') === false)
		{
			$this->controller = 'relay';
			$this->action = 'legacy';
			$this->template = '';
			$this->arguments = array($path);
			$this->queryParameters = array();
			return;
		}

		vB5_ApplicationAbstract::checkState();

		throw new vB5_Exception_404("invalid_page_url");
	}

	/**
	 * Get the class for a front end controller from the controller name
	 *
	 * Controller name comes from the url, the route record, or the vb:action parameter
	 * controllers of the for
	 * package_name will be located in the core/package/controller directory and will be
	 * named Package_Controller_Name
	 * otherwise they will be located in the includes/vb5/frontend/controller directory and will
	 * be named vB_Frontend_Controller_Controllerstring
	 *
	 * This is public to support the vb:action rendering in template runtime.  That should be
	 * strong revisited as it doesn't really work the same way as the other references to an
	 * action (a function is highly unlikely to work as both a template action and as url/route)
	 *
	 * @param string $controller
	 */
	public static function getControllerClassFromName($controller)
	{
		$info = explode('.', $controller, 2);
		if(count($info) == 1)
		{
			return 'vB5_Frontend_Controller_' . ucfirst($controller);
		}
		else
		{
			return  ucfirst($info[0]) . '_Controller_' . ucfirst($info[1]);
		}
	}


	/** Sets route information. Used by applicationLight to skip calling the full router. Mainly for template rendering
	 * @param mixed		array can include routeid, routeGuid, action, arguments. template, queryParameters, or breadcrumbs.
	 *
	 */
	public function setRouteInfo($routeInfo)
	{
		if (is_array($routeInfo))
		{
			foreach (array('routeid', 'routeGuid', 'action', 'arguments', 'template', 'queryParameters', 'breadcrumbs', 'headlinks')
				AS $key => $value)
			{
				if (!empty($routeInfo[$key]))
				{
					$this->$key = $value;
				}
			}
		}
	}

	public function getRouteId()
	{
		return $this->routeId;
	}

	public function getRouteGuid()
	{
		return $this->routeGuid;
	}

	public function getController()
	{
		return $this->controller;
	}

	public function getControllerClass()
	{
		return self::getControllerClassFromName($this->controller);
	}

	public function getAction()
	{
		return $this->action;
	}

	public function getTemplate()
	{
		return $this->template;
	}

	public function getArguments()
	{
		return $this->arguments;
	}

	public function getQueryParameters()
	{
		return $this->queryParameters;
	}

	public function getPageKey()
	{
		return $this->pageKey;
	}

	public function getUserAction()
	{
		return $this->userAction;
	}

	public function getBreadcrumbs()
	{
		return $this->breadcrumbs;
	}

	public function getHeadLinks()
	{
		return $this->headlinks;
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 103869 $
|| #######################################################################
\*=========================================================================*/
