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

class vB5_Frontend_Controller_Admin extends vB5_Frontend_Controller
{
	public function actionSavepage()
	{
		// require a POST request for this action
		$this->verifyPostRequest();

		$input = $_POST['input'];
		$url = $_POST['url'];


		//parse_url doesn't work on relative urls and I don't want to assume that
		//we have an absolute url.  We probably don't have a query string, but bad assumptions
		//about the url are what got us into this problem to begin with.
		$parts = explode('?', $url, 2);
		$url = $parts[0];

		$query = '';
		if (sizeof($parts) == 2)
		{
			$query = $parts[1];
		}

		if (preg_match('#^http#', $url))
		{
			$base = vB5_Template_Options::instance()->get('options.frontendurl');
			if (preg_match('#^' . preg_quote($base, '#') . '#', $url))
			{
				$url = substr($url, strlen($base)+1);
			}
		}

		//if we are hitting the index page directly then we should treat it like the site root
		if($url == 'index.php')
		{
			$url = '';
		}

		$api = Api_InterfaceAbstract::instance();
		$route = $api->callApi('route', 'getRoute', array('pathInfo' => $url, 'queryString' => $query));

		//if we have a redirect try to find the real route -- this should only need to handle one layer
		//and if that also gets a redirect things are broken somehow.
		if (!empty($route['redirect']))
		{
			$route = $api->callApi('route', 'getRoute', array('pathInfo' => ltrim($route['redirect'], '/'), 'queryString' => $query));
		}

		$result = $api->callApi('page', 'pageSave', array($input));
		if (empty($result['errors']))
		{
			$page = $api->callApi('page', 'fetchPageById', array('pageid' => $result['pageid'], 'routeData' => $route['arguments']));

			//the route classes are, unfortunately, inconsistant about returning a leading slash (they shouldn't) and that
			//will break the JS code if we do here.  So force it not to.
			$result['url'] = ltrim($page['url'], '/');
		}

		$this->sendAsJson($result);
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 101809 $
|| #######################################################################
\*=========================================================================*/
