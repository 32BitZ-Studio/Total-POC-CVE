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

class vB5_Route_PrivateMessage_Report extends vB5_Route_PrivateMessage_Index
{
	protected $pagenum = 1;
	protected $subtemplate = 'privatemessage_report';

	public function __construct(&$routeInfo, &$matches, &$queryString = '')
	{
		if (isset($matches['params']) AND !empty($matches['params']))
		{
			$paramString = (strpos($matches['params'], '/') === 0) ? substr($matches['params'], 1) : $matches['params'];
			$params = explode('/', $paramString);
			if (!empty($params))
			{
				$this->pagenum = $params[0];
			}

		}
		if (!empty($matches['pagenum']) AND intval($matches['pagenum']))
		{
			$this->pagenum = $matches['pagenum'];
		}

		$routeInfo['arguments']['subtemplate'] = $this->subtemplate;

		parent::__construct($routeInfo, $matches, $queryString);
	}

	public function validInput(&$data)
	{
		if (!empty($data['pagenum']))
		{
			$this->pagenum = $data['pagenum'];
		}
		//we don't REQUIRE any parameters.
		return parent::validInput($data);
	}

	public function getUrlParameters()
	{
		return "/{$this->pagenum}";
	}

	public function getParameters()
	{
		return array(
			'pageNum' => $this->pagenum,
			// not sure if anything actually uses pageNum above, but adding pagenum to be consistent
			// with other PM routes.
			'pagenum' => $this->pagenum,
		);
	}

	public function getBreadcrumbs()
	{
		$breadcrumbs = array(
				array(
						'phrase' => 'inbox',
						'url'	=> vB5_Route::buildUrl('privatemessage')
				),
				array(
						'phrase' => 'reports',
						'url' => ''
				)
		);

		return $breadcrumbs;
	}

}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
