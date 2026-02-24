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

class vB5_Route_PrivateMessage_Viewinfraction
{
	use vB_Trait_NoSerialize;

	protected $subtemplate = 'privatemessage_viewinfraction';
	protected $messageid = 0;

	public function __construct(&$routeInfo, &$matches, &$queryString = '')
	{
		if (isset($matches['params']) AND !empty($matches['params']))
		{
			$paramString = (strpos($matches['params'], '/') === 0) ? substr($matches['params'], 1) : $matches['params'];
			list($this->nodeid) = explode('/', $paramString);
		}
		else if (isset($matches['nodeid']))
		{
			$this->nodeid = $matches['nodeid'];
		}
		$routeInfo['arguments']['subtemplate'] = $this->subtemplate;
	}

	public function validInput(&$data)
	{
		if ($this->nodeid)
		{
			$data['arguments'] = serialize(array(
				'nodeid' => $this->nodeid
			));

			return true;
		}
		else
		{
			return false;
		}
	}

	public function getUrlParameters()
	{
		return "/{$this->nodeid}";
	}

	public function getParameters()
	{
		return array('nodeid' => $this->nodeid);
	}

	public function getBreadcrumbs()
	{
		$breadcrumbs = array(
			array(
				'phrase' => 'infractions',
				'url'	=> ''
			),
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
