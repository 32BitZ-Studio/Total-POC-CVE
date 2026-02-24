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

class vB5_Route_PrivateMessage_Index
{
	use vB_Trait_NoSerialize;

	protected $subtemplate = 'privatemessage_foldersummary';

	public function __construct(&$routeInfo, &$matches, &$queryString = '')
	{
		// just modify routeInfo, no internal settings
		$routeInfo['arguments']['subtemplate'] = $this->subtemplate;
	}

	public function validInput(&$data)
	{
		$data['arguments'] = '';

		return true;
	}

	public function getUrlParameters()
	{
		return '';
	}

	public function getParameters()
	{
		// TODO: remove the dummy variable, this was just a demo
		return array('dummyIndex' => "I'm a dummy value!");
	}

	public function getBreadcrumbs()
	{
		return array(
			array(
				'phrase' => 'inbox',
				'url'	=> ''
			)
		);
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
