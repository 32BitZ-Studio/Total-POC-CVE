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

class vB5_Route_Legacy_Tag extends vB5_Route_Legacy
{
	protected $prefix = 'tags.php';
	
	// translate param, if fail just go to search page
	protected function getNewRouteInfo()
	{
		$param = & $this->queryParameters;
		$tag = array();
		if (!empty($param['tag']))
		{
			$tag['searchJSON'] = "{\"tag\":[\"$param[tag]\"]}";
		}
		$param = $tag;
		return 'search';
	}

	public function getRedirect301()
	{
		$data = $this->getNewRouteInfo();
		return $data;
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
