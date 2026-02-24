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

class vB5_Route_Legacy_Converse extends vB5_Route_Legacy
{
	protected $prefix = 'converse.php';

	// converse.php does not have friendly URL
	protected function getNewRouteInfo()
	{
		$param = & $this->queryParameters;
		if (!empty($param['u']) AND $oldid=intval($param['u']))
		{
			$this->arguments['userid'] = $oldid;
			return 'profile';
		}
		throw new vB_Exception_404('invalid_page');
	}
	
	public function getRedirect301()
	{
		$data = $this->getNewRouteInfo();
		$this->queryParameters = array();
		return $data;
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
