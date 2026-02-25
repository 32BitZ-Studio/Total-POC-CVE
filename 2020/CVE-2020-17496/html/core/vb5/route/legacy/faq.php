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

class vB5_Route_Legacy_Faq extends vB5_Route_Legacy
{
	protected $prefix = 'faq.php';
	
	// try its best to translate param to anchor
	protected function getNewRouteInfo()
	{
		$param = & $this->queryParameters;
		if (!empty($param['faq']))
		{
			try {
				$section = $param['faq'];
				$answer = vB_Api::instanceInternal('help')->getAnswer($section);
				$this->anchor = $answer['firstItem']['path'];
			} catch (Exception $e) {
				;
			}
		}
		return 'help';
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
