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

class vB5_Route_Legacy_Misc extends vB5_Route_Legacy
{
	protected $prefix = 'misc.php';
	
	protected function getNewRouteInfo()
	{
		$arguments = & $this->arguments;
		$param = & $this->queryParameters;
		$keys = array_keys($param);
		$idkey = array('t', 'threadid');
		if (empty($param['do']))
		{
			$param['do'] = 'showsmilies';
		}

		switch($param['do'])
		{
		case 'bbcode':
			$this->anchor = 'bbcode_reference/bbcode_why';
			return 'help';
		case 'showrules':
			$this->anchor = 'community_overview/general_tos';
			return 'help';
		case 'showsmilies':
			$this->anchor = 'bbcode_reference/bbcode_smilies';
			return 'help';
		case 'whoposted':
			if ($set=array_intersect($keys, $idkey) AND $pid=intval($param[reset($set)]))
			{
				$oldid = $pid;
				$oldcontenttypeid = vB_Types::instance()->getContentTypeID(array('package' => 'vBForum', 'class' =>'Thread'));
				$node = vB::getDbAssertor()->getRow('vBForum:node', array(
					'oldid' => $oldid,
					'oldcontenttypeid' => $oldcontenttypeid
				));
				
				if (!empty($node))
				{
					$arguments['nodeid'] = $node['nodeid'];
					return $node['routeid'];
				}
			}
		default:
			throw new vB_Exception_404('invalid_page');
		}
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
