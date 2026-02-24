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

class vB5_Route_Legacy_Threadprint extends vB5_Route_Legacy
{
	protected $prefix = 'printthread.php';

	// printthread.php does not have friendly URL
	protected function getNewRouteInfo()
	{
		$argument = & $this->arguments;
		$param = & $this->queryParameters;
		$keys = array_keys($param);
		$tidkey = array('t', 'threadid');
		$pidkey = array('p', 'postid');
		if ($set=array_intersect($keys, $tidkey) AND $pid=intval($param[reset($set)]))
		{
			$oldid = $pid;
			$node = vB::getDbAssertor()->getRow('vBForum:node', array(
				'oldid' => $oldid,
				'oldcontenttypeid' => vB_Types::instance()->getContentTypeID(array('package' => 'vBForum', 'class' =>'Thread'))
			));
		}
		else if ($set=array_intersect($keys, $pidkey) AND $pid=intval($param[reset($set)]))
		{
			$oldid = $pid;
			$node = vB::getDbAssertor()->getRow('vBForum:fetchLegacyPostIds', array(
				'oldids' => $oldid,
				'postContentTypeId' => vB_Types::instance()->getContentTypeID('vBForum_Post'),
			));
		}
		if (empty($node))
		{
			throw new vB_Exception_404('invalid_page');
		}

		$this->arguments['nodeid'] = $node['starter'];
		return $node['routeid'];
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
