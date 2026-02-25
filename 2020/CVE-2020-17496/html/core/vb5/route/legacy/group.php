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

class vB5_Route_Legacy_Group extends vB5_Route_Legacy
{
	protected $prefix = 'group.php';
	
	// group.php does not have friendly URL
	protected function getNewRouteInfo()
	{
		$oldtype = array(
			'cat' => 9988,
			'groupid' => vB_Types::instance()->getContentTypeID('vBForum_SocialGroup'),
			'discussionid' => vB_Types::instance()->getContentTypeID('vBForum_SocialGroupDiscussion')
		);
		$argument = & $this->arguments;
		$param = & $this->queryParameters;
		
		foreach ($oldtype as $key => $oldcontenttypeid)
		{
			if (!empty($param[$key]) AND $oldid=intval($param[$key]))
			{
				$node = vB::getDbAssertor()->getRow('vBForum:node', array(
					'oldid' => $oldid,
					'oldcontenttypeid' => $oldcontenttypeid
				));
				
				if (empty($node))
				{
					throw new vB_Exception_404('invalid_page');
				}
				
				$argument['nodeid'] = $node['nodeid'];
				return $node['routeid'];
			}
		}
		
		$sgChannelId = vB_Api::instance('socialgroup')->getSGChannel();
		$sgChannel = vB::getDbAssertor()->getRow('vBForum:node', array('nodeid' => $sgChannelId));
		$argument['nodeid'] = $sgChannel['nodeid'];
		return $sgChannel['routeid'];
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
