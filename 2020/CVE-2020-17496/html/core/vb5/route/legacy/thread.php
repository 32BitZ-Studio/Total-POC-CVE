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

class vB5_Route_Legacy_Thread extends vB5_Route_Legacy_Page
{
	protected $idkey = array('t', 'threadid');

	protected $prefix = 'showthread.php';

	// use postid if available
	protected function getNewRouteInfo()
	{
		$param = & $this->queryParameters;
		if (isset($param['p']) AND $oldid=intval($param['p']) OR isset($param['postid']) AND $oldid=intval($param['postid']))
		{
			$node = vB::getDbAssertor()->getRow('vBForum:fetchLegacyPostIds', array(
				'oldids' => $oldid,
				'postContentTypeId' => vB_Types::instance()->getContentTypeID('vBForum_Post'),
			));

			if (empty($node))
			{
				throw new vB_Exception_404('invalid_page');
			}

			$this->arguments['nodeid'] = $node['starter'];
			$this->arguments['innerPost'] = $node['nodeid'];
			return $node['routeid'];
		}

		//vb4 threads with polls get marked with the OLDTYPE_POLL special ID
		//they still have the same threadid as the oldid so there isn't any conflict.
		$this->oldcontenttypeid = array(
			vB_Types::instance()->getContentTypeID(array('package' => 'vBForum', 'class' =>'Thread')),
			vB_Api_ContentType::OLDTYPE_POLL,
		);

		return parent::getNewRouteInfo();
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 102676 $
|| #######################################################################
\*=========================================================================*/
