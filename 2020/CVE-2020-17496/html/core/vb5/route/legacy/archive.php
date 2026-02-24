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

class vB5_Route_Legacy_Archive extends vB5_Route_Legacy_Page
{
	protected $prefix = 'archive/index.php';

	// archive/index.php does not have frendly URL
	protected function getNewRouteInfo()
	{
		// go to home page if path is exactly like prefix
		if (count($this->matches) == 1 AND empty($this->queryParameters))
		{
			$forumHomeChannel = vB_Library::instance('content_channel')->getForumHomeChannel();
			return $forumHomeChannel['routeid'];
		}

		// capture old id
		$argument = & $this->arguments;
		$oldid = $argument['oldid'];

		$types = vB_Types::instance();

		// calculate old contenttypeid
		if ($this->matches['nodetype'] == 't')
		{
			$oldcontenttypeid = array(
				$types->getContentTypeID('vBForum_Thread'),
				vB_Api_ContentType::OLDTYPE_POLL,
			);
		}
		else if ($this->matches['nodetype'] == 'f')
		{
			$oldcontenttypeid = $types->getContentTypeID('vBForum_Thread');
		}

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

	public function getRegex()
	{
		return $this->prefix . '(?:/(?P<nodetype>t|f)-(?P<oldid>[1-9]\d*)(?:-p-(?P<pagenum>[1-9]\d*))?\.html)?';
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 102676 $
|| #######################################################################
\*=========================================================================*/
