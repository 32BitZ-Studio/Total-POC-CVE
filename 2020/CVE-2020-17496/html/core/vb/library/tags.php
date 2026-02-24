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

/**
 * vB_Library_Tags
 *
 * @package vBLibrary
 * @access public
 */
class vB_Library_Tags extends vB_Library
{
	public function deleteUserTagAssociations($userid)
	{
		$db = vB::getDbAssertor();

		//do this first because it relies on the tagnode records existing to find the
		//nodes related to the user.  It will exclude any tags associated with the users
		//while rebuilding.
		$db->assertQuery('setGroupConcatSize', array('maxlen' => 10000));
		$nodeids = $db->getColumn('vBForum:getTagNodesForUser', 'nodeid', array('userid' => $userid));

		//we went to some trouble to write this query to avoid pulling the nodeids down to the client
		//but ended up having to anyway to handle the cache.  It's not clear, however, if it's better
		//to pass the nodeids back or continue to look them up via subquery based on the userid.
		//Leaving as is for now.  It's only going to matter for users with thousands of tagged nodes
		$db->assertQuery('vBForum:updateTagListExcludeUser', array('userid' => $userid));
		$db->delete('vBForum:tagnode', array('userid' => $userid));

		vB_Library::instance('node')->nodesChanged($nodeids);
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 102837 $
|| #######################################################################
\*=========================================================================*/
