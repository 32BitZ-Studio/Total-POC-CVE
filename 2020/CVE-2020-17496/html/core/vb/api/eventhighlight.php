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
 * vB_Api_Eventhighlight
 *
 * @package vBApi
 * @access public
 */
class vB_Api_Eventhighlight extends vB_Api
{
	/**
	 * vB_Library_Eventhighlight
	 */
	protected $library = null;

	/**
	 * Constructor
	 */
	public function __construct()
	{
		$this->library = vB_Library::instance('eventhighlight');
	}

	/**
	 * Returns the specified event highlight for administration purposes.
	 *
	 * @param  int   Event highlight ID
	 * @param  bool  (optional) If true, add the permissions information
	 *
	 * @return array Event highlight information
	 */
	public function getEventHighlightAdmin($eventhighlightid, $withPermissions = false)
	{
		$this->checkEventHighlightAdminPermissions();

		return $this->library->getEventHighlightAdmin($eventhighlightid, $withPermissions);
	}

	/**
	 * Returns the full listing of event highlights for administration purposes.
	 *
	 * @param  array (optional) Array of eventhighlightids, if empty, all event highlights are returned
	 * @param  bool  (optional) If true, add the permissions information
	 *
	 * @return array Full listing of event highlights
	 */
	public function getEventHighlightsAdmin($eventhighlightids = array(), $withPermissions = false)
	{
		$this->checkEventHighlightAdminPermissions();

		return $this->library->getEventHighlightsAdmin($eventhighlightids, $withPermissions);
	}

	/**
	 * Returns the listing of event highlights for the currently logged in user
	 *
	 * @return array Listing of available event highlights
	 */
	public function getEventHighlightsUser()
	{
		return $this->library->getEventHighlightsUser();
	}

	/**
	 * Returns the view information to display all event highlights
	 *
	 * @return array View information for all event highlights (permissions only affect being able to apply an event highlight to a node)
	 */
	public function getEventHighlightViewInfo()
	{
		return $this->library->getEventHighlightViewInfo();
	}

	/**
	 * Saves (creates or updates) an event highlight
	 *
	 * @param  array Event highlight information
	 *
	 * @return array Event highlight information
	 */
	public function saveEventHighlight($data)
	{
		$this->checkEventHighlightAdminPermissions();

		return $this->library->saveEventHighlight($data);
	}

	/**
	 * Deletes an event highlight
	 *
	 * @param  array Event highlight ID
	 *
	 * @return array Success array
	 */
	public function deleteEventHighlight($eventhighlightid)
	{
		$this->checkEventHighlightAdminPermissions();

		return $this->library->deleteEventHighlight($eventhighlightid);
	}

	/**
	 * Saves event highlight display order for multiple event highlights
	 *
	 * @param  array Display order array ('event highlight id' => 'display order')
	 *
	 * @return array Success array
	 */
	public function saveEventHighlightDisplayOrder($displayOrder)
	{
		$this->checkEventHighlightAdminPermissions();

		return $this->library->saveEventHighlightDisplayOrder($displayOrder);
	}

	/**
	 * Saves event highlight permissions for one event highlight
	 *
	 * @param  int   Event highlight ID
	 * @param  bool  Deny by default (when new user groups are created, deny access to this event highlight)
	 * @param  array Array of usergroups to deny access to this event highlight
	 *
	 * @return array Success array
	 */
	public function saveEventHighlightPermissions($eventhighlightid, $denybydefault, $denyusergroups)
	{
		$this->checkEventHighlightAdminPermissions();

		return $this->library->saveEventHighlightPermissions($eventhighlightid, $denybydefault, $denyusergroups);
	}

	/**
	 * Verifies that the current user has all required admin permissions
	 * to administrate Event Highlights.
	 */
	private function checkEventHighlightAdminPermissions()
	{
		$this->checkHasAdminPermission('canadminforums');
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 103730 $
|| #######################################################################
\*=========================================================================*/
