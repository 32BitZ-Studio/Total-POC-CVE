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
 * vB_Api_Userrank
 *
 * @package vBApi
 * @access public
 */
class vB_Api_Userrank extends vB_Api
{
	protected $styles = array();

	/**
	 * Fetch Userrank By RankID
	 *
	 * @param int $rankid Rank ID
	 * @return array User rank information
	 */
	public function fetchById($rankid)
	{
		$this->checkHasAdminPermission('canadminusers');
		return vB_Library::instance('userrank')->fetchById($rankid);
	}

	/**
	 * Fetch All user ranks
	 *
	 * @return array Array of user ranks
	 */
	public function fetchAll()
	{
		$this->checkHasAdminPermission('canadminusers');
		return vB_Library::instance('userrank')->fetchAll();
	}

	/**
	 * Insert a new user rank or update existing user rank
	 *
	 * @param array $data User rank data to be inserted or updated
	 *              'ranklevel'   => Number of times to repeat rank
	 *              'usergroupid' => Usergroup
	 *              'minposts'    => Minimum Posts
	 *              'stack'       => Stack Rank. Boolean.
	 *              'display'     => Display Type. 0 - Always, 1 - If Displaygroup = This Group
	 *              'rankimg'     => User Rank File Path
	 *              'rankhtml'    => User Rank HTML Text
	 * @param int $rankid If not 0, it's the ID of the user rank to be updated
	 * @return int New rank's ID or updated rank's ID
	 */
	public function save($data, $rankid = 0)
	{
		$this->checkHasAdminPermission('canadminusers');
		return vB_Library::instance('userrank')->save($data, $rankid);
	}

	/**
	 * Delete an user rank
	 *
	 * @param int $rankid The ID of user rank to be deleted
	 * @return array -- standard success array
	 */
	public function delete($rankid)
	{
		$this->checkHasAdminPermission('canadminusers');
		vB_Library::instance('userrank')->delete($rankid);
		return array('success' => true);
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
