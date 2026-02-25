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
 * vB_Api_Icon
 *
 * @package vBApi
 * @access public
 */
class vB_Api_Icon extends vB_Api
{

	protected function __construct()
	{
		parent::__construct();
	}

	/**
	 * Returns the array of post icons that the current user can use.
	 *
	 * @param array $orderby Sort orders
	 * @return    array    The icons
	 */
	public function fetchAll($orderby = array())
	{
		$assertor = vB::getDbAssertor();

		// *** get icon perms
		$conditions = array('imagetype' => 2); // @TODO this should be a constant (2 == posticons)
		$iconperms = $assertor->assertQuery('vBForum:getImageCategoryPermissions', $conditions);

		$noperms = array();
		foreach ($iconperms AS $iconperm)
		{
			$noperms[$iconperm['imagecategoryid']][] = $iconperm['usergroupid'];
		}

		// *** get usergroups
		$userinfo = vB::getCurrentSession()->fetch_userinfo();
		$membergroupids = array();
		$infractiongroupids = array();

		// add member groups
		if (!empty($userinfo['membergroupids']))
		{
			$membergroupids = explode(',', $userinfo['membergroupids']);
		}
		$membergroupids[] = $userinfo['usergroupid'];

		// add infraction groups
		if (!empty($userinfo['infractiongroupids']))
		{
			$infractiongroupids = explode(',', $userinfo['infractiongroupids']);
			// key the array by the infraction usergroupid
			$infractiongroupids = array_combine($infractiongroupids, $infractiongroupids);
		}

		// *** check permissions
		$badcategories = array();
		foreach($noperms AS $imagecategoryid => $usergroups)
		{
			// if the user has at least one infraction group that DOESN'T HAVE
			// permission to use this post icon category, they won't have permission
			foreach($usergroups AS $usergroupid)
			{
				if (isset($infractiongroupids[$usergroupid]))
				{
					$badcategories[] = $imagecategoryid;
					// Since we've now added $imagecategoryid to $badcategories,
					// and it only needs to be added once, we can skip to the next
					// $imagecategoryid value. This skips checking the rest of
					// $usergroups and skips the member group check below.
					continue 2;
				}
			}

			// if the user is a member of at least one usergroup that DOES
			// HAVE permission for this icon group, they will have permission
			// In other words, the permission must be denied for ALL member
			// groups for it to be denied here.
			if (!count(array_diff($membergroupids, $usergroups)))
			{
				$badcategories[] = $imagecategoryid;
			}
		}
		if (empty($badcategories))
		{
			// add a dummy bad category since the value is always sent to query
			$badcategories[] = 0;
		}

		// *** get icons
		$result = vB::getDbAssertor()->assertQuery(
			'icon',
			array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
				vB_dB_Query::CONDITIONS_KEY => array(
					array('field' => 'imagecategoryid', 'operator' => vB_dB_Query::OPERATOR_NE, 'value' => $badcategories),
				),
			),
			$orderby
		);

		$icons = array();
		if ($result->valid())
		{
			foreach ($result AS $icon)
			{
				$icons[$icon['iconid']] = $icon;
			}
		}

		return $icons;
	}

	/**
	 * Writes debugging output to the filesystem for AJAX calls
	 *
	 * @param	mixed	Output to write
	 */
	protected function _writeDebugOutput($output)
	{
		$fname = dirname(__FILE__) . '/_debug_output.txt';
		file_put_contents($fname, $output);
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
