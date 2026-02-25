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

//might as well put this up here -- we aren't likely to use this class
//and not need it.
require_once(DIR . '/includes/functions.php');

/**
 * vB_Api_Prefix
 *
 * @package vBApi
 * @access public
 */
class vB_Api_Prefix extends vB_Api
{
	/**
	 * Fetch available prefixes of a Channel. It has permission check,
	 * So if an user doesn't have permission to use a prefix, the prefix
	 * won't be returned.
	 *
	 * @param int $nodeid Channel node ID
	 * @param bool $permcheck If set to true, it will return only the prefixes that
	 *        a user can use
	 *
	 * @return array Prefixes in format [PrefixsetID][PrefixID] => array(prefixid, restrictions)
	 */
	public function fetch($nodeid, $permcheck = true)
	{
		if (!$nodeid)
		{
			return array();
		}

		$data = vB_Library::instance('prefix')->getPrefixData();

		//we don't have anything.
		if(!isset($data['channelPrefixset'][$nodeid]))
		{
			return array();
		}

		if($permcheck)
		{
			$userinfo = vB::getCurrentSession()->fetch_userinfo();
			$membergroups = fetch_membergroupids_array($userinfo);
			$infractiongroups = explode(',', str_replace(' ', '', $userinfo['infractiongroupids']));
		}

		$result = array();
		foreach($data['channelPrefixset'][$nodeid] AS $prefixSetId)
		{
			$result[$prefixSetId] = array();

			foreach($data['prefixes'][$prefixSetId] AS $prefixid)
			{
				$restrictions = array();
				if (isset($data['restrictions'][$prefixid]))
				{
					$restrictions = $data['restrictions'][$prefixid];
				}

				if (!$permcheck OR $this->canUseInternal($prefixid, $restrictions, $membergroups, $infractiongroups))
				{
					$result[$prefixSetId][$prefixid] = array(
						'prefixid' => $prefixid,
						'restrictions' => $restrictions,
					);
				}
			}
		}

		return $result;
	}

	/**
	 *	Can the logged in user use the prefix in question
	 *
	 *	@param string $prefixid
	 *	@return array
	 *		-- 'canuse' => boolean -- note that we will return false if the prefixid does not exist.
	 */
	public function canUse($prefixid)
	{
		$library = vB_Library::instance('prefix');

		//we do not want to distinguish between a prefix that doesn't exist and one
		//that the user cannot use.  We have to explicitly check because the "restrictions"
		//array does not store information for prefixes that have no restrictions -- which is
		//the common case.
		if (!$library->prefixExists($prefixid))
		{
			return array('canuse' => false);
		}

		$userinfo = vB::getCurrentSession()->fetch_userinfo();
		$membergroups = fetch_membergroupids_array($userinfo);
		$infractiongroups = explode(',', str_replace(' ', '', $userinfo['infractiongroupids']));

		$data = $library->getPrefixData();
		$restrictions = array();
		if (isset($data['restrictions'][$prefixid]))
		{
			$restrictions = $data['restrictions'][$prefixid];
		}

		$canuse = $this->canUseInternal($prefixid, $restrictions, $membergroups, $infractiongroups);
		return array('canuse' => $canuse);
	}

	private function canUseInternal($prefixid, $restrictions, $membergroupids, $infractiongroupids)
	{
		if (empty($restrictions))
		{
			return true;
		}

		//if an infraction group the user is part of isn't allowed, that's a hard stop
		//it's not currenlty clear *how* the infractiongroupids field gets populated
		//but this was in the vB4 code we're replacing so we'll leave it.
		foreach ($restrictions AS $usergroupid)
		{
			if (in_array($usergroupid, $infractiongroupids))
			{
				return false;
			}
		}

		//otherwise allow if any group the user is a member of is not restricted
		return (bool) count(array_diff($membergroupids, $restrictions));
	}

}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
