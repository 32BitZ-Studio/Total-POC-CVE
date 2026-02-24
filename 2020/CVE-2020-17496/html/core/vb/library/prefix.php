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
 * vB_Library_Page
 *
 * @package vBLibrary
 * @access public
 */
class vB_Library_Prefix extends vB_Library
{

	/**
	 *	Rebuilds the prefix datastore
	 *
	 *	Datastore looks like
	 *		'prefixes' -- array of 'prefixsetid' => list of prefixes
	 *	 	'restrictions' -- array of 'prefixid' => list of restricted usergroups,
	 *	 	'channelPrefixset' -- array of 'channelid' => list of prefeix sets,
	 */
	//eventually all the code that needs to rebuild the datastore should
	//be in this class at which point we should make this private.
	public function buildDatastore()
	{
		$db = vB::getDbAssertor();

		//we could do this as a single query, but it's not honestly clear that preformance is better that
		//way and two queries is simpler
		$prefixes = array();
		$set = $db->select('vBForum:prefix', array(), array('displayorder'), array('prefixsetid', 'prefixid'));

		foreach($set AS $row)
		{
			$prefixes[$row['prefixsetid']][] = $row['prefixid'];
		}

		$prefixRestrictions = array();
		$set = $db->select('vBForum:prefixpermission', array());
		foreach($set AS $row)
		{
			$prefixRestrictions[$row['prefixid']][] = $row['usergroupid'];
		}

		$channelPrefixset = array();
		$set = $db->assertQuery('vBForum:getChannelPrefixset', array());
		foreach($set AS $row)
		{
			//if the prefix set doesn't have anything in it, then don't store.
			if (isset($prefixes[$row['prefixsetid']]))
			{
				$channelPrefixset[$row['nodeid']][] = $row['prefixsetid'];
			}
		}

		$data = array(
			'prefixes' => $prefixes,
			'restrictions' => $prefixRestrictions,
			'channelPrefixset' => $channelPrefixset,
		);
		vB::getDatastore()->build('prefixcache', serialize($data), 1);
		return $data;
	}


	/**
	 *	Does the given prefix exist?
	 *
	 *	@param string $prefixid
	 *	@return boolean
	 */
	public function prefixExists($prefixid)
	{
		//this isn't necesairly the fastest operation, but it's faster than a DB query.
		//We should alway be preloading the prefix cache, so we should have it.
		//if we end up calling it a lot it might be worth caching an inverted
		//map of the prefixes on this class so subsequent calls are fast -- but honestly
		//I don't think its a serious problem.
		$data = $this->getPrefixData();
		foreach($data['prefixes'] AS $prefixes)
		{
			if (in_array($prefixid, $prefixes))
			{
				return true;
			}
		}

		return false;
	}

	/**
	 *	Get the prefix datastore.  If it does not exist, rebuild it.
	 *
	 *	This should be the only way the prefixcache datastore is accessed
	 */
	public function getPrefixData()
	{
		$prefixes = vB::getDatastore()->getValue('prefixcache');

		if (is_null($prefixes))
		{
			$prefixes = $this->buildDatastore();
		}

		return $prefixes;
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 102970 $
|| #######################################################################
\*=========================================================================*/
