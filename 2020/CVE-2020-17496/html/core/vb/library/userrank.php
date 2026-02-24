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
 * vB_Libary_Userrank
 *
 * @package vBLibrary
 * @access public
 */
/*
 *	Note that the "ranks" datastore entry should be considered private to this class even though there is no
 *	way to enforce that.  The only other place its currently used is the unit tests -- in order to reset the
 *	value between tests and to test the "self heal" logic when the datastore entry randomly goes missing.
 */
class vB_Library_Userrank extends vB_Library
{
	/**
	 * Fetch Userrank By RankID
	 *
	 * @param int $rankid Rank ID
	 * @return array User rank information
	 */
	public function fetchById($rankid)
	{
		$rank = vB::getDbAssertor()->getRow('vBForum:ranks', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'rankid' => intval($rankid),
		));

		if (!$rank)
		{
			throw new vB_Exception_Api('invalid_rankid');
		}

		return $rank;
	}

	/**
	 * Fetch All user ranks
	 *
	 * @return array Array of user ranks
	 */
	public function fetchAll()
	{
		return vB::getDbAssertor()->getRows('userrank_fetchranks', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_STORED,
		));
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
	 *              'rankimg'     => User Rank File Path (only used if rankhtml is empty)
	 *              'rankhtml'    => User Rank HTML Text (if not empty rankimg will be ignored)
	 * @param int $rankid If not 0, it's the ID of the user rank to be updated
	 * @return int New rank's ID or updated rank's ID
	 */
	public function save($data, $rankid = 0)
	{
		$rankid = intval($rankid);

		if (!$data['ranklevel'] OR (!$data['rankimg'] AND !$data['rankhtml'] AND !$data['rankurl']))
		{
			throw new vB_Exception_Api('please_complete_required_fields');
		}

		if ($data['usergroupid'] == -1)
		{
			$data['usergroupid'] = 0;
		}

		if ($data['rankhtml'])
		{
			$type = 1;
			$data['rankimg'] = $data['rankhtml'];
		}
		else if ($data['rankurl'])
		{
			$type = 2;
			$data['rankimg'] = $data['rankurl'];
		}
		else
		{
			if (empty($type))
			{
				if (!(@is_file(DIR . $data['rankimg'])))
				{
					throw new vB_Exception_Api('invalid_file_path_specified');
				}
				$type = 0;
				$data['rankimg'] =  $data['rankimg'];
			}
			else
			{
				$type = $data['type'];
			}

		}

		if (!$rankid)
		{
			/*insert query*/
			$rankid = vB::getDbAssertor()->assertQuery('vBForum:ranks', array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_INSERT,
				'ranklevel' => intval($data['ranklevel']),
				'minposts' => intval($data['minposts']),
				'rankimg' => trim($data['rankimg']),
				'usergroupid' => intval($data['usergroupid']),
				'type' => $type,
				'stack' => intval($data['stack']),
				'display' => intval($data['display']),
			));

			if (!empty($rankid['errors']))
			{
				throw new vB_Exception_Api('invalid_data');
			}
		}
		else
		{
			/*update query*/
			//The unit test requires the return to be the rankid whether it's an insert or
			//update.  By coincidence it passed, but when fixing VBV-13749 it failed.
			$update = vB::getDbAssertor()->assertQuery('vBForum:ranks', array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_UPDATE,
				'ranklevel' => intval($data['ranklevel']),
				'minposts' => intval($data['minposts']),
				'rankimg' => trim($data['rankimg']),
				'usergroupid' => intval($data['usergroupid']),
				'type' => $type,
				'stack' => intval($data['stack']),
				'display' => intval($data['display']),
				vB_dB_Query::CONDITIONS_KEY => array(
					'rankid' => $rankid,
				)
			));

			if (!empty($update['errors']))
			{
				throw new vB_Exception_Api('invalid_data');
			}

		}

		$this->buildRanks();
		return $rankid;
	}

	/**
	 * Delete an user rank
	 *
	 * @param int $rankid The ID of user rank to be deleted
	 * @return void
	 */
	public function delete($rankid)
	{
		vB::getDbAssertor()->assertQuery('vBForum:ranks', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_DELETE,
			'rankid' => intval($rankid),
		));

		$this->buildRanks();
	}

	/**
	 * Delete all user ranks based for a given usergroup
	 *
	 * This is primarily intended for cleanup when a usergroup is deleted.
	 *
	 * @param int $usergroupid The usergroup to clear the ranks for.
	 */
	public function deleteForUsergroup($usergroupid)
	{
		vB::getDbAssertor()->assertQuery('vBForum:ranks', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_DELETE,
			'usergroupid' => $usergroupid
		));
		$this->buildRanks();
	}

	/**
	 *	Determines if we have ranks defined in the system.  This allows
	 *	us to determine if we even need to worry about changing a user's rank.
	 */
	public function haveRanks()
	{
		$ranks = vB::getDatastore()->getValue('ranks');
		if (!is_array($ranks))
		{
			$ranks = $this->buildRanks();
		}

		return !empty($ranks);
	}

	/**
	 *	Gets the current rank for a user.
	 *
	 *	Intended to allow updating the user after a change is made.
	 *
	 *	We use the following logic to find the ranks for a user.
	 *
	 * 	A rank is a match if
	 * 	* We our user has greater than or equal to the min post count for the rank
	 *  * We are a member of the ranks group (or the rank is set to all user groups)
	 *  * If we are set to only match the display group then our display group is the same as the rank group
	 *			If the rank is set to "all groups" and set to only match a display group then we match the
	 *			rank if we have not matched a previous rank.
	 *
	 *	Additionally we will not consider any ranks if we have previously matched a rank for the same usergroup
	 *	with a higher minimum post count.  If there are several ranks with the same user group and post count
	 *	that match we will select all of them if they are the highest that match.  For this purpose ranks
	 *	set to "all groups" are considered their own usergroup (that is we will select up to one rank per
	 *	usergroup and one for "all usergroups" assuming we do not select multiple ranks with the same postcount).
	 *
	 *  Note that there is undocumented (in the UI) behavior surrounding the seemingly nonsensical
	 *  combination of "all groups" and "display group = this group".  We specifically only match the group if
	 *  we haven't matched a previous ranks (for any usergroup, not just "all groups").  As an additional quirk,
	 *  if we would match an "all group" rank with a lower post count and without the display group flag set
	 *  we will match the rank with the display group flag instead, which seems inconsistant (this is because
	 *  we encounter the higher post cont rank first in process order and make a decision on it before looking
	 *  at the ranks farther down -- and when we encounter the lower ranks we've already selected the higher
	 *  count rank for all groups and therefore we do not consider the lower rank for inclusion).
	 *
	 *  This behavior was clearly done for a reason (based the specifical inclusion of code to handle that case),
	 *  however the reasons for it are lost to history.  It does not appear to be a widely used case in the wild.
	 *  The current thinking is that it is not a useful feature and we should consider it an error to enter a
	 *  rank in that state.  The logic has not yet been changed to reflect this (its been that way for a long
	 *  time and doesn't appear to be hurting anything).
	 *
	 *	@param $userinfo -- The user info array.  We only actually use the following fields
	 *	* posts
	 *	* usergroupid
	 *	* displaygroupid
	 *	* membergroupids
	 *	@return string The user rank html
	 */
	public function getRankHtml($userinfo)
	{
		//if for some reason we don't have the datastore value then rebuild it.  Replaces a call in the
		//admincp global page.  This is the only place where we use the rank datastore value.
		$ranks = vB::getDatastore()->getValue('ranks');
		if (!is_array($ranks))
		{
			$ranks = $this->buildRanks();
		}

		$doneusergroup = array();
		$userrank = '';

		//For historical reasons, probably to save space when the array is serialized in the datastore, the ranks
		//in the datastore use single character aliases for the fields
		//ranklevel: l, minposts: m, rankimg: i, type: t, stack: s, display: d, usergroupid: u

		//The logic in this loop is highly dependant on the ranks being order by usergroupid DESC and minpostcount DESC
		//The first is required so that the 'all user group' ranks go last which is what makes the wonky 'all user group'
		//and 'displaygroup = thisgroup' "feature" work (see doc block).  Since we aren't sure this feature is useful
		//that's only so important.
		//the second is required to ensure that only the highest min post count rank for each user group is used.
		$displaygroupid = (empty($userinfo['displaygroupid']) ? $userinfo['usergroupid'] : $userinfo['displaygroupid']);

		foreach ($ranks AS $rank)
		{
			//assume no match
			$match = false;

			//do we have enough posts to match this rank?
			if ($userinfo['posts'] >= $rank['m'])
			{
				//Either we haven't matched a rank for this usergroup before or the rank we matched has the
				//same min posts and this one (and thus we can match both per our rules).
				if (empty($doneusergroup[$rank['u']]) OR ($doneusergroup[$rank['u']] == $rank['m']))
				{
					//is this rank for a specific user group?
					if ($rank['u'] > 0)
					{
						//are we a member of that usergroup?
						if (is_member_of($userinfo, $rank['u'], false))
						{
							//do we need to match the display group?  If we do then do we?
							if (empty($rank['d']) OR $rank['u'] == $displaygroupid)
							{
								$match = true;
							}
						}
					}

					//is this the special value for "all groups"?  note that usergroup < 0 is
					//a "should not happen".  If we do see bad input we treat is as a "no match" casse.
					else if ($rank['u'] == 0)
					{
						//do we have the special case of "only match if no other ranks match" case?
						if (empty($rank['d']) OR empty($userrank))
						{
							$match = true;
						}
					}
				}
			}

			if ($match)
			{
				//@todo -- we should not be generating html this deep in the code.  Need to seperate into a data list and provide a
				//template for rendering on the front end.  However that's going to require some work in terms of changing the datamodel
				//on down so for now we'll go with the code the way its been since (I think) vB2
				if (!empty($userrank) AND $rank['s'])
				{
					$userrank .= '<br />';
				}
				$doneusergroup["$rank[u]"] = $rank['m'];

				for ($x = $rank['l']; $x--; $x > 0)
				{
					if (empty($rank['t']))
					{
						//must include 'core/'.  See VBV-14906
						$rank['i'] = ltrim($rank['i'], '/');
						$userrank .= "<img src=\"core/$rank[i]\" alt=\"\" border=\"\" />";
					}
					else if ($rank['t'] == 2)
					{
						$userrank .= "<img src=\"$rank[i]\" alt=\"\" border=\"\" />";
					}
					else
					{
						$userrank .= $rank['i'];
					}
				}
			}
		}

		return $userrank;
	}


	/**
	 *	Rebuild the rank datastore entry
	 *
	 *	Must be called after any operation that changes the rank table
	 */
	private function buildRanks()
	{
		//the logic for ranks strongly depends on this query returning things sorted is order
		//usergroupid DESC, minpost DESC
		$ranks = vB::getDbAssertor()->assertQuery('vBForum:fetchranks', array());

		$rankarray = array();
		foreach($ranks as $rank)
		{
			$rankarray[] = $rank;
		}

		vB::getDatastore()->build('ranks', serialize($rankarray), 1);
		return $rankarray;
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 102970 $
|| #######################################################################
\*=========================================================================*/
