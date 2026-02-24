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

// ######################## SET PHP ENVIRONMENT ###########################
error_reporting(E_ALL & ~E_NOTICE);
// if (!is_object($vbulletin->db))
// {
// 	exit;
// }

// ########################################################################
// ######################### START MAIN SCRIPT ############################
// ########################################################################

$vb5_config =& vB::getConfig();
$timenow = vB::getRequest()->getTimeNow();

$miscoptions = vB::getDatastore()->getValue('miscoptions');
$lastrun = !empty($miscoptions['promotions_lastrun']) ? $miscoptions['promotions_lastrun'] : $timenow - ($nextrun - $timenow);

// We only check the users that have been active since the lastrun to save a bit of cpu time.
$promotions = vB::getDbAssertor()->assertQuery('fetchUsersForPromotion', array('time' => $lastrun));

$usertitlecache = array();
$usertitles = vB::getDbAssertor()->assertQuery('usertitle', array(), array('field' => 'minposts', 'direction' => vB_dB_Query::SORT_ASC));
foreach ($usertitles as $usertitle)
{
	$usertitlecache["$usertitle[minposts]"] = $usertitle['title'];
}

$primaryupdates = array();
$secondaryupdates = array();
$userupdates = array();
$primarynames = array();
$secondarynames = array();
$titles = array();

$ranklib = vB_Library::instance('userrank');
foreach ($promotions as $promotion)
{
	// First make sure user isn't already a member of the group we are joining
	if ((strpos(",$promotion[membergroupids],", ",$promotion[joinusergroupid],") === false AND $promotion['type'] == 2) OR ($promotion['usergroupid'] != $promotion['joinusergroupid'] AND $promotion['type'] == 1))
	{
		$daysregged = intval(($timenow - $promotion['joindate']) / 86400);
		$joinusergroupid = $promotion['joinusergroupid'];
		$titles["$joinusergroupid"] = $promotion['title'];
		$dojoin = false;
		$reputation = false;
		$posts = false;
		$joindate = false;
		// These strategies are negative reputation checking
		if (($promotion['strategy'] > 7 AND $promotion['strategy'] < 16) OR $promotion['strategy'] == 24)
		{
			if ($promotion['reputation'] < $promotion['jumpreputation'])
			{
				$reputation = true;
			}
		}
		else if ($promotion['reputation'] >= $promotion['jumpreputation'])
		{
			$reputation = true;
		}

		if ($promotion['posts'] >= $promotion['jumpposts'])
		{
			$posts = true;
		}
		if ($daysregged >= $promotion['jumpdate'])
		{
			$joindate = true;
		}

		if ($promotion['strategy'] == 17)
		{
			$dojoin = iif($posts, true, false);
		}
		else if ($promotion['strategy'] == 18)
		{
			$dojoin = iif($joindate, true, false);
		}
		else if ($promotion['strategy'] == 16 OR $promotion['strategy'] == 24)
		{
			$dojoin = iif($reputation, true, false);
		}
		else
		{
			switch($promotion['strategy'])
			{
				case 0:
				case 8:
					if ($posts AND $reputation AND $joindate)
					{
						$dojoin = true;
					}
					break;
				case 1:
				case 9:
					if ($posts OR $reputation OR $joindate)
					{
						$dojoin = true;
					}
					break;
				case 2:
				case 10:
					if (($posts AND $reputation) OR $joindate)
					{
						$dojoin = true;
					}
					break;
				case 3:
				case 11:
					if ($posts AND ($reputation OR $joindate))
					{
						$dojoin = true;
					}
					break;
				case 4:
				case 12:
					if (($posts OR $reputation) AND $joindate)
					{
						$dojoin = true;
					}
					break;
				case 5:
				case 13:
					if ($posts OR ($reputation AND $joindate))
					{
						$dojoin = true;
					}
					break;
				case 6:
				case 14:
					if ($reputation AND ($posts OR $joindate))
					{
						$dojoin = true;
					}
					break;
				case 7:
				case 15:
					if ($reputation OR ($posts AND $joindate))
					{
						$dojoin = true;
					}
			}
		}

		if ($dojoin)
		{
			$user = $promotion;
			$undeletable_users = (!empty($vb5_config['SpecialUsers']['undeletableusers'])) ? 
					explode(',', $vb5_config['SpecialUsers']['undeletableusers']) : array();
			$undeletable_user = (in_array($promotion['userid'], $undeletable_users)) ? true : false;

			if ($promotion['type'] == 1 ) // Primary
			{
				if (!$undeletable_user)
				{
					$primaryupdates["$joinusergroupid"] .= ",$promotion[userid]";
					$primarynames["$joinusergroupid"] .= iif($primarynames["$joinusergroupid"], ", $promotion[username]", $promotion['username']);

					if (
						(!$promotion['displaygroupid'] OR $promotion['displaygroupid'] == $promotion['usergroupid']) AND
						!$promotion['customtitle']
						)
					{
						if ($promotion['ug_usertitle'])
						{
							// update title if the user (doesn't have a special display group or if their display group is their primary group)
							// and he doesn't have a custom title already, and the new usergroup has a custom title
							$userupdates["$promotion[userid]"]['title'] = $promotion['ug_usertitle'];
						}
						else
						{ // need to use default thats specified for X posts.
							foreach ($usertitlecache AS $minposts => $title)
							{
								if ($minposts <= $promotion['posts'])
								{
									$userupdates["$promotion[userid]"]['title'] = $title;
								}
								else
								{
									break;
								}
							}
						}
					}

					$user['displaygroupid'] = ($user['displaygroupid'] == $user['usergroupid']) ? $joinusergroupid : $user['displaygroupid'];
					$user['usergroupid'] = $joinusergroupid;
				}
			}
			else
			{
				$secondaryupdates["$joinusergroupid"][] = $promotion['userid'];
				$secondarynames["$joinusergroupid"] .= iif($secondarynames["$joinusergroupid"], ", $promotion[username]", $promotion['username']);
				$user['membergroupids'] .= (($user['membergroupids'] != '') ? ',' : '') . $joinusergroupid;
			}

			$userrank = $ranklib->getRankHtml($user);
			if ($promotion['rank'] != $userrank AND !$undeletable_user)
			{
				$userupdates["$promotion[userid]"]['rank'] = $userrank;
			}

		}
	}
}

$infractiongroupids = array();

if (!empty($primaryupdates))
{
	$groups = vB::getDbAssertor()->assertQuery('infractiongroup', array('usergroupid' => array_merge(array_keys($primaryupdates), array(-1))), array('field' => 'pointlevel', 'direction' => vB_dB_Query::SORT_ASC));
	foreach ($groups as $group)
	{
		$infractiongroupids["$group[usergroupid]"]["$group[pointlevel]"] =
			array(
				'orusergroupid' => $group['orusergroupid'],
				'override'      => $group['override'],
			);
	}

	foreach (array_keys($primaryupdates) AS $usergroupid)
	{
		if (empty($infractiongroupids["$usergroupid"]))
		{
			$infractiongroupids["$usergroupid"] = array();
		}
	}

	if (!empty($infractiongroupids['-1']))
	{
		foreach ($infractiongroupids AS $usergroupid => $pointlevel)
		{
			$infractiongroupids["$usergroupid"] += $infractiongroupids['-1'];
			ksort($infractiongroupids["$usergroupid"]);
		}
		unset($infractiongroupids['-1']);
	}

	$groupids = array();
	foreach ($infractiongroupids AS $usergroupid => $pointlevel)
	{
		$ids = '';
		$infractiongroupid = 0;
		foreach ($pointlevel AS $points => $infractioninfo)
		{
			if ($infractioninfo['override'])
			{
				$infractiongroupid = $infractioninfo['orusergroupid'];
			}
			$ids .= (!empty($ids) ? ',' : '') . $infractioninfo['orusergroupid'];
			$groupids["$usergroupid"]["$points"]['ids'] = $ids;
			$groupids["$usergroupid"]["$points"]['id'] = $infractiongroupid;
		}
	}
	unset($infractiongroupid, $infractiongroupids, $ids);
}

foreach ($primaryupdates AS $joinusergroupid => $ids)
{
	vB::getDbAssertor()->assertQuery('updateUserInfractions', array(
		'joinusergroupid' => $joinusergroupid,
		'pointlevel' => (empty($groupids[$joinusergroupid]) ? array() : $groupids[$joinusergroupid]),
		'ids' => $ids
	));

	$log = array(
		$titles["$joinusergroupid"],
		'*',
		$primarynames["$joinusergroupid"]
	);
	// the "1" indicates to use the second line of the phrase specified for this task
	log_cron_action(serialize($log), $nextitem, 1);
}
unset($groupids);

$vbulletin = &vB::get_registry();
foreach ($userupdates AS $userid => $info)
{
	$userdm = new vB_Datamanager_User($vbulletin, vB_DataManager_Constants::ERRTYPE_SILENT);
	$user = array('userid' => $userid);
	$userdm->set_existing($user);

	if ($info['title'])
	{
		$userdm->set('usertitle', $info['title']);
	}

	if ($info['rank'])
	{
		$userdm->setr('rank', $info['rank']);
	}

	$userdm->save();
	unset($userdm);
}

$miscoptions['promotions_lastrun'] = $timenow;
vB::getDatastore()->build('miscoptions', serialize($miscoptions), 1);

foreach ($secondaryupdates AS $joinusergroupid => $ids)
{
	if ($ids)
	{
		vB::getDbAssertor()->assertQuery('vBForum:updateUserMemberGroupsByUserId', 
			array(
				'usergroupid' => $joinusergroupid, 
				'auth' => $ids
			)
		);
	}
	$log = array(
		$titles["$joinusergroupid"],
		'%',
		$secondarynames["$joinusergroupid"]
	);
	log_cron_action(serialize($log), $nextitem, 1);
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| ####################################################################
\*======================================================================*/
?>
