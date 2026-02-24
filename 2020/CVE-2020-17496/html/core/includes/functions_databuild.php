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

function build_bbcode_video($checktable = false)
{
	if ($checktable)
	{
		try
		{
			vB::getDbAssertor()->assertQuery('bbcode_video', array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT
			));
		}
		catch (Exception $e)
		{
			return false;
		}
	}

	/*
		NOTE: having the 2nd param true for the loadProductXmlListParsed() call currently means you could potentially
		*override* (rather than add to) the default vbulletin's bbcode_video list by having a file named
		'bbcode_video_vbulletin.xml' (because the 'vbulletin' would be used as the key, overriding the default vbulletin
		data that also uses 'vbulletin' as the key).
		This may be a good thing or a bad thing. For now let's go with "add" instead of "override"
		$xmlData = vB_Library::instance('product')->loadProductXmlListParsed('bbcode_video', true);

		NOTE2: The "tagoption" attribute is used as the key (it's unique in DB and required by how bbcode parsing works), so
		providers from different packages sharing this key will resolve conflicts by a "priority" element.
		If this element is not provided for a provider node in the XML file, it'll default to "0". See VBV-9692
		We still do not want to accidentally override packages until we do the filtering via priority, so continue passing false for 2nd param.
	 */
	$xmlData = vB_Library::instance('product')->loadProductXmlListParsed('bbcode_video', false); // 2nd param is optional, default false, but explicitly specified here intentionally.

	$insert = array();
	$priority = array();
	$failed = array();
	foreach ($xmlData AS $data)
	{
		if (is_array($data['provider']))
		{
			$provider = $data['provider'];
			if (isset($provider['tagoption']) OR isset($provider['title']) OR isset($provider['url']))
			{
				/*
					It seems that if the XML file contains only 1 provider tag, we don't get a nested array for $data['provider'].
					Force consistency.
				 */
				$provider = array($provider);
			}

			foreach ($provider AS $provider)
			{

				$doInsert = false;
				$tagoption = $provider['tagoption'];
				$items = array();
				$items['tagoption'] = $tagoption;
				$items['provider'] = $provider['title'];
				$items['url'] = $provider['url'];
				$items['regex_url'] = $provider['regex_url'];
				$items['regex_scrape'] = $provider['regex_scrape'];
				$items['embed'] = $provider['embed'];

				// default to 0 if this element's not set.
				if (!isset($provider['priority']))
				{
					$provider['priority'] = 0;
				}

				if (isset($priority[$tagoption]))
				{

					if ($priority[$tagoption] < $provider['priority'])
					{
						$doInsert = true;
						$failed[] = $insert[$tagoption]; // save the overwritten one in failed array.
					}
				}
				else
				{
					$doInsert = true;
				}


				// bbcode_video table currently has tagoption as a unique key.
				if ($doInsert)
				{
					$priority[$tagoption] = $provider['priority'];
					$insert[$tagoption] = $items;
				}
				else
				{
					// todo: report these back to caller.
					$failed[] = $items;
				}
			}
		}
	}


	if (!empty($insert))
	{
		// TODO: wrap below 2 in a transaction if possible (need to change truncate to DELETE instead as I think truncate forces a commit)
		// in an attempt to avoid a case where a bad addon causes default bbcode_video to go away and we cannot recover.
		vB::getDbAssertor()->assertQuery('truncateTable', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_METHOD,
			'table' => 'bbcode_video'
		));
		$insertResult = vB::getDbAssertor()->assertQuery('bbcode_video', array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_MULTIPLEINSERT,
			vB_dB_Query::FIELDS_KEY => array('tagoption', 'provider', 'url', 'regex_url', 'regex_scrape', 'embed'),
			vB_dB_Query::VALUES_KEY => $insert));
	}

	$firsttag = '<vb:if condition="$provider == \'%1$s\'">';
	$secondtag = '<vb:elseif condition="$provider == \'%1$s\'" />';

	$template = array();
	$bbcodes = vB::getDbAssertor()->assertQuery('bbcode_video', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT
		),
		array('field' => array('priority'), 'direction' => array(vB_dB_Query::SORT_ASC))
	);

	foreach ($bbcodes as $bbcode)
	{
		if (empty($template))
		{
			$template[] = sprintf($firsttag, $bbcode['tagoption']);
		}
		else
		{
			$template[] = sprintf($secondtag, $bbcode['tagoption']);
		}
		$template[] = $bbcode['embed'];
	}
	$template[] = "</vb:if>";

	$final = implode("\r\n", $template);

	$exists = vB::getDbAssertor()->getRow('template', array(
			vB_dB_Query::CONDITIONS_KEY =>array(
				array('field' => 'title', 'value' => 'bbcode_video', 'operator' => vB_dB_Query::OPERATOR_EQ),
				array('field' => 'product', 'value' => array('', 'vbulletin'), 'operator' => vB_dB_Query::OPERATOR_EQ),
				array('field' => 'styleid', 'value' => -1, 'operator' => vB_dB_Query::OPERATOR_EQ)
			)
		));

	if ($exists)
	{
		try
		{
			vB_Api::instanceInternal('template')->update($exists['templateid'],'bbcode_video',$final,'vbulletin',false,false,'');
		}
		catch (Exception $e)
		{
			return false;
		}
	}
	else
	{
		vB_Api::instanceInternal('template')->insert(-1, 'bbcode_video', $final, 'vbulletin');
	}
	return true;
}

// ###################### Start build_userlist #######################
// This forces the cache for X list to be rebuilt, only generally needed for modifications.
function build_userlist($userid, $lists = array())
{
	$userid = intval($userid);
	if ($userid == 0)
	{
		return false;
	}

	if (empty($lists))
	{
		$userlists = vB::getDbAssertor()->assertQuery('vBForum:fetchuserlists', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_STORED,
			'userid' => $userid,
		));

		foreach ($userlists as $userlist)
		{
			$lists["$userlist[type]"][] = $userlist['userid'];
		}
	}

	$userdata = new vB_Datamanager_User(vB_DataManager_Constants::ERRTYPE_STANDARD);
	$existing = array('userid' => $userid);
	$userdata->set_existing($existing);

	foreach ($lists AS $listtype => $values)
	{
		$key = $listtype . 'list';
		if (isset($userdata->validfields["$key"]))
		{
			$userdata->set($key, implode(',', $values));
		}
	}

	/* Now to set the ones that weren't set. */
	foreach ($userdata->list_types AS $listtype)
	{
		$key = $listtype . 'list';
		if ($userdata->is_field_set($key))
		{
			$userdata->set($key, '');
		}
	}

	$userdata->save();

	return true;
}

// ###################### Start saveuserstats #######################
// Save user count & newest user into template
function build_user_statistics()
{
	$members = vB::getDbAssertor()->getRow('vBForum:fetchUserStats');

	// get newest member
	$newuser = vB::getDbAssertor()->getRow('vBForum:fetchnewuserstats',
		array('userid' => $members['maxid']));

	// make a little array with the data
	$values = array(
		'numbermembers' => $members['users'],
		'activemembers' => isset($members['active']) ? $members['active'] : 0,
		'newusername'   => $newuser['username'],
		'newuserid'     => $newuser['userid']
	);

	// update the special template
	vB::getDatastore()->build('userstats', serialize($values), 1);

	return $values;
}

// ###################### Start getbirthdays #######################
function build_birthdays()
{
	$storebirthdays = array();

	$serveroffset = date('Z', vB::getRequest()->getTimeNow()) / 3600;

	$fromdatestamp = vB::getRequest()->getTimeNow() + (-11 - $serveroffset) * 3600;
	$fromdate = getdate($fromdatestamp);
	$storebirthdays['day1'] = date('Y-m-d', $fromdatestamp);

	$todatestamp = vB::getRequest()->getTimeNow() + (13 - $serveroffset) * 3600;
	$todate = getdate($todatestamp);
	$storebirthdays['day2'] = date('Y-m-d', $todatestamp);

	$todayneggmt = date('m-d', $fromdatestamp);
	$todayposgmt = date('m-d', $todatestamp);

	$datastore = vB::getDatastore();
	$usergroupcache = $datastore->getValue('usergroupcache');
	$bf_ugp_genericoptions = $datastore->getValue('bf_ugp_genericoptions');

	// Seems quicker to grab the ids rather than doing a JOIN
	$usergroupids = array();
	foreach($usergroupcache AS $usergroupid => $usergroup)
	{
		if ($usergroup['genericoptions'] & $bf_ugp_genericoptions['showbirthday'])
		{
			$usergroupids[] = $usergroupid;
		}
	}

	$bdays = vB::getDbAssertor()->getRows('vBForum:fetchBirthdays', array(
		vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_METHOD,
		'todayneggmt' => $todayneggmt,
		'todayposgmt' => $todayposgmt,
		'usergroupids' => $usergroupids,
	));

	$year = date('Y');
	$day1 = $day2 = array();

	foreach ($bdays as $birthday)
	{
		$username = $birthday['username'];
		$userid = $birthday['userid'];
		$day = explode('-', $birthday['birthday']);
		if ($year > $day[2] AND $day[2] != '0000' AND $birthday['showbirthday'] == 2)
		{
			$age = $year - $day[2];
		}
		else
		{
			$age = null;
		}
		if ($todayneggmt == $day[0] . '-' . $day[1])
		{
			$day1[] = array(
				'userid'   => $userid,
				'username' => $username,
				'age'      => $age
			);
		}
		else
		{
			$day2[] = array(
				'userid'   => $userid,
				'username' => $username,
				'age'      => $age
			);
		}
	}
	$storebirthdays['users1'] = $day1;
	$storebirthdays['users2'] = $day2;

	$datastore->build('birthdaycache', serialize($storebirthdays), 1);
	return $storebirthdays;
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
