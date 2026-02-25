<?php
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
 * Gets the relationship of one user to another.
 *
 * The relationship level can be:
 *
 * 	3 - User 2 is a Friend of User 1 or is a Moderator
 *  2 - User 2 is on User 1's contact list
 *  1 - User 2 is a registered forum member
 *  0 - User 2 is a guest or ignored user
 *
 * @param int	$user1						- Id of user 1
 * @param int	$user2						- Id of user 2
 */
function fetch_user_relationship($user1, $user2)
{
	global $vbulletin;
	static $privacy_cache = array();

	$user1 = intval($user1);
	$user2 = intval($user2);

	if (!$user2)
	{
		return 0;
	}

	if (isset($privacy_cache["$user1-$user2"]))
	{
		return $privacy_cache["$user1-$user2"];
	}

	if ($user1 == $user2 OR can_moderate(0, '', $user2))
	{
		$privacy_cache["$user1-$user2"] = 3;
		return 3;
	}

	$contacts = vB::getDbAssertor()->assertQuery('userlist', array('userid' => $user1, 'relationid' => $user2));


	$return_value = 1;
	foreach ($contacts as $contact)
	{
		if ($contact['friend'] == 'yes')
		{
			$return_value = 3;
			break;
		}
		else if ($contact['type'] == 'ignore')
		{
			$return_value = 0;
			break;
		}
		else if ($contact['type'] == 'buddy')
		{
			// no break here, we neeed to make sure there is no other more definitive record
			$return_value = 2;
		}
	}


	$privacy_cache["$user1-$user2"] = $return_value;
	return $return_value;
}

//from old functions_album.php file
/**
* Determines whether the current browsing user can see private albums
* for the specified album owner.
*
* @param	integer	Album owner user ID
*
* @return	boolean True if yes
 */
//function only used in older upgrade steps
function can_view_private_albums($albumuserid)
{
	global $vbulletin;
	static $albumperms_cache = array();

	$albumuserid = intval($albumuserid);
	if (isset($albumperms_cache["$albumuserid"]))
	{
		return $albumperms_cache["$albumuserid"];
	}

	if ($vbulletin->userinfo['userid'] == $albumuserid)
	{
		$can_see_private = true;
	}
	else if ($vbulletin->userinfo['userid'] == 0)
	{
		$can_see_private = false;
	}
	else if (can_moderate(0, 'caneditalbumpicture') OR can_moderate(0, 'candeletealbumpicture'))
	{
		$can_see_private = true;
	}
	else
	{
		$friend_record = $vbulletin->db->query_first("
			SELECT userid
			FROM " . TABLE_PREFIX . "userlist
			WHERE userid = $albumuserid
				AND relationid = " . $vbulletin->userinfo['userid'] . "
				AND type = 'buddy'
		");
		$can_see_private = ($friend_record ? true : false);
	}

	$albumperms_cache["$albumuserid"] = $can_see_private;
	return $can_see_private;
}



/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 101123 $
|| #######################################################################
\*=========================================================================*/
