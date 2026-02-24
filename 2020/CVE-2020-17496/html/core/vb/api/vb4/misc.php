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
 * vB_Api_Vb4_misc
 *
 * @package vBApi
 * @access public
 */
class vB_Api_Vb4_misc extends vB_Api
{
	public function buddylist()
	{
		/*
		vB4 had a single directional "friend" concept.
		E.g.
			John adds Tom & Hank as friends, which add `userlist` records for
			(userid, relationid, type, friend)
				({John}, {Tom}, 'buddy', 'pending')
				({John}, {Hank}, 'buddy', 'pending')
			Tom rejects John's friend request, which updates the pending
			record to
				({John}, {Tom}, 'buddy', 'denied')
			Hank accepts John as a friend, which updates the pending record
			to
				({John}, {Hank}, 'buddy', 'yes')
			then adds a reverse record of
				({Hank}, {John}, 'buddy', 'yes')

			So John's "friends" for the buddylist are defined by the records:
				({John}, {Tom}, 'buddy', 'denied')
				({John}, {Hank}, 'buddy', 'yes')

		vB5 does not have "friends", but user "subscriptions" instead.
		Subscriptions are single directional, and a rejected subscription
		request deletes the pending request, so there's no record of the
		pending or rejected request after the subscribee processes the request.

			An analog to the above vB4 example would be:
			John subscribes to Tom & Hank, which add `userlist` records
				({John}, {Tom}, 'follow', 'pending')
				({John}, {Hank}, 'follow', 'pending')
			(assuming that Tom & Hank both do not automatically accept subscription
			requests. If either automatically accepts it, the created record will
			have friend = 'yes' instead.)
			Tom rejects John's subscription request, which deletes the pending record
			Hank accepts John as a friend, which updates the pending record
			to
				({John}, {Hank}, 'buddy', 'yes')
			but does not add a reverse record, unless Hank explicitly subscribes to John.

			In vB5, John's "friends" for the buddylist are defined by the records:
				({John}, {Hank}, 'buddy', 'yes')
		So even though John wanted to be able to see Tom in his buddylist, there isn't
		a record to look for as soon as Tom rejects the request. I'm not sure if it
		makes sense to count a friend = 'pending' record as a "friend" for vB5, as
		pending records are more ephemeral in vB5.

		Furthermore, I don't think adding John's subscribers (that is,
		userlist.relationid = {John} instead of userlist.userid = {John}) to the
		buddylist makes a whole lot of sense when trying to find the nearest analogs
		to vB4's "friends". It would also have less "value" than just the John's
		subscribee's (user.userid = {John}), especially if the user has numerous
		auto-accepted subscribers (e.g. a popular content creator or a site staff with
		hundreds or more subscribers).

		So, for the buddy list, we're only looking for
			userlist.userid = {currentuser}, type = "follow", friend = "yes"
		records. I think the closest existing vB5 API function for this data would be
		vB_Api_Follow::getFollowingUsers() .However, that method doesn't return
		user.options (for invisible check) & lastactivity, so I think we're better off
		doing our own query.
		*/
		$currentUserContext = vB::getUserContext();
		$userid = $currentUserContext->fetchUserId();
		if (empty($userid))
		{
			return array('response' => array('errormessage' => array('nopermission_loggedout')));
		}

		$bf_misc_useroptions = vB::getDatastore()->getValue('bf_misc_useroptions');
		$timeout = vB::getDatastore()->getOption('cookietimeout');
		$cutoff = vB::getRequest()->getTimeNow() - $timeout;
		$data = array(
			'userid' => $userid,
			'bit_useroptions_invisible' => $bf_misc_useroptions['invisible'],
			'cutoff' => $cutoff,
		);
		$allusers = vB::getDbAssertor()->assertQuery('fetchDataForBuddyList', $data);

		$canSeeHidden = $currentUserContext->hasPermission('genericpermissions', 'canseehidden');
		$onlineFriends = array();
		$offlineFriends = array();
		// Leaving $buddies out since it wasn't explicitlys pecified in the docs, and unsure
		// if mobile clients actually use it. It seems to be a space delimited list of
		// online buddies, but always starting with a '0 ' for whatever reason.
		//$buddies = '0 ';
		// some of this logic is based on fetch_online_status(), but
		// I opted to just reproduce some logic here as to not add dependency on
		// legacy code.
		// If there's duplicate session records (e.g. browsing on phone and pc)
		// we only care about the latest lastactivity.
		foreach($allusers as $_friend)
		{
			$_friendid = $_friend['userid'];
			$_invisiblemark = "";
			$_online = "offline";
			$_onlinestatusphrase = "x_is_offline";
			// Since we checked the cutoff in the query, if it has a lastactivity
			// joined, they're online. The legacy code also has some checks with
			// 'lastvisit', which we're just ignoring for now.
			$_isOnline = !empty($_friend['lastactivity']);
			if ($_isOnline)
			{
				if ($_friend['invisible'] > 0)
				{
					// If they're invisible, treat them as offline unless user has permission
					// to view invisible users.
					if ($canSeeHidden)
					{
						$_invisiblemark = "*";
						$_online = "invisible";
						$_onlinestatusphrase = "x_is_invisible";
						// if user can see the invisible online users, these go in the "online" block
						$_isOnline = true;
					}
					else
					{
						// This is different behavior than vB4.
						// Since we do not join "offline" session records via filter on the
						// query, a non empty lastactivity for invisible users implies
						// that they're online, which IMO is a privacy breach.
						$_friend['lastactivity'] = NULL;
						$_isOnline = false;
					}
				}
				else
				{
					// online AND visible.
					$_online = "online";
					$_onlinestatusphrase = "x_is_online_now";
				}
			}

			$_data = array(
				'buddy' => array(
					'username'           => $_friend['username'],
					'invisible'          => $_friend['invisible'],
					'userid'             => $_friendid,
					'lastactivity'       => $_friend['lastactivity'],
					// This seems to be only meaningful for "who's online" type of
					// user lists. I think for the buddylist, it will ALWAYS be a '+'
					// since every friend is, by definition, on the buddylist.
					'buddymark'          => '+',
					'invisiblemark'      => $_invisiblemark,
					'online'             => $_online,
					'onlinestatusphrase' => $_onlinestatusphrase,
					'statusicon'         => $_online,
				),
			);
			if ($_isOnline)
			{
				// Query ordered by username, lastactivity. Ignore older lastactivities.
				if (!isset($onlineFriends[$_friendid]))
				{
					$onlineFriends[$_friendid] = $_data;
				}
				//$buddies .= $_friendid . ' ';
			}
			else
			{
				$offlineFriends[$_friendid] = $_data;
			}
		}

		return array(
			'response' => array(
				'offlineusers' => $offlineFriends,
				'onlineusers'  => $onlineFriends,
				//'buddies'      => urlencode(trim($buddies)),
			)
		);
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 101141 $
|| #######################################################################
\*=========================================================================*/
