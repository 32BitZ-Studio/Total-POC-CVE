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

/*
if (!isset($GLOBALS['vbulletin']->db))
{
	exit;
}
*/

class vB_Upgrade_504a1 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '504a1';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.0.4 Alpha 1';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.0.3';

	/**
	* Beginning version compatibility
	*
	* @var	string
	*/
	public $VERSION_COMPAT_STARTS = '';

	/**
	* Ending version compatibility
	*
	* @var	string
	*/
	public $VERSION_COMPAT_ENDS   = '';

	/**
	 * 501a2 step8 changed all userlist.type = 'buddy' fields to
	 * userlist.type = 'follow'.  This included those with friend = 'denied.
	 * vB5 sets userlist.type = 'ignore', userlist.friend = 'denied'
	 * to equate a deny so we must update these bogus records.
	 * Update userlist.type = 'follow', userlist.friend = 'denied' to
	 * userlist.type = 'ignore', userlist.friend = 'denied'
	 *
	 * VBV-11987: In previous versions, the state "type=buddy,friend=denied" was when you sent
	 * a friend request to someone and they denied it. It was shown to you as still pending.
	 * In vB5, if your follow request is denied, the state is "type=follow,friend=pending", so
	 * we should change "type=follow,friend=denied" (buddy has been changed to follow) to
	 * "type=follow,friend=pending" instead of trying to convert it into an ignore user record
	 * when it was never intended to be an ignore. Trying to convert it to an ignore record
	 * is the source of the duplicate key error, since you could have both a friend request
	 * to someone that they have denied (type=follow,friend=denied) and you could ignore
	 * (type=ignore) that same user. As for sites that successfully ran this step, there is no
	 * way to reliably detect the incorrect ignore records and reverse them, since they are
	 * marked the same "type=ignore,friend=denied" as vB5 currently marks them.
	 */
	public function step_1()
	{
		$this->show_message(sprintf($this->phrase['vbphrase']['update_table'], 'userlist'));
		vB::getDbAssertor()->update('userlist', array(
			'friend' => 'pending'
		), array(
			'type'   => 'follow',
			'friend' => 'denied'
		));
	}

	/**
	 * Import follow requests .. but not those that are ignored
	 */
	public function step_2($data = NULL)
	{
		$batchsize = 125;
		$startat = intval($data['startat']);

		// Check if any users have custom folders
		if (!empty($data['totalUsers']))
		{
			$totalUsers = $data['totalUsers'];
		}
		else
		{
			// Get the number of users that have pending requests
			$totalUsers = vB::getDbAssertor()->getRow('vBInstall:getTotalPendingFriends');
			$totalUsers = intval($totalUsers['totalusers']);

			if (intval($totalUsers) < 1)
			{
				$this->skip_message();
				return;
			}
			else
			{
				$this->show_message($this->phrase['version']['504a1']['converting_pending_friend_requests']);
			}
		}

		if ($startat >= $totalUsers)
		{
			$this->show_message(sprintf($this->phrase['core']['process_done']));
			return;
		}

		$totaldone = (($startat + $batchsize) > $totalUsers ? $totalUsers : $startat + $batchsize);
		$this->show_message(sprintf($this->phrase['core']['processed_records_x_y_z'], $startat + 1, $totaldone, $totalUsers));
		$users = vB::getDbAssertor()->getRows('vBInstall:convertPendingFriends', array('startat' => $startat, 'batchsize' => $batchsize));

		if ($users)
		{
			vB_Upgrade::createAdminSession();

			$messageLibrary = vB_Library::instance('Content_Privatemessage');
			// Note: These are requests, not notifications, and are not affected by notification refactor.
			$notifications = array();

			foreach($users AS $user)
			{
				if (!$user['ignored'])
				{
					// Check if this request already has a notification
					$existing = vB::getDbAssertor()->getRows('vBInstall:getCurrentPendingRequest', array('userid' => $user['userid'], 'relationid' => $user['relationid']));
					if (!$existing)
					{
						$notifications[] = array(
							'msgtype' => 'request',
							'sentto'  => $user['relationid'],
							'aboutid' => $user['userid'],
							'about'   => 'follow',
							'sender'  => $user['userid']
						);
					}
				}
			}

			foreach ($notifications AS $notification)
			{
				// send notification only if receiver is not the sender.

				if ($notification['sentto'] != $notification['sender'])
				{
					try
					{	// This will throw an exception if the user doesn't exist
						$check = vB::getDbAssertor()->assertQuery('user', array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
							'userid' => array($notification['sender'], $notification['sender'])));

						//There should be two records.
						if ($check->valid() AND $check->next() AND $check->valid())
						{
							$nodeid = $messageLibrary->addMessageNoFlood($notification);
						}
					}
					catch (vB_Exception_Api $e)
					{}
				}
			}
		}

		return array('startat' => ($startat + $batchsize), 'totalUsers' => $totalUsers);
	}

	/**
	 * convert title, meta keywords and description of user custom existing pages into phrases
	 * remove columns from page table
	 */
	public function step_3()
	{
		if (!$this->field_exists('page', 'title'))
		{
			$this->skip_message();
			return;
		}

		$this->show_message($this->phrase['version']['504a1']['converting_page_metadata_to_phrases']);

		vB_Upgrade::createAdminSession();

		$phraseApi = vB_Api::instanceInternal('phrase');

		// List pages
		$pages = vB::getDbAssertor()->getRows('page');
		$replace = array(
			0 => array('find' => array('.', 'vbulletin-'), 'replace' => ''),
			1 => array('find' => array('-'), 'replace' => '_')
		);
		foreach ($pages as $page)
		{
			$guidforphrase = str_replace($replace[0]['find'], $replace[0]['replace'], $page['guid']);
			$guidforphrase = str_replace($replace[1]['find'], $replace[1]['replace'], $guidforphrase);

			if (!empty($page['title']))
			{
				$check = vB::getDbAssertor()->getField('vBInstall:checkPagePhrase', array('varname' => 'page_' . $guidforphrase . '_title'));
				if (empty($check))
				{
					$phraseApi->save('pagemeta',
						'page_' . $guidforphrase . '_title',
						array(
							'text' => array($page['title']),
							'product' => 'vbulletin',
							'oldvarname' => 'page_' . $guidforphrase . '_title',
							'oldfieldname' => 'global',
							'skipdebug' => 1,
						)
					);
				}
			}

			if (!empty($page['metadescription']))
			{
				$check = vB::getDbAssertor()->getField('vBInstall:checkPagePhrase', array('varname' => 'page_' . $guidforphrase . '_metadesc'));
				if (empty($check))
				{
					$phraseApi->save('pagemeta',
						'page_' . $guidforphrase . '_metadesc',
						array(
							'text' => array($page['metadescription']),
							'product' => 'vbulletin',
							'oldvarname' => 'page_' . $guidforphrase . '_metadesc',
							'oldfieldname' => 'global',
							'skipdebug' => 1,
						)
					);
				}
			}

				}

		$this->show_message($this->phrase['core']['done']);

		// TODO: we should remove these 3 fields from page table later.
		// title, metadescription, metakeywords
	}

	/**
	 * Increase the size of 'title' field in product table
	 */
	public function step_4()
	{
		$this->run_query(
			sprintf($this->phrase['core']['altering_x_table'], 'product', 1, 1),
			"ALTER TABLE " . TABLE_PREFIX . "product CHANGE title title VARCHAR(250) NOT NULL DEFAULT '0'"
		);
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
