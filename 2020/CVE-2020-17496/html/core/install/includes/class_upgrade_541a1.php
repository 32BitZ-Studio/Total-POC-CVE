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
/*
if (!isset($GLOBALS['vbulletin']->db))
{
	exit;
}
*/

class vB_Upgrade_541a1 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '541a1';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.4.1 Alpha 1';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.4.0';

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


	// Set albums as unprotected so they show up in search results
	public function step_1()
	{
		$this->show_message($this->phrase['version']['541a1']['show_albums_in_search']);

		$db = vB::getDbAssertor();

		$albumChannel = $db->getRow('vBForum:channel', array('guid' => vB_Channel::ALBUM_CHANNEL));
		if (!empty($albumChannel['nodeid']))
		{
			$db->assertQuery('vBInstall:updateChannelProtected',
				array(
					'channelid' => $albumChannel['nodeid'],
					'protected' => 0,
				)
			);
		}
	}

	// Set infraction & report nodes to be protected (in case any old ones
	// prior to special channel being protected exist on this forum).
	public function step_2()
	{
		$this->show_message($this->phrase['version']['541a1']['update_old_infraction_report_nodes']);

		$db = vB::getDbAssertor();

		$channels = $db->getRows('vBForum:channel', array('guid' => array(vB_Channel::INFRACTION_CHANNEL, vB_Channel::REPORT_CHANNEL)));
		foreach ($channels AS $channel)
		{
			if (!empty($channel['nodeid']))
			{
				$db->assertQuery('vBInstall:updateChannelProtected',
					array(
						'channelid' => $channel['nodeid'],
						'protected' => 1,
					)
				);
			}
		}
	}

	// Update any imported albums with the incorrect channel routeid to conversation routeid
	public function step_3()
	{
		vB_Upgrade::createAdminSession();
		$assertor = vB::getDbAssertor();
		$albumChannel = vB_Library::instance('node')->fetchAlbumChannel();
		$albumRouteid = $assertor->getColumn('vBForum:node', 'routeid', array('nodeid' => $albumChannel));
		$albumRouteid = reset($albumRouteid);

		$check = $assertor->getRow('vBForum:node', array('parentid' => $albumChannel, 'routeid' => $albumRouteid));
		if (!empty($check))
		{
			$channelRoute = $assertor->getRow('routenew',
				array(
					'contentid' => $albumChannel,
					'class' => 'vB5_Route_Channel',
				)
			);
			$convoRoute = $assertor->getRow('routenew',
				array(
					'contentid' => $albumChannel,
					'class' => 'vB5_Route_Conversation',
				)
			);
			/*
			Note:
				500b12 step_3()'s fixNodeRouteid , which comes after 500a28 step_17()'s import album,
				failed to fix the broken starter routeids because it seems at the first import, the starters
				are NOT set. The starters seem to be fixed later down the line in another upgrade step.
			 */
			$this->show_message($this->phrase['version'][$this->SHORT_VERSION]['updating_imported_album_routeid']);
			$assertor->assertQuery('vBInstall:updateRouteidForStarterNodeWithParentAndRoute',
				array(
					'newRouteid' => $convoRoute['routeid'],
					'oldRouteid' => $channelRoute['routeid'],
					'parentid' => $albumChannel,
				)
			);
		}
		else
		{
			$this->skip_message();
		}
	}


	// Add admin message to warn about broken view permssions for updated albums
	public function step_4()
	{
		$this->add_adminmessage(
			'after_upgrade_notify_users_check_album_viewperms',
			array(
				'dismissible' => 1,
				'execurl'     => 'announcement.php?do=add',
				'method'      => 'get',
				'status'      => 'undone',
			)
		);
	}

	// change require_moderate to skip_moderate pt 1
	// add column
	public function step_5()
	{
		if (!$this->field_exists('permission', 'skip_moderate'))
		{

			$this->run_query(
				sprintf($this->phrase['core']['altering_x_table'], 'permission', 1, 3),
				"ALTER TABLE " . TABLE_PREFIX . "permission
					ADD COLUMN skip_moderate SMALLINT UNSIGNED NOT NULL DEFAULT 0"
			);
		}
		else
		{
			$this->skip_message();
		}
	}

	// change require_moderate to skip_moderate pt 2
	// flip the bit & save to new column
	public function step_6($data = null)
	{
		vB_Upgrade::createAdminSession();
		$assertor = vB::getDbAssertor();

		$count = $assertor->getRow('vBInstall:getRequireModerateNeedingConversionCount');
		if (!empty($count))
		{
			$count = $count['count'];
		}

		if ($this->field_exists('permission', 'require_moderate'))
		{
			if (!empty($count))
			{
				$this->show_message(
					sprintf($this->phrase['core']['altering_x_table'], 'permission', 2, 3)
				);
				$assertor->assertQuery('vBInstall:convertRequireModerateToSkipModerate');
			}
			else
			{
				$this->skip_message();
			}
		}
		else
		{
			$this->skip_message();
		}
	}

	// change require_moderate to skip_moderate pt 3
	// drop old column once finished.
	public function step_7($data = null)
	{
		vB_Upgrade::createAdminSession();
		$assertor = vB::getDbAssertor();

		$count = $assertor->getRow('vBInstall:getRequireModerateNeedingConversionCount');
		if (!empty($count))
		{
			$count = $count['count'];
		}

		if ($this->field_exists('permission', 'require_moderate'))
		{
			if (empty($count))
			{
				$this->run_query(
					sprintf($this->phrase['core']['altering_x_table'], 'permission', 3, 3),
					"ALTER TABLE " . TABLE_PREFIX . "permission
						DROP COLUMN require_moderate"
				);
				// rebuild any caches that might reference permission table fields (AFAIK mostly in memory in permissioncontext)
				vB::getUserContext()->rebuildGroupAccess();
				// done
				$this->show_message(sprintf($this->phrase['core']['process_done']));
			}
			else
			{
				// step 6 isn't finished.. not much we can do here.
				$this->skip_message();
			}
		}
		else
		{
			$this->skip_message();
		}
	}
}

/*======================================================================*\
|| ####################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 101013 $
|| ####################################################################
\*======================================================================*/