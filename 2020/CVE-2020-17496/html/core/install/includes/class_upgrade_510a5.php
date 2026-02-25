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

class vB_Upgrade_510a5 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '510a5';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.1.0 Alpha 5';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.1.0 Alpha 4';

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
	 * Step 1 - Long step warning for step 2.
	 */
	public function step_1($data = null)
	{
		$this->long_next_step();
	}

	/**
	 * Step 2 - Updates preview image to a valid vB5 value (VBV-11788).
	 */
	public function step_2($data = null)
	{
		$startat = (int) isset($data['startat']) ? $data['startat'] : 0;
		$batchsize = 300;

		$assertor = vB::getDbAssertor();

		if ($startat == 0)
		{
			$this->show_message(sprintf($this->phrase['version']['510a5']['updating_article_preview_images']));
		}

		// Get nodeids
		// don't send startat to the query, since the previous nodes have been modified
		// and will no longer match this query (it always needs to start from offset 0).
		$rows = $assertor->getRows('vBInstall:getNodesWithUrlPreviewImage', array(
			'batchsize' => $batchsize,
		));

		if (empty($rows))
		{
			// done
			$this->show_message(sprintf($this->phrase['core']['process_done']));

			return;
		}
		else
		{
			// process the preview images

			vB_Upgrade::createAdminSession();

			$processedFrom = 0;
			$processedTo = 0;
			$legacyattachmentids = array();

			// Remove any current previewimages in case the legacy attachment is not available
			// or autoPopulatePreviewImage doesn't find one to set
			$nodeids = array();
			foreach ($rows AS $row)
			{
				$nodeids[] = $row['nodeid'];
			}
			$assertor->update('vBForum:text', array('previewimage' => ''), array('nodeid' => $nodeids));
			unset($nodeids);

			foreach ($rows AS $row)
			{
				if (preg_match('/attachment\.php\?attachmentid=(\d+)/i', $row['previewimage'], $match))
				{
					$legacyattachmentids[$row['nodeid']] = (int) $match[1];
				}
				else
				{
					// Handle custom preview image tag for static HTML pages and PHP eval pages/
					// In this case, we will scan the article and auto-assign a preview as we do
					// for all regular articles in vB5.
					vB_Api::instanceInternal('Content_Text')->autoPopulatePreviewImage($row['nodeid']);
				}

				if ($processedFrom == 0)
				{
					$processedFrom = $row['nodeid'];
					$processedTo = $row['nodeid'];
				}
				$processedFrom = min($processedFrom, $row['nodeid']);
				$processedTo = max($processedFrom, $row['nodeid']);
			}

			// get nodeids for the attachments
			if (!empty($legacyattachmentids))
			{
				$legacyattachments = vB_Api::instanceInternal('filedata')->fetchLegacyAttachments(array_values($legacyattachmentids));

				foreach ($legacyattachmentids AS $nodeid => $attachmentid)
				{
					if (isset($legacyattachments[$attachmentid]))
					{
						$legacyattachment = $legacyattachments[$attachmentid];

						/*update query*/
						$assertor->update('vBForum:text', array('previewimage' => $legacyattachment['nodeid']), array('nodeid' => $nodeid));
					}
				}
				unset($legacyattachmentids, $legacyattachments, $legacyattachment);
			}

			// output progress
			$this->show_message(sprintf($this->phrase['core']['processed_records_x_y'], $processedFrom, $processedTo));

			// return for next batch
			return array('startat' => $startat + $batchsize);
		}
	}

	/** Make sure the two article system usergroups exist */
	public function step_3()
	{
		vB_Upgrade::createAdminSession();
		$this->show_message(sprintf($this->phrase['vbphrase']['update_table'], TABLE_PREFIX . 'permission'));
		$this->createSystemGroups();

		// rebuild usergroup cache
		vB_Library::instance('usergroup')->buildDatastore();
		vB_Api::instanceInternal('usergroup')->fetchUsergroupList(true);
	}

	/** Set default Article permissions
	*/
	public function step_4()
	{
		// we should only run this once.  If completed this will show as step = 0 because it's the last.
		$check = vB::getDbAssertor()->assertQuery('vBInstall:upgradelog', array('script' => '510a5', 'step' => '0'));

		if ($check->valid())
		{
			$this->skip_message();
		}
		else
		{
			vB_Upgrade::createAdminSession();
			$this->show_message(sprintf($this->phrase['vbphrase']['update_table'], TABLE_PREFIX . 'permission'));
			$parsedRaw = vB_Xml_Import::parseFile(DIR . '/includes/xml/bitfield_vbulletin.xml');
			$permBits = array();
			foreach ($parsedRaw['bitfielddefs']['group'] AS $group)
			{
				if ($group['name'] == 'ugp')
				{
					foreach($group['group'] AS $bfgroup)
					{
						if (($bfgroup['name'] == 'forumpermissions2') OR ($bfgroup['name'] == 'forumpermissions') OR
							($bfgroup['name'] == 'createpermissions'))
						{
							$permBits[$bfgroup['name']] = array();
							foreach ($bfgroup['bitfield'] AS $bitfield)
							{
								$permBits[$bfgroup['name']][$bitfield['name']] = intval($bitfield['value']);
							}
						}
					}
				}
			}
			//revoke create from registered users and guests from Articles channel.
			$channel = vB_Library::instance('content_channel')->fetchChannelByGUID(vB_Channel::DEFAULT_ARTICLE_PARENT);
			$groupApi = vB_Api::instanceInternal('usergroup');
			$registered = $groupApi->fetchUsergroupBySystemID(vB_Api_UserGroup::REGISTERED_SYSGROUPID);
			$registered = $registered['usergroupid'];
			$guest = $groupApi->fetchUsergroupBySystemID(vB_Api_UserGroup::UNREGISTERED_SYSGROUPID);
			$guest = $guest['usergroupid'];
			$author = $groupApi->fetchUsergroupBySystemID(vB_Api_UserGroup::CMS_AUTHOR_SYSGROUPID);
			$author = $author['usergroupid'];
			$editor = $groupApi->fetchUsergroupBySystemID(vB_Api_UserGroup::CMS_EDITOR_SYSGROUPID);
			$editor = $editor['usergroupid'];
			$channelPermHandler = vB_ChannelPermission::instance();

			$defaultPerms = vB::getDbAssertor()->getRow('vBForum:permission', array('nodeid' => 1, 'groupid' => $registered));
			unset($defaultPerms['permissionid']);
			unset($defaultPerms['groupid']);
			unset($defaultPerms['nodeid']);
			$found = array();


			$perms = $defaultPerms;
			$perms['forumpermissions'] |= $permBits['forumpermissions']['canpostnew']  |
				$permBits['forumpermissions']['canseedelnotice'] | $permBits['forumpermissions']['canview'] |
				$permBits['forumpermissions']['canviewthreads'] | $permBits['forumpermissions']['canviewothers'] |
				$permBits['forumpermissions']['canreply'] | $permBits['forumpermissions']['caneditpost'] |
				$permBits['forumpermissions']['cangetattachment'] | $permBits['forumpermissions']['canpostattachment'] |
				$permBits['forumpermissions']['cantagown'] | $permBits['forumpermissions']['candeletetagown'];
			$perms['forumpermissions2'] |= $permBits['forumpermissions2']['canalwaysview'];
			//but not canpublish
			$perms['forumpermissions2'] &= ~$permBits['forumpermissions2']['canpublish'];
			// and force moderation
			$perms['createpermissions'] |= $permBits['createpermissions']['vbforum_text'] |
				$permBits['createpermissions']['vbforum_gallery'] | $permBits['createpermissions']['vbforum_poll'] |
				$permBits['createpermissions']['vbforum_attach'] | $permBits['createpermissions']['vbforum_photo'] |
				$permBits['createpermissions']['vbforum_video'] | $permBits['createpermissions']['vbforum_link'];
			//Allow to edit own for 365 days.
			//Allow to edit for 365 days.
			$perms['edit_time'] = 365;
			//and save
			$channelPermHandler->setPermissions($channel['nodeid'], $author, $perms);

			$perms = $defaultPerms;
			$perms['forumpermissions'] |= $permBits['forumpermissions']['canpostnew'] |
				$permBits['forumpermissions']['canseedelnotice'] | $permBits['forumpermissions']['canview'] |
				$permBits['forumpermissions']['canviewthreads'] | $permBits['forumpermissions']['canviewothers'] |
				$permBits['forumpermissions']['canreply'] | $permBits['forumpermissions']['caneditpost'] |
				$permBits['forumpermissions']['cangetattachment'] | $permBits['forumpermissions']['canpostattachment'] |
				$permBits['forumpermissions']['cantagown'] | $permBits['forumpermissions']['candeletetagown'] |
				$permBits['forumpermissions']['caneditpost'];
			$perms['forumpermissions2'] |= $permBits['forumpermissions2']['canalwaysview'];
			$perms['forumpermissions2'] |= $permBits['forumpermissions2']['canalwayspost'];
			$perms['forumpermissions2'] |= $permBits['forumpermissions2']['canpublish'];
			$perms['forumpermissions2'] |= $permBits['forumpermissions2']['caneditothers'];
			$perms['createpermissions'] |= $permBits['createpermissions']['vbforum_text'] |
				$permBits['createpermissions']['vbforum_gallery'] | $permBits['createpermissions']['vbforum_poll'] |
				$permBits['createpermissions']['vbforum_attach'] | $permBits['createpermissions']['vbforum_photo'] |
				$permBits['createpermissions']['vbforum_video'] |$permBits['createpermissions']['vbforum_link'];
			//Allow to edit own for 365 days.
			$perms['edit_time'] = 365;
			//and save
			$channelPermHandler->setPermissions($channel['nodeid'], $editor, $perms);

			$perms = $defaultPerms;
			$perms['forumpermissions'] &= ~$permBits['forumpermissions']['canpostnew'];
			$perms['forumpermissions2'] &= ~$permBits['forumpermissions2']['canpublish'];
			// followforummoderation, 131072 was removed from bitfields in VBV-7734, but still referenced in a few upgrade steps. Hard coding it for now.
			$perms['forumpermissions'] |= $permBits['forumpermissions']['canreply'] | $permBits['forumpermissions']['canview'] |
				$permBits['forumpermissions']['canviewthreads'] | $permBits['forumpermissions']['canviewothers'] |
				$permBits['forumpermissions']['cangetattachment'] | 131072;
			$perms['forumpermissions2'] |= $permBits['forumpermissions2']['cancomment'];
			$channelPermHandler->setPermissions($channel['nodeid'], $registered, $perms);


			$perms = vB::getDbAssertor()->getRow('vBForum:permission', array('nodeid' => $channel['nodeid'], 'groupid' => $guest));

			// if there's no existing channel permission for guests for the article channel, let's take their perms for the root channel
			// there's no fallback for the root channel because I don't think it's possible for that particular permission record to be missing
			if (empty($perms))
			{
				$rootchannel = vB_Library::instance('content_channel')->fetchChannelByGUID(vB_Channel::MAIN_CHANNEL);
				$perms = vB::getDbAssertor()->getRow('vBForum:permission', array('nodeid' => $rootchannel['nodeid'], 'groupid' => $guest));
				unset($perms['permissionid']);
				unset($perms['groupid']);
				unset($perms['nodeid']);
			}

			$perms['forumpermissions'] &= ~$permBits['forumpermissions']['canpostnew'];
			$perms['forumpermissions'] &= ~$permBits['forumpermissions']['canreply'];
			$perms['forumpermissions2'] &= ~$permBits['forumpermissions2']['canpublish'];
			$perms['forumpermissions2'] &= ~$permBits['forumpermissions2']['cancomment'];
			$channelPermHandler->setPermissions($channel['nodeid'], $guest, $perms);
		}
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 100512 $
|| #######################################################################
\*=========================================================================*/
