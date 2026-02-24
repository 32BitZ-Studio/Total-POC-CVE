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

class vB_Upgrade_500rc1 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '500rc1';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.0.0 Release Candidate 1';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.0.0 Beta 28';

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
	 * Handle customized values for stylevars that have been renamed
	 */
	public function step_1()
	{
		$mapper = new vB_Stylevar_Mapper();

		// Add mappings
		$mapper->addMapping('thread_comment_background', 'comment_background');
		$mapper->addMapping('thread_comment_divider_color', 'comment_divider_color');

		// Do the processing
		if ($mapper->load() AND $mapper->process())
		{
			$this->show_message($this->phrase['version']['408']['mapping_customized_stylevars']);
			$mapper->processResults();
		}
		else
		{
			$this->skip_message();
		}
	}

	/**
	 * Add forumpermissons2 field in permission table.
	 */
	function step_2()
	{
		$this->add_field(
			sprintf($this->phrase['core']['altering_x_table'], 'permission', 1, 1),
			'permission',
			'forumpermissions2',
			'int',
			array('length' => 10, 'null' => false, 'default' => 0, 'attributes' => 'UNSIGNED')
		);
	}

	/**
	 * Update site navbars
	 */
	public function step_3()
	{
		$this->syncNavbars();
	}

	public function step_4()
	{
		$this->skip_message();
	}

	/** Drop hasowner column **/
	public function step_5()
	{
		if ($this->field_exists('node', 'hasowner'))
		{
			$this->drop_field(
				sprintf($this->phrase['core']['altering_x_table'], 'node', 1, 1),
				'node',
				'hasowner'
			);
		}
		else
		{
			$this->skip_message();
		}
	}

	/*
	 * The channel owner should have canconfigchannel in any channels where they are a moderator
	 */
	public function step_6()
	{
		vB_Upgrade::createAdminSession();
		$this->show_message($this->phrase['version']['500rc1']['correcting_channelowner_permission']);
		$forumPerms = vB::getDatastore()->getValue('bf_ugp_forumpermissions2');
		vB::getDbAssertor()->assertQuery('vBInstall:grantOwnerForumPerm:',
			array('permission' => $forumPerms['canconfigchannel'], 'systemgroupid' => 9));
		vB::getUserContext()->rebuildGroupAccess();

	}

	/**
	 * Add missing request and notification types
	 */
	public function step_7()
	{
		$this->run_query(
			sprintf($this->phrase['core']['altering_x_table'], 'privatemessage', 1, 1),
			"ALTER TABLE " . TABLE_PREFIX . "privatemessage CHANGE about about ENUM(
				'vote',
				'vote_reply',
				'rate',
				'reply',
				'follow',
				'following',
				'vm',
				'comment',
				'threadcomment',
				'subscription',
				'moderate',
				'" . vB_Api_Node::REQUEST_TAKE_OWNER . "',
				'" . vB_Api_Node::REQUEST_TAKE_MODERATOR . "',
				'" . vB_Api_Node::REQUEST_GRANT_OWNER . "',
				'" . vB_Api_Node::REQUEST_GRANT_MODERATOR . "',
				'" . vB_Api_Node::REQUEST_GRANT_MEMBER . "',
				'" . vB_Api_Node::REQUEST_TAKE_MEMBER . "',
				'" . vB_Api_Node::REQUEST_TAKE_SUBSCRIBER . "',
				'" . vB_Api_Node::REQUEST_GRANT_SUBSCRIBER . "',
				'" . vB_Api_Node::REQUEST_SG_TAKE_OWNER . "',
				'" . vB_Api_Node::REQUEST_SG_TAKE_MODERATOR . "',
				'" . vB_Api_Node::REQUEST_SG_GRANT_OWNER . "',
				'" . vB_Api_Node::REQUEST_SG_GRANT_MODERATOR . "',
				'" . vB_Api_Node::REQUEST_SG_GRANT_SUBSCRIBER . "',
				'" . vB_Api_Node::REQUEST_SG_TAKE_SUBSCRIBER . "',
				'" . vB_Api_Node::REQUEST_SG_GRANT_MEMBER . "',
				'" . vB_Api_Node::REQUEST_SG_TAKE_MEMBER . "');
			"
		);
	}

	/**
	 * Import notifications for new visitor messages
	 */
	function step_8($data = NULL)
	{
		// THIS HAS BEEN UPDATED AND MOVED INTO 516A6 STEP 1, AS IT REQUIRES
		// THE NEW NOTIFICATION TABLES & TYPE DATA.
		$this->skip_message();
		return;
	}

	/**
	 * Import notifications for social group invites
	 */
	function step_9($data = null)
	{
		if (!$this->tableExists('socialgroupmember'))
		{
			$this->skip_message();
			return;
		}

		if(empty($data['startat']))
		{
			$this->show_message(sprintf($this->phrase['vbphrase']['update_table'], TABLE_PREFIX . 'node'));
		}

		$callback = function($startat, $nextid)
		{
			// Fetch user info
			$users = vB::getDbAssertor()->assertQuery('user', array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
				vB_dB_Query::COLUMNS_KEY => array('userid', 'socgroupinvitecount'),
				vB_dB_Query::CONDITIONS_KEY => array(
					array('field' => 'userid', 'value' => $startat, 'operator' => vB_dB_Query::OPERATOR_GTE),
					array('field' => 'userid', 'value' => $nextid, 'operator' => vB_dB_Query::OPERATOR_LT),
				)
			));

			if ($users)
			{
				vB_Upgrade::createAdminSession();

				//$nodeLibrary = vB_Library::instance('node');

				// build a map of group info, indexed by the old groupid
				$groupInfo = array();

				$oldContentTypeId = vB_Types::instance()->getContentTypeID('vBForum_SocialGroup');
				$oldSocialGroups = vB::getDbAssertor()->assertQuery('vbForum:node', array(
					vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
					vB_dB_Query::COLUMNS_KEY => array('nodeid', 'oldid', 'userid'),
					vB_dB_Query::CONDITIONS_KEY => array(
						array('field' => 'oldcontenttypeid', 'value' => $oldContentTypeId),
					),
				));
				if ($oldSocialGroups)
				{
					foreach ($oldSocialGroups AS $oldSocialGroup)
					{
						$groupInfo[$oldSocialGroup['oldid']] = $oldSocialGroup;
					}
				}

				// Note: These are requests, not notifications, and are not affected by notification refactor.
				$notifications = array();

				foreach($users AS $user)
				{

					if ($user['socgroupinvitecount'] > 0)
					{
						// get groups that this user has been invited to
						$groups = vB::getDbAssertor()->getRows('vBInstall:socialgroupmember', array(
							vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
							vB_dB_Query::COLUMNS_KEY => array('groupid'),
							vB_dB_Query::CONDITIONS_KEY => array(
								array('field' => 'userid', 'value' => $user['userid']),
								array('field' => 'type', 'value' => 'invited'),
							),
						));

						// get vB5 node information for the groups
						$nodes = array();
						foreach ($groups AS $group)
						{
							if ($group['groupid'] > 0)
							{
								$nodes[] = $groupInfo[$group['groupid']];
							}
						}

						// prepare notifications
						foreach ($nodes AS $node)
						{
							$notifications[] = array(
								'about' => vB_Api_Node::REQUEST_SG_TAKE_MEMBER,
								'aboutid' => $node['nodeid'],
								'sentto' => $user['userid'],
								'sender' => $node['userid'],
							);

						}
					}
				}

				$messageLibrary = vB_Library::instance('Content_Privatemessage');

				foreach ($notifications AS $notification)
				{
					$notification['msgtype'] = 'request';
					$notification['rawtext'] = '';

					// send notification only if receiver is not the sender.
					// also check receiver's notification options with userReceivesNotification(userid, about)
					if (($notification['sentto'] != $notification['sender']) AND $messageLibrary->userReceivesNotification($notification['sentto'], $notification['about']))
					{
						// check for duplicate requests
						$messageLibrary->checkFolders($notification['sentto']);
						$folders = $messageLibrary->fetchFolders($notification['sentto']);
						$folderid = $folders['systemfolders'][vB_Library_Content_Privatemessage::REQUEST_FOLDER];

						$dupeCheck = vB::getDbAssertor()->getRows('vBInstall:500rc1_checkDuplicateRequests', array(
							'userid' => $notification['sentto'],
							'folderid' => $folderid,
							'aboutid' => $notification['aboutid'],
							'about' => vB_Api_Node::REQUEST_SG_TAKE_MEMBER,
						));

						// if not duplicate, insert the message
						if (count($dupeCheck) == 0)
						{
							$nodeid = $messageLibrary->addMessageNoFlood($notification);
						}
					}
				}
			}

			$this->show_message(sprintf($this->phrase['core']['processed_records_x_y'], $startat, $nextid), true);
		};

		return $this->updateByIdWalk($data,	500, 'vBInstall:getMaxUserid', 'user', 'userid', $callback);
	}

	/**
	 * Import notifications for social group join requests
	 */
	function step_10($data = null)
	{
		if (!$this->tableExists('socialgroupmember'))
		{
			$this->skip_message();
			return;
		}

		if(empty($data['startat']))
		{
			$this->show_message(sprintf($this->phrase['vbphrase']['update_table'], TABLE_PREFIX . 'node'));
		}

		$callback = function($startat, $nextid)
		{
			// Fetch user info
			$users = vB::getDbAssertor()->assertQuery('user', array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
				vB_dB_Query::COLUMNS_KEY => array('userid', 'socgroupreqcount'),
				vB_dB_Query::CONDITIONS_KEY => array(
					array('field' => 'userid', 'value' => $startat, 'operator' => vB_dB_Query::OPERATOR_GTE),
					array('field' => 'userid', 'value' => $nextid, 'operator' => vB_dB_Query::OPERATOR_LTE),
				)
			));

			if ($users)
			{
				vB_Upgrade::createAdminSession();

				//$nodeLibrary = vB_Library::instance('node');

				// build a map of group info, indexed by the old groupid
				$groupInfo = array();

				$oldContentTypeId = vB_Types::instance()->getContentTypeID('vBForum_SocialGroup');
				$oldSocialGroups = vB::getDbAssertor()->assertQuery('vbForum:node', array(
					vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
					vB_dB_Query::COLUMNS_KEY => array('nodeid', 'oldid', 'userid'),
					vB_dB_Query::CONDITIONS_KEY => array(
						array('field' => 'oldcontenttypeid', 'value' => $oldContentTypeId),
					),
				));
				if ($oldSocialGroups)
				{
					foreach ($oldSocialGroups AS $oldSocialGroup)
					{
						$groupInfo[$oldSocialGroup['oldid']] = $oldSocialGroup;
					}
				}

				// Note: These are requests, not notifications, and are not affected by notification refactor.
				$notifications = array();

				foreach($users AS $user)
				{

					if ($user['socgroupreqcount'] > 0)
					{
						// get nodes that this user owns or moderates
						$modNodeResult = vB_Library::instance('user')->getGroupInTopic($user['userid']);
						$modNodes = array();
						if ($modNodeResult)
						{
							foreach ($modNodeResult AS $modNodeResultItem)
							{
								$modNodes[] = $modNodeResultItem['nodeid'];
							}
						}

						// based on nodes, get groups that this user owns or moderates
						$modGroupOldIds = array();
						$oldContentTypeId = vB_Types::instance()->getContentTypeID('vBForum_SocialGroup');
						$modGroupsResult = vB::getDbAssertor()->assertQuery('vbForum:node', array(
							vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
							vB_dB_Query::COLUMNS_KEY => array('nodeid', 'oldid'),
							vB_dB_Query::CONDITIONS_KEY => array(
								array('field' => 'oldcontenttypeid', 'value' => $oldContentTypeId),
								array('field' => 'nodeid', 'value' => $modNodes),
							),
						));
						if ($modGroupsResult)
						{
							foreach ($modGroupsResult AS $modGroupsResultItem)
							{
								$modGroupOldIds[] = $modGroupsResultItem['oldid'];
							}
						}

						// form this user's groups, get the ones that have pending (moderated) users waiting for approval
						$groups = vB::getDbAssertor()->getRows('vBInstall:socialgroupmember', array(
							vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
							vB_dB_Query::COLUMNS_KEY => array('groupid', 'userid'),
							vB_dB_Query::CONDITIONS_KEY => array(
								array('field' => 'groupid', 'value' => $modGroupOldIds),
								array('field' => 'type', 'value' => 'moderated'),
							),
						));

						// get vB5 node information for the groups and add the userid of the pending / moderated user
						$nodes = array();
						$i = 0;
						foreach ($groups AS $group)
						{
							if ($group['groupid'] > 0)
							{
								$nodes[$i] = $groupInfo[$group['groupid']];
								$nodes[$i]['moderateduserid'] = $group['userid'];
								++$i;
							}
						}

						// prepare notifications
						foreach ($nodes AS $node)
						{
							$notifications[] = array(
								'about' => vB_Api_Node::REQUEST_SG_GRANT_MEMBER,
								'aboutid' => $node['nodeid'],
								'sentto' => $user['userid'],
								'sender' => $node['moderateduserid'],

							);
						}
					}
				}

				$messageLibrary = vB_Library::instance('Content_Privatemessage');

				foreach ($notifications AS $notification)
				{
					$notification['msgtype'] = 'request';
					$notification['rawtext'] = '';

					// send notification only if receiver is not the sender.
					// also check receiver's notification options with userReceivesNotification(userid, about)
					if (($notification['sentto'] != $notification['sender']) AND $messageLibrary->userReceivesNotification($notification['sentto'], $notification['about']))
					{
						// check for duplicate requests
						$messageLibrary->checkFolders($notification['sentto']);
						$folders = $messageLibrary->fetchFolders($notification['sentto']);
						$folderid = $folders['systemfolders'][vB_Library_Content_Privatemessage::REQUEST_FOLDER];

						$dupeCheck = vB::getDbAssertor()->getRows('vBInstall:500rc1_checkDuplicateRequests', array(
							'userid' => $notification['sentto'],
							'folderid' => $folderid,
							'aboutid' => $notification['aboutid'],
							'about' => vB_Api_Node::REQUEST_SG_GRANT_MEMBER,
						));

						// if not duplicate, insert the message
						if (count($dupeCheck) == 0)
						{
							$nodeid = $messageLibrary->addMessageNoFlood($notification, array('skipNonExistentRecipients' => true));
						}
					}
				}
			}

			$this->show_message(sprintf($this->phrase['core']['processed_records_x_y'], $startat, $nextid), true);
		};

		return $this->updateByIdWalk($data,	500, 'vBInstall:getMaxUserid', 'user', 'userid', $callback);
	}

	/*
	 * Set forum html state for imported starters (not set in 500a1 step_145)
	 */
	public function step_11($data = NULL)
	{
		//this step needs to happen before we set empty htmlstate values to off because it only
		//updates empty values. We lose that information once we force the default.  Swapping steps
		//to get the right order after collapsing the default setting from a later step.
		//
		//this is a little tricky.  In the big data set I'm looking at there is only 1 affected record.
		//normally a limit approach would be in order, but what we are looking for isn't on any kind of
		//index so we'll have to scan the resultset to find the affected records to start counting the limit.
		//At that point you might as well let the query run -- which is much faster for this DB, but risks
		//timeout on a DB with a lot more threads.  So we'll iterate over the smallest table we touch
		//(thread_post) but we'll also find the next ID instead of blindly iterating over potentently empty
		//ranges -- if we're only processing 500 at a time we should make sure there are 500 to process.
		//This requires scanning over our batch size to find the last record in the limit set, but that's bounded
		//by the batch size (and we find our starting point on the index).
		if ($this->tableExists('forum') AND $this->tableExists('post') AND $this->field_exists('post', 'htmlstate'))
		{
			$callback = function($startat, $nextid)
			{
				$this->show_message(sprintf($this->phrase['version']['500rc1']['updating_text_nodes_to_threadid'], $nextid), true);
				vB::getDbAssertor()->assertQuery('vBInstall:updateStarterPostHtmlState', array(
					'startat' => $startat,
					'nextthreadid' => $nextid,
				));
			};

			return $this->updateByIdWalk($data,	500, 'vBInstall:getThreadPostMaxThread', 'vBForum:thread_post', 'threadid', $callback);
		}
		else
		{
			$this->skip_message();
		}
	}

	/*
	 * Turn off html for imported posts that don't have allowhtml in the original forum.
	 * Relies on forum options being imported correctly before granting allow html option in a later upgrade step.
	 */
	public function step_12($data = NULL)
	{
		$db = vB::getDbAssertor();

		$batchsize = 5000;
		$threadTypeId = vB_Types::instance()->getContentTypeID('vBForum_Thread');
		$postTypeId = vB_Types::instance()->getContentTypeID('vBForum_Post');
		$forumOptions = vB::getDatastore()->getValue('bf_misc_forumoptions');
		$startat = intval($data['startat']);

		if (!empty($data['max']))
		{
			$max = $data['max'];
		}
		else
		{
			$max = $db->getRow('vBInstall:getMaxNodeid');
			$max = $max['maxid'];

			//If we don't have any posts, we're done.
			if (intval($max) < 1)
			{
				$this->skip_message();
				return;
			}
		}

		if ($startat > $max)
		{
			$this->show_message(sprintf($this->phrase['core']['process_done']));
			return;
		}

		$this->show_message(sprintf($this->phrase['version']['500rc1']['updating_text_nodes_x_y'], $startat, $max), true);
		//I'm not entirely clear on the purpose of this condition.  We don't reference any of these tables in the
		//query we wrap this in so it's not to prevent a DB error.  It's possible that the query changed at some
		//point.  I'm collapsing two steps into a single pass of the text table.  Previously this entire step
		//was wrapped in this block, but we should run *a* query here.  We'll fall back to the query the other
		//step ran previously if we wouldn't have run this step originally.  updateImportedForumPostHtmlState now
		//does what updateAllTextHtmlStateDefault in addition to what it used to do.
		//
		//Most of the time spent is in the batching/running through the records on the DB.  The actual updating is
		//small change so this should be a substantial time savings over running them twice.
		if ($this->tableExists('forum') AND $this->tableExists('post') AND $this->field_exists('post', 'htmlstate'))
		{
			$db->assertQuery('vBInstall:updateImportedForumPostHtmlState', array(
				'startat' => $startat,
				'batchsize' => $batchsize,
				'allowhtmlpermission' => $forumOptions['allowhtml'],
				'oldcontenttypeids' => array($threadTypeId, $postTypeId),
			));
		}
		else
		{
			$db->assertQuery('vBInstall:updateAllTextHtmlStateDefault', array(
				'startat' => $startat,
				'batchsize' => $batchsize
			));
		}
		return array('startat' => ($startat + $batchsize), 'max' => $max);
	}

	/**
	 * Turn off htmlstate for blog entries and comments
	 * 	from vb3/4.
	 * Turning off vB5 blog entries / comments should be handled by
	 *  updateAllTextHtmlStateDefault since they'll be null
	 * We'll tackle handling it correctly in the future, but right now we want to avoid potential XSS issues.
	 */
	public function step_13($data = NULL)
	{
		//
		// We scan the entire text table to set the html state in step 11 anyway (and previously step 17 which
		// was collapsed into step 11 -- this could be collapsed there as well)
		// What we want to set it to is different, but that could be handled with one join and some extra "or" logic.
		// Using or is frequently bad, but in this case it won't disrupt any indexes or cause us to
		// scan extra rows.  The join is going to be the bigger deal, but it's going to be faster
		// than scanning everything twice.
		//

		// check if blog product exists. Else, no action needed
		if (isset($this->registry->products['vbblog']) AND $this->registry->products['vbblog'])
		{
			$this->show_message($this->phrase['version']['500rc1']['updating_text_nodes_for_blogs']);
			$startat = intval($data['startat']);
			$batchsize = 500;
			// contenttypeid 9985 - from class_upgrade_500a22 step2
			// contenttypeid 9984 - from class_upgrade_500a22 step3
			$oldContetypeid_blogStarter = 9985;
			$oldContetypeid_blogReply = 9984;

			//this doesn't really work because "max" isn't propagated in $data, but
			//leaving it in so that it will work if we fix that.
			if (!empty($data['max']))
			{
					$max = $data['max'];
			}
			else
			{
				// grab the max id for imported vb3/4 blog entry/reply content types
				$max = vB::getDbAssertor()->getRow(	'vBInstall:getMaxNodeidForOldContent',
					array('oldcontenttypeid' => array($oldContetypeid_blogStarter, $oldContetypeid_blogReply))
				);
				$max = $max['maxid'];
			}

			if($startat > $max)
			{
				// we're done here
				$this->show_message(sprintf($this->phrase['core']['process_done']));
				return;
			}
			else
			{
				// let's just turn them all off for now.
				vB::getDbAssertor()->assertQuery('vBInstall:updateImportedBlogPostHtmlState', array(
					'startat' => $startat,
					'batchsize' => $batchsize,
					'oldcontenttypeids' => array($oldContetypeid_blogStarter, $oldContetypeid_blogReply)
				));

				// start next batch
				return array('startat' => ($startat + $batchsize), 'max' => $max);
			}
		}
		else
		{
			// no action needed for vb5 upgrades for now
			$this->skip_message();
		}
	}

	/*
	 * Update default channel options. Allow HTML by default. Leave it to channel permissions.
	 */
	public function step_14()
	{
		$this->show_message(sprintf($this->phrase['vbphrase']['update_table'], 'channel'));
		vB::getDbAssertor()->assertQuery('vBInstall:alterChannelOptions');
	}

	/*
	 * Set allowhtml for channels. This should be handled by channel permissions and text.htmlstate.
	 */
	public function step_15()
	{
		$this->show_message($this->phrase['version']['500rc1']['updating_channel_options']);
		$forumOptions = vB::getDatastore()->getValue('bf_misc_forumoptions');
		vB::getDbAssertor()->assertQuery('vBInstall:updateAllowHtmlChannelOption', array(
			'allowhtmlpermission' => $forumOptions['allowhtml']
		));
	}

	/*
	 * Set the html state to not be null and a sane default
	 */
	public function step_16()
	{
		$this->show_message(sprintf($this->phrase['vbphrase']['update_table'], 'text'));
		vB::getDbAssertor()->assertQuery('vBInstall:alterTextHtmlstate');
	}

	/**
	 * Update the default text.allow html to be 'off' instead of NULL or ''
	 * this was added to the query in step_11 and is no longer needed
	 */
	public function step_17($data = NULL)
	{
		$this->skip_message();
	}

	/**
	 * Fix contenttypeid for redirect nodes
	 */
	public function step_18($data = null)
	{
		$db = vB::getDbAssertor();

		$startat = intval($data['startat']);
		$batchsize = 500;

		//old redirects
		$oldcontenttype = 9980;

		//this doesn't really work because "max" isn't propagated in $data, but
		//leaving it in so that it will work if we fix that.
		if (!empty($data['max']))
		{
			$max = $data['max'];
		}
		else
		{
			// grab the max id for imported vb3/4 blog entry/reply content types
			$max = $db->getRow(	'vBInstall:getMaxOldidForOldContent', array('oldcontenttypeid' => $oldcontenttype));

			if(!$max)
			{
				$this->skip_message();
			}

			$max = $max['maxid'];
		}

		if($startat > $max)
		{
			// we're done here
			$this->show_message(sprintf($this->phrase['core']['process_done']));
			return;
		}

		$nextrow = $db->getRows(
			'vBForum:node',
			array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
				vB_dB_Query::CONDITIONS_KEY => array(
					'oldcontenttypeid' => $oldcontenttype,
					array('field' => 'oldid', 'value' => $startat, 'operator' =>  vB_dB_Query::OPERATOR_GT),
				),
				vB_dB_Query::COLUMNS_KEY => array('oldid'),
				vB_Db_Query::PARAM_LIMIT => 1,
				vB_Db_Query::PARAM_LIMITSTART => $batchsize
			),
			array('oldcontenttypeid', 'nodeid')
		);

		//if we don't have a row, we paged off the table so we just need to go from start to the end
		if($nextrow)
		{
			$nextrow = reset($nextrow);
			$nextoldid = $nextrow['oldid'];
		}
		else
		{
			//we don't include the next threadid in the query below so we need to go "one more than max"
			//to ensure that we process the last record and terminate on the next call.
			$nextoldid = $max+1;
		}

		$this->show_message(sprintf($this->phrase['version']['500rc1']['updating_nodes_to_oldid_x_max_y'], $nextoldid, $max));

		vB_Types::instance()->reloadTypes();
		$redirectTypeId = vB_Types::instance()->getContentTypeId('vBForum_Redirect');

		$db->assertQuery('vBInstall:fixRedirectContentTypeId', array(
			'redirectContentTypeId' => $redirectTypeId,
			'redirectOldContentTypeId' => $oldcontenttype,
			'startat' => $startat,
			'nextoldid' => $nextoldid,
		));

		// start next batch
		return array('startat' => $nextoldid, 'max' => $max);
	}

	/**
	 * Fix some forumpermissons2 values as three bitfields moved.
	 */
	function step_19()
	{
		/* We only need to run this once.
		To do this we check the upgrader log to
		see if this step has been previously run. */
		$log = vB::getDbAssertor()->getRow('vBInstall:upgradelog', array('script' => '500rc1', 'step' => 19)); // Must match this step.

		if (empty($log))
		{
			vB::getDbAssertor()->assertQuery(
			'vBInstall:fixFperms2',
			array (
					'oldp1' => 16777216, // canattachmentcss in vB4.
					'oldp2' => 33554432, // bypassdoublepost in vB4.
					'oldp3' => 67108864, // canwrtmembers in vB4.
					'newp1' => 8,
					'newp2' => 16,
					'newp3' => 32,
				)
			);

			$this->show_message(sprintf($this->phrase['core']['process_done']));
		}
		else
		{
			$this->skip_message();
		}
	}

	/*
	 * Remove the vB4.2 cronemail task if it exists.
	 */
	public function step_20()
	{
		$this->show_message(sprintf($this->phrase['vbphrase']['update_table'], 'cron'));
		vB::getDbAssertor()->delete('cron', array('varname' => array('cronmail', 'reminder', 'activitypopularity')));
	}

	/*
	 Step 21 - Used to add the nodestats (node_dailycleanup.php) cron, but the cron's been removed VBV-11871
	*/
	public function step_21()
	{
		$this->skip_message();
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 101486 $
|| #######################################################################
\*=========================================================================*/
