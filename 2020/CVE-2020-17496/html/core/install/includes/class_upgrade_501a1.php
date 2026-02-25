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

class vB_Upgrade_501a1 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '501a1';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.0.1 Alpha 1';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.0.0';

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

	public function step_1()
	{
		$this->skip_message();
	}

	/*
	 Step 2 - Used to add the nodestats (node_dailycleanup.php) cron, but the cron's been removed VBV-11871
	*/
	public function step_2()
	{
		$this->skip_message();
	}

	/*
	 * Remove the vB4 tasks
	 */
	public function step_3()
	{
		$this->show_message(sprintf($this->phrase['vbphrase']['update_table'], 'cron'));
		vB::getDbAssertor()->delete('cron', array('varname' => array('cronmail', 'reminder', 'activitypopularity')));
	}

	/** Fix blog title, description **/
	public function step_4($data = NULL)
	{
		if ($this->tableExists('blog_user') AND $this->tableExists('node'))
		{
			$this->show_message($this->phrase['version']['501a1']['fixing_blog_data']);
			$startat = intval($data['startat']);
			$batchsize = 2000;
			$assertor = vB::getDbAssertor();

			if (isset($data['startat']))
			{
				$startat = $data['startat'];
			}

			if (!empty($data['maxvB4']))
			{
				$maxToFix = $data['maxvB4'];
			}
			else
			{
				$maxToFix = $assertor->getRow('vBInstall:getMaxBlogUserIdToFix', array('contenttypeid' => 9999));
				$maxToFix = intval($maxToFix['maxid']);

				//If there are no blogs to fix...
				if (intval($maxToFix) < 1)
				{
					$this->skip_message();
					return;
				}
			}

			if (!isset($startat))
			{
				$maxFixed = $assertor->getRow('vBInstall:getMaxFixedBlogUserId', array('contenttypeid' => 9999));

				if (!empty($maxFixed) AND !empty($maxFixed['maxid']))
				{
					$startat = $maxFixed['maxid'];
				}
				else
				{
					$startat = 0;
				}
			}

			$blogs  = $assertor->assertQuery('vBInstall:getBlogsUserToFix', array('startat' => $startat, 'batchsize' => $batchsize, 'contenttypeid' => 9999));
			if (!$blogs->valid())
			{
				$this->show_message(sprintf($this->phrase['core']['process_done']));
				return;
			}

			vB_Upgrade::createAdminSession();
			$channelLib = vB_Library::instance('content_channel');
			foreach ($blogs AS $blog)
			{
				$blog['urlident'] = $channelLib->getUniqueUrlIdent($blog['title']);
				$channelLib->update($blog['nodeid'], $blog);
			}

			$this->show_message(sprintf($this->phrase['core']['processed_records_x'], $batchsize));
			return array('startat' => ($startat + $batchsize), 'maxvB4' => $maxToFix);
		}
		else
		{
			$this->skip_message();
		}
	}

	/** Fix nodeoptions **/
	public function step_5($data = NULL)
	{
		if ($this->tableExists('blog_user') AND $this->tableExists('node'))
		{
			$this->show_message($this->phrase['version']['501a1']['fixing_blog_options']);
			$startat = intval($data['startat']);
			$batchsize = 2000;
			$assertor = vB::getDbAssertor();

			if (isset($data['startat']))
			{
				$startat = $data['startat'];
			}

			if (!empty($data['maxvB4']))
			{
				$maxToFix = $data['maxvB4'];
			}
			else
			{
				$maxToFix = $assertor->getRow('vBInstall:getMaxBlogUserIdToFixOptions', array('contenttypeid' => 9999));
				$maxToFix = intval($maxToFix['maxid']);

				//If there are no blogs to fix...
				if (intval($maxToFix) < 1)
				{
					$this->skip_message();
					return;
				}
			}

			if (!isset($startat))
			{
				$maxFixed = $assertor->getRow('vBInstall:getMaxOptionsFixedBlogUserId', array('contenttypeid' => 9999));

				if (!empty($maxFixed) AND !empty($maxFixed['maxid']))
				{
					$startat = $maxFixed['maxid'];
				}
				else
				{
					$startat = 0;
				}
			}

			$blogs  = $assertor->assertQuery('vBInstall:getBlogsUserToFixOptions', array('startat' => $startat, 'batchsize' => $batchsize, 'contenttypeid' => 9999));
			if (!$blogs->valid())
			{
				$this->show_message(sprintf($this->phrase['core']['process_done']));
				return;
			}

			// let's map the vB4 options and port them to vB5
			// allow smilie 					=> 1/0
			// moderate comments 				=> 1
			// parse links						=> 2
			// allow comments 					=> 4
			// options_member/guest can view	=> 1
			// options_member/guest can post 	=> 2
			$options = array(1 => vB_Api_Node::OPTION_MODERATE_COMMENTS, 2 => vB_Api_Node::OPTION_NODE_PARSELINKS, 4 => vB_Api_Node::OPTION_ALLOW_POST);
			$perms = array('viewperms' => 1, 'commentperms' => 2);
			vB_Upgrade::createAdminSession();
			$nodeLib = vB_Library::instance('node');
			$nodeApi = vB_Api::instance('node');
			foreach ($blogs AS $blog)
			{
				$nodeoption = 0;
				if (!$blog['allowsmilie'])
				{
					$nodeoption |= vB_Api_Node::OPTION_NODE_DISABLE_SMILIES;
				}

				foreach ($options AS $vb4 => $vb5)
				{
					if ($blog['options'] & $vb4)
					{
						$nodeoption |= $vb5;
					}
				}

				$nodeperms = array();
				foreach ($perms AS $name => $val)
				{
					// everyone
					if(($blog['options_member'] & $val) AND ($blog['options_guest'] & $val))
					{
						$nodeperms[$name] = 2;
					}
					// registered and members
					else if(($blog['options_member'] & $val) AND !($blog['options_guest'] & $val))
					{
						$nodeperms[$name] = 1;
					}
					// there's no currently guest only option in blogs...leave this alone
					else if(!($blog['options_member'] & $val) AND ($blog['options_guest'] & $val))
					{
						$nodeperms[$name] = 2;
					}
					// let's just leave any other case as blog members
					else
					{
						$nodeperms[$name] = 0;
					}
				}

				$nodeLib->setNodeOptions($blog['nodeid'], $nodeoption);
				$nodeApi->setNodePerms($blog['nodeid'], $nodeperms);
			}

			$this->show_message(sprintf($this->phrase['core']['processed_records_x'], $batchsize));
			return array('startat' => ($startat + $batchsize), 'maxvB4' => $maxToFix);
		}
		else
		{
			$this->skip_message();
		}
	}

	/*
	 * Step 6 - Grant canalwaysview, canalwayspost, canalwayspostnew to admin and super mods
	 */
	public function step_6()
	{
		$this->show_message(sprintf($this->phrase['vbphrase']['update_table'], 'permission'));
		vB::getDbAssertor()->assertQuery('vBInstall:setCanAlwaysPerms', array('groupids' => array(vB_Api_UserGroup::SUPER_MODERATOR, vB_Api_UserGroup::ADMINISTRATOR)));
	}

	/**
	*	Correctly import htmlstate for blog entries
	*
	*/
	public function step_7($data = NULL)
	{
		// check if blog product exists. Else, no action needed
		if 	(	(isset($this->registry->products['vbblog']) AND $this->registry->products['vbblog']) OR
				$this->field_exists('usergroup', 'vbblog_entry_permissions')
			)
		{

			$this->show_message($this->phrase['version']['501a1']['importing_htmlstates_for_blog_entries']);
			$startat = intval($data['startat']);
			$batchsize = 500;
			// contenttypeid 9985 - from class_upgrade_500a22 step2
			$oldContetypeid_blogStarter = 9985;

			if (!empty($data['usersWithAllowHTML']))
			{
				$usersWithAllowHTML = $data['usersWithAllowHTML'];
			}
			else
			{
				// grab all groups that have vbblog_entry_permissions & blog_allowhtml
				// Bitfields from vb4:
				// <bitfield name="blog_allowhtml" group="vbblog_entry_permissions" phrase="allow_html">8192</bitfield>
				// <bitfield name="blog_allowhtml" group="vbblog_comment_permissions" phrase="allow_html">1024</bitfield>
				// blog_comment_bitfield is 0 so that we ignore vbblog_comment_permissiosn
				$userGroupsWithAllowHTMLqry = vB::getDbAssertor()->assertQuery('vBInstall:getUsergroupsWithAllowHtml', array(
						'blog_entry_bitfield' => 8192,
						'blog_comment_bitfield' => 0
				));

				// if there are no usergroups with the permissions, we're done.
				if(!$userGroupsWithAllowHTMLqry->valid())
				{
					$this->show_message(sprintf($this->phrase['core']['process_done']));
					return;
				}

				// make a list of usergroups
				$userGroupsWithAllowHTML = array();
				foreach($userGroupsWithAllowHTMLqry AS $qryRow)
				{
					$userGroupsWithAllowHTML[] = $qryRow['usergroupid'];
				}

				// generate a list of users that are in these usergroups
				$usersWithAllowHTMLQry = vB::getDbAssertor()->assertQuery('vBInstall:getUsersInUsergroups', array(
						'usergroupids' => $userGroupsWithAllowHTML
				));

				// if there are no users in the usergroups, we're done.
				if(!$usersWithAllowHTMLQry->valid())
				{
					$this->show_message(sprintf($this->phrase['core']['process_done']));
					return;
				}

				// make a list of users
				$usersWithAllowHTML = array();
				foreach($usersWithAllowHTMLQry AS $qryRow)
				{
					$usersWithAllowHTML[] = $qryRow['userid'];
				}
			}


			if (!empty($data['max']))
			{
					$max = $data['max'];
			}
			else
			{
				// grab the max id for imported vb3/4 blog entry/reply content types
				$max = vB::getDbAssertor()->getRow(	'vBInstall:getMaxNodeidForOldContent',
											array(	'oldcontenttypeid' => array($oldContetypeid_blogStarter))
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
				// import them for the users in $usersWithAllowHTML
				vB::getDbAssertor()->assertQuery('vBInstall:importBlogEntryHtmlState', array(
					'startat' => $startat,
					'batchsize' => $batchsize,
					'oldcontenttypeids' => $oldContetypeid_blogStarter,
					'usersWithAllowHTML' => $usersWithAllowHTML
				));

				// output current progress
				$this->show_message(sprintf($this->phrase['core']['processed_records_x_y'], $startat + 1, $startat + $batchsize));
				// start next batch
				return array('startat' => ($startat + $batchsize), 'max' => $max, 'usersWithAllowHTML' => $usersWithAllowHTML);
			}
		}
		else
		{
			// no action needed since they didn't have blogs
			$this->skip_message();
		}
	}


	/**
	*	Correctly import htmlstate for blog comments
	*
	*/
	public function step_8($data = NULL)
	{
		// check if blog product exists. Else, no action needed
		if ( 	(isset($this->registry->products['vbblog']) AND $this->registry->products['vbblog']) OR
				$this->field_exists('usergroup', 'vbblog_comment_permissions')
			)
		{

			$this->show_message($this->phrase['version']['501a1']['importing_htmlstates_for_blog_comments']);
			$startat = intval($data['startat']);
			$batchsize = 500;
			// contenttypeid 9985 - from class_upgrade_500a22 step2
			// contenttypeid 9984 - from class_upgrade_500a22 step3
			$oldContetypeid_blogReply = 9984;

			if (!empty($data['usersWithAllowHTML']))
			{
				$usersWithAllowHTML = $data['usersWithAllowHTML'];
			}
			else
			{
				// grab all groups that have vbblog_comment_permissiosn & blog_allowhtml
				// Bitfields from vb4:
				// <bitfield name="blog_allowhtml" group="vbblog_entry_permissions" phrase="allow_html">8192</bitfield>
				// <bitfield name="blog_allowhtml" group="vbblog_comment_permissions" phrase="allow_html">1024</bitfield>
				// blog_entry_bitfield is 0 so that we ignore vbblog_entry_permission
				$userGroupsWithAllowHTMLqry = vB::getDbAssertor()->assertQuery('vBInstall:getUsergroupsWithAllowHtml', array(
						'blog_entry_bitfield' => 0,
						'blog_comment_bitfield' => 1024
				));

				// if there are no usergroups with the permissions, we're done.
				if(!$userGroupsWithAllowHTMLqry->valid())
				{
					$this->show_message(sprintf($this->phrase['core']['process_done']));
					return;
				}

				// make a list of usergroups
				$userGroupsWithAllowHTML = array();
				foreach($userGroupsWithAllowHTMLqry AS $qryRow)
				{
					$userGroupsWithAllowHTML[] = $qryRow['usergroupid'];
				}

				// generate a list of users that are in these usergroups
				$usersWithAllowHTMLQry = vB::getDbAssertor()->assertQuery('vBInstall:getUsersInUsergroups', array(
						'usergroupids' => $userGroupsWithAllowHTML
				));

				// if there are no users in the usergroups, we're done.
				if(!$usersWithAllowHTMLQry->valid())
				{
					$this->show_message(sprintf($this->phrase['core']['process_done']));
					return;
				}

				// make a list of users
				$usersWithAllowHTML = array();
				foreach($usersWithAllowHTMLQry AS $qryRow)
				{
					$usersWithAllowHTML[] = $qryRow['userid'];
				}
			}


			if (!empty($data['max']))
			{
					$max = $data['max'];
			}
			else
			{
				// grab the max id for imported vb3/4 blog entry/reply content types
				$max = vB::getDbAssertor()->getRow(	'vBInstall:getMaxNodeidForOldContent',
											array(	'oldcontenttypeid' => array($oldContetypeid_blogReply))
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
				// import them for the users in $usersWithAllowHTML
				vB::getDbAssertor()->assertQuery('vBInstall:importBlogCommentHtmlState', array(
					'startat' => $startat,
					'batchsize' => $batchsize,
					'oldcontenttypeids' => $oldContetypeid_blogReply,
					'usersWithAllowHTML' => $usersWithAllowHTML
				));

				// output current progress
				$this->show_message(sprintf($this->phrase['core']['processed_records_x_y'], $startat + 1, $startat + $batchsize));
				// start next batch
				return array('startat' => ($startat + $batchsize), 'max' => $max, 'usersWithAllowHTML' => $usersWithAllowHTML);
			}
		}
		else
		{
			// no action needed since they didn't have blogs
			$this->skip_message();
		}
	}

	/*
	 * Step 9 - Import blog membership records
	 * Note that we user startat to send the channel membergroupid so we don't request again.
	 */
	public function step_9($data = NULL)
	{
		if ($this->tableExists('blog_user') AND $this->tableExists('node') AND $this->tableExists('blog_groupmembership') AND $this->tableExists('groupintopic'))
		{
			$assertor = vB::getDbAssertor();
			$maxToImport = $assertor->getRow('vBInstall:getMaxBlogMemberToImport', array('contenttypeid' => 9999));
			$maxToImport = intval($maxToImport['maxnodeid']);

			//If there are no records
			if (intval($maxToImport) < 1)
			{
				$this->skip_message();
				return;
			}

			$batchsize = 2000;
			$this->show_message($this->phrase['version']['501a1']['importing_blog_members']);

			if (!empty($data['startat']))
			{
				$membergroupid = intval($data['startat']);
			}
			else
			{
				$membergroupRec = $assertor->getRow('vBForum:usergroup', array('systemgroupid' => vB_Api_UserGroup::CHANNEL_MEMBER_SYSGROUPID));
				$membergroupid = $membergroupRec['usergroupid'];
			}

			$assertor->assertQuery('vBInstall:importBlogMembers', array('batchsize' => $batchsize, 'contenttypeid' => 9999, 'groupid' => $membergroupid));
			$this->show_message(sprintf($this->phrase['core']['processed_records_x'], $batchsize));
			return array('startat' => $membergroupid);
		}
		else
		{
			$this->skip_message();
		}
	}

	/*
	 * Step 10 - Create needed PM starter sentto records for pm replies.
	 * Note that we user startat to send the pmtypeid so we don't request again.
	 */
	public function step_10($data = NULL)
	{
		if ($this->tableExists('node') AND $this->tableExists('sentto') AND $this->tableExists('messagefolder'))
		{
			$assertor = vB::getDbAssertor();
			if (!empty($data['startat']))
			{
				$pmType = $data['startat'];
			}
			else
			{
				$pmType = vB_Types::instance()->getContentTypeID('vBForum_PrivateMessage');
			}

			$maxToImport = $assertor->getRow('vBInstall:getMaxPmStarterToCreate', array('contenttypeid' => 9981, 'pmtypeid' => $pmType));
			$maxToImport = intval($maxToImport['maxid']);

			//If there are no records
			if (intval($maxToImport) < 1)
			{
				$this->skip_message();
				return;
			}

			$batchsize = 2000;
			$this->show_message($this->phrase['version']['501a1']['fixing_pm_starters']);
			$assertor->assertQuery('vBInstall:createStarterPmRecords', array('batchsize' => $batchsize, 'contenttypeid' => 9981, 'pmtypeid' => $pmType));
			$this->show_message(sprintf($this->phrase['core']['processed_records_x'], $batchsize));
			return array('startat' => $pmType);
		}
		else
		{
			$this->skip_message();
		}
	}

	/*
	 *	Step 11
	 *	Correct imported groups' pagetemplateids
	 */
	public function step_11($data = NULL)
	{
		if ($this->tableExists('socialgroup'))
		{
			// social groups don't have a specific hard-coded oldcontenttypeid (see 500a29 step_2~4)
			if (!empty($data['oldContentTypeId']))
			{
				$oldContentTypeId = $data['oldContentTypeId'];
			}
			else
			{
				$oldContentTypeId = vB_Types::instance()->getContentTypeID('vBForum_SocialGroup');
			}

			// grab the default channel page template's id
			if (!empty($data['defaultChannelTemplateid']))
			{
				$defaultChannelTemplateid = $data['defaultChannelTemplateid'];
			}
			else
			{
				$templatetitle = 'Default Channel Page Template';
				$titleQry = vB::getDbAssertor()->getRow( 'vBInstall:getPagetemplateidByTitle',
										array('templatetitle' => $templatetitle)
									);
				$defaultChannelTemplateid = $titleQry['pagetemplateid'];
			}

			// grab the default channel page template's id
			if (!empty($data['defaultGroupshomeTemplateid']))
			{
				$defaultGroupshomeTemplateid = $data['defaultGroupshomeTemplateid'];
			}
			else
			{
				$templatetitle = 'Group';
				$titleQry = vB::getDbAssertor()->getRow( 'vBInstall:getPagetemplateidByTitle',
										array('templatetitle' => $templatetitle)
									);
				$defaultGroupshomeTemplateid = $titleQry['pagetemplateid'];
			}

			$this->show_message($this->phrase['version']['501a1']['setting_imported_group_pagetemplateids']);
			$startat = intval($data['startat']);
			$batchsize = 1000;
			// grab max from the data passed in or re-fetch it via query
			if (!empty($data['max']))
			{
					$max = $data['max'];
			}
			else
			{
				// Get the max pageid for imported social groups
				$max = vB::getDbAssertor()->getRow(	'vBInstall:getMaxPageidForOldSocialGroups',
											array(	'oldcontenttypeid' => array($oldContentTypeId))
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
				// update the pagetemplateid for the next batch
				vB::getDbAssertor()->assertQuery('vBInstall:updateImportedGroupsPagetemplateid', array(
					'startat' => $startat,
					'batchsize' => $batchsize,
					'oldcontenttypeid' => $oldContentTypeId,
					'changefrom' => $defaultChannelTemplateid,
					'changeto' => $defaultGroupshomeTemplateid
				));

				// start next batch
				return array(	'startat' => ($startat + $batchsize),
								'max' => $max,
								'oldContentTypeId' => $oldContentTypeId,
								'defaultChannelTemplateid' => $defaultChannelTemplateid,
								'defaultGroupshomeTemplateid' => $defaultGroupshomeTemplateid
							);
			}
		}
		else
		{
			$this->skip_message();
		}
	}

}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
