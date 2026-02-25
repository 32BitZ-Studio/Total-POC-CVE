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

class vB_Upgrade_501a2 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '501a2';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.0.1 Alpha 2';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.0.1 Alpha 1';

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

	/*
	 * Step 1 - Move MSN account info to Skype field when possible
	 */
	public function step_1($data = NULL)
	{
		if ($data == NULL)
		{
			$this->show_message($this->phrase['version']['501a2']['moving_msn_info']);
		}

		$batchsize = 2000;
		$assertor = vB::getDbAssertor();

		$assertor->assertQuery('vBInstall:moveMsnInfo', array('batchsize' => $batchsize));

		$affectedRows = $assertor->affected_rows();

		if ($affectedRows < $batchsize )
		{
			$this->show_message(sprintf($this->phrase['core']['process_done']));
			return;
		}
		else
		{
			$this->show_message(sprintf($this->phrase['core']['processed_records_x'], $affectedRows));

			// keep updating
			return array('startat' => 1);
		}
	}

	public function step_2()
	{
		$this->skip_message();
	}

	/*
	 * Step 3 - Update spamlog, add nodeid
	 */
	public function step_3()
	{
		$this->add_field(
			sprintf($this->phrase['core']['altering_x_table'], 'spamlog', 1, 5),
			'spamlog',
			'nodeid',
			'int',
			self::FIELD_DEFAULTS
		);
	}

	/*
	 * Step 4 - Update spamlog.nodeid -- this will get non first posts.
	 */
	public function step_4()
	{
		if ($this->field_exists('spamlog', 'postid'))
		{
			$this->show_message(sprintf($this->phrase['core']['altering_x_table'], 'spamlog', 2, 5));
			$postTypeId = vB_Types::instance()->getContentTypeID('vBForum_Post');
			vB::getDbAssertor()->assertQuery('vBInstall:501a2_updateSpamlog1', array('posttypeid' => $postTypeId));
		}
		else
		{
			$this->skip_message();
		}
	}

	/*
	 * Step 5 - Update spamlog.nodeid -- this will get first posts, which are now saved as thread type in vB5.
	 */
	public function step_5()
	{
		if ($this->field_exists('spamlog', 'postid'))
		{
			$this->show_message(sprintf($this->phrase['core']['altering_x_table'], 'spamlog', 3, 5));
			$threadTypeId = vB_Types::instance()->getContentTypeID('vBForum_Thread');
			vB::getDbAssertor()->assertQuery('vBInstall:501a2_updateSpamlog2', array('threadtypeid' => $threadTypeId));
		}
		else
		{
			$this->skip_message();
		}
	}

	/*
	 * Step 6 - We may have some orphan logs that reference a non-existant post/thread. These logs have nodeids of 0.
	 * Remove them.
	 */
	public function step_6()
	{
		if ($this->field_exists('spamlog', 'postid'))
		{
			$this->show_message(sprintf($this->phrase['core']['altering_x_table'], 'spamlog', 4, 5));
			vB::getDbAssertor()->assertQuery('vBInstall:501a2_updateSpamlog3');
		}
		else
		{
			$this->skip_message();
		}
	}

	/*
	 * Step 7
	 */
	public function step_7()
	{
		if ($this->field_exists('spamlog', 'postid'))
		{
			$this->run_query(
				sprintf($this->phrase['core']['altering_x_table'], 'spamlog', 5, 5),
				"ALTER TABLE " . TABLE_PREFIX . "spamlog DROP PRIMARY KEY, ADD PRIMARY KEY(nodeid)",
				self::MYSQL_ERROR_DROP_KEY_COLUMN_MISSING
			);
		}
		else
		{
			$this->skip_message();
		}
	}

	/*
	 * Step 8 - Converting buddies to subscribers/subscriptions
	 */
	public function step_8()
	{
		$this->show_message($this->phrase['version']['501a2']['converting_friends']);
		vB::getDbAssertor()->assertQuery('vBInstall:convertFriends');
	}

	/**
	 * Update the infractions table schema
	 */
	public function step_9()
	{
		if ($this->field_exists('infraction', 'nodeid') AND !$this->field_exists('infraction', 'infractednodeid'))
		{
			// the node that received the infraction
			$this->run_query(
				sprintf($this->phrase['core']['altering_x_table'], 'infraction', 1, 6),
				"ALTER TABLE " . TABLE_PREFIX . "infraction CHANGE nodeid infractednodeid INT UNSIGNED NOT NULL DEFAULT '0'"
			);
		}
		else
		{
			$this->skip_message();
		}
	}

	/**
	 * Update the infractions table schema
	 */
	public function step_10()
	{
		if ($this->field_exists('infraction', 'userid') AND !$this->field_exists('infraction', 'infracteduserid'))
		{
			// the user who received the infraction
			$this->run_query(
				sprintf($this->phrase['core']['altering_x_table'], 'infraction', 2, 6),
				"ALTER TABLE " . TABLE_PREFIX . "infraction CHANGE userid infracteduserid INT UNSIGNED NOT NULL DEFAULT '0'"
			);
		}
		else
		{
			$this->skip_message();
		}
	}

	/**
	 * Update the infractions table schema
	 */
	public function step_11()
	{
		if ($this->field_exists('infraction', 'whoadded'))
		{
			// the user who gave the infraction
			$this->run_query(
				sprintf($this->phrase['core']['altering_x_table'], 'infraction', 3, 6),
				"ALTER TABLE " . TABLE_PREFIX . "infraction CHANGE whoadded userid INT UNSIGNED NOT NULL DEFAULT '0'"
			);
		}
		else
		{
			$this->skip_message();
		}
	}

	/**
	 * Update the infractions table schema
	 */
	public function step_12()
	{
		if ($this->field_exists('infraction', 'infractionid'))
		{
		// remove auto_increment from infractionid
		$this->run_query(
			sprintf($this->phrase['core']['altering_x_table'], 'infraction', 4, 6),
			"ALTER TABLE " . TABLE_PREFIX . "infraction CHANGE infractionid infractionid INT UNSIGNED NOT NULL DEFAULT '0'"
		);
	}
		else
		{
			$this->skip_message();
		}
	}

	/**
	 * Update the infractions table schema
	 */
	public function step_13()
	{
		// drop primary index from infractionid
		$this->run_query(
			sprintf($this->phrase['core']['altering_x_table'], 'infraction', 5, 6),
			"ALTER TABLE " . TABLE_PREFIX . "infraction DROP PRIMARY KEY",
			self::MYSQL_ERROR_DROP_KEY_COLUMN_MISSING
		);
	}

	/**
	 * Update the infractions table schema
	 */
	public function step_14()
	{
		// add the new nodeid column
		$this->add_field(
			sprintf($this->phrase['core']['altering_x_table'], 'infraction', 6, 6),
			'infraction',
			'nodeid',
			'int',
			self::FIELD_DEFAULTS
		);
	}

	/**
	 * Add the infraction content type if needed
	 */
	public function step_15()
	{
		$this->add_contenttype('vbulletin', 'vBForum', 'Infraction');
	}

	/**
	 * Add the Infraction channel
	 */
	public function step_16()
	{

		vB_Upgrade::createAdminSession();
		$infractionChannel = vB::getDbAssertor()->getRow('vBForum:channel', array('guid' => vB_Channel::INFRACTION_CHANNEL));

		//Check if the infraction channel exists if not create it.
		$createInfractionChannel = (!$infractionChannel OR empty($infractionChannel['nodeid']));

		// If we have a legacy infractions forum, use it
		$forumId = vB::getDbAssertor()->getRow('vBInstall:getUiForumId');
		if(!empty($forumId) AND $forumId['value'] > 0)
		{
			$forumTypeId =  vB_Types::instance()->getContentTypeID('vBForum_Forum');
			$oldInfractionForum = vB::getDbAssertor()->getRow('vBInstall:getInfractionChannelNodeId', array(
					'oldForumTypeId' => $forumTypeId,
					'forumId' => $forumId['value']
			));

			if ($oldInfractionForum AND $oldInfractionForum['nodeid'])
			{
				if ($oldInfractionForum['guid'] != vB_Channel::INFRACTION_CHANNEL)
				{
					//delete the brand new infraction channel created inside the upgrade
					if (!empty($infractionChannel['nodeid']))
					{
						$channelLibrary = vB_Library::instance('content_channel');
						$channelLibrary->delete($infractionChannel['nodeid']);
					}

			vB::getDbAssertor()->assertQuery('vBInstall:setGuidToInfractionChannel', array(
					'guidInfraction' => vB_Channel::INFRACTION_CHANNEL,
					'infractionChannelId' => $oldInfractionForum['nodeid']
			));
				}

			$createInfractionChannel = false;
		}
		}

		if($createInfractionChannel)
		{
			$channelApi = vB_Api::instance('content_channel');
			$title = "Infractions";
			$sectionData = array('title' => $title, 'parentid' => $channelApi->fetchChannelIdByGUID(vB_Channel::DEFAULT_FORUM_PARENT), 'htmltitle' => $title, 'description' => $title,
				'publishdate' => vB::getRequest()->getTimeNow(),
				'userid' => 1, 'guid' => vB_Channel::INFRACTION_CHANNEL);
			$channelApi->add($sectionData);
			$this->show_message(sprintf($this->phrase['vbphrase']['update_table'], TABLE_PREFIX . 'channel'));
		}
		else
		{
			$this->skip_message();
	}
	}

	/*
	 * Set infractednodeid = 0 (Fixes problems introduced in step_153 in the 500a1 upgrade script)
	 */
	public function step_17($data = NULL)
	{
		$startat = intval($data['startat']);
		$batchsize = 1000;
		$assertor = vB::getDbAssertor();

		if(!empty($data['startat']))
		{
			$startat = intval($data['startat']);
		}
		if(!empty($data['max']))
		{
			$maxToFix = $data['max'];
		}
		else
		{
			$maxToFix = vB::getDbAssertor()->getRow('vBInstall:getMaxInfractedNodeWrong');
			$maxToFix = intval($maxToFix['maxid']);
		}
		if (!isset($startat))
		{
			$maxFixed = $assertor->getRow('vBInstall:getMaxFixedInfractedNodeWrong');

			if (!empty($maxFixed) AND !empty($maxFixed['maxid']))
			{
				$startat = $maxFixed['maxid'];
			}
			else
			{
				$startat = 0;
			}
		}
		if($startat > $maxToFix)
		{
			//// we're done here
			$this->show_message(sprintf($this->phrase['core']['process_done']));
			return;
		}
		else
		{
			vB::getDbAssertor()->assertQuery('vBInstall:fixInfractedNodeWrong', array(
						'startat' => $startat,
						'batchsize' => $batchsize
					));
			$this->show_message(sprintf($this->phrase['core']['processed_records_x'], $batchsize));
			return array('startat' => ($startat + $batchsize), 'max' => $maxToFix);
		}
	}

	/**
	 * Import infractions threads (infracted threads)
	 */
	public function step_18($data = NULL)
	{
		$assertor = vB::getDbAssertor();
		$startat = intval($data['startat']);
		$batchsize = 500;
		$threadTypeId =  vB_Types::instance()->getContentTypeID('vBForum_Thread');
		if(!empty($data['startat']))
		{
			$startat = intval($data['startat']);
		}
		if(!empty($data['max']))
		{
			$maxToFix = $data['max'];
		}
		else
		{
			// grab the max id for imported vb3/4 blog entry/reply content types
			$maxToFix = vB::getDbAssertor()->getRow('vBInstall:getMaxThreadNodeidForInfractions', array('threadTypeId' => $threadTypeId));
			$maxToFix = intval($maxToFix['maxid']);
		}
		if (!isset($startat))
		{
			$maxFixed = $assertor->getRow('vBInstall:getMaxThreadNodeidFixedForInfractions', array('threadTypeId' => $threadTypeId));

			if (!empty($maxFixed) AND !empty($maxFixed['maxid']))
			{
				$startat = $maxFixed['maxid'];
			}
			else
			{
				$startat = 0;
			}
		}

		if($startat > $maxToFix)
		{
			//// we're done here
			$this->show_message(sprintf($this->phrase['core']['process_done']));
			return;
		}
		else
		{
			vB::getDbAssertor()->assertQuery('vBInstall:importThreadsInfractions', array(
						'threadTypeId' => $threadTypeId,
						'startat' => $startat,
						'batchsize' => $batchsize
					));
			$this->show_message(sprintf($this->phrase['core']['processed_records_x'], $batchsize));
			return array('startat' => ($startat + $batchsize), 'max' => $maxToFix);
		}

	}

	/**
	 * Import infractions Post (infracted post)
	 */
	public function step_19($data = NULL)
	{
		$assertor = vB::getDbAssertor();
		$startat = intval($data['startat']);
		$batchsize = 500;
		$postTypeId =  vB_Types::instance()->getContentTypeID('vBForum_Post');
		if(!empty($data['startat']))
		{
			$startat = intval($data['startat']);
		}
		if(!empty($data['max']))
		{
			$maxToFix = $data['max'];
		}
		else
		{
			// grab the max id for imported vb3/4 blog entry/reply content types
			$maxToFix = vB::getDbAssertor()->getRow('vBInstall:getMaxPostNodeidForInfractions', array('postTypeId' => $postTypeId));
			$maxToFix = intval($maxToFix['maxid']);
		}
		if (!isset($startat))
		{
			$maxFixed = $assertor->getRow('vBInstall:getMaxPostNodeidFixedForInfractions', array('postTypeId' => $postTypeId));

			if (!empty($maxFixed) AND !empty($maxFixed['maxid']))
			{
				$startat = $maxFixed['maxid'];
			}
			else
			{
				$startat = 0;
			}
		}

		if($startat > $maxToFix)
		{
			//// we're done here
			$this->show_message(sprintf($this->phrase['core']['process_done']));
			return;
		}
		else
		{
			vB::getDbAssertor()->assertQuery('vBInstall:importPostInfractions', array(
						'postTypeId' => $postTypeId,
						'startat' => $startat,
						'batchsize' => $batchsize
					));
			$this->show_message(sprintf($this->phrase['core']['processed_records_x'], $batchsize));
			return array('startat' => ($startat + $batchsize), 'max' => $maxToFix);
		}

	}

	/*
	 * Add infraction threads to infraction channel
	 * 9976 oldcontentype for infractions on THREADS with infractions discussions
	 * infractions that has threadid > 0
	 */
	public function step_20($data = NULL)
	{
		$assertor = vB::getDbAssertor();
		$startat = intval($data['startat']);
		$batchsize = 1000;
		$threadTypeId =  vB_Types::instance()->getContentTypeID('vBForum_Thread');
		$infractionTypeId =  vB_Types::instance()->getContentTypeID('vBForum_Infraction');
		$infractionChannel = vB::getDbAssertor()->getRow('vBForum:channel', array('guid' => vB_Channel::INFRACTION_CHANNEL));
		if(!empty($data['startat']))
		{
			$startat = intval($data['startat']);
		}
		if(!empty($data['max']))
		{
			$maxToFix = $data['max'];
		}
		else
		{
			$maxToFix = vB::getDbAssertor()->getRow('vBInstall:getMaxThreadNodeidForInfractionChannel',  array(
							'oldTypeId' => $threadTypeId
					));
			$maxToFix = intval($maxToFix['maxid']);
		}
		if (!isset($startat))
		{
			$maxFixed = $assertor->getRow('vBInstall:getMaxThreadNodeidFixedForInfractionChannel',array(
							'infractionChannel'=> $infractionChannel['nodeid'],
							'oldTypeId' => '9976'
					));

			if (!empty($maxFixed) AND !empty($maxFixed['maxid']))
			{
				$startat = $maxFixed['maxid'];
			}
			else
			{
				$startat = 0;
			}
		}
		if($startat > $maxToFix)
		{
			//// we're done here
			$this->show_message(sprintf($this->phrase['core']['process_done']));
			return;
		}
		else
		{
			vB::getDbAssertor()->assertQuery('vBInstall:importThreadNodesToInfractionChannel', array(
						'oldTypeId' => $threadTypeId,
						'infractionTypeId' => $infractionTypeId,
						//'infractionChannel' => $infractionChannel['nodeid'],
						'oldInfractionTypeId' => '9976',
						'startat' => $startat,
						'batchsize' => $batchsize
					));
			$NodesInfo = vB::getDbAssertor()->getRows('vBInstall:getNodeIdsToMove', array(
						'oldTypeId' => '9976',
						'startat' => $startat,
						'batchsize' => $batchsize
			));

			if(!empty($NodesInfo))
			{
				$nodeIdsArray = array();
				foreach($NodesInfo as $nodeid)
				{
					$nodeIdsArray[] = $nodeid['nodeid'];
				}

				vB_Upgrade::createAdminSession();
				vB_Api::instance('node')->moveNodes($nodeIdsArray, $infractionChannel['nodeid']);
			}
			$this->show_message(sprintf($this->phrase['core']['processed_records_x'], $batchsize));
			return array('startat' => ($startat + $batchsize), 'max' => $maxToFix);
		}
	}


	 /*
	 * Add infraction threads to infraction channel
	 * 9975 oldcontentype for on POSTS infraction threads
	 * infractions that has threadid > 0
	 */
	public function step_21($data = NULL)
	{
		$assertor = vB::getDbAssertor();
		$startat = intval($data['startat']);
		$batchsize = 1000;
		$threadTypeId =  vB_Types::instance()->getContentTypeID('vBForum_Thread');
		$infractionTypeId =  vB_Types::instance()->getContentTypeID('vBForum_Infraction');
		$infractionChannel = vB::getDbAssertor()->getRow('vBForum:channel', array('guid' => vB_Channel::INFRACTION_CHANNEL));
		if(!empty($data['startat']))
		{
			$startat = intval($data['startat']);
		}
		if(!empty($data['max']))
		{
			$maxToFix = $data['max'];
		}
		else
		{
			$maxToFix = vB::getDbAssertor()->getRow('vBInstall:getMaxPostNodeidForInfractionChannel',  array(
							'oldTypeId' => $threadTypeId
					));
			$maxToFix = intval($maxToFix['maxid']);
		}
		if (!isset($startat))
		{
			$maxFixed = $assertor->getRow('vBInstall:getMaxPostNodeidFixedForInfractionChannel',array(
							'infractionChannel'=> $infractionChannel['nodeid'],
							'oldTypeId' => '9975'
					));

			if (!empty($maxFixed) AND !empty($maxFixed['maxid']))
			{
				$startat = $maxFixed['maxid'];
			}
			else
			{
				$startat = 0;
			}
		}
		if($startat > $maxToFix)
		{
			//// we're done here
			$this->show_message(sprintf($this->phrase['core']['process_done']));
			return;
		}
		else
		{
			vB::getDbAssertor()->assertQuery('vBInstall:importPostNodesToInfractionChannel', array(
						'oldTypeId' => $threadTypeId,
						'infractionTypeId' => $infractionTypeId,
						//'infractionChannel' => $infractionChannel['nodeid'],
						'oldInfractionTypeId' => '9975',
						'startat' => $startat,
						'batchsize' => $batchsize
					));
			$NodesInfo = vB::getDbAssertor()->getRows('vBInstall:getNodeIdsToMove', array(
						'oldTypeId' => '9975',
						'startat' => $startat,
						'batchsize' => $batchsize
			));

			if(!empty($NodesInfo))
			{
				$nodeIdsArray = array();
				foreach($NodesInfo as $nodeid)
				{
					$nodeIdsArray[] = $nodeid['nodeid'];
				}

				vB_Upgrade::createAdminSession();
				vB_Api::instance('node')->moveNodes($nodeIdsArray, $infractionChannel['nodeid']);
			}
			$this->show_message(sprintf($this->phrase['core']['processed_records_x'], $batchsize));
			return array('startat' => ($startat + $batchsize), 'max' => $maxToFix);
		}
	}


	/**
	 * Add Nodes for orphan infractions (with no infraction threads on them)
	 * In this case we add the nodes for threads
	 * 9979 is now the oldcontentype for postid starter which got infracted
	 */
	public function step_22($data = NULL)
	{
		$assertor = vB::getDbAssertor();
		$startat = intval($data['startat']);
		$batchsize = 1000;
		$threadTypeId =  vB_Types::instance()->getContentTypeID('vBForum_Thread');
		$infractionTypeId =  vB_Types::instance()->getContentTypeID('vBForum_Infraction');
		$infractionChannel = vB::getDbAssertor()->getRow('vBForum:channel', array('guid' => vB_Channel::INFRACTION_CHANNEL));
		$assertor = vB::getDbAssertor();
		if(!empty($data['startat']))
		{
			$startat = intval($data['startat']);
		}
		if(!empty($data['max']))
		{
			$maxToFix = $data['max'];
		}
		else
		{
			$maxToFix = vB::getDbAssertor()->getRow('vBInstall:getMaxOrphanInfraction', array('oldTypeId' => $threadTypeId));
			$maxToFix = intval($maxToFix['maxid']);
		}
		if (!$startat)
		{
			$maxFixed = $assertor->getRow('vBInstall:getMaxFixedOrphanInfraction', array('oldTypeId' => '9979'));

			if (!empty($maxFixed) AND !empty($maxFixed['maxid']))
			{
				$startat = $maxFixed['maxid'];
			}
			else
			{
				$startat = 0;
			}
		}

		if($startat >= $maxToFix)
		{
			//// we're done here
			$this->show_message(sprintf($this->phrase['core']['process_done']));
			return;
		}
		else
		{
			$assertor->assertQuery('vBInstall:addNodesForOrphanInfractions', array(
						'infractionTypeId' => $infractionTypeId,
						'oldInfractionTypeId' => '9979',
						'infractionChannelId' => $infractionChannel['nodeid'],
						'oldTypeId' => $threadTypeId,
						'startat' => $startat,
						'batchsize' => $batchsize
					));

			$assertor->assertQuery('vBInstall:addClosureSelfInfraction',
                                array('startat' => $startat, 'batchsize' => $batchsize, 'contenttypeid' => '9979'));

			$assertor->assertQuery('vBInstall:addClosureParentsInfraction',
                                array('startat' => $startat, 'batchsize' => $batchsize, 'contenttypeid' => '9979'));

			$assertor->assertQuery('vBInstall:setPMStarter',
                                array('startat' => $startat, 'batchsize' => $batchsize, 'contenttypeid' => '9979'));

			$this->show_message(sprintf($this->phrase['core']['processed_records_x'], $batchsize));
			return array('startat' => ($startat + $batchsize), 'max' => $maxToFix);
		}
	}

	/**
	 * Add Nodes for orphan infractions (with no infraction threads on them)
	 * In this case we add the nodes for post
	 * 9978 is now the oldcontentype for postid starter which got infracted
	 */
	public function step_23($data = NULL)
	{
		$startat = intval($data['startat']);
		$batchsize = 1000;
		$postTypeId =  vB_Types::instance()->getContentTypeID('vBForum_Post');
		$infractionTypeId =  vB_Types::instance()->getContentTypeID('vBForum_Infraction');
		$infractionChannel = vB::getDbAssertor()->getRow('vBForum:channel', array('guid' => vB_Channel::INFRACTION_CHANNEL));
		$assertor = vB::getDbAssertor();

		if(!empty($data['startat']))
		{
			$startat = intval($data['startat']);
		}
		if(!empty($data['max']))
		{
			$maxToFix = $data['max'];
		}
		else
		{
			$maxToFix = vB::getDbAssertor()->getRow('vBInstall:getMaxOrphanInfraction', array('oldTypeId' => $postTypeId));
			$maxToFix = intval($maxToFix['maxid']);
		}
		if (!$startat)
		{
			$maxFixed = $assertor->getRow('vBInstall:getMaxFixedOrphanInfraction', array('oldTypeId' => '9978'));

			if (!empty($maxFixed) AND !empty($maxFixed['maxid']))
			{
				$startat = $maxFixed['maxid'];
			}
			else
			{
				$startat = 0;
			}
		}

		if($startat >= $maxToFix)
		{
			//// we're done here
			$this->show_message(sprintf($this->phrase['core']['process_done']));
			return;
		}
		else
		{
			vB::getDbAssertor()->assertQuery('vBInstall:addNodesForOrphanInfractions', array(
						'infractionTypeId' => $infractionTypeId,
						'oldInfractionTypeId' => '9978',
						'infractionChannelId' => $infractionChannel['nodeid'],
						'oldTypeId' => $postTypeId,
						'startat' => $startat,
						'batchsize' => $batchsize
					));

			$assertor->assertQuery('vBInstall:addClosureSelfInfraction',
                                array('startat' => $startat, 'batchsize' => $batchsize, 'contenttypeid' => '9978'));

			$assertor->assertQuery('vBInstall:addClosureParentsInfraction',
                                array('startat' => $startat, 'batchsize' => $batchsize, 'contenttypeid' => '9978'));

			$assertor->assertQuery('vBInstall:setPMStarter',
                                array('startat' => $startat, 'batchsize' => $batchsize, 'contenttypeid' => '9978'));

			$this->show_message(sprintf($this->phrase['core']['processed_records_x'], $batchsize));
			return array('startat' => ($startat + $batchsize), 'max' => $maxToFix);
		}
	}

	/**
	 * Add Nodes for orphan infractions (with no infraction threads on them)
	 * In this case we add the nodes for profile
	 * 9977 is now the oldcontentype for postid=0 on infraction table (profile)
	 */
	public function step_24($data = NULL)
	{
		$startat = intval($data['startat']);
		$batchsize = 1000;

		$infractionTypeId =  vB_Types::instance()->getContentTypeID('vBForum_Infraction');
		$infractionChannel = vB::getDbAssertor()->getRow('vBForum:channel', array('guid' => vB_Channel::INFRACTION_CHANNEL));
		$assertor = vB::getDbAssertor();

		if(!empty($data['startat']))
		{
			$startat = intval($data['startat']);
		}
		if(!empty($data['max']))
		{
			$maxToFix = $data['max'];
		}
		else
		{
			$maxToFix = vB::getDbAssertor()->getRow('vBInstall:getMaxOrphanProfileInfraction');
			$maxToFix = intval($maxToFix['maxid']);
		}
		if (!$startat)
		{
			$maxFixed = $assertor->getRow('vBInstall:getMaxFixedOrphanProfileInfraction', array('oldTypeId' => '9977'));

			if (!empty($maxFixed) AND !empty($maxFixed['maxid']))
			{
				$startat = $maxFixed['maxid'];
			}
			else
			{
				$startat = 0;
			}
		}

		if($startat >= $maxToFix)
		{
			//// we're done here
			$this->show_message(sprintf($this->phrase['core']['process_done']));
			return;
		}
		else
		{
			vB::getDbAssertor()->assertQuery('vBInstall:addNodesForOrphanProfileInfractions', array(
						'infractionTypeId' => $infractionTypeId,
						'oldInfractionTypeId' => '9977',
						'infractionChannelId' => $infractionChannel['nodeid'],
						'startat' => $startat,
						'batchsize' => $batchsize
					));

			$assertor->assertQuery('vBInstall:addClosureSelfInfraction',
                                array('startat' => $startat, 'batchsize' => $batchsize, 'contenttypeid' => '9977'));

			$assertor->assertQuery('vBInstall:addClosureParentsInfraction',
                                array('startat' => $startat, 'batchsize' => $batchsize, 'contenttypeid' => '9977'));

			$assertor->assertQuery('vBInstall:setPMStarter',
                                array('startat' => $startat, 'batchsize' => $batchsize, 'contenttypeid' => '9977'));

			$this->show_message(sprintf($this->phrase['core']['processed_records_x'], $batchsize));
			return array('startat' => ($startat + $batchsize), 'max' => $maxToFix);
		}
	}

	/**
	 * Add nodeid into the infraction table, we are adding in this steps for threads infraction only
	 *
	 */
	public function step_25($data = NULL)
	{
		$startat = intval($data['startat']);
		$batchsize = 1000;
		$infractionTypeId =  vB_Types::instance()->getContentTypeID('vBForum_Infraction');

		if(!empty($data['startat']))
		{
			$startat = intval($data['startat']);
		}
		if(!empty($data['max']))
		{
			$maxToFix = $data['max'];
		}
		else
		{
			$maxToFix = vB::getDbAssertor()->getRow('vBInstall:getMaxNodeidIntoInfraction', array(
							'oldInfractionTypeId' => array('9979','9976', '9975'),
							'infractionTypeId' => $infractionTypeId
			));
			$maxToFix = intval($maxToFix['maxid']);
		}
		if (!isset($startat))
		{
			$maxFixed = vB::getDbAssertor()->getRow('vBInstall:getMaxNodeidFixedIntoInfraction', array(
							'oldInfractionTypeId' => array('9979','9976', '9975'),
							'infractionTypeId' => $infractionTypeId
			));

			if (!empty($maxFixed) AND !empty($maxFixed['maxid']))
			{
				$startat = $maxFixed['maxid'];
			}
			else
			{
				$startat = 0;
			}
		}

		if($startat > $maxToFix)
		{
			//// we're done here
			$this->show_message(sprintf($this->phrase['core']['process_done']));
			return;
		}
		else
		{
			vB::getDbAssertor()->assertQuery('vBInstall:addNodeidIntoInfraction', array(
						'oldInfractionTypeId' => array('9979','9976', '9975'),
						'infractionTypeId' => $infractionTypeId,
						'startat' => $startat,
						'batchsize' => $batchsize
					));
			$this->show_message(sprintf($this->phrase['core']['processed_records_x'], $batchsize));
			return array('startat' => ($startat + $batchsize), 'max' => $maxToFix);
		}
	}

	/**
	 * Add nodeid into the infraction table, we are adding in this steps for Post infraction only
	 *
	 */
	public function step_26($data = NULL)
	{
		$startat = intval($data['startat']);
		$batchsize = 1000;
		$infractionTypeId =  vB_Types::instance()->getContentTypeID('vBForum_Infraction');
		$assertor = vB::getDbAssertor();
		if(!empty($data['startat']))
		{
			$startat = intval($data['startat']);
		}
		if(!empty($data['max']))
		{
			$maxToFix = $data['max'];
		}
		else
		{
			$maxToFix = vB::getDbAssertor()->getRow('vBInstall:getMaxNodeidIntoInfraction', array(
							'oldInfractionTypeId' => '9978',
							'infractionTypeId' => $infractionTypeId
			));
			$maxToFix = intval($maxToFix['maxid']);
		}
		if (!isset($startat))
		{
			$maxFixed = $assertor->getRow('vBInstall:getMaxNodeidFixedIntoInfraction', array(
							'oldInfractionTypeId' => '9978',
							'infractionTypeId' => $infractionTypeId
			));

			if (!empty($maxFixed) AND !empty($maxFixed['maxid']))
			{
				$startat = $maxFixed['maxid'];
			}
			else
			{
				$startat = 0;
			}
		}

		if($startat > $maxToFix)
		{
			//// we're done here
			$this->show_message(sprintf($this->phrase['core']['process_done']));
			return;
		}
		else
		{
			vB::getDbAssertor()->assertQuery('vBInstall:addNodeidIntoInfraction', array(
						'oldInfractionTypeId' => '9978',
						'infractionTypeId' => $infractionTypeId,
						'startat' => $startat,
						'batchsize' => $batchsize
					));
			$this->show_message(sprintf($this->phrase['core']['processed_records_x'], $batchsize));
			return array('startat' => ($startat + $batchsize), 'max' => $maxToFix);
		}
	}

	/**
	 * Add nodeid into the infraction table, we are adding in this steps for Profile infraction only
	 *
	 */
	public function step_27($data = NULL)
	{
		$startat = intval($data['startat']);
		$batchsize = 1000;
		$infractionTypeId =  vB_Types::instance()->getContentTypeID('vBForum_Infraction');

		if(!empty($data['startat']))
		{
			$startat = intval($data['startat']);
		}
		if(!empty($data['max']))
		{
			$maxToFix = $data['max'];
		}
		else
		{
			$maxToFix = vB::getDbAssertor()->getRow('vBInstall:getMaxNodeidIntoInfraction', array(
							'oldInfractionTypeId' => '9977',
							'infractionTypeId' => $infractionTypeId
			));
			$maxToFix = intval($maxToFix['maxid']);
		}
		if (!isset($startat))
		{
			$maxFixed = vB::getDbAssertor()->getRow('vBInstall:getMaxNodeidFixedIntoInfraction', array(
							'oldInfractionTypeId' => '9977',
							'infractionTypeId' => $infractionTypeId
			));

			if (!empty($maxFixed) AND !empty($maxFixed['maxid']))
			{
				$startat = $maxFixed['maxid'];
			}
			else
			{
				$startat = 0;
			}
		}
		if($startat > $maxToFix)
		{
			//// we're done here
			$this->show_message(sprintf($this->phrase['core']['process_done']));
			return;
		}
		else
		{
			vB::getDbAssertor()->assertQuery('vBInstall:addNodeidIntoInfraction', array(
						'oldInfractionTypeId' => '9977',
						'infractionTypeId' => $infractionTypeId,
						'startat' => $startat,
						'batchsize' => $batchsize
					));
			$this->show_message(sprintf($this->phrase['core']['processed_records_x'], $batchsize));
			return array('startat' => ($startat + $batchsize), 'max' => $maxToFix);
		}
	}

	/*
	 * Removed physically deleted posts from infraction table
	 * At this point we only have nodeid = 0 in infraction table for physically deleted posts
	 */
	public function step_28($data = NULL)
	{
		$startat = intval($data['startat']);
		$batchsize = 1000;

		$maxRecord = vB::getDbAssertor()->getRow('vBInstall:getMaxInfractionIdPDeleted');
		$maxRecord = intval($maxRecord['maxid']);

		if (empty($maxRecord) OR $maxRecord == 0)
		{
			//// we're done here
			$this->show_message(sprintf($this->phrase['core']['process_done']));
			return;
		}
		else
		{
			vB::getDbAssertor()->assertQuery('vBInstall:removedPDeletedInfractions', array(
						'batchsize' => $batchsize
					));
			$this->show_message(sprintf($this->phrase['core']['processed_records_x'], $batchsize));
			return array('startat' => ($startat + $batchsize));
		}
	}

	/**
	 * Update the infractions table schema
	 */

	public function step_29()
	{
		// Add nodeid as primary key
		$infractiondescr = $this->db->query_first("SHOW COLUMNS FROM " . TABLE_PREFIX . "infraction LIKE 'nodeid'");

		if (!empty($infractiondescr['Key']) AND ($infractiondescr['Key'] == 'PRI'))
		{
		$this->run_query(
			sprintf($this->phrase['core']['altering_x_table'], 'infraction', 1, 1),
				"ALTER TABLE " . TABLE_PREFIX . "infraction DROP PRIMARY KEY, ADD PRIMARY KEY(nodeid)",
				self::MYSQL_ERROR_DROP_KEY_COLUMN_MISSING
			);
		}
		else
		{
			$this->run_query(
				sprintf($this->phrase['core']['altering_x_table'], 'infraction', 1, 1),
			"ALTER TABLE " . TABLE_PREFIX . "infraction ADD PRIMARY KEY (nodeid)"
		);
	}
	}

	/**
	 * Update the titles for infractions nodes (Threads)
	 * For starters where oldcontenttypeid = 9979, 9975, 9976
	 */
	public function step_30($data = NULL)
	{
		vB_Upgrade::createAdminSession();

		// get phrases for title & rawtext
		$assertor = vB::getDbAssertor();
		$startat = intval($data['startat']);
		$batchsize = 1000;
		$infractionTypeId =  vB_Types::instance()->getContentTypeID('vBForum_Infraction');
		$threadTypeId =  vB_Types::instance()->getContentTypeID('vBForum_Thread');

		if(!empty($data['startat']))
		{
			$startat = intval($data['startat']);
		}
		if(!empty($data['max']))
		{
			$maxToFix = $data['max'];
		}
		else
		{
			$maxToFix = vB::getDbAssertor()->getRow('vBInstall:getMaxInfractionWithoutNodeTitle', array(
							'infractionTypeId' => $infractionTypeId,
							'oldTypeId' => array('9979','9976', '9975')));
			$maxToFix = intval($maxToFix['maxid']);
		}
		if (!isset($startat))
		{
			$maxFixed = $assertor->getRow('vBInstall:getMaxInfractionFixedNodeTitle', array(
							'infractionTypeId' => $infractionTypeId,
							'oldTypeId' => array('9979','9976', '9975')));

			if (!empty($maxFixed) AND !empty($maxFixed['maxid']))
			{
				$startat = $maxFixed['maxid'];
			}
			else
			{
				$startat = 0;
			}
		}

		if($startat >= $maxToFix)
		{
			//// we're done here
			$this->show_message(sprintf($this->phrase['core']['process_done']));
			return;
		}
		else
		{
			$infractionsInfo = $assertor->getRows('vBInstall:getInfractedNodeTitles', array(
				'oldTypeId' => $threadTypeId,
				'startat' => $startat,
				'batchsize' => $batchsize));

			$titles = array();
			$text = array();

			foreach($infractionsInfo as $infractionInfo)
			{

				$phraseLevelid = 'infractionlevel'.$infractionInfo['ilevelid'].'_title';
				$infractionLevelInfo = $this->phrase['custom']['infractionlevel'][$phraseLevelid];

				if($infractionInfo['ipoints'] == 0)
				{
					$titles[$infractionInfo['nodeid']] = sprintf($this->phrase['version']['501a2']['warning_for_x_y_in_topic_z'], $infractionInfo['iusername'], $infractionLevelInfo, $infractionInfo['title']);
				}
				else
				{
					$titles[$infractionInfo['nodeid']] = sprintf($this->phrase['version']['501a2']['infraction_for_x_y_in_topic_z'], $infractionInfo['iusername'], $infractionLevelInfo, $infractionInfo['title']);
				}

				$text[$infractionInfo['nodeid']] = sprintf(
					$this->phrase['version']['501a2']['infraction_topic_post'],
					// link to infracted node
					vB5_Route::buildUrl($infractionInfo['routeid'] . '|fullurl', array('nodeid' => $infractionInfo['infractednodeid'], 'title' => $infractionInfo['title']), array('p' => $infractionInfo['infractednodeid'])) . '#post' . $infractionInfo['infractednodeid'],
					// infracted topic title
					$infractionInfo['title'],
					// infracted user link
					vB5_Route::buildUrl('profile|fullurl', array('userid' => $infractionInfo['iuserid'])),
					// infracted user name
					$infractionInfo['iusername'],
					// infraction title
					$titles[$infractionInfo['nodeid']],
					// infraction points
					$infractionInfo['ipoints'],
					// administrative note
					$infractionInfo['note'],
					// original post (infracted node)
					$infractionInfo['irawtext']
				);
			}

			foreach($titles as $nodeid => $title)
			{

				vB::getDbAssertor()->assertQuery('vBInstall:setTitleForInfractionNodes', array(
						'infractionNodeTitle' => $title,
						'urlident' => vB_String::getUrlIdent($title),
						'infractionNodeId' => $nodeid
					));
			}

			foreach($text as $nodeid => $nodeText)
			{
				vB::getDbAssertor()->assertQuery('vBInstall:setTextForInfractionNodes', array(
						'infractionText' => $nodeText,
						'nodeid' => $nodeid
					));
			}

			$this->show_message(sprintf($this->phrase['core']['processed_records_x'], $batchsize));
			return array('startat' => ($startat + $batchsize), 'max' => $maxToFix);
		}
	}

		/**
	 * Update the titles for infractions nodes (Post)
	 * For replies where oldcontenttypeid = 9978
	 */
	public function step_31($data = NULL)
	{
		vB_Upgrade::createAdminSession();

		// get phrases for title & rawtext
		$assertor = vB::getDbAssertor();
		$startat = intval($data['startat']);
		$batchsize = 1000;
		$infractionTypeId =  vB_Types::instance()->getContentTypeID('vBForum_Infraction');
		$postTypeId =  vB_Types::instance()->getContentTypeID('vBForum_Post');

		if(!empty($data['startat']))
		{
			$startat = intval($data['startat']);
		}
		if(!empty($data['max']))
		{
			$maxToFix = $data['max'];
		}
		else
		{
			$maxToFix = vB::getDbAssertor()->getRow('vBInstall:getMaxInfractionWithoutNodeTitle', array(
							'infractionTypeId' => $infractionTypeId,
							'oldTypeId' => '9978'));
			$maxToFix = intval($maxToFix['maxid']);
		}
		if (!isset($startat))
		{
			$maxFixed = $assertor->getRow('vBInstall:getMaxInfractionFixedNodeTitle', array(
							'infractionTypeId' => $infractionTypeId,
							'oldTypeId' => '9978'));

			if (!empty($maxFixed) AND !empty($maxFixed['maxid']))
			{
				$startat = $maxFixed['maxid'];
			}
			else
			{
				$startat = 0;
			}
		}

		if($startat >= $maxToFix)
		{
			//// we're done here
			$this->show_message(sprintf($this->phrase['core']['process_done']));
			return;
		}
		else
		{
			$infractionsInfo = $assertor->getRows('vBInstall:getInfractedForPostNodeTitles', array(
				'oldTypeId' => $postTypeId,
				'startat' => $startat,
				'batchsize' => $batchsize));

			$titles = array();
			$text = array();
			foreach($infractionsInfo as $infractionInfo)
			{
				$phraseLevelid = 'infractionlevel'.$infractionInfo['ilevelid'].'_title';
				$infractionLevelInfo = $this->phrase['custom']['infractionlevel'][$phraseLevelid];

				if($infractionInfo['ipoints'] == 0)
				{
					$titles[$infractionInfo['nodeid']] = sprintf($this->phrase['version']['501a2']['warning_for_x_y_in_topic_z'], $infractionInfo['iusername'], $infractionLevelInfo, $infractionInfo['title']);
				}
				else
				{
					$titles[$infractionInfo['nodeid']] = sprintf($this->phrase['version']['501a2']['infraction_for_x_y_in_topic_z'], $infractionInfo['iusername'], $infractionLevelInfo, $infractionInfo['title']);
				}

				$text[$infractionInfo['nodeid']] = sprintf(
					$this->phrase['version']['501a2']['infraction_topic_post'],
					// link to infracted node
					vB5_Route::buildUrl($infractionInfo['routeid'] . '|fullurl', array('nodeid' => $infractionInfo['infractednodeid'], 'title' => $infractionInfo['title']), array('p' => $infractionInfo['infractednodeid'])) . '#post' . $infractionInfo['infractednodeid'],
					// infracted topic title
					$infractionInfo['title'],
					// infracted user link
					vB5_Route::buildUrl('profile|fullurl', array('userid' => $infractionInfo['iuserid'])),
					// infracted user name
					$infractionInfo['iusername'],
					// infraction title
					$titles[$infractionInfo['nodeid']],
					// infraction points
					$infractionInfo['ipoints'],
					// administrative note
					$infractionInfo['note'],
					// original post (infracted node)
					$infractionInfo['irawtext']
				);
			}

			foreach($titles as $nodeid => $title)
			{
				vB::getDbAssertor()->assertQuery('vBInstall:setTitleForInfractionNodes', array(
						'infractionNodeTitle' => $title,
						'urlident' => vB_String::getUrlIdent($title),
						'infractionNodeId' => $nodeid
					));
			}

			foreach($text as $nodeid => $nodeText)
			{
				vB::getDbAssertor()->assertQuery('vBInstall:setTextForInfractionNodes', array(
						'infractionText' => $nodeText,
						'nodeid' => $nodeid
					));
			}

			$this->show_message(sprintf($this->phrase['core']['processed_records_x'], $batchsize));
			return array('startat' => ($startat + $batchsize), 'max' => $maxToFix);
		}
	}

	/**
	 * Update the titles for infractions nodes (Profile)
	 * For profiles where oldcontenttypeid = 9977
	 */
	public function step_32($data = NULL)
	{
		vB_Upgrade::createAdminSession();

		// get phrases for title & rawtext
		$assertor = vB::getDbAssertor();
		$startat = intval($data['startat']);
		$batchsize = 1000;
		$infractionTypeId =  vB_Types::instance()->getContentTypeID('vBForum_Infraction');

		if(!empty($data['startat']))
		{
			$startat = intval($data['startat']);
		}
		if(!empty($data['max']))
		{
			$maxToFix = $data['max'];
		}
		else
		{
			$maxToFix = vB::getDbAssertor()->getRow('vBInstall:getMaxInfractionWithoutNodeTitle', array(
							'infractionTypeId' => $infractionTypeId,
							'oldTypeId' => '9977'));
			$maxToFix = intval($maxToFix['maxid']);
		}
		if (!isset($startat))
		{
			$maxFixed = $assertor->getRow('vBInstall:getMaxInfractionFixedNodeTitle', array(
							'infractionTypeId' => $infractionTypeId,
							'oldTypeId' => '9977'));

			if (!empty($maxFixed) AND !empty($maxFixed['maxid']))
			{
				$startat = $maxFixed['maxid'];
			}
			else
			{
				$startat = 0;
			}
		}

		if($startat >= $maxToFix)
		{
			//// we're done here
			$this->show_message(sprintf($this->phrase['core']['process_done']));
			return;
		}
		else
		{
			$infractionsInfo = $assertor->getRows('vBInstall:getInfractedProfileInfo', array(
				'oldTypeId' => '9977',
				'startat' => $startat,
				'batchsize' => $batchsize));

			$titles = array();
			$text = array();
			foreach($infractionsInfo as $infractionInfo)
			{
				$phraseLevelid = 'infractionlevel'.$infractionInfo['ilevelid'].'_title';
				$infractionLevelInfo = $this->phrase['custom']['infractionlevel'][$phraseLevelid];

				if($infractionInfo['ipoints'] == 0)
				{
					$titles[$infractionInfo['nodeid']] = sprintf($this->phrase['version']['501a2']['warning_for_x_y'], $infractionInfo['iusername'], $infractionLevelInfo);
				}
				else
				{
					$titles[$infractionInfo['nodeid']] = sprintf($this->phrase['version']['501a2']['infraction_for_x_y'], $infractionInfo['iusername'], $infractionLevelInfo);
				}

				$text[$infractionInfo['nodeid']] =sprintf(
					$this->phrase['version']['501a2']['infraction_topic_profile'],
					// infracted user link
					vB5_Route::buildUrl('profile|fullurl', array('userid' => $infractionInfo['iuserid'])),
					// infracted user name
					$infractionInfo['iusername'],
					// infraction title
					$infractionLevelInfo,
					// infraction points
					$infractionInfo['ipoints'],
					// administrative note
					$infractionInfo['note']
				);
			}

			foreach($titles as $nodeid => $title)
			{
				vB::getDbAssertor()->assertQuery('vBInstall:setTitleForInfractionNodes', array(
						'infractionNodeTitle' => $title,
						'urlident' => vB_String::getUrlIdent($title),
						'infractionNodeId' => $nodeid
					));
			}

			foreach($text as $nodeid => $nodeText)
			{
				vB::getDbAssertor()->assertQuery('vBInstall:setTextForInfractionNodes', array(
						'infractionText' => $nodeText,
						'nodeid' => $nodeid
					));
			}

			$this->show_message(sprintf($this->phrase['core']['processed_records_x'], $batchsize));
			return array('startat' => ($startat + $batchsize), 'max' => $maxToFix);
		}
	}

	//this step has been moved to 502a1
	public function step_33()
	{
		$this->skip_message();
	}

	/*
	 * Removed the channelid field
	 */
	public function step_34()
	{
		if ($this->field_exists('infraction', 'channelid'))
			{
				$this->drop_field(
					sprintf($this->phrase['core']['altering_x_table'], 'infraction', 1, 1),
					'infraction',
					'channelid'
				);
			}
			else
			{
				$this->skip_message();
			}
	}

	public function step_35()
	{
		$infractionChannel = vB::getDbAssertor()->getRow('vBForum:channel', array('guid' => vB_Channel::INFRACTION_CHANNEL));
		$routeInfo = vB::getDbAssertor()->getRow('routenew', array(
					'class' => 'vB5_Route_Conversation',
					'contentid' => $infractionChannel['nodeid']));

		vB::getDbAssertor()->assertQuery('vBInstall:setInfractionConversationRouteId', array(
					'infractionRouteId' => $routeInfo['routeid'],
					'infractionNodeId' => $infractionChannel['nodeid']
		));
		$this->show_message(sprintf($this->phrase['vbphrase']['update_table'], TABLE_PREFIX . 'node'));

	}

	public function step_36()
	{
		$infractionChannel = vB::getDbAssertor()->getRow('vBForum:channel', array('guid' => vB_Channel::INFRACTION_CHANNEL));
		$textCount = vB::getDbAssertor()->getRow('vBInstall:totalStarters');

		vB::getDbAssertor()->assertQuery('vBInstall:setTextCountForInfractionChannel', array(
					'textCount' => $textCount['totalCount'],
					'infractionNodeid' => $infractionChannel['nodeid']
			));

		$this->show_message(sprintf($this->phrase['vbphrase']['update_table'], TABLE_PREFIX . 'node'));
	}

	public function step_37()
	{
		$infractionChannel = vB::getDbAssertor()->getRow('vBForum:channel', array('guid' => vB_Channel::INFRACTION_CHANNEL));
		$channelTypeid = vB_Types::instance()->getContentTypeID('vBForum_Channel');

		vB::getDbAssertor()->assertQuery('vBAdmincp:updateChannelCounts',
			array(
				'nodeids' => array($infractionChannel['nodeid']),
				'channelTypeid' => $channelTypeid,
			)
		);
		$this->show_message(sprintf($this->phrase['vbphrase']['update_table'], TABLE_PREFIX . 'node'));

	}

	/**
	 * Update the denormalized values for text.infraction that
	 * show if the node has been infracted or warned.
	 */
	public function step_38($data = null)
	{
		$this->show_message(sprintf($this->phrase['vbphrase']['update_table'], TABLE_PREFIX . 'text'));

		$assertor = vB::getDbAssertor();
		$startat = intval($data['startat']);
		$batchsize = 500;

		$infractions = $assertor->getRows('vBforum:infraction', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
			vB_dB_Query::CONDITIONS_KEY => array(
				array(
					'field' => 'action',
					'value' => 0,
					'operator' => vB_dB_Query::OPERATOR_EQ,
				),
				array(
					'field' => 'infractednodeid',
					'value' => 0,
					'operator' => vB_dB_Query::OPERATOR_GT,
				),
			),
			vB_dB_Query::PARAM_LIMITSTART => $startat,
			vB_dB_Query::PARAM_LIMIT => $batchsize,
		));

		if (!$infractions)
		{
			// done
			$this->show_message(sprintf($this->phrase['core']['process_done']));
			return;
		}
		else
		{
			foreach ($infractions AS $infraction)
			{
				// 1=infraction, 2=warning
				$value = $infraction['points'] > 0 ? 1 : 2;
				$assertor->update('vBforum:text', array('infraction' => $value), array('nodeid' => $infraction['infractednodeid']));
			}

			$this->show_message(sprintf($this->phrase['core']['processed_records_x'], $batchsize));
			return array('startat' => ($startat + $batchsize));
		}
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 100907 $
|| #######################################################################
\*=========================================================================*/
