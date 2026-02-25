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

class vB_Upgrade_503a3 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '503a3';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.0.3 Alpha 3';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.0.3 Alpha 2';

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
	* Step 1 - Add index on cacheevent.event
	*/
	public function step_1()
	{
		$this->add_index(
			sprintf($this->phrase['core']['altering_x_table'], 'cacheevent', 1, 1),
			'cacheevent',
			'event',
			'event'
		);
	}

	/*
	 *	Step 2 - Find and import the missing PM Starters
	 *  missed by the query: vBInstall:importPMStarter in 500a28 step 6, VBV-9232
	 *	Closure records are fixed after all missing records are imported.
	 *
	*/
	public function step_2($data = NULL)
	{

		if ($this->tableExists('pmtext') AND $this->tableExists('pm'))
		{
			// output what we're doing
			$this->show_message($this->phrase['version']['503a3']['importing_missing_PM_starters']);

			$assertor = vB::getDbAssertor();
			$batchsize = 10000;
			$startat = intval($data['startat']);

			//First see if we need to do something. Maybe we're O.K.
			if (!empty($data['maxToFix']))
			{
				$maxToFix = $data['maxToFix'];
			}
			else
			{
				$maxToFix = $assertor->getRow('vBInstall:getMaxMissingPMStarter', array('contenttypeid' => vB_Api_ContentType::OLDTYPE_PMSTARTER));
				$maxToFix = intval($maxToFix['maxToFix']);
				//If we don't have any missing, we're done.
				if (intval($maxToFix) < 1)
				{
					$this->skip_message();
					return;
				}
			}

			if ($startat >= $maxToFix)
			{
				$this->show_message(sprintf($this->phrase['core']['process_done']));
				return;
			}

			$nodeLib = vB_Library::instance('node');
			$pmHomeid = $nodeLib->fetchPMChannel();
			$pmHome = $nodeLib->getNode($pmHomeid);
			$assertor->assertQuery('vBInstall:importMissingPMStarter', array('startat' => $startat, 'batchsize' => $batchsize,
			'pmRouteid' => $pmHome['routeid'], 'privatemessageType' => vB_Types::instance()->getContentTypeID('vBForum_PrivateMessage'),
			'privateMessageChannel' => $pmHomeid, 'contenttypeid' => vB_Api_ContentType::OLDTYPE_PMSTARTER));
			$assertor->assertQuery('vBInstall:setPMStarter', array('startat' => $startat, 'batchsize' => $batchsize, 'contenttypeid' => vB_Api_ContentType::OLDTYPE_PMSTARTER));
			$assertor->assertQuery('vBInstall:importMissingPMText', array('startat' => $startat, 'batchsize' => $batchsize, 'contenttypeid' => vB_Api_ContentType::OLDTYPE_PMSTARTER));
			$assertor->assertQuery('vBInstall:importMissingPMMessage', array('startat' => $startat, 'batchsize' => $batchsize, 'contenttypeid' => vB_Api_ContentType::OLDTYPE_PMSTARTER));
			$assertor->assertQuery('vBInstall:importMissingPMSent', array('startat' => $startat, 'batchsize' => $batchsize, 'contenttypeid' => vB_Api_ContentType::OLDTYPE_PMSTARTER));
			$assertor->assertQuery('vBInstall:importMissingPMInbox', array('startat' => $startat, 'batchsize' => $batchsize, 'contenttypeid' => vB_Api_ContentType::OLDTYPE_PMSTARTER));
			$assertor->assertQuery('vBInstall:updateChannelRoutes', array('startat' => $startat, 'batchsize' => $batchsize, 'contenttypeid' => vB_Api_ContentType::OLDTYPE_PMSTARTER));

			// output current progress
			$this->show_message(sprintf($this->phrase['core']['processed_records_x_y_z'], $startat + 1, $startat + $batchsize, $maxToFix));

			return array('startat' => ($startat + $batchsize), 'maxToFix' => $maxToFix);
		}
		else
		{
			$this->skip_message();
		}
	}

	/*
	 * insert album legacy routes
	 */
	public function step_3()
	{
		$this->show_message(sprintf($this->phrase['vbphrase']['update_table'], 'routenew'));

		$db = vB::getDbAssertor();
		$legacyClass = array(
			'vB5_Route_Legacy_Album'
		);

		foreach ($legacyClass as $c)
		{
			$route = new $c;
			$data = array(
				'prefix'	=> $route->getPrefix(),
				'regex'		=> $route->getRegex(),
				'class'		=> $c,
				'arguments'	=> serialize($route->getArguments()),
			);
			$data['guid'] = vB_Xml_Export_Route::createGUID($data);
			$db->delete('routenew', array('class' => $c));
			$db->insert('routenew', $data);
		}
	}

	/*
	 *	Step 4 - Find and import the missing PM responses
	 *  missed by the query: vBInstall:importPMResponse in 500a28 step 7, VBV-9232
	 *	Closure records are fixed after all missing records are imported.
	 *
	*/
	public function step_4($data = NULL)
	{

		if ($this->tableExists('pmtext') AND $this->tableExists('pm'))
		{
			// output what we're doing
			$this->show_message($this->phrase['version']['503a3']['importing_missing_PM_responses']);

			$assertor = vB::getDbAssertor();
			$batchsize = 1000;

			//First see if we need to do something. Maybe we're O.K.
			if (!empty($data['maxToFix']))
			{
				$maxToFix = $data['maxToFix'];
			}
			else
			{
				$maxToFix = $assertor->getRow('vBInstall:getMaxMissingPMResponse', array('contenttypeidResponse' => vB_Api_ContentType::OLDTYPE_PMRESPONSE,
					'contenttypeidStarter' => vB_Api_ContentType::OLDTYPE_PMSTARTER));
				$maxToFix = intval($maxToFix['maxToFix']);
				//If we don't have any missing, we're done.
				if ($maxToFix < 1)
				{
					$this->skip_message();
					return;
				}
			}

			// Here we fetch the minimum record to fix, this is to avoid unnecessary query executions if there are too sparse missing records
			$minToFix = $assertor->getRow('vBInstall:getMinMissingPMResponse', array('contenttypeidResponse' => vB_Api_ContentType::OLDTYPE_PMRESPONSE,
					'contenttypeidStarter' => vB_Api_ContentType::OLDTYPE_PMSTARTER));
			$startat = intval($minToFix['minToFix']);

			if (($startat < 1) OR ($startat > $maxToFix))
			{
				$this->show_message(sprintf($this->phrase['core']['process_done']));
				return;
			}

			// Here we decrement to take into account the '>' sign for the $startat in queries used in other steps
			$startat--;

			$nodeLib = vB_Library::instance('node');
			$pmHomeid = $nodeLib->fetchPMChannel();
			$pmHome = $nodeLib->getNode($pmHomeid);
			$assertor->assertQuery('vBInstall:importMissingPMResponse', array('startat' => $startat, 'batchsize' => $batchsize,
			'pmRouteid' => $pmHome['routeid'], 'privatemessageType' => vB_Types::instance()->getContentTypeID('vBForum_PrivateMessage'),
			'privateMessageChannel' => $pmHomeid, 'contenttypeidResponse' => vB_Api_ContentType::OLDTYPE_PMRESPONSE, 'contenttypeidStarter' => vB_Api_ContentType::OLDTYPE_PMSTARTER));
			$assertor->assertQuery('vBInstall:importMissingPMText', array('startat' => $startat, 'batchsize' => $batchsize, 'contenttypeid' => vB_Api_ContentType::OLDTYPE_PMRESPONSE));
			$assertor->assertQuery('vBInstall:importMissingPMMessage', array('startat' => $startat, 'batchsize' => $batchsize, 'contenttypeid' => vB_Api_ContentType::OLDTYPE_PMRESPONSE));
			$assertor->assertQuery('vBInstall:importMissingPMSent', array('startat' => $startat, 'batchsize' => $batchsize, 'contenttypeid' => vB_Api_ContentType::OLDTYPE_PMRESPONSE));
			$assertor->assertQuery('vBInstall:importMissingPMInbox', array('startat' => $startat, 'batchsize' => $batchsize, 'contenttypeid' => vB_Api_ContentType::OLDTYPE_PMRESPONSE));

			// output current progress, increment $startat just for display purposes, it is overwritten in the next iteration
			$startat++;
			$this->show_message(sprintf($this->phrase['core']['processed_records_x_y_z'], $startat, $startat + $batchsize, $maxToFix));

			return array('startat' => $startat, 'maxToFix' => $maxToFix);
		}
		else
		{
			$this->skip_message();
		}
	}

	function step_5()
	{
		$this->add_index(
			sprintf($this->phrase['core']['create_index_x_on_y'], 'contenttypeid_parentid', TABLE_PREFIX . 'node'),
			'node',
			'contenttypeid_parentid',
			array('contenttypeid', 'parentid')
		);
	}

	/**
	 * Create new fields to support official custom languages
	 */
	public function step_6()
	{
		if (!$this->field_exists('language', 'vblangcode'))
		{
			// Create nodeid field
			$this->add_field(
				sprintf($this->phrase['core']['altering_x_table'], 'language', 1, 2),
				'language',
				'vblangcode',
				'varchar',
				array('length' => 12, 'default' => '',)
			);
		}
		else
		{
			$this->skip_message();
		}

		if (!$this->field_exists('language', 'newoptions'))
		{
			// Create nodeid field
			$this->add_field(
				sprintf($this->phrase['core']['altering_x_table'], 'language', 2, 2),
				'language',
				'revision',
				'smallint',
				self::FIELD_DEFAULTS
			);
		}
		else
		{
			$this->skip_message();
		}
	}

	/*
	 *	Step 7- Find and import the missing Visitor Messages
	 *  missed by the query: vBInstall:ImportVisitorMessages, importVMText
	 * 	in 500a28 step_16, VBV-9232
	 *
	*/
	public function step_7($data = NULL)
	{
		// visitormessage table needs to exist for importing...
		if ($this->tableExists('visitormessage') AND $this->tableExists('node') AND $this->tableExists('text'))
		{
			// output what we're doing
			$this->show_message($this->phrase['version']['503a3']['importing_missing_VM']);

			$assertor = vB::getDbAssertor();
			$batchSize = 1000;
			$startat = intval($data['startat']);
			$textTypeid = vB_Types::instance()->getContentTypeID('vBForum_Text');
			$vmTypeid = vB_Types::instance()->getContentTypeID('vBForum_VisitorMessage');

			/*
			 *	The batching for this is a bit different. Basically, this step should
			 *	loop until getMissingVM doesn't find any more missing VM's. If it enters an
			 *	infinite loop, something went wrong in the importing.
			 */

			// We grab missing vm's.
			$missingVMs = $assertor->assertQuery('vBInstall:getMissingVM',
				array(
					'vmtypeid' => $vmTypeid,
					'batchsize' => $batchSize
				)
			);

			// if there are no more visitor messages missing, then we are done.
			if (!$missingVMs->valid())
			{
				$this->show_message(sprintf($this->phrase['core']['process_done']));
				return;
			}

			// otherwise, let's grab the vmid's from the query
			$vmidList = array();
			foreach ($missingVMs AS $vmRow)
			{
				$vmidList[] = $vmRow['vmid'];
			}

			$nodeLib = vB_Library::instance('node');
			$vmHomeid = $nodeLib->fetchVMChannel();
			$vmHome = $nodeLib->getNode($vmHomeid);

			// import the visitor messages into the node table
			$assertor->assertQuery('vBInstall:ImportMissingVisitorMessages', array(
				'vmChannel' => $vmHomeid,
				'texttypeid' => $textTypeid,
				'visitorMessageType' => $vmTypeid,
				'vmRouteid' => $vmHome['routeid'],
				'vmIds' => $vmidList
			));
			// then the text table..
			$assertor->assertQuery('vBInstall:importMissingVMText', array(
				'visitorMessageType' => $vmTypeid,
				'vmIds' => $vmidList
			));

			// then create the closure records..
			$assertor->assertQuery('vBInstall:addClosureSelfForOldids', array(
				'contenttypeid' => $vmTypeid,
				'oldids' => $vmidList,
			));
			$assertor->assertQuery('vBInstall:addClosureParentsForOldids', array(
				'contenttypeid' => $vmTypeid,
				'oldids' => $vmidList,
			));
			// now set some channel routes & node starters
			$assertor->assertQuery('vBInstall:updateChannelRoutesAndStarter_503a3', array(
				'contenttypeid' => $vmTypeid,
				'oldids' => $vmidList
			));

			// output current progress
			$this->show_message(sprintf($this->phrase['core']['processed_records_x'], count($vmidList)));

			// return something so it'll kick off the next batch, even though this batching doesn't use startat
			return array('startat' => 1);
		}
		else
		{
			$this->skip_message();
		}
	}

	/*
	 *	Step 8 - Find and import the missing SG discussions and their first post as starters
	 *  missed by the query: vBInstall:importSGDiscussions in 500a29 step 6, VBV-9232
	 *	Closure records are fixed after all missing records are imported.
	 *
	*/
	public function step_8($data = NULL)
	{
		if ($this->tableExists('socialgroup') AND $this->tableExists('discussion') AND $this->tableExists('groupmessage'))
		{
			$startat = intval($data['startat']);
			$assertor = vB::getDbAssertor();
			$groupTypeid = vB_Types::instance()->getContentTypeID('vBForum_SocialGroup');
			$discussionTypeid = vB_Types::instance()->getContentTypeID('vBForum_SocialGroupDiscussion');
			$batchsize = 1000;

			// Get the missing SG discussions
			$missingSGDiscussions = $assertor->assertQuery('vBInstall:getMissingSGDiscussions',
				array(
					'groupTypeid' => $groupTypeid,
					'discussionTypeid' => $discussionTypeid,
					'batchsize' => $batchsize
				)
			);

			// if there are no more records missing, then we are done.
			if (!$missingSGDiscussions->valid())
			{
				$this->show_message(sprintf($this->phrase['core']['process_done']));
				return;
			}

			// Get the discussionid from the query
			$discussionList = array();
			foreach ($missingSGDiscussions AS $discussion)
			{
				$discussionList[] = $discussion['discussionid'];
			}

			// And import them as text
			$this->show_message($this->phrase['version']['503a3']['importing_missing_discussions']);
			$assertor->assertQuery('vBInstall:importMissingSGDiscussions',array(
				'textTypeid' =>  vB_Types::instance()->getContentTypeID('vBForum_Text'),
				'discussionTypeid' => $discussionTypeid,
				'discussionList' => $discussionList,
				'grouptypeid' => $groupTypeid
			));

			// Get the nodeids from the newly imported discussions
			$discussionsText = $assertor->assertQuery('vBInstall:getMissingSGDiscussionText',array(
				'batchsize' => $batchsize,
				'discussionTypeid' => $discussionTypeid
			));

			$nodeList = array();
			foreach ($discussionsText AS $text)
			{
				$nodeList[] = $text['nodeid'];
			}

			// set them as starters
			$assertor->assertQuery('vBInstall:setStarterByNodeList',array(
				'nodeList' => $nodeList
			));

			// and import them to the text table
			$assertor->assertQuery('vBInstall:importMissingSGDiscussionText',array(
				'discussionTypeid' => $discussionTypeid,
				'textList' => $nodeList
			));

			$assertor->assertQuery('vBInstall:updateChannelRoutesByNodeList',array(
				'nodeList' => $nodeList,
				'contenttypeid' => $discussionTypeid
			));

			$this->show_message(sprintf($this->phrase['core']['processed_records_x'], $batchsize));
			return array('startat' => ($startat));

		}
		else
		{
			$this->skip_message();
		}
	}

	/*
	 *	Step 9 - Find and import the missing SG messages
	 *  missed by the query: vBInstall:importSGPosts in 500a29 step 7, VBV-9232
	 *	Closure records are fixed after all missing records are imported.
	 *
	*/
	public function step_9($data = NULL)
	{
		if ($this->tableExists('socialgroup') AND $this->tableExists('discussion') AND $this->tableExists('groupmessage'))
		{
			$startat = intval($data['startat']);
			$assertor = vB::getDbAssertor();
			$groupTypeid = vB_Types::instance()->getContentTypeID('vBForum_SocialGroup');
			$discussionTypeid = vB_Types::instance()->getContentTypeID('vBForum_SocialGroupDiscussion');
			$messageTypeid = vB_Types::instance()->getContentTypeID('vBForum_SocialGroupMessage');
			$batchsize = 1000;

			// Get the missing SG posts
			$missingSGPosts = $assertor->assertQuery('vBInstall:getMissingSGPosts',
				array(
					'messageTypeid' => $messageTypeid,
					'discussionTypeid' => $discussionTypeid,
					'batchsize' => $batchsize
				)
			);

			// if there are no more records missing, then we are done.
			if (!$missingSGPosts->valid())
			{
				$this->show_message(sprintf($this->phrase['core']['process_done']));
				return;
			}

			// Get the groupmessage id from the query
			$messageList = array();
			foreach ($missingSGPosts AS $message)
			{
				$messageList[] = $message['gmid'];
			}

			// And import them as text
			$this->show_message($this->phrase['version']['503a3']['importing_missing_messages']);
			$assertor->assertQuery('vBInstall:importMissingSGPosts',array(
				'textTypeid' =>  vB_Types::instance()->getContentTypeID('vBForum_Text'),
				'discussionTypeid' => $discussionTypeid,
				'messageList' => $messageList,
				'messageTypeid' => $messageTypeid
			));

			// Get the nodeids from the newly imported posts
			$postsText = $assertor->assertQuery('vBInstall:getMissingSGPostsText',array(
				'batchsize' => $batchsize,
				'messageTypeid' => $messageTypeid
			));

			$nodeList = array();
			foreach ($postsText AS $text)
			{
				$nodeList[] = $text['nodeid'];
			}

			// and import them to the text table
			$assertor->assertQuery('vBInstall:importMissingSGPostText',array(
				'messageTypeid' => $messageTypeid,
				'nodeList' => $nodeList
			));

			$this->show_message(sprintf($this->phrase['core']['processed_records_x'], count($messageList)));
			return array('startat' => ($startat));

		}
		else
		{
			$this->skip_message();
		}
	}

	/**
	* Removing Search Queue Processor Scheduled Tasks
	**/
	function step_10()
	{
			$this->show_message(sprintf($this->phrase['version']['503a3']['delete_queue_processor_cron']));
			vB::getDbAssertor()->delete('cron',array(
				'varname' => 'searchqueueupdates',
				'volatile' => 1,
				'product' => 'vbulletin'
			));
	}

	/*
	 *	Step 11 - Find and import the missing SG galleries
	 *  missed by the query: vBInstall:importSGGalleryNode in 500a29 step 8, VBV-9232
	 *	Closure records are fixed after all missing records are imported.
	 *
	*/
	public function step_11($data = NULL)
	{
		if ($this->tableExists('socialgroup') AND $this->tableExists('node') AND $this->tableExists('attachment') AND $this->tableExists('gallery'))
		{
			$startat = intval($data['startat']);
			$assertor = vB::getDbAssertor();
			$groupTypeid = vB_Types::instance()->getContentTypeID('vBForum_SocialGroup');
			$galleryTypeid = vB_Types::instance()->getContentTypeID('vBForum_Gallery');
			$batchsize = 1000;

			// Get the missing SG galleries
			$missingSGGalleries = $assertor->assertQuery('vBInstall:getMissingSGGalleryNode',
				array(
					'groupTypeid' => $groupTypeid,
					'oldGalleryTypeid' => vB_Api_ContentType::OLDTYPE_SGGALLERY,
					'batchsize' => $batchsize
				)
			);

			// if there are no more records missing, then we are done.
			if (!$missingSGGalleries->valid())
			{
				$this->show_message(sprintf($this->phrase['core']['process_done']));
				return;
			}

			// Get the gallery id from the query
			$galleryList = array();
			foreach ($missingSGGalleries AS $gallery)
			{
				$galleryList[] = $gallery['galleryid'];
			}

			// And import them
			$this->show_message($this->phrase['version']['503a3']['importing_missing_SG_galleries']);
			$assertor->assertQuery('vBInstall:importMissingSGGalleryNode',array(
				'groupTypeid' =>  $groupTypeid,
				'galleryTypeid' => $galleryTypeid,
				'galleryList' => $galleryList
			));

			// Get the nodeids from the newly imported galleries
			$galleyNodes = $assertor->assertQuery('vBInstall:getMissingSGGallery',array(
				'batchsize' => $batchsize,
				'groupTypeid' => $groupTypeid,
				'oldGalleryTypeid' => vB_Api_ContentType::OLDTYPE_SGGALLERY
			));

			$nodeList = array();
			foreach ($galleyNodes AS $gallery)
			{
				$nodeList[] = $gallery['nodeid'];
			}

			// import them to the gallery table
			$assertor->assertQuery('vBInstall:importMissingSGGallery',array(
				'oldGalleryTypeid' => vB_Api_ContentType::OLDTYPE_SGGALLERY,
				'nodeList' => $nodeList,
				'groupTypeid' => $groupTypeid,
				'caption' => $this->phrase['version']['500a29']['imported_socialgroup_galleries']
			));

			// and to the text table
			$assertor->assertQuery('vBInstall:importMissingSGText',array(
				'oldGalleryTypeid' => vB_Api_ContentType::OLDTYPE_SGGALLERY,
				'nodeList' => $nodeList,
				'groupTypeid' => $groupTypeid,
				'caption' => $this->phrase['version']['500a29']['imported_socialgroup_galleries']
			));

			// set them as starters
			$assertor->assertQuery('vBInstall:setStarterByNodeList',array(
				'nodeList' => $nodeList
			));

			$assertor->assertQuery('vBInstall:updateChannelRoutesByNodeList',array(
				'nodeList' => $nodeList,
				'contenttypeid' => vB_Api_ContentType::OLDTYPE_SGGALLERY
			));

			$this->show_message(sprintf($this->phrase['core']['processed_records_x'], count($galleryList)));
			return array('startat' => ($startat));

		}
		else
		{
			$this->skip_message();
		}
	}

	/*
	 *	Step 12 - Find and import the missing SG photos
	 *  missed by the query: vBInstall:importSGPhotoNodes in 500a29 step 9, VBV-9232
	 *	Closure records are fixed after all missing records are imported.
	 *
	*/
	public function step_12($data = NULL)
	{
		if ($this->tableExists('socialgroup') AND $this->tableExists('node') AND $this->tableExists('attachment') AND $this->tableExists('photo'))
		{
			$startat = intval($data['startat']);
			$assertor = vB::getDbAssertor();
			$groupTypeid = vB_Types::instance()->getContentTypeID('vBForum_SocialGroup');
			$galleryTypeid = vB_Types::instance()->getContentTypeID('vBForum_Gallery');
			$photoTypeid = vB_Types::instance()->getContentTypeID('vBForum_Photo');
			$batchsize = 1000;

			// Get the missing SG photos
			$missingSGPhotos = $assertor->assertQuery('vBInstall:getMissingSGPhotoNodes',
				array(
					'groupTypeid' => $groupTypeid,
					'oldGalleryTypeid' => vB_Api_ContentType::OLDTYPE_SGGALLERY,
					'oldPhotoTypeid' => vB_Api_ContentType::OLDTYPE_SGPHOTO,
					'batchsize' => $batchsize
				)
			);

			// if there are no more records missing, then we are done.
			if (!$missingSGPhotos->valid())
			{
				$this->show_message(sprintf($this->phrase['core']['process_done']));
				return;
			}

			// Get the attachmentid from the query
			$photoList = array();
			foreach ($missingSGPhotos AS $photo)
			{
				$photoList[] = $photo['attachmentid'];
			}

			// And import them
			$this->show_message($this->phrase['version']['503a3']['importing_missing_SG_photos']);
			$assertor->assertQuery('vBInstall:importMissingSGPhotoNodes',array(
				'groupTypeid' =>  $groupTypeid,
				'oldGalleryTypeid' => vB_Api_ContentType::OLDTYPE_SGGALLERY,
				'oldPhotoTypeid' => vB_Api_ContentType::OLDTYPE_SGPHOTO,
				'photoTypeid' => $photoTypeid,
				'photoList' => $photoList
			));

			$assertor->assertQuery('vBInstall:importMissingSGPhotos', array(
				'groupTypeid' =>  $groupTypeid,
				'oldPhotoTypeid' => vB_Api_ContentType::OLDTYPE_SGPHOTO,
				'photoList' => $photoList
			));

			$assertor->assertQuery('vBInstall:fixMissingLastGalleryData',array(
				'photoList' => $photoList
			));

			$this->show_message(sprintf($this->phrase['core']['processed_records_x'], count($photoList)));
			return array('startat' => ($startat));

		}
		else
		{
			$this->skip_message();
		}
	}

	function step_13()
	{
		$this->skip_message();
	}

	/**
	 * Update lastcontentid data for socialgroups, this is a carbon copy of the one in 500a29, step_19
	 * The query getMaxImportedPost is returning the max node.oldid, but for the batching in updateDiscussionLastContentId
	 * node.nodeid was being used, therefore usually not updating the nodes.
	 * updateDiscussionLastContentId was fixed to use oldid, this step will fix installations already upgraded to 5.0.x and missing nodes (VBV-9232),
	 *
	 */
	function step_14($data = NULL)
	{
		$messageTypeid = vB_Types::instance()->getContentTypeID('vBForum_SocialGroupMessage');
		$discussionTypeid = vB_Types::instance()->getContentTypeID('vBForum_SocialGroupDiscussion');
		$batchsize = 10000;
		$startat = intval($data['startat']);
		$assertor = vB::getDbAssertor();

		$maxvB5 = $assertor->getRow('vBInstall:getMaxImportedPost', array('contenttypeid' => $messageTypeid));
		$maxvB5 = intval($maxvB5['maxid']);

		if ($startat == 0)
		{
			$this->show_message(sprintf($this->phrase['vbphrase']['update_table'], TABLE_PREFIX . 'node'));
		}
		else if ($startat >= $maxvB5)
		{
			$this->show_message(sprintf($this->phrase['core']['process_done']));
			return;
		}
		$assertor->assertQuery('vBInstall:updateDiscussionLastContentId', array('messageTypeid' => $messageTypeid,
			'discussionTypeid' => $discussionTypeid,'startat' => $startat, 'batchsize' => $batchsize));
		$this->show_message(sprintf($this->phrase['core']['processed_records_x'], $batchsize));
		return array('startat' => $startat + $batchsize);
	}

	/*
	 * 	Step 15 - Add missing closure records VBV-9232
	 * 	This step is inefficient. It walks through the entire node table
	 *	and finds nodes with missing closure records via
	 *	getNoclosureNodes & getOrphanNodes.
	 *	Since it's rare that either query actually returns anything,
	 *	this step will probably do quite a few iterations doing nothing
	 *	until a node with missing closure records is found.
	*/
	public function step_15($data = NULL)
	{
		if ($this->tableExists('node') AND $this->tableExists('closure'))
		{
			$assertor = vB::getDbAssertor();
			$batchSize = 50000;
			$startat = intval($data['startat']);

			// get max nodeid
			if (!empty($data['maxNodeid']))
			{
				$maxNodeid = intval($data['maxNodeid']);
			}
			else
			{
				$maxNodeid = $assertor->getRow('vBInstall:getMaxNodeid', array());
				$maxNodeid = intval($maxNodeid['maxid']);
			}
			//If we don't have any nodes, we do nothing.
			if ($maxNodeid < 1)
			{
				$this->skip_message();
				return;
			}

			// finish condition
			if ($maxNodeid <= $startat)
			{
				$this->show_message(sprintf($this->phrase['core']['process_done']));
				return;
			}


			// output what we're doing
			$this->show_message($this->phrase['version']['502rc1']['adding_missing_closure']);


			// grab the nodeid's for the nodes missing closure records
			$nodesMissingSelfClosures = $assertor->assertQuery('vBInstall:getNoclosureNodes',
				array(
					'oldcontenttypeid' => $albumTypeid,
					'startat' => $startat,
					'batchsize' => $batchSize,
				)
			);
			// some nodes might have self closure but no parent closure.
			$nodesMissingParentClosures = $assertor->assertQuery('vBInstall:getOrphanNodes',
				array(
					'oldcontenttypeid' => $albumTypeid,
					'startat' => $startat,
					'batchsize' => $batchSize,
				)
			);

			// If there were no nodes missing closure in this batch, quickly move on to the next batch
			if ( !($nodesMissingSelfClosures->valid() OR $nodesMissingParentClosures->valid()) )
			{
				// output current progress
				$this->show_message(sprintf($this->phrase['core']['processed_records_x_y_z'], $startat + 1, $startat + $batchSize, $maxNodeid));
				// kick off the next batch
				return array('startat' => ($startat + $batchSize), 'maxNodeid' => $maxNodeid);
			}

			// otherwise, let's grab the nodeid's from the query
			$nodeIdList_needself = array();
			foreach ($nodesMissingSelfClosures AS $nodeRow)
			{
				$nodeIdList_needself[] = $nodeRow['nodeid'];
			}

			$nodeIdList_needparents = array();
			foreach ($nodesMissingParentClosures AS $nodeRow)
			{
				$nodeIdList_needparents[] = $nodeRow['nodeid'];
			}


			// add closure records
			if (!empty($nodeIdList_needself))
			{
				$assertor->assertQuery('vBInstall:addMissingClosureSelf',
					array(
						'nodeIdList' => $nodeIdList_needself
					)
				);
			}

			if (!empty($nodeIdList_needparents))
			{
				$assertor->assertQuery('vBInstall:addMissingClosureParents',
					array(
						'nodeIdList' => $nodeIdList_needparents
					)
				);
			}


			// output current progress
			$this->show_message(sprintf($this->phrase['core']['processed_records_x_y_z'], $startat + 1, $startat + $batchSize, $maxNodeid));
			// kick off the next batch
			return array('startat' => ($startat + $batchSize), 'maxNodeid' => $maxNodeid);
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
|| # CVS: $RCSfile$ - $Revision: 104027 $
|| #######################################################################
\*=========================================================================*/
