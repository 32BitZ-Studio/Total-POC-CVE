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

class vB_Upgrade_504rc1 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '504rc1';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.0.4 Release Candidate 1';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.0.4 Alpha 3';

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
	 * Step 1 - Add new sigpicnew table
	 */
	public function step_1()
	{
		$this->run_query(
			sprintf($this->phrase['vbphrase']['create_table'], TABLE_PREFIX . "sigpicnew"),
			"CREATE TABLE " . TABLE_PREFIX . "sigpicnew (
				userid int(10) unsigned NOT NULL default '0',
				filedataid int(10) unsigned NOT NULL default '0',
				PRIMARY KEY  (userid),
				KEY filedataid (filedataid)
			)",
			self::MYSQL_ERROR_TABLE_EXISTS
		);
	}

	/**
	 * Update site navbars
	 */
	public function step_2()
	{
		$this->syncNavbars();
	}
	
	/**
	 * Step 3 - Update blog nodes with new nodeoption vB_Api_Node::OPTION_AUTOSUBSCRIBE_ON_JOIN = 512;
	 */
	public function step_3($data = NULL)
	{
		// display what we're doing
		$this->show_message(sprintf($this->phrase['version']['504rc1']['update_blog_nodeoption']));
		
		// set-up constants, objects etc.
		$blogChannelId = vB_Library::instance('Blog')->getBlogChannel();
		$assertor = vB::getDbAssertor();
		// We'll be updating the node table. At about 100k, a similar update query (different parentid)
		// on the node table on the dev DB took ~5s
		$batchsize = 100000; 
		$startat = intval($data['startat']);
		// fetch max nodeid if necessary
		if (!isset($data['max']))
		{
			$maxNodeid  = $assertor->getRow('vBInstall:getMaxChildNodeid', array('parentid' => $blogChannelId));
			$data['max'] = intval($maxNodeid['maxid']);
		}
		$max = intval($data['max']);
		
		// if we went through all the blog nodes, we're done
		if($startat >= $max)
		{
			$this->show_message(sprintf($this->phrase['core']['process_done']));
			return;
		}
		
		// update node table
		$assertor->assertQuery('vBInstall:updateBlogNodeOptions', 
			array(	'setNewOption' => vB_Api_Node::OPTION_AUTOSUBSCRIBE_ON_JOIN,
					'blogChannelId' => $blogChannelId,
					'startat' => $startat,
					'batchsize' => $batchsize
			));
		
		// output progress & return for next batch
		$this->show_message(sprintf($this->phrase['core']['processed_records_x_y_z'], $startat + 1, $startat + $batchsize, $max));
		return array('startat' => ($startat + $batchsize), 'max' => $data['max']);		
	}
	
	/**
	 * Step 4 - Add subscriptions for blog owners, moderators & members
	 */
	public function step_4($data = NULL)
	{
		// display what we're doing
		$this->show_message(sprintf($this->phrase['version']['504rc1']['add_blog_subscription']));
		
		// set-up constants, objects etc.
		$blogChannelId = vB_Library::instance('Blog')->getBlogChannel();
		$assertor = vB::getDbAssertor();
		
		// fetch blog channel GIT records that're missing subscriptions
		$queryResult = $assertor->assertQuery('vBInstall:fetchBlogGroupintopicMissingSubscriptions', 
			array(
					'blogChannelId' => $blogChannelId
			));
		
		// if none found, nothing to do.
		if (!$queryResult->valid())
		{
			$this->show_message(sprintf($this->phrase['core']['process_done']));
			return;
		}
		
		$subscriptionToAdd = array();
		foreach ($queryResult AS $key => $gitRow)
		{
			$subscriptionToAdd[] = array("nodeid" => $gitRow['nodeid'], "userid" => $gitRow['userid']);
		}
		
		// remove duplicates
		$subscriptionToAdd = array_map('unserialize', array_unique(array_map('serialize', $subscriptionToAdd)));
		
		// batchSize note: I do not believe this step requires batching. Tested on about 50k records to insert 
		// 		which took a few seconds. I am not aware of there being that many blogs * (owner + moderators + members)
		//		in the wild.
		// Add subscription records. 
		$assertor->assertQuery('vBInstall:addSubscriptionRecords', array('subscriptions' => $subscriptionToAdd));
		
		
		// finished
		$this->show_message(sprintf($this->phrase['core']['process_done']));
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
