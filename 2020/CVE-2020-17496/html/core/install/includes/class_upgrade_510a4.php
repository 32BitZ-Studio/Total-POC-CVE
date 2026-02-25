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

class vB_Upgrade_510a4 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '510a4';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.1.0 Alpha 4';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.1.0 Alpha 3';

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
	 * Step 1 - Update blog nodes, set displayorder = 1;
	 */
	public function step_1($data = NULL)
	{
		if (!isset($data['startat']) OR $data['startat'] == 0)
		{
			// display what we're doing if it's the first iteration
			$this->show_message(sprintf($this->phrase['version']['510a4']['update_blog_displayorder']));
		}

		// set-up constants, objects etc.
		$blogChannelId = vB_Library::instance('Blog')->getBlogChannel();
		$assertor = vB::getDbAssertor();
		$batchsize = 10000; // takes about 5s per batch on a 500k node DB.
		$startat = intval($data['startat']);
		// grab blog nodeids & put them in an array
		$nodeidQry = $assertor->assertQuery('vBInstall:getBlogsWithNullDisplayorder',
			array(
				'blogChannelId' => $blogChannelId,
				'batchsize' => $batchsize,
			)
		);
		$nodeids = array();
		foreach ($nodeidQry AS $node)
		{
			$nodeids[] = $node['nodeid'];
		}

		// if no nodes are left to update, we're done
		if(count($nodeids) == 0)
		{
			$this->show_message(sprintf($this->phrase['core']['process_done']));
			return;
		}

		// update node table
		$assertor->assertQuery('vBInstall:updateNodesDisplayorder',
			array(
				"nodeids" => $nodeids
			)
		);

		// output progress & return for next batch
		$this->show_message(sprintf($this->phrase['core']['processed_records_x_y'], min($nodeids), max($nodeids)));
		return array('startat' => 1);
	}

	/**
	 * Step 2 - Update social group & sg category nodes, set displayorder = 1;
	 */
	public function step_2($data = NULL)
	{
		if (!isset($data['startat']) OR $data['startat'] == 0)
		{
			// display what we're doing if it's the first iteration
			$this->show_message(sprintf($this->phrase['version']['510a4']['update_socialgroup_displayorder']));
		}

		// set-up constants, objects etc.
		$sgChannelId = vB_Library::instance('node')->getSGChannel();
		$assertor = vB::getDbAssertor();
		$batchsize = 10000; // takes about 5s per batch on a 500k node DB.
		$startat = intval($data['startat']);
		// grab SG nodeids & put them in an array. This assumes that any node in the closure table
		// with depth 2 from the social group root channel is a social group.
		// Depth 1 is a SG category, depth 3+ would be discussions
		$nodeidQry = $assertor->assertQuery('vBInstall:getSocialGroupsWithNullDisplayorder',
			array(
				'sgChannelId' => $sgChannelId,
				'batchsize' => $batchsize,
			)
		);
		$nodeids = array();
		foreach ($nodeidQry AS $node)
		{
			$nodeids[] = $node['nodeid'];
		}

		// if no nodes are left to update, we're done
		if(count($nodeids) == 0)
		{
			$this->show_message(sprintf($this->phrase['core']['process_done']));
			return;
		}

		// update node table
		$assertor->assertQuery('vBInstall:updateNodesDisplayorder',
			array(
				"nodeids" => $nodeids
			)
		);

		// output progress & return for next batch
		$this->show_message(sprintf($this->phrase['core']['processed_records_x_y'], min($nodeids), max($nodeids)));
		return array('startat' => 1);
	}

	/**
	 * Step 3 - Updates filedata records to change refcount from 0 to 1 if the image
	 * is being used as a link preview image (VBV-11243)
	 */
	public function step_3($data = null)
	{
		$startat = (int) isset($data['startat']) ? $data['startat'] : 0;
		$batchsize = 500;
		$assertor = vB::getDbAssertor();

		if ($startat == 0)
		{
			$this->show_message(sprintf($this->phrase['version']['510a4']['updating_link_preview_images']));
		}

		// Get filedataids
		// Don't send the startat value to the query. The offset will always be 0
		// because the previous records are now updated and will no longer match.
		$filedataidRes = $assertor->getRows('vBInstall:getLinkPreviewFiledataidsWithRefcountZero', array(
			'batchsize' => $batchsize,
		));
		$filedataids = array();
		foreach ($filedataidRes AS $filedataid)
		{
			$filedataids[] = $filedataid['filedataid'];
		}

		$filedataidCount = count($filedataids);

		if ($filedataidCount > 0)
		{
			// process filedata records
			$assertor->update('filedata', array('refcount' => 1), array('filedataid' => $filedataids));

			// output progress
			$this->show_message(sprintf($this->phrase['core']['processed_records_x_y'], $startat + 1, $startat + $filedataidCount));

			// return for next batch
			// send the calculated startat value for display purposes only
			return array('startat' => $startat + $filedataidCount);
		}
		else
		{
			// done
			$this->show_message(sprintf($this->phrase['core']['process_done']));

			return;
		}
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
