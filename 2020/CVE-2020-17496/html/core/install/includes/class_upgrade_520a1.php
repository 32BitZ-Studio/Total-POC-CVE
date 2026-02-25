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

class vB_Upgrade_520a1 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '520a1';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.2.0 Alpha 1';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.1.11 Alpha 2';

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
	 * Insert a preview image where missing (VBV-13883)
	 * This step is very similar to 513b1 step_4
	 */
	public function step_1($data = null)
	{
		$startat = (int) isset($data['startat']) ? $data['startat'] : 0;
		$batchsize = 100;

		$assertor = vB::getDbAssertor();
		vB_Upgrade::createAdminSession();

		if ($startat == 0)
		{
			$this->show_message(sprintf($this->phrase['version']['520a1']['updating_photo_preview_images']));
		}

		$galleryContentTypeId =  vB_Types::instance()->getContentTypeID('vBForum_Gallery');
		$rootChannelId = vB_Api::instanceInternal('Content_Channel')->fetchChannelIdByGUID(vB_Channel::MAIN_CHANNEL);

		// Get nodeids
		$rows = $assertor->assertQuery('vBInstall:getPhotoNodesWithMissingPreviewImage', array(
			'root_channel' => $rootChannelId,
			'gallery_contenttypeid' => $galleryContentTypeId,
			'batchsize' => $batchsize,
			'last_processed_nodeid' => $startat,
		));
		$nodeids = array();
		foreach ($rows AS $row)
		{
			$nodeids[] = $row['nodeid'];
		}

		if (empty($nodeids))
		{
			// done
			$this->show_message(sprintf($this->phrase['core']['process_done']));

			return;
		}
		else
		{
			// Assign preview images
			foreach ($nodeids AS $nodeid)
			{
				vB_Library::instance('Content_Gallery')->autoPopulatePreviewImage($nodeid);
			}

			$firstNodeId = min($nodeids);
			$lastNodeId = max($nodeids);

			// output progress
			$this->show_message(sprintf($this->phrase['core']['processed_records_x_y'], $firstNodeId, $lastNodeId));

			// return for next batch
			return array('startat' => $lastNodeId);
		}
	}

	/**
	 * Step 2 - Search indices may be missing or incomplete.
	 *	Add an adminCP message notifying admins to run the search reindex tool.
	 *	We do not want to rebuild the search index during upgrades, as
	 *		1) it may not be needed and
	 *		2) it can take a long time, and since the index can be rebuilt while the site is operational (AFAIK), there's
	 *			no reason to translate that time into downtime due to upgrades.
	 */
	public function step_2($data = NULL)
	{
		$this->add_adminmessage(
			'after_upgrade_520_rebuild_search_index',
			array(
				'dismissible' => 1,			// Note, DB column is "dismissable" with an a, but the function param is "dismissible" with an i.
				'script'      => 'misc.php',
				'action'      => 'doindextypes',
				'execurl'     => 'misc.php?do=doindextypes&indextypes=0&perpage=250&startat=0&autoredirect=1',
				'method'      => 'post',
				'status'      => 'undone',
			)
		);
	}
}

/*======================================================================*\
|| ####################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 101013 $
|| ####################################################################
\*======================================================================*/
