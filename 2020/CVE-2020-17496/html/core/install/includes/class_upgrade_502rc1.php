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

class vB_Upgrade_502rc1 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '502rc1';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.0.2 Release Candidate 1';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.0.2 Beta 1';

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
	 *	Step 1 - Find and import the missing albums VBV-8952
	 *	This is similar to step_17 of class_upgrade_500a28,
	 * 	and imports the albums that the step missed.
	 *	The closure records that the mentioned step left out
	 *	should be added by step 3
	*/
	public function step_1($data = NULL)
	{
		if ($this->tableExists('album') AND $this->tableExists('attachment')  AND $this->tableExists('filedata'))
		{
			// output what we're doing
			$this->show_message($this->phrase['version']['502rc1']['importing_missing_albums']);

			$assertor = vB::getDbAssertor();
			$batchSize = 1000;
			$startat = intval($data['startat']);
			$albumTypeid = vB_Types::instance()->getContentTypeID('vBForum_Album');

			/*
			 * 	The batching for this is a bit different.
			 *	It will essentially import $batchSize missing albums at a time
			 *	Until vBInstall:getMissingAlbums does not return any more.
			 *	If it never stops, that probably means something went wrong in the
			 * 	importing &	getMissingAlbums keeps pulling results
			 *
			 *	Update note: VBV-9795, sometimes users can be deleted but their
			 *	albums can persist due to VBIV-10754. To prevent this issue from
			 *	causing the upgrader to run this step forever, only missing albums
			 *	with an existing user record will be fetched, via INNER JOIN
			 */
			$missingAlbums = $assertor->assertQuery('vBInstall:getMissingAlbums',
				array(
					'oldcontenttypeid' => $albumTypeid,
					'batchsize' => $batchSize,
				)
			);

			// if there are no more albums missing, then we are done.
			if (!$missingAlbums->valid())
			{
				$this->show_message(sprintf($this->phrase['core']['process_done']));
				return;
			}

			// otherwise, let's grab the albumid's from the query
			$albumIdList = array();
			foreach ($missingAlbums AS $albumRow)
			{
				$albumIdList[] = $albumRow['albumid'];
			}

			// we need the routeid for the album channel
			$albumChannel = vB_Library::instance('node')->fetchAlbumChannel();
			$album = $assertor->getRow('vBForum:node', array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
				'nodeid' => $albumChannel));
			$route = $assertor->getRow('routenew',
				array(
					'contentid' => $albumChannel,
					'class' => 'vB5_Route_Conversation',
				)
			);

			// import the albums into the node table as galleries.
			$assertor->assertQuery('vBInstall:importMissingAlbumNodes',
				array(
					'oldcontenttypeid' => $albumTypeid,
					'albumIdList' => $albumIdList,
					'gallerytypeid' => vB_Types::instance()->getContentTypeID('vBForum_Gallery'),
					'albumChannel' => $albumChannel,
					'routeid' => $route['routeid']
				)
			);
			// Set starter = nodeid for the galleries.
			$assertor->assertQuery('vBInstall:setStarterForImportedAlbums',
				array(
					'oldcontenttypeid' => $albumTypeid,
					'albumIdList' => $albumIdList
				)
			);

			// import text records
			$assertor->assertQuery('vBInstall:addMissingTextAlbumRecords_502rc1',
				array(
					'oldcontenttypeid' => $albumTypeid,
					'albumIdList' => $albumIdList
				)
			);

			// import albums into gallery table
			$assertor->assertQuery('vBInstall:importMissingAlbums2Gallery',
				array(
					'oldcontenttypeid' => $albumTypeid,
					'albumIdList' => $albumIdList,
				)
			);

			// adding closure records will come in a future step.


			// output current progress
			$this->show_message(sprintf($this->phrase['core']['processed_records_x'], count($albumIdList)));

			// return something so it'll kick off the next batch, even though this batching doesn't use startat
			return array('startat' => 1);
		}
		else
		{
			$this->skip_message();
		}
	}

	/*
	 *	Step 2 - Find and import the missing photos VBV-8952
	 *	This is similar to step_18 of class_upgrade_500a28,
	 * 	and imports the photos that the step missed.
	 *	The closure records that the mentioned step left out
	 *	should be added by step 3
	*/
	public function step_2($data = NULL)
	{
		if ($this->tableExists('album') AND $this->tableExists('attachment')  AND $this->tableExists('filedata'))
		{
			// output what we're doing
			$this->show_message($this->phrase['version']['502rc1']['importing_missing_photos']);

			$assertor = vB::getDbAssertor();
			$batchSize = 1000;
			$startat = intval($data['startat']);
			$photoTypeid = vB_Types::instance()->getContentTypeID('vBForum_Photo');
			$albumTypeid = vB_Types::instance()->getContentTypeID('vBForum_Album');


			/*
			 * 	The batching for this is like in step 1.
			 *
			 *	Update note: VBV-9795, see comment above getMissingAlbums.
			 *	Only missing albums with an existing user record will be
			 * 	fetched, via INNER JOIN
			 */
			$missingPhotos = $assertor->assertQuery('vBInstall:getMissingPhotos',
				array(
					'oldcontenttypeid' => vB_Api_ContentType::OLDTYPE_PHOTO,
					'batchsize' => $batchSize,
					'albumtypeid' => $albumTypeid
				)
			);

			// if there are no more photos missing, then we are done.
			if (!$missingPhotos->valid())
			{
				$this->show_message(sprintf($this->phrase['core']['process_done']));
				return;
			}

			// otherwise, let's grab the attachmentid's from the query
			$attachmentIdList = array();
			foreach ($missingPhotos AS $photoRow)
			{
				$attachmentIdList[] = $photoRow['attachmentid'];
			}

			// import them into the node table.
			// starter = parentid will be set with the query (in reference to 500b28 step_8 / VBV-7108)
			$assertor->assertQuery('vBInstall:importMissingPhotoNodes',
				array(
					'phototypeid' => $photoTypeid,
					'albumtypeid' => $albumTypeid,
					'attachmentIdList' => $attachmentIdList
				)
			);

			// import photos into photo table
			$assertor->assertQuery('vBInstall:importMissingPhotos2Photo',
				array(
					'attachmentIdList' => $attachmentIdList
				)
			);


			// output current progress
			$this->show_message(sprintf($this->phrase['core']['processed_records_x'], count($attachmentIdList)));

			// return something so it'll kick off the next batch, even though this batching doesn't use startat
			return array('startat' => 1);
		}
		else
		{
			$this->skip_message();
		}
	}



	/*
	 * 	Step 3 - Add missing closure records VBV-8952 / VBV-8975
	 * 	This step is inefficient. It walks through the entire node table
	 *	and finds nodes with missing closure records via
	 *	getNoclosureNodes & getOrphanNodes.
	 *	Since it's rare that either query actually returns anything,
	 *	this step will probably do quite a few iterations doing nothing
	 *	until a node with missing closure records is found.
	*/
	public function step_3($data = NULL)
	{
		if ($this->tableExists('node') AND $this->tableExists('closure'))
		{
			$assertor = vB::getDbAssertor();
			$batchSize = 100000;
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


	/** This adds the new candeletechannesl permission for channel owners  */
	public function step_4()
	{
		$this->show_message($this->phrase['version']['502rc1']['adding_owner_candelete_permission']);
		vB::getDbAssertor()->assertQuery('vBInstall:grantOwnerForumPerm', array('permission' => 256, 'systemgroupid' => 9));
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 104027 $
|| #######################################################################
\*=========================================================================*/
