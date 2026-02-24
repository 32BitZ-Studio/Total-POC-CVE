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

class vB_Upgrade_513b1 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '513b1';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.1.3 Beta 1';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.1.3 Alpha 6';

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
	 * 	Reset publicview for filedata records that shouldn't be public
	 */
	public function step_1()
	{
		$this->show_message($this->phrase['version']['513b1']['fix_publicview_attach']);
		/*
		 *	Tried on a test DB that had 4k filedata & attach record pairs and the update didn't
		 *	more than a couple seconds at most, so I didn't batch this.
		 *	I did not add the queries to the vbinstall package to make it simpler for support to
		 *	upload this as a single script.
		 */
		$assertor = vB::getDbAssertor();
		$logos = $assertor->assertQuery('stylevar', array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT, 'stylevarid' => 'titleimage'));
		$logoFiledataids = array();
		foreach ($logos AS $logo)
		{
			$value = unserialize($logo['value']);
			if (!empty($value['url']) )
			{
				if (preg_match('#^filedata/fetch\?filedataid=(?P<filedataid>[0-9]+)$#i', $value['url'], $matches))
				{
					$filedataid = (int)$matches['filedataid'];
					$logoFiledataids[$filedataid] = $filedataid;
				}
			}
		}

		if (!empty($logoFiledataids))
		{
			$assertor->assertQuery('vBInstall:fixAttachPublicviewSkipFiledataids',
				array(
					'skipfiledataids' => $logoFiledataids
				)
			);
		}
		else
		{
			$assertor->assertQuery('vBInstall:fixAttachPublicview');
		}
	}

	/**
	 * 	Reset publicview for filedata records that have 0 refcount, in case any
	 *	attachments were removed and filedata record was missed by step_1
	 */
	public function step_2()
	{
		$this->show_message($this->phrase['version']['513b1']['fix_publicview_unref']);
		$assertor = vB::getDbAssertor();
		$assertor->assertQuery('vBInstall:fixUnreferencedFiledataPublicview');

		$this->long_next_step();
	}

	/**
	 * Fix any attachments that are stored incorrectly in the fs. VBV-13339
	 */
	public function step_3()
	{
		$vboptions = vB::getDatastore()->getValue('options');

		if ($vboptions['attachfile'] == vB_Library_Filedata::ATTACH_AS_FILES_NEW AND file_exists($vboptions['attachpath']))
		{
			$this->show_message($this->phrase['version']['513b1']['move_attachment_files']);

			$filedataLib = vB_Library::instance('filedata');
			$count = 0;

			foreach (new DirectoryIterator($vboptions['attachpath']) AS $fileinfo)
			{
				if (!$fileinfo->isDir())
				{
					continue;
				}

				$filename = $fileinfo->getFilename();

				if (!preg_match('/^[0-9][0-9]+$/', $filename))
				{
					continue;
				}

				// If we reach this point, these attachments are stored as
				// ATTACH_AS_FILES_OLD instead of ATTACH_AS_FILES_NEW.
				// The directory name is the userid
				$newpath = $filedataLib->fetchAttachmentPath($filename, vB_Library_Filedata::ATTACH_AS_FILES_NEW);

				// Move attachments to new location
				foreach (new DirectoryIterator($fileinfo->getPathname()) AS $fileinfo2)
				{
					if (!$fileinfo2->isFile())
					{
						continue;
					}

					if (preg_match('/^([0-9]+)\.?(attach|icon|thumb|small|medium|large)$/', $fileinfo2->getFilename(), $matches))
					{
						// 1 - filedataid
						// 2 - extension/type

						$currentFile = $fileinfo2->getPathname();
						$targetFile = $newpath . '/' . $matches[1] . '.' . $matches[2];

						// If target is an existing file with different filesize, don't attempt the rename
						if (!file_exists($targetFile) OR filesize($targetFile) == filesize($currentFile))
						{
							rename($currentFile, $targetFile);
							++$count;
						}
					}
				}

				// attempt to remove the directory, if empty
				@rmdir($fileinfo->getPathname());
			}

			if ($count > 0)
			{
				$this->show_message(sprintf($this->phrase['version']['513b1']['x_attachment_files_moved'], $count));
			}
			else
			{
				$this->show_message($this->phrase['version']['513b1']['no_attachment_files_to_move']);
			}
		}
		else
		{
			$this->skip_message();
		}

		$this->long_next_step();
	}

	/**
	 * Insert a preview image where missing (VBV-11329)
	 */
	public function step_4($data = null)
	{
		$startat = (int) isset($data['startat']) ? $data['startat'] : 0;
		$batchsize = 100;

		$assertor = vB::getDbAssertor();
		vB_Upgrade::createAdminSession();

		if ($startat == 0)
		{
			$this->show_message(sprintf($this->phrase['version']['510a5']['updating_article_preview_images']));
		}

		$attachContentTypeId =  vB_Types::instance()->getContentTypeID('vBForum_Attach');
		$articlesRootChannelId = vB_Api::instanceInternal('Content_Channel')->fetchChannelIdByGUID(vB_Channel::DEFAULT_ARTICLE_PARENT);

		// Get nodeids
		$rows = $assertor->assertQuery('vBInstall:getNodesWithMissingPreviewImage', array(
			'root_article_channel' => $articlesRootChannelId,
			'attach_contenttypeid' => $attachContentTypeId,
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
				vB_Api::instanceInternal('Content_Text')->autoPopulatePreviewImage($nodeid);
			}

			$firstNodeId = min($nodeids);
			$lastNodeId = max($nodeids);

			// output progress
			$this->show_message(sprintf($this->phrase['core']['processed_records_x_y'], $firstNodeId, $lastNodeId));

			// return for next batch
			return array('startat' => $lastNodeId);
		}
	}

}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
