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

class vB_Upgrade_517b3 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '517b3';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.1.7 Beta 3';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.1.7 Beta 2';

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
	 * VBV-14663 Clean node.title & photo.caption. Based on 515b2 step_1
	 */
	public function step_1($data = null)
	{
		vB_Upgrade::createAdminSession();

		$startat = (int) isset($data['startat']) ? $data['startat'] : 0;
		$batchsize = 100;

		$assertor = vB::getDbAssertor();

		if ($startat == 0)
		{
			$this->show_message($this->phrase['version']['517b3']['cleaning_photo_captions']);
		}

		// For each photo, we need to html escape the associated node.title & photo.caption, if not already escaped
		// According to vB_Api_Content::cleanInput(), title should be cleaned regardless of user's canusehtml permission,
		// so we'll not bother checking permissions and just clean them.

		// get attach records
		$rows = $assertor->getRows('vBInstall:getPhotos', array(
			'startat' => (int) $startat,
			'batchsize' => (int) $batchsize,
		));

		$rowcount = count($rows);

		if ($rowcount == 0)
		{
			// done
			$this->show_message(sprintf($this->phrase['core']['process_done']));

			return;
		}
		else
		{
			// make changes
			foreach ($rows AS $row)
			{
				// Escape filenames (VBV-14084)
				$updates = array();
				$needsUpdate = false;
				foreach (array('title', 'caption') AS $field)
				{
					/*
						Note, this bit is different from 515b2 step_1() since we update two tables (node & photo) simultaneously.
						I wanted to keep the update method query logic simple, so I'm setting $updates has to be outside of the "if changed" condition
						below. If *either* field requires update, this ensures both title & caption will have a value to be set to even if one doesn't
						strictly require changing. See vBInstall:updatePhotoTitleAndCaption for the query.
					 */
					$escaped = vB_String::htmlSpecialCharsUni($row[$field]);
					$updates[$field] = $escaped;
					if ($row[$field] === vB_String::unHtmlSpecialChars($row[$field]))
					{
						// unescaping didn't change anything, so this filename may need to be escaped
						if ($escaped !== $row[$field])
						{
							// there was a change, need to save it
							$needsUpdate = true;
						}
					}
				}

				if ($needsUpdate)
				{
					$updates['nodeid'] = $row['nodeid'];
					// save any changes....
					$assertor->assertQuery('vBInstall:updatePhotoTitleAndCaption', $updates);
				}
			}

			// output progress
			$from = $startat + 1;
			$to = $from + $rowcount - 1;
			$this->show_message(sprintf($this->phrase['core']['processed_records_x_y'], $from, $to));

			// return for next batch
			return array('startat' => $startat + $batchsize);
		}
	}
}

/*======================================================================*\
|| ####################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 101013 $
|| ####################################################################
\*======================================================================*/