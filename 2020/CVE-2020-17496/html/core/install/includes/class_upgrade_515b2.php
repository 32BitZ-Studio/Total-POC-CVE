<?php
/*======================================================================*\
|| #################################################################### ||
|| # vBulletin 5.6.0
|| # ---------------------------------------------------------------- # ||
|| # Copyright ©2000-2020 MH Sub I, LLC dba vBulletin. All Rights Reserved. ||
|| # This file may not be redistributed in whole or significant part. # ||
|| # ---------------- VBULLETIN IS NOT FREE SOFTWARE ---------------- # ||
|| # http://www.vbulletin.com | http://www.vbulletin.com/license.html # ||
|| #################################################################### ||
\*======================================================================*/
/*
if (!isset($GLOBALS['vbulletin']->db))
{
	exit;
}
*/

class vB_Upgrade_515b2 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '515b2';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.1.5 Beta 2';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.1.5 Beta 1';

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
	 * VBV-14079 and VBV-14084 - clean attachment settings and filenames
	 */
	public function step_1($data = null)
	{
		vB_Upgrade::createAdminSession();

		$startat = (int) isset($data['startat']) ? $data['startat'] : 0;
		$batchsize = 100;

		$assertor = vB::getDbAssertor();

		if ($startat == 0)
		{
			$this->show_message($this->phrase['version']['515b2']['cleaning_attachment_filenames_and_settings']);
		}

		// For each attachment, we need to:
		// 1. html escape the attachment filename, if not already escaped (VBV-14084)
		// 2. pull data from settings without using unserialize, then re-serialize it
		//    to mitigate the PHP unserialize object injection vulnerability (VBV-14079)
		// 3. check that the author has 'canattachmentcss' for in this channel, and
		//    if not, blank out the settings[styles] value that they don't have
		//    permission to set. This mitigates the XSS vulnerability. (VBV-14079)

		// get attach records
		$rows = $assertor->getRows('vBInstall:getAttachmentsWithParentAndAuthor', array(
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
				if ($row['filename'] === vB_String::unHtmlSpecialChars($row['filename']))
				{
					// unescaping didn't change anything, so this filename may need to be escaped
					$escaped = vB_String::htmlSpecialCharsUni($row['filename']);
					if ($escaped !== $row['filename'])
					{
						// there was a change, need to save it
						$updates['filename'] = $escaped;
					}
				}

				if (!empty($row['settings']))
				{
					// ensure that settings contains only valid serialized
					// data we are expecting. parseAttachSettings will fail
					// if there is anything unexpected such as a serialized
					// object.
					$settings = $this->parseAttachSettings($row['settings']);

					if (empty($settings))
					{
						// insert the defaults
						$settings = array(
							'alignment'   => 'none',
							'size'        => 'full',
							'title'       => '',
							'description' => '',
							'styles'      => '',
							'link'        => 0,
							'linkurl'     => '',
							'linktarget'  => 0,
						);
					}

					// remove settings['styles'] if the user doesn't have
					// 'canattachmentcss' (VBV-14079)
					$usercontext = vB::getUserContext($row['userid']);
					if (!$usercontext OR !$usercontext->getChannelPermission('forumpermissions', 'canattachmentcss', $row['nodeid']))
					{
						// user doesn't have the permission for this node
						$settings['styles'] = '';
					}

					$settings = serialize($settings);

					if ($settings !== $row['settings'])
					{
						$updates['settings'] = $settings;
					}
				}

				if (!empty($updates))
				{
					// save any changes....
					$assertor->update('vBForum:attach', $updates, array('nodeid' => $row['nodeid']));
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

	/**
	 * Internal function used by step_1 to safely parse serialized data
	 * without the risk of trying to instantiate serialized objects, etc.
	 * This is *not* a full unserialize function, it *only* handles the
	 * data that we expect to be in the settings field, in the format that
	 * we expect, namely an array of specific strings.
	 *
	 * @param  string Serialized array of settings
	 * @return array  The unserialized array of settings, checked against
	 *                a whitelist, OR an empty array of any unexpected
	 *                data was found
	 */
	protected function parseAttachSettings($settings)
	{
		// expect an array
		if (!preg_match('#^a:(\d+):{(.+)}$#', $settings, $matches))
		{
			return array();
		}

		$count = $matches[1];
		$elementString = $matches[2];
		$elements = array();

		$whitelist = array(
			'alignment',
			'size',
			'title',
			'description',
			'styles',
			'link',
			'linkurl',
			'linktarget',
		);

		// each array element should have a string key and a string or int value
		for ($i = 0; $i < $count; ++$i)
		{
			// get key length
			if (!preg_match('#^s:(\d+):#', $elementString, $matches))
			{
				return array();
			}
			$keyLen = $matches[1];
			$matchLen = strlen($matches[0]);
			$elementString = substr($elementString, $matchLen);
			$key = (string) substr($elementString, 1, $keyLen); // 1 to advance past the opening quote (")
			$elementString = substr($elementString, $keyLen + 3); // +3 to account for the quotes ("") and ending (;)

			// get value
			if (!preg_match('#^(s|i):#', $elementString, $matches))
			{
				return array();
			}
			$type = $matches[1];
			if ($type == 's')
			{
				if (!preg_match('#^s:(\d+):#', $elementString, $matches))
				{
					return array();
				}
				$valueLen = $matches[1];
				$matchLen = strlen($matches[0]);
				$elementString = substr($elementString, $matchLen);
				$value = (string) substr($elementString, 1, $valueLen); // 1 to advance past the opening quote (")
				$elementString = substr($elementString, $valueLen + 3); // +3 to account for the quotes ("") and ending (;)
			}
			else // 'i'
			{
				if (!preg_match('#^i:(\d+);#', $elementString, $matches))
				{
					return array();
				}
				$value = (int) $matches[1];
				$matchLen = strlen($matches[0]);
				$elementString = substr($elementString, $matchLen);
			}

			if (in_array($key, $whitelist, true))
			{
				if ($key === 'alignment')
				{
					$value = in_array($value, array('none', 'left', 'center', 'right'), true) ? $value : 'none';
				}
				else if ($key === 'size')
				{
					$value = vB_Api::instanceInternal('Filedata')->sanitizeFiletype($value);
				}

				$elements[$key] = $value;
			}

		}

		return $elements;
	}
}

/*======================================================================*\
|| ####################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 101013 $
|| ####################################################################
\*======================================================================*/
