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

class vB_Xml_Import_ScreenLayout extends vB_Xml_Import
{
	protected function import()
	{
		if (empty($this->parsedXML['page']))
		{
			$this->parsedXML['page'] = array();
		}

		// get all columns but the key
		$screenLayoutTable = $this->db->fetchTableStructure('screenlayout');
		$screenLayoutTableColumns = array_diff($screenLayoutTable['structure'], array($screenLayoutTable['key']));

		//$phraseLib = vB_Library::instance('phrase');

		$screenLayouts = $this->parsedXML['screenlayout'];
		foreach ($screenLayouts AS $screenLayout)
		{
			// prepare the sectiondata for saving
			if (!empty($screenLayout['sectiondata']))
			{
				// normalize rows, depending on if there is one or more
				$rows = is_array($screenLayout['sectiondata']['row'][0]) ? $screenLayout['sectiondata']['row'] : array($screenLayout['sectiondata']['row']);

				$sectionData = array();
				foreach ($rows AS $row)
				{
					// normalize sections/columns, depending on if there is one or more
					$sections = is_array($row['column'][0]) ? $row['column'] : array($row['column']);

					$sectionData[] = $sections;
				}

				$screenLayout['sectiondata'] = json_encode($sectionData);
			}
			else
			{
				$screenLayout['sectiondata'] = '';
			}

			// insert the screenlayout record
			$screenLayoutId = 0;
			$existing = $this->db->getRow('screenlayout', array('guid' => $screenLayout['guid']));

			if ($existing)
			{
				if ($this->options & self::OPTION_OVERWRITE)
				{
					// overwrite
					$guid = $screenLayout['guid'];
					unset($screenLayout['guid']);
					$this->db->update('screenlayout', $screenLayout, array('guid' => $guid));
				}

				$screenLayoutId = $existing['screenlayoutid'];
			}
			else
			{
				// insert new
				$screenLayoutId = $this->db->insert('screenlayout', $screenLayout);

				if (is_array($screenLayoutId))
				{
					$screenLayoutId = array_pop($screenLayoutId);
				}
			}
		}
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
