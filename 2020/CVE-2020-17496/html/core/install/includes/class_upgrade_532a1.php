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

class vB_Upgrade_532a1 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '532a1';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.3.2 Alpha 1';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.3.1';

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
	 * Step 1 Convert Latest Blog Comments and Latest Group Topics modules
	 * to search modules (VBV-16936)
	 */
	public function step_1()
	{
		$assertor = vB::getDbAssertor();

		$guids = array(
			'vbulletin-widget_blogsidebar-4eb423cfd6dea7.34930851',
			'vbulletin-widget_sgsidebar-4eb423cfd6dea7.34930861',
		);
		$oldWidgets = $assertor->getRows('widget', array('guid' => $guids));

		$searchWidget = $assertor->getRow('widget', array('guid' => 'vbulletin-widget_search-4eb423cfd6a5f3.08329785'));

		$updated = false;

		// matches the new adminconfig value used in vbulletin-pagetemplates.xml for the
		// search modules that replace the two old sidebar modules.
		// copying the whole thing here to better avoid typos and make it easier to keep the
		// two in sync, at the expense of a couple of unserialize calls.
		$newAdminConfigs = array(
			'vbulletin-widget_blogsidebar-4eb423cfd6dea7.34930851' => unserialize('a:3:{s:11:"searchTitle";s:20:"Latest Blog Comments";s:14:"resultsPerPage";s:1:"3";s:10:"searchJSON";s:157:"{"date":{"from":"30"},"sort":{"created":"desc"},"exclude_type":["vBForum_PrivateMessage"],"reply_only":"1","channelguid":"vbulletin-4ecbdf567f3a38.99555305"}";}'),
			'vbulletin-widget_sgsidebar-4eb423cfd6dea7.34930861' => unserialize('a:3:{s:11:"searchTitle";s:19:"Latest Group Topics";s:14:"resultsPerPage";s:1:"5";s:10:"searchJSON";s:159:"{"date":{"from":"30"},"sort":{"created":"desc"},"exclude_type":["vBForum_PrivateMessage"],"starter_only":"1","channelguid":"vbulletin-4ecbdf567f3a38.99555306"}";}'),
		);

		foreach ($oldWidgets AS $oldWidget)
		{
			$oldWidgetId = $oldWidget['widgetid'];

			// convert instances of the old widgets to instances of the search widget
			$oldInstances = $assertor->getRows('widgetinstance', array('widgetid' => $oldWidgetId));
			foreach ($oldInstances AS $oldInstance)
			{
				// change widgetid to the search widget
				$values = array('widgetid' => $searchWidget['widgetid']);
				$conditions = array('widgetinstanceid' => $oldInstance['widgetinstanceid']);

				// change searchJSON to the new default
				$adminconfig = array();
				if (!empty($oldInstance['adminconfig']))
				{
					$temp = unserialize($oldInstance['adminconfig']);
					if ($temp)
					{
						$adminconfig = $temp;
					}
				}
				$adminconfig['searchJSON'] = $newAdminConfigs[$oldWidget['guid']]['searchJSON'];
				// add to array for update
				$values['adminconfig'] = serialize($adminconfig);

				// we will leave the other config items alone (module title, perpage setting, etc.)
				// this works out, since the two old modules actually used the same config settings
				// with the same names as the search module does.

				// run the update
				$assertor->update('widgetinstance', $values, $conditions);
			}

			// delete the old widget & widget definition records
			$assertor->delete('widget', array('widgetid' => $oldWidget['widgetid']));
			$assertor->delete('widgetdefinition', array('widgetid' => $oldWidget['widgetid']));

			$updated = true;
		}

		if ($updated)
		{
			$this->show_message($this->phrase['version']['532a1']['converting_blog_and_group_sidebar_modules_to_search_modules']);
		}
		else
		{
			$this->skip_message();
		}
	}
}

/*======================================================================*\
|| ####################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 101013 $
|| ####################################################################
\*======================================================================*/
