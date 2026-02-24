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

class vB_Upgrade_527a1 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '527a1';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.2.7 Alpha 1';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.2.6';

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

	public function step_1()
	{
		$this->show_message($this->phrase['version']['526a7']['updating_recentblogposts_widget']);

		$assertor = vB::getDbAssertor();
		// Some search & sgsidebar widgets have the content types specified, which makes it troublesome when
		// we add new contenttypes.
		$widgetguid = "vbulletin-widget_search-4eb423cfd6a5f3.08329785";
		$widgetRow = $assertor->getRow('widget', array('guid' => $widgetguid));
		$widgetID = $widgetRow['widgetid'];
		$pagetemplateguid = "vbulletin-4ecbdac9370e30.09770013";
		$pagetemplateRow = $assertor->getRow('pagetemplate', array('guid' => $pagetemplateguid));
		$pagetemplateID = $pagetemplateRow['pagetemplateid'];

		$updated = array();
		$widgetinstanceRows = $assertor->getRows('widgetinstance', array('widgetid' => $widgetID, 'pagetemplateid' => $pagetemplateID));
		foreach($widgetinstanceRows AS $__row)
		{
			$__widgetinstanceid = $__row['widgetinstanceid'];
			$__adminconfig = unserialize($__row['adminconfig']);

			if (!empty($__adminconfig['searchTitle']) AND "Recent Blog Posts" == $__adminconfig['searchTitle'] AND !empty($__adminconfig['searchJSON']))
			{
				$__searchJSON = json_decode($__adminconfig['searchJSON'], 1);

				/*
					The old serialized searchJSON was:
						s:10:"searchJSON";s:125:"{"date":{"from":"30"},"channel":["5"],"sort":{"created":"desc"},"exclude_type":["vBForum_PrivateMessage"],"starter_only":"1"}";
					with channel = array("5");

				 */
				if (!empty($__searchJSON['channel']) AND is_array($__searchJSON['channel']) AND reset($__searchJSON['channel']) == 5)
				{
					unset($__searchJSON['channel']);
					$__searchJSON['channelguid'] = "vbulletin-4ecbdf567f3a38.99555305"; // Blogs channel GUID taken from the channels XML
					$__adminconfig['searchJSON'] = json_encode($__searchJSON);
					$__serialized = serialize($__adminconfig);
					if (!empty($__serialized))
					{
						$try = $assertor->update(
							'widgetinstance',
							array('adminconfig' => $__serialized),
							array('widgetinstanceid' => $__widgetinstanceid)
						);
						$updated[] = $__widgetinstanceid;
					}
				}
			}
		}

		$this->show_message(sprintf($this->phrase['core']['processed_records_x'], count($updated)));
	}
}

/*======================================================================*\
|| ####################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 101013 $
|| ####################################################################
\*======================================================================*/