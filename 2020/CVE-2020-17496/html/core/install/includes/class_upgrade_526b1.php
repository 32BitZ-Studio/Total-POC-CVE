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

class vB_Upgrade_526b1 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '526b1';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.2.6 Beta 1';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.2.6 Alpha 6';

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
		$this->show_message($this->phrase['version']['526a6']['updating_searchwidgets']);

		$assertor = vB::getDbAssertor();
		// Some search & sgsidebar widgets have the content types specified, which makes it troublesome when
		// we add new contenttypes.
		$guids = array("vbulletin-widget_search-4eb423cfd6a5f3.08329785",
			"vbulletin-widget_sgsidebar-4eb423cfd6dea7.34930861"
		);
		$widgetRows = $assertor->getRows('widget', array('guid' => $guids));
		$widgetIDs = array();
		foreach($widgetRows AS $__row)
		{
			$widgetIDs[] = $__row['widgetid'];
		}


		$types = array(
			array("vBForum_Gallery","vBForum_Link","vBForum_Photo","vBForum_Poll","vBForum_Text","vBForum_Video"),
			array("vBForum_Text","vBForum_Poll","vBForum_Gallery","vBForum_Video","vBForum_Link"),
		);
		$updated = array();
		$widgetinstanceRows = $assertor->getRows('widgetinstance', array('widgetid' => $widgetIDs));
		foreach($widgetinstanceRows AS $__row)
		{
			$__widgetinstanceid = $__row['widgetinstanceid'];
			$__adminconfig = unserialize($__row['adminconfig']);

			if (isset($__adminconfig['searchJSON']))
			{
				// Sometimes searchJSON can apparently be saved as an array instead of a json_encoded string
				if (!is_array($__adminconfig['searchJSON']))
				{
					$__searchJSON = json_decode($__adminconfig['searchJSON'], 1);
				}
				if (!empty($__searchJSON['type']))
				{
					foreach($types AS $__types)
					{
						if (
							$__searchJSON['type'] == $__types OR
							empty(array_diff($__searchJSON['type'], $__types)) AND empty(array_diff($__types, $__searchJSON['type']))
						)
						{
							unset($__searchJSON['type']);
							$__adminconfig['searchJSON'] = json_encode($__searchJSON);
							$__serialized = serialize($__adminconfig);
							if (!empty($__serialized))
							{
								$try = $assertor->update(
									'widgetinstance',
									array('adminconfig' => $__serialized),
									array('widgetinstanceid' => $__widgetinstanceid)
								);
								$updated[] =  $__widgetinstanceid;
							}
							break;
						}
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