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

class vB_Upgrade_527a3 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '527a3';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.2.7 Alpha 3';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.2.7 Alpha 2';

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
	 * VBV-17001 - if the infractions tab exists in the display tabs setting for widget_profile,
	 * reset the config to default to avoid displaying a blank tab
	 */
	public function step_1()
	{
		$db = vB::getDbAssertor();
		$updated = false;

		$widget = $db->getRow('widget', array('guid' => 'vbulletin-widget_profile-4eb423cfd6d4b0.24011159'));
		$instances = $db->getRows('widgetinstance', array('widgetid' => $widget['widgetid']));

		foreach ($instances AS $instance)
		{
			if (empty($instance['adminconfig']))
			{
				continue;
			}

			$adminconfig = unserialize($instance['adminconfig']);
			if (!$adminconfig)
			{
				continue;
			}

			if (!empty($adminconfig['display_tabs']) AND is_array($adminconfig['display_tabs']))
			{
				$foundBadTab = false;
				foreach ($adminconfig['display_tabs'] AS $tab)
				{
					if ($tab == '#infractions-tab')
					{
						$foundBadTab = true;
						break;
					}
				}

				if ($foundBadTab)
				{
					// reset tabs to default value
					$adminconfig['display_tabs'] = '';
					$adminconfig['tab_order'] = '';
					$adminconfig['default_tab'] = '';

					// update
					$condition = array('widgetinstanceid' => $instance['widgetinstanceid']);
					$values = array('adminconfig' => serialize($adminconfig));
					$db->update('widgetinstance', $values, $condition);

					$updated = true;
				}
			}
		}

		if ($updated)
		{
			$this->show_message($this->phrase['version']['527a3']['updating_profile_module_tab_config']);
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