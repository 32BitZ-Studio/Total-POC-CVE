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

class vB_Upgrade_522a5 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '522a5';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.2.2 Alpha 5';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.2.2 Alpha 4';

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
	 * VBV-15926 - Unserialize the show_at_breakpoints module config item
	 */
	public function step_1()
	{
		$db = vB::getDbAssertor();
		$updated = false;

		$instances = $db->select('widgetinstance', array(), false,  array('widgetinstanceid', 'adminconfig'));

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

			if (isset($adminconfig['show_at_breakpoints']))
			{
				$unserialized = @unserialize($adminconfig['show_at_breakpoints']);
				if ($unserialized)
				{
					$adminconfig['show_at_breakpoints'] = $unserialized;

					$condition = array('widgetinstanceid' => $instance['widgetinstanceid']);
					$values = array('adminconfig' => serialize($adminconfig));
					$db->update('widgetinstance', $values, $condition);

					$updated = true;
				}
			}
		}

		if ($updated)
		{
			$this->show_message($this->phrase['version']['522a5']['update_module_setting_show_at_breakpoints']);
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
