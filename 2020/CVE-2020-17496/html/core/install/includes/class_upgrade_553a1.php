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

class vB_Upgrade_553a1 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '553a1';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.5.3 Alpha 1';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.5.2';

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
		$db = vB::getDbAssertor();

		$datastore = vB::getDatastore();
		$permissions = $datastore->getValue('bf_ugp_forumpermissions2');
		$topicperm = $permissions['skipmoderatetopics'];
		$replyperm = $permissions['skipmoderatereplies'];
		$attachperm = $permissions['skipmoderateattach'];

		//we're going to remove this field so check for reentrance.
		if ($this->field_exists('permission', 'skip_moderate'))
		{
			$this->show_message(sprintf($this->phrase['vbphrase']['update_table'], TABLE_PREFIX . 'permission'));

			//set the new perm bit fields to match the skip_moderate field
			$db->update('vBForum:permission',
				array(
					vB_dB_Query::BITFIELDS_KEY => array (
						array('field' => 'forumpermissions2', 'operator' => vB_dB_Query::BITFIELDS_SET, 'value' => $topicperm),
						array('field' => 'forumpermissions2', 'operator' => vB_dB_Query::BITFIELDS_SET, 'value' => $replyperm),
						array('field' => 'forumpermissions2', 'operator' => vB_dB_Query::BITFIELDS_SET, 'value' => $attachperm),
					)
				),
				array('skip_moderate' => 1)
			);

			//set the new perm bit fields to match the skip_moderate field
			$db->update('vBForum:permission',
				array(
					vB_dB_Query::BITFIELDS_KEY => array (
						array('field' => 'forumpermissions2', 'operator' => vB_dB_Query::BITFIELDS_UNSET, 'value' => $topicperm),
						array('field' => 'forumpermissions2', 'operator' => vB_dB_Query::BITFIELDS_UNSET, 'value' => $replyperm),
						array('field' => 'forumpermissions2', 'operator' => vB_dB_Query::BITFIELDS_UNSET, 'value' => $attachperm),
					)
				),
				array('skip_moderate' => 0)
			);
		}
		else
		{
			$this->skip_message();
		}
	}

	public function step_2()
	{
		$this->drop_field(
			sprintf($this->phrase['core']['altering_x_table'], 'permission', 1, 1),
			"permission",
			"skip_moderate"
		);
	}
}

/*======================================================================*\
|| ####################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 101621 $
|| ####################################################################
\*======================================================================*/
