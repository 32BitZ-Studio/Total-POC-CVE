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

class vB_Upgrade_553a2 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '553a2';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.5.3 Alpha 2';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.5.3 Alpha 1';

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
		$this->drop_table('customprofilepic');
	}

	public function step_2()
	{
		$this->drop_field(
			sprintf($this->phrase['core']['altering_x_table'], TABLE_PREFIX . 'usergroup', 1, 3),
			'usergroup',
			'profilepicmaxwidth'
		);
	}

	public function step_3()
	{
		$this->drop_field(
			sprintf($this->phrase['core']['altering_x_table'], TABLE_PREFIX . 'usergroup', 2, 3),
			'usergroup',
			'profilepicmaxheight'
		);
	}

	public function step_4()
	{
		$this->drop_field(
			sprintf($this->phrase['core']['altering_x_table'], TABLE_PREFIX . 'usergroup', 3, 3),
			'usergroup',
			'profilepicmaxsize'
		);
	}

	public function step_5()
	{
		$db = vB::getDbAssertor();

		$datastore = vB::getDatastore();
		$forumpermissions = $datastore->getValue('bf_ugp_forumpermissions2');
		$topicperm = $forumpermissions['skipmoderatetopics'];
		$replyperm = $forumpermissions['skipmoderatereplies'];
		$attachperm = $forumpermissions['skipmoderateattach'];

		$permissions = $datastore->getValue('bf_ugp_genericoptions');
		$notbannedgroup = $permissions['isnotbannedgroup'];

		$this->show_message(sprintf($this->phrase['vbphrase']['update_table'], TABLE_PREFIX . 'usergroup'));
		//we don't have skip_moderate for the usergroups -- it's only on the forumpermission record.  It
		//does not appear that we are actually doing anything with the formpermission2 record -- changing
		//it on the user group page actually sets it on the root forum -- so let's set some sensisble defaults
		//that should sync the behavior with new installs and call it a day.

		//set the permissions to true if the group is not banned.
		$db->update('usergroup',
			array(
				vB_dB_Query::BITFIELDS_KEY => array (
					array('field' => 'forumpermissions2', 'operator' => vB_dB_Query::BITFIELDS_SET, 'value' => $topicperm),
					array('field' => 'forumpermissions2', 'operator' => vB_dB_Query::BITFIELDS_SET, 'value' => $replyperm),
					array('field' => 'forumpermissions2', 'operator' => vB_dB_Query::BITFIELDS_SET, 'value' => $attachperm),
				)
			),
			array(array('field' => 'genericoptions', 'operator' => vB_dB_Query::OPERATOR_AND, 'value' => $notbannedgroup))
		);

		//set the permissions to false if the group is banned.
		$db->update('usergroup',
			array(
				vB_dB_Query::BITFIELDS_KEY => array (
					array('field' => 'forumpermissions2', 'operator' => vB_dB_Query::BITFIELDS_UNSET, 'value' => $topicperm),
					array('field' => 'forumpermissions2', 'operator' => vB_dB_Query::BITFIELDS_UNSET, 'value' => $replyperm),
					array('field' => 'forumpermissions2', 'operator' => vB_dB_Query::BITFIELDS_UNSET, 'value' => $attachperm),
				)
			),
			array(array('field' => 'genericoptions', 'operator' => vB_dB_Query::OPERATOR_NAND, 'value' => $notbannedgroup))
		);
	}

	// Add covering index to support fcm_cron's fetching fcmessage_offload by receiveafter
	public function step_6()
	{
		$this->add_index(
			sprintf($this->phrase['core']['altering_x_table'], 'fcmessage_offload', 1, 1),
			'fcmessage_offload',
			'removeafter_hash',
			array('removeafter', 'hash')
		);
	}

	public function step_7()
	{
		$this->drop_field(
			sprintf($this->phrase['core']['altering_x_table'], TABLE_PREFIX . 'user', 1, 3),
			'user',
			'profilepicrevision'
		);
	}

	public function step_8()
	{
		$this->drop_field(
			sprintf($this->phrase['core']['altering_x_table'], TABLE_PREFIX . 'user', 2, 3),
			'user',
			'logintype'
		);
	}

	public function step_9()
	{
		$this->drop_field(
			sprintf($this->phrase['core']['altering_x_table'], TABLE_PREFIX . 'user', 3, 3),
			'user',
			'fbaccesstoken'
		);
	}
	/**
	 * Update user.startofweek to 1 (Sunday), if they currently have -1 (an invalid value)
	 */
	public function step_10($data = null)
	{
		return $this->updateFieldValueBatch($data, 'user', 'userid', 'startofweek', -1, 1, 5000);
	}
}

/*======================================================================*\
|| ####################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 101808 $
|| ####################################################################
\*======================================================================*/
