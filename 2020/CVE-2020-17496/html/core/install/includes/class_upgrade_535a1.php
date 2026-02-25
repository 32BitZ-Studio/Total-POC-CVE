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

class vB_Upgrade_535a1 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '535a1';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.3.5 Alpha 1';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.3.4';

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
		$code = vB::getDatastore()->getOption('ga_code');
		if ($code AND !preg_match('#^\s*<script#', $code))
		{
			$code = '<script type="text/javascript">' . "\n$code\n" . '</script>';
			vB_Library::instance('options')->updateValue('ga_code', $code);
		}
		$this->show_message($this->phrase['version']['535a1']['update_google_analytics']);
	}

	/**
	 * Removing Search Queue Processor Scheduled Tasks
	 */
	public function step_2()
	{
		//it turns out this got a different varname if it was added by the upgrader than if it was
		//added by the installer.  We got one a long time ago, we need to get the other one now.
		$this->show_message(sprintf($this->phrase['version']['503a3']['delete_queue_processor_cron']));
		vB::getDbAssertor()->delete('cron', array(
			'varname' => 'queueprocessor',
			'volatile' => 1,
			'product' => 'vbulletin',
		));
	}

	public function step_3($data)
	{
		$callback =	function($startat, $nextid)
		{
			$this->show_message(sprintf($this->phrase['core']['update_table_x_ids_y_z'], TABLE_PREFIX . 'user', $startat, $nextid), true);
			$db = vB::getDbAssertor();
			$db->update(
				'user',
				array('maxposts' => -1),
				array(
					'maxposts' => 0,
					array('field' => 'userid', 'value' => $startat, 'operator' =>  vB_dB_Query::OPERATOR_GTE),
					array('field' => 'userid', 'value' => $nextid, 'operator' =>  vB_dB_Query::OPERATOR_LT),
				)
			);
		};

		return $this->updateByIdWalk($data,	20000, 'vBInstall:getMaxUserid', 'user', 'userid', $callback);
	}
}

/*======================================================================*\
|| ####################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 101013 $
|| ####################################################################
\*======================================================================*/
