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

class vB_Upgrade_535a3 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '535a3';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.3.5 Alpha 3';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.3.5 Alpha 2';

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
		$this->drop_table('block');
	}

	public function step_2()
	{
		$this->drop_table('blockconfig');
	}

	public function step_3()
	{
		$this->drop_table('blocktype');
	}

	public function step_4()
	{
		$this->drop_table('blog_userread');
	}

	public function step_5()
	{
		$this->drop_table('action');
	}

	public function step_6()
	{
		$this->drop_table('dbquery');
	}

	public function step_7()
	{
		$this->drop_table('contentread');
	}

	public function step_8()
	{
		$this->drop_table('apipost');
	}

	public function step_9()
	{
		$hvtype = vB::getDatastore()->getOption('hv_type');
		if($hvtype == 'Recaptcha')
		{
			vB_Upgrade::createAdminSession();
			$this->show_message($this->phrase['version']['535a3']['update_recaptcha1']);
			$this->set_option('hv_type', '', 'Image');

			$this->add_adminmessage(
				'recapcha_removal_warning',
				array(
					'dismissable' => 1,
					'script'      => 'verify.php',
					'action'      => '',
					'execurl'     => 'verify.php',
					'method'      => 'get',
					'status'      => 'undone',
				),
				false
			);
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
