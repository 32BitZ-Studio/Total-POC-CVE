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

class vB_Upgrade_555a3 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '555a3';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.5.5 Alpha 3';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.5.5 Alpha 2';

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
		// noop step just to output the long step message
		// for updating the birthdayemail user option
		$this->long_next_step();
	}

	// Set the user 'birthdayemail' option to 'on' for all existing users. There previously
	// was no option and all users would get the email.
	public function step_2()
	{
		$assertor = vB::getDbAssertor();

		// bitfields are rebuilt as part of the upgrade initialization, so the
		// new bitfield will already be present here (see class_upgrade init())
		$bf_misc_useroptions = vB::getDatastore()->getValue('bf_misc_useroptions');

		$check = $assertor->getRow('vBInstall:checkUserOptionBirthdayEmails', array(
			'birthdayemailmask' => $bf_misc_useroptions['birthdayemail'],
		));

		if (!$check)
		{
			$this->show_message(sprintf($this->phrase['vbphrase']['update_table'], TABLE_PREFIX . 'user'));

			// If setting this bit in one go turns out to be too much, we can use
			// updateByIdWalk(). But we allow this type of query in the Admin CP
			// query tool, so I think it will be okay here. Added the 'long next step'
			// message just to be on the safe side.
			$result = $assertor->assertQuery('vBInstall:updateUserOptionBirthdayEmails', array(
				'birthdayemailmask' => $bf_misc_useroptions['birthdayemail'],
			));
		}
		else
		{
			// There is at least one user with the birthday email option turned on, so
			// we'll assume that this step has already run or that v555a3 or later has
			// already been installed. In either case, we don't want to run this step
			// and risk enabling 'birthdayemail' for users who have already turned it
			// off.
			$this->skip_message();
		}
	}
}

/*======================================================================*\
|| ####################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 102796 $
|| ####################################################################
\*======================================================================*/
