<?php
/*======================================================================*\
|| #################################################################### ||
|| # vBulletin 5.6.0
|| # ---------------------------------------------------------------- # ||
|| # Copyright ©2000-2020 MH Sub I, LLC dba vBulletin. All Rights Reserved. ||
|| # This file may not be redistributed in whole or significant part. # ||
|| # ---------------- VBULLETIN IS NOT FREE SOFTWARE ---------------- # ||
|| #        www.vbulletin.com | www.vbulletin.com/license.html        # ||
|| #################################################################### ||
\*======================================================================*/

class vB_Upgrade_424rc3 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '424rc3';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '4.2.4 Release Candidate 3';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '4.2.4 Release Candidate 2';

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

	/*
	Update Read Marking Option
	This sets everyone to use DB marking as we removed the option in 4.2.5.
	I believe vB5 still has this option so left this in so upgraded sites will continue to 
	use the option consistantly (vB5 really should remove the cookie based system as well).
	*/
	public function step_1()
	{
		$this->run_query(
			$this->phrase['version']['424rc3']['update_marking'],
			"UPDATE ".TABLE_PREFIX."setting SET value = '2' WHERE varname = 'threadmarking'"
		);
	}
}

/*======================================================================*\
|| ####################################################################
|| # NulleD By - vBSupport.org : $Revision: 101013 $
|| # $Date: 2019-03-15 10:31:08 -0700 (Fri, 15 Mar 2019) $
|| ####################################################################
\*======================================================================*/
