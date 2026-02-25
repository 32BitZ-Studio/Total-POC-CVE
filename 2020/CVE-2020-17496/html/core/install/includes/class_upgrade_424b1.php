<?php
/*======================================================================*\
|| #################################################################### ||
|| # vBulletin 5.6.0
|| # ---------------------------------------------------------------- # ||
|| # Copyright ©2000-2020 MH Sub I, LLC dba vBulletin. All Rights Reserved. ||
|| # This file may not be redistributed in whole or significant part. # ||
|| # ---------------- VBULLETIN IS NOT FREE SOFTWARE ---------------- # ||
|| # http://www.vbulletin.com | http://www.vbulletin.com/license.html # ||
|| #################################################################### ||
\*======================================================================*/

/*
if (!isset($GLOBALS['vbulletin']->db))
{
	exit;
}
*/

class vB_Upgrade_424b1 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '424b1';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '4.2.4 Beta 1';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '4.2.3';

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
	* Check attachment refcounts and fix any that are broken
	*/
	public function step_1()
	{
		$sql = "
			UPDATE " . TABLE_PREFIX . "filedata
			LEFT JOIN (
				SELECT filedataid, COUNT(attachmentid) AS actual
				FROM " . TABLE_PREFIX . "attachment
				GROUP BY filedataid
			) list USING (filedataid) 
			SET refcount = IFNULL(actual, 0)
			WHERE refcount <> IFNULL(actual, 0)
		";

		$res = $this->run_query(sprintf($this->phrase['vbphrase']['update_table_x'], 'filedata', 1, 1), $sql);
	}

	/*

	Step 2 Moved, it is now 5.2.3 Alpha 5, Step 2 

	*/

	/*

	Step 3 Moved, it is now 5.2.3 Alpha 5, Step 3 

	*/

	/*

	Step 4 Moved, it is now 5.2.3 Alpha 5, Step 4 

	*/

	/*

	Step 5 Moved, it is now 5.2.3 Alpha 5, Step 5 

	*/

	/*

	Step 6 Removed, it was an update to the Post Table, unused in vB5 

	*/
}

/*======================================================================*\
|| ####################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 101013 $
|| ####################################################################
\*======================================================================*/
