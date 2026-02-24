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

class vB_Upgrade_504a3 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '504a3';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.0.4 Alpha 3';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.0.4 Alpha 2';

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
	 * Step 1	-	500b27 step_8 did not escape the prefix before putting it into
	 *			the regex, so any conversation routes with regex in the urlIdent
	 *			need to be repaired. Since step_8 is removed now, just re-create 
	 *			the regex for all conversations
	 */
	public function step_1($data = NULL)
	{
		// this step has been moved to 505rc1, because the conversation route's regex has been updated in 5.0.5
		$this->skip_message();	
	}
	
	/**
	 * Step 2	-	Since we used to allow [ and ] in the urlIdent, we have to modify
	 *			the regex for conversation routes that affect any topics with [ and ] in the title
	 *			so that they can be routed.
	 */
	public function step_2($data = NULL)
	{	
		// this step has been moved to 505rc1, because the conversation route's regex has been updated in 5.0.5
		$this->skip_message();	
	}

}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
