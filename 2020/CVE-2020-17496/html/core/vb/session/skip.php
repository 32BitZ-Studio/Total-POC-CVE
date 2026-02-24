<?php if (!defined('VB_ENTRY')) die('Access denied.');
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

/**
 * This class replaces the use of SKIP_SESSIONCREATE.
 * All it does is overriding the methods that are not supposed to run when the flag is on
 */
class vB_Session_Skip extends vB_Session
{
	public function __construct(&$dBAssertor, &$datastore, &$config, $styleid = 0, $languageid = 0)
	{
		parent::__construct($dBAssertor, $datastore, $config, '', array(), $styleid, $languageid);
	}

	protected function loadExistingSession($sessionhash, $restoreSessionInfo)
	{
		return false;
	}

	public function save()
	{
		return;
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
