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

// ######################## SET PHP ENVIRONMENT ###########################
error_reporting(E_ALL & ~E_NOTICE);
chdir('./../');

// ##################### DEFINE IMPORTANT CONSTANTS #######################
define('VB_AREA', 'Install');
define('TIMENOW', time());
if (!defined('VB_ENTRY'))
{
	define('VB_ENTRY', 1);
}

header('Expires: ' . gmdate("D, d M Y H:i:s", TIMENOW) . ' GMT');
header("Last-Modified: " . gmdate("D, d M Y H:i:s", TIMENOW) . ' GMT');

$frontendConfigPath = dirname(__FILE__) . '/../../config.php';
$backendConfigPath = dirname(__FILE__) . '/../includes/config.php';
$makeConfigPath = dirname(__FILE__) . '/makeconfig.php';
// Only if we don't have one of the files
if (file_exists($makeConfigPath) AND (!file_exists($frontendConfigPath) OR !file_exists($backendConfigPath)))
{
	require_once('./install/makeconfig.php');
	exit;
}

// ########################## REQUIRE BACK-END ############################
require_once('./install/includes/class_upgrade.php');

//if we get a DB error from the init class, let's assume that
//its an install with bad connection information.  The installer
//handles bad connections gracefully and will prompt before
//overwriting if the DB magically comes back up.
try
{
	require_once('./install/init.php');
}
catch(vB_Exception_Database $e)
{
	exec_header_redirect('install.php');
}

require_once(DIR . '/includes/functions.php');
require_once(DIR . '/includes/functions_misc.php');

$db->hide_errors();
$db->query_first("SELECT * FROM " . TABLE_PREFIX . "user LIMIT 1");
if ($db->errno())
{
	exec_header_redirect('install.php');
}
else
{
	exec_header_redirect('upgrade.php');
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
