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

global $vbphrase, $phrasegroups, $vbulletin, $specialtemplates;

// identify where we are
define('VB_AREA', 'AdminCP');
if(!defined('VB_ENTRY'))
{
	define('VB_ENTRY', 1);
}
define('IN_CONTROL_PANEL', true);

if (!isset($phrasegroups) OR !is_array($phrasegroups))
{
	$phrasegroups = array('global');
}
if (!in_array('global', $phrasegroups))
{
	$phrasegroups[] = 'global';
}
$phrasegroups[] = 'cpglobal';

if (!isset($specialtemplates) OR !is_array($specialtemplates))
{
	$specialtemplates = array('mailqueue');
}

// ###################### Start functions #######################

//this is only needed if we are going directly to site/core/admincp/...
//which is deprecated.  If we use the front end relay (site/admincp/...)
//then CWD will already be set
if (!defined('CWD'))
{
	chdir('./../');
	$cwd = getcwd();

	if(is_link($cwd))
	{
		$cwd = dirname(dirname($_SERVER["SCRIPT_FILENAME"]));
	}
	else if (empty($cwd))
	{
		$cwd = '.';
	}

	define('CWD', $cwd);
}

if (!defined('VB_API'))
{
	define('VB_API', false);
}



require_once(CWD . '/includes/init.php');
require_once(DIR . '/includes/adminfunctions.php');

set_exception_handler(function($e)
{
	try
	{
		$errors = array();
		if($e instanceof vB_Exception_Api)
		{
			$errors = $e->get_errors();
			$config = vB::getConfig();
			if (!empty($config['Misc']['debug']))
			{
				$trace = '## ' . $e->getFile() . '(' . $e->getLine() . ") Exception Thrown \n" . $e->getTraceAsString();
				$errors[] = array("exception_trace", $trace);
			}
			print_stop_message_array($errors);
		}

		else if ($e instanceof vB_Exception_Database)
		{
			$config = vB::getConfig();
			if (!empty($config['Misc']['debug']) OR vB::getUserContext()->hasAdminPermission('cancontrolpanel'))
			{
				$errors = array('Error ' . $e->getMessage());
				$trace = '## ' . $e->getFile() . '(' . $e->getLine() . ") Exception Thrown \n" . $e->getTraceAsString();
				$errors[] = array("exception_trace", $trace);
				print_stop_message_array($errors);
			}
			else
			{
				// This text is purposely hard-coded since we don't have
				// access to the database to get a phrase
				print_cp_message('There has been a database error, and the current page cannot be displayed. Site staff have been notified.');
			}
		}
		else
		{
			$errors = array(array('unexpected_error', $e->getMessage()));
			$config = vB::getConfig();
			if (!empty($config['Misc']['debug']))
			{
				$trace = '## ' . $e->getFile() . '(' . $e->getLine() . ") Exception Thrown \n" . $e->getTraceAsString();
				$errors[] = array("exception_trace", $trace);
			}
			print_stop_message_array($errors);
		}
	}
	//if the above throws and exception we're cooked -- just do what we can
	catch (Error $e2)
	{
		print_cp_message('Got error "' . $e2->getMessage() . '" while trying to process error "' . $e->getMessage() . '"');
	}
	//if the above throws and exception we're cooked -- just do what we can
	catch (Exception $e2)
	{
		print_cp_message('Got error "' . $e2->getMessage() . '" while trying to process error "' . $e->getMessage() . '"');
	}
});

$config = vB::getConfig();
if (!empty($config['Security']['AdminIP']))
{
	$cpips = $config['Security']['AdminIP'];
	if (!is_array($cpips))
	{
		$cpips = explode(',', $cpips);
	}

	$ip = vB::getRequest()->getIpAddress();
	if (!vB_Ip::ipInArray($ip, $cpips))
	{
		print_stop_message2('no_permission');
	}
}

//we no longer double load the session which means that the previous session was
//loaded before we got to the admincp code.  So we fix some things.
//We really need to better control the loading of user information to avoid
//having to do this, but that requires considerable cleanup in the the
//admincp.
$session = vB::getCurrentSession();

$session->clearUserInfo();
$vbulletin->userinfo = &$session->fetch_userinfo();

vB_Language::preloadPhraseGroups($phrasegroups);
//Force load of the user information
$session->loadPhraseGroups();

$vb5_config =& vB::getConfig();
$assertor = vB::getDbAssertor();

// ###################### Start headers (send no-cache) #######################
exec_nocache_headers();

# cache full permissions so scheduled tasks will have access to them
$permissions = cache_permissions($vbulletin->userinfo);
$vbulletin->userinfo['permissions'] =& $permissions;

if (
		// this checks for superadmins, basic admin control and administrator table
		// administrator table has adminpermissions = 0 ?!?
		!vB::getUserContext()->hasAdminPermission('cancontrolpanel') AND
		// this checks for datastore
		!vB::getUserContext()->hasPermission('adminpermissions', 'cancontrolpanel')
	)
{
	$checkpwd = 1;
}

// ###################### Get date / time info #######################
// override date/time settings if specified
fetch_options_overrides($vbulletin->userinfo);
fetch_time_data();

// ############################################ LANGUAGE STUFF ####################################
// initialize $vbphrase and set language constants
$vbphrase = init_language();
if ($stylestuff = $assertor->getRow('vBForum:style', array('styleid' => $vbulletin->options['styleid']), array()))
{
	fetch_stylevars($stylestuff, $vbulletin->userinfo);
}
else
{
	$_tmp = NULL;
	fetch_stylevars($_tmp, $vbulletin->userinfo);
}

// ############################################ Check for files existance ####################################
if (empty($vb5_config['Misc']['debug']) and !defined('BYPASS_FILE_CHECK'))
{
	// check for files existance. Potential security risks!
	$continue = false;
	if (is_dir(DIR . '/install') == true)
	{
		if ($_SERVER['REQUEST_METHOD'] == 'GET')
		{
			$continue = $vbulletin->scriptpath;
		}
		print_stop_message2(array('security_alert_x_still_exists'));
	}
	else if (file_exists(DIR . '/admincp/tools.php'))
	{
		if ($_SERVER['REQUEST_METHOD'] == 'GET')
		{
			$continue = $vbulletin->scriptpath;
		}
		print_stop_message2(array('security_alert_tools_still_exists_in_x',  'admincp'));
	}
	else if (file_exists(DIR . '/' . $vb5_config['Misc']['modcpdir'] . '/tools.php'))
	{
		if ($_SERVER['REQUEST_METHOD'] == 'GET')
		{
			$continue = $vbulletin->scriptpath;
		}
		print_stop_message2(array('security_alert_tools_still_exists_in_x',  $vb5_config['Misc']['modcpdir']),NULL,array(),NULL, $continue);
	}
}

// ############################################ Start Login Check ####################################
$vbulletin->input->clean_array_gpc('p', array(
	'adminhash' => vB_Cleaner::TYPE_STR,
	'ajax'      => vB_Cleaner::TYPE_BOOL,
));

assert_cp_sessionhash();

if (!CP_SESSIONHASH OR $checkpwd OR ($vbulletin->options['timeoutcontrolpanel'] AND !vB::getCurrentSession()->get('loggedin')))
{
	// #############################################################################
	// Put in some auto-repair ;)
	$check = array();

	$spectemps = $assertor->getRows('datastore', array());
	foreach ($spectemps AS $spectemp)
	{
		$check["$spectemp[title]"] = true;
	}

	if (!$check['maxloggedin'])
	{
		build_datastore('maxloggedin', '', 1);
	}
	if (!$check['smiliecache'])
	{
		build_datastore('smiliecache', '', 1);
		build_image_cache('smilie');
	}
	if (!$check['iconcache'])
	{
		build_datastore('iconcache', '', 1);
		build_image_cache('icon');
	}
	if (!$check['bbcodecache'])
	{
		build_datastore('bbcodecache', '', 1);
		build_bbcode_cache();
	}
	if (!$check['userstats'])
	{
		build_datastore('userstats', '', 1);
		require_once(DIR . '/includes/functions_databuild.php');
		build_user_statistics();
	}
	if (!$check['mailqueue'])
	{
		build_datastore('mailqueue');
	}
	if (!$check['cron'])
	{
		build_datastore('cron');
	}
	if (!$check['attachmentcache'])
	{
		build_datastore('attachmentcache', '', 1);
	}
	if (!$check['wol_spiders'])
	{
		build_datastore('wol_spiders', '', 1);
	}
	if (!$check['banemail'])
	{
		vB::getDatastore()->build('banemail', $settings['banemail']);
	}
	if (!$check['stylecache'])
	{
		vB_Library::instance('Style')->buildStyleDatastore();
	}
	if (!$check['usergroupcache'])
	{
		vB_Library::instance('usergroup')->buildDatastore();
	}
	if (!$check['loadcache'])
	{
		update_loadavg();
	}

	// Legacy Hook 'admin_global_datastore_check' Removed //

	// end auto-repair
	// #############################################################################

	print_cp_login();
}
else if ($_POST['do'] AND ADMINHASH != $vbulletin->GPC['adminhash'])
{
	print_cp_login(true);
}

if (file_exists(DIR . '/includes/version_vbulletin.php'))
{
	include_once(DIR . '/includes/version_vbulletin.php');
}

if (defined('FILE_VERSION_VBULLETIN') AND FILE_VERSION_VBULLETIN !== '')
{
	define('ADMIN_VERSION_VBULLETIN', FILE_VERSION_VBULLETIN);
}
else
{
	define('ADMIN_VERSION_VBULLETIN', $vbulletin->options['templateversion']);
}

// Legacy Hook 'admin_global' Removed //

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 103168 $
|| #######################################################################
\*=========================================================================*/
