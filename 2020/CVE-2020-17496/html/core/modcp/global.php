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

// identify where we are
define('VB_AREA', 'ModCP');

//this should technically be the name of the script file being run, but
//it really just needs to be set to something to pass the include checks
//and figuring out how to set it correctly from $_SERVER information is
//proving to be more trouble than it is  worth

define('IN_CONTROL_PANEL', true);

if (!defined('VB_ENTRY'))
{
	define('VB_ENTRY', 'ModCP');
}

if (!defined('VB_API'))
{
	define('VB_API', false);
}

if (!isset($phrasegroups) OR !is_array($phrasegroups))
{
	$phrasegroups = array();
}
$phrasegroups[] = 'cpglobal';

if (!isset($specialtemplates) OR !is_array($specialtemplates))
{
	$specialtemplates = array();
}
if (!in_array('global', $phrasegroups))
{
	$phrasegroups[] = 'global';
}

// ###################### Start functions #######################

//this is only needed if we are going directly to site/core/admincp/...
//which is deprecated.  If we use the front end relay (site/admincp/...)
//then CWD will already be set
if (!defined('CWD'))
{
	chdir('./../');
	define('CWD', (($getcwd = getcwd()) ? $getcwd : '.'));
}

require_once(CWD . '/includes/init.php');
require_once(DIR . '/includes/adminfunctions.php');
require_once(DIR . '/includes/functions_calendar.php');

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
if (!empty($config['Security']['ModIP']))
{
	$cpips = $config['Security']['ModIP'];
	if (!is_array($cpips))
	{
		$cpips = explode(',', $cpips);
	}

	$ip = vB::getRequest()->getIpAddress();
	if (!vB_Ip::ipInArray($ip, $cpips))
	{
		print_cp_header('', '');
		print_modcp_stop_message2('no_permission');
		print_cp_footer();
	}
}

vB_Language::preloadPhraseGroups($phrasegroups);
//Force load of the user information
vB::getCurrentSession()->loadPhraseGroups();
// ###################### Start headers #######################
exec_nocache_headers();

// ###################### Get date / time info #######################
// override date/time settings if specified
fetch_options_overrides($vbulletin->userinfo);
fetch_time_data();

// ############################################ LANGUAGE STUFF ####################################
// initialize $vbphrase and set language constants
$vbphrase = init_language();
$_tmp = NULL;
fetch_stylevars($_tmp, $vbulletin->userinfo);

$permissions = cache_permissions($vbulletin->userinfo, true);
$vbulletin->userinfo['permissions'] =& $permissions;
$cpsession = array();

$vbulletin->input->clean_array_gpc('p', array(
	'adminhash' => vB_Cleaner::TYPE_STR,
));

$vbulletin->input->clean_array_gpc('c', array(
	COOKIE_PREFIX . 'cpsession' => vB_Cleaner::TYPE_STR,
));

if (!empty($vbulletin->GPC[COOKIE_PREFIX . 'cpsession']))
{
	$cpsession = $db->query_first("
		SELECT * FROM " . TABLE_PREFIX . "cpsession
		WHERE userid = " . $vbulletin->userinfo['userid'] . "
			AND hash = '" . $db->escape_string($vbulletin->GPC[COOKIE_PREFIX . 'cpsession']) . "'
			AND dateline > " . iif($vbulletin->options['timeoutcontrolpanel'], intval(TIMENOW - $vbulletin->options['cookietimeout']), intval(TIMENOW - 3600))
	);

	if (!empty($cpsession))
	{
		$db->shutdown_query("
			UPDATE LOW_PRIORITY " . TABLE_PREFIX . "cpsession
			SET dateline = " . TIMENOW . "
			WHERE userid = " . $vbulletin->userinfo['userid'] . "
				AND hash = '" . $db->escape_string($vbulletin->GPC[COOKIE_PREFIX . 'cpsession']) . "'
		");
	}
}

define('CP_SESSIONHASH', $cpsession['hash']);

if (!can_moderate() OR ($vbulletin->options['timeoutcontrolpanel'] AND !vB::getCurrentSession()->get('loggedin'))
	OR empty($vbulletin->GPC[COOKIE_PREFIX . 'cpsession'])
	OR $vbulletin->GPC[COOKIE_PREFIX . 'cpsession'] != $cpsession['hash']
	OR empty($cpsession))
{
	print_cp_login();
}
else if ($_POST['do'] AND ADMINHASH != $vbulletin->GPC['adminhash'])
{
	if ($_POST['login_redirect'])
	{
		unset($_GET['do'], $_POST['do'], $_REQUEST['do']);
	}
	else
	{
		print_cp_login(true);
	}
}

// Legacy Hook 'mod_global' Removed //

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 100473 $
|| #######################################################################
\*=========================================================================*/
