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

// ####################### SET PHP ENVIRONMENT ###########################
error_reporting(E_ALL);

// #################### DEFINE IMPORTANT CONSTANTS #######################
define('THIS_SCRIPT', 'login');
//define('CSRF_PROTECTION', true);
define('CSRF_SKIP_LIST', 'login');
define('CONTENT_PAGE', false);
if (!defined('VB_ENTRY'))
{
	define('VB_ENTRY', 1);
}
// ################### PRE-CACHE TEMPLATES AND DATA ######################
// get special phrase groups
global $phrasegroups, $specialtemplates, $globaltemplates, $actiontemplates, $show;
$phrasegroups = array();

// get special data templates from the datastore
$specialtemplates = array();

// pre-cache templates used by all actions
$globaltemplates = array();

// pre-cache templates used by specific actions
$actiontemplates = array(
	'lostpw' => array(
		'lostpw',
		'humanverify'
	)
);

// ######################### REQUIRE BACK-END ############################
require_once(dirname(__FILE__) . '/global.php');
require_once(DIR . '/includes/adminfunctions.php');
require_once(DIR . '/includes/functions_login.php');

global $vbulletin, $vbphrase;
// #######################################################################
// ######################## START MAIN SCRIPT ############################
// #######################################################################

if (empty($_REQUEST['do']))
{
	exec_header_redirect(vB5_Route::buildUrl('home|fullurl'));
}

// ############################### start do login ###############################
// this was a _REQUEST action but where do we all login via request?
if ($_POST['do'] == 'login')
{
	$vbulletin->input->clean_array_gpc('p', array(
		'vb_login_username'        => vB_Cleaner::TYPE_STR,
		'vb_login_password'        => vB_Cleaner::TYPE_STR,
		'vb_login_md5password'     => vB_Cleaner::TYPE_STR,
		'vb_login_md5password_utf' => vB_Cleaner::TYPE_STR,
		'vb_login_mfa_authcode'    => vB_Cleaner::TYPE_NOHTML,
		'postvars'                 => vB_Cleaner::TYPE_BINARY,
		'cookieuser'               => vB_Cleaner::TYPE_BOOL,
		'logintype'                => vB_Cleaner::TYPE_STR,
		'cssprefs'                 => vB_Cleaner::TYPE_STR,
		'inlineverify'             => vB_Cleaner::TYPE_BOOL,
	));

	$passwords = array(
		'password' => $vbulletin->GPC['vb_login_password'],
		'md5password' => $vbulletin->GPC['vb_login_md5password'],
		'md5password_utf' => $vbulletin->GPC['vb_login_md5password_utf'],
	);

	$extraAuth = array(
		'mfa_authcode' => $vbulletin->GPC['vb_login_mfa_authcode'],
	);

	$userApi = vB_Api::instance('user');
	$res = $userApi->login2($vbulletin->GPC['vb_login_username'], $passwords, $extraAuth, $vbulletin->GPC['logintype']);

	if(isset($res['errors']))
	{
		$errorid = $res['errors'][0][0];
		$knownloginerror = (strpos($errorid, 'badmfa') === 0 OR strpos($errorid, 'badlogin') === 0 OR $errorid == 'strikes');

		//we should only be using this for a cp login at this point, but leaving this check in
		//in an abundance of caution.  Note that this redirect doesn't handle general errors
		//so we need to check if its one of the one's we do handle.  Otherwise use a more generic
		//error display below.
		if ($knownloginerror AND $vbulletin->GPC['logintype'] === 'cplogin' OR $vbulletin->GPC['logintype'] === 'modcplogin')
		{
			$url = unhtmlspecialchars($vbulletin->url);

			$urlarr = vB_String::parseUrl($url);

			$urlquery = $urlarr['query'];

			$oldargs = array();
			if ($urlquery)
			{
				parse_str($urlquery, $oldargs);
			}

			$args = $oldargs;
			unset($args['loginerror']);

			$args['loginerror_arr'] = $res['errors'][0];
			$args['vb_login_username'] = $vbulletin->GPC['vb_login_username'];
			$argstr = http_build_query($args);

			$url = $urlarr['path'];

			if ($argstr)
			{
				$url .= '?' . $argstr;
			}

			print_cp_redirect_old($url);
		}

		print_stop_message2($res['errors'][0]);
	}

	if ($vbulletin->GPC['logintype'] === 'cplogin')
	{
		vB_User::setAdminCss($res['userid'], $vbulletin->GPC['cssprefs']);
	}

	// set cookies (temp hack for admincp)
	if (isset($res['cpsession']))
	{
		vbsetcookie('cpsession', $res['cpsession'], false, true, true);
	}

	vbsetcookie('sessionhash', $res['sessionhash'], false, true, true);
	do_login_redirect();
}
else if ($_GET['do'] == 'login')
{
	// add consistency with previous behavior
	exec_header_redirect(vB5_Route::buildUrl('home|fullurl'));
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 102490 $
|| #######################################################################
\*=========================================================================*/
