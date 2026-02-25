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

error_reporting(E_ALL & ~E_NOTICE);

define('VB_API', true);
define('VB5_API_VERSION_START', 500);
define('VB_API_VERSION', 560);
define('VB_API_VERSION_MIN', 1);
define('CWD_API', (($getcwd = getcwd()) ? $getcwd : '.') . '/includes/api');
define('NOCOOKIES', true);
require_once('vb/vb.php');
vB::silentWarnings(); // VBV-16618 Suppress or Resolve array_merge error in MAPI
vB::init();

$api_m = trim($_REQUEST['api_m']);

// Client ID
$api_c = intval($_REQUEST['api_c']);

// Access token
$api_s = trim($_REQUEST['api_s']);

// Request Signature Verification Prepare (Verified in vB_Session_Api)
$api_sig = trim($_REQUEST['api_sig']);

global $api_version;
$api_version = intval($_REQUEST['api_v']);

global $VB_API_PARAMS_TO_VERIFY, $VB_API_REQUESTS;

// Note, "cms." calls are vb4 calls, but might get interpretted as vb5 calls if api_version is not set!!
if (empty($api_m) || ($api_version >= VB5_API_VERSION_START && !strpos($api_m, '.') && !strstr($api_m, 'api_init')))
{
	header($_SERVER['SERVER_PROTOCOL'] . ' 400 Bad Request');
	header("Connection: Close");
	die();
}

// $VB_API_PARAMS_TO_VERIFY is set in class_core.php's
// vB_Input_Cleaner::__construct(), due to convert_short_vars()
// causing API signature error (page => pagenumber)
// In vB4, the API sig was verified *before* input cleaning.
/*
unset($_GET['']); // See VBM-835
$VB_API_PARAMS_TO_VERIFY = $_GET;

unset(
	$VB_API_PARAMS_TO_VERIFY['api_c'],
	$VB_API_PARAMS_TO_VERIFY['api_v'],
	$VB_API_PARAMS_TO_VERIFY['api_s'],
	$VB_API_PARAMS_TO_VERIFY['api_sig'],
	$VB_API_PARAMS_TO_VERIFY['debug'],
	$VB_API_PARAMS_TO_VERIFY['showall'],
	$VB_API_PARAMS_TO_VERIFY['do'],
	$VB_API_PARAMS_TO_VERIFY['r']
);

ksort($VB_API_PARAMS_TO_VERIFY);
*/

$VB_API_REQUESTS = array(
	'api_m' => $api_m,
	'api_version' => $api_version,
	'api_c' => $api_c,
	'api_s' => $api_s,
	'api_sig' => $api_sig
);

$request = new vB_Request_Api();
vB::setRequest($request);
try
{
	$request->createSession($VB_API_PARAMS_TO_VERIFY, $VB_API_REQUESTS);
	unset($VB_API_PARAMS_TO_VERIFY); // we shouldn't ever use this after sig validation as part of createSession() above.
}
catch (Exception $e)
{
	if ($e instanceof vB_Exception_Api)
	{
		print_apierror($e->get_errors(), $e->getMessage());
	}
	else
	{
		print_apierror($e->getMessage());
	}
}

// At this point, createSession() above should've called vB_Session_Api::validateApiSession() & verified
// our API signature, and these requests should be considered human-verified (VBV-19480)
require_once(DIR . '/includes/class_humanverify.php');
vB_HumanVerify::disableHV();


$api_m = trim($_REQUEST['api_m']);

// API Version
if (!$api_version)
{
	$api_version = VB_API_VERSION;
}
if ($api_version < VB_API_VERSION_MIN)
{
	print_apierror('api_version_too_low', 'This server accepts API version ' . VB_API_VERSION_MIN . ' at least. The requested API version is too low.');
}
elseif ($api_version > VB_API_VERSION)
{
	print_apierror('api_version_too_high', 'This server accepts API version ' . VB_API_VERSION . ' at most. The requested API version is too high.');
}

define('VB_API_VERSION_CURRENT', $api_version);

if($api_version < VB5_API_VERSION_START || strstr("api_init", $api_m))
{
	$old_api_m = $api_m;
	define("VB4_MAPI_METHOD", $old_api_m);
	$api_m = vB_Api::map_vb4_input_to_vb5($api_m, $_REQUEST);
}

// $methodsegments[0] is the API class name
// $methodsegments[1] is the API function name
// $_REQUEST data as function named params

$methodsegments = explode(".", $api_m);

try
{
	$apiobj = vB_Api::instance(strtolower($methodsegments[0]));
	$data = $apiobj->callNamed($methodsegments[1], array_merge($_REQUEST, $_FILES));

	if(isset($data['errors']))
	{
		//do some stuff to make the return more like what it was when we were calling
		//instanceInternal.  We might want to unwind this, but only after making sure
		//that the mobile client can handle it.
		$errors = $data['errors'];
		foreach($errors AS $key => $error)
		{
			if($error[0] == 'exception_trace')
			{
				unset($errors[$key]);
			}
		}

		print_apierror($errors);
	}

	// Note: previously there was an !empty($data) check here but it was removed as
	// certain API returns *can* be empty (api_cmssectionlist)
	if($api_version < VB5_API_VERSION_START)
	{
		vB_Api::map_vb5_output_to_vb4($old_api_m, $data);
	}
	print_apioutput($data);
}
catch (Exception $e)
{
	if ($e instanceof vB_Exception_Api)
	{
		print_apierror($e->get_errors(), $e->getMessage());
	}
	else
	{
		print_apierror($e->getMessage());
	}
}

function print_apierror($errors, $debugstr = '')
{
	global $api_version;

	if (!is_array($errors))
	{
		$errors = array($errors);
	}

	$data = array();
	if($api_version < VB5_API_VERSION_START)
	{
		vB_Api::map_vb5_errors_to_vb4(VB4_MAPI_METHOD, $errors);
		$data = $errors;
		print_apioutput($data);
		return;
	}
	else
	{
		$data = array('errors' => $errors);
	}

	$vb5_config =& vB::getConfig();

	if ($debugstr AND $vb5_config['Misc']['debug'])
	{
		$data['debug'] = $debugstr;
	}

	print_apioutput($data);
}

function print_apioutput($data)
{
	global $VB_API_REQUESTS;

	// We need to convert $data charset if we're not using UTF-8
	if (vB_String::getCharset() != 'UTF-8')
	{
		$data = vB_String::toCharset($data, vB_String::getCharset(), 'UTF-8');
	}

	header('Content-type: application/json; charset=UTF-8');

	// IE will cache ajax requests, and we need to prevent this - VBV-148
	header('Cache-Control: max-age=0,no-cache,no-store,post-check=0,pre-check=0');
	header('Expires: Sat, 1 Jan 2000 01:00:00 GMT');
	header("Last-Modified: " . gmdate("D, d M Y H:i:s") . " GMT");
	header("Pragma: no-cache");

	$output = json_encode($data, JSON_PARTIAL_OUTPUT_ON_ERROR);

	//we can get here because we failed to create the session so let's make sure its
	//a proper API session (hack alert).
	$currentSession = vB::getCurrentSession();
	$apiclient = array();
	if ($currentSession instanceof vB_Session_Api)
	{
		$apiclient = $currentSession->getApiClient();
	}

	$vboptions = vB::getDatastore()->getValue('options');

	if ($apiclient AND !in_array($VB_API_REQUESTS['api_m'], array('user.login', 'user.logout')))
	{
		$sign = md5($output . $apiclient['apiaccesstoken'] . $apiclient['apiclientid'] . $apiclient['secret'] . $vboptions['apikey']);
		@header('Authorization: ' . $sign);
	}

	echo $output;

	exit;
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 103771 $
|| #######################################################################
\*=========================================================================*/
