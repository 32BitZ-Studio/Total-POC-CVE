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
error_reporting(E_ALL & ~E_NOTICE);

// #################### DEFINE IMPORTANT CONSTANTS #######################
define('THIS_SCRIPT', 'sprite');
define('CSRF_PROTECTION', true);
define('NOSHUTDOWNFUNC', 1);
define('NOCOOKIES', 1);
define('NOPMPOPUP', 1);
define('VB_AREA', 'Forum');

if (!defined('VB_ENTRY'))
{
	define('VB_ENTRY', 1);
}

// ################### HANDLE 304 NOT MODIFIED STATUS ####################
if ((!empty($_SERVER['HTTP_IF_MODIFIED_SINCE']) OR !empty($_SERVER['HTTP_IF_NONE_MATCH'])))
{
	// Immediately send back the 304 Not Modified header if this sprite is cached (don't initialize vB)
	http_response_code(304);
	// remove the content-type and X-Powered headers to emulate a 304 Not Modified response as close as possible
	header('Content-Type:');
	header('X-Powered-By:');
	exit;
}

// ####################### SANITIZE VARIABLES ###########################
if (preg_match('#^([a-z0-9_\-]+\.svg)$#i', $_REQUEST['sprite'], $matches))
{
	$templateName = $matches[1];
}
else
{
	$templateName = '';
}
$styleid = (int) $_REQUEST['styleid'];
$ltr = ($_REQUEST['td'] !== 'rtl');

// ######################### REQUIRE BACK-END ############################
//always process this script as guest
require_once(dirname(__FILE__) . '/vb/vb.php');
vB::init();
vB::setRequest(new vB_Request_Web());
vB::setCurrentSession(new vB_Session_Skip(vB::getDBAssertor(), vB::getDatastore(), vB::getConfig(), $styleid));

$style = vB_Library::instance('style')->getStyleById($styleid);

//this is extracted from the old bootstrap that we are replacing.
//the template runtime depends on $vbulletin->stylevars being set
//which is really a bad way to do business, but that needs more
//effort to clean up than is available at present
global $vbulletin;
$vbulletin = vB::get_registry();
$vbulletin->stylevars = $style['newstylevars'];
// call set_stylevar_ltr() and set_stylevar_meta() instead of the full fetch_stylevars() which accesses userinfo.
// this populates the pseudo stylevars we need
set_stylevar_ltr($ltr);
set_stylevar_meta($style['styleid']);

vB_Library::instance('template')->cacheTemplates(array($templateName), $style['templatelist'], false, true);

// #######################################################################
// ######################## START MAIN SCRIPT ############################
// #######################################################################

$output = '';

if (!empty($templateName))
{
	$templater = vB_Template::create($templateName);
	$output = $templater->render(true, false, true);
}

if (empty($output))
{
	// output "Sprite not found" as an SVG image
	$output = '<svg version="1.1" baseProfile="full" width="300" height="50" xmlns="http://www.w3.org/2000/svg"><rect width="100%" height="100%" fill="#999999" /><text x="150" y="30" font-size="20" text-anchor="middle" fill="#FFFFFF">Sprite not found</text></svg>';
}
else if (!headers_sent() AND vB::getDatastore()->getOption('gzipoutput'))
{
	// this sets the Content-Encoding header if it ends up gzipping the output
	$output = fetch_gzipped_text($output, vB::getDatastore()->getOption('gziplevel'));
}

// send output
header('Content-Type: image/svg+xml');
header('Cache-control: max-age=31536000, private');
header('Expires: ' . gmdate("D, d M Y H:i:s", vB::getRequest()->getTimeNow() + 31536000) . ' GMT');
header('Pragma:');
header('Last-Modified: ' . gmdate('D, d M Y H:i:s', $style['dateline']) . ' GMT');
header('Content-Length: ' . strlen($output));
header('Vary: Accept-Encoding');

echo $output;


/*========================================================================*\
|| ######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 101013 $
|| ######################################################################
\*========================================================================*/
