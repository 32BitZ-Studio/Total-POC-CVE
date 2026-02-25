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
define('THIS_SCRIPT', 'css');
define('CSRF_PROTECTION', true);
if (!defined('VB_ENTRY'))
{
	define('VB_ENTRY', 1);
}
// Immediately send back the 304 Not Modified header if this css is cached
if ((!empty($_SERVER['HTTP_IF_MODIFIED_SINCE']) OR !empty($_SERVER['HTTP_IF_NONE_MATCH'])))
{
	http_response_code(304);
	// remove the content-type and X-Powered headers to emulate a 304 Not Modified response as close as possible
	header('Content-Type:');
	header('X-Powered-By:');
	exit;
}

// ################### PRE-CACHE TEMPLATES AND DATA ######################
preg_match_all('#([a-z0-9_\-]+\.css)#i', $_REQUEST['sheet'], $matches);
$css_templates = $matches[1];

// ######################### REQUIRE BACK-END ############################
$cssStyleid = (int) $_GET['styleid'];
//this should only be 'rtl' or 'ltr' but if its something else we'll
//assume 'ltr' instead of throwing an error.
$ltr = ($_GET['td'] != 'rtl');

//always process this script as guest to avoid
require_once(dirname(__FILE__) . '/vb/vb.php');
vB::init();
vB::setRequest(new vB_Request_Web());
vB::setCurrentSession(new vB_Session_Skip(vB::getDBAssertor(), vB::getDatastore(), vB::getConfig(), $cssStyleid));

$style = vB_Library::instance('style')->getStyleById($cssStyleid);

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

vB_Library::instance('template')->cacheTemplates($css_templates, $style['templatelist'], false, true);

// #######################################################################
// ######################## START MAIN SCRIPT ############################
// #######################################################################

if (empty($css_templates))
{
	$output = "/* Unable to find css sheet */";
}
else
{
	$count = 0;
	$output = '';

	foreach ($css_templates AS $template)
	{
		if ($count > 0)
		{
			$output .= "\r\n\r\n";
		}

		$templater = vB_Template::create($template);

		/* Note that the css publishing mechanism relies on the fact that
		there isn't any user specific data passed to the css templates.
		We violate this for a users profile css, because thats its reason for existing. */
		if ($template == 'css_profile.css')
		{
			$userId = 0;
			if (
				isset($_REQUEST['userid']) AND
				intval($_REQUEST['userid']) AND
				isset($_REQUEST['showusercss']) AND
				intval($_REQUEST['showusercss']) == 1
			)
			{
				$userId = intval($_REQUEST['userid']);
			}
			$templater->register('userid', $userId);
		}

		$template = $templater->render(true, false, true);

		if ($count > 0)
		{
			$template = preg_replace("#@charset .*#i", "", $template);
		}

		$count++;
		$output .= $template;
	}

	$output = vB_String::getCssMinifiedText($output);

	if ($output == '')
	{
		$output = '/* Unable to find css template */';
	}
	else if (!headers_sent() AND vB::getDatastore()->getOption('gzipoutput'))
	{
		$output = fetch_gzipped_text($output, vB::getDatastore()->getOption('gziplevel'));
	}
}

header('Content-Type: text/css');
header('Cache-control: max-age=31536000, private');
header('Expires: ' . gmdate("D, d M Y H:i:s", vB::getRequest()->getTimeNow() + 31536000) . ' GMT');
header('Pragma:');
header('Last-Modified: ' . gmdate('D, d M Y H:i:s', $style['dateline']) . ' GMT');
header('Content-Length: ' . strlen($output));
echo $output;

/*========================================================================*\
|| ######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 100935 $
|| ######################################################################
\*========================================================================*/
