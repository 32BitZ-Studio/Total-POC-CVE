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

if (!defined('VB_ENTRY'))
{
	define('VB_ENTRY', 1);
}

define('NOCHECKSTATE', 1);

// ####################### SET PHP ENVIRONMENT ###########################
error_reporting(E_ALL & ~E_NOTICE);
@ini_set('zlib.output_compression', 'Off');
@set_time_limit(0);
if (@ini_get('output_handler') == 'ob_gzhandler' AND @ob_get_length() !== false)
{	// if output_handler = ob_gzhandler, turn it off and remove the header sent by PHP
	@ob_end_clean();
	header('Content-Encoding:');
}

// #################### DEFINE IMPORTANT CONSTANTS #######################
//define('THIS_SCRIPT', 'xmlsitemap');
//define('BYPASS_FORUM_DISABLED', true);
//define('CSRF_PROTECTION', true);

// ################### PRE-CACHE TEMPLATES AND DATA ######################
global $vbulletin;

// ######################### REQUIRE BACK-END ############################
require_once(dirname(__FILE__) . '/global.php');

// #######################################################################
// ######################## START MAIN SCRIPT ############################
// #######################################################################

$vbulletin->input->clean_array_gpc('r', array(
	'fn' => vB_Cleaner::TYPE_STR
));

$sitemap_path = resolve_server_path(vB::getDatastore()->getOption('sitemap_path'));

if ($vbulletin->GPC['fn'])
{
	$sitemap_filename = preg_replace('#[^a-z0-9_.]#i', '', $vbulletin->GPC['fn']);
	$sitemap_filename = preg_replace('#\.{2,}#', '.', $sitemap_filename);

	if (substr($sitemap_filename, -4) != '.xml' AND substr($sitemap_filename, -7) != '.xml.gz')
	{
		$sitemap_filename = '';
	}
}
else if (file_exists($sitemap_path . '/vbulletin_sitemap_index.xml.gz'))
{
	$sitemap_filename = 'vbulletin_sitemap_index.xml.gz';
}
else if (file_exists($sitemap_path . '/vbulletin_sitemap_index.xml'))
{
	$sitemap_filename = 'vbulletin_sitemap_index.xml';
}
else
{
	$sitemap_filename = '';
}

if ($sitemap_filename AND file_exists($sitemap_path . "/$sitemap_filename"))
{
	$gzipped = (substr($sitemap_filename, -3) == '.gz');

	if ($gzipped)
	{
		header('Content-Transfer-Encoding: binary');
		header('Content-Encoding: gzip');
		$output_filename = substr($sitemap_filename, 0, -3);
	}
	else
	{
		$output_filename = $sitemap_filename;
	}

	header('Accept-Ranges: bytes');
	$filesize = sprintf('%u', filesize($sitemap_path . "/$sitemap_filename"));
	header("Content-Length: $filesize");
	header('Content-Type: text/xml');
	header('Content-Disposition: attachment; filename="' . rawurlencode($output_filename) . '"');

	readfile($sitemap_path . "/$sitemap_filename");

	exit;
}

throw new vB_Exception_404('sitemap_not_found');

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 103425 $
|| #######################################################################
\*=========================================================================*/
