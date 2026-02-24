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

define('VB_REQUEST_START_TIME', microtime(true));

if (!defined('VB_ENTRY'))
{
	define('VB_ENTRY', 1);
}

// Check for cached image calls to filedata/fetch?
if (isset($_REQUEST['routestring'])
		AND
	$_REQUEST['routestring'] == 'filedata/fetch'
		AND
	(isset($_SERVER['HTTP_IF_MODIFIED_SINCE']) AND !empty($_SERVER['HTTP_IF_MODIFIED_SINCE'])
		OR
	(isset($_SERVER['HTTP_IF_NONE_MATCH']) AND !empty($_SERVER['HTTP_IF_NONE_MATCH']))))
{
	http_response_code(304);
}


require_once('includes/vb5/autoloader.php');
vB5_Autoloader::register(dirname(__FILE__));

//For a few set routes we can run a streamlined function.
if (vB5_Frontend_ApplicationLight::isQuickRoute())
{
	$app = vB5_Frontend_ApplicationLight::init('config.php');
	vB5_Frontend_ExplainQueries::initialize();
	if ($app->execute())
	{
		vB5_Frontend_ExplainQueries::finish();
		exit();
	}
}

$app = vB5_Frontend_Application::init('config.php');
//todo, move this back so we can catch notices in the startup code. For now, we can set the value in the php.ini
//file to catch these situations.
// We report all errors here because we have to make Application Notice free
error_reporting(E_ALL | E_STRICT);

$config = vB5_Config::instance();
if (!$config->report_all_php_errors) {
	// Note that E_STRICT became part of E_ALL in PHP 5.4
	error_reporting(E_ALL & ~(E_NOTICE | E_STRICT));
}

$routing = $app->getRouter();
$method = $routing->getAction();
$template = $routing->getTemplate();
$class = $routing->getControllerClass();

if (!class_exists($class))
{
	// @todo - this needs a proper error message
	die("Couldn't find controller file for $class");
}

vB5_Frontend_ExplainQueries::initialize();
$c = new $class($template);

call_user_func_array(array(&$c, $method), $routing->getArguments());

vB5_Frontend_ExplainQueries::finish();

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
