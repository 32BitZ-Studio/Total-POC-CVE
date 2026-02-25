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

//usually this should be called via the rely from the front end
//so this should already be done.  If it isn't let's make it work anyway
if (!class_exists('vB'))
{
	require_once(dirname(__FILE__) . '/vb/vb.php');
	vB::init();
	vB::setRequest(new vB_Request_Web());
}

if (!empty($_REQUEST['attachmentid']))
{

	$contentTypeApi = vB_Api::instance('ContentType');
	$contenttypeids = array();
	// TODO: What is 'PictureComment' and should it be in the list?
	foreach (array('Attach', 'Photo', 'Picture') AS $class)
	{
		$contenttypeids[$class] = $contentTypeApi->fetchContentTypeIdFromClass($class);
	}
	if (!empty($_REQUEST['s']))
	{
		// Just pass this through. The filedatafetch will need it.
		// This is a string that's latter passed over to the assertor
		// which would db escape it. Also see Api_Interface_Light::init()
		// where it's extracted & passed to the session object
		$sessionParam = "&s=" . (string) $_REQUEST['s'];
	}
	else
	{
		$sessionParam = '';
	}
	if (!empty($_REQUEST['api']) AND intval($_REQUEST['attachmentid']) < 0)
	{
		/*
			Temporary hack. If api = 1 with a negative attachmentid, assume it's coming in
			from the mobile app w/ -{nodeid} .
		 */
		$nodeid = abs(intval($_REQUEST['attachmentid']));
		$db = vB::getDbAssertor();
		$node = $db->getRow('vBForum:node', array(
			'nodeid' => $nodeid,
			'contenttypeid' => $contenttypeids,
		));
	}
	else
	{
		$oldid = intval($_REQUEST['attachmentid']);
		$db = vB::getDbAssertor();
		$node = $db->getRow('vBForum:node', array(
			'oldid' => $oldid,
			'oldcontenttypeid' => array(
				vB_Api_ContentType::OLDTYPE_SGPHOTO,
				vB_Api_ContentType::OLDTYPE_PHOTO,
				vB_Api_ContentType::OLDTYPE_THREADATTACHMENT,
				vB_Api_ContentType::OLDTYPE_POSTATTACHMENT,
				vB_Api_ContentType::OLDTYPE_BLOGATTACHMENT
			)
		));
	}
	if ($node)
	{
		if (!empty($node['oldcontenttypeid']))
		{
			switch($node['oldcontenttypeid'])
			{
				case vB_Api_ContentType::OLDTYPE_SGPHOTO:
				case vB_Api_ContentType::OLDTYPE_PHOTO:
					$requestvar = 'photoid';
					break;
				default:
					$requestvar = 'id';
			}
		}
		else
		{
			switch($node['contenttypeid'])
			{
				case $contenttypeids['Photo']:
				case $contenttypeids['Picture']: // todo double check that 'Picture' uses photoid
					$requestvar = 'photoid';
					break;
				default:
					$requestvar = 'id';
			}

		}
		$redirecturl = "filedata/fetch?${requestvar}=$node[nodeid]" . $sessionParam;
		header("Location: $redirecturl", true, 301);
		exit;
	}
}

//This script is intended to return a file, not an html document (well now we intend to redirect to a document).
//that means this error will only display when troubleshooting since img tags and the like don't display content when
//they get a 404.  A large 404 page is not only unnecesary but counter productive.
//
//status is to handle some weirdly configured CGI setups.  Probably not needed
//in this day and age, but doesn't really hurt.
http_response_code(404);

echo vB_Phrase::fetchSinglePhrase('error_404');
/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
