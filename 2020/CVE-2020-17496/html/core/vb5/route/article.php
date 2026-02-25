<?php if (!defined('VB_ENTRY')) die('Access denied.');
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

class vB5_Route_Article extends vB5_Route_Conversation
{

	// todo: Can we have a slug that doesn't even have the nodeid? It might be more human readable, something to consider...
	const REGEXP = '(?P<nodeid>[0-9]+)(?P<title>(-[^!@\\#\\$%\\^&\\*\\(\\)\\+\\?/:;"\'\\\\,\\.<>= _\\[\\]]*)*)(?:/contentpage(?P<contentpagenum>[0-9]+))?(?:/page(?P<pagenum>[0-9]+))?';
	const CUSTOM_URL_REGEXP = '(?:/contentpage(?P<contentpagenum>[0-9]+))?(?:/page(?P<pagenum>[0-9]+))?'; // Note that the leading / means that a multi-page article content can't be set as a home page

	public function __construct($routeInfo, $matches, $queryString = '', $anchor = '')
	{
		parent::__construct($routeInfo, $matches, $queryString, $anchor);
		
		// I'm leaving this bit of comment here to remind ourselves that we need to actually ensure that articles have a meta description.
		// Meta Description
		/*
		$this->arguments['metadescription'] = ;
		*/
	}

	protected static function validInput(array &$data)
	{
		parent::validInput($data);
		$data['class'] = __CLASS__;
		
		return $data;
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
