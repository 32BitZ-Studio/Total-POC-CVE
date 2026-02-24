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

class vB5_Route_Legacy_Blog extends vB5_Route_Legacy_Node
{
	protected $idkey = array('u', 'userid');

	protected $prefix = 'blog.php';

	protected function getNewRouteInfo()
	{
		// go to home page if path is exactly like prefix
		if (count($this->matches) == 1 AND empty($this->queryParameters))
		{
			$blogHomeChannelId = vB_Api::instance('blog')->getBlogChannel();
			$blogHomeChannel = vB_Library::instance('content_channel')->getBareContent($blogHomeChannelId);
			$blogHomeChannel = $blogHomeChannel[$blogHomeChannelId];
			return $blogHomeChannel['routeid'];
		}
		$this->oldcontenttypeid = vB_Api_ContentType::OLDTYPE_BLOGCHANNEL;
		return parent::getNewRouteInfo();
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
