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

class vB5_Route_Legacy_vBCms extends vB5_Route_Legacy_Node
{
	protected $prefix = 'content.php';
	protected $regex = '^content[.php]?[^0-9]*(?P<oldid>[0-9]+)?(-)?(?P<urlident>[^/]*)?(/view/)?(?P<oldpage>[0-9]+)?';

	// although there are 3 different oldcontenttypeids, each oldid should be unique amongst all 3, since they all come
	// from the same table's unique key (cms_node.nodeid)
	protected $oldcontenttypeid =
		array(
			vB_Api_ContentType::OLDTYPE_CMS_SECTION,
			vB_Api_ContentType::OLDTYPE_CMS_ARTICLE,
			vB_Api_ContentType::OLDTYPE_CMS_STATICPAGE
		);

	public function __construct($routeInfo = array(), $matches = array(), $queryString = '', $anchor = '')
	{
		/* Depending on the friendliness setting, we can have four different url formats.  Like:
		   content.php?280-Accu-Sim-In-General/view/2
		   content.php?r=280-Accu-Sim-In-General/view/2
		   content.php/280-Accu-Sim-In-General/view/2
		   content/280-Accu-Sim-In-General/view/2
		*/
		parent::__construct($routeInfo, $matches, $queryString, $anchor);

		if (!empty($queryString) AND (empty($this->arguments['oldid']) OR !is_numeric($this->arguments['oldid'])
				OR empty($this->arguments['oldpage']) OR !is_numeric($this->arguments['oldpage'])))
		{
			$queryMatches = array();
			if (preg_match('#[^0-9]*(?P<oldid>[0-9]+)?(-)?(?P<urlident>[^%2F]*)?(%2Fview%2F)?(?P<oldpage>[0-9]+)?#i', $queryString, $queryMatches))
			{
				if (!empty($queryMatches['oldid']))
				{
					$this->arguments['oldid'] = $queryMatches['oldid'];
				}

				if (!empty($queryMatches['oldpage']))
				{
					$this->arguments['contentpage'] = $queryMatches['oldpage'];
				}
			}
		}

		if (!empty($this->arguments['oldid']) AND is_numeric($this->arguments['oldid']))
		{
			$node = vB::getDbAssertor()->getRow('vBForum:node', array(
				'oldid' => $this->arguments['oldid'],
				'oldcontenttypeid' => $this->oldcontenttypeid
				));

			if (!empty($node) AND empty($node['errors']))
			{
				$this->arguments['nodeid'] = $node['nodeid'];
				$this->arguments['contenttypeid'] = $node['contenttypeid'];
				$this->arguments['routeid'] = $node['routeid'];
			}
		}

		// I'm leaving this bit of comment here to remind ourselves that we need to actually ensure that articles have a meta description.
		// Meta Description
		/*
		   $this->arguments['metadescription'] = ;
		*/
	}


	protected function getNewRouteInfo()
	{
		return $this->arguments['routeid'];
	}

	/** returns the default regex
	 *
	 *	@return	string
	 */
	public function getRegex()
	{
		return $this->regex;
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
