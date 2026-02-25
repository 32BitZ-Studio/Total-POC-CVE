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

class vB5_Route_Newcontent extends vB5_Route
{
	public static function exportArguments($arguments)
	{
		$data = unserialize($arguments);

		$page = vB::getDbAssertor()->getRow('page', array('pageid' => $data['pageid']));
		if (empty($page))
		{
			throw new Exception('Couldn\'t find page');
		}
		$data['pageGuid'] = $page['guid'];
		unset($data['pageid']);

		return serialize($data);
	}

	public static function importArguments($arguments)
	{
		$data = unserialize($arguments);

		$page = vB::getDbAssertor()->getRow('page', array('guid' => $data['pageGuid']));
		if (empty($page))
		{
			throw new Exception('Couldn\'t find page');
		}
		$data['pageid'] = $page['pageid'];
		unset($data['pageGuid']);

		return serialize($data);
	}

	public static function importContentId($arguments)
	{
		return $arguments['pageid'];
	}

	/**
	 * Sets the breadcrumbs for the route
	 *
	 * @return	array
	 */
	protected function setBreadcrumbs()
	{
		$this->breadcrumbs = array();

		$phrase = 'create_new_topic';

		if (isset($this->arguments['nodeid']) && $this->arguments['nodeid'])
		{
			$onlyAddTopParent = false;

			$channelInfo = vB_Api::instanceInternal('Content_Channel')->fetchChannelById(intval($this->arguments['nodeid']));
			if ($channelInfo)
			{
				switch($channelInfo['channeltype'])
				{
					case 'blog':
						$phrase = 'create_new_blog_entry';
						break;
					case 'group':
						$phrase = 'create_new_topic';
						break;
					case 'article':
						$phrase = 'create_new_article';
						// when creating an article, the breadcrumb should
						// always be home > articles > create article
						// since you can choose the category when creating the article
						$onlyAddTopParent = true;
						break;
					default:
						break;
				}
			}

			$this->addParentNodeBreadcrumbs($this->arguments['nodeid'], $onlyAddTopParent);
		}

		$this->breadcrumbs[] = array(
			'phrase' => $phrase,
		);
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
