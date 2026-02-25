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

/**
 * vB_Library_Article
 *
 * @package vBLibrary
 * @access public
 */
class vB_Library_Article extends vB_Library
{
	protected $articleHomeChannel = false;

	/**
	 *	This class is based on vB_Library_Blog
	 */
	protected function __construct()
	{
		parent::__construct();
		$this->assertor = vB::getDbAssertor();
		$this->articleHomeChannel = $this->getArticleChannel();
	}

	public function createArticleCategory($input)
	{
		$parentChannel = (isset($input['parentid']) ? $input['parentid'] : $this->getArticleChannel());
		return $this->createChannel($input, $parentChannel, vB_Page::getArticleConversPageTemplate(), vB_Page::getArticleChannelPageTemplate(), vB_Api_UserGroup::CHANNEL_OWNER_SYSGROUPID);
	}

	/**
	 * Create an article category channel. This function works basically like the blog library's version
	 *
	 * @param array 	$input						data array, should have standard channel data like title, parentid,
	 * @param int 		$channelid					parentid that the new channel should fall under.
	 * @param int		$channelConvTemplateid		"Conversation" level pagetemplate to use. Typically vB_Page::getArticleConversPageTemplate()
	 * @param int 		$channelPgTemplateId		"Channel" level pagetemplate to use. Typically  vB_Page::getArticleChannelPageTemplate()
	 * @param int 		$ownerSystemGroupId
	 *
	 * @return int The nodeid of the new blog channel
	 */
	public function createChannel($input, $channelid, $channelConvTemplateid, $channelPgTemplateId, $ownerSystemGroupId)
	{
		if (!isset($input['parentid']) OR intval($input['parentid']) < 1)
		{
			$input['parentid'] = $channelid;
		}

		$input['inlist'] = 1; // we don't want it to be shown in channel list, but we want to move them
		$input['protected'] = 0;

		if (empty($input['userid']))
		{
			$input['userid'] =  vB::getCurrentSession()->get('userid');
		}


		if (!isset($input['publishdate']))
		{
			$input['publishdate'] = vB::getRequest()->getTimeNow();
		}

		$input['templates']['vB5_Route_Channel'] = $channelPgTemplateId;
		$input['templates']['vB5_Route_Article'] = $channelConvTemplateid;
		$input['childroute'] = 'vB5_Route_Article';

		// add channel node
		$channelLib = vB_Library::instance('content_channel');
		$input['page_parentid'] = 0;
		$result = $channelLib->add($input, array('skipNotifications' => true, 'skipFloodCheck' => true, 'skipDupCheck' => true));
		//Make the current user the channel owner.
		$userApi = vB_Api::instanceInternal('user');
		$usergroup = vB::getDbAssertor()->getRow('usergroup', array('systemgroupid' => $ownerSystemGroupId));
		vB_Cache::allCacheEvent(array('nodeChg_' . $this->articleHomeChannel, "nodeChg_$channelid"));
		vB::getUserContext()->rebuildGroupAccess();
		vB_Channel::rebuildChannelTypes();
		// clear follow cache
		vB_Api::instanceInternal('follow')->clearFollowCache(array($input['userid']));
		return $result['nodeid'];
	}

	/**
	 * @uses fetch the id of the global Articles Home Channel
	 * @return int nodeid of actual Articles Home Channel
	 */
	public function getArticleChannel()
	{
		if ($this->articleHomeChannel)
		{
			return $this->articleHomeChannel;
		}
		// use default pagetemplate for blogs
		$articleHomeChannel = vB_Library::instance('content_channel')->fetchChannelByGUID(vB_Channel::DEFAULT_ARTICLE_PARENT);

		if (isset($articleHomeChannel['nodeid']))
		{
			$this->articleHomeChannel = $articleHomeChannel['nodeid'];
		}
		return $this->articleHomeChannel;
	}

	/**
	 * Determines if the given node is under the Articles Home Channel
	 *
	 * @param	int	$nodeid
	 * @return	bool
	 */
	public function isArticleNode($nodeId, $node = false)
	{
		$nodeId = intval($nodeId);
		$articlesRootChannelId = vB_Api::instance('content_channel')->fetchChannelIdByGUID(vB_Channel::DEFAULT_ARTICLE_PARENT);

		if ($nodeId < 0)
		{
			return false;
		}

		if (empty($node))
		{
			$node = vB_Library::instance('node')->getNode($nodeId, true, false);
		}
		if (empty($node['parents']))
		{
			$parents = vB_Library::instance('node')->getParents($nodeId);
			foreach ($parents as $parent)
			{
				if ($parent['nodeid'] == $articlesRootChannelId)
				{
					return true;
				}
			}
			return false;
		}
		return in_array($articlesRootChannelId, $node['parents']);
	}


	/**
	 * 	when adding functions for content creation, do not forget about vB_Api_Node::OPTION_NODE_DISABLE_BBCODE for static pages.
	 */

}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
