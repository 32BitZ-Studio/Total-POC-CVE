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
/*
if (!isset($GLOBALS['vbulletin']->db))
{
	exit;
}
*/

class vB_Upgrade_552b1 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '552b1';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.5.2 Beta 1';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.5.2 Alpha 4';

	/**
	* Beginning version compatibility
	*
	* @var	string
	*/
	public $VERSION_COMPAT_STARTS = '';

	/**
	* Ending version compatibility
	*
	* @var	string
	*/
	public $VERSION_COMPAT_ENDS   = '';

	/**
	 * Fix the incorrect pagetemplateid for pages associated with Group channels
	 * that existed when the installation was upgraded from vB4. They were using
	 * the default page template for forum topics (vB_Page::TEMPLATE_CONVERSATION)
	 * instead of the default page template for group topics which is
	 * vB_Page::TEMPLATE_SOCIALGROUPCONVERSATION. If there are group channel pages
	 * that are using the incorrect *default* they will be changed to the correct
	 * default. If they are using any other page template (for example, a custom
	 * page template), they will not be changed.
	 */
	public function step_1()
	{
		$assertor = vB::getDbAssertor();

		// create a lookup table for all group channels
		$groupParentChannel = $assertor->getRow('vBForum:channel', array('guid' => vB_Channel::DEFAULT_SOCIALGROUP_PARENT));
		$channelNodeIds = $assertor->getColumn('vBForum:channel', 'nodeid', array());
		$groupChannelLookup = $assertor->getColumn('vBForum:closure', 'child', array(
			'parent' => $groupParentChannel['nodeid'],
			'child' => $channelNodeIds,
		), false, 'child');

		// scan all conversation (topic) routes to isolate the ones that
		// are for group topic pages, based on the route arguments
		$groupChannelPageIds = array();
		$routes = $assertor->getRows('routenew', array('class' => 'vB5_Route_Conversation'));
		foreach ($routes AS $route)
		{
			$args = array();
			if (!empty($route['arguments']))
			{
				$temp = unserialize($route['arguments']);
				if ($temp)
				{
					$args = $temp;
				}
			}

			if (!empty($args['channelid']))
			{
				$channelId = (int) $args['channelid'];
				if (!empty($groupChannelLookup[$channelId]))
				{
					$pageId = (int) $args['pageid'];
					if ($pageId)
					{
						$groupChannelPageIds[] = $pageId;
					}
				}
			}
		}

		// if we have group channel pages, check if any of them need to be updated
		$updated = 0;
		if (!empty($groupChannelPageIds))
		{
			// get pages that need to be updated
			$conversationPageTemplate = $assertor->getRow('pagetemplate', array('guid' => vB_Page::TEMPLATE_CONVERSATION));
			$conditions = array(
				'pagetemplateid' => $conversationPageTemplate['pagetemplateid'],
				'pageid' => $groupChannelPageIds,
			);
			$pageIds = $assertor->getColumn('vBForum:page', 'pageid', $conditions);

			if (!empty($pageIds))
			{
				// we found some pages that have this issue
				// update the pagetemplate from the default forum topic page template
				// to the default group topic page template
				$groupConversationPageTemplate = $assertor->getRow('pagetemplate', array('guid' => vB_Page::TEMPLATE_SOCIALGROUPCONVERSATION));
				$values = array(
					'pagetemplateid' => $groupConversationPageTemplate['pagetemplateid'],
				);
				$updated = $assertor->update('vBForum:page', $values, $conditions);
			}
		}

		// tell the user what we did
		if ($updated)
		{
			$this->show_message(sprintf($this->phrase['version']['552b1']['updating_group_topic_page_templates_x'], $updated));
		}
		else
		{
			$this->skip_message();
		}
	}
}

/*======================================================================*\
|| ####################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 101436 $
|| ####################################################################
\*======================================================================*/