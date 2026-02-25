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
 * vB_Library_Content_Channel
 *
 * @package vBLibrary
 * @access public
 */
class vB_Library_Content_Channel extends vB_Library_Content
{
	//override in client- the text name
	protected $contenttype = 'vBForum_Channel';

	//The table for the type-specific data.
	protected $tablename = 'channel';

	protected function buildChannelOptions($nodeid, $options)
	{
		if ($nodeid)
		{
			$prior = vB::getDbAssertor()->getRow('vBForum:channel', array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
				vB_dB_Query::CONDITIONS_KEY => array('nodeid' => $nodeid)
			));
		}

		$value = ($nodeid AND $prior) ? $prior['options'] : 0;
		$forumOptions = vB::getDatastore()->getValue('bf_misc_forumoptions');

		foreach($options AS $name => $on)
		{
			if (isset($forumOptions[$name]))
			{
				if ($on)
				{
					$value = $value | $forumOptions[$name];
				}
				else
				{
					$value = $value & (~$forumOptions[$name]);
				}
			}
		}

		return $value;
	}

	/**
	 * Adds a new channel.
	 *
	 *	@param	mixed		Array of field => value pairs which define the record.
	 *  @param	array		Array of options for the content being created.
	 *  	Understands skipTransaction, skipFloodCheck, floodchecktime, skipDupCheck, skipNotification,
	 *      nodeonly, skipBuildLanguage
	 *		- nodeonly:	Boolean indicating whether extra info for channel should be created (page, routes, etc). Used for importing channels
	 *
	 * 	@return	mixed		array with errors, or nodeid.
	 */
	public function add($data, array $options = array('nodeonly' => false))
	{
		$options += array('skipDupCheck' => true);
		//Store this so we know whether we should call afterAdd()
		$skipTransaction = !empty($options['skipTransaction']);

		// This was added for VBV-833 so that adding a channel in the admincp didn't cause an error
		// if no parent was selected.  However DEFAULT_CHANNEL_PARENT now, unfortunatley and confusingly,
		// refers to the "special channel".  This is almost certainly the wrong behavior.  I suspect that
		// this has not been noticed to date because we can't hit this case in normal operation.  The use
		// case referenced in VBV-833 is not longer possible because we require a parent in the UI.
		if (!isset($data['parentid']) OR $data['parentid'] <= 0)
		{
			// TODO: API will no longer allow this. Remove this code as well at some point.
			//as noted above DEFAULT_CHANNEL_PARENT is the "special" channel.
			$data['parentid'] = $this->fetchChannelIdByGUID(vB_Channel::DEFAULT_CHANNEL_PARENT);
		}
		else
		{
			// if we are not using the default channel parent, we need to check for pagetemplates
			if (!isset($data['templates']))
			{
				$parent = vB::getDbAssertor()->getRow('vBForum:channel', array(
					vB_dB_Query::COLUMNS_KEY => array('nodeid', 'guid'),
					vB_dB_Query::CONDITIONS_KEY => array('nodeid' => $data['parentid'])
				));

				switch($parent['guid'])
				{
					case vB_Channel::DEFAULT_SOCIALGROUP_PARENT:
						// This is done only when saving from activity stream configuration, once it is removed we can get rid of this
						$data['templates']['vB5_Route_Channel'] = vB_Page::getSGCategoryPageTemplate();
						$data['templates']['vB5_Route_Conversation'] = vB_Page::getSGCategoryConversPageTemplate();
						$data['category'] = 1;
						break;
					case vB_Channel::DEFAULT_ARTICLE_PARENT:
						// articles
						$data['templates']['vB5_Route_Channel'] = vB_Page::getArticleChannelPageTemplate();
						$data['templates']['vB5_Route_Conversation'] = vB_Page::getArticleConversPageTemplate();
						break;
					default:
						// use inherited from parent channel
						break;
				}
			}
		}

		if (!isset($data['guid'])) // when importing channels, we already have a guid
		{
			// creating guid
			$data['guid'] = vB_Xml_Export_Channel::createGUID($data);
		}

		// parse options array
		if (isset($data['options']))
		{
			if (is_array($data['options']))
			{
				$value = $this->buildChannelOptions(0, $data['options']);

				if ($value !== FALSE)
				{
					$data['options'] = $value;
				}
				else
				{
					// do not update field
					unset($data['options']);
				}
			}
			else
			{
				// should we accept raw ints as updates?
				unset($data['options']);
			}
		}

		if (empty($data['urlident']) AND !empty($data['title']))
		{
			$data['urlident'] = $this->getUniqueUrlIdent($data['title']);
		}

		if (!isset($options['nodeonly']) || !$options['nodeonly'])
		{
			// if we are going to create pages, verify that prefix/regex generated is valid BEFORE creating the node
			vB5_Route_Channel::validatePrefix($data);
		}

		try
		{
			if (!$skipTransaction)
			{
				$this->assertor->beginTransaction();
			}
			$options['skipTransaction'] = true;
			$result = parent::add($data, $options);

			if (!isset($options['nodeonly']) || !$options['nodeonly'])
			{
				$this->nodeLibrary->clearCacheEvents($result['nodeid']);
				$skipBuildLanguage = !empty($options['skipBuildLanguage']);
				$this->createChannelPages($result['nodeid'], $data, $skipBuildLanguage);
			}

			if (!$skipTransaction)
			{
				$this->beforeCommit($result['nodeid'], $data, $options, $result['cacheEvents'], $result['nodeVals']);
				$this->assertor->commitTransaction();
			}
		}
		catch(exception $e)
		{
			if (!$skipTransaction)
			{
				$this->assertor->rollbackTransaction();
			}
			throw $e;
		}
		//and announce that the cached channel structure has changed.
		$result['cacheEvents'][] = 'vB_ChannelStructure_chg';

		$usercontext = vB::getUserContext();

		if (isset($data['filedataid']) AND
			$usercontext->getChannelPermission('forumpermissions', 'canuploadchannelicon', $result['nodeid']))
		{
			/*
				TODO: This seems like it would allow a *private* filedata to be set to a public icon.
				It seems like that could be problematic:
				E.g. someone uploads a private photo, a mod or admin who can set channel icons but not the first user's
				private albums gets a hold of the filedataid & just sets it to a channel icon.

				So perhaps we should limit this to their own non-publicview filedata records, OR publicview=1 filedata records?

				Update: ATM there's a (coincidental?) filedata API call to fetch the filedata for the specified filedataid in validateIcon()
				which will throw an exception for filedata that the current user has no view perms to, which mitigates this somewhat.
			 */
			$this->qryAfterAdd[] = array('definition' => 'incrementFiledataRefcountAndMakePublic', 'data' => array('filedataid' => $data['filedataid']));
		}

		if (!$skipTransaction)
		{
			$this->afterAdd($result['nodeid'], $data, $options, $result['cacheEvents'], $result['nodeVals']);
		}

		if (!defined('VB_AREA') OR !in_array(VB_AREA, array('Install', 'Upgrade')))
		{
			//we need to potentially update cssasfiles.  Nothing else should be affected so we won't update the child styles
			if (!empty($data['styleid']) AND $data['styleid'] > 0)
			{
				$styleLib->resetForcedStyles();
				$buildStyle = vB_Library::instance('style')->buildStyle($data['styleid'], '', array(), false, false);
			}

			$usercontext->rebuildGroupAccess();
			$usercontext->reloadUserPerms();
			vB_Channel::rebuildChannelTypes();
		}

		return $result;
	}

	public function update($nodeid, $data)
	{
		$db = vB::getDbAssertor();

		// parse options array
		if (isset($data['options']))
		{
			if (is_array($data['options']))
			{
				$data['options'] = $this->buildChannelOptions($nodeid, $data['options']);
			}
			else
			{
				// should we accept raw ints as updates?
				unset($data['options']);
			}
		}

		if (isset($data['styleid']))
		{
			$existing = $db->getRow('vBForum:channel', array('nodeid' => $nodeid));
		}

		$success = parent::update($nodeid, $data);

		// Update page title for the channel
		if (!empty($data['title']))
		{
			$existingRouteId = (int) $db->getField('vBForum:node', array(
				vB_dB_Query::COLUMNS_KEY => array('routeid'),
				'nodeid' => $nodeid,
			));

			if ($existingRouteId > 0)
			{
				$existingPage = $db->getRow('page', array('routeid' => $existingRouteId));

				$db->update('page', array('title' => $data['title']), array('pageid' => $existingPage['pageid']));
				$db->update('page', array('title' => $data['title']), array('parentid' => $existingPage['pageid']));

				// Update title phrase
				$phraseLib = vB_Library::instance('phrase');
				$guidforphrase = $phraseLib->cleanGuidForPhrase($existingPage['guid']);
				$phraseLib->save('pagemeta',
					'page_' . $guidforphrase . '_title',
					array(
						'text' => array($data['title']),
						'product' => $existingPage['product'],
						'oldvarname' => 'page_' . $guidforphrase . '_title',
						'oldfieldname' => 'global',
						'skipdebug' => 1,
					)
				);
				if (isset($data['description']))
				{
					$phraseLib->save('pagemeta',
						'page_' . $guidforphrase . '_metadesc',
						array(
							'text' => array($data['description']),
							'product' => $existingPage['product'],
							'oldvarname' => 'page_' . $guidforphrase . '_metadesc',
							'oldfieldname' => 'global',
							'skipdebug' => 1,
						)
					);
				}
			}
		}

		//if it's not even set, we didn't update it and we don't want to do anything here.
		if (isset($data['styleid']))
		{
			$styleLib = vB_Library::instance('style');
			$styleLib->resetForcedStyles();

			//we need to potentially update cssasfiles.  Nothing else should be affected so we won't update the child styles
			if ($data['styleid'] != $existing['styleid'])
			{
				if ($data['styleid'] > 0)
				{
					$buildStyle = $styleLib->buildStyle($data['styleid'], '', array(), false, false);
				}

				//this won't presently do anything, but if we change the rebuild to properly remove directories
				//when a style is no longer reading from disk then this will be useful.
				if ($existing['styleid'] > 0)
				{
					$buildStyle = $styleLib->buildStyle($existing['styleid'], '', array(), false, false);
				}
			}
		}

		vB_Cache::instance()->event('vB_ChannelStructure_chg');
		vB::getUserContext()->rebuildGroupAccess();
		vB_Channel::rebuildChannelTypes();

		return $success;
	}

	/**
	 * Permanently deletes a channel
	 *	@param	integer	The nodeid of the record to be deleted
	 *
	 *	@return	boolean
	 */
	public function delete($nodeid)
	{
		if (empty($nodeid))
		{
			return false;
		}
		// prevent deleting of top level channels
		if (in_array($nodeid, vB_Api::instanceInternal('content_channel')->fetchTopLevelChannelIds()))
		{
			throw new vB_Exception_Api('cant_delete_top_level');
		}
		// get the direct children.
		$children_nodes = vB::getDbAssertor()->assertQuery('vBForum:getChildrenOnly', array('nodeid' => $nodeid));
		$nodeids = array();
		$children_by_type = array();
		foreach ($children_nodes as $node)
		{
			$children_by_type[$node['contenttypeid']][$node['nodeid']] = $node['nodeid'];
			$nodeids[] = $node['nodeid'];
		}

		foreach ($children_by_type as $contenttypeid => $nodes)
		{
			$contentLib = vB_Library_Content::getContentLib($contenttypeid);
			$contentLib->deleteChildren($nodes);
		}

		if (!empty($nodeids))
		{
			vB_Search_Core::instance()->deleteBulk($nodeids);
		}

		// deleting the node
		$success = parent::delete($nodeid);
		// delete pages and routes
		$this->deleteChannelPages($nodeid);

		vB_Cache::instance()->event('vB_ChannelStructure_chg');
		vB::getUserContext()->rebuildGroupAccess();
		vB_Channel::rebuildChannelTypes();
		return $success;
	}

	/**
	 * Returns the node content as an associative array
	 *	@param	integer	The id in the primary table
	 *	@param	array of permissions request- (array group, permission)
	 *	@return	int
	 */
	public function getFullContent($nodeids, $permissions = false)
	{
		$result = parent::getFullContent($nodeids, $permissions);

		if ($result)
		{
			$forumOptions = vB::getDatastore()->getValue('bf_misc_forumoptions');
			foreach ($result AS $key => $channel)
			{
				$options = array();
				foreach($forumOptions AS $name => $bitfield)
				{
					$options[$name] = ($channel['options'] & $bitfield) ? 1 : 0;
				}

				$result[$key]['options'] = $options;
			}
		}

		return $result;
	}

	/**
	 * Returns the node content as an associative array. Like getFullContent but without the permissions data.
	 *	@param	integer	The id in the primary table
	 *	@return	int
	 */
	public function getBareContent($nodeids)
	{
		$result = parent::getBareContent($nodeids);
		if ($result)
		{
			$forumOptions = vB::getDatastore()->getValue('bf_misc_forumoptions');
			$type = vB_Api_External::TYPE_RSS2;
			$rssinfo = vB_Library::instance('external')->getExternalDataForChannels(array_keys($result), $type);
			foreach ($result AS $key => $channel)
			{
				$options = array();
				foreach($forumOptions AS $name => $bitfield)
				{
					$options[$name] = ($channel['options'] & $bitfield) ? 1 : 0;
				}

				$result[$key]['options'] = $options;
				$result[$key]['rss_enabled'] = $rssinfo[$key][$type . '_enabled'];
				$result[$key]['rss_route'] = $rssinfo[$key][$type . '_route'];
			}
		}

		return $result;
	}



	public function getIndexableFromNode($content, $include_attachments = true)
	{
		$indexableContent = parent::getIndexableFromNode($content, $include_attachments);
		if (!empty($content['description']))
		{
			$indexableContent['description'] = $content['description'];
		}
		return $indexableContent;
	}

	/**
	 * Toggles the channel between acting like a forum (can have threads in it)
	 * and acting like a category (can only have subchannels in it)
	 *
	 * @param bool $makeCategory
	 * @param int $nodeId
	 * @param bool $force - If true, it will force page recreation even if the category field matches
	 * @return boolean
	 * @throws vB_Exception_Api
	 */
	public function switchForumCategory($makeCategory, $nodeId, $force = false)
	{
		$nodeId = intval($nodeId);
		$node = vB_Library::instance('node')->getNodeContent($nodeId);

		if (empty($node))
		{
			throw new vB_Exception_Api('invalid_request');
		}
		else
		{
			$node = $node[$nodeId];
			if ( !$force AND
				(($makeCategory AND $node['category'] == 1) OR (!$makeCategory AND $node['category'] == 0)) )
			{
				// we don't need to do anything
				return true;
			}
		}

		$data = $pageData = array();

		if ($makeCategory)
		{
			if (!$force)
			{
				// check that the node doesn't have any content other than subchannels
				$count = (int) vB::getDbAssertor()->getField('vBForum:getDirectContentCount', array(
					'parentid' => $node['nodeid'],
					'excludeTypes' => array($this->contenttypeid),
				));

				if ($count > 0)
				{
					throw new vB_Exception_Api('cannot_convert_channel');
				}
			}

			$data['category'] = 1;
			$data['options']['cancontainthreads'] = 0;
		}
		else
		{
			$data['category'] = 0;
			$data['options']['cancontainthreads'] = 1;
		}

		// Change the channel to a category or vice-versa
		$response = $this->update($node['nodeid'], $data);

		// If that was successful, modify the pages and routes for the channel/category
		if ($response)
		{
			// Categories have one page and one route (for the channel)
			// Channels/forums have two pages and two routes (one for the channel and one for conversations in the channel)

			if ($makeCategory)
			{
				// Changing from a forum to category-- delete
				// the "Conversation" page and route
				// leaving the "Channel" page and route
				$this->deleteChannelPages($node['nodeid'], false);
			}

			// The "Channel" page and route are already there.
			// If making this a category, the channel page will be updated.
			// If making this a forum, the channel page will be updated and
			// the "Conversation" page & route will be created
			$pageData['title'] = $node['title'];
			$pageData['parentid'] = $node['parentid'];
			$pageData['category'] = $makeCategory ? 1 : 0;
			$this->createChannelPages($node['nodeid'], $pageData);

			return true;
		}
		else
		{
			return false;
		}
	}

	/**
	 * Creates pagetemplate, pages and routes for a channel
	 * @param int nodeid
	 * @param array $data - Must contain the following fields:
	 *		- templates
	 *			- vB5_Route_Channel
	 *			- vB5_Route_Conversation (optional)
	 *		- parentid
	 *		- title
	 *		- page_parentid
	 * @param bool $skipBuildLanguage - Set true to skip rebuilding languages after page
	 *                            phrase (page title, meta description) additions.
	 *                            Sometimes in upgrade steps we add channels in bulk
	 *                            via the content_channel library. In those cases, we don't
	 *                            want to rebuild languages on every single channel add, and
	 *                            wait until the end to rebuild them on one go.
	 */
	protected function createChannelPages($nodeid, $data, $skipBuildLanguage = false)
	{
		$db = vB::getDbAssertor();

		// default to creating a forum/channel, not a category
		if (!isset($data['category']))
		{
			$data['category'] = 0;
		}

		// Default child route & channel/child templates. Note, if you set a childroute,
		// you should also set the $data['templates'][vB5_Route_Channel'] & $data['templates'][$childRoute] appropriately
		$childRoute = (isset($data['childroute']))? $data['childroute'] : 'vB5_Route_Conversation';
		$childTemplate = vB_Page::getConversPageTemplate();
		$channelTemplate = vB_Page::getChannelPageTemplate();

		if (
			!isset($data['templates'])
			||
			!isset($data['templates']['vB5_Route_Channel'])
			||
			!isset($data['templates'][$childRoute])
		)
		{
			$parentChannel = $this->getContent($data['parentid']);
			if (isset($parentChannel[$data['parentid']]))
			{
				$parentChannel = $parentChannel[$data['parentid']];
			}
			if ($parentChannel['category'] != $data['category'])
			{
				// we cannot inherit the templates, use the default ones
				if ($data['category'] > 0)
				{
					$templates['vB5_Route_Channel'] = vB_Page::getCategoryChannelPageTemplate();
				}
				else
				{
					$templates['vB5_Route_Channel'] = $channelTemplate;
					$templates[$childRoute] = $childTemplate;
				}
			}
			else
			{
				// Get page templates used by parent
				$templates = array();
				$parentRoutes = $db->assertQuery('routenew', array(
					vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
					vB_dB_Query::CONDITIONS_KEY => array(
						array('field' => 'class', 'value' => array('vB5_Route_Channel', $childRoute)),
						array('field' => 'contentid', 'value' => $data['parentid']),
						array('field' => 'redirect301', 'operator' =>vB_dB_Query::OPERATOR_ISNULL)
					)
				));
				$routeInfo = array();
				foreach($parentRoutes AS $parentRoute)
				{
					$args = unserialize($parentRoute['arguments']);
					$routeInfo[$parentRoute['class']] = $args['pageid'];
				}
				$parentPages = $db->assertQuery('page', array(
					vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
					vB_dB_Query::CONDITIONS_KEY => array(
						array('field' => 'pageid', 'value' => array_values($routeInfo))
					)
				));
				foreach($parentPages as $parentPage)
				{
					foreach($routeInfo AS $class => $pageId)
					{
						if ($pageId == $parentPage['pageid'])
						{
							// don't use template from forum homepage
							if (($class == 'vB5_Route_Channel') AND ($parentPage['pagetemplateid'] == 1))
							{
								$masterTemplate = vB::getDbAssertor()->getRow('pagetemplate', array('guid' => vB_Page::TEMPLATE_CHANNEL));
								$templates[$class] = $masterTemplate['pagetemplateid'];
							}
							else
							{
								$templates[$class] = $parentPage['pagetemplateid'];
							}
							$parentPageIds[$class] = $pageId;
						}
					}
				}
			}
		}
		else
		{
			$templates = $data['templates'];
			unset($data['templates']);
		}

		// check if the main channel page already exists
		$existingRouteId = (int) vB::getDbAssertor()->getField('vBForum:node',
			array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
				vB_dB_Query::COLUMNS_KEY => array('routeid'),
				vB_dB_Query::CONDITIONS_KEY => array(
					array('field' => 'nodeid', 'value' => $nodeid, 'operator' => vB_dB_Query::OPERATOR_EQ),
				),
			)
		);
		if ($existingRouteId > 0)
		{
			$existingPage = vB::getDbAssertor()->getRow('page',
				array(
					vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
					vB_dB_Query::CONDITIONS_KEY => array(
						array('field' => 'routeid', 'value' => $existingRouteId, 'operator' => vB_dB_Query::OPERATOR_EQ),
					),
				)
			);
		}
		else
		{
			$existingPage = array();
		}

		$phraseLib = vB_Library::instance('phrase');
		if (empty($existingPage))
		{
			// Create main channel page
			$page['guid'] = vB_Xml_Export_Page::createGUID(array());
			$page['pagetemplateid'] = $templates['vB5_Route_Channel'];
			$page['title'] = $data['title'];
			$page['pagetype'] = vB_Page::TYPE_CUSTOM;
			$page['parentid'] = isset($data['page_parentid']) ? $data['page_parentid'] : (isset($parentPageIds['vB5_Route_Channel']) ? $parentPageIds['vB5_Route_Channel'] : 0);
			$pageid = $db->insert('page', $page);
			if (is_array($pageid))
			{
				$pageid = (int) array_pop($pageid);
			}

			$guidforphrase = vB_Library::instance('phrase')->cleanGuidForPhrase($page['guid']);

			$newpage = vB::getDbAssertor()->getColumn('page', 'product', array('pageid' => $pageid));
			$productid = array_pop($newpage);

			$phraseLib->save('pagemeta',
				'page_' . $guidforphrase . '_title',
				array(
					'text' => array($page['title']),
					'product' => $productid,
					'oldvarname' => 'page_' . $guidforphrase . '_title',
					'oldfieldname' => 'global',
					'skipdebug' => 1,
				),
				true
			);
			if (isset($data['description']))
			{
				$phraseLib->save('pagemeta',
					'page_' . $guidforphrase . '_metadesc',
					array(
						'text' => array($data['description']),
						'product' => $productid,
						'oldvarname' => 'page_' . $guidforphrase . '_metadesc',
						'oldfieldname' => 'global',
						'skipdebug' => 1,
					),
					true
				);
			}

			// Create route for main channel page
			$route_data = array(
				'nodeid' => $nodeid,
				'pageid' => $pageid,
			);

			if (!empty($data['routeguid']))
			{
				$route_data['guid'] = $data['routeguid'];
			}

			if (!empty($data['urlident']))
			{
				$route_data['urlident'] = $data['urlident'];
			}

			$channelRouteId = vB5_Route_Channel::createRoute('vB5_Route_Channel', $route_data);
			if (is_array($channelRouteId))
			{
				$channelRouteId = (int) array_pop($channelRouteId);
			}

			$db->update('vBForum:node', array('routeid' => $channelRouteId), array('nodeid' => $nodeid));
			$db->update('page', array('routeid' => $channelRouteId), array('pageid' => $pageid));
		}
		else
		{
			//Update the existing main channel page
			$page['pagetemplateid'] = $existingPage['pagetemplateid'];
			$page['title'] = $data['title'];
			$page['pagetype'] = $existingPage['pagetype'];
			$page['parentid'] = isset($data['page_parentid']) ? $data['page_parentid'] : (isset($parentPageIds['vB5_Route_Channel']) ? $parentPageIds['vB5_Route_Channel'] : 0);

			$pageid = $existingPage['pageid'];
			$db->update('page', $page, array('pageid' => $pageid));

			$productid = $existingPage['product'];
		}

		vB_Cache::instance(vB_Cache::CACHE_FAST)->event("nodeChg_$nodeid");
		vB_Cache::instance()->event("nodeChg_$nodeid");

		if ($data['category'] == 0 AND isset($templates[$childRoute]) AND !empty($templates[$childRoute]))
		{
			// Create the conversation page
			$page['guid'] = vB_Xml_Export_Page::createGUID(array());
			$page['pagetemplateid'] = $templates[$childRoute];
			$page['title'] = $data['title'];
			$page['pagetype'] = vB_Page::TYPE_DEFAULT;
			$page['parentid'] = $pageid;
			$pageid = $db->insert('page', $page);
			if (is_array($pageid))
			{
				$pageid = (int) array_pop($pageid);
			}

			$guidforphrase = vB_Library::instance('phrase')->cleanGuidForPhrase($page['guid']);
			$phraseLib->save('pagemeta',
				'page_' . $guidforphrase . '_title',
				array(
					'text' => array($page['title']),
					'product' => $productid,
					'oldvarname' => 'page_' . $guidforphrase . '_title',
					'oldfieldname' => 'global',
					'skipdebug' => 1,
				),
				true
			);
			if (isset($data['description']))
			{
				$phraseLib->save('pagemeta',
					'page_' . $guidforphrase . '_metadesc',
					array(
						'text' => array($data['description']),
						'product' => $productid,
						'oldvarname' => 'page_' . $guidforphrase . '_metadesc',
						'oldfieldname' => 'global',
						'skipdebug' => 1,
					),
					true
				);
			}

			// Create route for conversation page
			$conversationRouteId = call_user_func(array($childRoute, 'createRoute'), $childRoute, array(
				'channelid'	=> $nodeid,
				'pageid'	=> $pageid
			));
			if (is_array($conversationRouteId))
			{
				$conversationRouteId = (int) array_pop($conversationRouteId);
			}

			$db->update('page', array('routeid' => $conversationRouteId), array('pageid' => $pageid));
		}

		if (!$skipBuildLanguage)
		{
			// Rebuild all languages after phrase additions in 1 go instead of doing it 2-4 times.
			vB_Library::instance('language')->rebuildAllLanguages();
		}
	}

	/**
	 * Deletes pages and routes for a channel
	 *
	 * @param	int	$nodeId
	 * @param	bool	true to delete both channel and conversation pages/routes
	 *			false to only delete the conversation page/route, and leave the channel page/route
	 *			false is used when converting a channel to a category
	 */
	protected function deleteChannelPages($nodeId, $deleteAll = true)
	{
		if ($deleteAll)
		{
			$routeClasses = array(
				'vB5_Route_Channel',
				'vB5_Route_Conversation',
				'vB5_Route_Article',
			);
		}
		else
		{
			$routeClasses = array(
				'vB5_Route_Conversation',
				'vB5_Route_Article',
			);
		}

		// get the routes involved with this channel
		$routes = vB::getDbAssertor()->getRows('routenew', array(
			vB_dB_Query::CONDITIONS_KEY => array(
				array('field' => 'contentid', 'value' => $nodeId, 'operator' => vB_dB_Query::OPERATOR_EQ),
				array('field' => 'class', 'value' => $routeClasses, 'operator' => vB_dB_Query::OPERATOR_EQ)
			)
		), false, 'routeid');

		if (!empty($routes))
		{
			// delete the routes
			vB::getDbAssertor()->delete('routenew', array(
				array('field' => 'routeid', 'value' => array_keys($routes), 'operator' => vB_dB_Query::OPERATOR_EQ)
			));

			// delete the pages
			vB::getDbAssertor()->delete('page', array(
				array('field' => 'routeid', 'value' => array_keys($routes), 'operator' => vB_dB_Query::OPERATOR_EQ)
			));

			// We do not remove the routeid in the associated channel node record here
			// since we are calling this because we have already deleted the node,
			// or because we are switching the channel from acting as a forum/channel
			// to acting as a category (or the other way around), and the main
			// channel page/route still exist and will be used
		}
	}

	public function getForumHomeChannel()
	{
		$forumChannel = $this->fetchChannelByGUID(vB_Channel::DEFAULT_FORUM_PARENT);
		return vB_Library::instance('node')->getNodeBare($forumChannel['nodeid']);
	}

	public function getMainChannel()
	{
		$forumChannel = $this->fetchChannelByGUID(vB_Channel::MAIN_CHANNEL);
		return vB_Library::instance('node')->getNodeBare($forumChannel['nodeid']);
	}

	/**
	 * This creates an urlident from a title, and guarantees it will not be a duplicate
	 *
	 * @param	string	the title
	 * @return	string
	 */
	public function getUniqueUrlIdent($title)
	{
		//first see if this is good. Note that we don't care if it's used for a node that isn't a channel.
		$candidate = vB_String::getUrlIdent($title);
		$check = $this->assertor->getRow('vBForum:node', array(
		 	'urlident' => $candidate,
			'contenttypeid' => $this->contenttypeid,
		));

		if (empty($check) OR !empty($check['errors']))
		{
			return $candidate;
		}
		//So now we try adding _a, b, c, etc.  If we get to z we'll throw an exception.
		$charVal = ord('a');
		$charVal2 = ord('a');
		while (true)
		{
			if ($charVal >= ord('z') AND $charVal2 >= ord('z'))
			{
				throw new vB_Exception_Api('invalid_data' . $candidate . '-' . chr($charVal) . chr($charVal2) );
			}

			$check = $this->assertor->getRow('vBForum:node', array(
				'urlident' => $candidate . '-' . chr($charVal) . chr($charVal2),
				'contenttypeid' => $this->contenttypeid,
			));

			if (empty($check) OR !empty($check['errors']))
			{
				return $candidate . '-' . chr($charVal) . chr($charVal2);
			}

			$charVal2++;

			if ($charVal2 >= ord('z'))
			{
				$charVal++;
				$charVal2 = ord('a');
			}
		}
	}

	/**
	 * Returns a channel record based on its node guid
	 *
	 * @param	string	GUID
	 *
	 * @return	array	Channel information
	 */
	public function fetchChannelByGUID($guid)
	{
		$cache = vB_Cache::instance(vB_Cache::CACHE_FAST);
		$channel = $cache->read('vbChannelGUID_' . $guid);
		if (!empty($channel))
		{
			return $channel;
		}

		$parentChannelGUIDs = vB_Channel::getDefaultGUIDs();
		$parentChannels = vB::getDbAssertor()->assertQuery('vBForum:channel', array('guid' => $parentChannelGUIDs));
		$channel = array();
		foreach ($parentChannels as $parentChannel)
		{
			$cache->write('vbChannelGUID_' . $parentChannel['guid'], $parentChannel, 1440, 'nodeChg_' . $parentChannel['nodeid']);
			if ($parentChannel['guid'] == $guid)
			{
				$channel = $parentChannel;
			}
		}

		return $channel;
	}

	/**
	 * Returns a channel id based on its node guid
	 *
	 * @param  string Channel GUID
	 *
	 * @return int    Channel id
	 */
	public function fetchChannelIdByGUID($guid)
	{
		$channel = $this->fetchChannelByGUID($guid);
		return empty($channel) ? false : $channel['nodeid'];
	}

	/**
	 * This function either deletes the channel if it has no children, or fixes it.
	 *
	 * @param	mixed	node record, which may have missing child table data.
	 */
	public function incompleteNodeCleanup($node)
	{
		//If we have child records we should create an empty text table record.
		$children = $this->assertor->assertQuery('vBForum:node', array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT, 'parentid' => $node['nodeid']));

		if ($children->valid())
		{
			//We need to make sure we have text and gallery records.
			$data = array('nodeid' => $node['nodeid'], 'category' => 0);
			$data['guid'] = vB_Xml_Export_Channel::createGUID($data);
			$data[vB_dB_Query::TYPE_KEY] = vB_dB_Query::QUERY_INSERT;
			$this->assertor->assertQuery('vBForum:channel', $data);
			vB_Cache::allCacheEvent(array('nodeChg_' . $node['parentid'], 'nodeChg_' . $node['nodeid']));
			vB_Library::instance('node')->clearCacheEvents($node['nodeid']);
		}
		else
		{
			//just delete
			parent::incompleteNodeCleanup($node);
		}
	}

	/**
	 * Assembles the response for detailed content
	 *
	 *	@param	mixed	assertor response object
	 *	@param	mixed	optional array of permissions
	 *
	 *	@return	mixed	formatted data
	 */
	public function assembleContent(&$content, $permissions = false)
	{
		$nodesContent = parent::assembleContent($content, $permissions);

		$results = array();
		$type = vB_Api_External::TYPE_RSS2;
		$rssinfo = vB_Library::instance('external')->getExternalDataForChannels(array_keys($nodesContent), $type);
		foreach($nodesContent AS $record)
		{
			$results[$record['nodeid']] = $record;
			$results[$record['nodeid']]['rss_enabled'] = $rssinfo[$record['nodeid']][$type . '_enabled'];
			$results[$record['nodeid']]['rss_route'] = $rssinfo[$record['nodeid']][$type . '_route'];
		}

		return $results;
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 103456 $
|| #######################################################################
\*=========================================================================*/
