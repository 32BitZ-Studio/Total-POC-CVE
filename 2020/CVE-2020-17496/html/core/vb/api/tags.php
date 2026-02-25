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
 * vB_Api_Tags
 *
 * @package vBApi
 * @access public
 */
class vB_Api_Tags extends vB_Api
{
	protected $tagsObj = array();
	protected $errors = null;
	protected $library = null;

	public function __construct()
	{
		parent::__construct();

		$this->library = vB_Library::instance('tags');
	}

	/**
	 * Adds new tags and/or deletes tags (added by the current user) if they have removed them from the list
	 *
	 * @param	int	Node ID
	 * @param	array	List of tags
	 *
	 * @return	array 	List of all tags on the node
	 */
	public function updateUserTags($nodeid, array $taglist = array())
	{
		$nodeid = (int) $nodeid;
		$userid = (int) vB::getUserContext()->fetchUserId();

		if (empty($this->tagsObj[$nodeid]))
		{
			$this->tagsObj[$nodeid] = new vB_Tags($nodeid);
		}

		$nodeTagInfo = $this->getNodeTags($nodeid);
		$nodeTags = $nodeTagInfo['tags'];

		$canManageTags = $this->tagsObj[$nodeid]->canManageTag();

		$remove = array();
		foreach ($nodeTags AS $tag)
		{
			if ($tag['userid'] == $userid OR $canManageTags)
			{
				if (!in_array($tag['tagtext'], $taglist))
				{
					$remove[] = $tag['tagtext'];
				}
			}
		}

		$return = true;

		if (!empty($remove))
		{
			$return = $this->removeTags($nodeid, $remove);
		}
		if (!empty($taglist))
		{
			$return = $this->addTags($nodeid, $taglist);
		}

		return $return;
	}

	/**
	 * Add tags to the current item
	 * implements vB_Tag::addTagsToContent
	 *
	 * @param	NodeId
	 * @param	Taglist to add
	 *
	 * @return	Comma-separated list of all tags on the node
	 */
	public function addTags($nodeid, $taglist)
	{
		$nodeid = (int) $nodeid;

		if ($nodeid < 1)
		{
			throw new vB_Exception_Api('invalid_data_w_x_y_z', array($nodeid, '$nodeid', __CLASS__, __FUNCTION__));
		}

		if (empty($this->tagsObj[$nodeid]))
		{
			$this->tagsObj[$nodeid] = new vB_Tags($nodeid);
		}

		$errors = $this->tagsObj[$nodeid]->addTagsToContent($taglist);
		if (sizeof($errors) > 0)
		{
			throw $this->getExceptionFromErrors($errors);
		}

		$tags = $this->getNodeTags($nodeid);

		// addTags() is called by both add (calls addTags) and update (calls updateUserTags, which calls addTags)
		$this->monitorWordsInTags($nodeid, $tags);

		return $tags;
	}

	protected function monitorWordsInTags($nodeid, $nodeTagInfo = false)
	{
		if (!$nodeTagInfo)
		{
			$nodeTagInfo = $this->getNodeTags($nodeid);
		}

		if (!$nodeTagInfo)
		{
			return;
		}

		$tags = array();
		foreach ($nodeTagInfo['tags'] AS $tag)
		{
			$tags[] = $tag['tagtext'];
		}

		// Check for monitored words and send notifications
		if (!empty($tags))
		{
			$this->library->monitorWords(implode(' ', $tags), 'node-tags', $nodeid);
		}
	}

	/**
	 * Checks if the taglist contains invalid tags
	 *
	 * @param  [string|array]  $taglist [Comma separated string or an array with the tags]
	 * @param  integer $nodeid  		[The nodeid of the node the tags belong. If 0 this is done on node entry]
	 * @throws vB_Exception_Api
	 * @return [array] $errorArray [Array with the errors if any]
	 */
	public function validTags($taglist, $nodeid = 0)
	{
		if (empty($this->tagsObj[$nodeid]))
		{
			$this->tagsObj[$nodeid] = new vB_Tags($nodeid);
		}

		$errorArray = array();
		$this->tagsObj[$nodeid]->filterTagList($taglist, $errorArray);

		if (sizeof($errorArray) > 0)
		{
			throw $this->getExceptionFromErrors($errorArray);
		}

		return true;
	}

	/*
	 * @uses   Inserts new tags to database; node independent
	 * @param  String, TagText
	 * @return Mixed, response
	 */
	public function insertTags($tagtext)
	{
		if (!vB::getUserContext()->hasPermission('genericpermissions', 'cancreatetag'))
		{
			throw new vB_Exception_Api('tag_no_create');
		}

		$response = array();
		$exception = new vB_Exception_Api();
		$tagdm = new vB_DataManager_Tag(vB_DataManager_Constants::ERRTYPE_ARRAY);
		if ($tagdm->fetch_by_tagtext($tagtext))
		{
			$exception->add_error("tag_exists", array());
		}

		if ($tagtext AND is_string($tagtext))
		{
			require_once(DIR . '/includes/class_taggablecontent.php');
			$valid = vB_Taggable_Content_Item::filter_tag_list(array($tagtext), $errors, false);
		}
		else
		{
			$exception->add_error("invalid_tag_value", array());
		}

		if (!empty($valid))
		{
			$tagdm->set('tagtext', $valid[0]);
			$tagdm->set('dateline', vB::getRequest()->getTimeNow());
			if ($tagdm->errors)
			{
				$exception->add_error($tagdm->errors, array());
			}
			$tagdm->save();
			$response['result'] = true;
		}
		else
		{
			if (!empty($errors))
			{
				foreach ($errors as $error)
				{
					$phraseid = $error[0];
					unset($error[0]);
					$exception->add_error($phraseid, $error);
				}
			}
			else
			{
				$exception->add_error("invalid_tag_value", array());
			}
		}

		//Exception Handling
		if ($exception->has_errors())
		{
			throw $exception;
		}

		return $response;
	}

	/**
	 * Sets the tag matching tag text (case insensitive) to the exact text given
	 * Used to fix case when merging tags.
	 *
	 * @param	String, tag text
	 * @return	array ('result', response
	 */
	public function updateTags($tagtext)
	{
		$this->checkHasAdminPermission('canadmintags');

		$response = array();
		$exception = new vB_Exception_Api();
		$tagdm = new vB_DataManager_Tag(vB_DataManager_Constants::ERRTYPE_ARRAY);
		if (!$tagdm->fetch_by_tagtext($tagtext))
		{
			$exception->add_error("tag_not_exist", array());
		}
		else
		{
			$tagdm->set('tagtext', $tagtext);
			$tagdm->set('dateline', vB::getRequest()->getTimeNow());
			if ($tagdm->errors)
			{
				$exception->add_error($tagdm->errors, array());
			}
			$response['result'] = $tagdm->save();
		}

		//Exception Handling
		if ($exception->has_errors())
		{
			throw $exception;
		}

		return $response;
	}

	/**
	 * @uses	Create new tag for synonim tags
	 * @param	Array, Array of tags to merge
	 * @param	Integer, Id of canonical tag
	 * @return	Mixed response
	 */
	public function createSynonyms($tagList, $targetid)
	{
		$this->checkHasAdminPermission('canadmintags');

		$exception = new vB_Exception_Api();
		$mergetagdm = new vB_DataManager_Tag(vB_DataManager_Constants::ERRTYPE_ARRAY);

		//clear existing because they may be changed here.
		$this->tagsObj = array();

		$target = new vB_DataManager_Tag(vB_DataManager_Constants::ERRTYPE_ARRAY);
		if (!$x= $target->fetch_by_id($targetid))
		{
			throw new vB_Exception_Api('tag_not_exist');
		}

		//if our targe is a synonym, make sure that we merge to its canonical tag
		if ($target->is_synonym())
		{
			$targetid = $target->fetch_field('canonicaltagid');
		}

		/*
		//Check that target tag exists
		$target = vB::getDbAssertor()->getRow('vBForum:tag',
			array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
				'tagid' => $targetid)
		);

		if (!$target)
		{
			throw new vB_Exception_Api('tag_not_exist');
		}
		 */

		//Make synonym for every tag in the list
		foreach ($tagList AS $mergetagid)
		{
			if ($mergetagid == $targetid)
			{
				//making a tag a synonym of itself will cause bad things to happen.
				continue;
			}
			if ($mergetagdm->fetch_by_id($mergetagid))
			{
				$mergetagdm->make_synonym($targetid);
			}
			else
			{
				$exception->add_error("tag_not_exist", array());
			}
		}

		if ($mergetagdm->errors)
		{
			throw $mergetagdm->get_exception();
		}
		else
		{
			$response['result'] = true;
		}

		//Exception Handling
		if ($exception->has_errors())
		{
			throw $exception;
		}

		return $response;
	}

	/**
	 * @uses	Promote tags
	 * @param	int|array     Tag id or array of tag ids
	 *
	 * @return	True if success
	 */
	public function promoteTags($taglist)
	{
		$this->checkHasAdminPermission('canadmintags');
		$exception = new vB_Exception_Api();

		if(!is_array($taglist))
		{
			$taglist = array($taglist);
		}

		//Check that tags exist and they are synonyms
		$target = vB::getDbAssertor()->assertQuery('vBForum:tag', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'tagid' => $taglist
		));

		if ($target AND $target->valid())
		{
			foreach ($target as $tag)
			{
				$existTag = array();
				if ($tag['canonicaltagid'] == 0)
				{
					$existTag[] = $tag['tagid'];
				}
			}

			$taglist = array_diff($taglist, $existTag);

			if (!empty($taglist))
			{
				foreach ($taglist as $tagid)
				{
					$tagdm = new vB_DataManager_Tag(vB_DataManager_Constants::ERRTYPE_ARRAY);
					if ($tagdm->fetch_by_id($tagid))
					{
						$tagdm->make_independent();
					}
					if ($tagdm->errors)
					{
						throw $tagdm->get_exception();
					}
				}
				if (!$tagdm->errors)
				{
					$response['result'] = true;
				}
			}
			else
			{
				$exception->add_error("cant_promote_tag_to_tag", array());
			}
		}
		else
		{
			$exception->add_error("tag_not_exist", array());
		}

		//Exception Handling
		if ($exception->has_errors())
		{
			throw $exception;
		}

		return $response;
	}

	/**
	 * Get synonyms of a given tag
	 * @param integer $tagid
	 * @return array 'tags' => array of $tagid => $tagtext for the synonyms of $tagid
	 */
	public function getTagSynonyms($tagid)
	{
		$exists = vB::getDbAssertor()->getRow('vBForum:tag', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
			vB_dB_Query::COLUMNS_KEY => array('tagid'),
			'tagid' => $tagid,
		));

		if (!$exists)
		{
			throw new vB_Exception_Api('tag_not_exist');
		}

		$set = vB::getDbAssertor()->assertQuery('vBForum:tag',
			array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
				vB_dB_Query::COLUMNS_KEY => array('tagid', 'tagtext'),
				'canonicaltagid' => $tagid,
			),
			array('field' => 'tagtext', 'direction' => vB_dB_Query::SORT_ASC)
		);

		$tags = array();
		foreach($set AS $tag)
		{
			$tags[$tag['tagid']] = $tag['tagtext'];
		}

		return array('tags' => $tags);
	}

	/**
	 * Remove tags from an item
	 * Implements vB_Tag::deleteTag
	 *
	 * @param	NodeId
	 * @param	Tags to delete (if not specified it will delete all tags from node).
	 * @return standard success array
	 */
	public function removeTags($nodeid, $tags = '')
	{
		$nodeid = (int) $nodeid;

		if ($nodeid < 1)
		{
			throw new vB_Exception_Api('invalid_data_w_x_y_z', array($nodeid, '$nodeid', __CLASS__, __FUNCTION__));
		}

		if (empty($this->tagsObj[$nodeid]))
		{
			$this->tagsObj[$nodeid] = new vB_Tags($nodeid);
		}

		if($this->tagsObj[$nodeid]->canManageTag())
		{
			$errors = $this->tagsObj[$nodeid]->deleteTags($tags);
			if (sizeof($errors))
			{
				throw $this->getExceptionFromErrors($errors);
			}
		}
		else
		{
			$userid = vB::getUserContext()->fetchUserId();
			$node = vB_Library::instance('node')->getNodeBare($nodeid);

			if ($userid == $node['userid'])
			{
				// try deleting tags one by one (a user can delete tags they added)
				$nodeTags = $this->getNodeTags($nodeid);
				$nodeTagsByText = array();
				foreach ($nodeTags['tags'] AS $nodeTag)
				{
					$nodeTagsByText[$nodeTag['tagtext']] = $nodeTag;
				}

				if (!is_array($tags))
				{
					$tags = $this->tagsObj[$nodeid]->splitTagList($tags);
				}

				$deleteTags = array();
				foreach ($tags AS $tag)
				{
					if (!empty($nodeTagsByText[$tag]))
					{
						if ($nodeTagsByText[$tag]['userid'] == $userid)
						{
							// this user added this tag, so they can delete it
							$deleteTags[] = $tag;
						}
					}
				}
				if (!empty($deleteTags))
				{
					$errors = $this->tagsObj[$nodeid]->deleteTags($deleteTags);
					if (sizeof($errors))
					{
						throw $this->getExceptionFromErrors($errors);
					}
				}
			}
			else
			{
				throw new vB_Exception_Api('no_permission');
			}
		}

		return array('success' => true);
	}

	/**
	 * @uses		Deletes tag from database, node independent function
	 * @param	Array Tags Id to delete
	 * @return standard success array
	 */
	public function killTags($killTagList)
	{
		$this->checkHasAdminPermission('canadmintags');

		if (!is_array($killTagList))
		{
			$killTagList = array($killTagList);
		}

		$exception = new vB_Exception_Api();
		$killtagdm = new vB_DataManager_Tag(vB_DataManager_Constants::ERRTYPE_ARRAY);

		//clear existing because they may be changed here.
		$this->tagsObj = array();

		//Check that tags exist and they are synonyms
		$target = vB::getDbAssertor()->assertQuery('vBForum:tag',
			array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
				'tagid' => $killTagList
			)
		);
		if ($target AND $target->valid())
		{
			foreach ($killTagList AS $killtagid)
			{
				if ($killtagdm->fetch_by_id($killtagid))
				{
					$killtagdm->delete();
				}
			}
		}
		else
		{
			$exception->add_error("tag_not_exist", array());
		}

		//Exception Handling
		if ($exception->has_errors())
		{
			throw $exception;
		}

		return array('success' => true);
	}

	/**
	 * Gets the tag list from an specific node.
	 * Implements vB_Tags::fetchExistingTagList
	 *
	 * @param	NodeId
	 *
	 * @return	The taglist from node
	 */
	public function getTagsList($nodeid)
	{
		if (empty($this->tagsObj[$nodeid]))
		{
			$this->tagsObj[$nodeid] = new vB_Tags($nodeid);
		}
		return $this->tagsObj[$nodeid]->fetchExistingTagList();
	}

	/**
	 * Merge tags from nodes.
	 * Implements vB_Tags::mergeTagAttachments
	 *
	 * @param	int $nodeid
	 * @param	array $sourceids array of nodeids to merge tags from
	 * @return standard success array
	 */
	public function mergeTags($nodeid, $sourceids)
	{
		if (!is_array($sourceids))
		{
			throw new vB_Exception_Api('invalid_data_w_x_y_z', array($sourceids, 'sourceids', __CLASS__, __FUNCTION__));
		}

		if (empty($this->tagsObj[$nodeid]))
		{
			$this->tagsObj[$nodeid] = new vB_Tags($nodeid);
		}

		$this->tagsObj[$nodeid]->mergeTagAttachments($sourceids);
		return array('success' => true);
	}

	/**
	 * Move tags from one node to another one.
	 * Implements vB_Tags::moveTagAttachments
	 *
	 * @param	TargetNodeId (Node to move tags in)
	 * @param	SourceNodeId (Node to move tags from)
	 * @return standard success array
	 */
	public function moveTags($nodeid, $sourceid)
	{
		if (empty($this->tagsObj[$nodeid]))
		{
			$this->tagsObj[$nodeid] = new vB_Tags($nodeid);
		}

		//If we have the existing tags loaded in the source file we need to remove them.
		if (is_array($sourceid))
		{
			foreach ($sourceid as $removeid)
			{
				if (array_key_exists($removeid, $this->tagsObj))
				{
					//there is no public method to clear the
					unset($this->tagsObj[$sourceid]);
				}
			}

		}
		else
		{
			if (array_key_exists($sourceid, $this->tagsObj))
			{
				//there is no public method to clear the
				unset($this->tagsObj[$sourceid]);
			}
		}
		$this->tagsObj[$nodeid]->moveTagAttachments($sourceid);
		return array('success' => true);
	}

	/**
	 * Copy tags from a node to another one.
	 * Implements vB_Tags::copyTagAttachments.
	 *
	 * @param	TargetNodeId (Node to copy tags in)
	 * @param	SourceNodeId (Node to copy tags from)
	 * @return standard success array
	 */
	public function copyTags($nodeid, $sourceid)
	{
		if (empty($this->tagsObj[$nodeid]))
		{
			$this->tagsObj[$nodeid] = new vB_Tags($nodeid);
		}
		$this->tagsObj[$nodeid]->copyTagAttachments($sourceid);
		return array('success' => true);
	}

	/**
	 * Get tags with full info (userid, tagid, tagtext) from node.
	 * Implements vB_Tags::getNodeTags
	 *
	 * @param	NodeId
	 * @return	Tags from node
	 */
	public function getNodeTags($nodeid)
	{
		if (empty($this->tagsObj[$nodeid]))
		{
			$this->tagsObj[$nodeid] = new vB_Tags($nodeid);
		}

		$userid = vB::getUserContext()->fetchUserId();
		$limits = $this->tagsObj[$nodeid]->fetchTagLimits();

		$tags = $this->tagsObj[$nodeid]->getNodeTags();

		$displaytags = array();
		if (!empty($tags))
		{
			foreach ($tags AS $k => $tag)
			{
				$displaytags[] = $tag['tagtext'];

				$tags[$k]['searchurl'] = vB5_Route::buildUrl('search|fullurl', array(), array('searchJSON' => json_encode(array('tag' => $tag['tagtext']))));
			}
		}
		$displaytags = implode(', ', $displaytags);

		return array(
			'tags' => $tags,
			'displaytags' => $displaytags,
			'userid' => $userid,
			'nodeid' => $nodeid,
			'maxtags' => $limits['content_limit'],
			'maxusertags' => $limits['user_limit'],
			'canmanagetags' => $this->tagsObj[$nodeid]->canManageTag(),
		);
	}

	public function getAutocomplete($searchStr, $limitstart = 0, $limitnumber = 25)
	{
		$query = vB::getDbAssertor()->assertQuery(
			'vBForum:getPopularTags', array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_METHOD,
				'searchStr' => $searchStr,
				 vB_dB_Query::PARAM_LIMIT => $limitnumber,
				'offset' => $limitstart
			)
		);
		$popular_tags = array();

		while($query AND $query->valid() AND $tag = $query->current())
		{
			$popular_tags[] = array(
				'title' =>	$tag['tagtext'],
				'value' =>	$tag['userid'],
				'id' =>		$tag['tagid']
			);
			$query->next();
		}
		return array('suggestions' => $popular_tags);
	}

	/**
	 * Get an array of tags for building tag cloud
	 *
	 * @param int $levels Tag cloud levels
	 * @param int $limit How many tags to be fetched
	 * @param string $type The type of tag cloud
	 * @return array
	 */
	public function fetchTagsForCloud($taglevels = 5, $limit = 20, $type = 'nodes')
	{
		switch ($type) {
			case 'search':
				$function = 'fetchSearchTagsForCloud';
			break;
			case 'nodes':
			default:
				$function = 'fetchTagsForCloud';
			break;
		}
		$tags = vB::getDbAssertor()->getRows($function, array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_METHOD,
			vB_dB_Query::PARAM_LIMIT => intval($limit)
		));
		$totals = array();
		foreach ($tags as $currenttag)
		{
			$totals[$currenttag['tagid']] = $currenttag['searchcount'];
		}

		// fetch the stddev levels
		$levels = fetch_standard_deviated_levels($totals, $taglevels);

		// assign the levels back to the tags
		foreach ($tags AS $k => $tag)
		{
			$tags[$k]['level'] = $levels[$tag['tagid']];
			$tags[$k]['tagtext_url'] = urlencode(unhtmlspecialchars($tag['tagtext']));
		}

		// sort the tags by tagtext
		usort($tags, array($this, 'sortTagsByTagText'));

		return $tags;
	}

	/**
	 * Returns an array of tags for the tag navigation widget
	 *
	 * @param	int	Channel ID for the root channel for this tag navigation module
	 * @param	int	Maximum number of tags to return
	 * @param	bool	If true, it will add the information to display as a cloud (instead of a list)
	 * @param	int	The number of levels of tags (sizes for cloud)
	 *
	 * @return	array	Tag information
	 */
	public function fetchTagsForTagNavigation($channelId, $limit = 25, $addCloudInfo = false, $levels = 5)
	{
		$channelId = (int) $channelId;
		$channelId = $channelId < 1 ? 1 : $channelId;

		$limit = (int) $limit;
		$limit = $limit < 1 ? 1 : ($limit > 500 ? 500 : $limit);

		$tags = vB::getDbAssertor()->getRows('fetchTagsForTagNavigation', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_METHOD,
			vB_dB_Query::PARAM_LIMIT => $limit,
			'root_channel' => $channelId,
		));

		if ($addCloudInfo)
		{
			// assign levels to tags for tag cloud display
			$counts = array();
			foreach ($tags AS $tag)
			{
				$counts[$tag['tagid']] = $tag['count'];
			}

			$stddevlevels = fetch_standard_deviated_levels($counts, $levels);

			foreach ($tags AS $k => $tag)
			{
				$tags[$k]['level'] = $stddevlevels[$tag['tagid']];
			}
		}

		usort($tags, array($this, 'sortTagsByTagText'));

		return $tags;
	}

	/**
	 * Sort function for fetchTagsForTagNavigation
	 *
	 * @param	array	Tag info
	 * @param	array	Tag info
	 *
	 * @return	int
	 */
	protected function sortTagsByTagText($a, $b)
	{
		return strnatcasecmp($a['tagtext'], $b['tagtext']);
	}

	/**
	 * Fetch tag by label
	 * @param	string $tagtext
	 * @return	array -- tag record
	 */
	public function fetchTagByText($tagtext)
	{
		$response = array();
		$tag = vB::getDbAssertor()->getRow('vBForum:tag',
			array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
				'tagtext' => vB_String::vBStrToLower($tagtext)
			)
		);
		if ($tag)
		{
			$response['tag'] = $tag;
		}
		else
		{
			throw new vB_Exception_Api("tag_not_exist");
		}

		return $response;
	}

	/**
	 * Get the tags
	 *	@param int|array $tagid
	 *	return array 'tags' => array(tagid => tag record)
	 */
	public function getTags($tagids)
	{
		$tags = vB::getDbAssertor()->getRows('vBForum:tag', array('tagid' => $tagids), false, 'tagid');
		return array('tags' => $tags);
	}

	/**
	 * Saves the seached for tags so we can build a search tag cloud based on it
	 * @param array $tagIds the ids of the tags that it was searched for
	 */
	public function logSearchTags($tagIds)
	{
		if (!empty($tagIds))
		{
			// create new tags
			$tagIdsInsert = array();
			$timenow = vB::getRequest()->getTimeNow();
			foreach ($tagIds AS $tagId)
			{
				$tagIdsInsert[] = array( $tagId, $timenow);
			}
			vB::getDbAssertor()->assertQuery('vBDBSearch:tagsearch', array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_MULTIPLEINSERT,
				vB_dB_Query::FIELDS_KEY => array('tagid', 'dateline'),
				vB_dB_Query::VALUES_KEY => $tagIdsInsert
			));
		}
	}

	/**
	 * Delete the associations between nodes and tags created by a user
	 * @param $userid
	 */
	public function deleteUserTagAssociations($userid)
	{
		$this->checkHasAdminPermission('canadmintags');
		$this->library->deleteUserTagAssociations($userid);
		return array('success' => true);
	}


	protected function getExceptionFromErrors($errors)
	{
		$e = new vB_Exception_Api();
		foreach($errors AS $error)
		{
			if (is_array($error))
			{
				$phraseid = array_shift($error);
				$e->add_error($phraseid, $error);
			}
			else
			{
				$e->add_error($error, array());
			}
		}

		return $e;
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 102938 $
|| #######################################################################
\*=========================================================================*/
