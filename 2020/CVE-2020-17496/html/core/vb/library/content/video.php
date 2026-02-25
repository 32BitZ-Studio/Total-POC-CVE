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
 * vB_Library_Content_Video
 *
 * @package vBLibrary
 * @access public
 */
class vB_Library_Content_Video extends vB_Library_Content_Text
{
	//override in client- the text name
	protected $contenttype = 'vBForum_Video';

	//The table for the type-specific data.
	protected $tablename = array('video', 'text');

	//list of fields that are included in the index
	protected $index_fields = array('rawtext','url_title');

	protected $providers = array();


	protected function __construct()
	{
		$this->library = vB_Library::instance('Content_Attach');
		parent::__construct();
	}

	/**
	 * Returns the node content as an associative array with fullcontent
	 *	@param	integer	The id in the primary table
	 *	@param array permissions
	 *
	 *	*	@param bool	appends to the content the channel routeid and title, and starter route and title the as an associative array
	 */
	public function getFullContent($nodeid, $permissions = false)
	{
		if (empty($nodeid))
		{
			return array();
		}
		$results = parent::getFullContent($nodeid, $permissions);
		$videoitems = $this->fetchVideoItems($nodeid);

		foreach ($results as $key => $result)
		{
			$results[$key]['items'] = array();

		}

		foreach ($videoitems as $videoitem)
		{
			$results[$videoitem['nodeid']]['items'][] = $videoitem;
		}

		foreach ($results as $key => $result)
		{
			if (empty($result['items']))
			{
				$results[$key]['videocount'] = 0;
			}
			else
			{
				$results[$key]['videocount'] = count($result['items']);
			}
		}
		self::writeToCache($results, self::CACHELEVEL_FULLCONTENT);
		return $results;
	}

	public function getIndexableFromNode($content, $include_attachments = true)
	{
		$indexableContent = parent::getIndexableFromNode($content, $include_attachments);
		if (empty($content['url_title']))
		{
			$indexableContent['url_title'] = $content['url_title'];
		}
		return $indexableContent;
	}

	/**
	 * 	updates a record
	 *
	 *	@param int $nodeid
	 *	@param array $data -- The data for the node to be updated
	 *	@param boolean $convertWysiwygTextToBbcode
	 *
	 * 	@return boolean
	 */
	public function update($nodeid, $data, $convertWysiwygTextToBbcode = true)
	{
		$currentNode = vB_Library::instance('Node')->getNodeBare($nodeid);

		if ($currentNode['contenttypeid'] != vB_Types::instance()->getContentTypeID($this->contenttype))
		{
			parent::changeContentType($nodeid, $currentNode['contenttypeid'], $this->contenttype);
			$data['contenttypeid'] = vB_Types::instance()->getContentTypeID($this->contenttype);
		}

		$newvideoitems = array();
		if (isset($data['videoitems']))
		{
			$newvideoitems = $this->checkVideoData($data);
			unset($data['videoitems']);
		}

		// check if thumbnail needs updating
		$currentNodeContent = vB_Library::instance('Node')->getNodeContent($nodeid);
		$currentNodeContent = reset($currentNodeContent);
		if (!empty($currentNodeContent['url']) AND $currentNodeContent['url'] != $data['url'])
		{
			// video has changed; force thumbnail update. See getVideoThumbnail()
			$data['thumbnail'] = '';
		}

		$result = parent::update($nodeid, $data, $convertWysiwygTextToBbcode);

		// process videoitems if they are provided
		if (!empty($newvideoitems))
		{
			// Get a list of current video items
			$videoitems = $this->fetchVideoItems($nodeid);

			$oldvideoitemids = array();
			$newvideoitemids = array();
			foreach ($videoitems AS $item)
			{
				$oldvideoitemids[$item['videoitemid']] = $item['videoitemid'];
			}
			foreach ($newvideoitems AS $item)
			{
				$newvideoitemids[$item['videoitemid']] = $item['videoitemid'];
				$newvideoitemdata[$item['videoitemid']] = $item;
			}

			$itemstoremove = array_diff($oldvideoitemids, $newvideoitemids);
			$itemstoupdate = array_intersect($oldvideoitemids, $newvideoitemids);
			$itemstoinsert = array_diff($newvideoitemids, $oldvideoitemids);

			// Save video items
			foreach ($itemstoinsert AS $itemid)
			{
				$this->assertor->assertQuery("videoitem", array(
					vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_INSERT,
					'nodeid' => $nodeid,
					'provider' => $newvideoitemdata[$itemid]['provider'],
					'code' => $newvideoitemdata[$itemid]['code'],
					'url' => $newvideoitemdata[$itemid]['url'],
				));
			}
			foreach ($itemstoupdate AS $itemid)
			{
				$this->assertor->assertQuery("videoitem", array(
					vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_UPDATE,
					'nodeid' => $nodeid,
					'provider' => $newvideoitemdata[$itemid]['provider'],
					'code' => $newvideoitemdata[$itemid]['code'],
					'url' => $newvideoitemdata[$itemid]['url'],
					vB_dB_Query::CONDITIONS_KEY => array(
						'videoitemid' => $itemid,
					)
				));
			}
			foreach ($itemstoremove AS $itemid)
			{
				$this->assertor->assertQuery("videoitem", array(
					vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_DELETE,
					'videoitemid' => $itemid,
				));
			}
		}

		// do the indexing after the options are added
		vB_Library::instance('search')->index($nodeid);
		vB_Cache::instance(vB_Cache::CACHE_FAST)->event("nodeChg_$nodeid");
		vB_Cache::instance()->event("nodeChg_$nodeid");

		return $result;
	}

	/**
	 * Permanently deletes a node
	 *	@param	integer	The nodeid of the record to be deleted
	 *
	 *	@return	boolean
	 */
	public function delete($nodeid)
	{
		//We need to update the parent counts, but first we need to get the status
		$node = $this->assertor->getRow('vBForum:node', array('nodeid' => $nodeid));
		//We have to get this before we delete
		if ($node['showpublished'])
		{
			$parents = vB_Library::instance('Node')->getParents($nodeid);
		}

		//do the delete
		parent::delete($nodeid);

		//delete videoitems
		$this->assertor->assertQuery('videoitem', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_DELETE,
			'nodeid' => $nodeid,
		));
		vB_Cache::instance(vB_Cache::CACHE_FAST)->event("nodeChg_$nodeid");
		vB_Cache::instance()->event("nodeChg_$nodeid");
		return true;
	}

	/**
	 * Delete the records without updating the parent info. It is used when deleting a whole channel and it's children need to be removed
	 * @param array $childrenIds - list of node ids
	 */
	public function deleteChildren($childrenIds)
	{
		//delete the main tables
		parent::deleteChildren($childrenIds);

		//delete videoitems
		$this->assertor->assertQuery('vBForum:videoitem', array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_DELETE,
				'nodeid' => $childrenIds,
		));
	}


	/**
	 * Adds a new node.
	 *
	 * @param	mixed		Array of field => value pairs which define the record.
	 * 						Understands skipTransaction, skipFloodCheck, floodchecktime, skipDupCheck, skipNotification, nl2br, autoparselinks.
	 *							- nl2br: if TRUE, all \n will be converted to <br /> so that it's not removed by the html parser (e.g. comments).
	 * @param	bool		Convert text to bbcode
	 *
	 * @return	mixed		array with nodeid (int), success (bool), cacheEvents (array of strings),
	 *		nodeVals (array of field => value), attachments (array of attachment records).
	 */
	public function add($data, array $options = array(), $convertWysiwygTextToBbcode = true)
	{
		// TODO: Permission check
//		$loginuser = &vB::getCurrentSession()->fetch_userinfo();
//		$usercontext = &vB::getUserContext($loginuser['userid']);
//		if (!$usercontext->hasPermission('forumpermissions', 'canpostvideo'))
//		{
//			throw new Exception('no_permission');
//		}
		//Store this so we know whether we should call afterAdd()
		$skipTransaction = !empty($options['skipTransaction']);

		$videoitems = $this->checkVideoData($data);

		unset($data['videoitems']);

		if (!$videoitems)
		{
			throw new vB_Exception_Api("invalid_videoitems");
		}

		try
		{
			if (!$skipTransaction)
			{
				$this->assertor->beginTransaction();
			}
			$options['skipTransaction'] = true;
			$result = parent::add($data, $options, $convertWysiwygTextToBbcode);

			// Save video items
			foreach ($videoitems AS $item)
			{
				$this->assertor->assertQuery("videoitem", array(
					vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_INSERT,
					'nodeid' => $result['nodeid'],
					'provider' => $item['provider'],
					'code' => $item['code'],
					'url' => $item['url'],
				));
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

		if (!$skipTransaction)
		{
			//The child classes that have their own transactions all set this to true so afterAdd is always called just once.
			$this->afterAdd($result['nodeid'], $data, $options, $result['cacheEvents'], $result['nodeVals']);
		}

		//indexing is done in the parent class
		return $result;
	}

	/**
	 * Get information from video's URL.
	 * This method makes use of bbcode_video table to get provider information
	 * @param $url
	 * @return array|bool Video data. False if the url is not supported or invalid
	 */
	public function getVideoFromUrl($url)
	{
		static $scraped = 0;

		$vboptions = vB::getDatastore()->getValue('options');

		if (!$this->providers)
		{
			$columns = array('provider', 'url', 'regex_url', 'regex_scrape', 'tagoption');
			$this->providers = $this->assertor->getRows('bbcode_video', array(vB_Db_Query::COLUMNS_KEY => $columns), 'priority', 'tagoption');
		}

		if (!empty($this->providers))
		{
			$match = false;
			foreach ($this->providers AS $provider)
			{
				$addcaret = ($provider['regex_url'][0] != '^') ? '^' : '';
				if (preg_match('#' . $addcaret . $provider['regex_url'] . '#si', $url, $match))
				{
					break;
				}
			}

			if ($match)
			{
				if (!$provider['regex_scrape'] AND $match[1])
				{
					$data = array(
						'provider' => $provider['tagoption'],
						'code' => $match[1],
						'url' => $url,
					);
				}
				else if ($provider['regex_scrape'] AND $vboptions['bbcode_video_scrape'] > 0 AND $scraped < $vboptions['bbcode_video_scrape'])
				{
					$vurl = vB::getUrlLoader();
					$result = $vurl->get($url);

					if (preg_match('#' . $provider['regex_scrape'] . '#si', $result['body'], $scrapematch))
					{
						$data = array(
							'provider' => $provider['tagoption'],
							'code' => $scrapematch[1],
							'url' => $url,
						);
					}
					$scraped++;
				}
			}

			if (!empty($data))
			{
				return $data;
			}
			else
			{
				return false;
			}
		}

		return false;
	}

	public function getQuotes($nodeids)
	{
		//Per Product, we just quote the text content (but this may change in the future)
		//If and when the requirement changes to include the non-text content, don't call the parent method and then implement it here
		return parent::getQuotes($nodeids);
	}

	/**
	 * Check video node input data and return an array of valid video items
	 *
	 * @throws vB_Exception_Api
	 * @param $data
	 * @return void
	 */
	protected function checkVideoData($data)
	{
		if (!$data['videoitems'] OR !is_array($data['videoitems']))
		{
			throw new vB_Exception_Api('please_complete_required_fields');
		}

		$return = array();
		foreach ($data['videoitems'] AS $video)
		{
			if (!$video['url'])
			{
				continue;
			}

			if (!isset($video['videoitemid']))
			{
				$video['videoitemid'] = 0;
			}

			if ($info = $this->getVideoFromUrl($video['url']))
			{

				$return[] = array(
					'videoitemid' => $video['videoitemid'],
					'url' => $video['url'],
					'provider' => $info['provider'],
					'code' => $info['code'],
				);
			}
		}

		if ($return)
		{
			return $return;
		}
		else
		{
			throw new vB_Exception_Api('please_complete_required_fields');
		}
	}

	/**
	 * Fetch video items by nodeid
	 *
	 * @param $nodeid Node ID
	 * @return array Video items
	 */
	protected function fetchVideoItems($nodeid)
	{
		return $this->assertor->getRows("vBForum:videoitem", array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'nodeid' => $nodeid
		));
	}

	/**
	 * Adds content info to $result so that merged content can be edited.
	 * @param array $result
	 * @param array $content
	 */
	public function mergeContentInfo(&$result, $content)
	{
		parent::mergeContentInfo($result, $content);

		if (!isset($content['items']))
		{
			throw new vB_Exception_Api('invalid_content_info');
		}

		foreach($content['items'] AS $video)
		{
			$result['items'][] = $video;
		}
	}

	/**
	 * Performs the merge of content and updates the node.
	 * @param type $data
	 * @return type
	 */
	public function mergeContent($data)
	{
		// modify tables records (only one record will be modified due to constraints)
		$sources = array_diff($data['mergePosts'], array($data['destnodeid']));

		$db = vB::getDbAssertor();
		$db->update('vBForum:video', array('nodeid' => $data['destnodeid']), array(array('field' => 'nodeid', 'value' => $sources)));
		$db->update('vBForum:node', array('contenttypeid' => $this->contenttypeid), array('nodeid' => $data['destnodeid']));

		// get videoitems
		$videoitems = array();
		foreach($data AS $key => $value)
		{
			if (preg_match('#^videoitems\[([\d]+)#', $key, $matches))
			{
				$videoitems[] = array(
					'videoitemid' => intval($matches[1]),
					'url' => $value['url'],
				);
			}
			else if (preg_match('^videoitems\[new', $key, $matches))
			{
				foreach ($value as $video)
				{
					$videoitems[]['url'] = $video['url'];
				}
			}
		}

		$videoData = array(
			'userid' => $data['destauthorid'],
			'rawtext' => $data['text'],
			'videoitems' => $videoitems
		);

		return vB_Api::instanceInternal('content_video')->update($data['destnodeid'], $videoData);
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 102779 $
|| #######################################################################
\*=========================================================================*/
