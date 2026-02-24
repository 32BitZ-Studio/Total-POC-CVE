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
 * vB_Library_Content_Gallery
 *
 * @package vBLibrary
 * @access public
 */
class vB_Library_Content_Gallery extends vB_Library_Content_Text
{
	//override in client- the text name
	protected $contenttype = 'vBForum_Gallery';

	//The table for the type-specific data.
	protected $tablename = array('gallery', 'text');

	//Whether we change the parent's text count- 1 or zero
	protected $textCountChange = 1;

	//Does this content show author signature?
	protected $showSignature = true;

	/**
	 * 	Adds a new node.
	 *
	 *	@param	mixed		Array of field => value pairs which define the record.
	 * 	@param	array		Array of options for the content being created
	 * 						Understands skipTransaction, skipFloodCheck, floodchecktime, skipDupCheck, skipNotification, nl2br, autoparselinks.
	 *							- nl2br: if TRUE, all \n will be converted to <br /> so that it's not removed by the html parser (e.g. comments).
	 * 	@param	bool		Convert text to bbcode
	 *
	 * 	@return	array	array with
	 * 		* nodeid (int)
	 * 		* success (bool),
	 * 		* cacheEvents (array of strings),
	 * 		* nodeVals (array of field => value)
	 * 		* attachments (array of attachment records).
	 */
	public function add($data, array $options = array(), $convertWysiwygTextToBbcode = true)
	{
		try
		{
			//Store this so we know whether we should call afterAdd()
			$skipTransaction = !empty($options['skipTransaction']);

			if (!$skipTransaction)
			{
				$this->assertor->beginTransaction();
			}
			$options['skipTransaction'] = true;
			$result = parent::add($data, $options, $convertWysiwygTextToBbcode);
			// @todo is this not already done in the vB_Library_Content_Text class?
			//We want to save in one batch. Otherwise if moderation is set the attached photos will be lost.
			//See VBV-12360

			if (is_int($result['nodeid']) AND !empty($data['photos']))
			{
				// Note, photos' data are now cleaned at the vB_Api_Content_Text level in cleanInput()
				if (!empty($data['photos']) AND is_array($data['photos']))
				{
					$photoLib = vB_Library::instance('content_photo');
					$node = $this->getFullContent($result['nodeid']);
					$node = array_pop($node);
					$published = $node['showpublished'];
					foreach ($data['photos'] AS $photo)
					{
						$photo['parentid'] = $result['nodeid'];

						$photo['showpublished'] = $published;
						$photo['showapproved'] = $published;

						if (!isset($photo['options']))
						{
							$photo['options'] = $options;
						}
						//We must have skipTransaction set or the photo api will attempt to start a transaction and cause an exception
						$photo['options']['skipTransaction'] = true;
						$photoLib->add($photo, $photo['options']);
					}
				}
			}

			// Obtain and set generic conversation route
			$conversation = $this->getConversationParent($result['nodeid']);
			$routeid = vB_Api::instanceInternal('route')->getChannelConversationRoute($conversation['parentid']);
			$this->assertor->update('vBForum:node', array('routeid' => $routeid), array('nodeid' => $result['nodeid']));

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
		//basic cache events are cleared in the parent class
		return $result;
	}

	/**
	 *	@see vB_Library_Content::removePrivateDataFromNode
	 */
	public function removePrivateDataFromNode(&$node)
	{
		parent::removePrivateDataFromNode($node);
		if (empty($node['content']['moderatorperms']['canviewips']))
		{
			if (isset($node['content']['firstphoto']['ipaddress']))
			{
				$node['content']['firstphoto']['ipaddress'] = "";
			}

			$subarrays = array('photo', 'photopreview');
			foreach($subarrays AS $subarray)
			{
				if (isset($node['content'][$subarray]))
				{
					foreach($node['content'][$subarray] AS $subnodeid => $subnode)
					{
						$node['content'][$subarray][$subnodeid]['ipaddress'] = "";
					}
				}
			}

			//in some cases these fields are added directly to the node array
			if (isset($node['firstphoto']['ipaddress']))
			{
				$node['firstphoto']['ipaddress'] = "";
			}

			foreach($subarrays AS $subarray)
			{
				if (isset($node[$subarray]))
				{
					foreach($node[$subarray] AS $subnodeid => $subnode)
					{
						$node[$subarray][$subnodeid]['ipaddress'] = "";
					}
				}
			}
		}
	}

	/**
	 * 	Returns the node content as an associative array with fullcontent
	 *	@param	mixed	integer or array of integers=The id in the primary table
	 *	@param array permissions
	 *
	 * 	@param bool	appends to the content the channel routeid and title, and starter route and title the as an associative array
	 */
	public function getFullContent($nodes, $permissions = false)
	{
		$contentInfo = parent::getFullContent($nodes, $permissions);
		return $this->addPhotoInfo($contentInfo, $nodes);
	}

	/**
	 *	Get and cache node data
	 *	@param	mixed	array of nodeids
	 *	@return mixed	array of photo table records
	 */
	protected function getPhotos($nodeids)
	{
		if (!is_array($nodeids))
		{
			$nodeids = array($nodeids);
		}

		//First let's see what we have in cache.
		$found = array();
		$notfound = array();
		$cache = vB_Cache::instance(vB_Cache::CACHE_FAST);

		foreach ($nodeids AS $nodeid)
		{
			$photos = $cache->read("vBPhoto_$nodeid");

			if (!empty($photos))
			{
				$found = array_merge($found, $photos);
			}
			else if ($photos !== NULL)
			{
				$notfound[$nodeid] = array() ;
			}
		}

		if (!empty($notfound))
		{
			$photos = vB::getDbAssertor()->assertQuery('vBForum:getPhotos', array('parentid' => array_keys($notfound)));

			foreach($photos AS $photo)
			{
				$found[] = $photo;
				$notfound[$photo['parentid']][$photo['nodeid']] = $photo;
			}

			//cache what we've found- but not false. Use empty array so we can distinguish
			// cached data from uncached.
			foreach ($notfound AS $parentId => $photos)
			{
				$hashKey = "vBPhoto_$parentId";

				if (empty($photo))
				{
					$photo = array();
				}
				$cache->write($hashKey, $photos, 1440, "nodeChg_$nodeid");
			}
		}

		return $found;


	}

	protected function addPhotoInfo($contentInfo, $nodes)
	{
		$options = vB::getDatastore()->getValue('options');
		$galleryCount = $options['attatchgallerythumbs'];
		$photos = $this->getPhotos($nodes);
		//the key of for each node is the nodeid, fortunately
		foreach ($photos AS $photo)
		{
			//Need to add the photo to the right node.
			if (isset($photo['parentid']) && isset($contentInfo[$photo['parentid']]))
			{
				if (empty($contentInfo[$photo['parentid']]['firstphoto']))
				{
					$contentInfo[$photo['parentid']]['firstphoto'] = $photo;
				}
				//We have a match
				if (!isset($contentInfo[$photo['parentid']]['photo']))
				{
					$contentInfo[$photo['parentid']]['photo'] = array();
				}

				$photo['shortcaption'] = substr($photo['caption'],0,10);
				$contentInfo[$photo['parentid']]['photo'][$photo['nodeid']] = $photo;
			}
		}

		if (is_array($nodes))
		{
			foreach ($nodes as $node)
			{
				if (empty($contentInfo[$node]))
				{
					continue;
				}
				if (empty($contentInfo[$node]['photo']))
				{
					$contentInfo[$node]['photocount'] = 0;
				}
				else
				{
					$contentInfo[$node]['photocount'] = count($contentInfo[$node]['photo']);
				}
				//add 3 photo previews
				if (isset($contentInfo[$node]['photo']))
				{
					$contentInfo[$node]['photopreview'] = ($contentInfo[$node]['photocount'] > $galleryCount) ? array_slice($contentInfo[$node]['photo'], 0, $galleryCount) : $contentInfo[$node]['photo'];
				}
			}
		}
		elseif (!empty($contentInfo[$nodes]))
		{
			if (empty($contentInfo[$nodes]['photo']))
			{
				$contentInfo[$nodes]['photocount'] = 0;
				$contentInfo[$nodes]['photopreview'] = array();
			}
			else
			{
				$contentInfo[$nodes]['photocount'] = count($contentInfo[$nodes]['photo']);
				//add 3 photo previews
				$contentInfo[$nodes]['photopreview'] = ($contentInfo[$nodes]['photocount'] > $galleryCount) ? array_slice($contentInfo[$nodes]['photo'], 0, $galleryCount) : $contentInfo[$nodes]['photo'];
			}
		}
		return $contentInfo;
	}

	/**
	 * Adds content info to $result so that merged content can be edited.
	 * @param array $result
	 * @param array $content
	 */
	public function mergeContentInfo(&$result, $content)
	{
		parent::mergeContentInfo($result, $content);

		if (!isset($content['photo']))
		{
			throw new vB_Exception_Api('invalid_content_info');
		}

		foreach($content['photo'] as $photo)
		{
			$result['photo'][$photo['nodeid']] = $photo;
		}

		$result['photocount'] = count($result['photo']);
	}

	/**
	 * Performs the merge of content and updates the node.
	 * @param type $data
	 * @return type
	 */
	public function mergeContent($data)
	{
		// modify tables records (only one record will be modified due to constraints)
		$db = vB::getDbAssertor();

		$nodes = vB_Api::instanceInternal('node')->getContentForNodes(array($data['destnodeid']));
		$destNode = array_pop($nodes);
		if ($destNode['contenttypeclass'] != 'Gallery')
		{
			$db->insert('gallery', array('nodeid' => $data['destnodeid']));
		}

		$db->update('vBForum:node', array('contenttypeid' => $this->contenttypeid), array('nodeid' => $data['destnodeid']));

		// get photos
		$filedataids = array();
		if (!empty($data['filedataid[]']))
		{
			if (!is_array($data['filedataid[]']))
			{
				$data['filedataid[]'] = array($data['filedataid[]']);
			}

			foreach ($data['filedataid[]'] AS $filedataid)
			{
				$title_key = "title_$filedataid";
				$filedataids[$filedataid] = (isset($data[$title_key])) ? $data[$title_key] : '';
			}
		}

		$data['rawtext'] = $data['text'];

		return $this->updateFromWeb($data['destnodeid'], $data, $filedataids);
	}

	public function getQuotes($nodeids)
	{
		//Per Product, we just quote the text content (but this may change in the future)
		//If and when the requirement changes to include the non-text content, don't call the parent method and then implement it here
		return parent::getQuotes($nodeids);
	}

	/** This function either deletes the gallery if it has no photos, or fixes it.
	 *
	@param	mixed	node record, which may have missing child table data.
	 */
	public function incompleteNodeCleanup($node)
	{

		//If we have child records we should create whatever records we missed.
		$children = $this->assertor->assertQuery('vBForum:node', array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT, 'parentid' => $node['nodeid']));

		if ($children->valid())
		{
			//We need to make sure we have text and gallery records.
			foreach((array)$this->tablename AS $table)
			{
				$tableCheck = $this->assertor->assertQuery('vBForum:' . $table, array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT, 'nodeid' => $node['nodeid']));

				if (!$tableCheck->valid())
				{
					$this->assertor->assertQuery('vBForum:' . $table, array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_INSERT, 'nodeid' => $node['nodeid']));
				}
			}
			vB_Cache::allCacheEvent(array('nodeChg_' . $node['parentid'], 'nodeChg_' . $node['nodeid']));
			vB_Library::instance('node')->clearCacheEvents($node['nodeid']);
		}
		else
		{
			//Just do the delete, which is handled in the parent classes
			parent::incompleteNodeCleanup($node);
		}

	}

	/**
	 * validates that the current can create a node with these values
	 *
	 * @param  array  Array of field => value pairs which define the record.
	 * @param  string Parameters to be checked for permission
	 *
	 * @return bool
	 */
	public function validate($data, $action = self::ACTION_ADD, $nodeid = false, $nodes = false, $userid = null)
	{
		// For now only allow checking permissions on another user for action_view.
		// vB_Library_Content::validate() should already check this but leaving a copy here in case of
		// changes later.
		$currentUserid = vB::getCurrentSession()->get('userid');
		if ($action != self::ACTION_VIEW AND !is_null($userid) AND $userid != $currentUserid)
		{
			throw new vB_Exception_Api('invalid_data_w_x_y_z', array($userid, '$userid', __CLASS__, __FUNCTION__));
		}

		// If userid is empty check perms for *current* user. This is used by the view checks with user "follow"
		// in the block below.
		if (empty($userid))
		{
			$userid = $currentUserid;
		}

		//One extra check. If the node would otherwise be viewable but viewperms is zero for an album, the the current user
		//is the owner or follows the owner, they can see it.
		if (parent::validate($data, $action, $nodeid, $nodes, $userid))
		{
			return true;
		}

		if ($action == self::ACTION_VIEW)
		{
			if (!is_array($nodeid))
			{
				$nodeid = array($nodeid);
			}

			if (!$nodes)
			{
				$nodes = vB_Library::instance('node')->getNodes($nodeid);
			}

			$albumChannel = vB_Library::instance('node')->fetchAlbumChannel();
			$following = vB_Api::instanceInternal('follow')->getFollowingParameters($userid);

			if (empty($following['user']))
			{
				$following = array($userid);
			}
			else
			{
				$following = $following['user'];
				$following[] = $userid;
			}

			foreach ($nodes AS $node)
			{
				if (($node['parentid'] != $albumChannel) OR ($node['viewperms'] != 0) OR !in_array($node['userid'], $following))
				{
					return false;
				}
			}
			//If we got here all is O.K.
			return true;
		}
		return false;
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 102683 $
|| #######################################################################
\*=========================================================================*/
