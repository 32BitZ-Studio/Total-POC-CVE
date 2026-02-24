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
 * vB_Api_Content
 *
 * @package vBApi
 * @author ebrown
 * @copyright Copyright (c) 2011
 * @version $Id: content.php 101425 2019-04-25 01:20:42Z ksours $
 * @access public
 */
abstract class vB_Api_Content extends vB_Api
{
	/**
	 * List of methods that which can still be called as normal even when the
	 * API is disabled due to forum being closed, password expired, IP ban, etc.
	 *
	 * @var array $disableWhiteList
	 */
	protected $disableWhiteList = array('getTimeNow');

	/**
	 * @var vB_UserContext Instance of vB_UserContext
	 */
	protected $usercontext;

	/**
	 * @var vB_dB_Assertor Instance of the database assertor
	 */
	protected $assertor;

	/**
	 * @var vB_Api_Node Instance of the Node API
	 */
	protected $nodeApi;

	/**
	 * @var array vBulletin options
	 */
	protected $options;

	/**
	 * @var bool Flag that allows skipping the flood check (used for types like Photos, where we'll upload several together)
	 */
	protected $doFloodCheck = true;

	/**
	 * @var vB_Library_Content Instance of the content library
	 */
	protected $library;

	/**
	 * Constructor
	 */
	protected function __construct()
	{
		parent::__construct();

		//The table for the type-specific data.
		$this->assertor = vB::getDbAssertor();
		$this->nodeApi = vB_Api::instanceInternal('node');
		$this->options = vB::getDatastore()->getValue('options');
	}

	/**
	 * Returns textCountChange property
	 * @return int
	 */
	public function getTextCountChange()
	{
		return $this->library->getTextCountChange();
	}

	/**
	 * Adds a new node
	 *
	 * @param  mixed   Array of field => value pairs which define the record.
	 * @param  array   Array of options for the content being created.
	 *                 Understands skipTransaction, skipFloodCheck, floodchecktime, many subclasses have skipNotification. See subclasses for more info.
	 *
	 * @return integer the new nodeid
	 */
	public function add($data, $options = array())
	{
		/*
			An add should never have a preexisting nodeid set.
			It should have a parentid instead.

			It's not used for anything, but let's unset it prevent possible
			weird permission/cleaninput bypassing.
		 */
		unset($data['nodeid']);

		if (!$this->library->validate($data, vB_Library_Content::ACTION_ADD))
		{
			throw new vB_Exception_Api('no_create_permissions');
		}

		//We shouldn't pass the open or show open fields
		unset($data['open']);
		unset($data['showopen']);

		$data = $this->cleanInput($data);
		$this->cleanOptions($options);
		$result = $this->library->add($data, $options);
		return $result['nodeid'];
	}

	/**
	 * Clean unallowed options from user request, only cleans 'skipFloodCheck' for now
	 *
	 * @param array $options Array of options, may be passed in from client
	 */
	protected function cleanOptions(&$options)
	{
		if (isset($options['skipFloodCheck']))
		{
			unset($options['skipFloodCheck']);
		}
		//clients don't get to set skipTransaction
		unset ($options['skipTransaction']);
	}

	/**
	 * Cleans the input in the $data array, directly updating $data.
	 *
	 * @param mixed     Array of fieldname => data pairs, passed by reference.
	 * @param int|false Nodeid of the node being edited, false if creating new
	 */
	public function cleanInput($data, $nodeid = false)
	{
		if (isset($data['userid']))
		{
			unset($data['userid']);
		}

		if (isset($data['authorname']))
		{
			unset($data['authorname']);
		}

		// For new nodes, approved/showapproved handling done in vB_Library_Content::add()
		// For existing nodes, we do NOT want to change their status via content API, only
		// the node API.
		unset($data['approved']);
		unset($data['showapproved']);

		// These fields should be cleaned regardless of the user's canusehtml permission.
		$cleaner = vB::getCleaner();
		foreach(array('title', 'htmltitle', 'description', 'prefixid', 'caption') AS $fieldname)
		{
			if (isset($data[$fieldname]))
			{
				$data[$fieldname] = $cleaner->clean($data[$fieldname], vB_Cleaner::TYPE_NOHTML);
			}
		}

		foreach(array('open', 'showopen') AS $fieldname)
		{
			if (isset($data[$fieldname]))
			{
				$data[$fieldname] = $cleaner->clean($data[$fieldname], vB_Cleaner::TYPE_INT);
			}
		}

		if (isset($data['urlident']))
		{
			// Let's make sure it's a valid identifier. No spaces, UTF-8 encoded, etc.
			$data['urlident'] = vB_String::getUrlIdent($data['urlident']);
		}

		// These fields are cleaned for people who cannot use html
		foreach(array('pagetext') AS $fieldname)
		{
			if (isset($data[$fieldname]))
			{
				$data[$fieldname] = $cleaner->clean($data[$fieldname], vB_Cleaner::TYPE_NOHTML);
			}
		}

		if (!empty($data['parentid']))
		{
			$checkNodeid = $data['parentid'];
		}
		else if ($nodeid)
		{
			$checkNodeid = $nodeid;
		}

		//Channels are handled a bit differently.
		if (isset($this->contenttype))
		{
			$isChannel = ($this->contenttype == 'vBForum_Channel');
		}
		//Note that contenttype should always be set. The next three checks should never be necessary.
		//But just in case, any of these will give a valid check.
		else if (isset($data['contenttypeid']))
		{
			$isChannel = ($data['contenttypeid'] == vB_Types::instance()->getContentTypeID('vBForum_Channel'));
		}
		else if (!empty($nodeid))
		{
			$node = $this->nodeApi->getNode($nodeid);
			$isChannel = ($node['contenttypeid'] == vB_Types::instance()->getContentTypeID('vBForum_Channel'));
		}
		else if (!empty($data['nodeid']))
		{
			$node = $this->nodeApi->getNode($data['nodeid']);
			$isChannel = ($node['contenttypeid'] == vB_Types::instance()->getContentTypeID('vBForum_Channel'));
		}

		if (!empty($isChannel))
		{
			//if this is an update we do nothing. If publishdate is already set we do nothing.
			if (empty($nodeid) AND !isset($data['publishdate']))
			{
				$data['publishdate'] = vB::getRequest()->getTimeNow();
			}
		}
		else if (!empty($checkNodeid))
		{
			$userContext = vB::getUserContext();

			//do not return any data from checkNode, the user might not have permissions to see it.
			$checkNode = vB_Library::instance('node')->getNodeFullContent($checkNodeid);
			$checkNode = array_pop($checkNode);

			// VBV-12342 - If this is a new node & the usergroup requires moderation on this channel, we need to
			// set approved & showapproved to 0. Do not mess with publishdate. If it's not an article, it'll be
			// published immediately in the publishdate handling below.
			// Update:  VBV-18640 - approved/showapproved checks moved to vB_Library_Content::add() (update()
			// intentionally does not modify approved/showapproved state ATM). Above comment left in place
			// to allow SVN Blame on that commit without jumps.

			/* PUBLISHDATE HANDLING */
			// For articles the handling is more complex
			if (($checkNode['channeltype'] == 'article'))
			{
				$publish = true;

				if (!empty($nodeid))
				{
					$node = $this->nodeApi->getNode($nodeid);
					$starter = ($node['nodeid'] == $node['starter']);
				}
				else if (!empty($data['nodeid']))
				{
					$node = $this->nodeApi->getNode($data['nodeid']);
					$starter = ($node['nodeid'] == $node['starter']);
				}
				else
				{
					$node = $this->nodeApi->getNode($data['parentid']);
					$starter = ($node['contenttypeid'] == vB_Types::instance()->getContentTypeID('vBForum_Channel'));
				}

				if ($starter)
				{
					$canpublish = $userContext->getChannelPermission('forumpermissions2', 'canpublish', $checkNode['channelid']);

					//if this is a add (we don't have a nodeid) AND the user can't publish, we force publishdate to zero
					if (!$canpublish OR (isset($data['publish_now']) AND $data['publish_now'] === false))
					{
						// if the user can't publish, but can create, then we save as a draft.
						$data['publish_now'] = false;
						$publish = false;

						// Only unset publishdate if user cannot publish. If they can publish and
						// they set publish_now == false, they want to pull the article & save it as a draft.
						if ($nodeid AND !$canpublish)
						{
							unset($data['publishdate']);
						}
						else
						{
							$data['publishdate'] = 0;
						}
					}
				}

				if ($publish)
				{
					if (
						empty($data['publishdate']) OR
						!$userContext->getChannelPermission('forumpermissions2' , 'canpublish',$checkNode['channelid'])
					)
					{
						$data['publishdate'] = vB::getRequest()->getTimeNow();
					}
				}

			}
			else if (!$nodeid)
			//New non-articles are published immediately.
			{
				if (
					empty($data['publishdate']) OR
					!$userContext->getChannelPermission('forumpermissions2' , 'canpublish', $checkNode['channelid'])
				)
				{
					$data['publishdate'] = vB::getRequest()->getTimeNow();
				}
			}
		}
		else if (!$nodeid)
		{
			$data['publishdate'] = vB::getRequest()->getTimeNow();
		}

		return $data;
	}

	/**
	 * Permanently deletes a node
	 *
	 * @param  integer The nodeid of the record to be deleted
	 *
	 * @return boolean
	 */
	public function delete($nodeid)
	{
		//if we every check anything more than the validate function here (which we probably shouldn't)
		//we need to change the code in vB_Api_Node::deleteNodes which also has to check for delete
		//permissions
		if (!$this->library->validate(array(), vB_Library_Content::ACTION_DELETE, $nodeid))
		{
			throw new vB_Exception_Api('no_delete_permissions');
		}

		return $this->library->delete($nodeid);
	}

	/**
	 * Returns a content api of the appropriate type
	 *
	 * @param  int   The content type id
	 *
	 * @return mixed Content api object
	 */
	public static function getContentApi($contenttypeid)
	{
		return vB_Api::instanceInternal('Content_' . vB_Types::instance()->getContentTypeClass($contenttypeid));
	}

	/**
	 * Determines if this record is in a published state
	 *
	 * @param  array The standard array of data sent to the add() method
	 *
	 * @return bool
	 */
	public function isPublished($data)
	{
		return $this->library->isPublished($data);
	}

	/**
	 * Updates a record
	 *
	 * @param  mixed array of nodeids
	 * @param  mixed array of permissions that should be checked.
	 *
	 * @return bool
	 */
	public function update($nodeid, $data)
	{
		/*
			If this is set, this will be overwritten anyways by $nodeid in
			vB_Library_Content::update(), so there's no reason this should be set.
			Let's just unset it to prevent possible weird permission/cleaninput bypassing
			with it set.
		 */
		unset($data['nodeid']);

		if (!$this->library->validate($data, vB_Library_Content::ACTION_UPDATE, $nodeid))
		{
			throw new vB_Exception_Api('no_update_permissions');
		}

		$data = $this->cleanInput($data, $nodeid);

		$content = $this->nodeApi->getNodeFullContent($nodeid);
		$content = array_pop($content);

		if (($content['channeltype'] != 'article') AND !vB::getUserContext()->getChannelPermission('forumpermissions2', 'canpublish', $content['parentid']))
		{
			unset($data['publishdate']);
			unset($data['publishnow']);
		}

		// approved/showapproved unsetting/checking is done in cleanInput() now, VBV-18640

		if (empty($data['title']))
		{
			unset ($data['title']);
		}

		$nodeInfo = vB_Api::instanceInternal('node')->getNode($nodeid);

		//check time limit on editing of thread title
		if(isset($data['title']) AND ($data['title'] != $nodeInfo['title']) AND !vB_Library::instance('node')->canEditThreadTitle($nodeid))
		{
			throw new vB_Exception_Api('exceeded_timelimit_editing_thread_title');
		}

		return $this->library->update($nodeid, $data);
	}

	/**
	 * Alias for @getFullContent
	 */
	public function getContent($nodeid, $permissions = false)
	{
		return $this->getFullContent($nodeid, $permissions);
	}

	/**
	 * Returns the node content plus the channel routeid and title, and starter route and title, and permissions and other data
	 *
	 * @param  integer The node id
	 * @param  array   Permissions
	 *
	 * @return array   The standard array of node data
	 */
	public function getFullContent($nodeid, $permissions = false)
	{
		$temporary = $this->library->getFullContent($nodeid, $permissions);
		$data = array();

		if (!$this->library->validate($data, vB_Library_Content::ACTION_VIEW, $nodeid, $temporary))
		{
			throw new vB_Exception_Api('no_permission');
		}

		foreach($temporary AS $key => $node)
		{
			if (empty($node['moderatorperms']['canviewips']))
			{
				$temporary[$key]['ipaddress'] = '';
			}
		}

		return $temporary;
	}

	/**
	 * Takes a node record and removes the data cannot be viewed based on public_preview.
	 * It's called from the search Api, which avoids using the content APIs
	 *
	 * @param mixed The node record, normally from getNodeFullContent, by reference
	 */
	public function cleanPreviewContent($record)
	{
		static $channelTypeId;
		static $allCanView;

		if (!isset($channelTypeId))
		{
			$channelTypeId = vB_Types::instance()->getContentTypeID('vBForum_Channel');
			$allCanView = $this->library->getAllCanView();
		}
		$thisUserid = vB::getCurrentSession()->get('userid');

		if (empty($record['content']['moderatorperms']['canviewips']))
		{
			unset($record['ipaddress']);
			unset($record['content']['ipaddress']);
		}

		//if the current user can't view thread content here we have to unset a number of fields.
		if (
			empty($record['content']['permissions']['canviewthreads'])	OR
			(empty($record['content']['permissions']['canviewothers']) AND ($record['userid'] != $thisUserid))	OR
			empty($record['content']['canview'])
		)
		{
			if (!empty($record['public_preview']))
			{
				$this->nodeApi->getPreviewOnly($record['content']);
			}
			else
			{
				foreach ($record as $field => $value)
				{
					if (($field != 'content') AND !array_key_exists($field, $allCanView))
					{
						unset($record[$field]);
					}
				}

				if (isset($record['content']))
				{
					foreach ($record['content'] as $field => $value)
					{
						if (!array_key_exists($field, $allCanView))
						{
							unset($record['content']['field']);
						}
					}
				}
				$record['lastcontent'] = $record['content']['lastcontent'] = $record['publishdate'];
				$record['lastcontentid'] = $record['content']['lastcontent'] = $record['nodeid'];
				$record['lastcontentauthor'] = $record['content']['lastcontent'] = $record['authorname'];
				$record['lastauthorid'] = $record['content']['lastcontent'] = $record['userid'];
			}
			$record['content']['permissions']['canvote'] = 0;
			$record['content']['permissions']['canuserep'] = 0;
			$record['content']['permissions']['can_flag']= $record['can_flag']= 0;
			$record['content']['permissions']['can_comment'] = $record['can_comment'] = 0;
			$record['content']['canreply'] = 0;
		}

		return $record;
	}

	/**
	 * Returns the node content, channel routeid and title, and starter route
	 * and title, but no permissions or other subsidiary data
	 *
	 * @param  int   The Node ID
	 * @param  array Permissions
	 *
	 * @return mixed
	 */
	public function getBareContent($nodeid, $permissions = false)
	{
		$temporary = $this->library->getBareContent($nodeid, $permissions);
		$data = array();

		if (!$this->library->validate($data, vB_Library_Content::ACTION_VIEW, $nodeid, $temporary))
		{
			foreach ($temporary as $key => $node)
			{
				if ($node['public_preview'])
				{
					$temporary[$key] = $this->nodeApi->getPreviewOnly($node);
				}
				else
				{
					throw new vB_Exception_Api('no_permission');
				}

			}
		}

		foreach($temporary AS $key => $node)
		{
			if (empty($node['moderatorperms']['canviewips']))
			{
				$temporary[$key]['ipaddress'] = '';
			}
		}

		return $temporary;
	}

	/**
	 * Gets the conversation starter for a node.  If the node is a
	 * channel it returns the channel array.
	 *
	 * @param  int $nodeid
	 * @return array|false The starter node array.  False when the node lookup fails
	 * @throws vB_Exception_Api('no_permission')
	 */
	public function getConversationParent($nodeid)
	{
		$starter = $this->library->getConversationParent($nodeid);

		if(!$starter)
		{
			return false;
		}

		//there is no guarentee that the starter is the same content type as the child
		//so load the correct API class for the starter before validating.
		$lib = vB_Library_Content::getContentLib($starter['contenttypeid']);
		$starterid = $starter['nodeid'];
		if (!$lib->validate(array(), vB_Library_Content::ACTION_VIEW, $starterid, array($starterid => $starter)))
		{
			throw new vB_Exception_Api('no_permission');
		}

		return $starter;
	}

	/**
	 * The classes  that inherit this should implement this function
	 * It should return the content that should be indexed
	 * If there is a title field, the array key for that field should be 'title',
	 * the rest of the text can have any key
	 *
	 * @param  int   $nodeId - it might be the node (assiciative array)
	 *
	 * @return array $indexableContent
	 */
	public function getIndexableContent($nodeId, $include_attachments = true)
	{
		return $this->library->getIndexableContent($nodeId, $include_attachments);
	}

	/**
	 * Returns an array with bbcode options for the node.
	 *
	 * @param int $nodeId
	 */
	public function getBbcodeOptions($nodeId)
	{
		// This method needs to be overwritten for each relevant contenttype
		return array();
	}

	/**
	 * Gives the current board time- needed to set publishdate.
	 *
	 * @return int
	 */
	public function getTimeNow()
	{
		return vB::getRequest()->getTimeNow();
	}

	/**
	 * This returns the text to quote a node. Used initially for private messaging.
	 *
	 * @param  int    The nodeid of the quoted item
	 *
	 * @return string Quote text
	 */
	public function getQuoteText($nodeid)
	{
		//This must be implemented in the child class
		throw new vB_Exception_Api('feature_not_implemented');
	}


	/**
	 * This returns the text to quote a node. Used initially for private messaging.
	 *
	 * @param  int    The nodeid of the quoted item
	 *
	 * @return string Quote text.
	 */
	public function createQuoteText($nodeid, $pageText)
	{
		//This must be implemented in the child class
		throw new vB_Exception_Api('feature_not_implemented');
	}


	/**
	 * Returns the tables used by this content type.
	 *
	 * @return array Array of table names
	 */
	public function fetchTableName()
	{
		return $this->library->fetchTableName();
	}


	/**
	 * Determines whether a specific node is a visitor message
	 *
	 * @param  int  NodeID
	 *
	 * @return bool
	 */
	public function isVisitorMessage($nodeid)
	{
		return $this->library->isVisitorMessage($nodeid);
	}

	/**
	 * Extracts the video and photo content from text.
	 *
	 * @param  string
	 *
	 * @return mixed  Array of "photo", "video". Each is an array of images.
	 */
	public function extractMedia($rawtext)
	{
		$filter = '~\[video.*\[\/video~i';
		$matches = array();

		preg_match_all($filter, $rawtext, $matches);

		return $matches;
	}

	/**
	 * Checks the "limit" permissions for this content item
	 *
	 * @param  array Info about the content that needs to be added
	 *
	 * @return bool  Either true if all the tests passed or thrown exception
	 */
	protected function verify_limits($data)
	{
		// This is where conent general checks should go
		return true;
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 101425 $
|| #######################################################################
\*=========================================================================*/
