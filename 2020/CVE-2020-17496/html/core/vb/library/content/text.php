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
 * vB_Library_Content_Text
 *
 * @package vBLibrary
 * @access public
 */
class vB_Library_Content_Text extends vB_Library_Content
{
	private static $descriptionLength = 320;

	//override in client- the text name
	protected $contenttype = 'vBForum_Text';

	//The table for the type-specific data.
	protected $tablename = 'text';

	//list of fields that are included in the index
	protected $index_fields = array('rawtext');

	//When we parse the page.
	protected $bbcode_parser = false;

	//Whether we change the parent's text count- 1 or zero
	protected $textCountChange = 1;

	protected $canBeLastContent = true;


	//Whether we inherit viewperms from parents
	protected $inheritViewPerms = 0;

	//for spam checking
	protected $spamType = false;
	protected $spamKey = false;

	//Does this content show author signature?
	protected $showSignature = true;

	/**
	 * If true, then creating a node of this content type will increment
	 * the user's post count. If false, it will not. Generally, this should be
	 * true for topic starters and replies, and false for everything else.
	 *
	 * @var	bool
	 */
	protected $includeInUserPostCount = true;

	protected function __construct()
	{
		parent::__construct();
		//see if we have spam checking set.
		if (isset($this->options['vb_antispam_type']) AND $this->options['vb_antispam_type'] > 0 AND !empty($this->options['vb_antispam_key']))
		{
			$this->spamType = $this->options['vb_antispam_type'];
			$this->spamKey = $this->options['vb_antispam_key'];
		}
	}

	/**
	 * Returns the node content as an associative array with fullcontent
	 * @param	mixed	integer or array of integers=The id in the primary table
	 * @param array permissions
	 */
	public function getFullContent($nodes, $permissions = false)
	{
		if (empty($nodes))
		{
			return array();
		}

		$results = parent::getFullContent($nodes, $permissions);

		return $this->addContentInfo($results);
	}

	protected function addContentInfo($results)
	{
		//the key of for each node is the nodeid, fortunately
		$userids = array();
		$userContext = vB::getUserContext();
		//If pagetext and previewtext aren't populated let's do that now.
		foreach ($results as $key => $record)
		{
			if (isset($record['pagetextimages']))
			{
				unset($results[$key]['pagetextimages']);
			}

			//make sure the current user can see the content
			if (!$userContext->getChannelPermission('forumpermissions', 'canviewthreads', $record['nodeid'], false, $record['parentid']))
			{
				continue;
			}

			if (!empty($record['userid']) AND !in_array($record['userid'], $userids))
			{
				$userids[] = $record['userid'];
			}

			if (empty($record['starter']))
			{
				//The starter should never be empty or zero.  Let's fix this.
				$starter = $this->getStarter($record['nodeid']);
				$data = array(
					vB_dB_Query::TYPE_KEY =>vB_dB_Query::QUERY_UPDATE,
					'nodeid' => $record['nodeid'],
					'starter' => $starter
				);
				$this->assertor->assertQuery('vBForum:node', $data);
				$results[$key]['starter'] = $starter;
			}
			$results[$key]['attach'] = array();
		}

		if (!empty($userids))
		{
			$userLib = vB_Library::instance('user');
			$userLib->preloadUserInfo($userids);

			$userInfoArray = array();
			foreach($userids AS $userid)
			{
				$userInfoArray[$userid] = vB_User::fetchUserinfo($userid);
			}

			$fieldsToCopy = array_flip(array(
				'userid',
				'username',
				'rank',
				'usertitle',
				'joindate',
				'posts',
				'customtitle',
				'receivepm',
				'enable_pmchat',
			));

			$canseehiddencustomfields = vB::getUserContext()->hasPermission('genericpermissions', 'canseehiddencustomfields');
			$userFields = $userLib->getProfileFieldsFromUserInfoArray($userInfoArray, $canseehiddencustomfields);
			foreach ($results AS $key => $record)
			{
				if (empty($record['userid']) OR empty($userInfoArray[$record['userid']]))
				{
					continue;
				}

				$userInfo = $userInfoArray[$record['userid']];
				$results[$key]['userinfo'] = array_intersect_key($userInfo, $fieldsToCopy);
				$results[$key]['userinfo']['userfield'] = $userFields[$record['userid']] ?? array();
			}
		}

		//let's get the attachment info.
		$attachments = vB_Api::instanceInternal('node')->getNodeAttachments(array_keys($results));
		foreach ($attachments AS $attachment)
		{
			if (array_key_exists($attachment['parentid'], $results))
			{
				if (!is_array($results[$attachment['parentid']]['attach']))
				{
					$results[$attachment['parentid']]['attach'] = array();
				}
				$results[$attachment['parentid']]['attach'][] = $attachment;
			}
		}

		foreach ($results AS $key => $result)
		{
			if (empty($result))
			{
				continue;
			}

			if (!empty($result['attach']) AND is_array($result['attach']))
			{
				$results[$key]['photocount'] = count($result['attach']);
			}
			else
			{
				$results[$key]['photocount'] = 0;
			}
		}

		return $results;
	}


	/**
	 * Cleans the input in the $data array, specifically *after* any html/wysiwyg -> bbcode parsing.
	 *
	 * @param array $data Array of fieldname => data pairs, passed by reference.
	 */
	public function postBbcodeParseCleanRawtext(&$data)
	{
		/*
			image2 attachments
			Clean json-encoded attachment data that's part of the rawtext
			TODO: we do another regex match in the text library replaceAttachBbcodeTempids(). Any way to reduce dupe work and improve
			performance??
		 */
		if (preg_match_all('#\[(?<tag>attach|img2)=json\](?<jsondata>{(?:(?!}\[/\k<tag>\]).)*})\[/\k<tag>\]#i', $data['rawtext'], $matches))
		{
			foreach($matches['jsondata'] AS $key => $__data)
			{
				$custom_config = json_decode($__data, true);

				if (empty($custom_config))
				{
					// todo: better error handling if json encoded data was botched somehow?
					$custom_config = array();
				}

				/*
					We're forced to clean HTML at render instead of save because
					otherwise the wysiwyg <-> source mode doesn't get the same data and
					can cause issues with special characters (particularly double-quotes) in attributes.
					We do the cleaning @ bbcode parser's processCustomImgConfig().

					// KEEP THIS SYNCED, GREP FOR FOLLOWING IN includes/vb5/template/bbcode.php
					// GREP MARK IMAGE2 ACCEPTED CONFIG
				 */
				$accepted_config = array(
					'alt'	                  => vB_Cleaner::TYPE_NOHTML,
					'title'                   => vB_Cleaner::TYPE_NOHTML,
					'data-tempid'             => vB_Cleaner::TYPE_NOHTML,
					'data-attachmentid'       => vB_Cleaner::TYPE_INT,
					'width'                   => vB_Cleaner::TYPE_NUM,
					'height'                  => vB_Cleaner::TYPE_NUM,
					'data-align'              => vB_Cleaner::TYPE_NOHTML,
					'caption'                 => vB_Cleaner::TYPE_NOHTML,
					'data-linktype'           => vB_Cleaner::TYPE_INT,
					'data-linkurl'            => vB_Cleaner::TYPE_NOHTML, // todo: should this be TYPE_STR & cleaned when inserted into HTML??
					'data-linktarget'         => vB_Cleaner::TYPE_INT,
					'style'                   => vB_Cleaner::TYPE_STR, // Unset below if they do not have permission
					'src'                     => vB_Cleaner::TYPE_STR, // only used for [IMG2]..[/IMG2] This is cleaned by bbcode parser before html insert
					'data-size'               => vB_Cleaner::TYPE_NOHTML,
				);
				//$custom_config = vB::getCleaner()->cleanArray($custom_config, $accepted_config);
				foreach ($custom_config AS $key2 => $__unused)
				{
					if (!isset($accepted_config))
					{
						unset($custom_config[$key2]);
					}
				}


				// might be a bit nonstandard to be checking a permission here, but there's no easy way around it.
				if (isset($custom_config['style']))
				{
					$canStyle = vB::getUserContext()->getChannelPermission('forumpermissions', 'canattachmentcss', $data['parentid']);
					if (!$canStyle)
					{
						unset($custom_config['style']);
					}
				}

				if (strtolower($matches['tag'][$key]) == 'img2')
				{
					$prefix = "[IMG2=JSON]";
					$suffix = "[/IMG2]";
				}
				else
				{
					$prefix = "[ATTACH=JSON]";
					$suffix = "[/ATTACH]";
				}

				$newattachbbcode = $prefix . json_encode($custom_config, JSON_HEX_QUOT). $suffix;
				$data['rawtext'] = str_replace($matches[0][$key], $newattachbbcode, $data['rawtext']);
			}
		}
	}

	/**
	 * Updates a text node.
	 *
	 * @param	int	The node ID for the node that is being updated
	 * @param	array	Array of flags and new data for this node.
	 *			DATA: This array can contain new values for any of the fields
	 *			in the node table, and any of the fields in any of the extended
	 * 			tables for the content type for this node (see the $tablename property).
	 *			FLAGS: This array may also contain flags that affect behavior, but are
	 *			not part of the data saved to the tables. Flags: (may not be a complete list)
	 *			* nl2br - if true, converts any new lines in rawtext to <br />
	 * @param	bool	Flag instructing us to convert rawtext from WYSIWYG editor markup to BBCode.
	 *
	 * @return	boolean
	 */
	public function update($nodeid, $data, $convertWysiwygTextToBbcode = true)
	{
		// html permission already checked in the api
		if (isset($data['htmlstate']) AND $data['htmlstate'] == 'on' AND isset($data['disable_bbcode']) AND $data['disable_bbcode'] == 1)
		{
			// article 'static html' type
			$convertWysiwygTextToBbcode = false;
			if (isset($data['nl2br']))
			{
				$data['nl2br'] = false;
			}
		}

		$node = $this->assertor->getRow('vBForum:node', array('nodeid' => $nodeid));

		//We may need to update the "last" counts.
		if (isset($data['publishdate']) OR isset($data['unpublishdate']) OR isset($data['showpublished']))
		{
			$updates = array('lastauthorid' => $node['userid'], 'nodeid' => $nodeid);

			if (!isset($data['publishdate']))
			{
				$updates['lastcontent'] = $node['publishdate'];
			}
			else
			{
				$updates['lastcontent'] = $data['publishdate'];
			}

			if (empty($data['lastcontentauthor']))
			{
				$updates['lastcontentauthor'] = $node['authorname'];
			}
			else
			{
				$updates['lastcontentauthor'] = $data['authorname'];
			}

			if (empty($data['lastauthorid']))
			{
				$updates['lastauthorid'] = $node['userid'];
			}
		}

		$parents = vB_Library::instance('node')->getParents($node['parentid']);
		$parents = array_reverse($parents);

		if (!empty($data['rawtext']))
		{
			// Needed for converting new lines for the mobile app VBV-9886
			// Also converts new lines for the web app, when CKEditor is not in use (plain text area) VBV-11279
			if (isset($data['nl2br']) AND $data['nl2br'])
			{
				$data['rawtext'] = nl2br($data['rawtext']);
			}

			if ($convertWysiwygTextToBbcode)
			{
				$channelType = vB_Types::instance()->getContentTypeId('vBForum_Channel');

				// check if we can autoparselinks
				$options['autoparselinks'] = true;
				foreach($parents AS $parent)
				{
					// currently only groups and blogs seem to disallow this
					if (
							($parent['contenttypeid'] == $channelType
							AND vB_Api::instanceInternal('socialgroup')->isSGNode($parent['nodeid']) OR vB_Api::instanceInternal('blog')->isBlogNode($parent['nodeid']))
							AND ($channelOptions = vB_Library::instance('node')->getNodeOptions($parent['nodeid']))
					)
					{
						$options['autoparselinks'] = $channelOptions['autoparselinks'];
					}
				}

				$data['rawtext'] = vB_Api::instanceInternal('bbcode')->convertWysiwygTextToBbcode($data['rawtext'], $options);
				$this->postBbcodeParseCleanRawtext($data); // clean attachment bbcode data.
				if (empty($data['description']))
				{
					$data['description'] = vB_String::getPreviewText($this->replaceAndStripBbcode($data['rawtext'], $data), self::$descriptionLength);
				}
				else
				{
					$data['description'] = vB_String::getPreviewText($this->replaceAndStripBbcode($data['description']));
				}
			}

			// Shout prevention
			$data['rawtext'] = $this->fetchNoShoutingText($data['rawtext']);

			if (!isset($data['pagetext']))
			{
				$data['pagetext'] = '';
			}

			if (!isset($data['previewtext']))
			{
				$data['previewtext'] = '';
			}

			//Set the "hasvideo" value;
			$filter = '~\[video.*\[\/video~i';
			$matches = array();
			$count = preg_match_all($filter, $data['rawtext'], $matches);

			if ($count > 0 )
			{
				$data['hasvideo'] = 1;
			}
			else
			{
				$data['hasvideo'] = 0;
			}
		}
		else
		{
			if (empty($data['description']))
			{
				// when editing, and title & text have not changed, rawtext, title, and description can all be empty
				if (!empty($data['title']))
				{
					$data['description'] = vB_String::getPreviewText($this->parseAndStrip($data['title']));
				}
			}
			else
			{
				$data['description'] = vB_String::getPreviewText($this->parseAndStrip($data['description']));
			}
		}

		// Shout prevention
		if (!empty($data['title']))
		{
			$data['title'] = $this->fetchNoShoutingText($data['title']);
		}

		$isSpam = false;

		if (!empty($data['rawtext']) OR !empty($data['title']))
		{
			//make sure we have the fields we need for the spam check
			$spamCheckData = $data;

			$fields = array(
				'rawtext' => 'description',
				'title' => 'title',
				'parentid' => 'parentid',
			);
			foreach($fields AS $field => $alias)
			{
				if (empty($spamCheckData[$field]))
				{
					$spamCheckData[$field] = $node[$alias];
				}
			}
			// todo: Should we only check spam if any of the data has changed since the last time?
			// That way, if a post gets approved after it triggers spam, and something about it is updated but
			// not one of the spamCheckData fields, it won't get sent back into moderation.
			$isSpam = $this->checkSpam($node['userid'], $node['authorname'], $spamCheckData, array(), $parents);
		}

		if ($isSpam)
		{
			$data['approved'] = 0;
			$data['showapproved'] = 0;
			$this->assertor->assertQuery('spamlog', array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_INSERTIGNORE, 'nodeid' => $node['nodeid']));
		}

		$published = $this->isPublished($data);
		$result = parent::update($nodeid, $data);

		if (isset($node) AND ($published <> $node['showpublished']))
		{
			//We don't need to update the counts- that gets done in the parent class.
			if ($published)
			{
				$parentids = array();
				foreach($parents AS $node)
				{
					$parentids[] = $node['nodeid'];
				}

				$updates['parentlist'] = $parentids;
				$updates['lastcontentid'] = $nodeid;
				$this->assertor->assertQuery('vBForum:setLastDataParentList', $updates);
			}
		}

		$this->nodeApi->clearCacheEvents(array($nodeid, $node['parentid']));

		if ($result === true AND $isSpam)
		{
			return array('success' => true, 'warnings' => array('warning_spam_post'));
		}

		return $result;
	}

	public function parseAndStrip($text, $wysiwyg=true)
	{
		if (!empty($text))
		{
			// We can ignore autoparselinks setting here since the tags will be stripped anyway
			$bbOptions = array(
				'autoparselinks' => false,
			);

			if ($wysiwyg)
			{
				$text = vB_Api::instanceInternal('bbcode')->convertWysiwygTextToBbcode($text, $bbOptions);
			}

			return $this->replaceAndStripBbcode($text);
		}

		return '';
	}

	protected function replaceAndStripBbcode($text, $data = array())
	{
		if (!empty($text))
		{
			// replace [attach...] bbcode with a replacement string so that encoded bits don't get output into ugly double-escaped HTML
			// when used in page meta description.
			$text = $this->replaceAttachBbcodeForParseAndStrip($text, $data);

			// Skipping postBbcodeParseCleanRawtext() as anything that's to be saved in DB should've already gone through it via add() or update().
			$options = vB::getDatastore()->getValue('options');
			return trim(vB_String::stripBbcode($text, $options['ignorequotechars']));
		}

		return '';
	}

	/**
	 * Adds a new node.
	 *
	 * @param	mixed		Array of field => value pairs which define the record.
	 *  -- htmlstate
	 *  -- parentid
	 *  -- disable_bbcode
	 *  -- rawtext
	 *  -- and others
	 * @param	array		Array of options for the content being created
	 * 						Understands skipTransaction, skipFloodCheck, floodchecktime, skipDupCheck, skipNotification, nl2br, autoparselinks.
	 *							- nl2br: if TRUE, all \n will be converted to <br /> so that it's not removed by the html parser (e.g. comments).
	 * @param	bool		Convert text to bbcode
	 *
	 * @return	array
	 * 	-- nodeid (int)
	 * 	-- success (bool)
	 * 	-- cacheEvents (array of strings)
	 * 	-- nodeVals (array of field => value)
	 * 	-- attachments (array of attachment records)
	 */
	public function add($data, array $options = array(), $convertWysiwygTextToBbcode = true)
	{
		//Store this so we know whether we should call afterAdd()
		$skipTransaction = !empty($options['skipTransaction']);

		// html permission already checked in the api
		if (isset($data['htmlstate']) AND $data['htmlstate'] == 'on' AND isset($data['disable_bbcode']) AND $data['disable_bbcode'] == 1)
		{
			// article 'static html' type
			$convertWysiwygTextToBbcode = false;
			if (isset($options['nl2br']))
			{
				$options['nl2br'] = false;
			}
		}

		if (empty($data['parentid']))
		{
			throw new Exception('need_parent_node');
		}

		// Get parents for cleaning cache and checking permissions
		$parents = vB_Library::instance('node')->getParents($data['parentid']);
		$parents = array_reverse($parents);

		// convert to bbcode for saving
		if (isset($data['rawtext']) AND !empty($data['rawtext']))
		{
			// Converts new lines when CKEditor is not in use (plain text area) VBV-11279
			// also used for the mobile app.
			if (isset($options['nl2br']) AND $options['nl2br'])
			{
				$data['rawtext'] = nl2br($data['rawtext']);
			}

			if ($convertWysiwygTextToBbcode)
			{
				$channelType = vB_Types::instance()->getContentTypeId('vBForum_Channel');

				// check if we can autoparselinks
				$options['autoparselinks'] = true;
				foreach($parents AS $parent)
				{
					// currently only groups and blogs seem to disallow this
					if (
							($parent['contenttypeid'] == $channelType
							AND vB_Api::instanceInternal('socialgroup')->isSGNode($parent['nodeid']) OR vB_Api::instanceInternal('blog')->isBlogNode($parent['nodeid']))
							AND ($channelOptions = vB_Library::instance('node')->getNodeOptions($parent['nodeid']))
					)
					{
						$options['autoparselinks'] = $channelOptions['autoparselinks'];
					}
				}

				$data['rawtext'] = vB_Api::instanceInternal('bbcode')->convertWysiwygTextToBbcode($data['rawtext'], $options);
				$this->postBbcodeParseCleanRawtext($data); // clean attachment bbcode data.
				if (empty($data['description']))
				{
					$data['description'] = vB_String::getPreviewText($this->replaceAndStripBbcode($data['rawtext'], $data), self::$descriptionLength);
				}
				else
				{
					$data['description'] = vB_String::getPreviewText($this->replaceAndStripBbcode($data['description']));
				}
			}

			// Shout prevention
			$data['rawtext'] = $this->fetchNoShoutingText($data['rawtext']);
		}
		else
		{
			if (empty($data['description']))
			{
				$data['description'] = (isset($data['title'])) ?
					(vB_String::getPreviewText($this->parseAndStrip($data['title']))) : '';
			}
			else
			{
				$data['description'] = vB_String::getPreviewText($this->parseAndStrip($data['description']));
			}
		}

		// Shout prevention
		if (!empty($data['title']))
		{
			$data['title'] = $this->fetchNoShoutingText($data['title']);
		}

		if (empty($data['userid']))
		{
			$user = vB::getCurrentSession()->fetch_userinfo();
			$data['authorname'] = $user['username'];
			$userid = $data['userid'] = $user['userid'];
		}
		else
		{
			$userid = $data['userid'];
			$user = vB_Library::instance('user')->fetchUserinfo($userid);
			if (empty($data['authorname']))
			{
				$data['authorname'] = $user['username'];
			}
		}

		$isSpam = $this->checkSpam($userid, $data['authorname'], $data, $options, $parents);
		if ($isSpam)
		{
			$data['approved'] = 0;
			$data['showapproved'] = 0;
		}

		//We need a copy of the data, maybe
		$updates = array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_STORED);

		//Set the "hasvideo" value;
		if (!empty($data['rawtext']))
		{
			$filter = '~\[video.*\[\/video~i';
			$matches = array();
			$count = preg_match_all($filter, $data['rawtext'], $matches);

			if ($count > 0 )
			{
				$data['hasvideo'] = 1;
			}
			else
			{
				$data['hasvideo'] = 0;
			}
		}

		//publishdate is set in the parent class and api. If not set in data, it'll be set to vB::getRequest()->getTimeNow() in parent::add()
		if (isset($data['publishdate']))
		{
			$updates['lastcontent'] = $data['publishdate'];
		}
		else
		{
			$updates['lastcontent'] = vB::getRequest()->getTimeNow();
		}

		if (isset($data['userid']))
		{
			$updates['lastauthorid'] = $data['userid'];
		}
		else
		{
			$updates['lastauthorid'] = $data['userid'] = vB::getCurrentSession()->get('userid');
		}

		if (isset($data['authorname']))
		{
			$updates['lastcontentauthor'] = $data['authorname'];
		}
		else
		{
			$author = $this->assertor->getRow('user', array(
				vB_dB_Query::TYPE_KEY =>vB_dB_Query::QUERY_SELECT,
				'userid' => $data['userid'],
			));
			$data['authorname'] = $author['username'];
			$updates['lastcontentauthor'] = $author['username'];
		}

		$published = $this->isPublished($data);
		try
		{
			if (!$skipTransaction)
			{
				$this->assertor->beginTransaction();
			}
			$options['skipTransaction'] = true;
			$results = parent::add($data, $options);
			$newNode = $this->getFullContent($results['nodeid']);
			$newNode = array_pop($newNode);
			// Obtain and set generic conversation route
			$conversation = $this->getConversationParent($results['nodeid']);

			$routeid = vB_Api::instanceInternal('route')->getChannelConversationRoute($conversation['parentid']);
			$this->assertor->update('vBForum:node', array('routeid' => $routeid), array('nodeid' => $results['nodeid']));

			if (!$skipTransaction)
			{
				$this->beforeCommit($results['nodeid'], $data, $options, $results['cacheEvents'], $results['nodeVals']);
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

		//set the last post and count data.
		/* 	We do something similar (vBForum:fixNodeLast) that ends up affect parent last data in the parent add(),
		 *	downstream of updateParentCounts(). We should probably refactor to just do it in one place. I tried to
		 *	comment this section out, but the node test told me that they're not *quite* the same and this is
		 *	necessary.
		 */
		$approved = ($newNode['showapproved'] AND $newNode['approved']);
		if ($published AND $approved AND (!isset($options['skipUpdateLastContent']) OR !$options['skipUpdateLastContent']))
		{
			$updates['nodeid'] = $results['nodeid'];
			$updates['lastcontentid'] = $results['nodeid'];

			$parentids = array();
			foreach($parents AS $node)
			{
				$parentids[] = $node['nodeid'];
			}

			$updates['parentlist'] = $parentids;
			$this->qryAfterAdd[] = array('definition' => 'vBForum:setLastDataParentList', 'data' => $updates);
		}

		if (!$skipTransaction)
		{
			//The child classes that have their own transactions all set this to true so afterAdd is always called just once.
			$this->afterAdd($results['nodeid'], $data, $options, $results['cacheEvents'], $results['nodeVals']);
		}

		if ($isSpam)
		{
			$this->assertor->assertQuery('spamlog', array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_INSERTIGNORE, 'nodeid' => $results['nodeid']));
		}

		$cachedNodes = array($results['nodeid']);
		foreach ($parents AS $node)
		{
			$cachedNodes[] = $node['nodeid'];
		}

		$this->nodeApi->clearCacheEvents($cachedNodes);
		$this->nodeApi->clearCacheEvents(array($results['nodeid'], $data['parentid']));

		return $results;
	}

	private function checkSpam($userid, $authorname, $data, $options, $parents)
	{
		$isSpam = false;

		$userContext = vB::getUserContext($userid);

		$exemptFromCheck = $userContext->getChannelPermission('forumpermissions2', 'exemptfromspamcheck', $data['parentid']);
		$authorIsMod = $userContext->getChannelPermission('moderatorpermissions', 'canmoderateposts', $data['parentid']);
		$currenUserIsMod = vB::getUserContext()->getChannelPermission('moderatorpermissions', 'canmoderateposts', $data['parentid']);

		$skipSpam = ($exemptFromCheck OR $authorIsMod	OR (!empty($options['skipSpamCheck']) AND $currenUserIsMod));

		//run the spam check.
		if (!$skipSpam AND $this->spamType !== false)
		{
			$user = vB_Library::instance('user')->fetchUserinfo($userid);

			$comment_content = $data['rawtext'];
			//VBV-15098 - for topic starters, prepend with topic title & 2 new lines.
			// We need to check if parent is a channel to see if this is a starter. As a shortcut, if it lacks a title
			// assume it's not a starter and we don't have to bother going through parents
			if (!empty($data['title']))
			{
				$parentNode = null;
				foreach($parents AS $parent)
				{
					if ($parent['nodeid'] == $data['parentid'])
					{
						$parentNode = $parent;
						break;
					}
				}
				$channelType = vB_Types::instance()->getContentTypeId('vBForum_Channel');
				if ($parentNode['contenttypeid'] == $channelType)
				{
					$comment_content = $data['title'] . "\n\n" . $data['rawtext'];
				}
			}

			$params = array('comment_type' => 'user_post', 'comment_content' => $comment_content);

			$params['comment_author'] = $authorname;
//uncomment this line to force a "spam" response
//			$params['comment_author'] = 'viagra-test-123';
			$params['comment_author_email'] = $user['email'];

			$akismet = vB_Akismet::instance();
			$result = $akismet->verifyText($params);

			if ($result == 'spam')
			{
				$isSpam = true;
			}
		}

		if (!$skipSpam AND !$isSpam AND $blacklist = trim($this->options['vb_antispam_badwords']))
		{
			$badwords = preg_split('#\s+#', $blacklist, -1, PREG_SPLIT_NO_EMPTY);
			if (str_replace($badwords, '', strtolower($data['rawtext'])) != strtolower($data['rawtext']))
			{
				$isSpam = true;
			}
		}

		if (!$skipSpam AND !$isSpam)
		{
			preg_match_all('#\[(url|email).*\[/(\\1)\]#siU', $data['rawtext'], $matches);
			if (isset($matches[0]) AND count($matches[0]) > intval($this->options['vb_antispam_maxurl']))
			{
				$isSpam = true;
			}
		}

		return $isSpam;
	}

	/**
	 * This returns a string with quoted strings in bbcode format.
	 *
	 * @param	array|int $nodeids
	 * @return array|string either the quote for the node or an array of $nodeid => $quotes
	 * 	for the array of nodes
	 */
	public function getQuotes($nodeids)
	{
		$nodes = $this->getContent($nodeids);
		$quotes = $this->getQuotesFromNodes($nodes);
		if (is_array($nodeids))
		{
			return $quotes;
		}
		else
		{
			return $quotes[$nodeids];
		}
	}

	/**
	 *	Helper function to allow getQuotes in the API and Library classes to
	 *	generate the node list independantly (so that the API can check perms
	 *	without loading the nodes twice).
	 *
	 *	@param array $nodes -- array of nodes arrays from getContent (API or Library version)
	 *		does not accept a single node array
	 */
	public function getQuotesFromNodes($nodes)
	{
		$quotes = array();
		foreach ($nodes AS $node)
		{
			$nodeid = $node['nodeid'];
			$quotetext = strip_quotes(fetch_censored_text($node['rawtext']));
			//the username is stored htmlencoded.  The bbcode will html encode it parameters (and absolutely needs to)
			//so we need to unencode it here to avoid double encoding
			$quotes[$nodeid] = '[QUOTE=' . html_entity_decode($node['authorname']) . ';n' . $nodeid . ']' . $quotetext. '[/QUOTE]';
		}
		return $quotes;
	}

	public function getIndexableFromNode($content, $include_attachments = true)
	{
		$indexableContent = parent::getIndexableFromNode($content, $include_attachments);
		if (!empty($content['rawtext']))
		{
			$indexableContent['rawtext'] = $content['rawtext'];
		}
		return $indexableContent;
	}

	/**
	 * Adds content info to $result so that merged content can be edited.
	 * @param array $result
	 * @param array $content
	 */
	public function mergeContentInfo(&$result, $content)
	{
		if (!isset($content['rawtext']))
		{
			throw new vB_Exception_Api('invalid_content_info');
		}

		if (!isset($result['rawtext']) || empty($result['rawtext']))
		{
			$result['rawtext'] = $content['rawtext'];
		}
		else
		{
			$result['rawtext'] .= "\n{$content['rawtext']}";
		}
	}

	/**
	 * Performs the merge of content and updates the node.
	 * @param type $data
	 * @return type
	 */
	public function mergeContent($data)
	{
		// if we are merging text, the contenttype must already be text, so just update rawtext, author
		$update = array(
			'userid' => $data['destauthorid'],
			'rawtext' => $data['text']
		);

		return $this->update($data['destnodeid'], $update);
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

		$userid = vB::getCurrentSession()->get('userid');
		foreach($nodesContent AS $record)
		{
			if (isset($record['nodeid']))
			{
				if (($record['starter'] == $record['nodeid']) AND ($userid > 0) AND vB_Library::instance('node')->canEditThreadTitle($record['nodeid'], $record))
				{
					$record['canedittitle'] = 1;
				}
				else
				{
					$record['canedittitle'] = 0;
				}
				$results[$record['nodeid']] = $record;
			}

		}

		return $results;
	}

	/**
	 * Handles uploaded attachments-- Adds the attach nodes and handles updating
	 * data that needs updating after the attachments are added.
	 *
	 * @param	string	$type -- (update|add) Indicates if we're adding or updating the node.
	 * @param	int	$nodeid -- The nodeid that was added/updated
	 * @param	array	$data -- The standard add/update $data array. See the add() or
	 *			update() functions in this class.
	 * @param	array	$options -- The standard $options array for the 'add' function in this class.
	 *
	 * @return	array	Array of tempid => attachid key:value pairs.
	 */
	protected function handleAttachments($type, $nodeid, $data, $options = array())
	{
		// Attachment permissions/limits are already checked by
		// vB_Api_Content_Text->checkAttachmentPermissions() called from
		// update() and add().

		// Attachment data is cleaned from the text API's cleanInput method
		// (which calls the attach API's cleanInput) as part of the cleaning
		// thus making it safe to call the attach *library* below.

		$result = array();
		$attachLib = null;
		$node = null;

		// on update, remove requested existing attachments
		if ($type === 'update')
		{
			if (!empty($data['removeattachments']))
			{
				$attachLib = vB_Library::instance('Content_Attach');

				foreach($data['removeattachments'] AS $key => $attachmentid)
				{
					// TODO figure out a way to do this in bulk
					// See above note. Data cleaned via text API cleanInput
					$attachLib->delete($attachmentid);
				}
			}
		}

		// add any attachments (this is the same for update and add)
		if (!empty($data['attachments']))
		{
			$node = $this->getFullContent($nodeid);
			$node = reset($node);

			if (!$attachLib)
			{
				$attachLib = vB_Library::instance('Content_Attach');
			}

			foreach($data['attachments'] AS $key => $attachment)
			{
				if (isset($attachment['options']))
				{
					$attachOptions = $attachment['options'];
				}
				else
				{
					$attachOptions = $options; // add() options array passed in
				}

				$attachment['parentid'] = $nodeid;

				// Copied from the 'add' code, was not present in the 'update' code
				if ($type === 'add')
				{
					$attachment['publishdate'] = $node['publishdate'];
					$attachment['showpublished'] = $node['showpublished'];
					$attachment['showapproved'] = $node['showapproved'];
				}

				// See above note. Data cleaned via text API cleanInput
				$attachResult = $attachLib->add($attachment, $attachOptions);
				if (!empty($attachResult['nodeid']))
				{
					$result[$key] = $attachResult['nodeid'];
				}
			}
		}

		// **Updating**: always run this because even if they haven't added any
		// new attachments, the user may have inserted an image inline that needs
		// translating or changes the preview image. Also, for preview images,
		// even if all attachments have been removed, we need to blank the preview
		// image field.
		// **Adding**: when adding, we only need to run this if attachments have
		// been uploaded (if there are no attachments, there are no [attach]
		// bbcodes to fix and nothing to populate the preview image with) *OR*
		// if this is a Photo type post with photos.
		if ($type === 'update' OR !empty($result) OR !empty($data['photos']))
		{
			// need to pull the node information again, after
			// attachments have been added
			$this->nodeApi->clearCacheEvents(array($nodeid));
			$node = $this->getFullContent($nodeid);
			$node = reset($node);

			$updateValues = array();

			// fix the [attach] bbcode (change the tempid to the attach nodeid)
			if (!empty($result))
			{
				$rawtext = $this->replaceAttachBbcodeTempids($node['rawtext'], $result);
				if ($rawtext !== $node['rawtext'])
				{
					$updateValues['rawtext'] = $rawtext;
					$node['rawtext'] = $rawtext; // getPreviewImage needs the updated rawtext
				}
			}

			// set the first attachment as the preview image
			$previewimage = $this->getPreviewImage($node);
			// update the preview image if there is a change
			// don't check type in this comparison (!==) so that
			// false, null, and '' are considered the same (no preview image)
			if ($previewimage != $node['previewimage'])
			{
				if ($previewimage)
				{
					$updateValues['previewimage'] = $previewimage;
				}
				else
				{
					$updateValues['previewimage'] = vB_dB_Query::VALUE_ISNULL;
				}
			}

			if (!empty($updateValues))
			{
				$this->assertor->update('vBForum:text', $updateValues, array('nodeid' => $nodeid));
				$this->nodeApi->clearCacheEvents(array($nodeid));
			}
		}

		return $result;
	}

	/**
	 * DEPRECATED: This needs to remain until the corresponding API function is removed
	 *
	 * Used to change temporary id references in the specified node's rawtext to attach nodeids
	 *
	 * @deprecated Superceded by replaceAttachBbcodeTempids
	 *
	 * @param	mixed	$nodeId nodeid or array of nodeids
	 * @param	array	$content (optional) Node content array returned by getFullContent
	 * @param	array	$keysToAttachid (optional) array({tempid of attachment} => {attachment's nodeid})
	 *			maps temporary-ids (array key) of newly added attachments and
	 *			corresponding nodeids (array value) of said attachments.
	 *			While this is optional for historical reasons, it must be provided
	 *			if any temporary id references in the rawtext need to be replaced.
	 */
	public function fixAttachBBCode($nodeId, $content = null, $keysToAttachid = array())
	{
		if (!$content)
		{
			$content = $this->getFullContent($nodeId);
			$content = array_pop($content);
		}

		$rawtext = $this->replaceAttachBbcodeTempids($content['rawtext'], $keysToAttachid);

		// We need to manually insert the new 'rawtext' value instead
		// of calling this->update, since the update method does
		// many, many other things that we have no need to do here.
		// See VBV-13003.
		if ($rawtext !== $content['rawtext'])
		{
			$this->assertor->update('vBForum:text', array('rawtext' => $rawtext), array('nodeid' => $nodeId));
			$this->nodeApi->clearCacheEvents(array($nodeId));
		}
	}

	/**
	 * Replace [attach], [img] or [img2] bbcode with a plaintext keyword for use in meta description.
	 *
	 * @param	string   $rawtext   Text to be replaced.
	 * @param	array    $data      optional. Data array provided to add() or update() if available. May contain
	 *			                    'attachments' data.
	 *
	 * @return	string
	 */
	protected function replaceAttachBbcodeForParseAndStrip($rawtext, $data = array())
	{
		/*
			RESULTS OF THIS FUNCTION IS NOT SAFE FOR HTML!!!

			This function expects that the inputs went through postBbcodeParseCleanRawtext(), then unescaped the
			values that are expected to have been escaped to prevent double-escaping of special characters.

			Then the result is expected to go through vB_String::getPreviewText(), which will go through
			vB_String::htmlSpecialCharsUni(), before being used for HTML.

			At the moment, this function is called as part of $this->parseAndStrip() right after $this->postBbcodeParseCleanRawtext(),
			and the result is used for node.description after being put through vB_String::getPreviewText() (which will do HTML escaping).
			So the value saved to DB should be safe to use for HTML.

			It seems that the header template currently further escapes the description, meaning HTML entities will be double-escaped,
			but that's out of scope for this function & JIRA.
		 */

		/*
			match [attach], [attach=json] (& =right|left|config), [img] & [img2] bbcodes and try to extract the best data-point to use as replacement for the bbcode
			for meta description purposes.
			If advanced config is provided from the image2 plugin, the following values will be used in order/as available:
				caption, title, alt, src
			For external images, the src is used as the replacement variable unless it other data above was provided.
			For non-image attachments, it will attempt to find the provided filename and use that instead.
			If all else fails, it'll use the string 'attachment' for [attach], and the bbcode content (which should contain the SRC url) for [img]|[img2]
		 */
		if (preg_match_all('#\[(?<tag>attach|img2?)(?:=(?<align>right|left|config|json))?\](?<body>(?:(?!\[/\k<tag>\]).)*)\[/\k<tag>\]#i', $rawtext, $matches))
		{
			foreach($matches['body'] AS $__key => $__body)
			{
				$find = $matches[0][$__key]; // full match
				if (isset($matches['tag'][$__key]) AND strtolower($matches['tag'][$__key]) =='attach' )
				{
					$replace = 'attachment'; // Let's use this string as the default replacement for attach bbcodes.
				}
				else
				{
					$replace = $__body; // Legacy img codes have a URL in the body, so use that by default.
				}

				if (isset($matches['align'][$__key]))
				{
					$align = strtolower($matches['align'][$__key]);
				}
				else
				{
					$align = '';
				}
				if ($align == 'json')
				{
					$custom_config = json_decode($__body, true);

					if (!empty($custom_config))
					{
						/*
							Try to use caption, title, or alt, in that order.
							These values are expected to be cleaned by postBbcodeParseCleanRawtext() as TYPE_NOHTML.
							To prevent double escaping by getPreviewText(), we un-escape these.
						 */
						if (!empty($custom_config['caption']))
						{
							$replace = vB_String::unHtmlSpecialChars($custom_config['caption']);
						}
						else if (!empty($custom_config['title']))
						{
							$replace = vB_String::unHtmlSpecialChars($custom_config['title']);
						}
						else if (!empty($custom_config['alt']))
						{
							$replace = vB_String::unHtmlSpecialChars($custom_config['alt']);
						}
						else if (!empty($custom_config['src']))
						{
							// this one isn't cleaned by postBbcodeParseCleanRawtext()
							$replace = $custom_config['src'];
						}
						else if (!empty($data['attachments']) AND !empty($custom_config['data-tempid']) AND isset($data['attachments'][$custom_config['data-tempid']]))
						{
							// last ditch effort. Use filename if provided. Regardless of title above, if this value is provided
							// it'll be saved to the attach table, and it will be used by the bbcode parser as part of the phrased title.
							$attachData = $data['attachments'][$custom_config['data-tempid']];
							if (!empty($attachData['filename']))
							{
								// If available, try filename as the replacement as it may be slightly more meaningful than "attachment"
								$replace = $attachData['filename'];
							}
						}
						// else just go with default above.
					}

				}
				else
				{
					/*
						A non-image attachment, or a legacy img plugin attachment.
					 */
					if (!empty($data['attachments']) AND isset($data['attachments'][$__body]))
					{
						$attachData = $data['attachments'][$__body];
						if (!empty($attachData['filename']))
						{
							// If available, try filename as the replacement as it may be slightly more meaningful than "attachment"
							$replace = $attachData['filename'];
						}
					}
				}

				$rawtext = str_replace($find, $replace, $rawtext);
			}
		}


		return $rawtext;
	}

	/**
	 * Replaces the tempids in [attach] bbcodes with the nodeid/attachid for the
	 * attachment.
	 *
	 * @param	string	The rawtext for the node
	 * @param	array	Mapping of tempids => nodeid/attachid
	 *
	 * @return	string	The rawtext with the modified [attach] bbcodes
	 */
	protected function replaceAttachBbcodeTempids($rawtext, $keysToAttachid)
	{
		// keep the regex matched with the one in vB5_Template_Bbcode's handle_bbcode_img()
		if (preg_match_all('#\[attach(?:=(right|left|config|json))?\]((?:[[:alnum:]_]+)|{(?:(?!}\[/attach\]).)*})\[/attach\]#i', $rawtext, $matches))
		{
			foreach($matches[2] AS $key => $attachmentid)
			{
				$align = $matches[1]["$key"];
				// refer to wysiwyghtmlparser's handleWysiwygImg() for the code that replaces image tags with attach bbcodes
				if (preg_match('#(?<attachmentid>temp_\d+_\d+_\d+)#', $attachmentid, $matches_id))
				{
					$old_inner_code = $attachmentid;
					$attachmentid = $matches_id['attachmentid'];
					if (!empty($keysToAttachid[$attachmentid]))
					{
						if ($align == 'JSON')
						{
							// todo: if this regex turns out fragile, figure out a non-regex way to do it, similar to how wysiwyghtmlparser crafts this.
							$attachnodeid = (int) $keysToAttachid[$attachmentid];
							$custom_config = json_decode($old_inner_code, true);
							unset($custom_config['data-tempid']);
							$custom_config['data-attachmentid'] = $attachnodeid;
							$newattachbbcode = "[ATTACH=JSON]" . json_encode($custom_config, JSON_HEX_QUOT). "[/ATTACH]";
							$rawtext = str_replace($matches[0][$key], $newattachbbcode, $rawtext);
						}
						else
						{
							$attachnodeid = (int) $keysToAttachid[$attachmentid];
							$newattachbbcode = "[ATTACH" . (!empty($align) ? '=' . $align : '') . "]n" . $attachnodeid . "[/ATTACH]";
							$rawtext = str_replace($matches[0][$key], $newattachbbcode, $rawtext);
						}
					}
				}
			}
		}

		return $rawtext;
	}

	/**
	 * DEPRECATED: This needs to remain until the corresponding API function is removed
	 *
	 * Populates the previewimage field
	 * for this node. To be called after the node is saved and the
	 * attachments added.
	 *
	 * Finds the first image in the post text that can be used as a
	 * previewimage (uploaded here), or uses the first image attachment.
	 *
	 * @deprecated Superceded by getPreviewImage
	 *
	 * @param	int	Nodeid
	 * @param	array	$node (optional) Node content array returned by getFullContent
	 */
	public function autoPopulatePreviewImage($nodeId, $node = null)
	{
		if (!$node)
		{
			$node = $this->getFullContent($nodeId);
			$node = $node[$nodeId];
		}

		// This was previously restricted to $node['channeltype'] == 'article'
		// so the preview image was only populated for article nodes. We now also
		// use the preview image for the content slider module which displays
		// featured topics from any channel, so this should no longer be limited
		// to articles. For articles, the previewimage is displayed in the
		// channel/category listing.

		$data = array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'nodeid' => $nodeId,
			'previewimage' => vB_dB_Query::VALUE_ISNULL,
		);

		$attachid = $this->getPreviewImage($node);
		if ($attachid)
		{
			$data['previewimage'] = $attachid;
		}

		if ($data['previewimage'] != $node['previewimage'])
		{
			//At this point we're in an update or insert. We should just use a direct assertor query.
			$this->assertor->assertQuery('vBForum:text', $data);
			vB_Cache::allCacheEvent('nodeChg_' . $nodeId);
		}
	}

	/**
	 * Determines the best attachment to use for the preview image and returns the attachid/nodeid.
	 *
	 * @param	array	The node array returned by getFullContent
	 *
	 * @return	int|bool	The nodeid of the attachment that should be used as the preview image, or false for no preview image
	 */
	protected function getPreviewImage($node)
	{
		$attachmentids = array();
		$legacyattachmentids = array();

		// try images embedded in the text
		if (!empty($node['rawtext']))
		{
			// [ATTACH], [ATTACH=XXX], [IMG], [IMG=XXX]
			if (preg_match_all('#\[(ATTACH|IMG)(?:=[^]]+)?\](.*)\[\/\1\]#siU', $node['rawtext'], $matches))
			{
				if (!empty($matches[2]))
				{
					foreach ($matches[2] AS $match)
					{
						if (preg_match('#filedata\/fetch\?(?:filedata)?id=(\d+)#si', $match, $idmatch))
						{
							$attachmentids[] = (int) $idmatch[1];
						}
						else if (preg_match('#^n(\d+)$#siU', $match, $idmatch))
						{
							$attachmentids[] = (int) $idmatch[1];
						}
						else if (!empty($match) AND ctype_digit($match))
						{
							// legacy attachment without the 'n' prefix
							$legacyattachmentids[] = (int) $match;
						}
					}
				}
			}
		}

		// convert legacy attachment ids to current attachment ids
		if (!empty($legacyattachmentids))
		{
			$legacyattachments = vB_Api::instanceInternal('filedata')->fetchLegacyAttachments($legacyattachmentids);

			foreach ($legacyattachments AS $legacyattachment)
			{
				// TODO: Some legacy attachments may not be visible due to permissions. I don't think this function
				// as a whole cares about attachment permissions, since this is called from inside update(), and chances
				// are that the user who is updating this node can see all attachments in it, but perhaps the preview
				// image should only be one that's visible to guests? If so, check $legacyattachment['cangetimgattachment']
				// before setting here.
				$attachmentids[] = $legacyattachment['nodeid'];
			}
			unset($legacyattachmentids, $legacyattachments, $legacyattachment);
		}

		// try attachments (this includes gallery items from the "photo" content type)
		// we have two places where attachments can be found in the node data,
		// check both for greater resilience.
		$attachments = array();
		foreach (array('attach', 'attachments') AS $sourceKey)
		{
			if (!empty($node[$sourceKey]) AND is_array($node[$sourceKey]))
			{
				foreach($node[$sourceKey] AS &$attachment)
				{
					$attachmentids[] = $attachment['nodeid'];
					$attachments[$attachment['nodeid']] =& $attachment;
				}
			}
			unset($attachment);
		}

		$attachmentids = array_unique($attachmentids);
		if (!empty($attachmentids))
		{
			// use the first image found
			$attachment = null;
			$imageExtensions = array('gif', 'jpg', 'jpeg', 'jpe', 'png', 'bmp', 'tiff', 'tif', 'psd', 'pdf');
			foreach ($attachmentids AS $attachmentid)
			{
				if (isset($attachments[$attachmentid]['extension']) AND in_array(strtolower($attachments[$attachmentid]['extension']), $imageExtensions, true))
				{
					$attachment =& $attachments[$attachmentid];
					break;
				}
			}

			if ($attachment !== null)
			{
				return $attachment['nodeid'];
			}
		}

		return false;
	}


	//if the shouting functions are needed more generally they should be moved
	//to the string class, the utility string module, or a utility module
	//(if they can be seperated from the application suitably).  They
	//should not be public methods on this class.
	/**
	 * Stops text being all UPPER CASE
	 *
	 * @param	string	The text to apply 'anti-shouting' to
	 *
	 * @return	string The text with 'anti-shouting' applied
	 *
	 */
	private function fetchNoShoutingText($text)
	{
		/*
			strip_bbcode param notes:
				$message 		: NA
				$stripquotes 	: true, legacy
				$fast_and_dirty : false, legacy
				$showlinks 		: false, was true/default previously, but I don't see why having links (which will usually
								have lowercase characters) should allow them to shout in the rest of their text
				$stripimg 		: true, [attach] bbcodes in vB5 have string prefices (ex 'temp1234_5678' or 'n90'), so we
								must strip them for the check to work when user added inline attachments
				$keepquotetags	: not provided, default(false), legacy
		 */
		$effective_string = preg_replace('#[^a-z0-9\s]#i', '\2', strip_bbcode($text, true, false, false, true));
		if (
			$this->options['stopshouting'] AND
			vbstrlen($effective_string) >= $this->options['stopshouting'] AND
			$effective_string == strtoupper($effective_string) AND
			/* string does not consist entirely of non-alpha ascii chars #32591 */
			!preg_match('#^[\x20-\x40\x5B-\x60\x7B-\x7E\s]+$#', $effective_string)
		)
		{
			return $this->fetchSentenceCase($text);
		}
		else
		{
			return $text;
		}
	}

	/**
	 * Capitalizes the first letter of each sentence, provided it is within a-z. Lower-cases the entire string first
	 * Ignores locales
	 *
	 * @param	string	Text to capitalize
	 *
	 * @return	string
	 */
	private function fetchSentenceCase($text)
	{
		return preg_replace_callback(
			'#(^|\.\s+|\:\s+|\!\s+|\?\s+)[a-z]#',
			function ($matches) {return strtoupper($matches[0]);},
			vbstrtolower($text)
		);
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 103286 $
|| #######################################################################
\*=========================================================================*/
