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
 * vB_Api_Content_Text
 *
 * @package vBApi
 * @author ebrown
 * @copyright Copyright (c) 2011
 * @version $Id: text.php 102567 2019-08-16 16:47:02Z ksours $
 * @access public
 */
class vB_Api_Content_Text extends vB_Api_Content
{
	//override in client- the text name
	protected $contenttype = 'vBForum_Text';

	//The table for the type-specific data.
	protected $tablename = 'text';

	//When we parse the page.
	protected $bbcode_parser = false;

	//Does this content show author signature?
	protected $showSignature = true;

	//Is text required for this content type?
	protected $textRequired = true;

	/**
	 * Normal constructor- protected to prevent direct instantiation
	 */
	protected function __construct()
	{
		parent::__construct();
		$this->library = vB_Library::instance('Content_Text');
	}

	/**
	 * Permanently deletes a node
	 *
	 * @param  int  The nodeid of the record to be deleted
	 *
	 * @return bool
	 */
	public function delete($nodeid)
	{
		$node = $this->getContent($nodeid);

		if (!$this->library->validate($node, vB_Library_Content::ACTION_DELETE, $nodeid))
		{
			throw new vB_Exception_Api('no_permission');
		}
		return $this->library->delete($nodeid);
	}

	/**
	 * Adds a new node.
	 *
	 * @param  mixed   Array of field => value pairs which define the record.
	 *                 Understands skipTransaction, skipFloodCheck, floodchecktime, skipDupCheck, skipNotification, nl2br, autoparselinks.
	 *                 - nl2br: if TRUE, all \n will be converted to <br /> so that it's not removed by the html parser (e.g. comments).
	 *                 - wysiwyg: if true convert html to bbcode.  Defaults to true if not given.
	 *
	 * @return integer the new nodeid
	 */
	public function add($data, $options = array())
	{
		if ($this->textRequired AND empty($data['pagetext']) AND empty($data['rawtext']))
		{
			throw new vB_Exception_Api('text_required');
		}

		if (!$this->textRequired AND empty($data['pagetext']) AND empty($data['rawtext']))
		{
			// the duplicate check is based on the post text, which is not required,
			// so we need to skip it if there is no text
			$options['skipDupCheck'] = true;
		}

		$vboptions = vB::getDatastore()->getValue('options');
		$parentNode = vB_Library::instance('node')->getNode($data['parentid']);

		if (!empty($data['title']))
		{
			$strlen= vB_String::vbStrlen(trim($data['title']), true);
			if ($strlen > $vboptions['titlemaxchars'])
			{
				throw new vB_Exception_Api('maxchars_exceeded_x_title_y', array($vboptions['titlemaxchars'], $strlen));
			}
		}
		else
		{
			$channelcontentypeid = vB_Api::instanceInternal('contenttype')->fetchContentTypeIdFromClass('Channel');
			//title is requred for topics. VMs look like topics so they need to be exempt
			if ($parentNode['contenttypeid'] == $channelcontentypeid AND ($data['parentid'] != vB_Api::instanceInternal('node')->fetchVMChannel()))
			{
				throw new vB_Exception_Api('title_required');
			}
		}

		list($minChars, $maxChars) = $this->getCharLimits($vboptions, $parentNode);
		$this->checkTextLength($minChars, $maxChars, empty($data['pagetext']) ? $data['rawtext'] : $data['pagetext']);

		// If node is a starter and has no title
		if (!empty($data['starter']) AND ($data['starter'] != $data['parentid']) AND empty($data['title']))
		{
			return false;
		}

		if (isset($data['userid']))
		{
			unset($data['userid']);
		}

		if (isset($data['authorname']))
		{
			unset($data['authorname']);
		}

		if (!$this->library->validate($data, vB_Library_Content::ACTION_ADD))
		{
			throw new vB_Exception_Api('no_create_permissions');
		}

		/*
		 *	check attachment permissions & limits
		 *	When a text node is added, $data['attachments'] is set by the controller from the filedataids,
		 *	see vB5_Frontend_Controller_CreateContent->addAttachments()
		 *
		 *	This check is called here, content_text, and not the parent, content, because attachments are added via a call to
		 *	vB_Library_Content_Attach->add() from vB_Library_Content_Text->add(). So any other content type that should
		 *	be able to add attachments must be a child of text.
		 *
		 *	Placed after the validate() permission checks because that made more sense to me to check "can user add node?"
		 *	before "can user add attachments to node?", in terms of the order of exceptions the user might see, AND because
		 *	this check does not modify $data in anyway, and thus the result of validate() is independent of this bit of code.
		 */
		$this->checkAttachmentPermissions($data);

		// checks 'htmlstate' for comments and updates $data if needed
		$this->checkHtmlstateForComments($data);

		//We shouldn't pass the open or show open fields
		unset($data['open']);
		unset($data['showopen']);

		if (!isset($data['htmlstate']))
		{
			// default to off if the request didn't specify they want it on
			$data['htmlstate'] = 'off';
		}

		$data = $this->cleanInput($data);
		$this->cleanOptions($options);

		$wysiwyg = true;
		if(isset($options['wysiwyg']))
		{
			$wysiwyg = (bool) $options['wysiwyg'];
		}

		$result = $this->library->add($data, $options, $wysiwyg);

		if (is_numeric($result['nodeid']))
		{
			return $result['nodeid'];
		}

		return false;
	}

	/**
	 * Updates a record
	 *
	 * @param  mixed array of nodeid's
	 * @param  mixed array of permissions that should be checked.
	 *
	 * @return bool
	 */
	public function update($nodeid, $data)
	{
		//if we aren't changing the parent, use the existing parent.
		if (isset($data['parentid']))
		{
			$parentid = $data['parentid'];
		}
		else
		{
			$content = $this->nodeApi->getNodeFullContent($nodeid);
			$content = reset($content);
			$parentid = $content['parentid'];
		}

		if (!vB::getUserContext()->getChannelPermission('forumpermissions2', 'canusehtml', $parentid))
		{
			// Regardless of this node's previous htmlstate, if the user doesn't have permission to use html, turn it off.
			$data['htmlstate'] = 'off';
		}

		$vboptions = vB::getDatastore()->getValue('options');

		//if we don't have pagetext or text, we aren't changing that value and shouldn't
		//worry about validating it
		if (isset($data['pagetext']) OR isset($data['rawtext']))
		{
			if ($this->textRequired AND empty($data['pagetext']) AND empty($data['rawtext']))
			{
				throw new vB_Exception_Api('text_required');
			}

			$parentNode = vB_Library::instance('node')->getNode($parentid);

			list($minChars, $maxChars) = $this->getCharLimits($vboptions, $parentNode);
			$this->checkTextLength($minChars, $maxChars, empty($data['pagetext']) ? $data['rawtext'] : $data['pagetext']);
		}

		if (!empty($data['title']))
		{
			$strlen= vB_String::vbStrlen(trim($data['title']), true);
			if ($strlen > $vboptions['titlemaxchars'])
			{
				throw new vB_Exception_Api('maxchars_exceeded_x_title_y', array($vboptions['titlemaxchars'], $strlen));
			}
		}
/*
		else
		{
			$channelcontentypeid = vB_Api::instanceInternal('contenttype')->fetchContentTypeIdFromClass('Channel');
			//title is requred for topics. VMs look like topics so they need to be exempt
			if ($parentNode['contenttypeid'] == $channelcontentypeid AND ($data['parentid'] != vB_Api::instanceInternal('node')->fetchVMChannel()))
			{
				throw new vB_Exception_Api('title_required');
			}
		}
*/
		/*
		 *	check attachment permissions & limits
		 *	When a text node is added, $data['attachments'] is set by the controller from the filedataids, see
		 *	vB5_Frontend_Controller_CreateContent->addAttachments()
		 *	The actual attachment additions happen in vB5_Frontend_Controller_CreateContent->handleAttachmentUploads()
		 *
		 *	This check is called here, content_text, and not the parent, content, because attachments are added via a call to
		 *	vB_Library_Content_Attach->add() from vB_Library_Content_Text->add(). So any other content type that should
		 *	be able to add attachments must be a child of text.
		 *	TODO is this true for updates?
		 */
		$this->checkAttachmentPermissions($data, $nodeid);

		// checks 'htmlstate' for comments and updates $data if needed
		$this->checkHtmlstateForComments($data, $nodeid);

		// Parent update() calls cleanInput().
		$result = parent::update($nodeid, $data);

		return $result;
	}

	/**
	 *	Gets the char limits for a node's text
	 *
	 *	@param array $vboptions -- the vboption datastore array
	 *	@param array $parentNode -- the node to check's parent
	 *	@return array -- array($minChars, $maxChars)
	 */
	private function getCharLimits($vboptions, $parentNode)
	{
		$isComment = (isset($parentNode['parentid']) AND isset($parentNode['starter']) AND
			$parentNode['parentid'] == $parentNode['starter']);

		if ($isComment)
		{
			$minChars = $vboptions['commentminchars'];
			$maxChars = $vboptions['commentmaxchars'];
		}
		else
		{
			$minChars = $vboptions['postminchars'];
			$maxChars = $vboptions['postmaxchars'];
		}

		return array($minChars, $maxChars);
	}

	/**
	 *	Check that the $text length falls in the minChar/maxChar limits
	 *	Checks some class properties as well as does a transform on the text to
	 *	normalize things.
	 *
	 *	Throws an exception if validation fails.
	 *
	 *	@param int $minChars -- check if $this->textRequired is true
	 *	@param int $maxChars -- unlimited if 0
	 *	@param string $text
	 */
	protected function checkTextLength($minChars, $maxChars, $text)
	{
		$strlen = vB_String::vbStrlen($this->library->parseAndStrip($text, true));

		if ($this->textRequired AND $strlen < $minChars)
		{
			throw new vB_Exception_Api('please_enter_message_x_chars', $minChars);
		}

		if($maxChars != 0 AND $strlen > $maxChars)
		{
			throw new vB_Exception_Api('maxchars_exceeded_x_y', array($maxChars, $strlen));
		}
	}

	/**
	 * Checks 'htmlstate' and disables it if this is a comment
	 *
	 * @param  array (reference) The node data array
	 * @param  int   (optional) The node ID. This should be used when updating
	 *               and the parent ID is not passed in the data array
	 *
	 * @return void  This function modifies the passed $data array.
	 */
	protected function checkHtmlstateForComments(&$data, $nodeid = 0)
	{
		// Don't support HTML in comments (See VBV-7616)
		// * In forums & groups we have starter, reply, and comment
		// * In articles & blogs we have starter and reply, but the reply
		//   is treated as a comment in terms of the UI.
		// So, for forum & group *comments*, and for article & blog *replies*
		// we want to disable posting as HTML, even if the user has
		// the permission, because the UI is that of a comment and
		// there is no UI toggle to turn HTML on/off.

		$parentid = 0;

		if (!empty($data['parentid']))
		{
			$parentid = $data['parentid'];
		}
		else if ($nodeid > 0)
		{
			$node = vB_Library::instance('node')->getNodeBare($nodeid);
			if (!empty($node) AND empty($node['errors']))
			{
				$parentid = $node['parentid'];
			}
			unset($node);
		}

		if ($parentid < 1)
		{
			throw new vB_Exception_Api('invalid_parentid');
		}

		$parentNode = vB_Library::instance('node')->getNodeFullContent($parentid);
		$parentNode = $parentNode[$parentid];
		$disable = false;

		switch($parentNode['channeltype'])
		{
			case 'forum':
			case 'group':
				$isComment = (isset($parentNode['parentid']) AND isset($parentNode['starter']) AND $parentNode['parentid'] == $parentNode['starter']);
				if ($isComment)
				{
					$disable = true;
				}
				break;

			case 'article':
			case 'blog':
				$isReply = (isset($parentNode['nodeid']) AND isset($parentNode['starter']) AND $parentNode['nodeid'] == $parentNode['starter']);
				if ($isReply)
				{
					$disable = true;
				}
				break;
		}

		if ($disable)
		{
			$data['htmlstate'] = 'off';
		}
	}

	/**
	 * Returns a string with quoted strings in bbcode format.
	 *
	 * @param  mixed  array of integers
	 *
	 * @return string
	 */
	public function getQuotes($nodeids)
	{
		//load here to ensure permission checks happen.
		$nodes = $this->getContent($nodeids);
		$quotes = $this->library->getQuotesFromNodes($nodes);
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
	 * Gets the data the presentation layer needs to have to parse the rawtext.
	 *
	 * @param  mixed nodeId or array of nodeIds
	 *
	 * @return array Array of node information for parsing the content. Each item
	 *               indexed by the nodeid and contains:
	 *                   'bbcodeoptions', 'rawtext', 'previewtext', 'attachments', 'title'
	 *                   'channelid', 'htmlstate', 'disable_bbcode', 'avatar_userids'
	 */
	public function getDataForParse($nodeIds)
	{
		if (is_int($nodeIds))
		{
			$nodeIds = array($nodeIds);
		}
		else if (!is_array($nodeIds))
		{
			throw new vB_Exception_Api('invalid_data');
		}

		$results = array();
		$bfMiscForumoptions = vB::getDatastore()->getValue('bf_misc_forumoptions');
		$pmType = vB_Types::instance()->getContentTypeID('vBForum_PrivateMessage');
		$galleryTypeid = vB_Types::instance()->getContentTypeId('vBForum_Gallery');
		$photoTypeid = vB_Types::instance()->getContentTypeId('vBForum_Photo');
		$userContext = vB::getUserContext();
		$channelTypes = vB::getDatastore()->getValue('vBChannelTypes');

		if (!empty($nodeIds))
		{
			$nodes = $this->assertor->assertQuery('vBForum:getDataForParse', array('nodeid' => $nodeIds));

			foreach ($nodes AS $node)
			{
				try
				{
					if ($this->library->validate($node, vB_Library_Content::ACTION_VIEW, $node['nodeid'], array($node)))
					{
						$attachments = $this->nodeApi->getNodeAttachments($node['nodeid']);
						// We don't need to show attachments for gallery. See VBV-6389.
						// Or rather, we need to unset attachments that are part of a gallery, but want to show other attachments. See VBV-11058
						if ($galleryTypeid == $node['contenttypeid'])
						{
							foreach ($attachments AS $key => &$attachment)
							{
								// attachments have contenttype vBForum_Attach, while photos of a gallery have contenttype vBForum_Photo
								if ($photoTypeid == $attachment['contenttypeid'])
								{
									unset($attachments[$key]);
								}
							}

						}

						if ($node['contenttypeid'] == $pmType)
						{
							$bbCodeOptions = vB_Api::instance('content_privatemessage')->getBbcodeOptions();
						}
						else if ($userContext->getChannelPermission('forumpermissions', 'canviewthreads', $node['nodeid'], false, $node['parentid']))
						{
							$bbCodeOptions = array();
							foreach($bfMiscForumoptions AS $optionName => $optionVal)
							{
								$bbCodeOptions[$optionName] = (bool)($node['options'] & $optionVal);
							}
						}
						else
						{
							$bbCodeOptions = array();
						}

						// userids for avatar preloading
						$avatarUserIds = array();
						$avatarUserIds[$node['userid']] = $node['userid'];
						if (!empty($node['rawtext']) AND preg_match_all('#\[USER="([0-9]+)"\].*\[/USER\]#siU', $node['rawtext'], $matches))
						{
							foreach($matches[1] AS $match)
							{
								$avatarUserIds[$match] = $match;
							}
						}

						$results[$node['nodeid']] =  array(
							'bbcodeoptions'  => $bbCodeOptions,
							'rawtext'        => $node['rawtext'],
							'previewtext' 	 => $node['previewtext'],
							'attachments'    => $attachments,
							'title'          => $node['title'],
							'channelid'      => $node['channelid'],
							'htmlstate'      => $node['htmlstate'],
							'disable_bbcode' => $node['nodeoptions'] & vB_Api_Node::OPTION_NODE_DISABLE_BBCODE,
							'avatar_userids' => $avatarUserIds,
						);
					}
					else if ($node['public_preview'] > 0)
					{
						$results[$node['nodeid']] =  array(
							'bbcodeoptions'  => array(),
							'rawtext'        => '',
							'title'          => $node['title'],
							'channelid'      => $node['channelid'],
							'htmlstate'      => 'off',
							'preview_only'	 => 1,
							'disable_bbcode' => $node['nodeoptions'] & vB_Api_Node::OPTION_NODE_DISABLE_BBCODE,
							'avatar_userids' => array(),
						);

						require_once(DIR . '/includes/class_bbcode.php');
						$tags = fetch_tag_list();
						$registry = vB::get_registry();
						$bbcode_parser = new vB_BbCodeParser($registry, $tags);
						$previewBbcodeOptions = array(
							'allowsmilies' => 1,
							// @TODO: this should NOT be a value, it should be a key
							// but I'm not changing it at this time, since I don't know
							// if we want to parse bbcode in this case
							'allowbbcode',
							'allowimagecode' => 1,
						);

						if ($node['htmlstate'] != 'off')
						{
							$previewBbcodeOptions['allowhtml'] = 1;
						}

						if ($node['nodeid'] == $node['starter'])
						{
							$channel = vB_Library::instance('node')->getNodeFullContent($node['parentid']);
						}
						else
						{
							$starter = $this->nodeApi->getNode($node['starter']);
							$channel = vB_Library::instance('node')->getNodeFullContent($starter['parentid']);
						}
						$channel = array_pop($channel);

						if ($channel['channeltype'] == 'article')
						{
							$previewBbcodeOptions['allowPRBREAK'] =  1;
						}

						if (vB::getUserContext()->getChannelPermission('forumpermissions2', 'cangetimgattachment' , $node['nodeid']))
						{
							$previewBbcodeOptions['allowimages'] =  1;
						}

						$results[$node['nodeid']]['previewtext'] = $bbcode_parser->getPreview($node['rawtext'], 0, FALSE, ($node['htmlstate'] == 'on_nl2br'), null, $previewBbcodeOptions);
					}
					else
					{
						$results[$node['nodeid']] =  array(
							'bbcodeoptions'  => array(),
							'rawtext'        => '',
							'previewtext' 	 => '',
							'title'          => '',
							'attachments'    => array(),
							'channelid'      => $node['channelid'],
							'htmlstate'      => 'off',
							'disable_bbcode' => $node['nodeoptions'] & vB_Api_Node::OPTION_NODE_DISABLE_BBCODE,
							'avatar_userids' => array(),
						);

					}
					//channeltype
					if (isset($channelTypes[$node['channelid']]))
					{
						$results[$node['nodeid']]['channeltype'] = $channelTypes[$node['channelid']];
						if ($channelTypes[$node['channelid']] == 'article')
						{
							$results[$node['nodeid']]['previewLength']  = vB::getDatastore()->getOption('def_cms_previewlength');

							// VBV-12048 For articles, if preview break is present, use the length of the preview text instead of
							// the global cms preview length
							$prbreak = stripos($results[$node['nodeid']]['rawtext'], '[PRBREAK][/PRBREAK]');
							if ($prbreak !== FALSE)
							{
								$results[$node['nodeid']]['previewLength']  = $prbreak;
							}
						}
						else
						{
							$results[$node['nodeid']]['previewLength'] = vB::getDatastore()->getOption('threadpreview');
						}
					}
					else
					{
						$results[$node['nodeid']]['channeltype'] = '';
					}

				}
				catch (exception $e)
				{
					//probably a permission error. We can continue with whatever is valid.
 				}
			}
		}

		return $results;
	}

	/**
	 * Cleans the input in the $data array, directly updating $data.
	 *
	 * @param mixed     Array of fieldname => data pairs, passed by reference.
	 * @param int|false Nodeid of the node being edited, false if creating new
	 */
	public function cleanInput($data, $nodeid = false)
	{
		$data = parent::cleanInput($data, $nodeid);

		$canUseHtml = vB::getUserContext()->getChannelPermission('forumpermissions2', 'canusehtml',
			(empty($nodeid) AND isset($data['parentid'])) ? $data['parentid'] : $nodeid);

		if (isset($data['htmlstate']))
		{
			if ($canUseHtml)
			{
				switch ($data['htmlstate'])
				{
					case 'on':
					case 'on_nl2br':
					case 'off':
						// We're ok, don't do anything.
						break;
					default:
						$data['htmlstate'] = 'off';
						break;
				}
			}
			else
			{
				// User can't use HTML.
				$data['htmlstate'] = 'off';
			}
		}

		// ** clean attachment related data **
		// this calls the attach api to clean attachment data for this
		// text (or other content type) node. Only text content (and
		// subclasses) can have attachments, so this is the appropriate
		// place for this (not in the parent class)
		if (!empty($data['attachments']))
		{
			if (is_array($data['attachments']))
			{
				// use instanceInternal so we can pass by reference
				$attachApi = vB_Api::instanceInternal('Content_Attach');
				foreach ($data['attachments'] AS $k => $v)
				{
					// passed by reference and cleaned
					$data['attachments'][$k]['parentid'] = $data['parentid'];
					$data['attachments'][$k] = $attachApi->cleanInput($data['attachments'][$k]);
				}
			}
			else
			{
				$data['attachments'] = array();
			}
		}
		// Similar to above, but for gallery photos
		if (!empty($data['photos']))
		{
			if (is_array($data['photos']))
			{
				// use instanceInternal so we can pass by reference
				// Note, photoAPI actually doesn't have its own cleaner, so it just goes through this cleaner. But just in case we add its own, keep using
				// the photo API reference below.
				$photoApi = vB_Api::instanceInternal('Content_Photo');
				foreach ($data['photos'] AS $k => $v)
				{
					// passed by reference and cleaned
					$data['photos'][$k]['parentid'] = $data['parentid'];
					$data['photos'][$k] = $photoApi->cleanInput($data['photos'][$k], $nodeid);
				}
			}
			else
			{
				$data['photos'] = array();
			}
		}
		if (!empty($data['removeattachments']))
		{
			if (is_array($data['removeattachments']))
			{
				$removeattachments = array();
				foreach ($data['removeattachments'] AS $k => $v)
				{
					$removeattachments[intval($k)] = intval($v);
				}
				$data['removeattachments'] = $removeattachments;
			}
			else
			{
				$data['removeattachments'] = array();
			}
		}

		return $data;
	}

	/**
	 * DEPRECATED - This is now handled internally by the library, nothing is called from controllers.
	 *
	 * This was used by the createcontent controller's handleAttachmentUploads()  to fix temporary id references in the
	 * specified node's rawtext to nodeids
	 *
	 * @deprecated Superceded by replaceAttachBbcodeTempids in the text library.
	 *
	 * @param      mixed      $nodeId nodeid or array of nodeids
	 * @param      array      $keysToAttachid (optional) array({tempid of attachment} => {attachment's nodeid})
	 *                        maps temporary-ids (array key) of newly added attachments and
	 *                        corresponding nodeids (array value) of said attachments.
	 *                        While this is optional for historical reasons, it must be provided
	 *                        if any temporary id references in the rawtext need to be replaced.
	 *
	 * @return     mixed      array includes bbcodeoptions, attachments, and rawtext
	 */
	public function fixAttachBBCode($nodeId, $keysToAttachid = array())
	{
		$data = $this->library->getFullContent($nodeId);
		if ($this->library->validate($data, vB_Library_Content::ACTION_UPDATE, $nodeId))
		{
			$this->library->fixAttachBBCode($nodeId, $data, $keysToAttachid);
		}
	}

	/**
	 * DEPRECATED - This is now handled internally by the library, nothing is called from controllers.
	 * NOTE: This is still used by some upgrade steps, so we can't remove it completely at this time.
	 *
	 * Populates the previewimage field
	 * for this node. To be called after the node is saved and the
	 * attachments added.
	 *
	 * Finds the first image in the post text that can be used as a
	 * previewimage (uploaded here), or uses the first image attachment.
	 *
	 * @deprecated Superceded by getPreviewImage in the text library.
	 *
	 * @param      int        Nodeid
	 */
	public function autoPopulatePreviewImage($nodeId)
	{
		$data = $this->library->getFullContent($nodeId);
		if ($this->library->validate($data, vB_Library_Content::ACTION_UPDATE, $nodeId))
		{
			$this->library->autoPopulatePreviewImage($nodeId, $data);
		}
	}

	/**
	 * Checks createpermissions.vbforum_attach and forumpermissions.maxattachments
	 * to see that user can add attachments under $data['parentid'] and that attachment
	 * limit is not exceeded. Throws exceptions meant to prevent node addition/update,
	 * so this function should be called before calling Library's add() or update()
	 *
	 * The createpermissions.vbforum_attach will be checked if there is any change in
	 * attachments.
	 * However, the attachment limit forumpermissions.maxattachments will only be
	 * checked if there is a net gain of attachments.
	 * If there is absolutely no change to attachments (signified by an empty
	 * $data['attachments'] and empty $data['removeattachments']), no permission will be
	 * checked as we do not want to prevent a recent change in attachment-related channel
	 * permissions (e.g. attachment limit being decreased or the createpermission being
	 * unset since post creation) to prevent a text-only update.
	 *
	 * @param  array                                            $data Typical data array passed into add() or update().
	 *                                                          MUST have 'parentid' for add, 'parentid' OR 'nodeid' for update.
	 *                                                          CAN have 'attachments' if any is to be added,
	 *                                                          'removeattachments' if any is to be removed (update only).
	 *
	 * @throws vB_Exception_Api('invalid_parentid')             if required 'parentid' is not found in $data
	 * @throws vB_Exception_Api('no_create_permissions_attach') if user lacks createpermissions.vbforum_attach channel permission.
	 * @throws vB_Exception_Api('max_attachments_exceeded_x')   if attachment limit check failed per above notes.
	 */
	protected function checkAttachmentPermissions($data, $nodeid = false)
	{
		/*
		 *	Similar: vB_Api_Content_Photo->verify_limits().
		 *	I'm not implementing verify_limits instead because we check permissions as well as limits.
		 *	I may change my mind about it later.
		 */

		// we need a parentid to check things.
		if (!isset($data['parentid']))
		{
			if (!empty($nodeid))
			{
				$node = vB_Library::instance('node')->getNodeBare($nodeid);
				$parentid = $node['parentid'];
				unset($node); // not used elsewhere in this function.
			}
		}
		else
		{
			$parentid = $data['parentid'];
		}

		if (empty($parentid))
		{
			throw new vB_Exception_Api('invalid_parentid');
		}

		// If there's no suggested change, just return. We do this check again a bit below after we
		// spend time to retrieve attachments & verify removeattachments. This is to prevent a case
		// where nonexistant attachmentids were added to the form for removal to try to bypass the
		// attach limit check.
		if (empty($data['attachments']) AND empty($data['removeattachments']))
		{
			// while this function can return true, it is meaningless (only a shortcut to skip checking)
			return true;
		}

		$existingAttachmentIds = array();
		$existingAttachmentFiledataIds = array();
		$existingAttachments = array();
		if (!empty($nodeid))
		{
			$attachments = vB_Library::instance('node')->fetchNodeAttachments($nodeid);
			foreach ($attachments AS $attachment)
			{
				if (!empty($attachment['nodeid']))
				{
					$existingAttachmentIds[$attachment['nodeid']] = $attachment['nodeid'];
				}
				$existingAttachmentFiledataIds[$attachment['filedataid']] = $attachment['filedataid'];
				$existingAttachments[$attachment['nodeid']] = $attachment;
			}
		}

		// Get rid of any nodeids in removeattachments that actually is not this node's existing attachment.
		if (!empty($data['removeattachments']))
		{
			$data['removeattachments'] = array_intersect($data['removeattachments'], $existingAttachmentIds);
		}
		else
		{
			// prevent undefined index notices further down
			$data['removeattachments'] = array();
		}

		if (empty($data['attachments']))
		{
			// prevent undefined index notices further down
			$data['attachments'] = array();
		}

		// We already checked this above, but it is duplicated here in case whatever called this inserted
		// bogus attachment nodeids in removeattachments that have been removed by the above code.
		if (empty($data['attachments']) AND empty($data['removeattachments']))
		{
			return true;
		}

		// if we got to this point, there's some sort of suggested change, so let's check the permission & Limit.

		/*
		 *	We are NOT checking moderatorpermissions.canmoderateattachments to allow override here because apparently
		 *	that permission is a vB4 permission meant to be used with attachment-specific moderation features which
		 *	do not exist in vB5. See VBV-13062
		 *
		 *	We are NOT checking forumpermissions.canpostattachment because that permission will be removed. See
		 *	VBV-13034
		 *
		 *	TODO: Update/remove above comments as necessary when above JIRAs are resolved.
		 *
		 *	Moderation note: If the user has permission to edit another user's post, they should be able to edit the
		 *	attachments at will. That permission should be checked at validate() before the update() can go through.
		 *	I can't imagine a case where a user would have (1) permission to moderate/edit another user's post, (2)
		 *	does not have createpermissions.vbforum_attach for the channel and (3) be legitimately allowed to add or
		 *	remove attachments to another user's posts, so I am NOT going to check for those permissions here.
		 *	If there's feedback to change this behavior, then let's make sure the case of <(1) + (2) + can they add or
		 *	remove attachments to their own posts without the createpermission?> is defined.
		 */
		$canAdd = vB::getUserContext()->getChannelPermission('createpermissions', 'vbforum_attach', $parentid);
		if (!$canAdd)
		{
			throw new vB_Exception_Api('no_create_permissions_attach');
		}


		// In order to check the limit permission for attachments, we need to
		// figure out how many unique filedata records are attached/being attached
		// to this node. We need to check unique filedataids since we now add a
		// new attachment record for each inserted image, even if it's the same
		// physical "attachment" (filedata record)

		// First, calculate how many unique *new* filedata records we're adding
		$attachmentFiledataIds = array();
		foreach ($data['attachments'] AS $attach)
		{
			if (empty($existingAttachmentFiledataIds[$attach['filedataid']]))
			{
				$attachmentFiledataIds[$attach['filedataid']] = true;
			}
		}

		// Now, to check how many unique filedata records we are _removing_,
		// we have to make sure we are removing all attachment records associated
		// with that filedata record before counting it.
		// First, count how many attachments we are removing for each filedata record
		$removeAttachmentCounts = array();
		foreach ($data['removeattachments'] AS $rmAttachNodeId)
		{
			$rmAttachFiledataId = $existingAttachments[$rmAttachNodeId]['filedataid'];
			if (!isset($removeAttachmentCounts[$rmAttachFiledataId]))
			{
				$removeAttachmentCounts[$rmAttachFiledataId] = 0;
			}
			++$removeAttachmentCounts[$rmAttachFiledataId];
		}
		// Second, count how many attachments we already have for each filedata record
		$existingCounts = array();
		foreach ($existingAttachments AS $attachment)
		{
			if (!isset($existingCounts[$attachment['filedataid']]))
			{
				$existingCounts[$attachment['filedataid']] = 0;
			}
			++$existingCounts[$attachment['filedataid']];
		}
		// Lastly, if we are removing as many attach records as already exist for a given
		// filedata record, AND we are not adding any new attach records for this filedata
		// record, then we can count this as actually removing a filedata record
		$removeAttachmentFiledataIds = array();
		foreach ($removeAttachmentCounts AS $filedataid => $count)
		{
			if (!empty($existingCounts[$filedataid]) AND $count >= $existingCounts[$filedataid] AND empty($attachmentFiledataIds[$filedataid]))
			{
				$removeAttachmentFiledataIds[$filedataid] = true;
			}
		}

		// now check the limit permission. Some numbers to check...
		$netChange = count($attachmentFiledataIds) - count($removeAttachmentFiledataIds);
		$totalExpectedAttachments = count($existingAttachmentFiledataIds) + $netChange;
		$maxattachments = vB::getUserContext()->getChannelLimitPermission('forumpermissions', 'maxattachments', $parentid);

		// limit 0 means unlimited. And if there's no net gain of # of attachments, allow the update regardless of limit. (See notes in docblock)
		$checkLimit = ($maxattachments > 0 AND $netChange > 0);
		if ($checkLimit AND $totalExpectedAttachments > $maxattachments)
		{
			throw new vB_Exception_Api('max_attachments_exceeded_x', array($maxattachments));
		}
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 102567 $
|| #######################################################################
\*=========================================================================*/
