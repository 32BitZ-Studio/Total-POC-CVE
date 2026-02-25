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
 * vB_Api_Content_Gallery
 *
 * @package vBApi
 * @author ebrown
 * @copyright Copyright (c) 2011
 * @version $Id: gallery.php 102567 2019-08-16 16:47:02Z ksours $
 * @access public
 */
class vB_Api_Content_Gallery extends vB_Api_Content_Text
{
	//override in client- the text name
	protected $contenttype = 'vBForum_Gallery';

	//The table for the type-specific data.
	protected $tablename = array('gallery', 'text');

	//We need the primary key field name.
	protected $primarykey = 'nodeid';

	//Does this content show author signature?
	protected $showSignature = true;

	//Is text required for this content type?
	protected $textRequired = false;

	/**
	 * Normal constructor- protected to prevent direct instantiation
	 */
	protected function __construct()
	{
		parent::__construct();
		$this->library = vB_Library::instance('Content_Gallery');
	}

	/**
	 * Adds a new node.
	 *
	 * @param  array Array of field => value pairs which define the record.
	 * @param  array Array of options for the content being created
	 *               Understands skipTransaction, skipFloodCheck, floodchecktime, skipDupCheck, skipNotification, nl2br, autoparselinks.
	 *               - nl2br: if TRUE, all \n will be converted to <br /> so that it's not removed by the html parser (e.g. comments).
	 *               - wysiwyg: if true convert html to bbcode.  Defaults to true if not given.
	 *
	 * @return int   the new nodeid
	 */
	public function add($data, $options = array())
	{
		vB_Api::instanceInternal('hv')->verifyToken($data['hvinput'], 'post');

		$result = $this->validateGalleryData($data);

		if (
			(vB_Api::instanceInternal('node')->fetchAlbumChannel() == $data['parentid']) AND
			(!vB::getUserContext()->hasPermission('albumpermissions', 'picturefollowforummoderation'))
		)
		{
			$data['approved'] = 0;
			$data['showapproved'] = 0;
		}

		//viewperms can only be 0, 1, or 2
		if (!isset($data['viewperms']) OR ($data['viewperms'] > 2) OR ($data['viewperms'] < 0))
		{
			$data['viewperms'] = 2;
		}

		if ($result === true)
		{
			return parent::add($data, $options);
		}
		else
		{
			return $result;
		}

	}

	/**
	 * Updates from a web save
	 *
	 * @param  int The id in the primary table
	 *
	 * @return int Number of updates-standard save response.
	 */
	public function updateFromWeb($nodeid, $postdata, $filedataids = array())
	{
		//First do we have a nodeid?
		if (!$nodeid OR !intval($nodeid) OR !$this->library->validate($postdata, vB_Library_Content::ACTION_UPDATE, $nodeid))
		{
			throw new Exception('invalid_data');
		}
		$data = array();
		//And are we authorized to make changes?
		if (!$this->library->validate($data, vB_Library_Content::ACTION_UPDATE, $nodeid))
		{
			throw new Exception('no_permission');
		}

		if (isset($postdata['title']))
		{
			$postdata['urlident'] = vB_String::getUrlIdent($postdata['title']);
		}

		$existing = $this->getContent($nodeid);
		$existing = $existing[$nodeid];

		//all of this cleaning appears to duplicate the cleanInput function
		//called by the vB_Content::update function (the actual cleaning of
		//some of this is part of the vB_Text::cleanInput function but
		//that's a parent of this class.
		$cleaner = vB::getCleaner();
		//clean the gallery data.
		$fields = array(
			'title' => vB_Cleaner::TYPE_STR,
			'prefixid' => vB_Cleaner::TYPE_NOHTML,
			'iconid' => vB_Cleaner::TYPE_UINT,
			'caption' => vB_Cleaner::TYPE_STR,
			'htmltitle' => vB_Cleaner::TYPE_STR,
			'rawtext' => vB_Cleaner::TYPE_STR,
			'reason' => vB_Cleaner::TYPE_STR,
			'keyfields' => vB_Cleaner::TYPE_STR,
			'publishdate' => vB_Cleaner::TYPE_UINT,
			'unpublishdate' => vB_Cleaner::TYPE_UINT,
			'description' => vB_Cleaner::TYPE_STR,
			'displayorder' => vB_Cleaner::TYPE_UINT,
			'urlident' => vB_Cleaner::TYPE_STR,
			'tags' => vB_Cleaner::TYPE_STR,
			'allow_post' => vB_Cleaner::TYPE_BOOL,
			'parentid' => vB_Cleaner::TYPE_UINT,
			'viewperms' => vB_Cleaner::TYPE_UINT,
			'attachments' => vB_Cleaner::TYPE_NOCLEAN,	//cleaned separately below
			'removeattachments' => vB_Cleaner::TYPE_NOCLEAN,	//''
		);

		// copy data before they're dropped by the cleaner. These will be cleaned separately just a few lines down.
		$unclean['attachments'] = isset($postdata['attachments']) ? $postdata['attachments'] : array();
		$unclean['removeattachments'] = isset($postdata['removeattachments']) ? $postdata['removeattachments'] : array();

		$cleaned = $cleaner->cleanArray($postdata, $fields);
		// just unset the uncleaned ones. They're cleaned & set again below. I would've just unset them from
		// $postdata before it was tossed into cleanArray(), but there's special logic a few blocks down that
		// requires keys in $fields to be set in both $postdata & $cleaned for it to be sent into update()
		unset($cleaned['attachments']);
		unset($cleaned['removeattachments']);
		if (!isset($postdata['allow_post']))
		{
			// Apparently (copy pasted from createcontent getArticleInput()) :
			//do not set if not provide, use the API default values.  Otherwise things like the forums which aren't thinking about it
			//get set incorrectly.
			unset($cleaned['allow_post']);
		}

		if (!empty($unclean['attachments']))
		{
			// keep these fields in sync with controller's addAttachments()
			$attachfields = array(
				'filedataid' => vB_Cleaner::TYPE_UINT,
				'filename' => vB_Cleaner::TYPE_STR,
				//this is an array with it's own fields.  Don't duplicate cleaning
				//here, it's handled by the update function called below in a
				//much more maintainable way.
				'settings' => vB_Cleaner::TYPE_NOCLEAN,
			);
			foreach ($unclean['attachments'] AS $key => $attachdata)
			{
				$key = (int) $key;
				$cleaned['attachments'][$key] = $cleaner->cleanArray($attachdata, $attachfields);
			}
			unset($unclean['attachments']);
		}

		if (!empty($unclean['removeattachments']))
		{
			// keep these fields in sync with controller's addAttachments()
			foreach ($unclean['removeattachments'] AS $key => $attachnodeid)
			{
				$key = (int) $key;
				$cleaned['removeattachments'][$key] = (int) $attachnodeid;
			}
			unset($unclean['removeattachments']);
		}

		$updates = array();

		// cleaner will set viewperms to 0 if it's not passed in, but 0 is a valid value.
		// We need to distinguish between 0 & default.
		if (!isset($postdata['viewperms']))
		{
			unset($cleaned['viewperms']);
		}
		//viewperms can only be 0, 1, or 2
		if (!isset($cleaned['viewperms']) OR ($cleaned['viewperms'] > 2) OR ($cleaned['viewperms'] < 0))
		{
			$cleaned['viewperms'] = 2;
		}
		/*
		 *	Okay, I"m pretty sure the below isn't doing what was originally intended,
		 *	judging by the comment & the fact that we grab the pre-update node values,
		 *	$existing, above.
		 *	I'm guessing what was *supposed* to happen is that each $iteam in $cleaned
		 *	is compared against $existing's data, and is set to $updates only if it's
		 *	different.
		 *	However, there's been a lot of changes to the various bits of content
		 *	update() code, so I'm afraid to unset things from $updates now.
		 *	If anyone is going to edit below, make sure that handling for
		 *	$cleaned['attachments']and $cleaned['removeattachments'] are proplery
		 *	dealt with, otherwise there will be issues when editing a gallery post
		 *	and adding/removing attachments.
		 */
		//If nothing has changed we don't need to update the parent.
		foreach (array_keys($fields) as $fieldname)
		{
			if (isset($postdata[$fieldname]) AND isset($cleaned[$fieldname]))
			{
				$updates[$fieldname] = $cleaned[$fieldname];
			}
		}
		$results = true;
		if (!empty($updates))
		{
			$results = $this->update($nodeid, $updates);
		}

		if ($results AND (!is_array($results) OR empty($results['errors'])))
		{
			//let's get the current photo information;

			$existing = $this->library->getFullContent($nodeid);
			$existing = $existing[$nodeid];

			if (empty($existing['photo']))
			{
				$delete = array();
			}
			else
			{
				$delete = $existing['photo'];
			}

			//Now we match the submitted data against the photos
			//if they match, we remove from "delete" and do nothing else.
			//if the title is updated we do an immediate update.
			//Otherwise we add.
			if (!empty($filedataids) AND is_array($filedataids))
			{
				$photoApi = vB_Api::instanceInternal('content_photo');

				foreach ($filedataids AS $filedataid => $title)
				{
					//it has to be at least a integer.
					if (intval($filedataid))
					{
						//First see if we have a match.
						$foundMatch = false;
						foreach ($delete as $photoNodeid => $photo)
						{
							if ($filedataid == $photo['filedataid'])
							{
								$foundMatch = $photo;
								unset($delete[$photoNodeid]);
								break;
							}
						}

						if ($foundMatch)
						{
							if ($title != $foundMatch['title'])
							{
								$titles[$foundMatch['nodeid']] = $title;
							}
							//unset this record.

							//Skip to the next record
							continue;
						}
						//If we got here then this is new and must be added.
						//We do an add.
						$photoApi->add(array('parentid' => $nodeid,
							'caption' => $title, 'title' => $title, 'filedataid' => intval($filedataid)));
					}

				}
				if (!empty($delete))
				{
					foreach ($delete as $photo)
					{
						$photoApi->delete($photo['nodeid']);
					}
				}

				if (!empty($titles))
				{
					foreach ($titles as $photonodeid => $title)
					{
						$photoApi->update($photonodeid, array('caption' => $title, 'title' => $title));
					}
				}
			}
		}

		$this->nodeApi->clearCacheEvents($nodeid);
		return $results;
	}

	/**
	 * Validates the gallery data
	 *
	 * @param  array info about the photos
	 *
	 * @return bool
	 */
	protected function validateGalleryData($data)
	{
		$usercontext = vB::getUserContext();
		$albumChannel = vB_Api::instanceInternal('node')->fetchAlbumChannel();

		if (!empty($data['parentid']) AND $data['parentid'] == $albumChannel AND !$usercontext->hasPermission('albumpermissions', 'canviewalbum'))
		{
			throw new vB_Exception_Api('no_permission');
		}

		$albummaxpic = $usercontext->getLimit('albummaxpics');

		if (isset($data['photos']) AND !empty($albummaxpic))
		{
			$overcount = count($data['photos']) - $albummaxpic;
			if($overcount > 0)
			{
				throw new vB_Exception_Api('upload_album_pics_countfull_x', array($overcount));
			}
		}

		return true;
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 102567 $
|| #######################################################################
\*=========================================================================*/
