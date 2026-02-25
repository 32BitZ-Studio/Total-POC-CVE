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
 * vB_Api_Content_Photo
 *
 * @package vBApi
 * @copyright Copyright (c) 2011
 * @version $Id: photo.php 102567 2019-08-16 16:47:02Z ksours $
 * @access public
 */
class vB_Api_Content_Photo extends vB_Api_Content
{
	/** override in client- the text name */
	protected $contenttype = 'vBForum_Photo';

	/** The table for the type-specific data. */
	protected $tablename = 'photo';

	/** We need the primary key field name. */
	protected $primarykey = 'nodeid';

	//Control whether this record will display on a channel page listing.
	protected $inlist = 0;

	//Let's cache the author information. We need it for checking ancestry- no sense querying too many times.
	protected $authors = array();

	//skip the flood check

	protected $doFloodCheck = false;

	protected $imageHandler = false;

	/**
	 * Normal constructor- protected to prevent direct instantiation
	 */
	protected function __construct()
	{
		parent::__construct();
		$this->library = vB_Library::instance('Content_Photo');
	}

	/**
	 * Add photo record
	 *
	 * @param  mixed Array of field => value pairs which define the record.
	 * @param  array Array of options for the content being created.
	 *               Understands skipTransaction, skipFloodCheck, floodchecktime.
	 *
	 * @return int   photoid
	 */
	public function add($data, $options = array())
	{
		$data['contenttypeid'] = $this->library->fetchContentTypeId();
		if (!$this->library->validate($data, vB_Library_Content::ACTION_ADD))
		{
			throw new vB_Exception_Api('no_create_permissions');
		}
		$parentData = vB_Library::instance('node')->getNodeFullContent($data['parentid']);
		$parentData = empty($parentData) ? $parentData : $parentData[$data['parentid']];
		if (!array_key_exists($data['parentid'], $this->authors))
		{
			if (empty($parentData) OR !empty($parentData['errors']) OR empty($parentData['userid']))
			{
				throw new vB_Exception_Api('invalid_data');
			}
			$this->authors[$data['parentid']] = $parentData['userid'];
		}

		$data['userid'] = vB::getCurrentSession()->get('userid');

		if (!$parentData['canedit'])
		{
			throw new vB_Exception_Api('no_permission');
		}

		//this will throw an exception if validation fails
		$this->validateFileData($data['filedataid'], $data['userid']);

		if ((vB_Api::instanceInternal('node')->fetchAlbumChannel() == $parentData['parentid']) AND (!vB::getUserContext()->hasPermission('albumpermissions', 'picturefollowforummoderation')))
		{
			$data['showapproved'] = 0;
		}

		$data['options'] = $options;
		$this->verify_limits($data);
		$data = $this->cleanInput($data);
		$this->cleanOptions($options);
		$result = $this->library->add($data, $options);

		return $result['nodeid'];
	}

	/**
	 * For checking the photo specific limits
	 *
	 * @param  array       info about the photo that needs to be added
	 *
	 * @return bool|string either true if all the tests passed or throws exception
	 */
	protected function verify_limits($data)
	{
		parent::verify_limits($data);

		$usercontext = vB::getUserContext();
		$albumChannelId = $this->nodeApi->fetchAlbumChannel();
		$parentData = vB_Api::instance('node')->getNode($data['parentid']);

		// These check are only valid when posting to the album channel
		if ($albumChannelId == $parentData['parentid'])
		{
			if(empty($data['options']['isnewgallery']))
			{
				$albummaxpics = $usercontext->getLimit('albummaxpics');
				if ($albummaxpics > 0)
				{
					$numalbumpics = $this->assertor->getField('vBForum:getNumberAlbumPhotos', array(
						vB_dB_Query::TYPE_KEY =>vB_dB_Query::QUERY_STORED,
						'albumid' => $data['parentid'],
						'contenttypeid' => vB_Types::instance()->getContentTypeID($this->contenttype),
					));
					$overcount = $numalbumpics + 1 - $albummaxpics;
					if ($overcount > 0)
					{
						throw new vB_Exception_Api('upload_album_pics_countfull_x', array($overcount));
					}
				}
			}

			$albummaxsize = $usercontext->getLimit('albummaxsize');

			if ($albummaxsize)
			{
				$totalsize = $this->assertor->getField('vBForum:getUserPhotosSize', array(
					vB_dB_Query::TYPE_KEY =>vB_dB_Query::QUERY_STORED,
					'channelid' => $albumChannelId,
					'userid' => $data['userid'],
					'contenttypeid' => $photoType = vB_Types::instance()->getContentTypeID($this->contenttype),
				));

				$filedata = vB::getDbAssertor()->getRow('filedata', array(
					vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
					'filedataid' => $data['filedataid']
				));

				$newsize = $filedata['filesize'] + $totalsize;
				$size_overage = $newsize - $albummaxsize;
				if ($size_overage > 0)
				{
					throw new vB_Exception_Api('upload_album_sizefull', array($size_overage));
				}
			}
		}
		else
		{
			// Channel  permission for allowed attachemtns per node
			$maxattachments = vB::getUserContext()->getChannelLimitPermission('forumpermissions', 'maxattachments', $parentData['parentid']);

			// Check max allowed attachments per post
			if ($maxattachments)
			{
				$numpostPhotos = $this->assertor->getField('vBForum:getNumberPosthotos', array(
					vB_dB_Query::TYPE_KEY =>vB_dB_Query::QUERY_STORED,
					'nodeid' => $data['parentid'],
					'contenttypeid' => vB_Types::instance()->getContentTypeID($this->contenttype),
				));
				$overcount = $numpostPhotos + 1 - $maxattachments;
				if ($overcount > 0)
				{
					throw new vB_Exception_Api('you_may_only_attach_x_files_per_post', array($maxattachments));
				}
			}
		}

		return true;
	}

	/**
	 * Delete photo record
	 *
	 * @param  int  photo id
	 *
	 * @return bool
	 */
	public function delete($photoId)
	{
		if (!$this->canDeletePhoto(vB::getCurrentSession()->get('userid'), $photoId))
		{
			throw new vB_Exception_Api('no_delete_permissions');
		}

		return $this->library->delete($photoId);
	}

	/**
	 * Checks if user can delete a given photo
	 *
	 * @param  int  User Id
	 * @param  int  Photo Id
	 *
	 * @return bool Value to indicate whether user can or not delete photo
	 */
	protected function canDeletePhoto($userId, $photoId)
	{
		$galleryId = $this->library->fetchParent($photoId);

		/** moderators can delete photos */
		if (vB::getUserContext()->getChannelPermission("moderatorpermissions", "canmoderateattachments", $galleryId))
		{
			return true;
		}

		/** owner can delete photos */
		return $this->library->isOwner($galleryId, $userId);
	}

	/**
	 * Returns an image record based on photo ID
	 *
	 * @param  int   Photo ID
	 * @param  bool  Include thumbnail
	 * @param  bool  Include extra data
	 *
	 * @return array Array of image data
	 */
	public function fetchImageByPhotoid($id, $thumb = false, $includeData = true)
	{
		return $this->library->fetchImageByPhotoid($id, $thumb, $includeData);
	}

	/**
	 * Validate filedata record
	 *
	 * @param  int   fileDataId to check
	 * @param  int   UserId
	 *
	 * @return array Information keys from the error: 'errors' => boolean indicating if the validation contains errors, 'error_id' => phraseid of the error found
	 */
	protected function validateFileData($fileDataId, $userId)
	{
		$fileData = $this->assertor->getRow(
			"vBForum:filedata", array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
				'filedataid' => $fileDataId
		));

		if (empty($fileData))
		{
			throw new vB_Exception_Api('invalid_filedataid_x', array($fileDataId));
		}

		if ($fileData["userid"] != $userId)
		{
			throw new vB_Exception_Api('invalid_user_filedata');
		}
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 102567 $
|| #######################################################################
\*=========================================================================*/
