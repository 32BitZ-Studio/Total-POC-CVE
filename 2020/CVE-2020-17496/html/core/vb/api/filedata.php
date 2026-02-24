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
 * vB_Api_Filedata
 *
 * @package vBApi
 */
class vB_Api_Filedata extends vB_Api
{
	/**#@+
	* Allowed resize labels
	*/
	const SIZE_ICON	  = 'icon';
	const SIZE_THUMB  = 'thumb';
	const SIZE_SMALL  = 'small';
	const SIZE_MEDIUM = 'medium';
	const SIZE_LARGE  = 'large';
	const SIZE_FULL   = 'full';
	/**#@-*/

	/**
	 * Contains white listed methods which act as normal when API is disabled
	 * no matter of special scenarios like forum closed, password expiry, ip ban and others.
	 *
	 * @var array $disableWhiteList
	 */
	protected $disableWhiteList = array(
		'fetchImageByFiledataid', // used applicationLight fetchImage for custom logos
	);

	/**
	 * Ensures that Sent in thumbnail type is valid
	 *
	 * @param	mixed	Image size to get
	 *
	 * @return	string	Valid image size to get
	 */
	public function sanitizeFiletype($type)
	{
		return vB_Library::instance('filedata')->sanitizeFiletype($type);
	}

	/**
	 * Fetch image information about an attachment based on file data id
	 *
	 * @see    vB_Api_Content_Attach::fetchImageByFiledataid
	 *
	 * @param  int   Filedataid
	 * @param  mixed Size requested
	 * @param  bool  Should we include the image content
	 * @param  int   Attachment node id where we are displaying this filedata record
	 *
	 * @return mixed array of data, includes filesize, dateline, htmltype, filename, extension, and filedataid
	 */
	public function fetchImageByFiledataid($id, $type = vB_Api_Filedata::SIZE_FULL, $includeData = true, $attachmentnodeid = 0)
	{
		if (empty($id) OR !is_numeric($id) OR !intval($id))
		{
			throw new vB_Exception_Api('invalid_request');
		}

		$attachmentnodeid = (int) $attachmentnodeid;
		$type = $this->sanitizeFiletype($type);

		//If the record belongs to this user, or if this user can view attachments
		//in this section, then this is O.K.
		$userinfo = vB::getCurrentSession()->fetch_userinfo();

		$params = array('filedataid' => $id, 'type' => $type);
		$record = vB::getDbAssertor()->getRow('vBForum:getFiledataContent', $params);

		if (empty($record))
		{
			return false;
		}

		$canView = false;

		if ($userinfo['userid'] == $record['userid'] OR $record['publicview'] > 0)
		{
			$canView = true;
		}

		if (!$canView AND $attachmentnodeid > 0)
		{
			// this branch is used to load Photo type image thumbnails when a user
			// (usually an admin or mod) is editing a different user's Photo type post.

			$nodeLibrary = vB_Library::instance('node');

			// get the attachment node
			$attachment = $nodeLibrary->getNodeFullContent($attachmentnodeid);
			$attachment = isset($attachment[$attachmentnodeid]) ? $attachment[$attachmentnodeid] : $attachment;

			// ensure this filedata record is associated with this attachment
			if ($id == $attachment['filedataid'])
			{
				// get the post associated with this attachment record
				$postnodeid = $attachment['parentid'];
				$post = $nodeLibrary->getNodeFullContent($postnodeid);
				$post = isset($post[$postnodeid]) ? $post[$postnodeid] : $post;

				// if the user can edit this post, they can also view the attached images
				if ($post['canedit'])
				{
					$canView = true;
				}

				unset($post);
			}

			unset($attachment);
		}

		if ($canView)
		{
			$imageHandler = vB_Image::instance();

			return $imageHandler->loadFileData($record, $type, $includeData);
		}

		throw new vB_Exception_Api('no_image_view_permissions');
	}

	/**
	 * fetch filedata records based on filedata ids
	 *
	 * @param 	array/int		filedataids
	 *
	 * @return	array of data, includes filesize, dateline, htmltype, filename, extension, and filedataid
	 */
	public function fetchFiledataByid($ids)
	{
		if (empty($ids) OR !is_array($ids))
		{
			throw new vB_Exception_Api('invalid_request');
		}

		//If the record belongs to this user, or if this user can view attachments
		//in this section, then this is O.K.
		$userinfo = vB::getCurrentSession()->fetch_userinfo();

		$records = vB::getDbAssertor()->assertQuery('vBForum:getFiledataWithThumb', array('filedataid' => $ids));
		$filedatas = array();
		foreach ($records as $record)
		{
			if (($userinfo['userid'] == $record['userid']) OR ($record['publicview'] > 0))
			{
				$record['visible'] = $record['publicview'];
				$record['counter'] = $record['refcount'];
				$record['filename'] = $record['filehash'] . '.' . $record['extension'];
				$filedatas[$record['filedataid']] = $record;
			}
		}

		return $filedatas;
	}

	/**
	 * Returns filedataids, filenames & other publicly visible properties of requested legacy attachments.
	 * Also contains 'cangetattachment' and 'cangetimgattachment' which is specific to the current user.
	 *
	 * @param	int[]	$ids	Integer array of legacy attachment ids (stored in `node`.oldid in vB5)
	 *
	 * @return Array	Array(
	 *						{oldid1} => array(attachment information),
	 *						{oldid2} => array(attachment information),
	 *					)
	 *					Where attachment information contains
	 *						- oldid
	 *						- nodeid
	 *						- parentid
	 *						- filedataid
	 *						- filename
	 *						- filesize
	 *						- settings
	 *						- counter
	 *						- dateline
	 *						- resize_dateline
	 *						- extension
	 *						- cangetattachment
	 *						- cangetimgattachment
	 */
	public function fetchLegacyAttachments($ids)
	{
		if (empty($ids) OR !is_array($ids))
		{
			throw new vB_Exception_Api('invalid_request');
		}

		array_walk($ids, 'intval');

		$rows = vB::getDbAssertor()->assertQuery('vBForum:fetchLegacyAttachments',
			array(
				'oldids' => $ids,
				'oldcontenttypeid' => array(
					vB_Api_ContentType::OLDTYPE_THREADATTACHMENT,
					vB_Api_ContentType::OLDTYPE_POSTATTACHMENT,
					vB_Api_ContentType::OLDTYPE_BLOGATTACHMENT,
					vB_Api_ContentType::OLDTYPE_ARTICLEATTACHMENT,
				)
			)
		);
		$result = array();
		$userContext = vB::getUserContext();
		$publicFields = array(
			'oldid',
			'nodeid',
			'contenttypeid',
			'parentid',
			'filedataid',
			'filename',
			'filesize',
			'settings',
			'resize_filesize',
			'hasthumbnail',
			'counter',
			'dateline',
			'resize_dateline',
			'extension',
		);
		foreach($rows AS $row)
		{
			$allowedData = array();
			foreach ($publicFields AS $fieldname)
			{
				if (isset($row[$fieldname]))
				{
					$allowedData[$fieldname] = $row[$fieldname];
				}
			}
			$allowedData['visible'] = $row['publicview'];
			$allowedData['counter'] = $row['refcount'];
			if (empty($allowedData['filename']))
			{
				// I can't recall why we did this during the attachment refactor, but
				// it suggests that filename might be missing in imported attachments (possibly upgrade bug?)
				// I did see that my legacy attachments had `attach`.filename during my local upgrade testing,
				// but I'm leaving this here just in case.
				$allowedData['filename'] = $row['filehash']. '.' . $row['extension'];
			}

			// Not really "public" info since this is dependent on current user, but useful for calling functions
			$allowedData['cangetattachment'] = $userContext->getChannelPermission('forumpermissions', 'cangetattachment', $row['nodeid']);
			$allowedData['cangetimgattachment'] = $userContext->getChannelPermission('forumpermissions2', 'cangetimgattachment', $row['nodeid']);

			$result[$row['oldid']] = $allowedData;
		}

		return $result;
	}

	/**
	 * fetch filedataid(s) for the passed photo nodeid(s)
	 *
	 * 	@param 	mixed(array|int)	photoid(s)
	 *
	 *	@return	array	filedataids for the requested photos
	 */
	public function fetchPhotoFiledataid($nodeid)
	{
		if (!is_array($nodeid))
		{
			$nodeid = array($nodeid);
		}

		$filedataids = array();

		$resultSet = vB::getDbAssertor()->assertQuery('vBForum:photo', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'nodeid' => $nodeid
		));

		foreach ($resultSet as $filedata)
		{
			$filedataids[$filedata['nodeid']] = $filedata['filedataid'];
		}

		return $filedataids;
	}

	/**
	 * fetch filedataid(s) for the passed attachment nodeid(s)
	 *
	 * 	@param 	mixed(array|int)	$nodeids
	 *
	 *	@return	array	filedataids for the requested attachments
	 */
	public function fetchAttachFiledataid($nodeid)
	{
		if (!is_array($nodeid))
		{
			$nodeid = array($nodeid);
		}

		$filedataids = array();

		$resultSet = vB::getDbAssertor()->assertQuery('vBForum:attach', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'nodeid' => $nodeid
		));

		foreach ($resultSet as $filedata)
		{
			$filedataids[$filedata['nodeid']] = $filedata['filedataid'];
		}

		return $filedataids;
	}

	/**
	 * Returns the resize type (e.g. 'full', 'icon') that would require the minimal
	 * scale-down/shrink to fit inside a $targetLength pixel square.
	 * Note that this function always looks for greater than or equal to, not minimum
	 * difference (e.g. not meant for enlarging or "fit inside without transform" types
	 * of usage)
	 *
	 * @param   int|float   $targetLength   Desired target length (measured in pixels)
	 *                                      of the including box size.
	 *
	 * @return  string   Value to be used for the type= parameter for filedata/fetch
	 *                   image URLs
	 */
	public function fetchBestFitGTE($targetLength)
	{
		$type = vB_Library::instance('filedata')->fetchBestFitGTE($targetLength);

		return array(
			'type' => $type,
		);
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 102812 $
|| #######################################################################
\*=========================================================================*/
