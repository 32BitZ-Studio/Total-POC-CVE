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
 * vB_Library_Content_Attach
 *
 * @package vBLibrary
 * @access public
 */
class vB_Library_Content_Attach extends vB_Library_Content
{
	/**
	 * @deprecated Appears to be unused
	 */
	protected $types;

	/**
	 * @deprecated Appears to be unused
	 */
	protected $extension_map;

	//override in client- the text name
	protected $contenttype = 'vBForum_Attach';

	//The table for the type-specific data.
	protected $tablename = 'attach';

	//list of fields that are included in the index
	protected $index_fields = array('description');

	//Control whether this record will display on a channel page listing.
	protected $inlist = 0;

	//skip the flood check
	protected $doFloodCheck = false;

	//Image processing functions
	protected $imageHandler;

	protected function __construct()
	{
		parent::__construct();
		$this->imageHandler = vB_Image::instance();
	}

	/**
	 * Adds a new node.
	 *	This function will add a new attachment node & attach table record, increment refcount for the associated filedata table record, and set
	 *	the parent node record's hasphoto to 1
	 *
	 *	@param	mixed	$data		Array of field => value pairs which define the record. Must have all data required by vB_Library_Content::add().
	 *								At the minium, must have:
	 *									int		'parentid'		@see vB_Library_Content::add()
	 *									int 	'filedataid'
	 *								Additional data may include:
	 *									string	'caption'		Optional. Caption for the image. If caption is set, it will overwrite the description.
	 *									string	'description'	Optional. If description is set but caption is not set, the caption will be set to description.
	 *								@see vB_Library_Content::add() for more details
	 *								It can also contain data corresponding to the attach table fields, such as:
	 *									int		'visible'		???
	 *									int		'counter'		???
	 *									string	'filename'		???
	 *									int		'reportthreadid'		???
	 *									string	'settings'		Serialized array of attachment settings that are used by vB5_Template_BbCode's
	 *															attachReplaceCallback() to render the image with the specified settings. @see
	 *															vB_Api_Content_Attach::getAvailableSettings() for a list of the avaliable settings
	 *  @param	array	$options	Array of options for the content being created. Understands skipTransaction, skipFloodCheck, floodchecktime
	 *
	 * 	@return	array	Contains the data of the added node. Array with data-types & keys:
	 *						int			'nodeid'
	 *						bool		'success'
	 *						string[]	'cacheEvents'
	 *						array		'nodeVals' 		Array of field => value pairs representing the node table field values that were added to the node table.
	 *													@see vB_Library_Node::getNodeFields() or the node table structure for these fields
	 */
	public function add($data, array $options = array())
	{
		//Store this so we know whether we should call afterAdd()
		$skipTransaction = !empty($options['skipTransaction']);
		//todo -- lock the caption to the description until we collapse the fields.  Remove when caption goes away
		if (isset($data['caption']))
		{
			$data['description'] = $data['caption'];
		}
		else if (isset($data['description']))
		{
			$data['caption'] = $data['description'];
		}

		try
		{
			if (!$skipTransaction)
			{
				$this->assertor->beginTransaction();
			}
			$options['skipTransaction'] = true;
			$result = parent::add($data, $options);

			if ($result)
			{
				$this->assertor->assertQuery('vBForum:node', array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_UPDATE,
					'nodeid' => $data['parentid'], 'hasphoto' => 1 ));

				// Increment the refcount in filedata.
				// Note that validate() ensures that we have $data['filedataid'] set.
				$this->assertor->assertQuery('updateFiledataRefCount', array('countChange' => 1, 'filedataid' => $data['filedataid']));
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
		return $result;
	}


	/**
	 * Remove an attachment
	 * 	@param	INT	nodeid
	 */
	public function delete($nodeid)
	{
		//We need the parent id. After deletion we may need to set hasphoto = 0;
		$existing =	$this->nodeApi->getNode($nodeid);
		$this->removeAttachment($nodeid);
		parent::delete($nodeid);
		$photo = $this->assertor->getRow('vBForum:node', array('contenttypeid' => $this->contenttypeid, 'parentid' => $existing['parentid']));

		//If we got empty or error, there are no longer any attachments.
		if (!empty($existing['parentid']) AND (empty($photo) OR !empty($photo['errors'])))
		{
			$this->assertor->assertQuery('vBForum:node', array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_UPDATE,
				'hasphoto' => 0,
				vB_dB_Query::CONDITIONS_KEY => array(
					array('field' => 'nodeid', 'value' => $existing['parentid'], 'operator' => vB_dB_Query::OPERATOR_EQ)
				)
			));
		}
		$this->nodeApi->clearCacheEvents(array($nodeid, $existing['parentid']));
		return true;
	}

	/**
	 * Delete the records without updating the parent info. It is used when deleting a whole channel and it's children need to be removed
	 * @param array $childrenIds - list of node ids
	 */
	public function deleteChildren($childrenIds)
	{
		//existing attach data
		$attachdata = vB::getDbAssertor()->getColumn('vBForum:attach', 'filedataid', array('nodeid' => $childrenIds), false, 'nodeid');
		//the number of times an attachment is used in the list of nodes
		$refcounts = array_count_values($attachdata);
		//the individual existing filedata records
		$filedata = vB::getDbAssertor()->getColumn('filedata', 'refcount', array('filedataid' => array_keys($refcounts)), false, 'filedataid');
		foreach ($filedata as $filedataid => $nr)
		{
			//the new value of the existing refcount
			$refCount = max($nr - $refcounts[$filedataid], 0);
			$this->assertor->update("vBForum:filedata", array('refcount' => $refCount), array('filedataid' => $filedataid));
		}

		//delete the main tables
		parent::deleteChildren($childrenIds);
	}

	/**
	 * updates a record
	 *
	 *	@param	mixed		array of nodeid's
	 *	@param	mixed		array of permissions that should be checked.
	 *
	 * 	@return	boolean
	 */
	public function update($nodeid, $data)
	{
		$existing = $this->assertor->getRow('vBForum:attach', array('nodeid' => $nodeid));
		$existingNode =	$this->nodeApi->getNode($nodeid);

		//todo -- lock the caption to the description until we collapse the fields.  Remove when caption goes away
		if (isset($data['caption']))
		{
			$data['description'] = $data['caption'];
		}
		else if (isset($data['description']))
		{
			$data['caption'] = $data['description'];
		}

		if (parent::update($nodeid, $data))
		{
			//We need to update the filedata ref counts
			if (!empty($data['filedataid']) AND ($existing['filedataid'] != $data['filedataid']))
			{
				//Remove the existing
				$filedata = vB::getDbAssertor()->getRow('filedata', array(
						vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
						'filedataid' => $existing['filedataid']
				));

				if ($filedata['refcount'] > 1)
				{
					$params = array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_UPDATE,
					'filedataid' => $existing['filedataid'],
					'refcount' => $filedata['refcount'] - 1);
				}
				else
				{
					$params = array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_DELETE,
					'filedataid' => $existing['filedataid']);
					$this->assertor->assertQuery('vBForum:filedataresize', $params);
				}

				$this->assertor->assertQuery('filedata', $params);

				//add the new
				$filedata = vB::getDbAssertor()->getRow('filedata', array(
						vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
						'filedataid' => $data['filedataid']
				));

				if (!empty($filedata) AND empty($filedata['errors']))
				{
					$params = array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_UPDATE,
					'filedataid' => $data['filedataid'],
					'refcount' => $filedata['refcount'] + 1);

					$this->assertor->assertQuery('filedata', $params);
				}
			}
		}

		$nodesToClear = array($nodeid, $existingNode['parentid']);
		if (isset($data['parentid']) AND ($data['parentid'] != $existingNode['parentid']))
		{
			$nodesToClear[] = $data['parentid'];
		}
		$this->nodeApi->clearCacheEvents($nodesToClear);
	}

	/**
	 *	See base class for information
	 */
	public function getIndexableFromNode($node, $include_attachments = true)
	{
		$indexableContent = parent::getIndexableFromNode($node, $include_attachments);

		if (!empty($node['description']))
		{
			$indexableContent['description'] = $node['description'];
		}

		return $indexableContent;
	}


	/**
	 * Remove an attachment
	 * 	@param	INT	nodeid
	 */
	public function removeAttachment($id)
	{
		// Note that this will NOT remove an attachment record.
		// Going through delete() (which calls this function) will remove the attachment record.
		if (empty($id) OR !intval($id))
		{
			throw new Exception('invalid_request');
		}

		$db = vB::getDbAssertor();
		$attachdata = $db->getRow('vBForum:attach', array('nodeid' => $id));

		if (!empty($attachdata) AND $attachdata['filedataid'])
		{
			$filedata = $db->getRow('filedata', array('filedataid' => $attachdata['filedataid']));

			if ($filedata['refcount'] > 1)
			{
				$data = array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_UPDATE,
				'filedataid' => $attachdata['filedataid'],
				'refcount' => $filedata['refcount'] - 1);
			}
			else
			{
				$data = array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_DELETE,
				'filedataid' => $attachdata['filedataid']);
				$db->assertQuery('vBForum:filedataresize', $data);
			}

			$db->assertQuery('vBForum:filedata', $data);
		}

		return true;
	}

	public function removeSignaturePicture($userid)
	{
		$sigpic = vB::getDbAssertor()->getRow('vBForum:sigpicnew', array('userid' => intval($userid)));

		if (empty($sigpic))
		{
			return;
		}

		vB::getDbAssertor()->delete('vBForum:sigpicnew', array('userid' => intval($userid)));

		if ($sigpic['filedataid'])
		{
			$filedata = vB::getDbAssertor()->getRow('filedata', array(
					vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
					'filedataid' => $sigpic['filedataid']
			));

			if ($filedata['refcount'] > 1)
			{
				$data = array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_UPDATE,
				'filedataid' => $sigpic['filedataid'],
				'refcount' => $filedata['refcount'] - 1);
			}
			else
			{
				$data = array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_DELETE,
				'filedataid' => $sigpic['filedataid']);
				vB::getDbAssertor()->assertQuery('vBForum:filedataresize', $data);
			}

			vB::getDbAssertor()->assertQuery('vBForum:filedata', $data);
		}
	}

	/**
	 * Get attachments for a content type
	 * 	@param	INT	nodeid
	 */
	public function getAttachmentsFromType($typeid)
	{
		$attachdata = vB::getDbAssertor()->getRows('attachmentsByContentType', array('ctypeid' => $typeid));

		return $attachdata;
	}

	/** Remove all attachments for content type
	 * 	@param	INT	Content Type id
	 *
	 **/
	public function zapAttachmentType($typeid)
	{
		$list = $this->getAttachmentsFromType($typeid);

		foreach($list AS $attachment)
		{
			$this->removeAttachment($attachment['attachmentid']);
		}
	}

	/**
	 * Get array of http headers for this attachment file extension
	 *
	 * @param	string	$extension	file extension, e.g. 'doc', 'gif', 'pdf', 'jpg'
	 *
	 * @return	string[]	Array containing the 'content-type' http header string for $extension.
	 *						If $extension is not found in attachmenttype table, the default
	 *						'Content-type: application/octet-stream' is returned in the array.
	 *
	 * @access	public
	 **/
	public function getAttachmentHeaders($extension)
	{
		$headers = array('Content-type: application/octet-stream');
		if (!empty($extension))
		{
			$attach_meta = vB::getDbAssertor()->getRows('vBForum:fetchAttachPermsByExtension', array('extension' => $extension));
			if (!empty($attach_meta) AND !empty($attach_meta[0]['mimetype']))
			{
				$headers = unserialize($attach_meta[0]['mimetype']);
			}
		}

		return $headers;
	}


	/**
	 * Processes an uploaded file and saves it as an attachment
	 *
	 * @param	int             $userid		Userid of the user who is uploading the file
	 * @param	array           $file		Uploaded file data.
	 *										The object or array should have the following properties or elements with data-types and names:
	 *											string	'name'		Filename
	 *											int		'size'		Filesize
	 *											string	'type'		Filetype
	 *											string	'uploadfrom'	Optional. Where the file was uploaded from. E.g. 'profile', 'sgicon',
	 *																'signature', 'newContent'  or null
	 *											int		'parentid'	Optional. The nodeid/channelid this file should be saved under. Used for permission
	 *																checks
	 *										If it is an object, it should also have the following property:
	 *											string	'contents'	Contents of the file
	 *										If it is an array, it should also have the following element:
	 *											string	'tmp_name'	Filepath to the temporary file created on the server
	 * @param	bool			$cheperms	Optional, whether or not to check attachment permissions. Default true
	 * @param	bool			$imageOnly	Optional, whether or not to only allow an image attachment. Default false
	 *
	 * @return	array	Array of attachment data @see saveUpload()
	 *
	 * @throws	vB_Exception_Api('upload_file_exceeds_php_limit')	If file upload by PHP failed with error code UPLOAD_ERR_INI_SIZE or UPLOAD_ERR_FORM_SIZE
	 * @throws	vB_Exception_Api('upload_file_partially_uploaded')	If file upload by PHP failed with error code UPLOAD_ERR_PARTIAL
	 * @throws	vB_Exception_Api('upload_file_failed')				If file upload by PHP failed with error code UPLOAD_ERR_NO_FILE
	 * @throws	vB_Exception_Api('missing_temporary_folder')		If file upload by PHP failed with error code UPLOAD_ERR_NO_TMP_DIR
	 * @throws	vB_Exception_Api('upload_writefile_failed')			If file upload by PHP failed with error code UPLOAD_ERR_CANT_WRITE
	 * @throws	vB_Exception_Api('upload_stopped_by_extension')		If file upload by PHP failed with error code UPLOAD_ERR_EXTENSION
	 * @throws	Exception('Upload failed. PHP upload error: ' <error code>)		If file upload by PHP failed with an error code that's not included above
	 * @throws	vB_Exception_Api('invalid_file_data')				If $file['tmp_name'] contains no data
	 * @throws	vB_Exception_Api('upload_file_exceeds_limit')		If user exceeded their usergroup's attachlimit
	 * @throws	vB_Exception_Api('upload_exceeds_dimensions')		If the uploaded file exceeds allowed dimensions and resizing the image failed
	 * @throws	vB_Exception_Api('invalid_file')					If fetching getAttachmentPermissions() failed for specified file type & upload method
	 *
	 * @access	public
	 */
	public function uploadAttachment($userid, $file, $cheperms = true, $imageOnly = false)
	{
		//Leave for consistency with admincp
		if (!defined('ATTACH_AS_FILES_NEW'))
		{
			define('ATTACH_AS_FILES_NEW', 2);
		}
		$uploadFrom = '';

		$fileContents = null;
		if (is_object($file))
		{
			/*
				Blueimp file handler used in the frontend uploader controller will send in a file object instead of an array
				to the API. As such the object is converted into an array in the API, and handling code that was here (that
				originally was in the API) has since been removed in order to keep the library code cleaner.

				This exception is here to help catch any possible cases where there might've been a file array -> object
				conversion prior to calling the library directly instead of the api.
			 */
			throw new vB_Exception_Api('upload_file_failed');
		}
		else
		{
			$this->scanFileArray($file);

			if (!empty($file['tmp_name']) AND file_exists($file['tmp_name']))
			{
				$filearray = $file;
				$filebits = explode('.', $file['name']);
				$extension = end($filebits);
				$filesize = filesize($file['tmp_name']);
				$fileContents = file_get_contents($file['tmp_name']);

				if (!empty($file['uploadFrom']))
				{
					$uploadFrom = $file['uploadFrom'];
					unset($file['uploadFrom']);
				}

				if (!empty($file['parentid']))
				{
					$parentid = intval($file['parentid']);
				}
			}
		}

		// Used for upload error messaging later.
		$originalFilesize = $filesize ?? 0;

		$this->checkAndFixImageExtension($extension, $filearray);

		$isImage = $this->imageHandler->fileLocationIsImage($filearray['tmp_name']);
		if ($imageOnly AND !$isImage)
		{
			// taken from saveUpload(), placed here to hopefully avoid issues
			// with signature images etc early on.
			throw new vB_Exception_Api('upload_invalid_image');
		}



		if (empty($uploadFrom))
		{
			$uploadFrom = 'newContent';
		}

		if (empty($parentid))
		{
			$parentid = false;
		}


		/*
			If it claims to be an image...

			Strip exif data, rotate image, whatever we need to do to the image before we save it.
			A bit of a shame we may do multiple file writes (e.g. file_put_contents() in is_object($file)
			case above), but we need one central place to call this...

			Verify the image before we accept it & save it as filedata in case we *DO NOT* resize it. (Resize will call verify as well)
		 */
		if ($isImage)
		{
			/*
			Extremely large images greater than the config values can kill loadImage() below.
			Try to mitigate that via checking the original dimensions before sending it to loadImage().
			 */
			$this->checkConfigImageResizeLimitsForFile($filearray['tmp_name']);


			// Note, magic bytes are already checked as part of the $isImage check. Verify will also check
			// potentially dangerous bits in exif data, though that requires further vulnerabilities to exploit
			// e.g. include({image}) which AFAIK we avoid.
			$newImageData = $this->imageHandler->loadImage($filearray['tmp_name']);
			// Once we hit above, we do not care about the old file regardless of if it's "safe" or "dangerous".
			if (file_exists($filearray['tmp_name']))
			{
				@unlink($filearray['tmp_name']);
			}
			if (empty($newImageData))
			{
				throw new vB_Exception_Api('dangerous_image_rejected');
			}

			// Don't forget to delete the old file first!
			$filearray['size'] = $newImageData['size'];
			$filearray['type'] = $newImageData['type'];
			$filearray['tmp_name'] = $newImageData['tmp_name'];
			// $extension is still fixed by the checkAndFixImageExtension() call before.


			// This bit is moved down here after orientImage() because the image might've been rotated, which would swap width & height.
			list($filewidth, $fileheight) = getimagesize($filearray['tmp_name']);
			if (!$filewidth OR !$fileheight)
			{
				/*
					getimagesize couldn't get the dimensions even though our image verification on the original image passed,
					and we may have recreated an entirely new image??
					Assume something went horribly wrong here.
				 */
				throw new vB_Exception_Api('upload_invalid_image');
			}
			$filesize = filesize($filearray['tmp_name']);
			$fileContents = file_get_contents($filearray['tmp_name']);

			// Note: re-writing the image as part of orient image actually strips most of the exif, at least for GD.


			/*
			Check the config (or default, if not defined) resize limits. If image is too big, we won't
			attempt to resize it, and even if attachment permissions allow it, we will not accept it
			without resizing it.
			Note that we don't check this for non-images.
			 */
			$this->checkConfigImageResizeLimits($filewidth, $fileheight, $filesize);
		}
		else
		{
			$filewidth = false;
			$fileheight = false;
		}

		// Channel icon permissions
		if ($uploadFrom === 'sgicon' OR $uploadFrom === 'blogicon' OR $uploadFrom === 'channelicon')
		{
			try
			{
				vB_Api::instanceInternal('content_channel')->validateIcon($parentid, array('filedata' => $fileContents, 'filesize' => $filesize));
			}
			catch (vB_Exception_Api $e)
			{
				if ($e->has_error('upload_file_exceeds_limit'))
				{
					// try resizing image
					$resizeTargets = array(
						'width'    => 0,
						'height'   => 0,
						'filesize' => vB::getUserContext()->getChannelLimits($parentid, 'channeliconmaxsize'),
					);
					try
					{
						$resized = $this->resizeImage($userid, $filearray, $fileContents, $filesize, $filewidth, $fileheight, $extension, $resizeTargets);
					}
					catch(vB_Exception_Api $innerException)
					{
						// append the resize errors to our generic error.
						// This way, the user can see *why* their image has to be resized
						// in addition to why the resize failed.
						$innerErrors = $innerException->get_errors();
						foreach ($innerErrors AS $__error)
						{
							$__phrase_id = array_shift($__error);
							$e->add_error($__phrase_id, $__error);
						}

						// Throw original exception below.
						$resized = false;
					}

					if (!$resized)
					{
						if (isset($filearray['tmp_name']) AND file_exists($filearray['tmp_name']))
						{
							@unlink($filearray['tmp_name']);
						}
						throw $e;
					}
				}
				else
				{
					throw $e;
				}
			}
		}

		// TODO: This needs to check signature related usergroup permissions. VBV-14819
		// Signature picture
		if ($uploadFrom === 'signature')
		{
			$usercontext = vB::getUserContext();
			// Check if user has permission to upload signature picture
			if (!$usercontext->hasPermission('signaturepermissions', 'cansigpic'))
			{
				throw new vB_Exception_Api('no_permission');
			}

			// todo: check animated gif . Only GD has a private is_animated_gif() function ATM...

			// todo: check if $isImage & throw exception if not? Or are we supposed to allow nonimages in signatures?

			/*
			// VBV-14819 . Adding this since I was in the area, but don't have time to test right now,
			// so leaving it commented out until VBV-14819 is put into a sprint.

			$sigpicmaxsize = intval($usercontext->getUsergroupLimit('sigpicmaxsize'));
			$sigpicmaxwidth = intval($usercontext->getUsergroupLimit('sigpicmaxwidth'));
			$sigpicmaxheight = intval($usercontext->getUsergroupLimit('sigpicmaxheight'));

			$sizeOver = ($sigpicmaxsize > 0 AND $sigpicmaxsize < $filesize);
			$widthOver = ($sigpicmaxwidth > 0 AND $sigpicmaxwidth < $filewidth);
			$heightOver = ($sigpicmaxheight > 0 AND $sigpicmaxheight < $fileheight);

			if ($sizeOver OR $widthOver OR $heightOver)
			{
				$resizeTargets = array(
					'width'    => $sigpicmaxwidth,
					'height'   => $sigpicmaxheight,
					'filesize' => $sigpicmaxsize,
				);

				if ($sizeOver)
				{
					$unitSeparator = "&nbsp;";
					$exception = new vB_Exception_Api(
						'upload_file_exceeds_limit',
						array(
							vb_number_format($filesize, 1, true, null, null, $unitSeparator),
							vb_number_format($sigpicmaxsize, 1, true, null, null, $unitSeparator),
						)
					);
				}
				else
				{
					$exception = new vB_Exception_Api(
						'upload_exceeds_dimensions',
						array(
							$sigpicmaxwidth,
							$sigpicmaxheight,
							$filewidth,
							$fileheight
						)
					);
				}

				if ($isImage)
				{
					$exception->add_error('uploaded_jpeg_may_be_larger', array()); // VBV-17131
				}

				try
				{
					$resized = $this->resizeImage($userid, $filearray, $fileContents, $filesize, $filewidth, $fileheight, $extension, $resizeTargets);
				}
				catch(vB_Exception_Api $innerException)
				{
					// append the resize errors to our generic error.
					// This way, the user can see *why* their image has to be resized
					// in addition to why the resize failed.
					$innerErrors = $innerException->get_errors();
					foreach ($innerErrors AS $__error)
					{
						$__phrase_id = array_shift($__error);
						$exception->add_error($__phrase_id, $__error);
					}

					throw $exception;
				}
			}

			*/

			$imageOnly = true;
			$filearray['is_sigpic'] = 1;
		}



		// Everything below will be affected by attachment quota checks.
		$attachmentPermissions = $this->getAttachmentPermissions(array(
			'uploadFrom' => $uploadFrom,
			'extension' => $extension,
			'parentid' => $parentid,
		));
		if (!empty($attachmentPermissions['errors']))
		{
			$exception = new vB_Exception_Api();
			foreach ($attachmentPermissions['errors'] AS $__index => $__error)
			{
				if (is_array($__error))
				{
					// we don't array_shift here because errors returned by the function is in the
					// format 0 => phrase_id, 1 => phrase_args_array rather than the format of
					// array_unshift(phrase_args_array, phrase_id) that exception errors use
					$__phrase_id = $__error[0];
					$__phrase_args = $__error[1];
				}
				else
				{
					$__phrase_id = $__error;
					$__phrase_args = array();
				}

				// Special case, no_attach_perms_for_x, we need to set the file
				// extension in the phrase args
				if ($__phrase_id == "no_attach_perms_for_x")
				{
					// avoid some kind of reflection XSS
					$__phrase_args = array(vB_String::htmlSpecialCharsUni($extension));
				}

				$exception->add_error($__phrase_id, $__phrase_args);
			}

			throw $exception;
		}
		else
		{
			/*
				VBV-16066 - do not auto-resize when user hit his quota limits

				max_size is how large a single upload of the specific
				filetype can be.
				space_available is how much of their allotted quota (if any)
				is available to use.
				space_available === false when user has no quota limits.
			 */
			if ($attachmentPermissions['space_available'] !== false AND $filesize > $attachmentPermissions['space_available'])
			{
				/*
					We shouldn't hit the case of $result['space_available'] < 0, because
					that would've returned errors from getAttachmentPermissions()
					with the appropriate exception messages already.

					For now, don't care about if they happen to perfectly hit the quota limit with
					this upload... though their resizes might fail...?
				 */
				// this is going to be displayed in a popup dialog, and for English localization
				// the {X MB} happened to frequently land right at a line break, causing an ugly
				// break between the number & the units.
				// UPDATE: Going back to regular spaces due to the CKE upload alert double-escaping the
				// &bnsp; . See VBV-17265
				$unitSeparator = " ";
				$filesizeFormatted = vb_number_format($filesize, 1, true, null, null, $unitSeparator);
				$remainingFormated = vb_number_format($attachmentPermissions['space_available'], 1, true, null, null, $unitSeparator);
				$limitFormatted = vb_number_format($attachmentPermissions['attachlimit'], 1, true, null, null, $unitSeparator);
				//$globalLimitFormatted = vb_number_format($attachmentPermissions['options_limit'], 1, true, null, null, $unitSeparator);
				//$usergroupLimitFormatted = vb_number_format($attachmentPermissions['usergroup_limit'], 1, true, null, null, $unitSeparator);
				switch($attachmentPermissions['space_limit_from'])
				{
					case "options":
						$phrase_id = 'upload_quota_near_global';
						break;
					case "usergroup":
					default:
						$phrase_id = 'upload_quota_near_usergroup';
						break;
				}
				$phrase_args= array(
					$filesizeFormatted,
					$remainingFormated,
					$limitFormatted,
				);
				throw new vB_Exception_Api($phrase_id, $phrase_args);
			}
		}

		// Usergroup permissions
		if ($uploadFrom === 'profile')
		{
			$usercontext = vB::getUserContext();

			if ($cheperms)
			{
				// todo: update getAttachmentPermissions() & use $attachmentPermissions here
				$albumpicmaxheight = $usercontext->getLimit('albumpicmaxheight');
				$albumpicmaxwidth = $usercontext->getLimit('albumpicmaxwidth');


				if (($albumpicmaxwidth > 0 AND $filewidth > $albumpicmaxwidth) OR ($albumpicmaxheight > 0 AND $fileheight > $albumpicmaxheight))
				{
					// try resizing image
					$resizeTargets = array(
						'width'    => $albumpicmaxwidth,
						'height'   => $albumpicmaxheight,
						'filesize' => 0,
					);

					$exception = new vB_Exception_Api(
						'upload_exceeds_dimensions',
						array(
							$albumpicmaxwidth,
							$albumpicmaxheight,
							$filewidth,
							$fileheight
						)
					);

					try
					{
						$resized = $this->resizeImage($userid, $filearray, $fileContents, $filesize, $filewidth, $fileheight, $extension, $resizeTargets);
					}
					catch(vB_Exception_Api $innerException)
					{
						// append the resize errors to our generic error.
						// This way, the user can see *why* their image has to be resized
						// in addition to why the resize failed.
						$innerErrors = $innerException->get_errors();
						foreach ($innerErrors AS $__error)
						{
							$__phrase_id = array_shift($__error);
							$exception->add_error($__phrase_id, $__error);
						}

						throw $exception;
					}

					if (!$resized)
					{
						if (isset($filearray['tmp_name']) AND file_exists($filearray['tmp_name']))
						{
							@unlink($filearray['tmp_name']);
						}
						throw $exception;
					}
				}
			}
		}


		// Attachment permissions
		if ($cheperms AND $uploadFrom === 'newContent')
		{
			$resizeTargets = array(
				'width'    => $attachmentPermissions['max_width'],
				'height'   => $attachmentPermissions['max_height'],
				'filesize' => $attachmentPermissions['max_size'],
			);

			if (($attachmentPermissions['max_size'] > 0) AND ($filesize > $attachmentPermissions['max_size']))
			{
				$reportedFilesize = max($originalFilesize, $filesize);
				$unitSeparator = " ";
				$exception = new vB_Exception_Api(
					'upload_file_exceeds_limit',
					array(
						vb_number_format($reportedFilesize, 1, true, null, null, $unitSeparator),
						vb_number_format($attachmentPermissions['max_size'], 1, true, null, null, $unitSeparator)
					)
				);

				if ($isImage AND ($reportedFilesize != $originalFilesize))
				{
					$exception->add_error('uploaded_image_may_be_different_size', array()); // VBV-17131
				}

				try
				{
					// try resizing image. Note, if this is not an image, resizeImage() will return false.
					$resized = $this->resizeImage(
						$userid,
						$filearray,
						$fileContents,
						$filesize,
						$filewidth,
						$fileheight,
						$extension,
						$resizeTargets
					);
				}
				catch(vB_Exception_Api $innerException)
				{
					// append the resize errors to our generic error.
					// This way, the user can see *why* their image has to be resized
					// in addition to why the resize failed.
					$innerErrors = $innerException->get_errors();
					foreach ($innerErrors AS $__error)
					{
						$__phrase_id = array_shift($__error);
						$exception->add_error($__phrase_id, $__error);
					}
					throw $exception;
				}
				if (!$resized)
				{
					if (isset($filearray['tmp_name']) AND file_exists($filearray['tmp_name']))
					{
						@unlink($filearray['tmp_name']);
					}
					throw $exception;
				}
			}
			if (($attachmentPermissions['max_width'] > 0 AND $filewidth > $attachmentPermissions['max_width']) OR ($attachmentPermissions['max_height'] > 0 AND $fileheight > $attachmentPermissions['max_height']))
			{
				$exception = new vB_Exception_Api(
					'upload_exceeds_dimensions',
					array(
						$attachmentPermissions['max_width'],
						$attachmentPermissions['max_height'],
						$filewidth,
						$fileheight
					)
				);
				try
				{
					// try resizing image
					$resized = $this->resizeImage(
						$userid,
						$filearray,
						$fileContents,
						$filesize,
						$filewidth,
						$fileheight,
						$extension,
						$resizeTargets
					);
				}
				catch(vB_Exception_Api $innerException)
				{
					// append the resize errors to our generic error.
					// This way, the user can see *why* their image has to be resized
					// in addition to why the resize failed.
					$innerErrors = $innerException->get_errors();
					foreach ($innerErrors AS $__error)
					{
						$__phrase_id = array_shift($__error);
						$exception->add_error($__phrase_id, $__error);
					}
					throw $exception;
				}

				if (!$resized)
				{
					if (isset($filearray['tmp_name']) AND file_exists($filearray['tmp_name']))
					{
						@unlink($filearray['tmp_name']);
					}
					throw $exception;
				}
			}
		}

		$result = $this->saveUpload($userid, $filearray, $fileContents, $filesize, $extension, $imageOnly);

		if (file_exists($filearray['tmp_name']))
		{
			@unlink($filearray['tmp_name']);
		}

		return $result;
	}

	private function scanFileArray($file)
	{
		$check = false;
		if (!empty($file['tmp_name']))
		{
			$scanLib = vB_Library::instance('filescan');
			$check = $scanLib->scanFile($file['tmp_name']);
		}

		if (!$check)
		{
			// todo: separate out the empty tmp_name check vs scan failure check?
			// todo2: phrase currently indicates file will be deleted, but we don't do that here
			// (since we can't guarantee the file is an uploaded file rather than a local reference).
			throw new vB_Exception_Api('filescan_fail_uploaded_file');
		}
	}

	public function getAttachmentPermissions($data)
	{
		$result = array();

		$userid = vB::getCurrentSession()->get('userid');
		$uploadFrom = !empty($data['uploadFrom']) ? $data['uploadFrom'] : null;
		$usercontext = vB::getUserContext();
		$usergroupLimit = intval($usercontext->getUsergroupLimit('attachlimit'));
		$totalLimit = $usergroupLimit;
		$usedSpace = 0;
		$quotaLimitFrom = 'usergroup';
		$options = vB::getDatastore()->getValue('options');
		$globalLimit = $options['attachtotalspace'];

		// Check if we are not exceeding the quota
		if ($globalLimit > 0)
		{
			if (!$usergroupLimit OR $usergroupLimit > $globalLimit)
			{
				$totalLimit = $globalLimit;
				$quotaLimitFrom = 'options';
			}
		}

		//check to see if this user has their limit already.
		if ($totalLimit > 0)
		{
			$usedSpace = intval(vB::getDbAssertor()->getField('vBForum:getUserFiledataFilesizeSum', array('userid' => $userid)));

			if ($usedSpace >= $totalLimit)
			{
				// vB_Phrase::fetchSinglePhrase('upload_attachfull_user', $usedSpace - $totalLimit),
				$errors = array();

				// We do not want the sizes (with units, e.g. "34 KB") to wrap when the word happens to land at the
				// end of the line in the popup dialog, so use nonbreaking space instead of default space
				// UPDATE: Due to certain alerts double-escaping the &nbsp;, we're going back to using
				// regular spaces. See VBV-17265
				$exceededByFormatted = vb_number_format($usedSpace - $totalLimit, 1, true, null, null, " ");
				$globalLimitFormatted = vb_number_format($globalLimit, 1, true, null, null, " ");
				$usergroupLimitFormatted = vb_number_format($usergroupLimit, 1, true, null, null, " ");

				switch($quotaLimitFrom)
				{
					case "options":
						if ($usedSpace == $totalLimit)
						{
							$phrase_id = 'upload_quota_reached_global';
						}
						else
						{
							$phrase_id = 'upload_quota_exceeded_global';
						}
						$phrase_args= array($globalLimitFormatted, $exceededByFormatted);
						break;
					case "usergroup":
					default:
						if ($usedSpace == $totalLimit)
						{
							$phrase_id = 'upload_quota_reached_usergroup';
						}
						else
						{
							$phrase_id = 'upload_quota_exceeded_usergroup';
						}
						$phrase_args= array($usergroupLimitFormatted, $exceededByFormatted);
						break;
				}

				$result['errors'][] =  array($phrase_id, $phrase_args);

				return $result;
			}
			$spaceAvailable = $totalLimit - $usedSpace;
		}
		else
		{
			$spaceAvailable = false;
		}

		// Usergroup permissions
		if ($uploadFrom === 'profile')
		{
			/*
			 todo: get rid of or fix this. We don't even seem to use this
			 for uploads at all (we get the albumpicmaxheight/width
			 separately in the lib & don't bother with the size check at all.
			 Seems like the albummaxpics (count) check is checked in the gallery &
			 photo APIs.
			 ALso why are we using the attachlimit instead of something with the albummaxsize ??
			*/
			$usergroupattachlimit = $usercontext->getLimit('attachlimit');
			$albumpicmaxheight = $usercontext->getLimit('albumpicmaxheight');
			$albumpicmaxwidth = $usercontext->getLimit('albumpicmaxwidth');
			$result['max_size'] = $usergroupattachlimit;
			$result['max_height'] = $albumpicmaxheight;
			$result['max_width'] = $albumpicmaxwidth;
			$result['space_available'] = $spaceAvailable; // check for === false to differentiate between "no quota" and "0 bytes remaining"

			// todo: also need to check albummaxsize & get a separate total for album usage
			// to reassign $spaceAvailable if smaller
			if ($spaceAvailable !== false)
			{
				$result['space_limit_from'] = $quotaLimitFrom;
				$result['space_available'] = min($result['max_size'], $spaceAvailable);
				$result['attachlimit'] = $totalLimit;
			}
		}
		// Default to attachment permissions
		else
		{
			$extension = !empty($data['extension']) ? $data['extension'] : null;
			if ($extension != null)
			{
				// Fetch the parent channel or topic just in case we need to check group in topic.
				// The actual parent may not exist since we may be creating a new post/topic.
				$nodeid = (!empty($data['parentid'])) ? intval($data['parentid']) : false;
				$attachPerms = $usercontext->getAttachmentPermissions($extension, $nodeid);
				if ($attachPerms !== false)
				{
					$result['max_size'] = $attachPerms['size'];
					$result['max_height'] = $attachPerms['height'];
					$result['max_width'] = $attachPerms['width'];
					$result['space_available'] = $spaceAvailable; // check for === false to differentiate between "no quota" and "0 bytes remaining"
					$result['space_limit_from'] = $quotaLimitFrom;

					if ($spaceAvailable !== false)
					{
						//$result['usergroup_limit'] = $usergroupLimit;
						//$result['options_limit'] = $globalLimit;
						$result['attachlimit'] = $totalLimit;
					}
				}
				else
				{
					$result['errors'][] = 'no_attach_perms_for_x';
				}
			}
			else
			{
				// We may want to change this to be more descriptive (missing extension?), but for now leaving this as is.
				$result['errors'][] = 'invalid_file';
			}
		}

		return $result;
	}

	private function checkConfigImageResizeLimits($filewidth, $fileheight, $filesize = null)
	{
		if ($filewidth < 1 OR $fileheight < 1)
		{
			throw new vB_Exception_Api('upload_invalid_image');
		}

		/*
		This is here so that we can just outright reject the image (whether or not
		we would have otherwise attempted to resize based on attachment permissions)
		if it is larger than the config/default values.
		 */
		$config = vB::getConfig();
		$resizemaxwidth = ($config['Misc']['maxwidth']) ? $config['Misc']['maxwidth'] : 4608;
		$resizemaxheight = ($config['Misc']['maxheight']) ? $config['Misc']['maxheight'] : 3456;

		if (
			$filewidth > $resizemaxwidth OR
			$fileheight > $resizemaxheight
		)
		{
			throw new vB_Exception_Api(
				'unable_to_resize_image_dimensions_too_large',
				array(
					$filewidth,
					$fileheight,
					$resizemaxwidth,
					$resizemaxheight,
				)
			);
		}

		// We may add filesize config limits in the future, which is why we have an accepted but unused $filesize param at the moment.
	}

	/**
	 * Attempts to resize an uploaded image so that it can be saved as an attachment.
	 * If successful, it modifies $filearray, $fileContents, $filesize, $filewidth,
	 * $fileheight, $extension, and the temporary file as saved on disk, then returns true.
	 *
	 * @param	int	user id
	 * @param	array	file data array
	 * @param	string	file contents
	 * @param	int	file size
	 * @param	int	file width
	 * @param	int	file height
	 * @param	string	extension
	 * @param	array	target sizes (width, height, filesize)
	 *
	 * @return	bool	Returns false if the image is not successfully resized,
	 *			so the calling code can throw a size (dimensions or filesize) error
	 */
	protected function resizeImage($userid, &$filearray, &$fileContents, &$filesize, &$filewidth, &$fileheight, &$extension, array $targets)
	{
		/*
			Only allow images through this function. This means PDFs are NOT allowed into this function.
			Note, thumbnails for non-image files (namely PDF atm) is done directly from saveUpload(), not this function.

			Note that we also check isValidResizeType() a bit below, as not all images are resizable (bmp & tif using GD library, for ex)
		 */

		$this->checkAndFixImageExtension($extension, $filearray);
		$isImage = $this->imageHandler->fileLocationIsImage($filearray['tmp_name']);

		// ATM the caller (uploadAttachment()) already called filescan, so we're skipping this
		// here as to not perform unnecessary redundant work. However if any new callers arise,
		// or something changes in uploadAttachment(), we may want to do our own call here.
		// $this->scanUploadedFileArray($file);


		if (!$isImage)
		{
			return false;
		}

		$userid = (int) $userid;

		$options = vB::getDatastore()->getValue('options');
		$config = vB::getConfig();

		/*
			If we do loadImage() again here, it'll cause re-compression for JPEGs.
			We have 1st compression from uploadAttachment() calling loadImage(),
			a 2nd compression from below calling loadImage(), then the resize itself will be another jpeg save
			(though arguably that's already lossy from the resize itself, not just saving)

		 */
		// check validity of image
		if (!$this->imageHandler->verifyImageFile($fileContents, $filearray['tmp_name']))
		{
			if (file_exists($filearray['tmp_name']))
			{
				@unlink($filearray['tmp_name']);
			}
			throw new vB_Exception_Api('dangerous_image_rejected');
		}

		// Note, if we allow non-images (PDF) into this, we should switch this to fetchImageInfoForThumbnails() instaed
		// get image size
		$imageInfo = $this->imageHandler->fetchImageInfo($filearray['tmp_name']);

		if (!$imageInfo OR !$imageInfo[2])
		{
			throw new vB_Exception_Api('unable_to_resize_image_unknown_type');
		}

		// Currently we already call this in uploadAttachment(), but adding another call here
		// just in case resizeImage() gets called from another function.
		$this->checkConfigImageResizeLimits($imageInfo[0], $imageInfo[1], $filesize);

		if (empty($options['attachresize']))
		{
			throw new vB_Exception_Api('unable_to_resize_image_resize_disabled');
		}

		$validResizeType = $this->imageHandler->isValidResizeType($imageInfo[2]);
		if (!$validResizeType)
		{
			throw new vB_Exception_Api('unable_to_resize_image_resize_type', $imageInfo[2]);
		}


		// see if we need to do a resize
		if (
			($targets['width'] > 0 AND $imageInfo[0] > $targets['width'])
			OR
			($targets['height'] > 0 AND $imageInfo[1] > $targets['height'])
			OR
			($targets['filesize'] > 0 AND $filesize > $targets['filesize'])
		)
		{
			$targetWidth = $targets['width'] > 0 ? $targets['width'] : $imageInfo[0];
			$targetHeight = $targets['height'] > 0 ? $targets['height'] : $imageInfo[1];
			$targetSize = $targets['filesize'] > 0 ? $targets['filesize'] : $filesize;

			// if filesize is too large, calculate smaller dimensions
			if ($targetSize < $filesize)
			{
				$factor = $targetSize / $filesize; // factor may need adjusting

				$originalXtoYRatio = $imageInfo[0] / $imageInfo[1];
				$pixels = $imageInfo[0] * $imageInfo[1];
				$targetPixels = $pixels * $factor;

				/*
					Assuming a linear relationship between filesize & targetPixels
					(which isn't necessarily true for certain compressions)...

					$newX * $newY = $targetPixels;
					$newX / $newY = $originalXtoYRatio;

					$newX  = $originalXtoYRatio * $newY;
					       = $targetPixels / $newY;

					$originalXtoYRatio * $newY ^2 = $targetPixels;
					$newY = sqrt($targetPixels / $originalXtoYRatio);
				 */
				$newY = sqrt($targetPixels / $originalXtoYRatio);
				$newX = $originalXtoYRatio * $newY;
				$newY =  floor($newY);
				$newX = floor($newX);

				$targetWidth = min($newX, $targetWidth);
				$targetHeight = min($newY, $targetHeight);
			}

			// resize (dimensions too large)
			$labelImage = false;
			$drawBorder = false;
			$jpegConvert = false; // used to be true, but don't see a reason we should always convert to jpeg.
			$sharpenImage = false;
			$resizedImage = $this->imageHandler->fetchThumbnail(
				$filearray['name'],
				$filearray['tmp_name'],
				$targetWidth,
				$targetHeight,
				$options['thumbquality'],
				$labelImage,
				$drawBorder,
				$jpegConvert,
				$sharpenImage
			);

			if (empty($resizedImage['filedata']))
			{
				// resize failed. Let the caller determine the appropriate error message.
				//throw new vB_Exception_Api('unable_to_resize_image');
				return false;
			}

		}

		if (!empty($resizedImage))
		{
			// save new temp file
			$filename = vB_Utilities::getTmpFileName("$userid-$filesize", 'vbattach', ".$extension");

			file_put_contents($filename, $resizedImage['filedata']);

			if (file_exists($filearray['tmp_name']))
			{
				@unlink($filearray['tmp_name']);
			}

			$filearray['tmp_name'] = $filename;

			$filesize = filesize($filearray['tmp_name']);
			$fileContents = file_get_contents($filearray['tmp_name']);

			$filewidth = $resizedImage['width'];
			$fileheight = $resizedImage['height'];

			$filearray['name'] = !empty($resizedImage['filename']) ? $resizedImage['filename'] : $filearray['name'];

			$filebits = explode('.', $filearray['name']);
			$extension = end($filebits);

			// image successfully resized
			return true;
		}

		// resize was possibly skipped due to not requiring it... let the caller handle this.
		return false;
	}

	/**
	 * Upload an image based on the url
	 *
	 *  @param  int     user ID
	 * 	@param 	string	remote url
	 *  @param	bool	save as attachment
	 *
	 *	@return	mixed	array of data, includes filesize, dateline, htmltype, filename, extension, and filedataid
	 */
	public function uploadUrl($userid, $url, $attachment = false, $uploadfrom = '')
	{
		//Leave for consistency with admincp
		if (!defined('ATTACH_AS_FILES_NEW'))
		{
			define('ATTACH_AS_FILES_NEW', 2);
		}

		//Did we get a valid url?
		if (empty($url))
		{
			// throw the same exception to mitigate SSRF (VBV-13082)
			throw new vB_Exception_Api('upload_invalid_image');
		}

		if (!preg_match('#^https?://#i', $url))
		{
			// throw the same exception to mitigate SSRF (VBV-13082)
			throw new vB_Exception_Api('upload_invalid_image');
		}

		// Retrieve the image
		$vurl = vB::getUrlLoader();
		$vurl->setOption(vB_Utility_Url::FOLLOWLOCATION, 1);
		$vurl->setOption(vB_Utility_Url::HEADER, 1);

		//explicitly setting the maxsize to 0 doesn't actually do anything, but leaving
		//it in because we did it previously (implicitly) and because setting this to
		//something other than "unlimited" might be a good and calling it out specifically
		//seems useful.  Setting DIEONMAXSIZE does change the value -- but it's only relevant
		//if MAXSIZE is set to a non empty value.
		$vurl->setOption(vB_Utility_Url::MAXSIZE, 0);
		$vurl->setOption(vB_Utility_Url::DIEONMAXSIZE, 0);
		$fileResult = $vurl->get($url);

		if (empty($fileResult['body']))
		{
			// throw the same exception to mitigate SSRF (VBV-13082)
			throw new vB_Exception_Api('upload_invalid_image');
		}

		$pathinfo = pathinfo($url);
		if (empty($pathinfo))
		{
			// throw the same exception to mitigate SSRF (VBV-13082)
			throw new vB_Exception_Api('upload_invalid_image');
		}

		// if there's no extension here try get one from elsewhere
		$extension_map = $this->imageHandler->getExtensionMap();
		if (empty($pathinfo['extension']) OR !array_key_exists(strtolower($pathinfo['extension']), $extension_map))
		{
			// try to get an extension from the content type header
			if (!empty($fileResult['headers']['content-type']))
			{
				// should be something like image/jpeg
				$typeData = explode('/', $fileResult['headers']['content-type']);
				if ((count($typeData) == 2) AND array_key_exists(trim($typeData[1]), $extension_map))
				{
					$extension = strtolower($extension_map[trim($typeData[1])]);
				}
			}
			$name = $pathinfo['basename'] . '.' . $extension;
		}
		else
		{
			$extension = $pathinfo['extension'];
			$name = $pathinfo['basename'];
		}
		$extension = strtolower($extension);

		// todo.... is this appending .$extension safe??
		$filename = vB_Utilities::getTmpFileName($userid, 'vbattach', ".$extension");

		file_put_contents($filename, $fileResult['body']);
		$filesize = strlen($fileResult['body']);

		//Make a local copy
		$filearray = array(
			'name'     => $name,
			'size'     => $filesize,
			'type'     => 'image/' . $extension_map[$extension],
			'tmp_name' => $filename
		);

		if (!empty($uploadfrom))
		{
			$filearray['uploadFrom'] = $uploadfrom;
		}

		if ($attachment)
		{
			// file scan done in uploadAttachment
			return $this->uploadAttachment($userid, $filearray);
		}
		else
		{
			$this->scanFileArray($filearray);


			try
			{
				$this->checkConfigImageResizeLimitsForFile($filearray['tmp_name']);
			}
			catch (vB_Exception_Api $e)
			{
				// throw the same exception to mitigate SSRF (VBV-13082)
				throw new vB_Exception_Api('upload_invalid_image');
			}

			/*
				 loadImage() will do the whitelist check before passing it through to GD/IM, & header/exif
				checks (as part of verifyImageFile() after the image is written).
			 */
			$newImageData = $this->imageHandler->loadImage($filearray['tmp_name']);
			// Once we hit above, we do not care about the old file regardless of if it's "safe" or "dangerous".
			if (file_exists($filearray['tmp_name']))
			{
				@unlink($filearray['tmp_name']);
			}
			if (empty($newImageData))
			{
				// throw the same exception to mitigate SSRF (VBV-13082)
				throw new vB_Exception_Api('upload_invalid_image');
			}

			// Don't forget to delete the old file first!
			$filearray['size'] = $newImageData['size'];
			$filearray['type'] = $newImageData['type'];
			$filearray['tmp_name'] = $newImageData['tmp_name'];
		}

		$result = $this->saveUpload($userid, $filearray, $fileResult['body'], $filesize, $extension, true);

		if (file_exists($filearray['tmp_name']))
		{
			@unlink($filearray['tmp_name']);
		}

		return $result;
	}

	public function checkConfigImageResizeLimitsForFile($filepath)
	{
		$isImage = $this->imageHandler->fileLocationIsImage($filepath);
		if (!$isImage)
		{
			throw new vB_Exception_Api('upload_invalid_image');
		}

		$orientation = $this->imageHandler->getOrientation($filepath);
		// exif orientation values of 5, 6, 7 & 8 are 90/270 degrees, so width & height are flipped.
		if ($orientation >= 5 AND $orientation <= 8)
		{
			list($fileheight, $filewidth) = getimagesize($filepath);
		}
		else
		{
			list($filewidth, $fileheight) = getimagesize($filepath);
		}
		$filesize = filesize($filepath);

		return $this->checkConfigImageResizeLimits($filewidth, $fileheight, $filesize);
	}

	public function saveThemeIcon($userid, $filearray, $fileContents, $filesize, $extension, $imageOnly = false, $skipUploadPermissionCheck = false)
	{
		// This is used by the theme importer to upload the icons without re-compressing the JPGs.
		// Don't call this unless you're absolutely certain of
		// the image content.
		// You probably want to just go through uploadAttachment() like everyone else.

		// TODO: Remove need for $skipUploadPermissionCheck

		// adding scan call even though this function is not meant for use outside of *trusted* imports
		$this->scanFileArray($filearray);

		return $this->saveUpload($userid, $filearray, $fileContents, $filesize, $extension, $imageOnly = false, $skipUploadPermissionCheck = false);
	}


	/**
	 * Saves an uploaded file into the filedata system.
	 *
	 * @param	int		$userid				Id of user uploading the image. This user's permissions will be checked when necessary
	 * @param	array	$filearray			Array of data describing the uploaded file with data-types & keys:
	 *											string	'name'			Filename
	 *											int		'size'			Filesize
	 *											string	'type'			Filetype
	 *											string	'tmp_name'		Filepath to the temporary file created on the server
	 *											int		'parentid'		Optional. Node/Channelid this file will be uploaded under. If provided
	 *																	permissions will be checked under this node.
	 *											bool	'is_sigpic'		Optional. If this is not empty, the saved filedata will replace
	 *																	the user's sigpicnew record (or inserted for the user if none exists),
	 *																	and the filedata record will have refcount incremented & publicview
	 *																	set to 1.
	 * @param	string	$fileContents		String(?) containing file content BLOB
	 * @param	int		$filesize			File size
	 * @param	string	$extension			File extension
	 * @param	bool	$imageOnly			If true, this function will throw an exception if the file is not an image
	 * @param	bool	$skipUploadPermissionCheck		Optional boolean to skip permission checks. Only used internally when the system
	 *													saves a theme icon. Do not use for normal calls to this function.
	 *
	 * @return	array	Array of saved filedata info with data-types & keys:
	 *						int 		'filedataid'
	 *						int 		'filesize'
	 *						int			'thumbsize'		file size of the thumbnail of the saved filedata
	 *						string		'extension'
	 *						string		'filename'
	 *						string[]	'headers'		array containing the content-type http header of the saved filedata
	 *						boolean		'isimage'
	 *
	 * @throws	vB_Exception_Api('invalid_attachment_storage')	If 'attachfile' ("Save attachments as File") is enabled and the path specified
	 *															by 'attachpath' option is not writable for some reason
	 * @throws	vB_Exception_Api('dangerous_image_rejected')	If image verification failed for $fileContents or $filearray['tmp_name']
	 * @throws	vB_Exception_Api('upload_attachfull_total')		If attachment quota specified by 'attachtotalspace' option is exceeded
	 * @throws	vB_Exception_Api('cannot_create_file')			If the user fails the permission checks
	 * @throws	vB_Exception_Api('upload_invalid_image')		If $imageOnly is true and the uploaded file is not an image
	 * @throws	vB_Exception_Api('unable_to_add_filedata')		If adding the filedata record failed
	 * @throws	vB_Exception_Api('attachpathfailed')			If 'attachfile' ("Save attachments as File") is enabled and creating or fetching
	 *															the path to the attachment directory for the user failed
	 * @throws	vB_Exception_Api('upload_file_system_is_not_writable_path')		If 'attachfile' ("Save attachments as File") is enabled and the
	 *															path retrieved for the user is not writable.
	 *
	 * @access	private
	 */
	private function saveUpload($userid, $filearray, $fileContents, $filesize, $extension, $imageOnly = false, $skipUploadPermissionCheck = false)
	{
		// TODO upload check? at the moment, all callers have already called $this->scanFileArray(...), so
		// adding another here might just be duplicated processing ... furthermore the file that's sent here
		// may be a processed (e.g. resized) file rather than the original file.

		/*
			You will most likely want to call
				$this->imageHandler->loadImage({str filelocation});
			before you call this, as to rewrite the image using GD/IM as part of standard image upload protocol.
			However, beware that this will cause quality degradation for any lossy formats (like JPEG).
			Access is set to private to prevent accidentally calls to this (instead of to saveAttachment() ) from external
			soruces.
		 */

		$assertor = vB::getDbAssertor();
		$datastore = vB::getDatastore();
		$options = $datastore->getValue('options');
		$config = vB::getConfig();
		$usercontext = vB::getUserContext($userid);

		//make sure there's a place to put attachments.
		if ($options['attachfile'] AND
			(empty($options['attachpath']) OR !file_exists($options['attachpath']) OR !is_writable($options['attachpath']) OR !is_dir($options['attachpath'])))
		{
			throw new vB_Exception_Api('invalid_attachment_storage');
		}

		// Check if this is an image extension we're dealing with for displaying later.
		// exif_imagetype() will check the validity of image
		$isImage = $this->imageHandler->fileLocationIsImage($filearray['tmp_name']);
		if ($isImage)
		{
			/*
				verifyImageFile() will call verifyFileHeadersAndExif() first thing, no need to check it again here.

				Note, there's a very good chance that what we check here has already been forcibly re-written as an image
				as part of image security (downstrea of imageHandler->loadImage() call from whoever called us).

				loadImage() just straight up rewrites the image using the selected image library without checking headers/exif,
				so if you're trying to test sneaking in script tags & other stuff in the image and wondering why below doesn't
				trigger an error, it's probably because all the "bad stuff" has been destroyed by the image rewrite already.
			 */
			if (! $this->imageHandler->verifyImageFile($fileContents, $filearray['tmp_name']))
			{
				@unlink($filearray['tmp_name']);
				throw new vB_Exception_Api('dangerous_image_rejected');
			}
			/*
				Image talk...
				We could call magicWhiteList() and get the expected type from the file signature and
				compare the type to extension here. Since our output logic trusts the extension passed in,
				that could provide a slightly better ui/ux (and/or we could force-switch extensions here
				rather than allow clients to set it incorrectly). E.g. you could upload a gif with a .jpg,
				and it would be downloaded as a .jpg not a .gif, which may cause issues viewing it depending
				on the client.
				Currently, below, we only check that if an extension is *an* image type, the file is an image
				(& vice versa), but not that the extension is the *correct* image type.
			 */
		}

		/*
		 *	Note, this is for identification only, NOT for security!
		 *	If we're going to depend on the extension to determine if it's an image for outputting html,
		 *	let's at least check that it's an image.
		 */
		$this->checkAndFixImageExtension($extension, $filearray);

		/*
			Not calling getAttachmentPermissions() ATM on this extension, we leave that to the callers.
			(Not every saveUpload() call may require permission checks).
			uploadAttachment() does all that for certain branches before calling saveUpload() .
			uploadUrl() & saveThemeIcon() do not. Note that uploadUrl() will call uploadAttachment()
			for certain branches.

		 */

		// Thumbnails are a different story altogether. Something like a PDF
		// might have a thumbnail.
		$canHaveThumbnail = $this->imageHandler->imageThumbnailSupported($extension);

		/*
		 * TODO: We might want to check that the extension matches the mimetype.
		 *
		 */


		//We check to see if this file already exists.
		$filehash = md5($fileContents);

		$fileCheck = $assertor->getRow('vBForum:getFiledataWithThumb', array(
			'filehash' => $filehash,
			'filesize' => $filesize
		));

		// Does filedata already exist?
		if (empty($fileCheck) OR ($fileCheck['userid'] != $userid))
		{
			// Check if we are not exceeding the quota
			if ($options['attachtotalspace'] > 0)
			{
				$usedSpace = $assertor->getField('vBForum:getUserFiledataFilesizeSum', array('userid' => $userid));

				$overage = $usedSpace + $filesize - $options['attachtotalspace'];
				if ($overage > 0)
				{
					$overage = vb_number_format($overage, 1, true);
					$userinfo = vB::getCurrentSession()->fetch_userinfo();

					$maildata = vB_Api::instanceInternal('phrase')->fetchEmailPhrases(
						'attachfull',
						array(
							$userinfo['username'],
							$options['attachtotalspace'],
							$options['bburl'],
							'admincp',
							$overage,
						),
						array($options['bbtitle'])
					);
					vB_Mail::vbmail($options['webmasteremail'], $maildata['subject'], $maildata['message']);

					throw new vB_Exception_Api('upload_attachfull_total', $overage);
				}
			}

			// Can we move this permission check out of this library function?
			if (
				(!$usercontext->canUpload($filesize, $extension, (!empty($filearray['parentid'])) ? $filearray['parentid'] : false))
				AND !$skipUploadPermissionCheck	// TEMPORARY SOLUTION, NEED A BETTER WAY TO GET AROUND THIS FOR THEME ICONS
			)
			{
				@unlink($filearray['tmp_name']);
				throw new vB_Exception_Api('cannot_create_file');
			}

			if ($imageOnly AND !$isImage)
			{
				throw new vB_Exception_Api('upload_invalid_image');
			}
			$timenow =  vB::getRequest()->getTimeNow();

			if ($canHaveThumbnail)
			{
				/*
				TODO: if pdf thumbnailing is enabled, a PDF can get to this point,
				but it has not gone through the config maxwidth/maxheight check.
				Problem is, if the pdf is large enough, just trying to get its size
				via fetchImageInfoForThumbnails() could cause issues (consume too
				much memory/cpu/time)...
				We need some way of "cheaply" looking up its dimensions then add the
				maxwidth/height check PDFs agains the config limits before passing
				them into fetchIMageInfoForThumbnails().
				 */
				/*
					When PDF to JPG thumbnails are allowed for Magick|Imagick imagetype options, any issues
					with the dependencies (e.g. ghostscript not installed, delegates not properly configured,
					Imagick extension installation doesn't have support for PDF, etc) may cause the thumbnailing
					process to throw an error. In that case, we should just continue on as if thumbnails for PDF
					are disabled.
					For now only do this "thumbnail skip" for PDFs, not other types.
				 */
				try
				{
					//Get the image size information.
					$imageInfo = $this->imageHandler->fetchImageInfoForThumbnails($filearray['tmp_name']);
					$sizes = @unserialize($options['attachresizes']);
					if (!isset($sizes['thumb']) OR empty($sizes['thumb']))
					{
						$sizes['thumb'] = 100;
					}
					$thumbnail = $this->imageHandler->fetchThumbnail(
						$filearray['name'],
						$filearray['tmp_name'],
						$sizes['thumb'],
						$sizes['thumb'],
						$options['thumbquality']
					);
				}
				catch (Throwable $e)
				{
					if (strtolower($extension) == 'pdf')
					{
						/*
							checkAndFixImageExtension() should've already checked that
							the file header is the whitelisted PDF header, iff the image
							library is allowing PDF -> JPG conversions. If it's not doing
							the conversion, we wouldn't get here.

							If we need to double check the header, see
							vB_Image::compareExtensionToFilesignature()
						 */
						 $canHaveThumbnail = false;
					}

					// Just rethrow the exception if it's not a resize bypass.
					if ($canHaveThumbnail)
					{
						throw $e;
					}
				}
			}

			if (!$canHaveThumbnail)
			{
				$imageInfo = array();
				$thumbnail = array('filesize' => 0, 'width' => 0, 'height' => 0, 'filedata' => null);
			}

			$thumbnail_data = array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_INSERT,
				'resize_type'     => 'thumb',
				'resize_dateline' => $timenow,
				'resize_filesize' => $thumbnail['filesize'],
				'resize_width'    => $thumbnail['width'],
				'resize_height'   => $thumbnail['height'],
			);

			// Note, unless this is a sigpic (defined as !empty($filearray['is_sigpic'])), below will set
			// the refcount of the new filedata record to 0.
			// So the caller MUST increment the refcount if this image should not be removed by the cron.
			$data = array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_INSERT,
				'userid'    => $userid,
				'dateline'  => $timenow,
				'filesize'  => $filesize,
				'filehash'  => $filehash,
				'extension' => $extension,
				'refcount'  => 0,
			);
			if (!empty($imageInfo))
			{
				$data['width'] = $imageInfo[0];
				$data['height'] = $imageInfo[1];
			}

			//Looks like we're ready to store. But do we put it in the database or the filesystem?
			if ($options['attachfile'])
			{
				//We name the files based on the filedata record, but we don't have that until we create the record. So we need
				// to do an insert, then create/move the files.
				$filedataid = $assertor->assertQuery('filedata', $data);

				if (is_array($filedataid))
				{
					$filedataid = $filedataid[0];
				}

				if (!intval($filedataid))
				{
					throw new vB_Exception_Api('unable_to_add_filedata');
				}

				$path = $this->verifyAttachmentPath($userid);
				if (!$path)
				{
					throw new vB_Exception_Api('attachpathfailed');
				}

				if (!is_writable($path))
				{
					throw new vB_Exception_Api('upload_file_system_is_not_writable_path', array(htmlspecialchars($path)));
				}

				if (!empty($thumbnail['filedata']))
				{
					file_put_contents($path . $filedataid . '.thumb', $thumbnail['filedata']);
				}
				rename($filearray['tmp_name'] , $path . $filedataid . '.attach');
			}
			else
			{
				//We put the file contents into the data record.
				$data['filedata'] = $fileContents;
				$filedataid = $assertor->assertQuery('filedata', $data);

				// check here if the filedata was successfully stored to the db
				$consistencyCheck = $assertor->getRow('checkFiledataConsistency', array('filedataid' => $filedataid));
				if (!$consistencyCheck['filesize_matches'])
				{
					// the filedata was not saved correctly to the database,
					// it may have been truncated due to the ~16MB limit of MEDIUMBLOB
					throw new vB_Exception_Api('unable_to_add_filedata_data_missing');
				}
				if (!$consistencyCheck['filehash_matches'])
				{
					// the filedata was not saved correctly to the database
					// for unknown reasons
					throw new vB_Exception_Api('unable_to_add_filedata_data_corrupt');
				}

				if (is_array($filedataid))
				{
					$filedataid = $filedataid[0];
				}
				$thumbnail_data['resize_filedata'] = $thumbnail['filedata'];
			}

			$thumbnail_data['filedataid'] = $filedataid;
			if ($canHaveThumbnail)
			{
				$assertor->assertQuery('vBForum:filedataresize', $thumbnail_data);
			}

			if (!empty( $filearray['name']))
			{
				 $filename = $filearray['name'];
			}
			else
			{
				$filename = '';
			}

			$result = array(
				'filedataid' => $filedataid,
				'filesize'   => $filesize,
				'thumbsize'  => $thumbnail['filesize'],
				'extension'  => $extension,
				'filename'   => $filename,
				'headers'    => $this->getAttachmentHeaders(strtolower($extension)),
				'isimage'    => $isImage,
			);

			if (!empty($filearray['is_sigpic']))
			{
				$assertor->assertQuery('replaceSigpic', array('userid' => $userid, 'filedataid' => $filedataid));
				$assertor->assertQuery('incrementFiledataRefcountAndMakePublic', array('filedataid' => $filedataid));
			}
		}
		else
		{
			// file already exists so we are not going to insert a new one
			$filedataid = $fileCheck['filedataid'];

			if (!empty($filearray['is_sigpic']))
			{
				// Get old signature picture data and decrease refcount
				$oldfiledata = vB::getDbAssertor()->getRow('vBForum:sigpicnew', array('userid' => $userid));
				if ($oldfiledata)
				{
					vB::getDbAssertor()->assertQuery('decrementFiledataRefcount', array('filedataid' => $oldfiledata['filedataid']));
				}

				$assertor->assertQuery('replaceSigpic', array('userid' => $fileCheck['userid'], 'filedataid' => $filedataid));
				$assertor->assertQuery('incrementFiledataRefcountAndMakePublic', array('filedataid' => $filedataid));
			}

			$result = array(
				'filedataid' => $filedataid,
				'filesize'   => $fileCheck['filesize'] ,
				'thumbsize'  => $fileCheck['resize_filesize'],
				'extension'  => $extension,
				'filename'   => $filearray['name'],
				'headers'    => $this->getAttachmentHeaders(strtolower($extension)),
				'isimage'    => $isImage,
			);
		}

		return $result;
	}

	protected function verifyAttachmentPath($userid)
	{
		// Allow userid to be 0 since vB2 allowed guests to post attachments
		$userid = intval($userid);

		$path = $this->fetchAttachmentPath($userid);
		if (vB_Library_Functions::vbMkdir($path))
		{
			return $path;
		}
		else
		{
			return false;
		}
	}

	protected function fetchAttachmentPath($userid, $attachmentid = 0, $thumb = false, $overridepath = '')
	{
		$options =  vB::getDatastore()->get_value('options');
		$attachpath = !empty($overridepath) ? $overridepath : $options['attachpath'];

		if ($options['attachfile'] == ATTACH_AS_FILES_NEW) // expanded paths
		{
			$path = $attachpath . '/' . implode('/', preg_split('//', $userid,  -1, PREG_SPLIT_NO_EMPTY)) . '/';
		}
		else
		{
			$path = $attachpath . '/' . $userid . '/';
		}

		if ($attachmentid)
		{
			if ($thumb)
			{
				$path .= '/' . $attachmentid . '.thumb';
			}
			else
			{
				$path .= '/' . $attachmentid . '.attach';
			}
		}

		return $path;
	}

	private function checkAndFixImageExtension(&$extension, &$filearray)
	{
		/*
			We do not do any image writes here, just *renames*
			Currently this rename happens before we send the file off
			to the vb_image class.
		*/
		$filename = $filearray['tmp_name'];
		$name = $filearray['name'];
		$isImage = $this->imageHandler->fileLocationIsImage($filename);

		if ($isImage)
		{
			$imgExtension = $this->imageHandler->getExtensionFromFileheaders($filename);
			/*
				if $isImage, we should know what the "proper" extension is unless we forgot to set it in the image classes.
			 */
			if (!$imgExtension)
			{
				throw new vB_Exception_Api('image_extension_but_wrong_type');
			}

			/*
				Rename the file & extension if necessary.
			 */
			if ($extension != $imgExtension)
			{
				$entropy = $filename;
				$newfilename = vB_Utilities::getTmpFileName($entropy, 'vbattach', ".$imgExtension");

				$try = rename($filename, $newfilename);
				if (!$try)
				{
					if (file_exists($newfilename))
					{
						@unlink($newfilename);
					}
					throw new vB_Exception_Api('image_extension_but_wrong_type');
				}

				// The old file shouldn't be there after rename, but just in case.
				if (file_exists($filename))
				{
					@unlink($filename);
				}

				// Relabel everything. We pass by reference so that we can modify the initial file array.
				$name = substr($name, 0, -strlen($extension)) . $imgExtension;
				$filename = $newfilename;
				$extension = $imgExtension;

				$extension_map = $this->imageHandler->getExtensionMap();
				$filearray = array(
					'name'     => $name,
					'size'     => filesize($filename),
					'type'     => 'image/' . $extension_map[$extension],
					'tmp_name' => $filename
				);

			}
		}

		/*
			Note, I moved it here past the new "re-extension" code above. I don't think it's
			needed now, but there's some code below with comments about browser support and
			I don't have the brain power under this cold to figure that out today.
			So to be safe, I'll leave it here, and hopefully clean it up later...
		 */
		// extension doesn't really mean much... but let's make sure that an image extension is
		// an image & non-image-extension is not an image
		// We might remove this, as we shouldn't be trusting or using provided extensions AT ALL.
		$isImageExtension = $this->imageHandler->isImageExtension($extension);

		/*
			Certain types can be considered an image by all the checks, but we may not outwardly consider it an
			image because the browser does not support the type in an img element.
			For example, a legitimate .PSD file will pass all the checks, but we can't include that in an image tag.
			So we can't just check $isImageExtension === $isImage and call it a day.
			If it has an img-embeddable extension, ensure it's an image.
			If it's an image but not embeddable, check that the extension is for the type detected by the file signature.
		 */
		if ($isImageExtension)
		{
			if (!$isImage)
			{
				throw new vB_Exception_Api('image_extension_but_wrong_type');
			}
		}

		/*
			It's using a known file extension, but NOT
		 */
		$check = $this->imageHandler->compareExtensionToFilesignature($extension, $filename);
		if (!$check)
		{
			throw new vB_Exception_Api('image_extension_but_wrong_type');
		}
	}

	/**
	 * Validates that the current can create a node with these values
	 *
	 * @param  mixed  Array of field => value pairs which define the record.
	 * @param  string Parameters to be checked for permission
	 * @param  int    Node ID
	 * @param  array  Nodes
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

		if (parent::validate($data, $action, $nodeid, $nodes, $userid) == false)
		{
			return false;
		}

		switch ($action)
		{
			case self::ACTION_ADD:
				if (empty($data['filedataid']))
				{
					return false;
				}
				break;
		}

		return true;
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 103780 $
|| #######################################################################
\*=========================================================================*/
