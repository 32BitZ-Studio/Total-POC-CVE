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
 * vB_Library_Content_link
 *
 * @package vBLibrary
 * @access public
 */
class vB_Library_Content_Link extends vB_Library_Content_Text
{
	//override in client- the text name
	protected $contenttype = 'vBForum_Link';

	//The table for the type-specific data.
	protected $tablename = array('link', 'text');

	//list of fields that are included in the index
	protected $index_fields = array('rawtext','url_title');

	protected $providers = array();

	/**
	 * Checks if user can delete a given link
	 *
	 * @param 	int		User Id
	 *
	 * @param	int		Link Id
	 *
	 * @return boolean value to indicate whether user can or not delete link
	 */
	protected function canDeleteLink($userId, $nodeid, $fileDataRecord)
	{
		/** moderators can delete links */
		if (vB::getUserContext()->getChannelPermission("moderatorpermissions", "canmoderateattachments", $nodeid))
		{
			return true;
		}

		return false;
	}

	/**
	 * @param	int		Link ID
	 *
	 * @return	mixed	Filedata Record
	 */
	protected function fetchFileDataRecord($nodeid)
	{
		$link = $this->assertor->getRow("vBForum:link", array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
						'nodeid' => $nodeid ));

		$fileDataRecord = null;
		if ($link['filedataid'])
		{
			$fileDataRecord = $this->assertor->getRow("vBForum:filedata", array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
						'filedataid' => $link['filedataid'] ));
		}

		return $fileDataRecord;
	}

	/**
	 * Validate filedata record
	 * @param	int	fileDataId
	 *
	 * @param	int UserId
	 *
	 * @return	boolean	Indicate if fileData is valid for the user
	 */
	protected function validateFileData($fileDataId)
	{
		$fileData = $this->assertor->getRow("vBForum:filedata", array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
						'filedataid' => $fileDataId ));

		if (empty($fileData))
		{
			throw new vB_Exception_Api('invalid_filedata');
		}

		if ($fileData["userid"] != vB::getCurrentSession()->get('userid'))
		{
			throw new vB_Exception_Api('invalid_user_filedata');
		}

		return true;
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
	 * Permanently deletes a node
	 *	@param	integer	The nodeid of the record to be deleted
	 *
	 *	@return	boolean
	 */
	public function delete($nodeid)
	{
		/** Get filedata refcount */
		$fileDataRecord = $this->fetchFileDataRecord($nodeid);
		if ($fileDataRecord AND !$this->canDeleteLink(vB::getCurrentSession()->get('userid'), $nodeid, $fileDataRecord))
		{
			throw new vB_Exception_Api('no_delete_permissions');
		}

		if ($result = parent::delete($nodeid))
		{
			$refCount = $fileDataRecord["refcount"] - 1;
			$data = array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_UPDATE,
				vB_dB_Query::CONDITIONS_KEY =>  array('filedataid' => $fileDataRecord["filedataid"]), 'refcount' => $refCount);
			$this->assertor->assertQuery("vBForum:filedata", $data);

			return $result;
		}
		else
		{
			return false;
		}
	}

	/**
	 * Delete the records without updating the parent info. It is used when deleting a whole channel and it's children need to be removed
	 * @param array $childrenIds - list of node ids
	 */
	public function deleteChildren($childrenIds)
	{
		foreach ($childrenIds as $photoId)
		{
			$fileDataRecord = $this->fetchFileDataRecord($photoId);
			$refCount = $fileDataRecord["refcount"] - 1;
			$data = array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_UPDATE,
					vB_dB_Query::CONDITIONS_KEY =>  array('filedataid' => $fileDataRecord["filedataid"]), 'refcount' => $refCount);
			$this->assertor->assertQuery("vBForum:filedata", $data);
		}

		//delete the main tables
		parent::deleteChildren($childrenIds);
	}

	/**
	 * Adds a new node.
	 *
	 *	@param	mixed		Array of field => value pairs which define the record.
	 *	@param	array		Array of options for the content being created
	 * 						Understands skipTransaction, skipFloodCheck, floodchecktime, skipDupCheck, skipNotification, nl2br, autoparselinks.
	 *							- nl2br: if TRUE, all \n will be converted to <br /> so that it's not removed by the html parser (e.g. comments).
	 *
	 * 	@return	mixed		array with
	 * 		nodeid (int),
	 * 		success (bool),
	 * 		cacheEvents (array of strings),
	 * 		nodeVals (array of field => value),
	 * 		attachments (array of attachment records).
	 */
	public function add($data, array $options = array(), $convertWysiwygTextToBbcode = true)
	{
		$this->validateLinkData($data, __FUNCTION__);

		//Store this so we know whether we should call afterAdd()
		$skipTransaction = !empty($options['skipTransaction']);

		/** Validate Filedata */
		if (!empty($data["filedataid"]))
		{
			$this->validateFileData($data['filedataid']);
		}

		// increment refcount for the image (if it has one)
		if ($data['filedataid'] > 0)
		{
			vB::getDbAssertor()->assertQuery('updateFiledataRefCount', array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_STORED,
				'countChange' => 1,
				'filedataid' => $data["filedataid"],
			));
		}

		$options['skipTransaction'] = true;
		$result = parent::add($data, $options, $convertWysiwygTextToBbcode);

		//its troubling that this add function doesn't have a transaction, but we need to make sure
		//this gets called.
		$this->beforeCommit($result['nodeid'], $data, $options, $result['cacheEvents'], $result['nodeVals']);

		//indexing and cache clear are done in the parent
		if (!$skipTransaction)
		{
			//The child classes that have their own transactions all set this to true so afterAdd is always called just once.
			$this->afterAdd($result['nodeid'], $data, $options, $result['cacheEvents'], $result['nodeVals']);
		}
		return $result;
	}

	public function update($nodeid, $data, $convertWysiwygTextToBbcode = true)
	{
		$this->validateLinkData($data, __FUNCTION__);

		$currentNode = $this->getContent($nodeid);
		$currentNode = reset($currentNode);

		//if we don't have the filedataid passed, assume that its stayed the same.
		if (isset($data['filedataid']))
		{
			// adjust refcounts if the image has changed (or been added/removed)
			if ($currentNode['filedataid'] != $data['filedataid'])
			{
				// decrement refcount for the previous image (if it had one)
				if ($currentNode['filedataid'] > 0)
				{
					vB::getDbAssertor()->assertQuery('updateFiledataRefCount', array(
						vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_STORED,
						'countChange' => -1,
						'filedataid' => $currentNode["filedataid"],
					));
				}

				// increment refcount for the new image (if it has one)
				if ($data['filedataid'] > 0)
				{
					vB::getDbAssertor()->assertQuery('updateFiledataRefCount', array(
						vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_STORED,
						'countChange' => 1,
						'filedataid' => $data["filedataid"],
					));
				}
			}
			else
			{
				// Auto-correct: set refcount to 1 if it's 0. This problem can be encountered
				// in databases that existed before VBV-11243 was fixed.
				vB::getDbAssertor()->update('filedata', array('refcount' => 1), array('filedataid' => $currentNode['filedataid'], 'refcount' => 0));
			}
		}

		if ($currentNode['contenttypeid'] != vB_Types::instance()->getContentTypeID($this->contenttype))
		{
			parent::changeContentType($nodeid, $currentNode['contenttypeid'], $this->contenttype);
			$data['contenttypeid'] = vB_Types::instance()->getContentTypeID($this->contenttype);
		}

		return parent::update($nodeid, $data, $convertWysiwygTextToBbcode);
	}

	/**
	 *	Validates the data for update or add
	 *	@param array $data -- The data to be validated.
	 *	@param string $function -- The function we are validating for, so we can log that with the error message
	 *	@return none -- will throw an execption if there is an error.  Will not if everything is valid
	 */
	private function validateLinkData($data, $function)
	{
		if (!empty($data['url']))
		{
			$urlInfo = vB_String::parseUrl($data['url']);
			if (empty($urlInfo) OR (!empty($urlInfo['scheme']) AND $urlInfo['scheme'] != 'http' AND $urlInfo['scheme'] != 'https'))
			{
				throw new vB_Exception_Api('invalid_data_w_x_y_z', array($data['url'], '$data[\'url\']', __CLASS__, $function));
			}
		}
	}

	/**
	 * Adds content info to $result so that merged content can be edited.
	 * @param array $result
	 * @param array $content
	 */
	public function mergeContentInfo(&$result, $content)
	{
		parent::mergeContentInfo($result, $content);

		$fields = array('filedataid', 'url', 'url_title', 'meta');

		$missing = array_diff($fields, array_keys($content));
		if (!empty($missing))
		{
			throw new vB_Exception_Api('invalid_content_info');
		}

		foreach ($fields AS $field)
		{
			$result[$field] = $content[$field];
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
		$db->update('vBForum:link', array('nodeid' => $data['destnodeid']), array(array('field' => 'nodeid', 'value' => $sources)));
		$db->update('vBForum:node', array('contenttypeid' => $this->contenttypeid), array('nodeid' => $data['destnodeid']));

		//@TODO: There is no title for posting a reply or comment but api throws an error if blank. Fix this.
		if (empty($data['url_title']))
		{
			$data['url_title'] = '(Untitled)';
		}

		$filedataid = 0;
		if (!$data['url_nopreview'] AND $data['url_image'])
		{
			$ret = vB_Api::instance('content_attach')->uploadUrl($data['url_image']);

			if (empty($ret['error']))
			{
				$filedataid = $ret['filedataid'];
			}
		}

		if ($filedataid)
		{
//				vB_Api::instanceInternal('content_attach')->deleteAttachment($data['destnodeid']);
		}

		$linkData = array(
			'userid' => $data['destauthorid'],
			'url_title' => $data['url_title'],
			'rawtext' => $data['text'],
			'url' => $data['url'],
			'meta' => $data['url_meta'],
			// TODO: uncomment this when the editor is ready
//			'filedataid' => $filedataid
		);

		return vB_Api::instanceInternal('content_link')->update($data['destnodeid'], $linkData);
	}

	public function getQuotes($nodeids)
	{
		//Per Product, we just quote the text content (but this may change in the future)
		//If and when the requirement changes to include the non-text content, don't call the parent method and then implement it here
		return parent::getQuotes($nodeids);
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 102683 $
|| #######################################################################
\*=========================================================================*/
