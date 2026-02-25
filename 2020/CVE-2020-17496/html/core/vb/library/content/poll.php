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
 * vB_Library_Content_Poll
 *
 * @package vBLibrary
 * @access public
 */
class vB_Library_Content_Poll extends vB_Library_Content_Text
{
	//override in client- the text name
	protected $contenttype = 'vBForum_Poll';

	//The table for the type-specific data.
	protected $tablename = array('poll', 'text');

	//list of fields that are included in the index
	protected $index_fields = array('rawtext','options');

	//When we parse the page.
	protected $bbcode_parser = false;

	//Whether we change the parent's text count- 1 or zero
	protected $textCountChange = 1;

	protected $tableFields = array();

	/**
	 * Returns the node content as an associative array with fullcontent
	 *
	 * @param	mixed	integer or array of integers=The id in the primary table
	 * @param array permissions
	 *
	 * @param bool	appends to the content the channel routeid and title, and starter route and title the as an associative array
	 */
	public function getFullContent($nodes, $permissions = false)
	{
		$results = parent::getFullContent($nodes, $permissions);

		// TODO: Why do we call this when the parent::getFullContent() already called it?
		// $this->addContentInfo() @ parent level will still call this,
		// and this implementation of addContentInfo() calls parent's addContentInfo().
		return $this->addContentInfo($results);
	}

	protected function addContentInfo($results)
	{
		$results = parent::addContentInfo($results);

		$checkvoted = array();
		try
		{
			$checkvoted = $this->checkVotedMultiple(array_keys($results));
		}
		catch (vB_Exception_Api $e)
		{
			// Ignore for guest user
		}

		//the key of for each node is the nodeid, fortunately
		foreach ($results AS $key => &$record)
		{
			if (!empty($record['options']) AND !is_array($record['options']))
			{
				$record['options'] = @unserialize($record['options']);
			}

			/*
				mobile api needs to see which option the user voted for. If we cached this from the
				results of the pollvote query in checkVotedMultiple(), we might be able to save a
				array walk here.
			 */
			$userid = vB::getCurrentSession()->get('userid');
			if (!empty($checkvoted[$key]) AND !empty($userid))
			{
				foreach ($record['options'] AS $key2 => $option)
				{
					if (!empty($option['voters']))
					{
						foreach ($option['voters'] AS $voterid)
						{
							if ($voterid == $userid)
							{
								$record['options'][$key2]['uservote'] = true;
								break;
							}
						}
					}
				}
			}

			// Check if the poll is timeout
			if (isset($record['timeout']))
			{
				$record['istimeout'] = ($record['timeout'] AND $record['timeout'] < vB::getRequest()->getTimeNow());

				// For timeout input
				if ($record['timeout'])
				{
					$record['timeoutstr'] = vbdate("m/d/Y H:i", $record['timeout']);
				}
				else
				{
					$record['timeoutstr'] = '';
				}
			}
			else
			{
				$record['timeoutstr'] = '';
				$record['istimeout'] = false;
			}

			// Check if it's voted already
			// TODO: we need to improve this to consider voting permissions for guests.
			$record['voted'] = !empty($checkvoted[$key]) ? $checkvoted[$key] : false;
		}

		return $results;
	}

	/**
	 * updates a record
	 *
	 *	@param	mixed		array of nodeid's
	 *	@param	mixed		array of permissions that should be checked.
	 *
	 * 	@return	boolean
	 */
	public function update($nodeid, $data, $convertWysiwygTextToBbcode = true)
	{
		$existing = $this->nodeApi->getNode($nodeid);

		$changeOptions = false;
		if (isset($data['options']))
		{
			$this->checkPollOptions($data);
			$options = $data['options'];
			$changeOptions = true;
		}
		else
		{
			$options = null;
		}

		$oldnode = $this->getContent($nodeid);
		$oldnode = $oldnode[$nodeid];

		// skip the index in the parent and do it here so it can include the options
		$data['noIndex'] = true;

		//this is never set to true for polls in normal operation, but presume we unset it for a reason
		unset($data['parseurl']);

		unset($data['options']);

		$result = parent::update($nodeid, $data, $convertWysiwygTextToBbcode);

		if ($changeOptions)
		{
			$oldoptionids = array();
			$optionids = array();
			foreach ($oldnode['options'] as $option)
			{
				$oldoptionids[$option['polloptionid']] = $option['polloptionid'];
			}

			$bbcodelib = vB_Library::instance('bbcode');

			// Save poll options
			foreach ($options as $option)
			{
				if (!empty($option['polloptionid']))
				{
					// Check if the polloption belongs to the poll (node)
					$polloption = $this->assertor->getRow('vBForum:polloption', array('nodeid' => $nodeid));

					if ($polloption['nodeid'] == $nodeid)
					{
						$votes = $this->assertor->getRows('vBForum:pollvote', array('polloptionid' => $option['polloptionid']));

						$voters = array();
						foreach ($votes as $vote)
						{
							if (!in_array($vote['userid'], $voters))
							{
								$voters[] = $vote['userid'];
							}
						}

						$this->assertor->assertQuery('vBForum:polloption', array(
							vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_UPDATE,
							'title' => $option['title'],
							'votes' => count($votes),
							'voters' => serialize($voters),
							vB_dB_Query::CONDITIONS_KEY => array(
								'polloptionid' => $option['polloptionid']
							)
						));

						$optionids[$option['polloptionid']] = $option['polloptionid'];
					}
					else
					{
						throw new Exception('invalidid');
					}

				}
				else
				{
					// Insert new option
					$this->assertor->assertQuery('vBForum:polloption', array(
						vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_INSERT,
						'nodeid' => $nodeid,
						'title' => $option['title'],
					));

				}
			}

			$optionstoremove = array_diff($oldoptionids, $optionids);
			if ($optionstoremove)
			{
				$this->assertor->assertQuery('vBForum:polloption', array(
					vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_DELETE,
					'polloptionid' => $optionstoremove,
				));

				//delete pollvotes
				$this->assertor->assertQuery('vBForum:pollvote', array(
					vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_DELETE,
					'polloptionid' => $optionstoremove,
				));
			}
		}

		$this->updatePollCache($nodeid);
		$this->nodeApi->clearCacheEvents(array($nodeid, $existing['parentid']));
		// do the indexing after the options are added
		vB_Library::instance('search')->index($nodeid);

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
		$existing =	$this->nodeApi->getNode($nodeid);

		//do the delete
		parent::delete($nodeid);

		//delete polloptions
		$this->assertor->assertQuery('vBForum:polloption', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_DELETE,
			'nodeid' => $nodeid,
		));

		//delete pollvotes
		$this->assertor->assertQuery('vBForum:pollvote', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_DELETE,
			'nodeid' => $nodeid,
		));
		$this->nodeApi->clearCacheEvents(array($nodeid, $existing['parentid']));
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

		//delete polloptions
		$this->assertor->assertQuery('vBForum:polloption', array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_DELETE,
				'nodeid' => $childrenIds,
		));

		//delete pollvotes
		$this->assertor->assertQuery('vBForum:pollvote', array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_DELETE,
				'nodeid' => $childrenIds,
		));
	}


	/**
	 * Adds a new node.
	 *
	 * @param	mixed		Array of field => value pairs which define the record.
	 * @param	array		Array of options for the content being created.
	 * 						Understands skipTransaction, skipFloodCheck, floodchecktime, skipDupCheck, skipNotification, nl2br, autoparselinks.
	 *							- nl2br: if TRUE, all \n will be converted to <br /> so that it's not removed by the html parser (e.g. comments).
	 * @param	bool		Convert text to bbcode
	 *
	 * @return	mixed		array with nodeid (int), success (bool), cacheEvents (array of strings),
	 * 		nodeVals (array of field => value), attachments (array of attachment records).
	 */
	public function add($data, array $options = array(), $convertWysiwygTextToBbcode = true)
	{
		//Store this so we know whether we should call afterAdd()
		$skipTransaction = !empty($options['skipTransaction']);
		$this->checkPollOptions($data);

		// Keep an array of *only* the poll options, without the other options in the standard array
		$pollOptions = $data['options'];

		//this is needed for a later call to indexable content that is used for the
		//duplicate post check.
		//We need to sort out how to better handle this.  The options are needed for the
		//duplicate check, but if we set this, they'll be saved to the db (and we don't handle
		//serialized fields gracefully just yet).  However the value here isn't quite right (we
		//don't have all the of the data until after we save the records -- but it will be corrected
		//below in the "update cache" function
		$data['options'] = serialize($this->getCacheOptionsArrayFromOptions($data['options']));

		//this is never set to true for polls in normal operation, but presume we unset it for a reason
		unset($data['parseurl']);

		// skip the index in the parent and do it here so it can include the options
		$data['noIndex'] = true;

		try
		{
			if (!$skipTransaction)
			{
				$this->assertor->beginTransaction();
			}
			$options['skipTransaction'] = true;
			$result = parent::add($data, $options, $convertWysiwygTextToBbcode);

			// Save poll options
			foreach ($pollOptions AS $option)
			{
				// Insert new option
				$this->assertor->assertQuery('vBForum:polloption', array(
					vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_INSERT,
					'nodeid' => $result['nodeid'],
					'title' => $option['title'],
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
			$this->afterAdd($result['nodeid'], $data, $options, $result['cacheEvents'], $result['nodeVals']);
		}

		$this->updatePollCache($result['nodeid']);
		// do the indexing after the options are added
		$this->nodeApi->clearCacheEvents(array($result['nodeid'], $data['parentid']));
		vB_Library::instance('search')->index($result['nodeid']);

		return $result;
	}

	protected function checkPollOptions($data)
	{
		$vboptions = vB::getDatastore()->getValue('options');

		//should this be an admin option?  For now go with two because a poll with one option
		//makes no sense.
		$minPollOptions = 2;
		if (empty($data['options']) OR !is_array($data['options']) OR count($data['options']) < $minPollOptions)
		{
			throw new vB_Exception_Api('please_enter_at_least_x_poll_answers', array($minPollOptions));
		}
		if ($vboptions['maxpolloptions'] > 0 AND count($data['options']) > $vboptions['maxpolloptions'])
		{
			throw new vB_Exception_Api('too_many_options');
		}

		foreach ($data['options'] as &$option)
		{
			if (!$option['title'])
			{
				unset($option);
			}
			elseif ($vboptions['maxpolllength'] AND vB_String::vbStrlen($option['title']) > $vboptions['maxpolllength'])
			{
				throw new vB_Exception_Api('option_title_toolong');
			}
		}
	}

	public function vote($options, $userid = false)
	{
		if (!$userid)
		{
			$userid = vB::getCurrentSession()->get('userid');
		}

		foreach ($options as $option)
		{
			if (!$option)
			{
				throw new Exception('invalidid');
			}

			// Insert Vote
			$this->assertor->assertQuery('vBForum:pollvote', array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_INSERT,
				'nodeid' => $option['nodeid'],
				'polloptionid' => $option['polloptionid'],
				'userid' => $userid,
				'votedate' => vB::getRequest()->getTimeNow(),
			));

			$voters = @unserialize($option['voters']);

			if (!$voters)
			{
				$voters = array();
			}
			$votes = $option['votes'];
			if (!in_array($userid, $voters))
			{
				$voters[] = $userid;
				$votes++;
			}

			// Update option
			$this->assertor->assertQuery('vBForum:polloption', array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_UPDATE,
				'voters' => serialize($voters),
				'votes' => $votes,
				vB_dB_Query::CONDITIONS_KEY => array(
					'polloptionid' => $option['polloptionid']
				)
			));
			$nodeid = $option['nodeid'];
		}

		// All options should be in a same poll
		$this->updatePollCache($nodeid, true);

		//Send a notification.
		$poll = $this->nodeApi->getNode($nodeid);
		$recipients = array();

		$contextData = array(
			'sentbynodeid' => $nodeid,
			'sender' => $userid,
		);
		vB_Library::instance('notification')->triggerNotificationEvent('new-poll-vote', $contextData, $recipients);
		vB_Library::instance('notification')->insertNotificationsToDB();

		//If this node is not the starter, we need to send a notification to the starter also.
		// Note: this currently does not happen, but it's for when someone votes on a poll that was posted as a reply to another topic
		if ($poll['starter'] != $nodeid)
		{
			// Not yet implemented.
		}

		// TODO: Should subscribers get notifications for poll votes?

		return $nodeid;
	}

	/**
	 *	Gets poll options for unposted poll
	 *
	 *	This mimics the cached values in the "options" field of the poll table
	 *	(as constructed in the updatePollCache function).  It takes in the passed
	 *	title values and fills out the array with defaults so that the expected
	 *	fields are present.  ID values are set to null since they don't yet exist.
	 *	Also while the usual options array in cache is polloptionid => polloptionarray,
	 *	this is just an enumerated list of poll option arrays (because ids don't
	 *	exist yet).
	 *
	 *	@param array $polloptions array of arrays of the form
	 *		title => {poll option value}
	 *
	 *	@return array with the fields
	 *		title => passed value
	 *		polloptionid => null
	 *		nodeid => null
	 *		votes = 0
	 *		voters = array()
	 */
	protected function getCacheOptionsArrayFromOptions($polloptions)
	{
		$cache = array();
		foreach($polloptions AS $option)
		{
			//we haven't saved yet, we don't have a key or a node id
			$option['polloptionid'] = null;
			$option['nodeid'] = null;
			$option['votes'] = 0;
			$option['voters'] = array();

			//this is normaly a map of optionid => option but we don't have
			//that because we haven't saved and created the ids here.
			$cache[] = $option;
		}
		return $cache;
	}

	/**
	 * Updates Poll cache
	 *
	 * @param  int  Node ID for the affected poll
	 * @param  bool Whether or not to update the last vote info.
	 *
	 * @return void
	 */
	public function updatePollCache($nodeid, $updatelastvote = false)
	{
		// Update poll table's options
		// Get options
		$options = $this->assertor->getRows('vBForum:polloption', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'nodeid' => $nodeid
		));

		$optionstosave = array();
		foreach ($options as $option)
		{
			$option['voters'] = @unserialize($option['voters']);
			$optionstosave[$option['polloptionid']] = $option;
		}
		unset($options, $option);
		$voters = $this->assertor->getField('vBForum:poll_fetchvotes', array('nodeid' => $nodeid));

		foreach ($optionstosave as &$option)
		{
			if ($voters)
			{
				$option['percentage'] = ($option['votes'] / $voters) * 100;
			}
			else
			{
				$option['percentage'] = 0;
			}
		}

		$data = array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'options' => serialize($optionstosave),
			'votes' => $voters,
			vB_dB_Query::CONDITIONS_KEY => array(
				'nodeid' => $nodeid
			)
		);

		if ($updatelastvote)
		{
			$data['lastvote'] = vB::getRequest()->getTimeNow();
		}

		$this->assertor->assertQuery('vBForum:poll', $data);
		$this->nodeLibrary->clearCacheEvents(array($nodeid));
	}

	public function getIndexableFromNode($content, $include_attachments = true)
	{
		$indexableContent = parent::getIndexableFromNode($content, $include_attachments);
		$option_titles = array();
		//options may be serialized
		if (is_string($content['options']))
		{
			$content['options'] = unserialize($content['options']);
		}

		foreach ((array)$content['options'] AS $option)
		{
			array_push($option_titles, $option['title']);
		}
		$indexableContent['options'] = implode(',',$option_titles);

		return $indexableContent;
	}

	public function getQuotes($nodeids)
	{
		//Per Product, we just quote the text content (but this may change in the future)
		//If and when the requirement changes to include the non-text content, don't call the parent method and then implement it here
		return parent::getQuotes($nodeids);
	}

	protected function checkVoted($nodeid)
	{
		$result = $this->checkVotedMultiple(array($nodeid));
		return $result[$nodeid];
	}

	protected function checkVotedMultiple($nodeids)
	{
		static $checked = array();
		$notfound = array();
		$return = array();

		foreach ($nodeids as $nodeid)
		{
			if (isset($checked[$nodeid]))
			{
				$return[$nodeid] = $checked[$nodeid];
			}
			else
			{
				$notfound[] = $nodeid;
			}
		}

		if (empty($notfound))
		{
			return $return;
		}

		$loginuser = &vB::getCurrentSession()->fetch_userinfo();
		if (!$loginuser['userid'])
		{
			throw new vB_Exception_Api('not_logged_no_permission');
		}
		$uservoteinfo = vB::getDbAssertor()->getRows('vBForum:pollvote', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'userid' => $loginuser['userid'],
			'nodeid' => $notfound,
		), false, 'nodeid');

		foreach ($notfound as $nodeid)
		{
			if (!empty($uservoteinfo[$nodeid]))
			{
				$return[$nodeid] = true;
			}
			else
			{
				$return[$nodeid] = false;
			}
			$checked[$nodeid] = $return[$nodeid];
		}

		return $return;
	}

	/**
	 * Adds content info to $result so that merged content can be edited.
	 * @param array $result
	 * @param array $content
	 */
	public function mergeContentInfo(&$result, $content)
	{
		parent::mergeContentInfo($result, $content);

		$fields = array('title', 'options', 'timeout', 'timeoutstr', 'multiple', 'public');

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
		$db->update('poll', array('nodeid' => $data['destnodeid']), array(array('field' => 'nodeid', 'value' => $sources)));
		$db->update('vBForum:node', array('contenttypeid' => $this->contenttypeid), array('nodeid' => $data['destnodeid']));

		// get polloptions
		$polloptions = array();
		foreach($data AS $key => $value)
		{
			if (preg_match('#^polloptions\[([\d]+)#', $key, $matches))
			{
				$polloptions[] = array(
					'polloptionid' => intval($matches[1]),
					'title' => trim($value),
				);
			}
			else if (preg_match('^polloptions\[new', $key, $matches))
			{
				foreach ($value as $option)
				{
					$polloptions[]['title'] = trim($option);
				}
			}
		}

		$pollData = array(
			'title' => $data['title'],
			'rawtext' => $data['text'],
			'userid' => $data['destauthorid'],
			'urlident' => vB_String::getUrlIdent($data['title']),
			'options' => $polloptions,
			'multiple' => $data['multiple'],
			'public' => $data['public'],
			'parseurl' => $data['parseurl'],
			'timeout' => strtotime($data['timeout'])
		);

		return vB_Api::instanceInternal('content_poll')->update($data['destnodeid'], $pollData);
	}

	/**
	 * This cleans up for a node that was found to be incomplete by deleting the child nodes and subsidiary table records
	 *
	 * @param	mixed	node record, which may have missing child table data.
	 */
	public function incompleteNodeCleanup($node)
	{
		$deleted = parent::incompleteNodeCleanup($node);

		if ($deleted)
		{
			//The poll, text, and node records will be deleted by the parent. We need to delete polloption and pollvote;
			$params = array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_DELETE, 'nodeid' => $node['nodeid']);
			//delete polloptions
			$this->assertor->assertQuery('vBForum:polloption', $params);

			//delete pollvotes
			$this->assertor->assertQuery('vBForum:pollvote', $params);
		}

		return $deleted;
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 103189 $
|| #######################################################################
\*=========================================================================*/
