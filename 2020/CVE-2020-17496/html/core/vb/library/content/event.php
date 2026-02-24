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
 * vB_Library_Content_Event
 *
 * @package vBLibrary
 * @access public
 */
class vB_Library_Content_Event extends vB_Library_Content_Text
{
	//override in child- the text name
	protected $contenttype = 'vBForum_Event';

	//The table for the type-specific data.
	protected $tablename = array('event', 'text');

	//list of fields that are included in the index
	protected $index_fields = array('rawtext','location');

	//When we parse the page.
	protected $bbcode_parser = false;

	//Whether we change the parent's text count- 1 or zero
	protected $textCountChange = 1;

	/**
	 * Permanently deletes a node
	 *	@param	integer	The nodeid of the record to be deleted
	 *
	 *	@return	boolean
	 */
	public function delete($nodeid)
	{
		// TODO should this be LIB? API should've checked perms..
		$existing =	$this->nodeApi->getNode($nodeid);

		if (empty($existing))
		{
			return false;
		}

		//do the delete
		parent::delete($nodeid);

		//delete event record
		$this->assertor->assertQuery('vBForum:event', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_DELETE,
			'nodeid' => $nodeid,
		));

		return true;

		// vB_Library_Node::clearCacheEvents() called on node(s) & parentid(s) via vB_Library_Content::delete()
		// $this->nodeApi->clearCacheEvents(array($nodeid, $existing['parentid']));
	}

	/**
	 * Delete the records without updating the parent info. It is used when deleting a whole channel and it's children need to be removed
	 * @param array $childrenIds - list of node ids
	 */
	public function deleteChildren($childrenIds)
	{
		//delete the main tables
		parent::deleteChildren($childrenIds);

		//delete event record
		$this->assertor->assertQuery('vBForum:event', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_DELETE,
			'nodeid' => $childrenIds,
		));
	}


	/**
	 * Adds a new node.
	 *
	 * @param	mixed		Array of field => value pairs which define the record.
	 * @param	array		Array of options for the content being created.
	 * 		Understands skipTransaction, skipFloodCheck, floodchecktime, skipDupCheck,
	 * 			skipNotification, nl2br, autoparselinks.
	 *		- nl2br: if TRUE, all \n will be converted to <br /> so that it's not removed
	 *			by the html parser (e.g. comments).
	 * @param	bool		Convert text to bbcode
	 *
	 * @return	mixed		array with nodeid (int), success (bool), cacheEvents (array of strings),
	 * 	nodeVals (array of field => value), attachments (array of attachment records).
	 */
	public function add($data, array $options = array(), $convertWysiwygTextToBbcode = true)
	{
		//Store this so we know whether we should call afterAdd()
		$skipTransaction = !empty($options['skipTransaction']);
		// This will ensure we have location, eventstartdate, eventenddate.
		$data = $this->checkEventData($data);

		// skip the index in the parent and do it here so it can include anything that might've been
		// saved to DB in this add() implementation. ATM this is not necessary, see note below.
		$data['noIndex'] = true;

		try
		{
			if (!$skipTransaction)
			{
				$this->assertor->beginTransaction();
				$options['skipTransaction'] = true;
			}

			$result = parent::add($data, $options, $convertWysiwygTextToBbcode);
			/*
				Here is where we'd do event-specific stuff before committing the transaction, like adding extra data to
				other tables.
				Currently, the only extra data ATM is in $this->tablename (text, event), which is added by content's add()
				before afterAdd() is called (where the search index() is called, see 'noIndex' above and in content LIB).
				So wrapping this in its own transaction instead of letting the parent (text ATM) begin the transaction really
				is not even necesssary at this point. In fact, without checkEventData(), this implementation probably isn't even
				needed period.
				However, leaving it like this will make expanding easier in the future, and I don't think it causes big performance
				issues for the trade-off.
				If we're never going to expand this, we can remove the noIndex, transaction wrapping, & the cacheClear & search index
				at the end to just let the ancestors take care of it, and just call
					$data = $this->checkEventData($data);
					return parent::add($data, $options, $convertWysiwygTextToBbcode);
				and call it a day.
			 */

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


		// do the indexing after the event specific data (currently, only location is added to indexable text) is added
		$this->nodeApi->clearCacheEvents(array($result['nodeid'], $data['parentid']));
		vB_Library::instance('search')->index($result['nodeid']);

		return $result;
	}

	/**
	 * updates a record
	 *
	 * @param  int     $nodeid   Nodeid to update
	 * @param  Array   $data     Array of field => value pairs which define the record.
	 *
	 * @return	boolean
	 */
	public function update($nodeid, $data, $convertWysiwygTextToBbcode = true)
	{
		// $withJoinableContent = true so we get the event-table data for checkEventData()
		$existing = $this->nodeLibrary->getNode($nodeid, false, true);

		// This will ensure we have location, eventstartdate, eventenddate.
		$data = $this->checkEventData($data, $existing);

		// skip the index in the parent and do it here so it can include the event location
		$data['noIndex'] = true;


		$result = parent::update($nodeid, $data, $convertWysiwygTextToBbcode);
		/*
			See notes in add().
			Here is where we'd do event-specific stuff before reunning the index.
			Similar to add(), we don't really have to do this for event ATM since
			the only content-specific extra data is in text & event tables which
			are specified in $this->tablename, thus handled by content::add()
			If we want to keep things simple, all that's needed is
				$data = $this->checkEventData($data);
				$result = parent::update($nodeid, $data, $convertWysiwygTextToBbcode);
			but again, leaving this framework in place in case we need to expand it in future.
		 */

		// todo is this clearCacheEvents() required @ child level??
		$this->nodeApi->clearCacheEvents(array($nodeid, $existing['parentid']));
		// do the indexing after the event specific data is added. Not needed currently
		// as only data we're waiting for is event.location which is handled via content::add()
		vB_Library::instance('search')->index($nodeid);


		/*
		// TODO: Event change notification.
		// TODO: option to skip sending notification??
		$notificationLibrary = vB_Library::instance('notification');
		$recipients = array(); // the notification class will have to figure this out on its own.
		$contextData = array(
			'sender' => vB::getUserContext()->fetchUserId(), // if we ever support cron-triggered update()s, this might be the "wrong" userid (e.g. regular user whose page load kicked cron instead of the cron "system user")
			'old_data' => $existing,
			'new_data' => $data,
		);
		$notificationLibrary->triggerNotificationEvent('vbforum_event-update', $contextData, $recipients);
		$notificationLibrary->insertNotificationsToDB();
		*/

		return $result;
	}

	public function getEndOfDayUnixtime($timestamp, $userid = false, $hmsString = "11:59:59 PM", $ignoreDST = true)
	{
		$userApi = vB_Api::instanceInternal('user');
		$dateString = $userApi->unixtimestampToUserDateString($timestamp, $userid, "Y-m-d", $ignoreDST);
		$endOfDayString = $dateString['datestr'] . " " . trim($hmsString);
		$endOfDayTimestamp = $userApi->userTimeStrToUnixtimestamp($endOfDayString, $userid, $ignoreDST);
		$endOfDayTimestamp = $endOfDayTimestamp['unixtimestamp'];

		return $endOfDayTimestamp;
	}

	/**
	 * Checks if we have valid data for an event.
	 * Public to allow API to access this. Not meant for anything other than convenience checks.
	 *
	 * @param array       $data The standard create/update data array.
	 * @param array|false $existing The existing node array, if updating, else false
	 */
	public function checkEventData($data, $existing = false)
	{
		/*
			THIS DOES NOT CLEAN ANYTHING!!!
			You're thinking of vB_Api_Content_Event::cleanInput()
		 */

		/*
			Required:
				Start Date,
				Start Time,

			Optional:
				Location,
				End Date,
				End Time,
				All-day,

			Note, if all-day is set & true, it'll override the enddate & time to be
			11:59:59PM for the day of eventstartdate.

			To add or update an event as an all-day event, either set the allday flag,
			or set eventenddate to 0 and skip allday.

			To update an existing event from all-day to specified endtime,
			just set eventenddate & skip allday.
		 */

		// todo: will frontend allow a separate start date & start time that must be summed?
		// ATM eventstartdate & eventenddate are unix timestamps.

		// todo: Should we disallow eventstart/enddates in the past?
		// todo: Should we support strtotime() support with the dates for custom api clients?

		// Run the check A) when adding a new node or B) when updating, only if the field is set.
		// On update, if the field is not set in the incoming data, we won't update it at all
		if (!$existing OR isset($data['location']))
		{
			if (empty($data['location']))
			{
				//throw new vB_Exception_Api('event_no_location_specified');
				$data['location'] = '';
			}
			else
			{
				$strlen = vB_String::vbStrlen($data['location'], false);
				$maxChars = 191; // hard limit on DB column
				if ($strlen > $maxChars)
				{
					throw new vB_Exception_Api('maxchars_exceeded_event_location', array($maxChars, $strlen));
				}
			}
		}

		/*
			IF allday is set, eventstartdate & eventenddate *both* must be set.
			Only the date portion will be used, and it'll go from midnight (0AM) to
			midnight - 1 second (11:59:59PM) for the specified end & start dates.
		 */
		if (isset($data['allday']))
		{
			if ($data['allday'])
			{

				if (!$existing)
				{
					if (!isset($data['eventstartdate']))
					{
						throw new vB_Exception_Api('event_no_startdate_specified');
					}

					if (!isset($data['eventenddate']))
					{
						// todo: should we allow legacy behavior of skipping the end date to signify
						// "end at end of same day"?
						throw new vB_Exception_Api('event_invalid_enddate');
					}
				}
				else
				{
					// Nothing current should be calling update on events without specifying both
					// start & enddate, but just in case, pull it from existing data.
					if (!isset($data['eventstartdate']))
					{
						$data['eventstartdate'] = $existing['eventstartdate'];
					}

					if (!isset($data['eventenddate']))
					{
						$data['eventenddate'] = $existing['eventenddate'];
					}
				}

				$data['eventstartdate'] = $this->getEndOfDayUnixtime($data['eventstartdate'], false, "12:00:00 AM", $data['ignoredst']);
				$data['eventenddate'] = $this->getEndOfDayUnixtime($data['eventenddate'], false, "11:59:59 PM", $data['ignoredst']);
			}
		}
		else
		{
			// TODO: Remove this, should not be needed any longer and we can't keep supporting
			// legacy input behavior when the overall behavior changed so much. AFAIK only the
			// unit test uses it like this, frontend should always be setting an enddate.
			// Make sure that updating an event from all-day to explicit-end-date is allowed.
			// If they specified an eventenddate, and didn't pass in an allday, it should NOT be
			// an all-day event, even if the enddate did not change from the auto-generated
			// all-day eventenddate.
			if (!isset($data['allday']) AND isset($data['eventenddate']))
			{
				$data['allday'] = false;
			}
		}

		// Run the check A) when adding a new node or B) when updating, only if the field is set.
		// On update, if the field is not set in the incoming data, we won't update it at all
		if (!$existing OR isset($data['eventstartdate']) OR isset($data['eventenddate']))
		{
			// We specifically check eventstartdate and eventenddate together
			// even if only one was set in the incoming data

			if (empty($data['eventstartdate']))
			{
				throw new vB_Exception_Api('event_no_startdate_specified');
			}


			// if eventenddate is not 0, it cannot be earlier than the eventstartdate
			if ($data['eventenddate'] <= $data['eventstartdate'])
			{
				throw new vB_Exception_Api('event_invalid_enddate');
			}

			// eventenddate may not be X later than eventstartdate. event_max_duration min should be 1 (day),
			// so the trivial case of a single day all-day event will pass at all times and doesn't need a specific
			// code to fix the auto-generated event-enddate.
			$vboptions = vB::getDatastore()->getValue('options');
			$maxDurationSeconds = $vboptions['event_max_duration'] * 86400;
			if ($data['eventstartdate'] + $maxDurationSeconds < $data['eventenddate'])
			{
				throw new vB_Exception_Api('event_invalid_enddate_days_x', $vboptions['event_max_duration']);
			}
		}

		return $data;
	}


	public function getIndexableFromNode($content, $include_attachments = true)
	{
		$indexableContent = parent::getIndexableFromNode($content, $include_attachments);

		/*
			Everything but 'title' in this array gets imploded into a string then tokenized by the search core index.
			'title' gets pulled out for its own processing.
			See vB_Search_Core::getTitleAndText()
		 */
		$indexableContent['location'] = '';

		/*
			searh core calls getIndexableContent(), which gets the bare node, then fills $content with the "extra" content table data
			(e.g. text, event, poll, video ...) specified in $this->index_fields
		 */
		if (!empty($content['location']))
		{
			// Per MVP, location should be text-searchable.
			$indexableContent['location'] = $content['location'];
		}

		return $indexableContent;
	}

	public function getQuotes($nodeids)
	{
		//Per Product, we just quote the text content (but this may change in the future)
		//If and when the requirement changes to include the non-text content, don't call the parent method and then implement it here
		return parent::getQuotes($nodeids);
	}

	/**
	 * Merging event types is currently unsupported
	 */
	public function mergeContent($data)
	{
		// parent text has an implementation so we have to define this.
		throw new vB_Exception_Api('merge_invalid_contenttypes');
	}

	/**
	 * Merging event types is currently unsupported
	 */
	public function mergeContentInfo(&$result, $content)
	{
		// parent text has an implementation so we have to define this.
		throw new vB_Exception_Api('merge_invalid_contenttypes');
	}

	//public function incompleteNodeCleanup($node)
	// the parent (Content) implementation takes care of the node record, & everything specified in $this->tablename
	// (text, event). Nothing to do here.
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 102683 $
|| #######################################################################
\*=========================================================================*/
