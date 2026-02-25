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
 * vB_Library_Content_Report
 *
 * @package vBLibrary
 * @access public
 */
class vB_Library_Content_Report extends vB_Library_Content_Text
{
	//override in client- the text name
	protected $contenttype = 'vBForum_Report';

	//The table for the type-specific data.
	protected $tablename = array('report', 'text');

	protected $ReportChannel;

	/**
	 * If true, then creating a node of this content type will increment
	 * the user's post count. If false, it will not. Generally, this should be
	 * true for topic starters and replies, and false for everything else.
	 *
	 * @var	bool
	 */
	protected $includeInUserPostCount = false;

	// Do not send a moderator notification when this contenttype is created
	protected $skipModNotification = true;

	protected function __construct()
	{
		parent::__construct();
		$this->ReportChannel = $this->nodeApi->fetchReportChannel();
	}

	protected function sendPushNotifications($data)
	{
		$reportedNodeid = $data['reportnodeid'];
		// Note: getModeratorRecipients() checks view perms when 2nd param == "fcm"
		$moderators = $this->getModeratorRecipients($reportedNodeid, "fcm");
		$reportedNode = vB_Library::instance('node')->getNode($reportedNodeid, false, true);
		// As we do in $this->add(), assume current user is the reporter.
		$reporterInfo = vB::getCurrentSession()->fetch_userinfo();
		if (empty($reporterInfo['username']))
		{
			// Have not run into this yet, but this is probably the best we can assume
			$reporterInfo['username'] = "Guest";
		}

		// If the reported node is a Visitor Message, it lacks startertitle, and the
		// FCM will need special phrasing.
		$isVM = $this->isVisitorMessage($reportedNodeid);
		$missingData = (
			!$isVM AND empty($reportedNode['startertitle'])
			OR
			$isVM AND (
				empty($reportedNode['authorname']) OR
				empty($reportedNode['setfor'])
			)
		);
		if (empty($moderators) OR $missingData)
		{
			return;
		}

		$recipientsQuery = vB::getDbAssertor()->assertQuery('user',
			array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
				'userid' => $moderators,
				vB_dB_Query::COLUMNS_KEY => array(
					'userid',
					//'username',
					//'notification_options',
					//'email',
					//'emailnotification',
					'languageid'
				)
			)
		);
		$recipientByLanguageid = array();
		foreach ($recipientsQuery AS $__row)
		{
			$__langid = $__row['languageid'];
			$__userid = $__row['userid'];
			if (!isset($recipientByLanguageid[$__langid]))
			{
				$recipientByLanguageid[$__langid] = array();
			}
			$recipientByLanguageid[$__langid][$__userid] = $__userid;
		}

		$phraseApi = vB_Api::instanceInternal('phrase');
		$title = $reporterInfo['username'];

		$clickAction = vB_Library_FCMessaging::CLICK_ACTION_POST;
		$data = array(
			'INTENT_EXTRA_THREAD_ID' => $reportedNode['starter'],
			'INTENT_EXTRA_POST_ID' => $reportedNode['nodeid'],
		);
		if ($isVM)
		{
			$vmWallOwner = vB_User::fetchUserinfo($reportedNode['setfor']);
			$bodyPhraseid = 'fcm_report_visitormessage_x_y';
			$bodyPhraseArgs = array($reportedNode['authorname'], $vmWallOwner['username']);
			$data['INTENT_EXTRA_USERID'] = $reportedNode['setfor'];
			$clickAction = vB_Library_FCMessaging::CLICK_ACTION_VISITORMESSAGE;
		}
		else
		{
			if ($reportedNode['starter'] == $reportedNode['nodeid'])
			{
				$bodyPhraseid = 'fcm_report_topic_x';
			}
			else if ($reportedNode['parentid'] == $reportedNode['starter'])
			{
				$bodyPhraseid = 'fcm_report_reply_x';
			}
			else
			{
				$bodyPhraseid = 'fcm_report_comment_x';
				$clickAction = vB_Library_FCMessaging::CLICK_ACTION_COMMENT;
				$data['INTENT_EXTRA_POST_ID'] = $reportedNode['parentid'];
				$data['INTENT_EXTRA_COMMENT_ID'] = $reportedNode['nodeid'];
			}
			$bodyPhraseArgs = array($reportedNode['startertitle']);
		}

		$fcmLib = vB_Library::instance('FCMessaging');
		$messageHashes = array();
		foreach ($recipientByLanguageid AS $__langid => $__userids)
		{
			$__phrases = $phraseApi->fetch($bodyPhraseid, $__langid);
			$__bodyPhrase = $__phrases[$bodyPhraseid];
			$__renderedBodyPhrase = vsprintf($__bodyPhrase, $bodyPhraseArgs);
			$extra = array(
				'title' => $title,
				'body' => $__renderedBodyPhrase,  // this (username) will be unescaped in the FCM lib
				'click_action' => $clickAction,
				'data' => $data,
			);

			// offload to child task.
			$messageHash = $fcmLib->queueMessage(
				$__userids,
				vB_Library_FCMessaging::MESSAGE_TYPE_NOTIFICATION,
				$extra
			);
			if (empty($messageHash['error']) AND !empty($messageHash['hash']))
			{
				$messageHashes[] = $messageHash['hash'];
			}
		}

		if (!empty($messageHashes))
		{
			$sendMessagesResult = $fcmLib->sendMessages($messageHashes);
		}

		return;
	}

	protected function getModeratorRecipients($reportedNodeid, $type = "email")
	{
		$moderators = array();

		$vboptions = vB::getDatastore()->getValue('options');
		if ($vboptions['rpemail'] == 0)
		{
			// No email recipients.
			return $moderators;
		}

		if (empty($reportedNodeid))
		{
			return $moderators;
		}

		$nodeLib = vB_Library::instance('node');
		$moderatorsArray = $nodeLib->getNodeModerators($reportedNodeid);
		foreach ($moderatorsArray as $moderator)
		{
			$moderators[$moderator['userid']] = $moderator['userid'];
		}

		// 0 == no email, 1 == email moderators, 2 == email moderators, super moderators and administrators
		if ($vboptions['rpemail'] == 2)
		{
			// Fetch admins and super moderators
			$allmoderators = $nodeLib->getForumSupermoderatorsAdmins($moderators);
			foreach ($allmoderators as $moderator)
			{
				$moderators[$moderator['userid']] = $moderator['userid'];
			}
		}

		if ($type == "fcm")
		{
			// TODO: Should we push the view check out to email listing as well?
			$reportedNode = vB_Library::instance('node')->getNode($reportedNodeid, false, true);
			$contentLib = vB_Library_Content::getContentLib($reportedNode['contenttypeid']);

			foreach ($moderators AS $__key => $__userid)
			{
				$__canview = $contentLib->validate(
					$reportedNode,
					vB_Library_Content::ACTION_VIEW,
					$reportedNode['nodeid'],
					array($reportedNode['nodeid'] => $reportedNode),
					$__userid
				);
				if (!$__canview)
				{
					unset($moderators[$__key]);
				}
			}

			/*
				TODO: Do we need a new option for moderator listing for FCM, or can we just keep the
				email (['rpemail'] == 2) rules above?
			 */
		}

		return $moderators;
	}

	/**
	 * 	Adds a new node.
	 *
	 *	@param	mixed		Array of field => value pairs which define the record.
	 *	@param	array		Array of options for the content being created.
	 *						Understands skipTransaction, skipFloodCheck, floodchecktime, skipDupCheck, skipNotification, nl2br, autoparselinks.
	 *							- nl2br: if TRUE, all \n will be converted to <br /> so that it's not removed by the html parser (e.g. comments).
	 *	@param	bool		Convert text to bbcode
	 *
	 * 	@return	mixed		array with nodeid (int), success (bool), cacheEvents (array of strings), nodeVals (array of field => value), attachments (array of attachment records).
	 */
	public function add($data, array $options = array(), $convertWysiwygTextToBbcode = true)
	{
		//Store this so we know whether we should call afterAdd()
		$skipTransaction = !empty($options['skipTransaction']);
		$vboptions = vB::getDatastore()->getValue('options');
		$reportemail = ($vboptions['enableemail'] AND $vboptions['rpemail']);

		$data['reportnodeid'] = intval($data['reportnodeid']);
		// Build node title based on reportnodeid
		if (!$data['reportnodeid'])
		{
			throw new vB_Exception_Api('invalid_report_node');
		}

		$data['parentid'] = $this->ReportChannel;

		if (empty($data['title']))
		{
			$reportnode = $this->nodeApi->getNodeFullContent($data['reportnodeid']);
			$reportnode = $reportnode[$data['reportnodeid']];

			$phraseapi = vB_Api::instanceInternal('phrase');

			if ($reportnode['nodeid'] == $reportnode['starter'])
			{
				// Thread starter
				$data['title'] = $reportnode['title'];
			}
			elseif ($reportnode['parentid'] == $reportnode['starter'])
			{
				$phrases = $phraseapi->fetch(array('reply_to'));
				$data['title'] = $phrases['reply_to'] . ' ' . $reportnode['startertitle'];
			}
			else
			{
				$phrases = $phraseapi->fetch(array('comment_in_a_topic'));
				$data['title'] = $phrases['comment_in_a_topic'] . ' ' . $reportnode['startertitle'];
			}
		}

		$result = parent::add($data, $options, $convertWysiwygTextToBbcode);

		//we don't even set skip transaction or create a transaction so the parent class will call beforeCommit
		//we don't need to call it here.  However I think this means that afterAdd gets called twice, which is
		//not good.
		//$this->beforeCommit($result['nodeid'], $data, $options, $result['cacheEvents'], $result['nodeVals']);

		if (!$skipTransaction)
		{
			//The child classes that have their own transactions all set this to true so afterAdd is always called just once.
			$this->afterAdd($result['nodeid'], $data, $options, $result['cacheEvents'], $result['nodeVals']);
		}

		// 2017-08-11
		// afterAdd() does get called twice, which means if we send FCMs in afterAdd(), they'll go out twice.
		$this->sendPushNotifications($data);

		// send an email
		if ($reportemail)
		{
			$reporterInfo = vB::getCurrentSession()->fetch_userinfo();

			// Get moderators on the reported node
			$moderators = $this->getModeratorRecipients($reportnode['nodeid']);

			// get user info
			$moderatorUsernames = '';
			foreach ($moderators as $moderatorid => $moderator)
			{
				$moderators[$moderatorid] =  vB_Library::instance('user')->fetchUserinfo($moderatorid);
				$moderatorUsernames .= $moderators[$moderatorid]['username'] . ', ';
			}

			// Compose the email
			if ($reportnode['starter'] == $reportnode['nodeid'])
			{

				$maildata = vB_Api::instanceInternal('phrase')->fetchEmailPhrases('reportpost_newthread',
					array(
						$reporterInfo['username'],
						$reporterInfo['email'],
						$reportnode['title'],
						vB5_Route::buildUrl($reportnode['routeid'] . '|fullurl',
							array(
								'nodeid' => $reportnode['starter'],
								'userid' => $reportnode['starteruserid'],
								'username' => $reportnode['starterauthorname'],
								'innerPost' => $reportnode['nodeid'],
								'innerPostParent' => $reportnode['parentid'])
						),
						$data['rawtext'],
					),
					array(vB::getDatastore()->getOption('bbtitle'))
				);
			}
			else
			{
				$maildata = vB_Api::instanceInternal('phrase')->fetchEmailPhrases(
					'reportpost',
					array(
						$reporterInfo['username'],
						$reporterInfo['email'],
						$reportnode['title'],
						vB5_Route::buildUrl($reportnode['routeid'] . '|fullurl',
							array(
								'nodeid' => $reportnode['starter'],
								'userid' => $reportnode['starteruserid'],
								'username' => $reportnode['starterauthorname'],
								'innerPost' => $reportnode['nodeid'],
								'innerPostParent' => $reportnode['parentid'])
						),
						$reportnode['startertitle'],
						vB5_Route::buildUrl($reportnode['routeid'] . '|fullurl', array('nodeid' => $reportnode['starter'], 'title' => $reportnode['startertitle'])),
						$data['rawtext'],
					),
					array(vB::getDatastore()->getOption('bbtitle'))
				);
			}

			// Send out the emails
			foreach ($moderators AS $moderator)
			{
				if (!empty($moderator['email']))
				{
					vB_Mail::vbmail($moderator['email'], $maildata['subject'], $maildata['message'], false);
				}
			}
		}

		return $result;;
	}

	public function getFullContent($nodeid, $permissions = false)
	{
		if (empty($nodeid))
		{
			return array();
		}

		$results = parent::getFullContent($nodeid, $permissions);
		$reportparentnode = array();

		foreach ($results as $key => $result)
		{
			if (empty($results[$key]['reportnodeid']))
			{
				// reported node was deleted.
				$results[$key]['reportnodeid'] = NULL;
				$results[$key]['reportnodetype'] = NULL;
				$results[$key]['reportparentnode'] = NULL;
				$results[$key]['reportnodetitle'] = NULL;
				$results[$key]['reportnoderouteid'] = NULL;
				continue;
			}

			try
			{
				$reportnode = $this->nodeApi->getNodeFullContent($results[$key]['reportnodeid']);
			}
			catch (vB_Exception_NodePermission $e)
			{
				$results[$key]['node_no_permission'] = true;
				continue;
			}

			if ($reportnode[$results[$key]['reportnodeid']]['nodeid'] == $reportnode[$results[$key]['reportnodeid']]['starter'])
			{
				$results[$key]['reportnodetype'] = 'starter';
			}
			elseif ($reportnode[$results[$key]['reportnodeid']]['parentid'] == $reportnode[$results[$key]['reportnodeid']]['starter'])
			{
				$results[$key]['reportnodetype'] = 'reply';

				//fetch parent info of reply (starter)
				$parentid = $reportnode[$results[$key]['reportnodeid']]['parentid'];
				if (!isset($reportparentnode[$parentid]))
				{
					$reportparentnode[$parentid] = $this->nodeApi->getNodeFullContent($parentid);
					$reportparentnode[$parentid] = $reportparentnode[$parentid][$parentid];
				}
				$results[$key]['reportparentnode'] = $reportparentnode[$parentid];
			}
			else
			{
				$results[$key]['reportnodetype'] = 'comment';

				//fetch parent info of comment (reply)
				$parentid = $reportnode[$results[$key]['reportnodeid']]['parentid'];
				if (!isset($reportparentnode[$parentid]))
				{
					$reportparentnode[$parentid] = $this->nodeApi->getNodeFullContent($parentid);
					$reportparentnode[$parentid] = $reportparentnode[$parentid][$parentid];
				}
				$results[$key]['reportparentnode'] = $reportparentnode[$parentid];
			}
			$results[$key]['reportnodetitle'] = $reportnode[$results[$key]['reportnodeid']]['title'];
			$results[$key]['reportnoderouteid'] = $reportnode[$results[$key]['reportnodeid']]['routeid'];
		}

		return $results;
	}

	/**
	 * Report is not allowed to be updated.
	 *
	 * @throws vB_Exception_Api
	 * @param $nodeid
	 * @param $data
	 * @return void
	 */
	public function update($nodeid, $data, $convertWysiwygTextToBbcode = true)
	{
		throw new vB_Exception_Api('not_implemented');
	}

	/**
	 * Open or close reports
	 *
	 * @param array $nodeids Array of node IDs
	 * @param string $op 'open' or 'close'
	 * @return void
	 */
	public function openClose($nodeids, $op)
	{
		if (is_numeric($nodeids))
		{
			$nodeids = array($nodeids);
		}

		if (is_string($nodeids) AND strpos($nodeids, ','))
		{
			$nodeids = explode(',', $nodeids);
		}

		if (!$nodeids OR !is_array($nodeids))
		{
			throw new vB_Exception_Api('invalid_param', array('nodeid'));
		}

		// Not sure why it doesn't work
//		foreach ($nodeids as &$nodeid)
//		{
//			$nodeid = intval($nodeid);
//		}
//
//		$data = array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_UPDATE,
//			vB_dB_Query::CONDITIONS_KEY =>array('nodeid' => $nodeids),
//			'closed' => ($op == 'open'? 0 : 1));
//
//		$this->assertor->assertQuery('vBForum:report', $data);

		foreach ($nodeids as $nodeid)
		{
			$data = array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_UPDATE,
				vB_dB_Query::CONDITIONS_KEY =>array('nodeid' => intval($nodeid)),
				'closed' => ($op == 'open'? 0 : 1));

			$this->assertor->assertQuery('vBForum:report', $data);
		}

		$this->nodeApi->clearCacheEvents($nodeids);
	}

	/**
	 * Delete one or more reports
	 *
	 * @throws vB_Exception_Api
	 * @param $nodeids
	 * @return void
	 */
	public function bulkdelete($nodeids)
	{
		if (is_numeric($nodeids))
		{
			$nodeids = array($nodeids);
		}

		if (is_string($nodeids) AND strpos($nodeids, ','))
		{
			$nodeids = explode(',', $nodeids);
		}

		if (!$nodeids OR !is_array($nodeids))
		{
			throw new vB_Exception_Api('invalid_param', array('nodeid'));
		}

		foreach ($nodeids as $nodeid)
		{
			$this->delete($nodeid);
		}
	}

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

		if (is_null($userid))
		{
			$userid = $currentUserid;
		}
		$userContext = vB::getUserContext($userid);

		//the rules for reports are a little different -- for adding we want to check
		//the permissions on the channel for the node we are reporting the one we
		//are adding to.  For viewing we still want to check the regular way
		//also we are going to skip checks for disabled comments.  That way if the
		//admin disables comments after the fact existing comments can sill be reported.

		if ($action == self::ACTION_ADD)
		{
			if (empty($data['reportnodeid']))
			{
				throw new vB_Exception_Api('invalid_data_w_x_y_z', array($nodeid, 'nodeid', __CLASS__, __FUNCTION__));
			}

			if (!$userid)
			{
				return false;
			}

			if ($userContext->isSuperAdmin())
			{
				return true;
			}

			$reportnodeid = $data['reportnodeid'];
			$reportnode = vB_Library::instance('node')->getNode($reportnodeid);

			//check the showPublished.
			if ($reportnode['showpublished'] == 0)
			{
				if (!$userContext->getChannelPermission('moderatorpermissions', 'canmoderateposts', $reportnodeid))
				{
					return false;
				}
			}

			// Keep below in sync with vB_Library_Content::validate(..., self::ACTION_ADD,...). Look for 'GREPMARK VBV-16643' without quotes
			// in vB_Library_Content.
			//use show open here rather than open because it may be a more distant ancestor that is closed and not just the reportnode.
			//regardless if the reportnode is effectively closed we don't want to allow posting.
			if ($reportnode['showopen'] == 0 AND !$userContext->getChannelPermission('moderatorpermissions', 'canopenclose', $reportnodeid))
			{
				//if the topic is owned by the poster and they can open their own topics then they can post
				$starter = vB_Library::instance('node')->getNode($reportnode['starter']);

				if (!($starter['userid'] == $userid AND $userContext->getChannelPermission('forumpermissions', 'canopenclose', $reportnode['starter'])))
				{
					return false;
				}
			}
			return true;
		}
		else
		{
			return parent::validate($data, $action, $nodeid, $nodes, $userid);
		}
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 102683 $
|| #######################################################################
\*=========================================================================*/
