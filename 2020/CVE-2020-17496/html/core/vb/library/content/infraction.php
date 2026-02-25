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
 * vB_Library_Content_Infraction
 *
 * @package vBLibrary
 * @access public
 */
class vB_Library_Content_Infraction extends vB_Library_Content_Text
{
	//override in client- the text name
	protected $contenttype = 'vBForum_Infraction';

	//The table for the type-specific data.
	protected $tablename = array('infraction', 'text');

	//list of fields that are included in the index
	protected $index_fields = array('note','actionreason', 'customreason');

	protected $infractionChannel;

	protected $nodeLibrary = null;

	protected $cannotDelete = true;

	/**
	 * If true, then creating a node of this content type will increment
	 * the user's post count. If false, it will not. Generally, this should be
	 * true for topic starters and replies, and false for everything else.
	 *
	 * @var	bool
	 */
	protected $includeInUserPostCount = false;

	// Phrases that have been requested from the phrase api
	protected $phrases = array();

	// Do not send a moderator notification when this contenttype is created
	protected $skipModNotification = true;

	/**
	 * Constructor
	 */
	protected function __construct()
	{
		parent::__construct();

		$this->infractionChannel = $this->nodeApi->fetchInfractionChannel();
		$this->nodeLibrary = vB_Library::instance('node');

		// pull phrases for titles & pagetext
		$this->phrases = vB_Api::instanceInternal('phrase')->fetch(array(
			// infraction title
			'infraction_for_x_y',
			'infraction_for_x_y_in_topic_z',
			'warning_for_x_y',
			'warning_for_x_y_in_topic_z',
			// infraction page text
			'infraction_topic_post',
			'infraction_topic_profile',
			// pm title
			'infraction_received_ginfraction',
			'warning_received_ginfraction',
			// pm page text
			'infraction_received_post',
			'infraction_received_profile',
			'warning_received_post',
			'warning_received_profile',
			// automatic ban phrases
			'x_days',
			'x_weeks',
			'x_months',
			'x_years',
			'permanent',
		));
	}

	/*
		Overview of functions in this class:

		add
		update
		delete
		reverseInfraction

		getInfraction
		getNodeInfraction
		getUserInfractions
		getAutomaticBanList
		getInfractionLevels
		buildInfractionGroupIds

		// protected
		getInfractionNode
		validateInfractionData
		getInfractedNode
		getInfractionLevelInfo
		isWarning
		getExpires
		getInfractionTitle
		getInfractionPagetext
		sendPm
		updateDenormalizedUserData
		getPhrase
		fetchInfractionGroups
		getAutomaticBanToApply
		applyAutomaticBan
	*/



	// ========================================================================
	// ===== PUBLIC METHODS ===================================================
	// ========================================================================



	/**
	 * Adds a new infraction node
	 *
	 * @param	mixed		Array of field => value pairs which define the record.
	 * @param	array		Array of options for the content being created
	 * 						Understands skipTransaction, skipFloodCheck, floodchecktime, skipDupCheck, skipNotification, nl2br, autoparselinks.
	 *							- nl2br: if TRUE, all \n will be converted to <br /> so that it's not removed by the html parser (e.g. comments).
	 * 	@return	mixed		array with nodeid (int), success (bool), cacheEvents (array of strings), nodeVals (array of field => value), attachments (array of attachment records).
	 */
	public function add($data, array $options = array(), $convertWysiwygTextToBbcode = true)
	{
		//Store this so we know whether we should call afterAdd()
		$skipTransaction = !empty($options['skipTransaction']);
		$infractionLevels = $this->getInfractionLevels();

		$this->validateInfractionData($data, $infractionLevels);
		//An infraction should never be rejected because of duplication.
		$options['skipDupCheck'] = true;
		$infractedNode = $this->getInfractedNode($data);
		$infractedUserInfo = vB_User::fetchUserinfo($data['infracteduserid']);
		$infractionLevelInfo = $this->getInfractionLevelInfo($data, $infractionLevels);
		$isWarning = $this->isWarning($data, $infractionLevelInfo);
		$banToApply = $this->getAutomaticBanToApply($infractedUserInfo, $data, $infractionLevelInfo, $isWarning);

		// set infraction level info
		$data['points'] = $isWarning ? 0 : $infractionLevelInfo['points'];
		$data['reputation_penalty'] = $isWarning ? 0 : $infractionLevelInfo['reputation_penalty'];
		$data['expires'] = $this->getExpires($infractionLevelInfo, $data['infracteduserid']);
		$data['customreason'] = !empty($data['customreason']) ? $data['customreason'] : '';

		// make sure we have something for admin note and pm message
		$data['note'] = empty($data['note']) ? '' : $data['note'];
		$data['message'] = empty($data['message']) ? '' : $data['message'];

		// set parentid
		$data['parentid'] = $this->infractionChannel;

		// set title & pagetext
		$data['title'] = $this->getInfractionTitle($data, $infractedNode, $infractedUserInfo, $infractionLevelInfo, $isWarning);
		$data['rawtext'] = $this->getInfractionPagetext($data, $infractedNode, $infractedUserInfo, $infractionLevelInfo);
		try
		{
			if (!$skipTransaction)
			{
				$this->assertor->beginTransaction();
			}
			$options['skipTransaction'] = true;

			// *** add the infraction and populate the return info***
			$result = parent::add($data, $options, $convertWysiwygTextToBbcode);
			$result['infractionNodeid'] = $result['nodeid'];
			$result['isWarning'] = $isWarning ? 1 : 0;

			// applying the reputation penalty
			if ($data['reputation_penalty'])
			{
				$this->assertor->assertQuery('decUserReputation', array('penalty' => $data['reputation_penalty'], 'userid' => $infractedUserInfo['userid']));
				vB_Cache::allCacheEvent('userChg_' . $infractedUserInfo['userid']);
			}
			// invalidate cache
			$clearCacheNodeIds = array($data['parentid']);

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

		// update denormalized values
		if (empty($result['errors']))
		{
			if ($data['infractednodeid'])
			{
				// mark the infracted node's text record as having an infraction or warning
				// 1 = infraction, 2 = warning, 0 = no infraction or warning (or an expired/reversed infraction)
				$this->assertor->update('vBforum:text', array('infraction' => ($isWarning ? 2 : 1)), array('nodeid' => $data['infractednodeid']));
			}

			// update user info for infractions, warnings, and ipoints
			$this->updateDenormalizedUserData($data['infracteduserid']);

			// update infractiongroupids
			$this->buildInfractionGroupIds(array($infractedUserInfo['userid']));

			// send PM to infracted user
			if (!empty($data['message']))
			{
				$this->sendPm($data, $infractedNode, $infractedUserInfo, $infractionLevelInfo, $isWarning, $banToApply);
			}
			$clearCacheNodeIds[] = $result['nodeid'];
			$clearCacheNodeIds[] = $data['infractednodeid'];
		}

		// ban user if applicable
		if ($banToApply)
		{
			$this->applyAutomaticBan($infractedUserInfo, $banToApply, $data);
		}
		$this->nodeApi->clearCacheEvents($clearCacheNodeIds);
		return $result;
	}

	/**
	 * Cannot update an infraction (you can only reverse them)
	 *
	 * @throws vB_Exception_Api
	 * @param $nodeid
	 * @param $data
	 * @return void
	 */
	public function update($nodeid, $data, $convertWysiwygTextToBbcode = true)
	{
		throw new vB_Exception_Api('action_not_available');
	}

	/**
	 * Deletes an infraction. Currently the only UI for this is in the Admin CP
	 *
	 * @param $nodeid
	 *
	 * @return void
	 */
	public function delete($nodeid)
	{
		throw new vB_Exception_Api('cannot_delete_infraction_nodes');

		/*
		$infraction = $this->assertor->getRow('infraction', array('nodeid' => $nodeid));

		$returnValue = parent::delete($nodeid);

		if ($infraction)
		{
			// don't mark the infracted node's text record, because it's already deleted

			// update user info for infractions, warnings, and ipoints
			$this->updateDenormalizedUserData($infraction['infracteduserid']);

			// update infractiongroupids
			$this->buildInfractionGroupIds(array($infraction['infracteduserid']));
		}

		return $returnValue;
		*/
	}

	/**
	 * Reverse an infraction
	 *
	 * @param	int	The infraction nodeid
	 * @param	string	Reason for the reversal
	 */
	public function reverseInfraction($nodeid, $reason)
	{
		$user = vB::getCurrentSession()->fetch_userinfo();

		$data = array(
			'action' => 2,
			'actiondateline' => vB::getRequest()->getTimeNow(),
			'actionuserid' => $user['userid'],
			'actionreason' => $reason,
		);

		$ret = $this->assertor->update('infraction', $data, array('nodeid' => $nodeid));

		$clearCacheNodeIds = array();
		$clearCacheNodeIds[] = $nodeid;

		$infraction = $this->assertor->getRow('infraction', array('nodeid' => $nodeid));
		if ($infraction)
		{
			if ($infraction['infractednodeid'])
			{
				// mark the infracted node's text record as not having an infraction any more
				// 1 = infraction, 2 = warning, 0 = no infraction or warning (or an expired/reversed infraction)
				$this->assertor->update('vBforum:text', array('infraction' => 0), array('nodeid' => $infraction['infractednodeid']));

				$clearCacheNodeIds[] = $infraction['infractednodeid'];
			}
			// revert the reputation penalty
			if ($infraction['reputation_penalty'])
			{
				$this->assertor->assertQuery('incUserReputation', array('bonus' => $infraction['reputation_penalty'], 'userid' => $infraction['infracteduserid']));
				vB_Cache::allCacheEvent('userChg_' . $infraction['infracteduserid']);
			}

			// update user info for infractions, warnings, and ipoints
			$this->updateDenormalizedUserData($infraction['infracteduserid']);

			// update infractiongroupids
			$this->buildInfractionGroupIds(array($infraction['infracteduserid']));
		}

		// invalidate cache
		$this->nodeApi->clearCacheEvents($clearCacheNodeIds);

		return $ret;
	}

	/**
	 * Returns an infraction node based on its nodeid
	 *
	 * @param	int	Node ID
	 *
	 * @return	(array|false)	Array of infraction info, or false
	 */
	public function getInfraction($nodeid)
	{
		$nodeid = (int) $nodeid;

		$infraction = $this->assertor->getRow('infraction', array('nodeid' => $nodeid));

		if (!$infraction OR !$infraction['nodeid'])
		{
			return false;
		}

		return $this->getInfractionNode($infraction['nodeid']);
	}

	/**
	 * Returns the infraction node for the given node (if it has an infraction)
	 *
	 * @param	int	Node ID
	 *
	 * @return	(array|false)	Array of infraction info, or false if there is no infraction
	 */
	public function getNodeInfraction($nodeid)
	{
		$nodeid = (int) $nodeid;

		// return only one row, the newest added infraction (there may be previous
		// reversed or expired infractions on this node)
		$infraction = $this->assertor->getRow('infraction', array('infractednodeid' => $nodeid), array(
			'field' => 'nodeid',
			'direction' => vB_dB_Query::SORT_DESC,
		));

		if (!$infraction OR !$infraction['nodeid'])
		{
			return false;
		}

		return $this->getInfractionNode($infraction['nodeid']);
	}

	/**
	 * Returns the infraction nodes for infractions that the given user has received.
	 *
	 * @param	int	User ID
	 * @param	int	Offset to start returning records from
	 * @param	int	Limit - the max number of records to return
	 *
	 * @return	(array|false)	Array of infraction info, or false if there are no infractions
	 */
	public function getUserInfractions($userid, $offset = 0, $limit = 20)
	{
		$userid = (int) $userid;

		// we need to pull all records to properly calculate the stats (total points, etc.)
		$infractions = $this->assertor->getRows('getUserInfractions', array('infracteduserid' => $userid));

		if (!$infractions)
		{
			return false;
		}

		$infractionCount = count($infractions);

		$offset = max(intval($offset), 0);
		$offset = $offset >= $infractionCount ? $infractionCount - 1 : $offset;

		$limit = max(intval($limit), 1);
		$limit = $limit > 100 ? 100 : $limit; // can't return more than 100 records for now

		// calculate statistics
		$statistics = array(
			'total_records'      => $infractionCount, // total number of infraction/warning records for this user
			'records_returned'   => null,             // total number of records returned
			'records_offset'     => $offset,          // offset of the first record returned
			'total'              => 0,                // total active and expired infractions
			'active'             => 0,                // total active infractions
			'points'             => 0,                // total points of active infractions
			'total_penalty'      => 0,                // total reputation penalties
			'warnings'           => 0,                // total active warnings
			'total_infractions'  => 0,                // total active, expired and reversed infractions
			'total_warnings'     => 0,                // total active, expired and reversed warnings
		);

		// calculate pagination counts
		$totalPages = 1;
		if ($infractionCount > 0)
		{
			$totalPages = ceil($infractionCount / $limit);
		}

		if ($offset < $limit)
		{
			$pagenum = 1;
		}
		else
		{
			$pagenum = ceil(($offset + 1) / $limit);
		}

		$pagination = array(
			'page'			=> $pagenum,
			'totalcount'	=> $infractionCount,
			'totalpages'	=> $totalPages,
			'perpage'		=> $limit,
		);

		foreach ($infractions AS $infraction)
		{
			if ($infraction['action'] != 2) //exclude reversed infractions/warnings
			{
				if ($infraction['points'] == 0)
				{
					if ($infraction['action'] == 0) //count active warnings only
					{
						++$statistics['warnings'];
					}
				}
				else
				{
					++$statistics['total'];
					if ($infraction['action'] == 0) //count active infractions only
					{
						++$statistics['active'];
						$statistics['points'] += $infraction['points'];
					}
				}
				$statistics['total_penalty'] += $infraction['reputation_penalty'];
			}

			if ($infraction['points'] == 0)
			{
				++$statistics['total_warnings'];
			}
			else
			{
				++$statistics['total_infractions'];
			}
		}

		// limit results
		$infractions = array_slice($infractions, $offset, $limit);
		$statistics['records_returned'] = count($infractions);

		// get infraction nodes
		$infractionNodes = array();
		foreach ($infractions AS $infraction)
		{
			$infractionNodes[$infraction['nodeid']] = $this->getInfractionNode($infraction['nodeid'], true);
		}

		return array(
			'statistics' => $statistics,
			'infractions' => $infractionNodes,
			'pagination' => $pagination,
		);
	}

	/**
	 * Returns the usernames of those users that participated in an infraction conversation.
	 *
	 * @param	array	node IDs
	 *
	 * @return	(array) usernames
	 * first level key is the nodeid, second level key is the userid
	 */
	public function getParticipants($nodeids)
	{
		//added conditional block to prevent database query if no nodeids meet the canViewInfraction() permissions check from core\vb\api\content\infraction.php -> getParticipants()
		if (empty($nodeids)){
			return array();
		}
		else{
			$children = $this->assertor->assertQuery('vBForum:getChildren', array('nodeid' => $nodeids));

			if (!$children->valid())
			{
				return array();
			}

			$userids = array();
			foreach ($children as $child)
			{
				$userids[] = $child['userid'];
			}
			$usernames = $this->assertor->getColumn('user', 'username', array('userid' => $userids), false, 'userid');
			$participants = array();
			foreach ($children as $child)
			{
	// 			if (isset($participants[$child['parent']][$child['userid']]))
	// 			{
	// 				continue;
	// 			}
				$participants[$child['parent']][$child['userid']] = $usernames[$child['userid']];
			}
			return $participants;
		}
	}

	/**
	 * returns a certain type of infractions
	 * @param string $type
	 * @param boolean $replied_by_me - if true, only infractions that the user commented on
	 * type = 'user' => infractions given to a user
	 * type = 'post' => infractions given to a post by a user
	 */
	public function getInfractionsByType($type = '', $replied_by_me = false)
	{
		return $this->assertor->getRows('getInfractionsByType', array(
					'type' => $type,
					'replied_by_me' => $replied_by_me,
					'userid' => vB::getCurrentSession()->get('userid')
				)
				, false, 'nodeid');
	}


	/**
	 * Returns a list of automatic bans or an empty array if there are none.
	 *
	 * @return	array	Array of automatic bans
	 */
	public function getAutomaticBanList()
	{
		$automaticBans = vB::getDbAssertor()->getRows(
			'infractionban',
			array(
					vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT
			),
			array(
					'field' => array('method', 'amount'),
					'direction' => array(vB_dB_Query::SORT_ASC, vB_dB_Query::SORT_ASC)
			),
			'infractionbanid'
		);

		if (!$automaticBans)
		{
			return array();
		}

		foreach ($automaticBans AS &$automaticBan)
		{
			// add phrase to describe the "period" and calculate liftdate.
			switch($automaticBan['period'])
			{
				case 'D_1':
					$period = construct_phrase($this->getPhrase('x_days'), 1);
					$liftdate = 86400 * 1;
					break;

				case 'D_2':
					$period = construct_phrase($this->getPhrase('x_days'), 2);
					$liftdate = 86400 * 2;
					break;

				case 'D_3':
					$period = construct_phrase($this->getPhrase('x_days'), 3);
					$liftdate = 86400 * 3;
					break;

				case 'D_4':
					$period = construct_phrase($this->getPhrase('x_days'), 4);
					$liftdate = 86400 * 4;
					break;

				case 'D_5':
					$period = construct_phrase($this->getPhrase('x_days'), 5);
					$liftdate = 86400 * 5;
					break;

				case 'D_6':
					$period = construct_phrase($this->getPhrase('x_days'), 6);
					$liftdate = 86400 * 6;
					break;

				case 'D_7':
					$period = construct_phrase($this->getPhrase('x_days'), 7);
					$liftdate = 86400 * 7;
					break;

				case 'D_10':
					$period = construct_phrase($this->getPhrase('x_days'), 10);
					$liftdate = 86400 * 10;
					break;

				case 'D_14':
					$period = construct_phrase($this->getPhrase('x_weeks'), 2);
					$liftdate = 86400 * 14;
					break;

				case 'D_21':
					$period = construct_phrase($this->getPhrase('x_weeks'), 3);
					$liftdate = 86400 * 21;
					break;

				case 'M_1':
					$period = construct_phrase($this->getPhrase('x_months'), 1);
					$liftdate = 86400 * 30;
					break;

				case 'M_2':
					$period = construct_phrase($this->getPhrase('x_months'), 2);
					$liftdate = 86400 * 30 * 2;
					break;

				case 'M_3':
					$period = construct_phrase($this->getPhrase('x_months'), 3);
					$liftdate = 86400 * 30 * 3;
					break;

				case 'M_4':
					$period = construct_phrase($this->getPhrase('x_months'), 4);
					$liftdate = 86400 * 30 * 4;
					break;

				case 'M_5':
					$period = construct_phrase($this->getPhrase('x_months'), 5);
					$liftdate = 86400 * 30 * 5;
					break;

				case 'M_6':
					$period = construct_phrase($this->getPhrase('x_months'), 6);
					$liftdate = 86400 * 30 * 6;
					break;

				case 'Y_1':
					$period = construct_phrase($this->getPhrase('x_years'), 1);
					$liftdate = 86400 * 365;
					break;

				case 'Y_2':
					$period = construct_phrase($this->getPhrase('x_years'), 2);
					$liftdate = 86400 * 365 * 2;
					break;

				case 'PERMA':
					$period = $this->getPhrase('permanent');
					$liftdate = 0;
					break;

				default:
					$period = '';
					$liftdate = 0;
					break;
			}

			$automaticBan['period_phrase'] = $period;

			//if this isn't a permaban then the $liftdate is the number of seconds to add to now
			if ($liftdate > 0)
			{
				$liftdate += vB::getRequest()->getTimeNow();
			}

			$automaticBan['liftdate'] =  $liftdate;
		}

		return $automaticBans;
	}

	/**
	 * Returns an array of information for the infraction levels that are currently set up
	 *
	 * @return	array	Infraction levels
	 */
	public function getInfractionLevels()
	{
		// get infraction levels
		$infractionLevels = $this->assertor->getRows('infractionlevel');

		// get phrases for infraction level titles
		$phraseVarNames = array();
		foreach ($infractionLevels AS $infractionLevel)
		{
			$phraseVarNames[] = 'infractionlevel' . $infractionLevel['infractionlevelid'] . '_title';
		}
		$vbphrase = vB_Api::instanceInternal('phrase')->fetch($phraseVarNames);

		// add the title
		foreach ($infractionLevels AS $key => $infractionLevel)
		{
			$phraseVarName = 'infractionlevel' . $infractionLevel['infractionlevelid'] . '_title';
			$infractionLevels[$key]['title'] = isset($vbphrase[$phraseVarName]) ? $vbphrase[$phraseVarName] : "~~$phraseVarName~~";
		}

		// index the array
		$infractionLevelsIndexed = array();
		foreach ($infractionLevels AS $infractionLevel)
		{
			$infractionLevelsIndexed[$infractionLevel['infractionlevelid']] = $infractionLevel;
		}

		// done
		return $infractionLevelsIndexed;
	}

	/**
	 * gets the infraction groups
	 * @return array infraction groups with infractiongroupid as key >
	 */
	public function getInfractionGroups()
	{
		$usergroups = vB_Api::instanceInternal('usergroup')->fetchUsergroupList();
		$infractiongroups = $this->assertor->assertQuery('infractiongroup', array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
		), 'pointlevel');
		$groups = array();
		foreach ($infractiongroups as $infractiongroup)
		{
			$infractiongroup['usergroup'] = $usergroups[$infractiongroup['usergroupid']];
			$groups[$infractiongroup['infractiongroupid']] = $infractiongroup;
		}
		return $groups;
	}

	/**
	 * Takes valid data and sets it as part of the data to be saved
	 *
	 * @param	array		List of infraction groups
	 * @param integer  Userid of user
	 * @param	integer	Infraction Points
	 * @param interger Usergroupid
	 *
	 * @return array	User's final infraction groups
	 */
	public function fetchInfractionGroups(&$infractiongroups, $userid, $ipoints, $usergroupid)
	{
		static $cache = array();
		$data = array();

		$infractiongroupids = array();

		if (!empty($infractiongroups["$usergroupid"]))
		{
			foreach($infractiongroups["$usergroupid"] AS $pointlevel => $orusergroupids)
			{
				if ($pointlevel <= $ipoints)
				{
					foreach($orusergroupids AS $infinfo)
					{
						$data['infractiongroupids']["$infinfo[orusergroupid]"] = $infinfo['orusergroupid'];
						if ($infinfo['override'] AND $cache["$userid"]['pointlevel'] <= $pointlevel)
						{
							$cache["$userid"]['pointlevel'] = $pointlevel;
							$cache["$userid"]['infractiongroupid'] = $infinfo['orusergroupid'];
						}
					}
				}
				else
				{
					break;
				}
			}
		}

		if (!isset($data['infractiongroupids']) OR !is_array($data['infractiongroupids']))
		{
			$data['infractiongroupids'] = array();
		}

		if ($usergroupid != -1)
		{
			$temp = $this->fetchInfractionGroups($infractiongroups, $userid, $ipoints, -1);
			$data['infractiongroupids'] = array_merge($data['infractiongroupids'], $temp['infractiongroupids']);
		}

		if (!is_array($data['infractiongroupids']))
		{
			$data['infractiongroupids'] = array();
		}

		if (isset($cache["$userid"]))
		{
			$data['infractiongroupid'] = intval($cache["$userid"]['infractiongroupid']);
		}
		else
		{
			// We don't have any infraction groups so there's no infractiongroupid to set.
			$data['infractiongroupid'] = 0;
		}

		return $data;
	}


	public function getIndexableFromNode($content, $include_attachments = true)
	{
		$indexableContent = parent::getIndexableFromNode($content, $include_attachments);

		if (empty($content['note']))
		{
			$indexableContent['note'] = $content['note'];
		}

		if (empty($content['actionreason']))
		{
			$indexableContent['actionreason'] = $content['actionreason'];
		}

		if (empty($content['customreason']))
		{
			$indexableContent['customreason'] = $content['customreason'];
		}

		return $indexableContent;
	}

	// ========================================================================
	// ===== PROTECTED METHODS ================================================
	// ========================================================================



	/**
	 * Returns the full node information for an infraction node. Used by getUserInfractions and getNodeInfraction
	 *
	 * @param	int	Infraction node ID
	 * @param	bool	Whether on not to include the full node record for the infracted node.
	 *
	 * @return	(array|false)	Array of node information or false on failure
	 */
	protected function getInfractionNode($nodeid, $includeInfractedNodeInfo = false)
	{
		static $infractionLevels = null;

		if ($infractionLevels === null)
		{
			$infractionLevels = $this->getInfractionLevels();
		}

		// get infraction node
		$infractionNode = $this->nodeLibrary->getNodeFullContent($nodeid);
		if (!$infractionNode OR empty($infractionNode[$nodeid]))
		{
			return false;
		}
		$infractionNode = $infractionNode[$nodeid];

		// add infraction level information
		if ($infractionNode['infractionlevelid'])
		{
			$infractionNode['infractionlevel'] = $infractionLevels[$infractionNode['infractionlevelid']];
		}
		else
		{
			$infractionNode['infractionlevel'] = false; // custom infraction
		}

		if ($includeInfractedNodeInfo AND $infractionNode['infractednodeid'] > 0)
		{
			// add info about the infracted node
			$infractionNode['infracted_node'] = $this->nodeLibrary->getNodeFullContent($infractionNode['infractednodeid']);
			$infractionNode['infracted_node'] = $infractionNode['infracted_node'][$infractionNode['infractednodeid']];
		}

		return $infractionNode;
	}

	/**
	 * Validates infraction data
	 *
	 * @param	array	The infraction data
	 * @param	array	The infraction levels
	 */
	protected function validateInfractionData(array $data, array $infractionLevels)
	{
		// we need either an infractionlevelid or it's a custom infraction
		if (empty($data['infractionlevelid']))
		{
			// customreason is required
			if (empty($data['customreason']))
			{
				throw new vB_Exception_Api('invalid_custom_infraction_description');
			}

			// points is not required (0 points is a warning)
			// expires is required, unless period is 'N', which means it never expires
			if (
				empty($data['expires'])
				AND
				(empty($data['period']) OR $data['period'] != 'N')
			)
			{
				throw new vB_Exception_Api('invalid_timeframe');
			}
		}

		$vboptions = vB::getDatastore()->getValue('options');
		if ($vboptions['uimessage'] AND empty($data['message']))
		{
			throw new vB_Exception_Api('no_pm_message_specified');
		}

		if (empty($data['infracteduserid']))
		{
			throw new vB_Exception_Api('no_user_specified');
		}

		if (!empty($data['infractionlevelid']) AND !isset($infractionLevels[$data['infractionlevelid']]))
		{
			throw new vB_Exception_Api('invalid_infraction_level');
		}
	}

	/**
	 * Returns the (to be) infracted node information
	 *
	 * @param	(array|null)	The infraction data or null if we are doing a profile/user infraction.
	 */
	protected function getInfractedNode(array $data)
	{
		if (!empty($data['infractednodeid']))
		{
			if ($data['infractednodeid'] < 1)
			{
				throw new vB_Exception_Api('invalid_node');
			}

			$infractedNode = $this->nodeLibrary->getNodeFullContent($data['infractednodeid']);
			$infractedNode = $infractedNode[$data['infractednodeid']];

			if (empty($infractedNode))
			{
				throw new vB_Exception_Api('invalid_node');
			}
		}
		else
		{
			$infractedNode = array();
		}

		return $infractedNode;
	}

	/**
	 * Returns the infraction level information for this infraction (can be a custom infraction level)
	 *
	 * @param	array	The infraction level information.
	 */
	protected function getInfractionLevelInfo(array $data, array $infractionLevels)
	{
		if (!empty($data['infractionlevelid']))
		{
			// pre-defined infraction
			return $infractionLevels[$data['infractionlevelid']];
		}
		else
		{
			// custom infraction
			return array(
				'points' => $data['points'],
				'reputation_penalty' => $data['reputation_penalty'],
				'expires' => $data['expires'],
				'period' => $data['period'],
				'title' => $data['customreason'],
				'warning' => 1, // allow it to be a warning
				'extend' => 0,  // don't allow it to extend another infraction
			);
		}
	}

	/**
	 * Determines whether or not the infraction will be a warning or an infraction
	 *
	 * @param	array	The infraction data
	 * @param	array	The infraction level info for this infraction
	 *
	 * @return	bool	True if it will be a warning, false for an infraction
	 */
	protected function isWarning(array $data, array $infractionLevelInfo)
	{
		if (empty($data['infractionlevelid']))
		{
			// custom infraction with no points is a warning
			return empty($data['points']);
		}
		else
		{
			// pre-defined infraction
			return (
				// allows warnings
				$infractionLevelInfo['warning']
				// the "warning" checkbox is checked
				AND !empty($data['warning'][$data['infractionlevelid']])
			);
		}
	}

	/**
	 * Get the expires timestamp for the infraction
	 *
	 * @param	array	The information for this infraction level (or custom infraction as it may be)
	 * @param	int	The userid for the infracted user
	 * @return	int	The expires timestamp
	 */
	protected function getExpires(array $infractionLevelInfo, $userid)
	{
		if ($infractionLevelInfo['period'] == 'N')
		{
			return 0;
		}

		$periodMultipliers = array(
			'H' => 3600,
			'D' => 86400,
			'W' => 86400 * 7,
			'M' => 86400 * 30,
		);

		if (!in_array($infractionLevelInfo['period'], array_keys($periodMultipliers), true))
		{
			$infractionLevelInfo['period'] = 'H';
		}

		$timenow = vB::getRequest()->getTimeNow();
		$periodMultiplier = $periodMultipliers[$infractionLevelInfo['period']];
		$expires = $timenow + ($infractionLevelInfo['expires'] * $periodMultiplier);

		// Extend a previous infraction time if applicable
		if (!empty($infractionLevelInfo['infractionlevelid']) AND $infractionLevelInfo['extend'])
		{
			$infractions = $this->assertor->getRows('infraction', array(
				vB_dB_Query::CONDITIONS_KEY =>array(
					array('field' => 'infracteduserid', 'value' => $userid, 'operator' => vB_dB_Query::OPERATOR_EQ),
					array('field' => 'action', 'value' => 0, 'operator' => vB_dB_Query::OPERATOR_EQ),
					array('field' => 'expires', 'value' => $timenow, 'operator' => vB_dB_Query::OPERATOR_GT),
					array('field' => 'infractionlevelid', 'value' => $infractionLevelInfo['infractionlevelid'], 'operator' => vB_dB_Query::OPERATOR_EQ),
				),
			));

			foreach ($infractions AS $infraction)
			{
				// add any remaining time for previous infractions of the same infraction level
				$expires += ($infraction['expires'] - $timenow);
			}
		}

		return $expires;
	}

	/**
	 * Get the title for the infraction node
	 *
	 * @param	array	The infraction data
	 * @param	array	The (to be) infracted node information
	 * @param	array	The (to be) infracted user information
	 * @param	array	The information for this infraction level (or custom infraction as it may be)
	 * @param	bool	Whether or not this is a warning
	 *
	 * @return	string	The title for the infraction node
	 */
	protected function getInfractionTitle(array $data, array $infractedNode, array $infractedUserInfo, array $infractionLevelInfo, $isWarning)
	{
		if ($data['infractednodeid'])
		{
			if ($infractedNode['nodeid'] == $infractedNode['starter'])
			{
				$infractedNodeTitle = $infractedNode['title'];
			}
			else
			{
				$infractedNodeTitle = $infractedNode['startertitle'];
			}

			if ($isWarning)
			{
				return sprintf($this->getPhrase('warning_for_x_y_in_topic_z'), $infractedUserInfo['username'], $infractionLevelInfo['title'], $infractedNodeTitle);
			}
			else
			{
				return sprintf($this->getPhrase('infraction_for_x_y_in_topic_z'), $infractedUserInfo['username'], $infractionLevelInfo['title'], $infractedNodeTitle);
			}
		}
		else
		{
			if ($isWarning)
			{
				return sprintf($this->getPhrase('warning_for_x_y'), $infractedUserInfo['username'], $infractionLevelInfo['title']);
			}
			else
			{
				return sprintf($this->getPhrase('infraction_for_x_y'), $infractedUserInfo['username'], $infractionLevelInfo['title']);
			}
		}
	}

	/**
	 * Get pagetext for the infraction node
	 *
	 * @param	array	The infraction data
	 * @param	array	The (to be) infracted node information
	 * @param	array	The (to be) infracted user information
	 * @param	array	The information for this infraction level (or custom infraction as it may be)
	 *
	 * @return	string	The page text for the infraction node
	 */
	protected function getInfractionPagetext(array $data, array $infractedNode, array $infractedUserInfo, array $infractionLevelInfo)
	{
		// set pagetext
		if ($data['infractednodeid'])
		{
			// post infraction
			return sprintf(
				$this->getPhrase('infraction_topic_post'),
				// link to infracted node
				vB5_Route::buildUrl($infractedNode['routeid'] . '|fullurl', array('nodeid' => $infractedNode['nodeid'], 'title' => $infractedNode['title']), array('p' => $infractedNode['nodeid'])) . '#post' . $infractedNode['nodeid'],
				// infracted topic title
				($infractedNode['nodeid'] == $infractedNode['starter'] ? $infractedNode['title'] : $infractedNode['startertitle']),
				// infracted user link
				vB5_Route::buildUrl('profile|fullurl', array('userid' => $infractedUserInfo['userid'])),
				// infracted user name
				$infractedUserInfo['username'],
				// infraction title
				$infractionLevelInfo['title'],
				// infraction points
				$infractionLevelInfo['points'],
				// administrative note
				$data['note'],
				// message to user
				$data['message'],
				// original post (infracted node)
				$infractedNode['rawtext'],
				// reputation penalty
				$infractionLevelInfo['reputation_penalty']
			);
		}
		else
		{
			// profile infraction
			return sprintf(
				$this->getPhrase('infraction_topic_profile'),
				// infracted user link
				vB5_Route::buildUrl('profile|fullurl', array('userid' => $infractedUserInfo['userid'])),
				// infracted user name
				$infractedUserInfo['username'],
				// infraction title
				$infractionLevelInfo['title'],
				// infraction points
				$infractionLevelInfo['points'],
				// administrative note
				$data['note'],
				// message to user
				$data['message'],
				// reputation penalty
				$infractionLevelInfo['reputation_penalty']
			);
		}
	}

	/**
	 * Sends a PM to the infracted user
	 *
	 * @param	array	The infraction data
	 * @param	array	The (to be) infracted node information
	 * @param	array	The (to be) infracted user information
	 * @param	array	The information for this infraction level (or custom infraction as it may be)
	 * @param	bool	Whether or not this is a warning
	 * @param	mixed	if is an array the user will be banned if is false user won't be banned with this infraction, used to determine to send pm or email
	 *
	 * @return	(int|array)	The nodeid for the PM, or an array of information on error
	 */
	protected function sendPm(array $data, array $infractedNode, array $infractedUserInfo, array $infractionLevelInfo, $isWarning, $banToApply)
	{
		$vboptions = vB::getDatastore()->getValue('options');

		$pmData = array(
			'sentto' => array($data['infracteduserid']), 'sender' => vB::getCurrentSession()->get('userid')
		);

		// set PM title
		$pmData['title'] = sprintf($this->getPhrase(($isWarning ? 'warning' : 'infraction') . '_received_ginfraction'), $infractionLevelInfo['title']);

		// set PM text
		if ($data['infractednodeid'])
		{
			if ($isWarning)
			{
				// post warning
				$pmData['rawtext'] = sprintf(
					$this->getPhrase('warning_received_post'),
					$infractedUserInfo['username'],
					$vboptions['bbtitle'],
					$infractionLevelInfo['title'],
					$data['message'],
					vB5_Route::buildUrl($infractedNode['routeid'] . '|fullurl', array('nodeid' => $infractedNode['nodeid'], 'title' => $infractedNode['title']), array('p' => $infractedNode['nodeid'])) . '#post' . $infractedNode['nodeid'],
					($infractedNode['pagetext'] ? $infractedNode['pagetext'] : $infractedNode['rawtext'])
				);
			}
			else
			{
				// post infraction
				$pmData['rawtext'] = sprintf(
					$this->getPhrase('infraction_received_post'),
					$infractedUserInfo['username'],
					$vboptions['bbtitle'],
					$infractionLevelInfo['title'],
					$data['message'],
					$infractionLevelInfo['points'],
					vB5_Route::buildUrl($infractedNode['routeid'] . '|fullurl', array('nodeid' => $infractedNode['nodeid'], 'title' => $infractedNode['title']), array('p' => $infractedNode['nodeid'])) . '#post' . $infractedNode['nodeid'],
					($infractedNode['pagetext'] ? $infractedNode['pagetext'] : $infractedNode['rawtext']),
					$infractionLevelInfo['reputation_penalty']
				);
			}
		}
		else
		{
			if ($isWarning)
			{
				// profile warning
				$pmData['rawtext'] = sprintf(
					$this->getPhrase('warning_received_profile'),
					$infractedUserInfo['username'],
					$vboptions['bbtitle'],
					$infractionLevelInfo['title'],
					$data['message']
				);
			}
			else
			{
				// profile infraction
				$pmData['rawtext'] = sprintf(
					$this->getPhrase('infraction_received_profile'),
					$infractedUserInfo['username'],
					$vboptions['bbtitle'],
					$infractionLevelInfo['title'],
					$data['message'],
					$infractionLevelInfo['points'],
					$infractionLevelInfo['reputation_penalty']
				);
			}
		}

		$currentBan = $this->assertor->getRow('userban', array('userid' => $infractedUserInfo['userid']));

		if (// they currently have a permanent ban, so don't notify them at all
			($currentBan AND $currentBan['liftdate'] == 0)
			OR
			// they are going to receive a permanent ban, don't notify them
			(is_array($banToApply) AND isset($banToApply['liftdate']) AND $banToApply['liftdate'] == 0)
		)
		{
			return false;
		}

		if ($vboptions['enablepms'] AND vB::getUserContext($infractedUserInfo['userid'])->getUsergroupLimit('pmquota'))
		{
			vB_Library::instance('Content_Privatemessage')->add($pmData, array('skipDupCheck' => true));
		}

		if ($vboptions['enableemail'])
		{
			vB_Mail::vbmail($infractedUserInfo['email'], $pmData['title'], $pmData['rawtext'], true);
		}

		return true;
	}

	/**
	 * Updates the user record with infractions, warnings, and ipoints
	 *
	 * @param	int	User id
	 */
	protected function updateDenormalizedUserData($userid)
	{
		$userInfractions = $this->getUserInfractions($userid, 0, 1);

		$data = array(
			'infractions' => ($userInfractions ? intval($userInfractions['statistics']['total_infractions']) : 0),
			'warnings'    => ($userInfractions ? intval($userInfractions['statistics']['total_warnings']) : 0),
			'ipoints'     => ($userInfractions ? intval($userInfractions['statistics']['points']) : 0),
		);

		$conditions = array('userid' => $userid);

		$changed = $this->assertor->update('user', $data, $conditions);

		vB_Cache::allCacheEvent('userChg_' . $userid);

		return ($changed == 1);
	}

	/**
	 * Get a phrase
	 *
	 * @param	string	The varname of the phrase
	 *
	 * @return	string	The phrase
	 */
	protected function getPhrase($varname)
	{
		return isset($this->phrases[$varname]) ? $this->phrases[$varname] : '~~' . $varname . '~~';
	}

	/**
	 * Builds infraction groups for users. Also called from the cron script
	 *
	 * @param	array	User IDs to build
	 *
	 */
	public function buildInfractionGroupIds(array $userids)
	{
		static $infractiongroups = array();
		static $beenhere = false;

		if (!$beenhere)
		{
			$beenhere = true;

			$groups = $this->assertor->assertQuery('infractiongroup', array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
			), 'pointlevel');

			if ($groups->valid())
			{
				$group = $groups->current();
				while ($groups->valid())
				{
					$infractiongroups["$group[usergroupid]"]["$group[pointlevel]"][] = array(
						'orusergroupid' => $group['orusergroupid'],
						'override'      => $group['override'],
					);
					$group =  $groups->next();
				}
			}
		}

		$users = $this->assertor->assertQuery('user', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'userid' => $userids,
		));

		if ($users->valid())
		{
			$user = $users->current();
			while ($users->valid())
			{
				$infractioninfo = $this->fetchInfractionGroups($infractiongroups, $user['userid'], $user['ipoints'], $user['usergroupid']);

				if (($groupids = implode(',', $infractioninfo['infractiongroupids'])) != $user['infractiongroupids'] OR $infractioninfo['infractiongroupid'] != $user['infractiongroupid'])
				{
					$userdata = new vB_Datamanager_User(vB::get_registry(), vB_DataManager_Constants::ERRTYPE_STANDARD);
					$userdata->set_existing($user);
					$userdata->set('infractiongroupids', $groupids);
					$userdata->set('infractiongroupid', $infractioninfo['infractiongroupid']);
					$userdata->save();
				}
				$user = $users->next();
			}
		}

		// @todo Invalidate cache for the user records that changed?

	}


	/**
	 * Determines if this infraction triggers an automatic ban, and if so, returns the automatic ban information
	 *
	 * @param	array	User Info for the user to ban
	 * @param	array	Data for the infraction that's being given
	 * @param	array	Infraction level infrmation for the infraction that's being given
	 * @param	bool	Is this a warning?
	 */
	protected function getAutomaticBanToApply(array $userInfo, array $data, array $infractionLevelInfo, $isWarning)
	{
		if ($isWarning OR $infractionLevelInfo['points'] < 1)
		{
			// warnings don't change points or number of infractions and thus can't trigger a ban
			return false;
		}

		require_once(DIR . '/includes/adminfunctions.php');
		if (is_unalterable_user($userInfo['userid']))
		{
			return false;
		}

		$userInfractions = $this->getUserInfractions($userInfo['userid']);
		// number of active & expired infractions for an infraction-based ban
		$currentUserInfractions = $userInfractions['statistics']['total'];
		// number of active infraction points for a points-based ban
		$currentUserPoints = $userInfractions['statistics']['points'];

		// find the longest available ban
		$banList = $this->getAutomaticBanList();
		$banToApply = false;
		foreach ($banList AS $ban)
		{
			if ($ban['usergroup'] != -1 AND $ban['usergroup'] != $userInfo['usergroup'])
			{
				continue;
			}

			if (
					(
						$ban['method'] == 'points'
						AND
						($currentUserPoints + $infractionLevelInfo['points']) >= $ban['amount']
					)
					OR
					(
						$ban['method'] == 'infractions'
						AND
						($currentUserInfractions + 1) >= $ban['amount']
					)
			)
			{
				if ($ban['liftdate'] == 0)
				{
					// stop at the first non-expiring ban
					$banToApply = $ban;
					break;
				}
				else if (empty($banToApply['liftdate']) OR $ban['liftdate'] > $banToApply['liftdate'])
				{
					// find the longest ban
					$banToApply = $ban;
				}
			}
		}

		if (!$banToApply)
		{
			// no applicable ban found, nothing to do
			return false;
		}

		$currentBan = $this->assertor->getRow('userban', array('userid' => $userInfo['userid']));

		if (
				$currentBan
				AND
				(
					$currentBan['liftdate'] == 0 // permanent ban
					OR
					(
						$currentBan['liftdate'] > $banToApply['liftdate']
						AND
						$banToApply['liftdate'] != 0
					)
				)
		)
		{
			// user is already banned longer than we would ban them for
			return false;
		}

		// we have a ban to apply, but no reason was specified
		if (empty($data['banreason']))
		{
			throw new vB_Exception_Api('invalid_banreason');
		}
		return $banToApply;
	}

	/**
	 * Applies the automatic ban to the user
	 *
	 * @param	array	User Info for the user to ban
	 * @param	array	Data for the automatic ban to apply (returned from getAutomaticBanToApply)
	 * @param	array	Data for the infraction that's being given
	 */
	protected function applyAutomaticBan(array $userInfo, array $banToApply, array $data)
	{
		$currentBan = $this->assertor->getRow('userban', array('userid' => $userInfo['userid']));
		$user = vB::getCurrentSession()->fetch_userinfo();

		// Drop the ban hammer
		if ($currentBan)
		{
			if (
					($banToApply['liftdate'] == 0 OR $currentBan['liftdate'] < $banToApply['liftdate'])
					AND
					$currentBan['liftdate'] != 0
			)
			{
				// there is already a record - just update this record
				$this->assertor->update('userban', array(
					'bandate' => vB::getRequest()->getTimeNow(),
					'liftdate' => $banToApply['liftdate'],
					'adminid' => $user['userid'],
					'reason' => $data['banreason'],
				), array('userid' => $userInfo['userid']));
			}
		}
		else
		{
			// insert a record into the userban table
			/*insert query*/
			$this->assertor->insert('userban', array(
				'userid' => $userInfo['userid'],
				'usergroupid' => $userInfo['usergroupid'],
				'displaygroupid' => $userInfo['displaygroupid'],
				'customtitle' => $userInfo['customtitle'],
				'usertitle' => $userInfo['usertitle'],
				'bandate' => vB::getRequest()->getTimeNow(),
				'liftdate' => $banToApply['liftdate'],
				'adminid' => $user['userid'],
				'reason' => $data['banreason'],
			));
		}

		//$existingUserInfo = $this->assertor->getRow('user', array('userid' => $userInfo['userid']));
		$existingUserInfo = vB_User::fetchUserinfo($userInfo['userid']);

		// update the user record
		$userdata = new vB_Datamanager_User(vB::get_registry(), vB_DataManager_Constants::ERRTYPE_SILENT);
		$userdata->set_existing($existingUserInfo);
		$userdata->set('usergroupid', $banToApply['banusergroupid']);
		$userdata->set('displaygroupid', 0);
		$userdata->set('status', ''); // clear status, VBV-15853

		// update the user's title if they've specified a special user title for the banned group
		$bannedUserGroups = vB_Api::instanceInternal('usergroup')->fetchBannedUsergroups();
		if ($bannedUserGroups[$banToApply['banusergroupid']]['usertitle'] != '')
		{
			$userdata->set('usertitle', $bannedUserGroups[$banToApply['banusergroupid']]['usertitle']);
			$userdata->set('customtitle', 0);
		}

		$userdata->save();
		unset($userdata);
	}

	/**
	 * Determines if the logged-in user can infract the (author of) the given node
	 *
	 * @param	int	Node ID
	 * @param	array	Node record, if you have it
	 *
	 * @return	bool	The node (user) can be infracted by current user (or not)
	 */
	public function canInfractNode($nodeid, array $node = null)
	{
		$nodeid = (int) $nodeid;
		$infractionContentTypeId = null;

		if ($infractionContentTypeId === null)
		{
			$infractionContentTypeId = vB_Types::instance()->getContentTypeID('vBForum_Infraction');
		}
		if ($node === null OR !is_array($node))
		{
			// needs getNodeFullContent to pull the node[infraction] field
			$nodeBare = vB_Library::instance('node')->getNodeBare($nodeid);
			$node = vB_Library_Content::getContentLib($nodeBare['contenttypeid'])->getBareContent($nodeid);
			$node = array_pop($node);
		}

		return (
			// Cannot infract a post that already has an infraction
			empty($node['infraction'])
			// Cannot infract an infraction
			AND $node['contenttypeid'] != $infractionContentTypeId
			// Can the post author be infracted?
			AND $this->canInfractUser($node['userid'])
		);
	}

	/**
	 * Determines if the logged-in user can infract the given user
	 *
	 * @param	int	User ID
	 *
	 * @return	bool	The user can be infracted by current user (or not)
	 */
	public function canInfractUser($userid)
	{
		$userid = (int) $userid;

		$currentUserId = vB::getCurrentSession()->get('userid');

		return (
			// Must have 'cangiveinfraction' permission. Branch dies right here majority of the time
			vB::getUserContext()->hasPermission('genericpermissions', 'cangiveinfraction')
			// Can not give yourself an infraction
			AND $userid != $currentUserId
			// Can not give an admin an infraction
			AND !(vB::getUserContext($userid)->hasPermission('adminpermissions', 'cancontrolpanel'))
			// Only Admins can give a supermod an infraction
			AND (
				!(vB::getUserContext($userid)->hasPermission('adminpermissions', 'ismoderator'))
				OR vB::getUserContext()->hasPermission('adminpermissions', 'cancontrolpanel')
			)
			// Can not give guests infractions
			AND $userid
		);
	}

	/**
	 * Determines if the logged-in user can view any infractions on the given node
	 *
	 * @param	int	Node ID
	 * @param	array	Node record, if you have it
	 *
	 * @return	bool	The current user can view any infractions on this node (or not)
	 */
	public function canViewNodeInfraction($nodeid, array $node = null)
	{
		$nodeid = (int) $nodeid;
		$currentUserId = vB::getCurrentSession()->get('userid');

		if ($node === null OR !is_array($node))
		{
			try
			{
				// does not need getNodeFullContent because we only use node[userid]
				$node = vB_Library::instance('node')->getNode($nodeid);
			}
			catch (vB_Exception_Api $e)
			{
				return false; // if we can't get the node, we can't see it
			}
		}

		return (
			// is the node author
			$node['userid'] == $currentUserId
			// has the 'canseeinfraction' permission
			OR vB::getUserContext()->hasPermission('genericpermissions', 'canseeinfraction')
			// has the 'canreverseinfraction' permission
			OR vB::getUserContext()->hasPermission('genericpermissions', 'canreverseinfraction')
			// has the 'cangiveinfraction' permission
			OR vB::getUserContext()->hasPermission('genericpermissions', 'cangiveinfraction')
		);
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 102683 $
|| #######################################################################
\*=========================================================================*/
