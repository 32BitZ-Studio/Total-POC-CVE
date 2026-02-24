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
 * vB_Api_Ad
 * Advertising API
 *
 * @package vBApi
 * @access public
 */
class vB_Api_Ad extends vB_Api
{
	/**
	 * @var array $ad_cache All current ads (adid => array of ad info)
	 */
	protected $ad_cache = array();

	/**
	 * @var	array $ad_name_cache All current ad titles (adid => ad title)
	 */
	protected $ad_name_cache = array();

	/**
	 * @var	int $max_displayorder The highest display order value for all retrieved ads
	 */
	protected $max_displayorder = 0;

	/**
	 * Constructor
	 */
	protected function __construct()
	{
		parent::__construct();

		// cache all ads
		$this->updateAdCache();
	}

	/**
	 * Populates the ad cache properties $ad_cache and $ad_name_cache
	 */
	protected function updateAdCache()
	{
		// cache all ads
		$ad_result = vB::getDbAssertor()->getRows('ad', array(), array(
			'field' => array('displayorder'),
			'direction' => array(vB_dB_Query::SORT_ASC)
		));

		foreach ($ad_result as $ad)
		{
			$this->ad_cache["$ad[adid]"] = $ad;
			$this->ad_name_cache["$ad[adid]"] = $ad['title'];
			if ($ad['displayorder'] > $this->max_displayorder)
			{
				$this->max_displayorder = $ad['displayorder'];
			}
		}
	}

	/**
	 * Lists ads for a location
	 *
	 * @param  string     $adlocation The location we want to get ads for (string locations defined in templates)
	 *
	 * @return array Returns an array of ads (fields from the ad and adcriteria tables)
	 */
	public function listAdsByLocation($adlocation)
	{
		$adlocation = vB::getCleaner()->clean($adlocation,  vB_Cleaner::TYPE_STR);
		$this->checkHasAdminPermission('canadminads');

		$db = vB::getDbAssertor();
		$ads = $db->getRows('ad', array('adlocation' => $adlocation), false, 'adid');

		if (!$ads)
		{
			return array();
		}

		foreach ($ads AS $k => $ad)
		{
			$ads[$k]['criterias'] = $this->getCriteria($db, $ad['adid']);
		}

		return $ads;
	}

	/**
	 * Fetches an ad by its ID
	 *
	 * @param  int              $adid Ad ID
	 * @throws vB_Exception_Api invalidid if the specified ad id does not exist
	 * @return array            $ad Ad data (fields from the ad and adcriteria tables)
	 */
	public function fetch($adid)
	{
		$adid = vB::getCleaner()->clean($adid,  vB_Cleaner::TYPE_UINT);
		$this->checkHasAdminPermission('canadminads');

		$db = vB::getDbAssertor();

		$ad = $db->getRow('ad', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'adid' => $adid
		));

		if (!$ad)
		{
			throw new vB_Exception_Api('invalidid');
		}

		$ad['criterias'] = $this->getCriteria($db, $ad['adid']);
		return $ad;
	}

	/**
	 *	Rebuilds the template for given ad locations
	 *
	 *	@params array $locationids array of location id strings to rebuild
	 *	@return none
	 */
	private function rebuildAdTemplates($locationids)
	{
		//these will be needed if we ever make this public.  It might be useful
		//for the installer or on a maintenance page to force a rebuild (for example
		//we change how we create the templates and want to force existing ads to conform).
		//$locationids = vB::getCleaner()->clean($locationids,  vB_Cleaner::TYPE_ARRAY_NOHTML);
		//$this->checkHasAdminPermission('canadminads');

		foreach($locationids AS $locationid)
		{
			$template = $this->wrapAdTemplate($this->buildAdTemplate($locationid), $locationid);
			$this->replaceAdTemplate(-1, $locationid, $template, 'vbulletin');
		}

		vB_Library::instance('style')->buildAllStyles();
	}

	/**
	 * Updates an existing ad or saves a new ad
	 *
	 * @param  int              $adid ID of Ad to be updated. Set to 0 to insert a new Ad
	 * @param  array            $data Ad data
	 *
	 * @throws vB_Exception_Api invalid_title_specified if the title is missing
	 *
	 * @return int              Ad ID
	 */
	public function save($adid, $data)
	{
		if (!is_array($data))
		{
			throw new vB_Exception_Api('invalid_data_w_x_y_z', array($data, '$data', __CLASS__, __FUNCTION__));
		}

		//do this before cleaning or we'll end up not being able to distinguish
		//between "not set" and "0"
		if (!isset($data['displayorder']) OR !is_numeric($data['displayorder']))
		{
			$data['displayorder'] = 1;
		}

		if (!isset($data['active']) OR !is_numeric($data['active']))
		{
			$data['active'] = 0;
		}

		$cleaner = vB::getCleaner();
		$adid = $cleaner->clean($adid, vB_Cleaner::TYPE_UINT);
		$data = $cleaner->cleanArray($data, array(
			'criteria'            => vB_Cleaner::TYPE_ARRAY,
			'title'               => vB_Cleaner::TYPE_STR,
			'displayorder'        => vB_Cleaner::TYPE_UINT,
			'active'              => vB_Cleaner::TYPE_UINT,
			'ad_location'         => vB_Cleaner::TYPE_STR,
			'ad_html'             => vB_Cleaner::TYPE_STR,
			'ad_location_orig'    => vB_Cleaner::TYPE_STR,
		));
		$this->checkHasAdminPermission('canadminads');

		$criteria = $data['criteria'];
		if (!$data['title'])
		{
			throw new vB_Exception_Api('invalid_title_specified');
		}

		if (stripos($data['ad_html'], '</vb:literal>') !== false)
		{
			throw new vB_Exception_Api('no_permission');
		}

		$db = vB::getDbAssertor();
		$queryData = array(
			'title' => $data['title'],
			'adlocation' => $data['ad_location'],
			'displayorder' => $data['displayorder'],
			'active' => $data['active'],
			'snippet' => $data['ad_html'],
		);

		if ($adid)
		{
			// Update ad record
			$db->update('ad', $queryData, array('adid' => $adid));

			// delete criteria
			$db->delete('adcriteria', array('adid' => $adid));
		}
		// we are adding a new ad
		else
		{
			// insert ad record
			$adid = $db->insert('ad', $queryData);
			if (is_array($adid))
			{
				$adid = array_pop($adid);
			}
			$adid = (int) $adid;
		}

		// update the ad_cache
		$queryData['adid'] = $adid;
		$this->ad_cache[$adid] = $queryData;

		$criteriadata = array();

		foreach ($criteria AS $criteriaid => $criterion)
		{
			if (isset($criterion['active']) AND $criterion['active'])
			{
				$conditions = $this->getConditionsForSave($criteriaid, $criterion);
				// Avoid "Undefined index" notice error
				$criteriadata[] = array(
					$adid,
					$criteriaid,
					$conditions['condition1'],
					$conditions['condition2'],
					$conditions['condition3'],
					$conditions['conditionjson'],
				);
			}
		}

		if ($criteriadata)
		{
			$db->delete('adcriteria', array('adid' => $adid));
			$db->insertMultiple('adcriteria', array('adid', 'criteriaid', 'condition1', 'condition2', 'condition3', 'conditionjson'), $criteriadata);
		}

		$updatedadlocations = array($queryData['adlocation']);
		if (!empty($data['ad_location_orig']) AND $queryData['adlocation'] != $data['ad_location_orig'])
		{
			$updatedadlocations[] = $data['ad_location_orig'];
		}

		$this->rebuildAdTemplates($updatedadlocations);

		return $adid;
	}

	private function getConditionsForSave($criteriaid, $conditions)
	{
		//make sure that we have all of the conditions fields present in the array
		//also make sure that we don't have any that we don't recognize.
		$blank = array('condition1' => '', 'condition2' => '', 'condition3' => '');
		$newconditions = $blank;
		foreach($blank AS $key => $dummy)
		{
			if(isset($conditions[$key]))
			{
				$newconditions[$key] = $conditions[$key];
			}
		}

		$this->cleanConditions($criteriaid, $newconditions);

		if($this->useJSONCondition($criteriaid))
		{
			$jsonconditions = json_encode($newconditions);
			//if we are using json storage we don't want to set anything to the other fields.
			$newconditions = $blank;
			$newconditions['conditionjson'] = $jsonconditions;
		}
		else
		{
			$newconditions['conditionjson'] = '';
		}

		return $newconditions;
	}

	private function cleanConditions($criteriaid, &$conditions)
	{
		//allow criteria specific cleaning -- especially important before we start
		//serializing complex data types (even if it's with the safer json_encode/decode
		switch($criteriaid)
		{
			case 'browsing_forum_x':
			case 'in_usergroup_x':
			case 'not_in_usergroup_x':
				if(empty($conditions['condition1']))
				{
					$conditions['condition1'] = array();
				}
				else
				{
					//this should always be an array, but let's handle a single value just in case.
					if(!is_array($conditions['condition1']))
					{
						$conditions['condition1'] = array($conditions['condition1']);
					}

					$conditions['condition1'] = array_map('intval', $conditions['condition1']);
				}

				//these aren't used.  Make sure we don't use them
				$conditions['condition2'] = '';
				$conditions['condition3'] = '';
				break;

			//this is the legacy handling that was appied without regard to which criteria
			default:
				$conditions = array_map('trim', $conditions);
				break;
		}
	}

	private function getCriteria($db, $adid)
	{
		$criteria = $db->getRows('adcriteria', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'adid' => $adid
		));

		foreach($criteria AS $key => $dummy)
		{
			$this->expandJsonConditions($criteria[$key]);
		}
		return $criteria;
	}


	private function expandJsonConditions(&$criterion)
	{
		//if this field is set to use the json store *and* there is a value in the json field
		//otherwise assume it's legacy data and leave the old condition fields there
		if($this->useJSONCondition($criterion['criteriaid']) AND !empty($criterion['conditionjson']))
		{
			$jsonconditions = json_decode($criterion['conditionjson'], true);
			if($jsonconditions)
			{
				$criterion = array_merge($criterion, $jsonconditions);
			}
		}

		unset($criterion['conditionjson']);
	}

	private function useJSONCondition($criteriaid)
	{
		//for now browsing_forum_x is the only one using the json field.
		if(in_array($criteriaid, array('browsing_forum_x', 'in_usergroup_x', 'not_in_usergroup_x')))
		{
			return true;
		}

		return false;
	}


	/**
	 * Saves the active status and display orders for multiple ads
	 *
	 * @param  array $data Data to save. Format: array(adid => array('active' => $active, 'displayorder' => $displayorder), ...)
	 *
	 * @return bool  True on success
	 */
	public function quickSave($data)
	{
		if (!is_array($data))
		{
			throw new vB_Exception_Api('invalid_data_w_x_y_z', array($data, '$data', __CLASS__, __FUNCTION__));
		}

		$cleaner = vB::getCleaner();
		foreach($data AS $key => &$val)
		{
			$key = $cleaner->clean($key, vB_Cleaner::TYPE_UINT);
			$val = $cleaner->cleanArray($val, array(
				'active'       => vB_Cleaner::TYPE_UINT,
				'displayorder' => vB_Cleaner::TYPE_UINT,
			));
			$data[$key] = $val;
		}

		$this->checkHasAdminPermission('canadminads');

		$updatedadlocations = array();

		$db = vB::getDbAssertor();
		foreach ($data AS $adid => $value)
		{
			$db->update('ad',
				array(
					'active' => intval($value['active']),
					'displayorder' => intval($value['displayorder']),
				),
				array(
					'adid' => $adid,
				)
			);
		}

		$this->updateAdCache();

		foreach ($data AS $adid => $value)
		{
			if ($this->ad_cache[$adid])
			{
				$updatedadlocations[$this->ad_cache[$adid]['adlocation']] = $this->ad_cache[$adid]['adlocation'];
			}
		}

		$this->rebuildAdTemplates($updatedadlocations);

		return true;
	}

	/**
	 * Saves the number of header ads to use (this can be 1 or 2)
	 *
	 * @param  int  $number Number of header ads to show (1 or 2)
	 *
	 * @return bool True on success
	 */
	public function saveNumberOfHeaderAds($number)
	{
		$number = vB::getCleaner()->clean($number,  vB_Cleaner::TYPE_UINT);

		$this->checkHasAdminPermission('canadminads');

		if ($number > 1)
		{
			$number = 2;
		}
		else
		{
			$number = 1;
		}

		vB_Api::instanceInternal('options')->updateValue('headeradnum', $number);

		return true;
	}

	/**
	 * Deletes an ad
	 *
	 * @param  int  $adid Ad ID to delete
	 *
	 * @return bool Returns true on success
	 */
	public function delete($adid)
	{
		$adid = vB::getCleaner()->clean($adid,  vB_Cleaner::TYPE_UINT);

		$this->checkHasAdminPermission('canadminads');

		// get ad location
		$adlocation = $this->ad_cache[$adid]['adlocation'];

		// delete criteria
		vB::getDbAssertor()->delete('adcriteria', array('adid' => $adid));

		// delete ad
		vB::getDbAssertor()->delete('ad', array('adid' => $adid));

		// remove record from ad_cache
		unset($this->ad_cache[$adid]);
		$this->ad_cache = array_values($this->ad_cache);

		$this->rebuildAdTemplates(array($adlocation));
		return true;
	}

	/**
	 * Builds an ad template based on criteria
	 *
	 * @param  string $location Template location
	 *
	 * @return string Template string
	 */
	protected function buildAdTemplate($location)
	{
		$this->checkHasAdminPermission('canadminads');

		$template = '';
		$vboptions = vB::getDatastore()->getValue('options');

		foreach ($this->ad_cache AS $adid => $ad)
		{
			// active ads on the same location only
			if ($ad['active'] AND $ad['adlocation'] == $location)
			{
				$criterion = $this->getCriteria(vB::getDbAssertor(), $ad['adid']);

				// create the template conditionals
				$conditional_prefix = "";
				$conditional_postfix = "";

				// The following code is to make browsing_forum_x and browsing_forum_x_and_children work concurrently. See VBV-4442

				$browsing_channels = array();
				foreach ($criterion AS $criteria)
				{
					switch($criteria['criteriaid'])
					{
						case "in_usergroup_x":
							$groups =  $criteria['condition1'];
							//this should always be an array now, but some legacy data might still have it as a scalar.
							if(!is_array($groups))
							{
								$groups[] = intval($groups);
							}
							$conditional_prefix .= '<vb:if condition="is_member_of($' . 'user, array(' . implode(',', $groups) . '))">';
							$conditional_postfix .= "</vb:if>";
							break;
						case "not_in_usergroup_x":
							$groups =  $criteria['condition1'];
							//this should always be an array now, but some legacy data might still have it as a scalar.
							if(!is_array($groups))
							{
								$groups[] = intval($groups);
							}
							$conditional_prefix .= '<vb:if condition="!is_member_of($' . 'user, array(' . implode(',', $groups) . '))">';
							$conditional_postfix .= "</vb:if>";
							break;
						case "browsing_content_page":
							if (!empty($criteria['condition1']))
							{
								$conditional_prefix .= '<vb:if condition="!empty($page[\'nodeid\'])">';
							}
							else
							{
								$conditional_prefix .= '<vb:if condition="empty($page[\'nodeid\'])">';
							}
							$conditional_postfix .= "</vb:if>";
							break;
						case "browsing_forum_x":
							$channel =  $criteria['condition1'];
							//this should always be an array now, but some legacy data might still have it as a scalar.
							if(is_array($channel))
							{
								$browsing_channels = array_merge($browsing_channels, $channel);
							}
							else
							{
								//if channel isn't an int (probably due to a bug) then it will break the template
								//let's be sure that it is -- a value of 0 in the list will ultimately be harmless
								$browsing_channels[] = intval($channel);
							}
							break;
						case "browsing_forum_x_and_children":
							// find out who the children are:
							$channelcontenttypeid = vB_Api::instanceInternal('contenttype')->fetchContentTypeIdFromClass('Channel');
							$nodelib = vB_Library::instance('node');
							$children = $nodelib->listNodes(intval($criteria['condition1']), 1, 100, 0, $channelcontenttypeid, array());
							foreach ($children as $child)
							{
								$browsing_channels[] = intval($child['nodeid']);
							}
							$browsing_channels[] = intval($criteria['condition1']);
							break;
						case "style_is_x":
							$conditional_prefix .= '<vb:if condition="STYLEID == ' . intval($criteria['condition1']) . '">';
							$conditional_postfix .= "</vb:if>";
							break;
						case "no_visit_in_x_days":
							$conditional_prefix .= '<vb:if condition="$' . 'user[\'lastactivity\'] < $timenow - (86400*' . intval($criteria['condition1']) . ')">';
							$conditional_postfix .= "</vb:if>";
							break;
						case "no_posts_in_x_days":
							$conditional_prefix .= '<vb:if condition="$' . 'user[\'lastpost\'] < $timenow - (86400*' . intval($criteria['condition1']) . ') AND $user[\'lastpost\'] > 0">';
							$conditional_postfix .= "</vb:if>";
							break;
						case "has_x_postcount":
							$conditional_prefix .= '<vb:if condition="$' . 'user[\'posts\'] > ' . intval($criteria['condition1']) . ' AND $' . 'user[\'posts\'] < ' . intval($criteria['condition2']) . '">';
							$conditional_postfix .= "</vb:if>";
							break;
						case "has_never_posted":
							$conditional_prefix .= '<vb:if condition="$' . 'user[\'posts\'] == 0">';
							$conditional_postfix .= "</vb:if>";
							break;
						case "has_x_reputation":
							$conditional_prefix .= '<vb:if condition="$' . 'user[\'reputation\'] > ' . intval($criteria['condition1']) . ' AND $' . 'user[\'reputation\'] < ' . intval($criteria['condition2']) . '">';
							$conditional_postfix .= "</vb:if>";
							break;
						case "pm_storage_x_percent_full":
							$conditional_prefix .= '<vb:if condition="$' . 'pmboxpercentage = $' . 'user[\'pmtotal\'] / $' . 'user[\'permissions\'][\'pmquota\'] * 100"></vb:if>';
							$conditional_prefix .= '<vb:if condition="$' . 'pmboxpercentage > ' . intval($criteria['condition1']) . ' AND $' . 'pmboxpercentage < ' . intval($criteria['condition2']) . '">';
							$conditional_postfix .= "</vb:if>";
							break;
						case "came_from_search_engine":
							$conditional_prefix .= '<vb:if condition="is_came_from_search_engine()">';
							$conditional_postfix .= "</vb:if>";
							break;
						case "is_date":
							if ($criteria['condition2'])
							{
								$conditional_prefix .= '<vb:if condition="gmdate(\'d-m-Y\', $timenow) == \'' . str_replace("'", "\'", $criteria['condition1']) .'\'">';
								$conditional_postfix .= "</vb:if>";
							}
							else
							{
								$conditional_prefix .= '<vb:if condition="vbdate(\'d-m-Y\', $timenow, false, false) == \'' . str_replace("'", "\'", $criteria['condition1']) .'\'">';
								$conditional_postfix .= "</vb:if>";
							}
							break;
						case "is_time":
							if (preg_match('#^(\d{1,2}):(\d{2})$#', $criteria['condition1'], $start_time) AND preg_match('#^(\d{1,2}):(\d{2})$#', $criteria['condition2'], $end_time))
							{
								if ($criteria['condition3'])
								{
									$conditional_prefix .= '<vb:if condition="$now = gmmktime()"></vb:if>';
									$conditional_prefix .= '<vb:if condition="$end = gmmktime(' . $end_time[1] . ',' . $end_time[2] . ')"></vb:if>';
									$conditional_prefix .= '<vb:if condition="$start = gmmktime(' . $start_time[1] . ',' . $start_time[2] . ')"></vb:if>';
								}
								else
								{
									$conditional_prefix .= '<vb:if condition="$now = mktime()"></vb:if>';
									$conditional_prefix .= '<vb:if condition="$end = mktime(' . $end_time[1] . ',' . $end_time[2] . ')"></vb:if>';
									$conditional_prefix .= '<vb:if condition="$start = mktime(' . $start_time[1] . ',' . $start_time[2] . ')"></vb:if>';
								}
								$conditional_prefix .= '<vb:if condition="$now >= $start AND $now <= $end">';
								$conditional_postfix .= '</vb:if>';
							}
							break;
						case "ad_x_not_displayed":
							// no ad shown? make note of it, and create the array for us
							$conditional_prefix .= '<vb:if condition="$noadshown = !isset($' . 'adsshown)"></vb:if>';
							$conditional_prefix .= '<vb:if condition="$noadshown"><vb:if condition="$' . 'adsshown = array()"></vb:if></vb:if>';
							// if no ads shown, OR ad x have not been shown, show the ad
							$conditional_prefix .= '<vb:if condition="$noadshown OR !in_array(' . intval($criteria['condition1']) . ', $' . 'adsshown)">';
							$conditional_postfix .= '</vb:if>';
							break;
						default:
							break;
					}
				}

				if($browsing_channels)
				{
					$conditional_prefix .= '<vb:if condition="in_array($page[\'channelid\'], array(' . implode(',', $browsing_channels) . '))">';
					$conditional_postfix .= "</vb:if>";
				}

				// add a faux conditional before all the closing conditions to mark that we've shown certain ad already
				$conditional_postfix = '<vb:if condition="$' . 'adsshown[] = ' . $adid . '"></vb:if>' . $conditional_postfix;

				// wrap the conditionals around their ad snippet / template
				$template .= $conditional_prefix . '<vb:literal>' . $ad['snippet'] . '</vb:literal>' . $conditional_postfix;
			}
		}

		return $template;
	}

	/**
	 * Fetches display options
	 *
	 * @param  int   $adid (optinal) Ad ID
	 *
	 * @return array Array with two elements:
	 *               criteria_options - array with criterion name => criterion info (type, data, default value)
	 *               criteria_cache - not currently used
	 */
	public function fetchDisplayOptions($adid = 0)
	{
		$adid = vB::getCleaner()->clean($adid,  vB_Cleaner::TYPE_UINT);

		try
		{
			$this->checkHasAdminPermission('canadminads');
		}
		catch (vB_Exception_Api $e)
		{
			// No permission, return empty array
			return array();
		}

		require_once(DIR . '/includes/adminfunctions.php');

		$criteria_cache = array();
		// TODO: Fetch criteria cache by adid

		$usergroups = vB_Api::instanceInternal('usergroup')->fetchUsergroupList();
		$usergroup_options = array();
		foreach ($usergroups as $usergroup)
		{
			$usergroup_options[$usergroup['usergroupid']] = $usergroup['title'];
		}

		$vbphrase = vB_Api::instanceInternal('phrase')->fetch(array(
			'content', 'non_content', 'user_timezone', 'utc_universal_time'
		));

		$timenow = vB::getRequest()->getTimeNow();

		$forum_chooser_options = construct_forum_chooser_options();

		$criteria_options = array(
			'in_usergroup_x' => array(
				array(
					'type' => 'select_multiple',
					'data' => $usergroup_options,
					'default_value' => 2
				)
			),
			'not_in_usergroup_x' => array(
				array(
					'type' => 'select_multiple',
					'data' => $usergroup_options,
					'default_value' => 6
				)
			),
			'browsing_content_page' => array(
				array(
					'type' => 'select',
					'data' => array(
				    	'1' => $vbphrase['content'],
				   		'0' => $vbphrase['non_content']
				   	),
					'default_value' => 1
				)
			),
			'browsing_forum_x' => array(
				array(
					'type' => 'select_multiple',
					'data' => $forum_chooser_options,
					'default_index' => 0
				)
			),
			'browsing_forum_x_and_children' => array(
				array(
					'type' => 'select',
					'data' => $forum_chooser_options,
					'default_index' => 0
				)
			),
			'no_visit_in_x_days' => array(
				array(
					'type' => 'input',
					'default_value' => 30
				)
			),
			'no_posts_in_x_days' => array(
				array(
					'type' => 'input',
					'default_value' => 30
				)
			),
			'has_x_postcount' => array(
				array(
					'type' => 'input',
					'default_value' => ''
				),
				array(
					'type' => 'input',
					'default_value' => ''
				)
			),
			'has_never_posted' => array(
			),
			'has_x_reputation' => array(
				array(
					'type' => 'input',
					'default_value' => 100
				),
				array(
					'type' => 'input',
					'default_value' => 200
				)
			),
			// Don't remove the following commented code as we may get PM quote feature back in future
//			'pm_storage_x_percent_full' => array(
//				array(
//					'type' => 'input',
//					'default_value' => 90
//				),
//				array(
//					'type' => 'input',
//					'default_value' => 100
//				)
//			),
			'came_from_search_engine' => array(
			),
			'is_date' => array(
				array(
					'type' => 'input',
					'default_value' => vbdate('d-m-Y', $timenow, false, false)
				),
				array(
					'type' => 'select',
					'data' => array(
				    	'0' => $vbphrase['user_timezone'],
				   		'1' => $vbphrase['utc_universal_time']
				   	),
					'default_value' => 0
				)
			),
			'is_time' => array(
				array(
					'type' => 'input',
					'default_value' => vbdate('H:i', $timenow, false, false)
				),
				array(
					'type' => 'input',
					'default_value' => (($h = (intval(vbdate('H', $timenow, false, false)) + 1)) < 10 ? '0' . $h : $h) . vbdate(':i', $timenow, false, false)
				),
				array(
					'type' => 'select',
					'data' => array(
				    	'0' => $vbphrase['user_timezone'],
				   		'1' => $vbphrase['utc_universal_time']
				   	),
					'default_value' => 0
				)
			),
			/*
			* These are flagged for a future version
			'userfield_x_equals_y' => array(
			),
			'userfield_x_contains_y' => array(
			),
			*/
		);

		return array(
			'options' => $criteria_options,
			'cache' => $criteria_cache
		);
	}

	/**
	 * Wraps an ad template in a div with the correct id
	 *
	 * @param string $template  Template String
	 * @param string $id_name   Ad location (global_header1)
	 * @param string $id_prefix ID Prefix (Default: 'ad_')
	 *
	 * @return string Wrapped AD Template
	 */
	protected function wrapAdTemplate($template, $id_name, $id_prefix = 'ad_')
	{
		if (!$template)
		{
			return '';
		}

		// wrap the template in a div with the correct id
		$template_wrapped = '<div class="' . $id_prefix . $id_name . '_inner">' . $template . '</div>';

		return $template_wrapped;
	}

	/**
	 * Replaces ad code into correct template
	 *
	 * @param string $styleid         Style for template
	 * @param string $location        Ad location
	 * @param string $template        Template compiled
	 * @param string $product         Product that uses this template
	 */
	protected function replaceAdTemplate($styleid, $location, $template, $product = 'vbulletin')
	{
		$templateLib = vB_Library::instance('template');
		$templateOptions = array("forcenotextonly" => true, "textonly" => 0);
		// Try to insert the template
		try
		{
			$templateLib->insert($styleid, 'ad_' . $location, $template, $product, false, '', false, $templateOptions);
		}
		catch (vB_Exception_Api $e)
		{
			$templateid = $templateLib->getTemplateID('ad_' . $location, $styleid);
			$templateLib->update($templateid, 'ad_' . $location, $template, $product, false, false, '', false, $templateOptions);
		}
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 102914 $
|| #######################################################################
\*=========================================================================*/
