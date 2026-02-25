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
 * vB_Api_Wol
 * Who is online API
 *
 * @package vBApi
 * @access public
 */
class vB_Api_Wol extends vB_Api
{
	protected $onlineusers = array();

	/**
	 * Register an online action
	 * Example:
	 *   vB_Api::instanceInternal('Wol')->register('viewing_x', array(array('nodeid', $nodeid)));
	 *
	 * @param string $action
	 * @param array $params Parameters of the action
	 *        It's an array of parameters that will be used in the phrase
	 *        The key of a parameter is the index-1 of a phrase brace var
	 *        The value of a parameter may be a string which will directly replace brance var
	 *        Other types of id may be added later
	 * @param string $pagekey Pagekey of the page where the user is
	 * @param int $nodeid Node ID of the node being viewed
	 *
	 * @return array -- standard success array.
	 */
	public function register($action, $params = array(), $pagekey = '',  $location = '', $nodeid = 0)
	{
		$actiondata = array(
			'action' => $action,
			'params' => $params,
			'nodeid' => $nodeid,
		);

		$sessionhash = vB::getCurrentSession()->get('dbsessionhash');
		$data = array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'wol' => @serialize($actiondata),
			'pagekey' => $pagekey,
			'location' => $location,
			vB_dB_Query::CONDITIONS_KEY => array(
				'sessionhash' => $sessionhash,
			)
		);

		// Update action field of session table
		vB::getDbAssertor()->assertQuery('session', $data);
		return array('success' => true);
	}

	/**
	 * Fetch who is online records
	 *
	 * @param string $pagekey Fetch users who are only on the page with this pagekey
	 * @param string $who Show 'members', 'guests', 'spiders' or all ('')
	 * @param int $pagenumber
	 * @param int $perpage
	 * @param string $sortfield
	 * @param string $sortorder
	 * @return array Who is online information
	 */
	public function fetchAll($pagekey = '', $who = '', $pagenumber = 1, $perpage = 0, $sortfield = 'time', $sortorder = 'desc', $resolveIp = false)
	{
		//allow access to this function to everybody since basic information is widely displayed.
		//we'll restrict the information based on what people are actually allowed to see.

		$currentUserContext = vB::getUserContext();

		$vboptions = vB::getDatastore()->getValue('options');
		$bf_misc_useroptions = vB::getDatastore()->getValue('bf_misc_useroptions');

		// check permissions
		$canSeeIp = $currentUserContext->hasPermission('wolpermissions', 'canwhosonlineip');
		$canViewFull = $currentUserContext->hasPermission('wolpermissions', 'canwhosonlinefull');
		$canViewBad = $currentUserContext->hasPermission('wolpermissions', 'canwhosonlinebad');
		$canViewlocationUser = $currentUserContext->hasPermission('wolpermissions', 'canwhosonlinelocation');
		$canWhosOnline = $currentUserContext->hasPermission('wolpermissions', 'canwhosonline');

		$data = array(
			'who' => $who,
			'pagenumber' => $pagenumber,
			vB_dB_Query::PARAM_LIMIT => $perpage,
			'sortfield' => $sortfield,
			'sortorder' => $sortorder,
		);

		if ($pagekey)
		{
			$data['pagekey'] = $pagekey;
		}

		$nodeApi = vB_Api::instance('Node');

		$allusers = vB::getDbAssertor()->assertQuery('fetchWolAllUsers', $data);

		// $onlineUsers -> temp array to hold the info on already added users to the totalOnline array
		// $totalOnline -> This is the array we return in which we keep the ordering from the query we executed
		$onlineUsers = array();
		$totalOnline = array();
		$i = 0;
		foreach ($allusers AS $userRecord)
		{
			$usergroupidAux = $userRecord['usergroupid'];
			$userRecord = array_merge($userRecord, convert_bits_to_array($userRecord['options'] , $bf_misc_useroptions));
			$resolved = false;

			if ($userRecord['invisible'])
			{
				if (!($currentUserContext->hasPermission('genericpermissions', 'canseehidden') OR $userRecord['userid'] == vB::getCurrentSession()->fetch_userinfo_value('userid')))
				{
					continue;
				}
			}

			if (
				(
					$userRecord['userid'] > 0
					AND
					(
						empty($onlineUsers[$userRecord['userid']])
						OR
						(isset($onlineUsers[$userRecord['userid']]) AND $onlineUsers[$userRecord['userid']]['lastactivity'] < $userRecord['lastactivity'])
					)
				)
				OR
				$userRecord['userid'] == 0
			)
			{
				//We only want the most recent record
				if (($userRecord['userid'] > 0) AND isset($onlineUsers[$userRecord['userid']]))
				{
					continue;
				}

				// basic info used by the homepage What's Going On module
				$user = array(
					'username' => $userRecord['username'],
					'musername' => vB_Api::instanceInternal('User')->fetchMusername($userRecord),
					'userid' => $userRecord['userid'],
					'posts' => $userRecord['posts'],
					'enable_pmchat' => $userRecord['enable_pmchat'],
					'receivepm' => $userRecord['receivepm'],
				);

				// add additional info used by the Who's Online (/online) page
				if ($canWhosOnline)
				{
					$user['lastactivity'] = $userRecord['lastactivity'];
					$user['joindate'] = $userRecord['joindate'];

					if ($canSeeIp)
					{
						$user['host'] = $userRecord['host'];
					}

					if ($canViewBad)
					{
						$user['bad'] =  $userRecord['badlocation'];
					}

					if (isset($userRecord['wol']))
					{
						$wol =  @unserialize($userRecord['wol']);
						if (!empty($wol['action']))
						{
							if ($canViewFull)
							{
								$user['wol'] = $wol;
							}
							else
							{
								$user['wol']['action'] = $wol['action'];
							}
						}
					}

					if ($canViewlocationUser)
					{
						$user['location'] = $userRecord['location'];
					}

				}

				// check to see if the viewing user can view the target node
				// for this online user's location and wol action.
				// If not, don't show it.
				if (!empty($user['wol']['params']) OR !empty($user['location']))
				{
					if (!empty($user['wol']['nodeid']))
					{
						// can this user view the node?
						$node = $nodeApi->getNode($user['wol']['nodeid']);
						if (!empty($node['errors']))
						{
							unset($user['wol']['params']);
							unset($user['location']);
						}
					}
					else
					{
						// If we don't have a nodeid, don't show location
						// It's better to hide something they can see
						// than to let them see something they don't have
						// permission to see.
						unset($user['wol']['params']);
						unset($user['location']);

					}
				}

				// add a flag so the presentation layer can add an
				// invisible marker (we already checked if this user
				// is privy to this info above)
				$user['invisible'] = (bool) $userRecord['invisible'];

				// We need the avatars as per the wireframes
				$avatar = vB_Api::instanceInternal('user')->fetchAvatar($user['userid']);
				$user['avatarpath'] = $avatar['avatarpath'];

				if (!$canWhosOnline OR !$canViewlocationUser)
				{
					unset($user['location']);
				}

				if (!$canWhosOnline OR !$canSeeIp)
				{
					unset($user['host']);
				}

				if (!$user['username'])
				{
					$phrase = vB_Api::instanceInternal('phrase')->fetch('guest');
					$user['username'] = $phrase['guest'];
				}

				if ($resolveIp AND $canWhosOnline AND $canSeeIp)
				{
					$user['host'] = @gethostbyaddr($user['host']);
				}

				// guests don't have reputation
				if($user['userid'] > 0)
				{
					$user['reputationimg'] = vB_Library::instance('reputation')->fetchReputationImageInfo($userRecord);
				}

				$resolved = true;
			}

			if ($user['userid'] == 0)
			{
				// Add the guest in the totaOnline array and increase the counter $i
				$totalOnline[$i] = $user;
				$i++;
			}
			else if ($resolved)
			{
				// if we find this user already in the onlineUsers array, we overwrite the record in the totalOnline array
				// and we dont touch the counter $i
				if (isset($onlineUsers[$user['userid']]))
				{
					$totalOnline[$onlineUsers[$user['userid']]['totalid']] = $user;
				}
				else
				// If no record found we add the counter info to the user array and add it to the totelOnline array.
				// And increase the counter $i
				{
					$totalOnline[$i] = $user;
					$user['totalid'] = $i;
					$onlineUsers[$user['userid']] = $user;
					$i++;
				}
			}
		}

		return $totalOnline;
	}

	public function refreshUsers($pagekey = '', $who = '', $pagenumber = 1, $perpage = 0, $sortfield = 'time', $sortorder = 'desc', $resolveIp = false, $pageRouteId = null)
	{
		$result = array();

		$onlineUsers = $this->fetchAll($pagekey, $who, $pagenumber, $perpage, $sortfield , $sortorder, $resolveIp);

		$showIP = false;
		foreach ($onlineUsers AS $onlineUser)
		{
			if (!empty($onlineUser['host']))
			{
				$showIP = true;
			}
		}

		$onlineUserCounts = $this->fetchCounts($pagekey);
		$totalMembers = $who == 'members' ? $onlineUserCounts['members'] : $onlineUserCounts['total'];

		$pageRouteInfo = array();
		if ($pageRouteId)
		{
			$routeInfo = vB5_Route::getRouteByIdent($pageRouteId);
			$args = @unserialize($routeInfo['arguments']);
			$pageRouteInfo = array(
				'routeId' => $routeInfo['routeid'],
				'arguments' => array(
					'pageid' => $args['pageid'],
					'contentid' => $routeInfo['contentid'],
				),
				'queryParameters' => array(),
			);
		}

		$template = new vB5_Template('onlineuser_details');
		$template->register('onlineUsers', $onlineUsers);
		$template->register('showIP', $showIP);
		$template->register('totalMembers', $totalMembers);
		$template->register('pagenumber', $pagenumber);
		$template->register('perpage', $perpage);
		$template->register('pageRouteInfo', $pageRouteInfo);
		$template = $template->render();

		$userCounts = $this->fetchCounts($pagekey);

		$result['template'] = $template;
		$result['userCounts'] = $userCounts;
		return $result;
	}


	/**
	 * Fetch online user counts
	 *
	 * @param string $pagekey Fetch users who are only on the page with this pagekey
	 * @return array
	 * 	total int -- all users
	 *	members int -- members only
	 * 	guests int => guests only
	 *	recordusers int -- most users ever
	 *	maxonlinedate int -- Date the most ever user occurred as timestamp
	 *	recorddate string -- date as string (deprecated)
	 *	recordtime string -- time as string (deprecated)
	 */
	public function fetchCounts($pagekey = '')
	{
		$db = vB::getDbAssertor();
		$datastore = vB::getDatastore();

		if ($pagekey)
		{
			$members = $db->getField('fetchWolCount', array(
				'pagekey' => $pagekey,
				'who' => 'members'
			));
			$guests =  $db->getField('fetchWolCount', array(
				'pagekey' => $pagekey,
				'who' => 'guests'
			));
		}
		else
		{
			$members = $db->getField('fetchWolCount', array('who' => 'members'));
			$guests = $db->getField('fetchWolCount', array('who' => 'guests'));
		}

		$maxloggedin = $datastore->getValue('maxloggedin');
		$vboptions = $datastore->getValue('options');

		$totalonline = $members + $guests;

		// Update max loggedin users
		if (intval($maxloggedin['maxonline']) <= $totalonline)
		{
			$maxloggedin['maxonline'] = $totalonline;
			$maxloggedin['maxonlinedate'] = vB::getRequest()->getTimeNow();
			build_datastore('maxloggedin', serialize($maxloggedin), 1);
		}

		$recordusers = vb_number_format($maxloggedin['maxonline']);
		$recorddate = vbdate($vboptions['dateformat'], $maxloggedin['maxonlinedate']);
		$recordtime = vbdate($vboptions['timeformat'], $maxloggedin['maxonlinedate']);

		return array(
			'total' => $members + $guests,
			'members' => $members,
			'guests' => $guests,
			'recordusers' => $recordusers,
			'maxonlinedate' => $maxloggedin['maxonlinedate'],
			'recorddate' => $recorddate,
			'recordtime' => $recordtime,
		);
	}

	protected function checkWOLPermission($permission)
	{
		$loginuser = &vB::getCurrentSession()->fetch_userinfo();
		$usercontext = &vB::getUserContext($loginuser['userid']);
		return $usercontext->hasPermission('wolpermissions', $permission);
	}

	public static function buildSpiderList()
	{
		$spiders = array();

		$files = vB_Library::instance('product')->loadProductXmlList('spiders');
		foreach ($files AS $file)
		{
			$xmlobj = new vB_XML_Parser(false, $file);
			$spiderdata = $xmlobj->parse();

			if (is_array($spiderdata['spider']))
			{
				foreach ($spiderdata['spider'] AS $spiderling)
				{
					$addresses = array();
					$identlower = strtolower($spiderling['ident']);
					$spiders['agents']["$identlower"]['name'] = $spiderling['name'];
					$spiders['agents']["$identlower"]['type'] = $spiderling['type'];
					if (is_array($spiderling['addresses']['address']) AND !empty($spiderling['addresses']['address']))
					{
						if (empty($spiderling['addresses']['address'][0]))
						{
							$addresses[0] = $spiderling['addresses']['address'];
						}
						else
						{
							$addresses = $spiderling['addresses']['address'];
						}

						foreach ($addresses AS $key => $address)
						{
							if (in_array($address['type'], array('range', 'single', 'CIDR')))
							{
								$address['type'] = strtolower($address['type']);

								switch($address['type'])
								{
									case 'single':
										$ip2long = ip2long($address['value']);
										if ($ip2long != -1 AND $ip2long !== false)
										{
											$spiders['agents']["$identlower"]['lookup'][] = array(
												'startip' => $ip2long,
											);
										}
										break;

									case 'range':
										$ips = explode('-', $address['value']);
										$startip = ip2long(trim($ips[0]));
										$endip = ip2long(trim($ips[1]));
										if ($startip != -1 AND $startip !== false AND $endip != -1 AND $endip !== false AND $startip <= $endip)
										{
											$spiders['agents']["$identlower"]['lookup'][] = array(
												'startip' => $startip,
												'endip'   => $endip,
											);
										}
										break;

									case 'cidr':
										$ipsplit = explode('/', $address['value']);
										$startip = ip2long($ipsplit[0]);
										$mask = $ipsplit[1];
										if ($startip != -1 AND $startip !== false AND $mask <= 31 AND $mask >= 0)
										{
											$hostbits = 32 - $mask;
											$hosts = pow(2, $hostbits) - 1; // Number of specified IPs
											$endip = $startip + $hosts;
											$spiders['agents']["$identlower"]['lookup'][] = array(
												'startip' => $startip,
												'endip'   => $endip,
											);
										}
										break;
								}
							}
						}
					}

					$spiders['spiderstring'] .= ($spiders['spiderstring'] ? '|' : '') . preg_quote($spiderling['ident'], '#');
				}
			}

			unset($spiderdata, $xmlobj);
		}

		vB::getDatastore()->build('spiders', serialize($spiders), 1);

		return vB::getDatastore()->getValue('spiders');
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 103555 $
|| #######################################################################
\*=========================================================================*/
