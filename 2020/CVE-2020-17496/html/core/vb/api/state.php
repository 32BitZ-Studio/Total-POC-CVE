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
 * vB_Api_State
 *
 * @package vBApi
 * @access public
 */
class vB_Api_State extends vB_Api
{
	protected $disableWhiteList = array('checkBeforeView');

	/*
	 * Route
	 *
	 * @var	string
	 */
	protected $route = array();

	/*
	 * Route Segments
	 *
	 * @var	string
	 */
	protected $segments = array();

	protected $state;
	/*
	 * Valid Locations
	 *
	 * @var	array
	 */
	protected $location = array(
		'login'    => false,
		'ajax'     => false,
		'settings' => false,
		'lostpw'   => false,
		'admincp'  => false,
	);

	/*
	 * Locally cached checkIpBan() results. Sometimes we call checkState() multiple times,
	 * and checkIpBan() can be slow. No reason to process it more than once.
	 *
	 * @var	array
	 */
	protected $checkedIpResults = array();

	protected function __construct()
	{
		parent::__construct();
		$this->assertor = vB::getDbAssertor();
	}

	public function checkBeforeView($route = null)
	{
		if (!empty($route))
		{
			$this->setRoute($route);
		}
		else if (isset($this->state))
		{
			return $this->state;
		}

		$this->state = false;

		if (
			(
				($result = $this->checkForumClosed()) !== false
				AND
				(empty($route) OR !$this->location['admincp'])
			)
			OR
			(!$this->location['admincp'] AND
				(
					($result = $this->checkForumBusy()) !== false
					OR
					($result = $this->checkPasswordExpiry()) !== false
					OR
					($result = $this->checkProfileUpdate()) !== false
					OR
					($result = $this->checkIpBan(IPADDRESS)) !== false
					OR
					($result = $this->checkCSRF()) !== false
				)
			)
		)
		{
			$phrasevars = array('message');
			if (isset($result['error']))
			{
				$phrasevars[] = $result['error'];
			}
			$phrases =  vB_Api::instanceInternal('phrase')->fetch($phrasevars);
			$returnvalue = array('title' => $phrases['message']);
			if (isset($result['option']))
			{
				$returnvalue['msg'] = vB::getDatastore()->getOption($result['option']);
				$returnvalue['state'] = $result['option'];
				$this->state = $returnvalue;
			}
			else if (isset($result['error']))
			{
				if (isset($result['args']))
				{
					$returnvalue['msg'] = vsprintf($phrases[$result['error']], $result['args']);
				}
				else
				{
					$returnvalue['msg'] = $phrases[$result['error']];
				}
				$returnvalue['state'] = $result['error'];
				$this->state = $returnvalue;
			}
		}

		return $this->state;
	}

	/**
	 * Set route info since these functions are called during the route verification process
	 *
	 * @param	string	Route Controller
	 * @param	string	Route Action
	 *
	 */
	protected function setRoute($route)
	{
		$this->route = $route;
		$this->route['routeguid'] = isset($this->route['routeguid']) ? strtolower($this->route['routeguid']) : '';
		$this->route['controller'] = isset($this->route['controller']) ? strtolower($this->route['controller']) : '';
		$this->route['action'] = isset($this->route['action']) ? strtolower($this->route['action']) : '';

		$this->setLocation();
	}

	/**
	 * Clears the state check variable. Needed during unit tests but otherwise should never be needed.
	 */
	public function clearStateCheck()
	{
		unset($this->state);
	}
	/*
	 * Set location infomation
	 *
	 */
	protected function setLocation()
	{
		$this->location['login'] = ($this->route['controller'] == 'auth');

		$this->location['ajax'] = ($this->route['routeguid'] == 'vbulletin-4ecbdacd6a3d43.49233131');
		$this->location['lostpw'] = ($this->route['routeguid'] == 'vbulletin-4ecbdacd6a6f13.66635712');
		$this->location['admincp'] = ($this->route['routeguid'] == 'vbulletin-4ecbdacd6aa7c8.79724467');
		$this->location['contactus'] = ($this->route['routeguid'] == 'vbulletin-4ecbdacd6a6f13.66635713');

		$this->location['settings'] = (
			($this->route['routeguid'] == 'vbulletin-4ecbdacd6a9307.24480802')
				OR
			($this->route['controller'] == 'profile' AND $this->route['action'] == 'actionsaveaccountsettings')
		);

		if ($this->location['ajax'] AND isset($this->route['arguments']['route']))
		{
			// Split the route and also provide full lowercase version (ajax calls).
			$this->segments = explode('/', strtolower($this->route['arguments']['route']));
			$this->segments['route'] = implode('/', $this->segments);
		}
	}

	/*
	 * Check CSRF
	 *
	 */
	final public function checkCSRF()
	{
		/*
			Keep this function in sync with vB5_ApplicationAbstract::checkCSRF()
		 */
		if (!empty($_SERVER['REQUEST_METHOD']) AND strtoupper($_SERVER['REQUEST_METHOD']) == 'POST')
		{
			$userinfo = vB_User::fetchUserinfo();
			if ($userinfo['userid'] > 0 AND (!defined('CSRF_PROTECTION') OR (defined('CSRF_PROTECTION') AND CSRF_PROTECTION === true)))
			{
				if (!$this->location['login']) // check skip list goes here
				{
					if (!isset($_POST['securitytoken']))
					{
						$_POST['securitytoken'] = '';
					}
					if (!vB_User::verifySecurityToken($_POST['securitytoken'], $userinfo['securitytoken_raw']))
					{
						switch ($_POST['securitytoken'])
						{
							case '':
								/*
									We can reach this during a file upload if the upload size exceeded PHP's post_max_size,
									because then $_POST & $_FILES are emptied, so we lose the security token.
									Helpfully, this means you can't check $_FILES['error'], so we have to guess.
								*/
								$maxPostSize = $this->getPostMaxSizeBytes();
								if ($maxPostSize AND isset($_SERVER["CONTENT_LENGTH"]))
								{
									if ($maxPostSize < $_SERVER["CONTENT_LENGTH"])
									{
										return array('error' => 'php_max_post_size_exceeded');
									}
								}
								return array('error' => 'security_token_missing');
							case 'guest':
								return array('error' => 'security_token_guest');
							case 'timeout':
								return array('error' => 'security_token_timeout');
							default:
								return array('error' => 'security_token_invalid');
						}
					}
				}
			}
		}

		return false;
	}

	private function getPostMaxSizeBytes()
	{
		// todo: make this a global function?
		$maxPostSize = ini_get('post_max_size');

		if (empty($maxPostSize))
		{
			return 0;
		}

		$len = strspn($maxPostSize, '1234567890');
		$number = (int) substr($maxPostSize, 0, $len);
		$units = strtolower(substr($maxPostSize, $len));

		switch($units)
		{
			case 'g':
			case 'gb':
				$number *= 1024;
			case 'm':
			case 'mb':
				$number *= 1024;
			case 'k':
			case 'kb':
				$number *= 1024;
			default:
				break;
		}

		return $number;

	}

	/**
	 * Check if Forum is closed. Allows administrators and login actions to bypass.
	 *
	 * @return	mixed	error phrase on success, false on failure
	 */
	protected function checkForumClosed()
	{
		if (!defined('BYPASS_FORUM_DISABLED')
				AND
			!vB::getDatastore()->getOption('bbactive')
				AND
			!vB::getUserContext()->isAdministrator()
				AND
			!$this->location['login'] // Login
		)
		{
			return array('option' => 'bbclosedreason');
		}
		return false;
	}

	/*
	 * Check if forum is overloaded. Allow administrators and login actions to bypass.
	 *
	 * @return	mixed	error phrase on success, false on failure
	 */
	protected function checkForumBusy()
	{
		if ($this->serverOverloaded() AND !vB::getUserContext()->isAdministrator() AND !$this->location['login'])
		{
			return array('error' => 'toobusy');
		}
		return false;
	}

	/*
	 * Check profile fields
	 */
	protected function checkProfileUpdate()
	{
		if (vB::getCurrentSession()->get('profileupdate') AND !$this->location['settings'] AND !$this->location['login'] AND
			!vB::getUserContext()->isAdministrator())
		{
			return array(
				'error' => 'updateprofilefields',
				'args' => array(
					vB::getDatastore()->getOption('frontendurl') . '/settings/account'
				)
			);
		}
		return false;
	}

	/*
	 * Check IP Ban
	 */
	protected function checkIpBan($user_ipaddress)
	{
		$user_ipaddress = $user_ipaddress . '.';

		if (isset($this->checkedIpResults[$user_ipaddress]))
		{
			return $this->checkedIpResults[$user_ipaddress];
		}

		$ajaxroute = $this->segments['route'] ?? '';

		$excluded =
		(
			!empty($this->location['contactus'])
			OR $ajaxroute == '/api/phrase/fetch'
			OR $ajaxroute == '/api/contactus/sendmail'
		);
		if ($excluded)
		{
			// Skipping setting the result for an excluded route. For one, this check is fast,
			// for two, if we, for some reason, change routes between excluded & included, cached
			// result won't cause discrepancies from previous, uncached behavior.
			return false;
		}

		$this->checkedIpResults[$user_ipaddress] = false;
		$options = vB::getDatastore()->getValue('options');

		if ($options['enablebanning'] == 1 AND $options['banip'] = trim($options['banip']))
		{
			$isBanned = false;
			//either accept whitespace delimeted or comma delimited.  The latter is undocumented
			//but allowed because users don't read.
			$addresses = preg_split('#(\s+|\s*,\s*)#', $options['banip'], -1, PREG_SPLIT_NO_EMPTY);
			foreach ($addresses AS $banned_ip)
			{
				$bannedStrlen = strlen($banned_ip);

				//this is a rough check to avoid weird input.  If our prospective IP to ban
				//is longer than 250 characters then I don't know what it is, but it's not an
				//IP address.  This will avoid potential problems with too long RE strings below
				//We don't want to make this bound too tight because we don't have to and if
				//IP addresses get longer then it could cause weird bugs later.
				if($bannedStrlen > 250)
				{
					continue;
				}

				// Only run preg_match() if the banned IP has a wild card.
				$hasWildCard = (strpos($banned_ip, '*') !== false);
				if ($hasWildCard)
				{
					$banned_ip_regex = str_replace('\*', '(.*)', preg_quote($banned_ip, '#'));
					if (preg_match('#^' . $banned_ip_regex . '#U', $user_ipaddress))
					{
						$isBanned = true;
						break;
					}
				}
				else
				{
					// This dot suffixing is needed for the "prefix match" logic, so that
					// banned_ip = "12.34.56" or "12.34.56." will match "12.34.56.7" but
					// not "12.34.567.8"
					if ($banned_ip[$bannedStrlen - 1] != '.')
					{
						$banned_ip .= '.';
					}

					if (strpos($user_ipaddress, $banned_ip) === 0)
					{
						$isBanned = true;
						break;
					}
				}
			}

			if ($isBanned)
			{
				$this->checkedIpResults[$user_ipaddress] = array(
					'error' => 'banip',
					'args' => vB5_Route::buildUrl('contact-us|fullurl')
				);
			}
		}

		return $this->checkedIpResults[$user_ipaddress];
	}

	/*
	 * Check if user's password is expired
	 *
	 * @return	mixed	error phrase name on success, false on failure
	 */
	protected function checkPasswordExpiry()
	{
		$usergroupid = vB::getCurrentSession()->fetch_userinfo_value('usergroupid');
		$usergroup = vB_Library::instance('usergroup')->fetchUsergroupByID($usergroupid);
		$passwordexpires = $usergroup['passwordexpires'];

		if (vB::getCurrentSession()->fetch_userinfo_value('userid') AND $passwordexpires)
		{
			$passworddaysold = floor((vB::getRequest()->getTimeNow() - vB::GetCurrentSession()->fetch_userinfo_value('passworddate')) / 86400);

			if ($passworddaysold >= $passwordexpires)
			{
				if (!($this->location['settings']
					OR $this->location['login']
					OR $this->location['lostpw']
				))
				{
					return array(
						'error' => 'passwordexpired',
						'args' => array(
							$passworddaysold,
							vB::getDatastore()->getOption('frontendurl') . '/settings/account'
					));
				}
			}
		}
		return false;
	}

	/**
	 * Determines if the server is over the defined load limits
	 *
	 * @return	bool
	*/
	protected function serverOverloaded()
	{
		$loadcache = vB::getDatastore()->getValue('loadcache');

		if (strtoupper(substr(PHP_OS, 0, 3)) != 'WIN' AND vB::getDatastore()->getOption('loadlimit') > 0)
		{
			if (!is_array($loadcache) OR $loadcache['lastcheck'] < (vB::getRequest()->getTimeNow() - vB::getDatastore()->getOption('recheckfrequency')))
			{
				$this->updateLoadavg();
			}

			if ($loadcache['loadavg'] > vB::getDatastore()->getOption('loadlimit'))
			{
				return true;
			}
		}

		return false;
	}

	/*
	 * Update the loadavg cache
	 *
	 */
	protected function updateLoadavg()
	{
		$loadcache = array();

		if (function_exists('exec') AND $stats = @exec('uptime 2>&1') AND trim($stats) != '' AND preg_match('#: ([\d.,]+),?\s+([\d.,]+),?\s+([\d.,]+)$#', $stats, $regs))
		{
			$loadcache['loadavg'] = $regs[2];
		}
		else if (@file_exists('/proc/loadavg') AND $filestuff = @file_get_contents('/proc/loadavg'))
		{
			$loadavg = explode(' ', $filestuff);
			$loadcache['loadavg'] = $loadavg[1];
		}
		else
		{
			$loadcache['loadavg'] = 0;
		}

		$loadcache['lastcheck'] = vB::getRequest()->getTimeNow();
		vB::getDatastore()->build('loadcache', serialize($loadcache), 1);
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 101893 $
|| #######################################################################
\*=========================================================================*/
