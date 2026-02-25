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
* Class to handle interacting with the Stop Forum Spam service
*
* @package	vBulletin
*/
class vB_StopForumSpam
{
	use vB_Trait_NoSerialize;

	protected $options;

	/**
	* host
	*
	* @var	string
	*/
	protected $hostUrl = 'www.stopforumspam.com';

	protected static $instance;
	/**
	* Constructor
	*
	*/
	private function __construct()
	{
		$this->options = vB::getDatastore()->get_value('options');
	}

	/**
	 *	Enforces singleton use
	 */
	public static function instance()
	{
		if (empty(self::$instance))
		{
			self::$instance = new vB_StopForumSpam();
		}

		return self::$instance;
	}

	/**
	 * Submit spam
	 *
	 * @param	string Username
	 * @param	string Ip Address
	 * @param	string Text
	 * @param	string Email Address
	 *
	 */
	public function markAsSpam($username, $ip_addr, $evidence, $email)
	{
		if (!$this->options['vb_antispam_sfs_key'])
		{
			return;
		}

		$query = array(
			'username=' . urlencode($username),
			'ip_addr='  . urlencode($ip_addr),
			'evidence=' . urlencode($evidence),
			'email='    . urlencode($email),
			'api_key='  . urlencode($this->options['vb_antispam_sfs_key'])
		);

		$url = 'http://' . $this->hostUrl . '/add.php?' . implode('&', $query);
		$result = @json_decode($this->_submit($url), true);
	}

	/**
	 * @param	string	Username
	 * @param	string	IP Address
	 * @param	string	Email Address
	 *
	 * @return	bool	validity of request
	 */
	public function checkRegistration($username = '', $ipaddress = '', $email = '')
	{
		$query = array('f=json', 'unix=1');
		if ($username AND $this->options['vb_antispam_sfs_username'])
		{
			$query['username'] = 'username=' . urlencode($username);
		}
		if ($ipaddress AND $this->options['vb_antispam_sfs_ip'])
		{
			$query['ip'] = 'ip=' . urlencode($ipaddress);
		}
		if ($email AND $this->options['vb_antispam_sfs_email'])
		{
			$query['email'] = 'email=' . urlencode($email);
		}

		if (count($query) == 2)
		{	// No options are enabled so fall out of here
			return true;
		}

		$url = 'http://' . $this->hostUrl . '/api?' . implode('&', $query);
		$result = @json_decode($this->_submit($url), true);

		if (!$result OR !isset($result['success']))
		{
			return $this->options['vb_antispam_sfs_unavailable'];
		}

		$spammer = false;
		$maxconfidence = 0;
		if ($username AND $this->options['vb_antispam_sfs_username'] AND isset($result['username']['appears']) AND $result['username']['appears'] > 0)
		{
			$spammer = true;
			$minDaysPast = floor((vB::getRequest()->getTimeNow() - $result['username']['lastseen']) / 86400);
			$maxConfidence = $result['username']['confidence'];
		}

		if ($ipaddress AND $this->options['vb_antispam_sfs_ip'] AND isset($result['ip']['appears']) AND $result['ip']['appears'] > 0)
		{
			$allow = false;
			if ($whitelist = trim($this->options['vb_antispam_sfs_iplist']))
			{
				$addresses = preg_split('#\s+#', $whitelist, -1, PREG_SPLIT_NO_EMPTY);
				foreach ($addresses AS $allowed_ip)
				{
					if (strpos($allowed_ip, '*') === false AND $allowed_ip[strlen($allowed_ip) - 1] != '.' AND substr_count($allowed_ip, '.') < 4)
					{
						$allowed_ip .= '.';
					}

					$allowed_ip_regex = str_replace('\*', '(.*)', preg_quote($allowed_ip, '#'));
					if (preg_match('#^' . $allowed_ip_regex . '#U', $ipaddress))
					{
						$allow = true;
					}
				}
			}

			if (!$allow)
			{
				$spammer = true;
				$daysPast = floor((vB::getRequest()->getTimeNow() - $result['ip']['lastseen']) / 86400);
				$minDaysPast = isset($minDaysPast) ? min($minDaysPast, $daysPast) : $daysPast;
				$maxConfidence = isset($maxConfidence) ? max($maxConfidence, $result['ip']['confidence']) : $result['ip']['confidence'];
			}
		}

		if ($email AND $this->options['vb_antispam_sfs_email'] AND isset($result['email']['appears']) AND $result['email']['appears'] > 0)
		{
			$allow = false;
			if ($whitelist = trim($this->options['vb_antispam_sfs_emaillist']))
			{
				$emails = preg_split('#\s+#', $whitelist, -1, PREG_SPLIT_NO_EMPTY);
				foreach ($emails AS $_email)
				{
					if (strtolower($_email) == strtolower($email))
					{
						$allow = true;
					}
				}
			}

			if (!$allow)
			{
				$spammer = true;
				$daysPast = floor((vB::getRequest()->getTimeNow() - $result['email']['lastseen']) / 86400);
				$minDaysPast = isset($minDaysPast) ? min($minDaysPast, $daysPast) : $daysPast;
				$maxConfidence = isset($maxConfidence) ? max($maxConfidence, $result['email']['confidence']) : $result['email']['confidence'];
			}
		}

		if ($spammer)
		{
			if (!$this->options['vb_antispam_sfs_days'] OR $minDaysPast <= $this->options['vb_antispam_sfs_days'])
			{
				return false;
			}

			if ($maxConfidence >= $this->options['vb_antispam_sfs_confidence'])
			{
				return false;
			}
		}

		return true;
	}

	/**
	* Submits a request to the Stop Forum Post service
	*
	* @access	private
	*
	* @param	string	URL to submit to
	*
	* @return	string	Data returned by Stop Forum Spam
	*/
	protected function _submit($url)
	{
		$vurl = vB::getUrlLoader();
		//no idea if this is actually needed, but I don't want to muck with prior behavior here.
		$vurl->setOption(vB_Utility_Url::CLOSECONNECTION, 1);
		$result = $vurl->get($url);
		return $result['body'];
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 102785 $
|| #######################################################################
\*=========================================================================*/
