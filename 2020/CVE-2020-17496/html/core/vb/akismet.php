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

/*
Example code
$akismet = new vB_Akismet($vbulletin);
$akismet->akismetBoard = 'http://dev.vbulletin.com/vbblog/';
$akismet->akismetKey = '<ENTER YOUR OWN KEY>';

*/


/**
* Class to handle interacting with the Akismet service
*
* @package	vBulletin
*/
class vB_Akismet
{
	use vB_Trait_NoSerialize;

	protected $options;

	protected $hostUrl = 'rest.akismet.com';

	protected $verified = null;

	/**
	* Akismet version, used in URI
	*
	* @var	string
	*/
	protected $akismetVersion = '1.1';

	/**
	* Akismet key
	*
	* @var	string
	*/
	protected $akismetKey = '';

	/**
	* Akismet board URL
	*
	* @var	string
	*/
	protected $akismetBoard = '';

	/**
	* Akismet built URL
	*
	* @var	string
	*/
	protected $_akismetApiUrl = null;

	protected static $instance;

	/**
	 * Constructor
	 */
	private function __construct()
	{
		$this->options = vB::getDatastore()->getValue('options');
		if (!isset($this->options['vb_antispam_type']) OR empty($this->options['vb_antispam_key']))
		{
			$this->verified = false;
		}
		else
		{
			$this->bburl = $this->options['bburl'];
			$this->akismetKey = $this->options['vb_antispam_key'];
		}

		//validate the keys.
		$this->_build();

	}

	/**
	 *	Enforces singleton use
	 */
	public static function instance()
	{
		if (empty(self::$instance))
		{
			self::$instance = new vB_Akismet();
		}

		return self::$instance;
	}

	/**
	 * Set params
	 *
	 * @param	array	Params set before function call
	 * @return	array	Params
	 */
	protected function setParams($params)
	{
		if (!isset($params['user_ip']))
		{
			$params['user_ip'] = $_SERVER['REMOTE_ADDR'];
		}

		if (!isset($params['user_agent']))
		{
			if (defined('USER_AGENT'))
			{
				$params['user_agent'] = USER_AGENT;
			}
			else
			{
				$params['user_agent'] = $_SERVER['HTTP_USER_AGENT'];
			}
		}

		if (!isset($params['referrer']))
		{
			if (defined('HTTP_REFERER'))
			{
				$params['referrer'] = HTTP_REFERER;
			}
			else if (!empty($_SERVER['HTTP_REFERER']))
			{
				$params['referrer'] = $_SERVER['HTTP_REFERER'];
			}
			else
			{
				$params['referrer'] = $this->options['bburl'];
			}
		}

		$params['blog'] = $this->bburl;

		return $params;
	}

	/**
	* Makes a verification call to Aksimet to check content
	*
	* @param	array	Array of keys and values, http://akismet.com/development/api/
	*
	* @return	string	spam or ham
	*/
	public function verifyText($params)
	{
		if (!$this->verified)
		{
			return true;
		}

		//$params['comment_author'] = 'viagra-test-123';

		$params = $this->setParams($params);
		$result = $this->_submit($this->_akismetApiUrl . '/comment-check', $params);
		return (strpos($result, 'true') !== false) ? 'spam' : 'ham';
	}

	/**
	* Identify a missed item as spam
	*
	* @param	array	Array of keys and values, http://akismet.com/development/api/
	*
	* @return	string	direct result from API call
	*/
	public function markAsSpam($params)
	{
		if (!$this->verified)
		{
			return true;
		}

		if (!$this->_build())
		{
			return false;
		}
		$params = $this->setParams($params);

		$result = $this->_submit($this->_akismetApiUrl . '/submit-spam', $params);
		return $result;
	}

	/**
	* Identify a missed identified item as ham (false positive)
	*
	* @param	array	Array of keys and values, http://akismet.com/development/api/
	*
	* @return	string	direct result from API call
	*/
	public function markAsHam($params)
	{
		if (!$this->verified)
		{
			return true;
		}

		if (!$this->_build())
		{
			return false;
		}
		$params = $this->setParams($params);

		$result = $this->_submit($this->_akismetApiUrl . '/submit-ham', $params);
		return $result;
	}

	/**
	* Verify that the supplied Akismet key is valid and build the API URL
	*
	* @return	boolean	True if the building succeeded else false
	*/
	protected function _build()
	{
		if ($this->_akismetApiUrl === null)
		{
			// deal with new setting if scanning is disabled
			if (!$this->options['vb_antispam_type'])
			{
				return false;
			}

			$check_key = 'http://' . $this->hostUrl . '/' . $this->akismetVersion . '/verify-key';
			// if they entered the key in vB Options we'll assume its correct.
			if ($this->akismetKey == $this->options['vb_antispam_key'] OR strpos($this->_submit($check_key, array('key' => $this->akismetKey)), 'invalid') === false)
			{
				$this->_akismetApiUrl = 'http://' . $this->akismetKey . '.' . $this->hostUrl . '/' . $this->akismetVersion;
				$this->verified = true;
			}
		}

		return true;
	}

	/**
	* Submits a request to the Akismet service (POST)
	*
	* @access	private
	*
	* @param	string	URL to submit to
	* @param	array	Array of data to submit
	*
	* @return	string	Data returned by Akismet
	*/
	protected function _submit($submitUrl, $params)
	{
		//$params['is_test'] = 1;

		$vurl = vB::getUrlLoader();
		//no idea if this is actually needed, but I don't want to muck with prior behavior here.
		$vurl->setOption(vB_Utility_Url::CLOSECONNECTION, 1);
		$result = $vurl->post($submitUrl, $params);
		return $result['body'];
	}
}
/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 102785 $
|| #######################################################################
\*=========================================================================*/
