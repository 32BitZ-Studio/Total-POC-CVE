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

class vB_Session_Api extends vB_Session
{
	/**
	 *
	 * @var array
	 */
	protected $apiclient;
	private static $vBApiParamsToVerify = array();
	private static $vBApiRequests = array();

	public static function getSession($userId, $sessionHash = '', $dBAssertor = null, $datastore = null, $config = null)
	{
		$dBAssertor = ($dBAssertor) ? $dBAssertor : vB::getDbAssertor();
		$datastore = ($datastore) ? $datastore : vB::getDatastore();
		$config = ($config) ? $config : vB::getConfig();

		$session = new vB_Session_Api($dBAssertor, $datastore, $config, $sessionHash, self::$vBApiParamsToVerify, self::$vBApiRequests);
		$session->set('userid', $userId);
		$session->fetch_userinfo();

		return $session;
	}

	public static function createSession($vbApiParamsToVerify, $vBApiRequests)
	{
		self::$vBApiParamsToVerify = $vbApiParamsToVerify;
		self::$vBApiRequests = $vBApiRequests;
		$assertor = vB::getDbAssertor();
		$datastore = vB::getDatastore();
		$config = vB::getConfig();

		$session = new vB_Session_Api($assertor, $datastore, $config, '', $vbApiParamsToVerify, $vBApiRequests);

		return $session;
	}

	/**
	 *
	 * @param vB_dB_Assertor $dBAssertor
	 * @param vB_Datastore $datastore
	 * @param array $config
	 * @param array $vbApiParamsToVerify
	 * @param array $vBApiRequests
	 */
	// todo: do we need something else here?
	public function __construct($dBAssertor, $datastore, $config, $sessionhash = '', $vbApiParamsToVerify = array(), $vBApiRequests = array())
	{
		// we need this for validation, so can't wait for parent constructor
		$this->dBAssertor = & $dBAssertor;
		$this->datastore = & $datastore;
		$this->config = & $config;
		// Below call will either set $this->apiclient with the matched apiclient record, or throw an exception.
		$this->validateApiSession($vbApiParamsToVerify, $vBApiRequests);

		/*
			VBV-12249 was broken by VBV-13651. It seems that before r82998, the behavior for API sessions was
			to ALWAYS try to remember a session if a not-expired session was not found. The changes in VBV-13651
			seems to have completely broken this, so in order to force API sessions to always try to remember
			the session, we force the 'remembermetoken' to evaluate not empty, and not == 'facebook' (so boolean
			true won't work, thanks PHP)
			See the JIRAs, commits, & vB_session::loadExistingSession() for details.
		 */
		$restoreSessionInfo = array('remembermetoken' => 'hello, this is api');
		parent::__construct($dBAssertor, $datastore, $config, $sessionhash, $restoreSessionInfo);
	}

	public function getApiClient()
	{
		return $this->apiclient;
	}

	public function refetchApiClientFromDB()
	{
		if ($this->apiclient['apiclientid'])
		{
			$client = $this->dBAssertor->getRow('apiclient', array('apiclientid' => $this->apiclient['apiclientid']));
			$this->apiclient = $client;
		}
	}

	protected function validateApiSession($vbApiParamsToVerify, $vBApiRequests)
	{
		// VB API Request Signature Verification
		$options = $this->datastore->getValue('options');

		// API disabled
		if (!$options['enableapi'] OR !$options['apikey'])
		{
			throw new vB_Exception_Api('api_disabled');
		}

		if (!empty($vBApiRequests['api_c']))
		{
			// Get client information from api_c. api_c has been intvaled in api.php
			$client = $this->dBAssertor->getRow('apiclient', array('apiclientid' => $vBApiRequests['api_c']));
			if (!$client)
			{
				throw new vB_Exception_Api('invalid_clientid');
			}

			// An accesstoken is passed but invalid
			if ($vBApiRequests['api_s'] AND $vBApiRequests['api_s'] != $client['apiaccesstoken'])
			{
				throw new vB_Exception_Api('invalid_accesstoken');
			}

			$signtoverify = md5(http_build_query($vbApiParamsToVerify, '', '&') . $vBApiRequests['api_s'] . $client['apiclientid'] . $client['secret'] . $options['apikey']);
			if ($vBApiRequests['api_sig'] !== $signtoverify)
			{
				throw new vB_Exception_Api('invalid_api_signature');
			}
			else
			{
				$this->apiclient = $client;
			}

			if ($options['enableapilog'])
			{
				$hide = array(
					'vb_login_password',
					'vb_login_md5password',
					'vb_login_md5password_utf',
					'password',
					'password_md5',
					'passwordconfirm',
					'passwordconfirm_md5',
					/* Not currently used by mapi
					but might be in the future */
					'currentpassword',
					'currentpassword_md5',
					'newpassword',
					'newpasswordconfirm',
					'newpassword_md5',
					'newpasswordconfirm_md5',
				);

				$post_copy = $_POST;

				foreach ($hide AS $param)
				{
					if ($post_copy[$param])
					{
						$post_copy[$param] = '*****';
					}
				}

				$request = vB::getRequest();
				$this->dBAssertor->insertIgnore('apilog', array(
					'apiclientid'	=> $vBApiRequests['api_c'],
					'method'      => $vBApiRequests['api_m'],
					'paramget'		=> serialize($_GET),
					'parampost'		=> ($options['apilogpostparam']) ? serialize($post_copy) : '',
					'ipaddress'		=> $request->getAltIp(),
					'dateline'		=> $request->getTimeNow(),
				));
			}
		}
		// api.init is a special method that is able to generate new client info.
		elseif ($vBApiRequests['api_m'] != 'api.init' && ($vBApiRequests['api_version'] < VB5_API_VERSION_START && $vBApiRequests['api_m'] != 'api_init'))
		{
			throw new vB_Exception_Api('missing_api_signature');
		}
	}

	protected function fetchStoredSession($sessionhash, $restoreSessionInfo = array())
	{
		if ($this->apiclient['apiaccesstoken'])
		{
			$request = vB::getRequest();
			$options = $this->datastore->getValue('options');
			$test = (
				$this->vars = $this->dBAssertor->getRow('session',
					array(
						vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
						vB_dB_Query::CONDITIONS_KEY => array(
							array(
								'field' => 'apiaccesstoken',
								'value' => $this->apiclient['apiaccesstoken'],
								'operator' => vB_dB_Query::OPERATOR_EQ
							),
							array(
								'field' => 'lastactivity',
								'value' => ($request->getTimeNow() - $options['cookietimeout']),
								'operator' => vB_dB_Query::OPERATOR_GT
							),
							array(
								'field' => 'idhash',
								'value' => $this->getSessionIdHash(),
								'operator' => vB_dB_Query::OPERATOR_EQ
							)
						),
					)
				)
				AND
				$this->fetch_substr_ip($this->vars['host']) == $this->fetch_substr_ip($request->getSessionHost())
			);

			return $test;
		}
		else
		{
			// check if parent can fetch it using sessionhash
			return parent::fetchStoredSession($sessionhash, $restoreSessionInfo);
		}
	}

	/**
	 *
	 * @param array $restoreSessionInfo This is ignored (see parent class for details of what it usually does)
	 * @param array $useroptions
	 */
	protected function rememberSession($restoreSessionInfo, $useroptions)
	{
		// API 'Remember Me'. UserID is stored in apiclient table.
		if ($this->apiclient['userid'])
		{
			$userinfo = fetch_userinfo($this->apiclient['userid'], $useroptions, $languageid);

			// combination is valid
			if (!empty($this->vars['sessionhash']))
			{
				// old session still exists; kill it
				$this->dBAssertor->delete('session', array('sessionhash' => $this->vars['sessionhash']), TRUE);
			}

			$this->vars = $this->fetch_session($userinfo['userid']);
			$this->created = true;
			$this->userinfo = & $userinfo;

			return array ('auth' => true, 'remembermetoken' => '');
		}

		return array ('auth' => false, 'remembermetoken' => '');
	}

	protected function fetch_session($userid = 0)
	{
		$session = parent::fetch_session($userid);

		if ($this->apiclient['apiaccesstoken'])
		{
			// Access Token is valid here because it's validated in init.php
			$accesstoken = $this->apiclient['apiaccesstoken'];
		}
		else
		{
			// Generate an accesstoken
			$accesstoken = fetch_random_string();

			$this->apiclient['apiaccesstoken'] = $accesstoken;
		}

		$session['apiaccesstoken'] = $accesstoken;

		if ($this->apiclient['apiclientid'])
		{
			$session['apiclientid'] = intval($this->apiclient['apiclientid']);
			// Save accesstoken to apiclient table
			$this->dBAssertor->update('apiclient',
				array(
					'apiaccesstoken' => $accesstoken,
					'lastactivity' => vB::getRequest()->getTimeNow(),
				),
				array('apiclientid' => $session['apiclientid'])
			);
		}

		return $session;
	}

	public function save()
	{
		// This function exists solely to set the lastactivity on apiclient record as well as the session record
		// whenever we update the lastactivity. Note that vB_Session construction will always update the lastactivity
		// unless it failed to restore a session and had to create a completely new session.
		// So login_login SHOULD trigger this.
		if ($this->apiclient['apiclientid'] AND !empty($this->changes["lastactivity"]))
		{
			$lastactivity = intval($this->vars["lastactivity"]);
			$check = $this->dBAssertor->update('apiclient',
				array('lastactivity' => $lastactivity),  // value
				array('apiclientid' => $this->apiclient['apiclientid']) // condition
			);
		}

		parent::save();
	}

	public function validateCpsession($updatetimeout = true)
	{
		return true;
	}

}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 102401 $
|| #######################################################################
\*=========================================================================*/
