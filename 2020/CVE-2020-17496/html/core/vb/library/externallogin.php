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
 * @package vBLibrary
 *
 */

/**
 * vB_Library_Auth
 *
 * @package vBLibrary
 * @access public
 */
class vB_Library_ExternalLogin extends vB_Library
{
	use vB_Trait_NoSerialize;

	protected $loginlibraryid;
	protected $productid;


	public function __construct()
	{
		$this->getLoginLibraryId();
	}

	final public function createLoginLibraryId($productid = "", $class = "")
	{
		if (empty($productid) OR empty($class))
		{
			return false;
		}

		if (empty($this->getLoginLibraryId($productid)))
		{
			$values = array(
				'productid' => $productid,
				'class' => $class,
			);
			$values[vB_dB_Query::TYPE_KEY] = vB_dB_Query::QUERY_INSERT;
			// insert new
			$assertor = vB::getDBAssertor();
			$result = $assertor->assertQuery('vBForum:loginlibrary', $values);
		}

		return $this->getLoginLibraryId($productid);
	}

	final protected function getLoginLibraryId($productid = "")
	{
		if (empty($productid))
		{
			$productid = $this->productid;
		}

		if (!empty($this->loginlibraryid))
		{
			return $this->loginlibraryid;
		}
		else if (!empty($productid))
		{
			$assertor = vB::getDBAssertor();
			$check = $assertor->getRow('vBForum:loginlibrary', array('productid' => $productid));
			if (!empty($check['loginlibraryid']))
			{
				$this->loginlibraryid = $check['loginlibraryid'];
			}

			 return $this->loginlibraryid;
		}

		// not installed.
		return null;
	}

	protected function checkLinkSuccess($newUserAuth)
	{
		if (!empty($newUserAuth['external_userid']))
		{
			return true;
		}

		return false;
	}

	final protected function updateUserAuthRecord($data)
	{
		if (empty($data['userid']))
		{
			$data['userid'] =  vB::getCurrentSession()->get('userid');
		}
		$libid = $this->getLoginLibraryId();
		if (empty($data['userid']) OR empty($libid))
		{
			return array(
				'result' => false,
				'error' => 'missing userid or library id',
			);
		}

		$data['loginlibraryid'] = $libid;

		if (isset($data['additional_params']) AND is_array($data['additional_params']))
		{
			$data['additional_params'] = json_encode($data['additional_params']);
		}


		$assertor = vB::getDBAssertor();
		$conditions = array('userid' => $data['userid'], 'loginlibraryid' => $data['loginlibraryid']);

		/*
			Keep these in sync with table definition.
		 */
		$values = array();
		$acceptedKeys = array(
			'userid',
			'loginlibraryid',
			'external_userid',
			'token',
			'token_secret',
			'additional_params',
		);
		foreach ($acceptedKeys AS $__k)
		{
			if (isset($data[$__k]))
			{
				$values[$__k] = $data[$__k];
			}
		}

		$type = 'update';
		$check = $assertor->getRow('vBForum:userauth', $conditions);
		if (!empty($check))
		{
			// update existing
			$result = $assertor->update(
				'vBForum:userauth',
				$values, // values
				$conditions
			);
		}
		else
		{
			$type = 'insert';
			$values[vB_dB_Query::TYPE_KEY] = vB_dB_Query::QUERY_INSERT;
			// insert new
			$result = $assertor->assertQuery('vBForum:userauth', $values);
		}

		return array(
			'result' => $result,
			'type' => $type,
		);
	}

	final protected function checkExternalUseridAvailability($external_userid)
	{
		$assertor = vB::getDBAssertor();
		$check = $assertor->getRow('vBForum:userauth', array('external_userid' => $external_userid));
		return empty($check);
	}

	final public function getUserAuthRecord($external_userid = null, $token = null, $userid = null)
	{
		if (empty($userid))
		{
			$userid = vB::getCurrentSession()->get('userid');
		}
		$libid = $this->getLoginLibraryId();
		if ((empty($userid) AND empty($external_userid)) OR empty($libid))
		{
			return array();
		}
		else
		{
			$assertor = vB::getDBAssertor();
			/*
				We have 2 possible ways to fetch a unique userauth record:
					PRIMARY KEY `user_platform_constraint`  (`userid`, `loginlibraryid`),
					UNIQUE KEY `platform_extuser_constraint`  (`loginlibraryid`, `external_userid`),
			 */
			$conditions = array('loginlibraryid' => $libid);
			if (!empty($userid) AND empty($external_userid))
			{
				$conditions['userid'] = $userid;
			}
			if (!is_null($external_userid))
			{
				$conditions['external_userid'] = $external_userid;
			}
			if (!is_null($token))
			{
				$conditions['token'] = $token;
			}
			$check = $assertor->getRow('vBForum:userauth', $conditions);
			if (!empty($check))
			{
				$check['additional_params'] = json_decode($check['additional_params'], true);
				if (empty($check['additional_params']))
				{
					$check['additional_params'] = array();
				}
				return $check;
			}
		}

		return array();
	}

	final protected function deleteUserAuthRecord()
	{
		$userid = vB::getCurrentSession()->get('userid');
		$libid = $this->getLoginLibraryId();
		if (empty($userid) OR empty($libid))
		{
			return false;
		}
		else
		{
			$assertor = vB::getDBAssertor();
			$conditions = array('userid' => $userid, 'loginlibraryid' => $libid);
			$check = $assertor->delete('vBForum:userauth', $conditions);
			return $check;
		}
	}


	final protected function updateSessionAuthRecord($data)
	{
		$libid = $this->getLoginLibraryId();
		if (empty($libid))
		{
			return array(
				'result' => false,
				'error' => 'missing loginlibraryid',
			);
		}

		$session = vB::getCurrentSession();
		if (empty($session))
		{
			return array(
				'result' => false,
				'error' => 'session not found',
			);
		}

		$sessionhash = $session->get('dbsessionhash');
		if (empty($sessionhash))
		{
			return array(
				'result' => false,
				'error' => 'missing sessionhash',
			);
		}


		$data['sessionhash'] = $sessionhash;
		$data['loginlibraryid'] = $libid;

		if (isset($data['additional_params']) AND is_array($data['additional_params']))
		{
			$data['additional_params'] = json_encode($data['additional_params']);
		}

		// These sessionauth records are mostly for temporary usage to hold a request token-secret pair before
		// they're converted into a useable access token-secret pair, and don't need to last for long.
		// Ideally they'll be deleted after they're consumed in the conversion, but can linger if the
		// conversion process failed for some reason.
		$data['expires'] = vB::getRequest()->getTimeNow() + 86400;

		$assertor = vB::getDBAssertor();
		$conditions = array('sessionhash' => $data['sessionhash'], 'loginlibraryid' => $data['loginlibraryid']);
		$values = array();
		$acceptedKeys = array(
			'sessionhash',
			'loginlibraryid',
			'token',
			'token_secret',
			'additional_params',
			'expires',
		);
		foreach ($acceptedKeys AS $__k)
		{
			if (isset($data[$__k]))
			{
				$values[$__k] = $data[$__k];
			}
		}

		$type = 'update';
		$check = $assertor->getRow('vBForum:sessionauth', $conditions);
		if (!empty($check))
		{
			// update existing
			$result = $assertor->update(
				'vBForum:sessionauth',
				$values, // values
				$conditions
			);
		}
		else
		{
			$type = 'insert';
			$values[vB_dB_Query::TYPE_KEY] = vB_dB_Query::QUERY_INSERT;
			// insert new
			$result = $assertor->assertQuery('vBForum:sessionauth', $values);
		}

		return array(
			'result' => $result,
			'type' => $type,
		);
	}

	final public function getSessionAuthRecord($token = null)
	{
		$libid = $this->getLoginLibraryId();
		$session = vB::getCurrentSession();
		$sessionhash = $session->get('dbsessionhash');

		if (empty($libid) OR
			empty($session) OR
			empty($sessionhash)
		)
		{
			return array();
		}
		else
		{
			$assertor = vB::getDBAssertor();
			$conditions = array('sessionhash' => $sessionhash, 'loginlibraryid' => $libid);
			if (!is_null($token))
			{
				$conditions['token'] = $token;
			}
			$check = $assertor->getRow('vBForum:sessionauth', $conditions);
			if (!empty($check))
			{
				$check['additional_params'] = json_decode($check['additional_params'], true);
				if (empty($check['additional_params']))
				{
					$check['additional_params'] = array();
				}
				return $check;
			}
		}

		return array();
	}

	final protected function deleteSessionAuthRecord()
	{
		// cleanup any old records.
		$this->removeExpiredSessionAuths();

		$libid = $this->getLoginLibraryId();
		$session = vB::getCurrentSession();
		$sessionhash = $session->get('dbsessionhash');

		if (empty($libid) OR
			empty($session) OR
			empty($sessionhash)
		)
		{
			return false;
		}
		else
		{
			$assertor = vB::getDBAssertor();
			$conditions = array('sessionhash' => $sessionhash, 'loginlibraryid' => $libid);
			$check = $assertor->delete('vBForum:sessionauth', $conditions);
			return $check;
		}
	}

	final protected function removeExpiredSessionAuths()
	{
		$assertor = vB::getDBAssertor();
		$conditions = array(
			array(
				'field' => 'expires',
				'value' => vB::getRequest()->getTimeNow(),
				vB_dB_Query::OPERATOR_KEY => vB_dB_Query::OPERATOR_LTE
			),
		);
		$check = $assertor->assertQuery('vBForum:sessionauth',
			array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_DELETE,
				vB_dB_Query::CONDITIONS_KEY => $conditions,
			)
		);

		return $check;
	}

	/*
	 * Associate a vB Account with a 3rd party account.
	 * Custom packages' libraries should extend this class & override this.
	 * Typically (for OAuth1) you'd link the 3rd party's userid with
	 * `userauth`.`external_userid` & save the access token & secret
	 * linked with that id in `userauth`.`token` & .`token_secret`
	 */
	public function linkCurrentUserWithApp($params = array())
	{
		/*
			See oauth library for an example.
			Generally you'll want to verify the enduser authentication somehow, then when you're
			sure the current user is the third-party user he claims, store the identifiable information
			in the userauth via
				$userAuth = array(
					'userid' => {int currentuserid} e.g. vB::getCurrentSession()->get('userid'),
					'external_userid' => {string third party unique userid} e.g. twitter's id_str parameter,
					'token' => {user's access token received/exchanged from auth server},
					'token_secret' +> {user's token secret paired with above},
				);
				$this->saveUserLink($userAuth);
			If your implementation (e.g. oauth2) doesn't have a token & token secret, you can just
			store it in additional_params & call updateUserAuthRecord() directly. E.g.
				$userAuth = array(
					'userid' => vB::getCurrentSession()->get('userid'),
					'external_userid' => uniqid(),
					'additional_params' => array(
						'code' => "abcdefg",
						'somethingelse' => 'hello world',
					),
				);
				$this->updateUserAuthRecord($userAuth);
			However it is completely up to your package to verify a log-in attempt against the additional_params
			BEFORE calling loginUser({determined vb userid})!

			Remember to keep tokens & secrets secret, even from the current user. Most authentication implementations
			do not require that the user know the server-stored keypair, and may even close your application for
			violating terms of service if you do not keep them secure as these keypairs often provide access to the
			third party user (e.g. posting on their behalf, editing their profile).
		 */
		return false;
	}

	/*
	 * Break the link between a vB Account with a 3rd party account.
	 * Custom packages' APIs should extend this class & override this
	 * (e.g. call the 3rd party API to revoke access to user's account
	 * for the app, if 3rd party has such interfaces).
	 * By default, it will just remove the `userauth` record (and thus
	 * any token & token_secret) for this package & userid, as well as
	 * any `sessionauth` record associated with this session as cleanup.
	 */
	public function unlinkCurrentUserFromApp($params = array())
	{
		$this->deleteUserAuthRecord();
		$this->deleteSessionAuthRecord();
	}

	/*
	 * Utility function to generate a random string meant for single-use only.
	 * At the moment, does not guarantee single-use, caller must handle that.
	 */
	protected function getNonce($length = 32, $chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567')
	{
		/*
		todo: do we want to store this value & time-limit the nonce to disallow reuse?
		 */

		// default chars come from the allowed characters in Base32

		$random = new vB_Utility_Random();
		$secret = $random->string($chars, $length);

		return $secret;
	}

	/*
	 * More or less just a wrapper for vB_user::processNewLogin()
	 * Logs in the current session as the vB User specified as $vbuserid.
	 * WARNING: THIS DOES NOT CHECK if current session is indeed verified
	 * as $vbuserid. The caller must do so prior to calling this!
	 */
	final public function loginUser($vbuserid)
	{
		/*
		 Based on vB_Api_User::loginExternal()
		 */

		$currentUserid = vB::getCurrentSession()->get('userid');
		if (!empty($currentUserid))
		{
			throw new vB_Exception_Api('error_external_wrong_vb_user', $this->productid);
		}

		if (!$vbuserid)
		{
			throw new vB_Exception_Api('error_external_no_vb_user', $this->productid);
		}

		$session = vB::getRequest()->createSessionForUser($vbuserid);
		$sessionUserInfo = $session->fetch_userinfo();

		//don't try to set "rememberme" for FB logins (the remember me token is called 'password' for legacy reasons.
		$auth = array(
			'userid'       => $vbuserid,
			'password'     => $this->productid,
			'lastvisit'    => $sessionUserInfo['lastvisit'],
			'lastactivity' => $sessionUserInfo['lastactivity']
		);

		// create new session -- this is probably 90% unnecesary both for us and for the
		// normal login, but that's how we used to do it and using it doesn't make things
		// any worse.
		$res = vB_User::processNewLogin($auth);
		return array('login' => $res);
	}

	public function saveUserLink($userAuth)
	{
		if (!empty($userAuth['userid']) AND
			!empty($userAuth['external_userid']) AND
			!empty($userAuth['token']) AND
			!empty($userAuth['token_secret'])
		)
		{
			$check = $this->updateUserAuthRecord($userAuth);
			// delete the sessionauth record that was temporarily holding our access token+secret
			$this->deleteSessionAuthRecord();
		}
	}

	public function postUserDelete($userid)
	{
		// This hook is for packages that might have its own records that must be deleted, but
		// cannot extend this class/method due to naming conflicts.
		// At this point, the userauth record still exists (if user was linked)
		vB::getHooks()->invoke('hookExternalLoginPostUserDelete', array(
			'userid' => $userid,
		));


		if (!empty($userid))
		{
			$assertor = vB::getDBAssertor();
			$conditions = array('userid' => $userid);
			$assertor->delete('vBForum:userauth', $conditions);
		}
	}

	public final function getPersonalData($userid)
	{
		$userid = intval($userid);
		$assertor = vB::getDBAssertor();
		$query = $assertor->assertQuery('vBForum:getUserAuths', array('userid' => $userid));
		$personalData = array();
		foreach ($query AS $__row)
		{
			$__key = $__row['loginlibraryid'];
			$__row['additional_params'] = json_decode($__row['additional_params'], true);
			if (empty($__row['additional_params']))
			{
				$__row['additional_params'] = array();
			}

			/*
				We could run into some problems here. The class/function may not exist,
				or the product might be disabled.
				Even if the product is disabled, we probably need to return whatever personal
				data it *may* hold, but we also don't want to leak any sensitive auth data
				needlessly...
			 */
			$__data = array();
			try
			{
				$class = vB_Library::instance($__row['class']);

				if (method_exists($class, 'formatPersonalDataForExport'))
				{
					$__data = $class->formatPersonalDataForExport($__row);
				}
				else
				{
					// Do nothing for now.
				}
			}
			catch (Exception $e)
			{
				switch ($__row['productid'])
				{
					// We know how to deal with our own products
					case "twitterlogin":
					case "googlelogin":
						$__data = $this->formatPersonalDataForExport($__row);
						break;
					default:
						// Do nothing for now.
						break;
				}
			}

			if (!empty($__data))
			{
				$personalData[$__key] = $__data;
			}
		}

		return $personalData;
	}

	/**
	 * Given userauth record & the loginlibrary data, fetch any additional
	 * personal data stored for the user & format it for export.
	 *
	 * @param   $userauth   array    `userauth` and `loginlibrary` data for the user,
	 *                               including the following data:
	 *                                - int     userid
	 *                                - string  external_userid
	 *                                - array   additional_params
	 *                                - string  token
	 *                                - string  token_secret
	 *                                - int     loginlibraryid
	 *                                - int     productid
	 *                                - string  class
	 *
	 * @return array
	 *			each key should be a phrase title, and value should be the stored data
	 */
	public function formatPersonalDataForExport($userauth)
	{
		/*
			Both twitterlogin & googlelogin have external_userid.
			The auth token held by twitterlogin could be used to *fetch* additional
			data, but that shouldn't be considered public, and is not something
			to be leaked casually.
			In the future, if either package adds more personal data to storage,
			they should implement their own version of this function.
		 */
		$phraseKey = strtolower(trim($userauth['productid'])) . '_external_userid';
		return array(
			$phraseKey => $userauth['external_userid'],
		);
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 101013 $
|| #######################################################################
\*=========================================================================*/
