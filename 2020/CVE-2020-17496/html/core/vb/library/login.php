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
 * This class depends on the following
 *
 * * vB_Utility_Password_Algorithm
 * * vB Environment including the datastore and request objects
 * * Datastore value 'pwschemes'.
 *
 * It does not and should not depend on the permission objects.  All permissions
 * should be handled outside of the class and passed to to the class in the form
 * of override flags.
 *
 */

/**
 * vB_Library_Login
 *
 * @package vBLibrary
 * @access public
 */
class vB_Library_Login extends vB_Library
{
	/**
	 *	Verify a login value
	 *
	 *  In addition to the user's password, we'll verify do a couple of additional things
	 *  * If the password hash scheme is disabled, we'll reject the login entirely
	 *  * If the scheme is not current, we will attempt to quietly rehash
	 *  * If the scheme has been deprecated and we cannot rehash, then we'll expire the password.
	 *
	 *  @param array $login  The login info of the user to verify containg
	 *  	* token -- the password hash to verify against
	 *  	* scheme -- the scheme used to generate the hash
	 *  @param $passwords array.  Array of password variants in the form
	 *  	array('password' => $password, 'encoding' => $encoding)
	 *  valid values for encoding are 'text' and 'md5'.  This is required
	 *  to handle various legacy logic that encodes the password using md5
	 *  on the front end.  We may wish to expand that to include better
	 *  front end encodings in the future.
	 *  @return array
	 *  	* auth bool true if the login succeeded, false otherwise
	 *  	* remembermetoken string token to use for remember me logic (blank if not authenticated)
	 */
	public function verifyPasswordFromInfo($login, $passwords)
	{
		$datastore = vB::getDatastore();
		$schemes = $datastore->getValue('pwschemes');

		if (!isset($schemes[$login['scheme']]))
		{
			throw new vB_Exception_Api('invalid_password_scheme', array(vB5_Route::buildUrl('lostpw|fullurl')));
		}

		foreach($passwords AS $password)
		{
			$string = $password['password'];
			$encoding = $password['encoding'];

			if ($encoding == 'text')
			{
				//if text we need to encode before passing to the verfication system
				$string = $this->encodePassword($string);
			}
			else if ($encoding == 'md5')
			{
				//deliberate fallthrough
			}
			else
			{
				//if we don't recognize the scheme, then ignore.
				continue;
			}

			try
			{
				$algo = vB_Utility_Password_Algorithm::instance($login['scheme']);
				$result = $algo->verifyPassword($string, $login['token']);
			}
			catch(vB_Utility_Password_Exception_SchemeNotSupported $e)
			{
				throw new vB_Exception_Api('invalid_password_scheme', array(vB5_Route::buildUrl('lostpw|fullurl')));
			}

			if ($result)
			{
				$top = $this->getTopScheme($schemes);
				if ($login['scheme'] != $top OR $algo->requireRehash($login['token']))
				{
					$this->setPassword($login['userid'], $string, array('passwordhistorylength' => 0),
						array('passwordhistory' => true));
				}

				return array (
					'auth' => true,
					'remembermetoken' => $this->generateRememberMeToken($login['token'], vB_Request_Web::$COOKIE_SALT)
				);
			}
		}

		return array (
			'auth' => false,
			'remembermetoken' => ''
		);
	}

	/**
	 * Verify the remember token.
	 *
	 * This verifies if the "rememberme" token returned by the password verification
	 * function is valid for the given user
	 *
	 * @param array $login login information
	 * 	* token -- the user's password token
	 * 	* scheme -- the user's password scheme
	 * @param string $remembermetoken -- The token to checka
	 * @return array
	 * 	* auth (boolean) -- true if the rememberme token matches, false otherwise
	 * 	* remembermetoken (string) -- the "current" rememberme token.  This will be the same as the rememberme token
	 * 			passed in unless we validated based on a legacy value.  This should be used to update the rememberme value
	 * 			stored with the client.  If the auth failed, this will be blank.
	 */
	public function verifyRememberMeFromInfo($login, $remembermetoken)
	{
		$newtoken = $this->generateRememberMeToken($login['token'], vB_Request_Web::$COOKIE_SALT);
		$result = ($newtoken == $remembermetoken);

		//complete hack which requires the kind of understanding of the legacy hash
		//that totally breaks the enscapulation of the new password system.  However
		//explaining good software engineering practices to customers irate because
		//their remember me cookie broke after upgrade isn't not really high on
		//my to do list.  This can be removed once those cookies become extinct in the
		//wild.
		if (!$result AND $login['scheme'] == 'legacy')
		{
			list($hash, $salt) = explode(' ', $login['token']);
			$result = (md5($hash . vB_Request_Web::$COOKIE_SALT) == $remembermetoken);
		}

		return array (
			'auth' => $result,
			'remembermetoken' => ($result ? $newtoken : '')
		);
	}

	/**
	 *	Change the password for a user
	 *
	 *	@param int $userid -- the id of the user to change the passwordor
	 *	@param string $password -- the passsword to use for the new hash.  May be md5 encoded.
	 *	@param array $checkOptions -- values for permission checks.  These are all required (though they might be ignored if
	 *		the specific check is skipped).
	 *		* passwordhistorylength -- The number of days to look back for duplicate passwords
	 *	@param array $checkOverrides -- checks to skip.  This will usually be based on user permissions, but we shouldn't
	 *		check those in the library.  All of these fields are optional. If not set or set to false, the check
	 *		will be performed.  If set to true, then the check will be skipped.
	 *		* passwordhistory -- skip the check for the password history for this user.  Will will still store the
	 *				password set in the history
	 *	@return no return.  Will throw an exception if setting the password fails.
	 *	@throws vB_Exception_Api with the following possible errors
	 *		* usernotfound -- The userid does not exist.
	 *		* invalidpassword -- The password does not meet the configured standards for the site.
	 *				Currently this only checks that the password is not the same as the username, but the caller
	 *				should not assume that this is the only reason because this is likely to change in the future
	 *
	 */
	public function setPassword($userid, $password, $checkOptions, $checkOverrides = array())
	{
		/*
		 * Get the user info and handle front end encoding of the password
		 */

		//get the user info.  Will be used to check password against
		$db = vB::getDBAssertor();
		$login = $db->getRow('user', array(
			vB_dB_Query::COLUMNS_KEY => array('userid', 'username', 'token'),
			'userid' => $userid
		));

		if (!$login)
		{
			throw new vB_Exception_Api('invalid_user_specified');
		}

		//if the password isn't encoded, encode it.  This is the "magic" that makes the
		//md5 front end encoding work.  Should eventually replace with an flexible and
		//explicit encoding scheme
		$md5_password = $password;
		if (!$this->verifyMd5($password))
		{
			$md5_password = $this->encodePassword($password);
		}

		/*
		 *	validate the password
		 */

		// In the following password validation, we can use the non-md5-encoded
		// password, since we don't hash the password client-side when creating
		// or changing passwords, only when logging in. The has been verified for
		// creating/editing password for a user via the Admin CP, when registering,
		// and when changing a password via the frontend.
		// If we ever change this, we can send the password length as a separate
		// parameter for the minimum length check.

		$vboptions = vB::getDatastore()->getValue('options');
		$stringUtility = vB::getString();

		// Check disallowed words (the setting and their username)
		$badPasswords = array();
		if (!empty($vboptions['passwordbadwords']))
		{
			// The instructions say to put each word on a separate line, but
			// we'll quietly accept space delimited as well.
			$badPasswords = preg_split('#\s+#s', $stringUtility->strtolower($vboptions['passwordbadwords']), -1, PREG_SPLIT_NO_EMPTY);
		}
		$badPasswords[] = $stringUtility->strtolower($login['username']);
		$passwordLower = $stringUtility->strtolower($password);
		foreach($badPasswords AS $badPassword)
		{
			if ($passwordLower == $badPassword)
			{
				throw new vB_Exception_Api('invalid_password_specified');
			}
		}

		// NOTE: Keep password requirement checks in sync with the Javascript
		// checks in password.js checkPassword().

		// Check minimum length
		if (strlen($password) < $vboptions['passwordminlength'])
		{
			throw new vB_Exception_Api('password_too_short');
		}

		// Check upppercase requirement
		if ($vboptions['passwordrequireuppercase'] AND !preg_match('#[A-Z]#s', $password))
		{
			throw new vB_Exception_Api('password_needs_uppercase');
		}

		// Check number requirement
		if ($vboptions['passwordrequirenumbers'] AND !preg_match('#[0-9]#s', $password))
		{
			throw new vB_Exception_Api('password_needs_numbers');
		}

		// Check special chars requirement
		if ($vboptions['passwordrequirespecialchars'])
		{
			// non-alphanumeric printable ascii chars (32-47, 58-64, 91-96, 123-126)
			$printable = preg_quote(' !"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~', '#');
			if (!preg_match('#[' . $printable . ']#s', $password))
			{
				throw new vB_Exception_Api('password_needs_special_chars');
			}
		}

		//check the history
		if (empty($checkOverrides['passwordhistory']))
		{
			$lookback = (vB::getRequest()->getTimeNow() - ($checkOptions['passwordhistorylength'] * 86400));
			if (!$this->checkPasswordHistory($userid, $md5_password, $lookback))
			{
				throw new vB_Exception_Api(array('passwordhistory', $checkOptions['passwordhistorylength']));
			}
		}

		/*
		 *	Actually set the password
		 */
		$datastore = vB::getDatastore();
		$data = array();

		//we don't use "getTopScheme" here because in theory something could
		//go wrong when generating the token and we'd want to try another method.
		//In this instance we might end up rehashing on every login if we end up with
		//a bad alorithm class but that's better than failing to genereate hashes.
		$schemes = $this->getSchemesByPriority($datastore->getValue('pwschemes'));
		foreach($schemes AS $scheme)
		{
			try
			{
				$token = vB_Utility_Password_Algorithm::instance($scheme)->generateToken($md5_password);
				$data['token'] = $token;
				$data['scheme'] = $scheme;
				break;
			}
			catch (Exception $e)
			{
				//if something goes wrong, let's go to the next algorithm and try that.
				continue;
			}
		}

		if (!$data)
		{
			throw new vB_Exception_Api('no_available_schemes');
		}

		$data['passworddate'] = date('Y-m-d', vB::getRequest()->getTimeNow());
		$db->update('user', $data, array('userid' => $userid));

		//save the password history
		$data['userid'] = $userid;
		$data['passworddate'] = vB::getRequest()->getTimeNow();
		$db->insert('passwordhistory', $data);
	}

	private function getTopScheme($schemes)
	{
		$schemes = $this->getSchemesByPriority($schemes);
		foreach($schemes AS $scheme)
		{
			try
			{
				$algo = vB_Utility_Password_Algorithm::instance($scheme);
				if($algo)
				{
					break;
				}
			}
			catch (Exception $e)
			{
				//if something goes wrong, let's go to the next algorithm and try that.
				continue;
			}
		}

		return $scheme;
	}

	/**
	 *	Load the scheme files from xml files
	 */
	public function importPasswordSchemes()
	{
		$xmldir = DIR . '/includes/xml/';
		$xmlarrays = $this->readPasswordSchemes($xmldir);
		$schemes = $this->processPasswordSchemes($xmlarrays);
		vB::getDatastore()->build('pwschemes', serialize($schemes), 1);
	}

	/* ######################################################################################################
	 *	Some helper functions.  These should *not* have any dependancies on anything other than the
	 *	utility layer and the DB object.  The entry point function should handle grabbing all other
	 *	information from the environment and pass it through.
	 * ######################################################################################################*/


	protected function getSchemesByPriority($schemeArray)
	{
		if (!is_array($schemeArray))
		{
			return array();
		}

		$candidates = array();
		foreach($schemeArray AS $key => $data)
		{
			//a scheme with a null priority should never be considered for encoding a
			//new password.  These schemes exist solely to decode existing passwords
			if (is_null($data['priority']))
			{
				unset($schemeArray[$key]);
			}
			else
			{
				$candidates[$key] = $data['priority'];
			}
		}

		arsort($candidates);
		return array_keys($candidates);
	}

	/**
	 *	Fetch the scheme files from disk and returned the parsed arrays
	 *
	 *	@param string $xmldir the directory the xml files are located in
	 *	@return array the password scheme data in the form
	 *	array ('scheme' => array('priority' => $n))
	 *	Note that the scheme is an array for potential future expansion.
	 */
	protected function readPasswordSchemes($xmldir)
	{
		if (!is_readable($xmldir))
		{
			throw new vB_Exception_Api(array('error_x', 'Could not read the includes/xml directory'));
		}

		$handle =  opendir($xmldir);
		if (!$handle)
		{
			throw new vB_Exception_Api(array('error_x', 'Could not read the includes/xml directory'));
		}

		$schemeArrays = array();
		while (($file = readdir($handle)) !== false)
		{
			if (!preg_match('#^pwschemes_(.*).xml$#i', $file, $matches))
			{
				continue;
			}

			$xmlobj = new vB_XML_Parser(false, $xmldir . $file);
			if (!($xml = $xmlobj->parse()))
			{
				throw new vB_Exception_Api(array('error_x', 'Failed to parse password scheme file ' . $file));
			}

			$schemeArrays[] = $xml;
		}

		if (count($schemeArrays) == 0)
		{
			throw new vB_Exception_Api(array('error_x', 'No password scheme files found.'));
		}

		return $schemeArrays;
		closedir($handle);
	}

	protected function processPasswordSchemes($schemeArrays)
	{
		$disabledSchemes = array();
		$processedSchemes = array();
		foreach($schemeArrays AS $schemeArray)
		{
			$schemeArray = vB_XML_Parser::getList($schemeArray['scheme']);
			foreach($schemeArray AS $scheme)
			{
				//if its disbabled, just mark it and move on
				if (!empty($scheme['disabled']))
				{
					$disabledSchemes[] = $scheme['name'];
					continue;
				}

				//makes sure we don't pick up any stray attributes from the xml file.
				$values['priority'] = isset($scheme['priority']) ? $scheme['priority'] : null;

				//duplicate schemes are not allowed, wether in one file or in many
				if (isset($processedSchemes[$scheme['name']]))
				{
					throw new vB_Exception_Api(array('error_x', 'Duplicate scheme ' . $scheme['name']));
				}
				$processedSchemes[$scheme['name']] = $values;
			}
		}

		//anything that disabled should be treated as if we never saw it.
		foreach($disabledSchemes AS $disabled)
		{
			unset($processedSchemes[$disabled]);
		}
		return $processedSchemes;
	}

	/**
	 *	Verify that a string value is an md5 hash
	 *
	 *	@param string $md5 -- string to check for an md5 hash.
	 */
	protected function verifyMd5(&$md5)
	{
		//copied from datamanager.
		return ((bool) preg_match('#^[a-f0-9]{32}$#', $md5));
	}

	/**
	 *	Encode the password
	 *
	 *	The browswer will (if JS is enabled) encode the password as an md5hash
	 *	before sending to the server on login.  Previous versions did this when
	 *	setting the password.  This is an attempt to get the password into a
	 *	consistant form before hashing it with the main password hash.
	 *
	 *	Otherwise we can get situations where the hash we save doesn't match the
	 *	hash we entered for one reason or another.
	 */
	private function encodePassword($password)
	{
		$password = trim($password);
		$md5_password = $password;

		$string = vB::getString();
		//force the string to utf-8 if it is not.
		if (!$string->isDefaultCharset('utf-8'))
		{
			$md5_password = $string->toUtf8($md5_password);
		}
		//encode the utf8 extended characters like the browser does.
		$md5_password = vB_String::ncrEncode($md5_password, true);
		$md5_password = md5($md5_password);
		return $md5_password;
	}

	/**
	 * Checks to see if a password is in the user's password history
	 *
	 * Will also delete any expired records in the password history.
	 *
	 * @param	integer	$userid User ID
	 * @param string $fe_password -- the frontend encoded password
	 * @param	integer	$lookback The time period to look back for passwords in seconds
	 *
	 * @return boolean Returns true if password is in the history
	 */
	protected function checkPasswordHistory($userid, $fe_password, $lookback)
	{
		$db = vB::getDBAssertor();

		// first delete old password history
		$db->delete('passwordhistory', array(
				'userid' => $userid,
				array('field' =>'passworddate', 'value' => $lookback, 'operator' =>  vB_dB_Query::OPERATOR_LTE)
		));

		$old_passwords = $db->select('passwordhistory', array('userid' => $userid));
		foreach($old_passwords as $old_password)
		{
			//need to use the same scheme as when the history hash was created.  If the front end scheme has changed
			//then we'll be unable to check -- we'll just have to pass it along.  When we implement front end schemes
			//other than plain md5 we'll need to do something here to check if its changed.
			try
			{
				$verify = vB_Utility_Password_Algorithm::instance($old_password['scheme'])->verifyPassword($fe_password, $old_password['token']);
			}
			catch(Exception $e)
			{
				//if we fail to hash the password we'll just ignore that history record.  Better than failing because of an old
				//record that has a now invalid scheme or something else equally silly.
				continue;
			}

			if ($verify)
			{
				return false;
			}
		}

		return true;
	}


	/**
	* Inserts a record into the password history table if the user's password has changed
	*
	* @param	integer	User ID
	*/
	protected function updatePasswordHistory($userid, $data)
	{
		if (isset($this->user['password']) AND
			(empty($this->existing['password']) OR ($this->user['password'] != $this->existing['password'])))
		{
			/*insert query*/
			$this->assertor->assertQuery('insPasswordHistory', array(
					'userid' => $userid,
					'password' => $this->user['password'],
					'passworddate' => vB::getRequest()->getTimeNow()
			));
		}
	}

	protected function generateRememberMeToken($passwordtoken, $salt)
	{
		return hash('sha224', $passwordtoken . $salt);
	}
	/* ######################################################################################################
	 *	Some helper functions for MFA.  These should *not* have any dependancies on anything other than the
	 *	utility layer, the DB object, and the random number code.  The entry point function should
	 *	handle grabbing all other information from the environment and pass it through.
	 * ######################################################################################################*/

	public function resetMfaSecret($userid)
	{
		$db = vB::getDbAssertor();
		$mfa_user = $db->getRow('userloginmfa', array('userid' => $userid));

		// allowed characters in Base32
		$chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
		$random = new vB_Utility_Random();
		$secret = $random->string($chars, 16);

		if ($mfa_user)
		{
			$db->update(
				'userloginmfa',
				array(
					'secret' => $secret,
					'enabled' => 0,
					'dateline' => vB::getRequest()->getTimeNow()
				),
				array('userid' => $userid)
			);
		}
		else
		{
			$db->insert('userloginmfa', array(
				'userid' => $userid,
				'enabled' => 0,
				'secret' => $secret,
				'dateline' => vB::getRequest()->getTimeNow()
			));
		}

		return $secret;
	}

	public function setMfaEnabled($userid, $enabled)
	{
		$db = vB::getDbAssertor();
		$db->update(
			'userloginmfa',
			array('enabled' => ($enabled ? 1 : 0)),
			array('userid' => $userid)
		);
	}

	/**
	 * Check the Verification Code entered by the user.
	 */
	public function verifyMfa($secretkey, $thistry, $relaxedmode)
	{
		//note that it appears to be important that the secret key be
		//16 Base32 characters long.  The authenticator apps appear to
		//generate different values than this function for different key
		//lengths.  Its not clear why.  The standard does not appear to
		//specify anything about the key length.
		require_once(DIR . '/libraries/base32/base32.php');

		// Did the user enter 6 digits ?
		if (strlen($thistry) != 6)
		{
			return false;
		}
		else
		{
			$thistry = intval($thistry);
		}

		// If user is running in relaxed mode, we allow more time drifting
		// +/-1 min, as opposed to +/- 30 seconds in normal mode.
		if ($relaxedmode == 'enabled')
		{
			$firstcount = -2;
			$lastcount  =  2;
		}
		else
		{
			$firstcount = -1;
			$lastcount  =  1;
		}

		$tm = floor(time() / 30);

		$secretkey=Base32::decode($secretkey);
		// Keys from 30 seconds before and after are valid aswell.
		for ($i=$firstcount; $i<=$lastcount; $i++)
		{
			// Pack time into binary string
			$time = chr(0) . chr(0) . chr(0) . chr(0) . pack('N*', $tm + $i);

			// Hash it with users secret key
			$hm = hash_hmac('SHA1', $time, $secretkey, true);

			// Use last nipple of result as index/offset
			$offset = ord(substr($hm, -1)) & 0x0F;

			// grab 4 bytes of the result
			$hashpart = substr($hm,$offset,4);

			// Unpak binary value
			$value = unpack("N", $hashpart);
			$value = $value[1];

			// Only 32 bits
			$value = $value & 0x7FFFFFFF;
			$value = $value % 1000000;

			if ($value === $thistry)
			{
				// Return timeslot in which login happened.
				return $tm + $i;
			}

		}
		return false;
	}

}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 103945 $
|| #######################################################################
\*=========================================================================*/
