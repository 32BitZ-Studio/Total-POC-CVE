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
 * vB_Api_Facebook
 *
 * @package vBApi
 * @access public
 */
class vB_Api_Facebook extends vB_Api
{
	protected $disableFalseReturnOnly = array('isFacebookEnabled', 'userIsLoggedIn', 'getLoggedInFbUserId');

	/**
	 *	Is facebook enabled on this site.
	 *
	 *	@return bool true if the facebook system initialized properly, false otherwise
	 *		note that if we get an error this may be false even if facebook is configured
	 *		in the admincp.
	 */
	public function isFacebookEnabled()
	{
		return vB_Library::instance('facebook')->isFacebookEnabled();
	}

	/**
	 * Checks if the current user is logged into facebook
	 *
	 * @param bool $ping Whether to ping Facebook (unused)
	 * @return bool
	 */
	public function userIsLoggedIn($ping = false)
	{
		return vB_Library::instance('facebook')->userIsLoggedIn($ping);
	}

	/**
	 * Checks for a currrently logged in user through facebook api
	 *
	 * @return mixed, fb userid if logged in, false otherwise
	 */
	public function getLoggedInFbUserId()
	{
		return vB_Library::instance('facebook')->getLoggedInFbUserId();
	}

	/**
	 * Checks if current facebook user is associated with a vb user, and returns vb userid if so
	 *
	 * @param int, facebook userid to check in vb database, if not there well user current
	 * 		logged in user
	 * @return mixed, vb userid if one is associated, false if not
	 */
	public function getVbUseridFromFbUserid()
	{
		return vB_Library::instance('facebook')->getVbUseridFromFbUserid();
	}

	/**
	 * Get the logged in user's profile url.
	 *
	 * @return string|false facebook profile url or false on failure
	 * 	(forex, there is no logged in FB user)
	 */
	public function getFbProfileUrl()
	{
		return vB_Library::instance('facebook')->getFbProfileUrl();
	}

	/**
	 * Get the logged in user's profile picture url.
	 *
	 * @return string|false facebook profile picture url or false on failure
	 * 	(forex, there is no logged in FB user)
	 */
	public function getFbProfilePicUrl()
	{
		return vB_Library::instance('facebook')->getFbProfilePicUrl();
	}

	public function clearSession()
	{
		vB_Library::instance('facebook')->clearSession();
		return array('success' => true);
	}


	/**
	 * Grabs logged in user info from faceboook if user is logged in
	 *
	 * @return array, fb userinfo array if logged in, false otherwise,
	 * 		see the facebook '/me' docs for details
	 */
	public function getFbUserInfo()
	{
		return vB_Library::instance('facebook')->getFbUserInfo();
	}

	/**
	 *	Get the results from several functions in one call.
	 *
	 *	This is a cover function to make it easier to access all of the fb related information
	 *	for the current Facebook user in a single call.  This is an inefficient way of getting the
	 *	information if you aren't going to use most of it, but convenient if you are.
	 *
	 *	@return array
	 *		'profileurl' => result of getFbProfileUrl
	 *		'profilepicurl' => result of getFbProfilePicUrl
	 *		'vbuserid' => result of getVbUseridFromFbUserid
	 *		'user' = > result of getFbUserInfo
	 */
	public function getAllUserInfo()
	{
		$fblib = vB_Library::instance('facebook');
		$result = array();

		$result['profileurl'] = $fblib->getFbProfileUrl();
		$result['profilepicurl'] = $fblib->getFbProfilePicUrl();
		$result['vbuserid'] = $fblib->getVbUseridFromFbUserid();
		$result['user'] = $fblib->getFbUserInfo();
		return $result;
	}

	/**
	 *	Disconnects the current user from facebook
	 *
	 *	User must either be the current user or an administrator with permissions to
	 *	manage users.
	 *
	 *	@param int $userid -- The id of the user to disconnect
	 *	@return -- standard success array when successful, otherwise will throw an exception
	 */
	public function disconnectUser($userid)
	{
		$userid = intval($userid);

		//check permissions
		if (($userid != vB::getCurrentSession()->get('userid')) AND
			!vB::getUserContext()->hasAdminPermission('canadminpermissions'))
		{
			//this requires admin canadminpermissions or that it be for the current user.
			throw new vB_Exception_Api('no_permission');
		}
		vB_Library::instance('facebook')->disconnectUser($userid);

		//if we get this far without an exception we're good.
		return array('success' => true);
	}

	/**
	 *	Connects the currently logged in user to the currently logged in Facebook user
	 *
	 *	Note that we don't allow connection of a non logged in account because
	 *	we need to validate the FB login.  Connecting somebody else's account
	 *	to a FB just doesn't make sense as an action.
	 *
	 *	@param string $accessToken.  The facebook access token to verify the FB login.
	 *			if not given use the internal stored session.
	 *	@return -- standard success array when successful, otherwise will throw an exception
	 */
	public function connectCurrentUser($accessToken=null)
	{
		vB_Library::instance('facebook')->connectCurrentUser($accessToken);
		//if we get this far without an exception we're good.
		return array('success' => true);
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 101654 $
|| #######################################################################
\*=========================================================================*/
