<?php
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
 * Authentication/login related methods
 */
class vB5_Auth
{
	/**
	 * Sets cookies needed for authentication
	 *
	 * @param	array	$loginInfo - array of information returned from
	 *			the user::login api method
	 */
	public static function setLoginCookies(array $loginInfo, $loginType, $remember)
	{
		vB5_Cookie::set('sessionhash', $loginInfo['sessionhash'], 0, true);

		if ($loginType === 'cplogin')
		{
			vB5_Cookie::set('cpsession', $loginInfo['cpsession'], 0, true);
		}

		// in frontend we set these cookies only if rememberme is on
		if ($remember)
		{
			self::setRememberMeCookies($loginInfo['password'], $loginInfo['userid'], 365);
		}
	}

	public static function setRememberMeCookies($rememberMeToken, $userid, $expires = 30)
	{
		vB5_Cookie::set('password', $rememberMeToken, $expires, true);
		vB5_Cookie::set('userid', $userid, $expires, true);
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 103670 $
|| #######################################################################
\*=========================================================================*/
