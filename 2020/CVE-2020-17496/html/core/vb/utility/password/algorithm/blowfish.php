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
 *	@package vBUtility
 */

/**
 *	@package vBUtility
 */
class vB_Utility_Password_Algorithm_Blowfish extends vB_Utility_Password_Algorithm
{
	private $cost;

	protected function __construct($scheme)
	{
		//scheme specific init, need to do this every time because it could change.
		//this algorithm expects exactly one parameter
		$params = explode(':', $scheme);
		if (count($params) != 2)
		{
			throw new vB_Utility_Password_Exception_SchemeNotSupported();
		}

		$this->cost = (int) $params[1];
		parent::__construct($scheme);
	}

	public function generateToken($password)
	{
		$options['cost'] = $this->cost;
		$hash = password_hash($password, PASSWORD_BCRYPT, $options);
		return $hash;
	}

	public function verifyPassword($password, $token)
	{
		//if the cost part of the token does not match what we expect then don't validate
		//this shouldn't happen under ordinary circumstances, but we need to make sure we
		//don't provide any avenues for attack.
		list (,,$cost,) = explode('$', $token, 4);
		if ($cost != $this->cost)
		{
			return false;
		}

		return password_verify($password, $token);
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 102681 $
|| #######################################################################
\*=========================================================================*/
