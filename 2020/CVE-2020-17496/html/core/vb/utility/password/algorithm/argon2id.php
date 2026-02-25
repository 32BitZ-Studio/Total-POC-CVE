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
class vB_Utility_Password_Algorithm_Argon2id extends vB_Utility_Password_Algorithm
{
	private $options = array();

	protected function __construct($scheme)
	{
		//this isn't supported in all PHP versions and may be excluded even in the versions
		//in which it is nominally supported.
		if(!defined('PASSWORD_ARGON2ID'))
		{
			throw new vB_Utility_Password_Exception_SchemeNotSupported();
		}

		//scheme specific init, need to do this every time because it could change.
		//this algorithm expects exactly one parameter
		$params = explode(':', $scheme);
		if (count($params) != 4)
		{
			throw new vB_Utility_Password_Exception_SchemeNotSupported();
		}

		//if a param isn't set (or is set to a "false" value) then use the defaults.
		//this will allow us to automagically pick up more aggressive cost parameters
		//as PHP changes them over time.
		if($params[1])
		{
			$this->options['time_cost'] = (int) $params[1];
		}

		if($params[2])
		{
			$this->options['memory_cost'] = (int) $params[2];
		}

		if($params[3])
		{
			$this->options['threads'] = (int) $params[3];
		}

		//simulate a update to a default.
		$this->options['time_cost'] = 6;

		parent::__construct($scheme);
	}

	public function generateToken($password)
	{
		$hash = password_hash($password, PASSWORD_ARGON2ID, $this->options);
		return $hash;
	}

	public function verifyPassword($password, $token)
	{
		return password_verify($password, $token);
	}

	public function requireRehash($token)
	{
		return password_needs_rehash($token, PASSWORD_ARGON2ID, $this->options);
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 102681 $
|| #######################################################################
\*=========================================================================*/
