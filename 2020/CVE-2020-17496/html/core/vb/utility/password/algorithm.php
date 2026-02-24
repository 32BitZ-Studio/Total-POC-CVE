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
abstract class vB_Utility_Password_Algorithm
{
	use vB_Utility_Trait_NoSerialize;

	/**
	 *	Create an password algorithm object for the given scheme.
	 *
	 *	@param string $scheme -- the requested password scheme (algorithm + any parameters the argorithm expects
	 *		such as repetitions.
	 *	@return object An object of type vB_Password_Algorithm
	 *	@throws vB_Password_Exception_InvalidScheme
	 */
	public static function instance($scheme)
	{
		$algorithm = explode(':', $scheme, 2);
		$class = 'vB_Utility_Password_Algorithm_' . ucfirst($algorithm[0]);

		if (class_exists($class))
		{
			return new $class($scheme);
		}

		throw new vB_Utility_Password_Exception_InvalidScheme();
	}

	//hide the constructor, everything should go through the instance function
	protected function __construct($scheme)
	{
	}

	/**
	 *	Hash the password according to the password algorithm
	 *
	 *	@param string $password -- The password to encode.  It should already have any front end encoding applied.
	 *
	 *	@return string.  The pasword token
	 */
	abstract public function generateToken($password);


	/**
	 *	Hash the password according to the password algorithm
	 *
	 *	@param string $password -- The password to verify.  It should already have any front end encoding applied.
	 *	@param string $token.  The pasword token to verify against.
	 *
	 *	@return bool
	 */
	abstract public function verifyPassword($password, $token);

	/**
	 *	Check if the token requires a rehash.
	 *
	 *	This can happen if a scheme uses default options that have been changed.
	 *	@param string $token.
	 */
	public function requireRehash($token)
	{
		return false;
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 103299 $
|| #######################################################################
\*=========================================================================*/
