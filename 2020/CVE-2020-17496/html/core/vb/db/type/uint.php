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
 * @package vBDatabase
 */

/**
 * @package vBDatabase
 */
abstract class vB_dB_Type_UInt extends vB_dB_Type
{
	/**
	 * String representation of unsigned integer
	 * @var string
	 */
	protected $value;

	public static function instance($value)
	{
		return parent::getInstance('UInt', $value);
	}

	public function __construct($value)
	{
		// Also check if it's hex. PHP7 no longer considers 0x... strings numeric, but vB still supports inserting hex into DB.
		if (!is_numeric($value) AND !self::is_hex($value))
		{
			throw new vB_Exception_Assertor("Invalid value for vB_dB_Type_UInt constructor. Value must be numeric (hex notation allowed).");
		}

		$this->value = (string)$value;
	}

	/**
	 * Returns true if string is hex notation in 0x[0-9a-fA-F] format.
	 *
	 * @param	String    $string
	 *
	 * @return Bool
	 *
	 * @access private
	 */
	private static function is_hex($string)
	{
		// Only support strings starting w/ the hex prefix.
		if (empty($string) OR strpos($string, '0x') !== 0)
		{
			return false;
		}

		// snip prefix for ctype_xdigit
		$string = substr($string, 2);

		if (function_exists('ctype_xdigit'))
		{
			return ctype_xdigit($string);
		}
		else
		{
			return (preg_match( '/[^0-9a-fA-F]/', $string) === 0);
		}
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
