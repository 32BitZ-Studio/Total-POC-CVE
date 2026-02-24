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

abstract class vB5_Autoloader
{
	protected static $_paths = array();
	protected static $_autoloadInfo = array();

	public static function register($path)
	{
		self::$_paths[] = (string) $path . '/includes/'; // includes

		spl_autoload_register(array(__CLASS__, '_autoload'));
	}

	/**
	 * Extremely primitive autoloader
	 */
	protected static function _autoload($class)
	{
		self::$_autoloadInfo[$class] = array(
			'loader' => 'frontend',
		);

		if (preg_match('/[^a-z0-9_]/i', $class))
		{
			return;
		}

		$fname = str_replace('_', '/', strtolower($class)) . '.php';

		foreach (self::$_paths AS $path)
		{
			if (file_exists($path . $fname))
			{
				include($path . $fname);

				self::$_autoloadInfo[$class]['filename'] = $path . $fname;
				self::$_autoloadInfo[$class]['loaded'] = true;

				break;
			}
		}
	}

	/**
	 * Returns debug autoload info
	 *
	 * @return array Array of debug info containing 'classes' and 'count'
	 */
	public static function getAutoloadInfo()
	{
		return self::$_autoloadInfo;
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
