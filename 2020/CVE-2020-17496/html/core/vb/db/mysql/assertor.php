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
 * The vB core class.
 * Everything required at the core level should be accessible through this.
 *
 * The core class performs initialisation for error handling, exception handling,
 * application instatiation and optionally debug handling.
 *
 * @TODO: Much of what goes on in global.php and init.php will be handled, or at
 * least called here during the initialisation process.  This will be moved over as
 * global.php is refactored.
 *
 * @package vBulletin
 * @version $Revision: 103821 $
 * @since $Date: 2020-01-10 14:22:52 -0800 (Fri, 10 Jan 2020) $
 */
class vB_dB_MYSQL_Assertor extends vB_dB_Assertor
{
	/*Properties====================================================================*/

	protected static $db_type = 'MYSQL';

	protected function __construct(&$dbconfig, &$config)
	{
		parent::__construct($dbconfig, $config);
		self::$dbSlave = (!empty($dbconfig['SlaveServer']['servername'])) AND (!empty($dbconfig['SlaveServer']['port'])) AND
			(!empty($dbconfig['SlaveServer']['username']));

	}

	protected function load_database(&$dbconfig, &$config)
	{
		$db = new vB_Database_MySQLi($dbconfig, $config);

		//even if the connection fails its useful to have a valid
		//connection object.  Particularly for the installer.
		self::$db = $db;

		// get core functions
		if (!$db->isExplainEmpty())
		{
			$db->timer_start('Including Functions.php');
			require_once(DIR . '/includes/functions.php');
			$db->timer_stop(false);
		}
		else
		{
			require_once(DIR . '/includes/functions.php');
		}

// make database connection
		$db->connect(
				$dbconfig['Database']['dbname'],
				$dbconfig['MasterServer']['servername'],
				(isset($dbconfig['MasterServer']['port']) ? $dbconfig['MasterServer']['port'] : null) ,
				$dbconfig['MasterServer']['username'],
				$dbconfig['MasterServer']['password'],
				$dbconfig['MasterServer']['usepconnect'],
				$dbconfig['SlaveServer']['servername'],
				(isset($dbconfig['SlaveServer']['port']) ? $dbconfig['SlaveServer']['port'] : null) ,
				$dbconfig['SlaveServer']['username'],
				$dbconfig['SlaveServer']['password'],
				$dbconfig['SlaveServer']['usepconnect'],
				(isset($dbconfig['Mysqli']['ini_file']) ? $dbconfig['Mysqli']['ini_file'] : ''),
				(isset($dbconfig['Mysqli']['charset']) ? $dbconfig['Mysqli']['charset'] : '')
			);

		$db->force_sql_mode('');

		if (defined('DEMO_MODE') AND DEMO_MODE AND function_exists('vbulletin_demo_init_db'))
		{
			vbulletin_demo_init_db();
		}

		return $db;
	}

}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 103821 $
|| #######################################################################
\*=========================================================================*/
