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

// MySQLi Database Class

/**
* Class to interface with a MySQL 4.1 database
*
* This class also handles data replication between a master and slave(s) servers
*
* @package	vBulletin
* @version	$Revision: 101414 $
* @date		$Date: 2019-04-24 14:18:26 -0700 (Wed, 24 Apr 2019) $
*/
class vB_Database_MySQLi extends vB_Database
{
	/**
	* Array of function names, mapping a simple name to the RDBMS specific function name
	*
	* @var	array
	*/
	var $functions = array(
		'connect'            => 'mysqli_real_connect',
		'pconnect'           => 'mysqli_real_connect', // mysqli doesn't support persistent connections THANK YOU!
		'select_db'          => 'mysqli_select_db',
		'query'              => 'mysqli_query',
		'query_unbuffered'   => 'mysqli_unbuffered_query',
		'fetch_row'          => 'mysqli_fetch_row',
		'fetch_array'        => 'mysqli_fetch_array',
		'fetch_field'        => 'mysqli_fetch_field',
		'free_result'        => 'mysqli_free_result',
		'data_seek'          => 'mysqli_data_seek',
		'error'              => 'mysqli_error',
		'errno'              => 'mysqli_errno',
		'affected_rows'      => 'mysqli_affected_rows',
		'num_rows'           => 'mysqli_num_rows',
		'num_fields'         => 'mysqli_num_fields',
		'field_name'         => 'mysqli_field_tell',
		'insert_id'          => 'mysqli_insert_id',
		'escape_string'      => 'mysqli_real_escape_string',
		'real_escape_string' => 'mysqli_real_escape_string',
		'close'              => 'mysqli_close',
		'client_encoding'    => 'mysqli_client_encoding',
		'ping'               => 'mysqli_ping',
	);

	/**
	* Array of constants for use in fetch_array
	*
	* @var	array
	*/
	var $fetchtypes = array(
		self::DBARRAY_NUM   => MYSQLI_NUM,
		self::DBARRAY_ASSOC => MYSQLI_ASSOC,
		self::DBARRAY_BOTH  => MYSQLI_BOTH
	);

	/**
	* Initialize database connection(s)
	*
	* Connects to the specified master database server, and also to the slave server if it is specified
	*
	* @param	string  Name of the database server - should be either 'localhost' or an IP address
	* @param	integer	Port of the database server - usually 3306
	* @param	string  Username to connect to the database server
	* @param	string  Password associated with the username for the database server
	* @param	string  Persistent Connections - Not supported with MySQLi
	* @param	string  Configuration file from config.php.ini (my.ini / my.cnf)
	*
	* @return	object  Mysqli Resource
	*/
	protected function db_connect($servername, $port, $username, $password, $usepconnect, $configfile = '')
	{
		set_error_handler(array($this, 'catch_db_error'));

		$link = mysqli_init();
		# Set Options Connection Options
		if (!empty($configfile))
		{
			mysqli_options($link, MYSQLI_READ_DEFAULT_FILE, $configfile);
		}

		try
		{
			// this will execute at most 5 times, see catch_db_error()
			do
			{
				$connect = $this->functions['connect']($link, $servername, $username, $password, '', $port);
			}
			while ($connect == false AND $this->reporterror);
		}
		//this should be a finally block, but that's not supported for php < 5.5
		catch(Exception $e)
		{
			restore_error_handler();
			throw $e;
		}
		restore_error_handler();
		return (!$connect) ? false : $link;
	}

	protected function set_charset($charset, $link)
	{
		//if mysql is properly configured we don't need to do this, but
		//that's so very rare in the wild.
		if (empty($charset))
		{
			//there is no way to query a specific link directly so we hack it.
			$sql = 'SELECT @@character_set_database AS db_charset';
			$queryresult = @mysqli_query($link, $sql, MYSQLI_STORE_RESULT);
			$row = $this->fetch_array($queryresult);
			$charset = !empty($row['db_charset']) ? $row['db_charset'] : '';
			// We're using buffered (MYSQLI_STORE_RESULT) query for this but
			// might as well free up memory after we don't need it.
			@mysqli_free_result($queryresult);
		}

		if (!empty($charset))
		{
			return mysqli_set_charset($link, $charset);
		}
		else
		{
			return false;
		}
	}

	/**
	 *	Returns the *default* character encoding of the client which is not necesarily the one we are using.
	 */
	public function getInitialClientCharset()
	{
		//we've changed the charset immediately on connect and there is
		//no way to get that information after the fact.  So we will
		//create a new link to the db server just to get that information.
		//This isn't hugely efficient and should only be used in appropriate
		//contexts
		$link = $this->db_connect(
			$this->dbconfig['MasterServer']['servername'],
			$this->dbconfig['MasterServer']['port'],
			$this->dbconfig['MasterServer']['username'],
			$this->dbconfig['MasterServer']['password'],
			false,
			$this->dbconfig['Mysqli']['ini_file']
		);
		return mysqli_character_set_name($link);
	}


	/**
	* Executes an SQL query through the specified connection
	*
	* @param	boolean	Whether or not to run this query buffered (true) or unbuffered (false). Default is unbuffered.
	* @param	string	The connection ID to the database server
	*
	* @return	string
	*/
	function &execute_query($buffered = true, &$link)
	{
		$retries = $this->retries;
		$this->connection_recent =& $link;
		$this->querycount++;

		if ($this->doExplain)
		{
			$index = $this->preLogQueryToExplain();
		}

		while ($retries > 0)
		{
			if ($queryresult = @mysqli_query($link, $this->sql, ($buffered ? MYSQLI_STORE_RESULT : MYSQLI_USE_RESULT)))
			{
				if ($this->doExplain)
				{
					$this->postLogQueryToExplain($index);
				}

				// unset $sql to lower memory .. this isn't an error, so it's not needed
				$this->sql = '';
				return $queryresult;
			}
			else
			{
				//we retry only for deadlocks
				$this->error = $this->error();

				if (strpos($this->error, 'Deadlock') !== false)
				{
					$retries--;
				}
				else if (
					strpos($this->error, "Commands out of sync; you can't run this command now") !== false
					AND $this->reconnectAttempts > 0
				)
				{
					$this->reconnectAttempts--;
					/*
						For "mysql gone away" errors, we can probably just use $this->ping().
						For commands out of sync, when testing the mysqli ping actually emitted
						the same error, so let's just forcibly disconnect then reconnect to
						clear out the unfreed unbuffered ghost query.

						Note, when we reconnect, it calls $this->set_charset() which calls
						this function again.
						We shouldn't have circular *reconnect* attempts since we're decrementing
						$this->reconnectAttempts, but it may wipe out the state of this original
						query, particularly the query string & any previously set error data.
						Furthermore, if anything else calls free_result() (as set_charset()
						currently does), that will also wipe the query string, and dumping the
						current connection & reconnecting means the error() & errno() functions
						(that uses $this->connection_recent) will be unable to retrieve the
						old error.
						For the SQL, store it at this point, and restore it after reconnecting
						until we remove some circular logic in the near future (probably not bad
						to keep it even after, just in case). For the error... if it's a command
						out of sync, or a random disconnect, I'm not entirely sure how important
						it is to try to retain the current error. For the former it's likely a
						previous query that's still open that's blocking this query. For the
						latter it's possible that the disconnect is not related to this query,
						but also possible that this query was particularly slow or problematic...
						However, since we're not handling the latter right yet, I'm going to ignore
						the "store current error & restore it later" logic.
					 */
					$sql = $this->sql;
					// when implementing reconnect for mysql gone away, we may be able to just do
					// $this->ping() instead, but keep $this->reset_db_connection() for commands
					// out of sync. See above.
					$this->reset_db_connection();
					$this->sql = $sql;
					$retries--;
				}
				else
				{
					$retries = 0;
				}
			}
		}

		//note that the halt function does not reliably halt -- its affected by how the db class is set up by the caller.
		$this->halt();
		// unset $sql to lower memory .. error will have already been thrown
		$this->sql = '';
		// Because this function returns a reference, PHP expects something to be returned regardless of $this->halt() above.
		return $queryresult;
	}

	/**
	* Simple wrapper for select_db(), to allow argument order changes
	*
	* @param	string	Database name
	* @param	integer	Link identifier
	*
	* @return	boolean
	*/
	function select_db_wrapper($database = '', $link = null)
	{
		return $this->functions['select_db']($link, $database);
	}

	/**
	* Escapes a string to make it safe to be inserted into an SQL query
	*
	* @param	string	The string to be escaped
	*
	* @return	string
	*/
	function escape_string($string)
	{
		return $this->functions['real_escape_string']($this->connection_master, $string);
	}

	/**
	* Cleans a string to make it safe to be used in an SQL query as a table name or column/field name
	*
	* @param	string	The string to be cleaned
	*
	* @return	string
	*/
	function clean_identifier($identifier)
	{
		return preg_replace('#[^a-z0-9_]#i', '', $identifier);
	}

	/**
	* Returns the name of a field from within a query result set
	*
	* @param	string	The query result ID we are dealing with
	* @param	integer	The index position of the field
	*
	* @return	string
	*/
	function field_name($queryresult, $index)
	{
		$field = @$this->functions['fetch_field']($queryresult);
		return $field->name;
	}

	/**
	* Switches database error display ON
	*/
	function show_errors()
	{
		$this->reporterror = true;
		mysqli_report(MYSQLI_REPORT_ERROR);
	}

	/**
	* Switches database error display OFF
	*/
	function hide_errors()
	{
		$this->reporterror = false;
		mysqli_report(MYSQLI_REPORT_OFF);
	}

	/**
	* Ping connection and reconnect
	* Don't use this in a manner that could cause a loop condition
	*
	*/
	function ping()
	{
		if (!@$this->functions['ping']($this->connection_master))
		{
			$this->reset_db_connection();

		}
	}

	private function reset_db_connection()
	{
		$this->close();

		// make database connection
		$this->connect(
			$this->dbconfig['Database']['dbname'],
			$this->dbconfig['MasterServer']['servername'],
			$this->dbconfig['MasterServer']['port'],
			$this->dbconfig['MasterServer']['username'],
			$this->dbconfig['MasterServer']['password'],
			false, // mysqli doesn't support persistent connections
			$this->dbconfig['SlaveServer']['servername'],
			$this->dbconfig['SlaveServer']['port'],
			$this->dbconfig['SlaveServer']['username'],
			$this->dbconfig['SlaveServer']['password'],
			false, // mysqli doesn't support persistent connections
			$this->dbconfig['Mysqli']['ini_file'],
			(isset($this->dbconfig['Mysqli']['charset']) ? $this->dbconfig['Mysqli']['charset'] : '')
		);
	}

	/**
	* Lock tables
	*
	* @param	mixed	List of tables to lock
	* @param	string	Type of lock to perform
	*
	*/
	function lock_tables($tablelist)
	{
		if (!empty($tablelist) AND is_array($tablelist))
		{
			$sql = '';
			foreach($tablelist AS $name => $type)
			{
				$sql .= (!empty($sql) ? ', ' : '') . TABLE_PREFIX . $name . " " . $type;
			}

			$this->query_write("LOCK TABLES $sql");
			$this->locked = true;
		}
	}

	function errno()
	{
		if ($this->connection_recent === null)
		{
			$this->errno = 0;
		}
		else
		{
			if (!($this->errno = @$this->functions['errno']($this->connection_recent)))
			{
				$this->errno = 0;
			};
		}

		/*	1046 = No database,
			1146 = Table Missing.
			This is quite likely not a valid vB5 database */
		if ((!defined('VB_AREA') OR VB_AREA != 'Install')
			AND (
				strpos($this->sql, 'routenew')
				OR strpos($this->sql, 'cache')
			)
			AND (in_array($this->errno, $this->getCriticalErrors()))
		)
		{
			$this->errno = -1;
		}

		return $this->errno;
	}

	/**
	* Helper function used by getExplain to run the EXPLAIN query for the current query
	*
	* @param	string	The current SQL query
	*
	* @return	string	The formatted output for the EXPLAIN information for the query
	*/
	protected function runExplainQuery($sql)
	{
		if (!$this->doExplain)
		{
			return;
		}

		$results = $this->functions['query']($this->connection_recent, 'EXPLAIN ' . $sql);
		$output = '<table width="100%" cellpadding="2" cellspacing="1"><tr>';
		while ($field = $this->functions['fetch_field']($results))
		{
			$output .= '<th>' . $field->name . '</th>';
		}
		$output .= '</tr>';
		$numfields = mysqli_field_count($this->connection_recent); // $this->functions['num_fields']
		while ($result = $this->fetch_row($results))
		{
			$output .= '<tr>';
			for ($i = 0; $i < $numfields; $i++)
			{
				$output .= "<td>" . ($result["$i"] == '' ? '&nbsp;' : $result["$i"]) . "</td>";
			}
			$output .= '</tr>';
		}
		$output .= '</table>';

		return $output;
	}

	/**
	* Function to return the codes of critical errors when testing if a database
	* is a valid vB5 database - normally database not found and table not found errors.
	*
	* @return	array	An array of error codes.
	*/
	function getCriticalErrors()
	{
	/*	1046 = No database,
		1146 = Table Missing */
		return array(1046, 1146);
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 101414 $
|| #######################################################################
\*=========================================================================*/
