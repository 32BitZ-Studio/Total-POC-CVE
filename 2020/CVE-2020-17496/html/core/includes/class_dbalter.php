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

error_reporting(E_ALL & ~E_NOTICE);

define('ERRDB_FIELD_DOES_NOT_EXIST', 1);
define('ERRDB_FIELD_EXISTS', 2);
define('ERRDB_ENUM_DOES_NOT_EXIST', 3);
define('ERRDB_ENUM_EXISTS', 4);
define('ERRDB_FIELD_WRONG_TYPE', 5);

define('ERRDB_MYSQL', 100);

/**
* Database Modification Class
*
* This class allows an abstracted method for altering database structure without throwing database errors willy nilly
*
* @package 		vBulletin
* @version		$Revision: 102399 $
* @date 		$Date: 2019-07-30 15:02:53 -0700 (Tue, 30 Jul 2019) $
* @copyright 	http://www.vbulletin.com/license.html
*
*/

abstract class vB_Database_Alter
{
	/**
	* Whether a table has been initialized for altering.
	*
	* @var	boolean
	*/
	var $init = false;

	/**
	* Number of the latest error from the database. 0 if no error.
	*
	* @var	integer
	*/
	var $error_no = 0;

	/**
	* Description of the latest error from the database.
	*
	* @var	string
	*/
	var $error_desc = '';

	/**
	* The text of the last query that has been run. Helpful for debugging.
	*
	* @var	string
	*/
	var $sql = '';

	/**
	* Array of table index data
	*
	* @var	array
	*/
	var $table_index_data = array();

	/**
	* Array of table status data
	*
	* @var	array
	*/
	var $table_status_data = array();

	/**
	* Array of table field data
	*
	* @var	array
	*/
	var $table_field_data = array();

	/**
	* Name of the table being altered
	*
	* @var	string
	*/
	var $table_name = '';

	/**
	* Database object
	*
	* @var  object
	*/
	var $db = null;

	/**
	*
	*
	*/
	var $tag = "### vBulletin Database Alter ###";

	/**
	* Constructor - checks that the database object has been passed correctly.
	*
	* @param	vB_Database	The vB_Database object ($db)
	*/
	public function __construct($db)
	{
		if (is_object($db))
		{
			$this->db = $db;
		}
		else
		{
			trigger_error('<strong>vB_Database_Alter</strong>: $this->db is not an object.', E_USER_ERROR);
		}
	}

	/**
	* Populates the $table_index_data, $table_status_data and $table_field_data arrays with all relevant information that is obtainable
	* about this database table.  Leave $tablename blank to use the table used in the previous call to this functions. The arrays are used
	* by the private and public functions to perform their work.  Nothing can be done to a table until this function is invoked.
	*
	* @param	string	$tablename	Name of table
	*
	* @return	bool
	*/
	public function fetch_table_info($tablename = '')
	{
		$this->set_error();

		if ($tablename != '')
		{
			$this->table_name = $tablename;
		}
		else if ($this->table_name == '')
		{
			trigger_error('<strong>vB_Database_Alter</strong>: The first call to fetch_table_info() requires a valid table parameter.', E_USER_ERROR);
		}

		if ($this->fetch_index_info() AND $this->fetch_table_status() AND $this->fetch_field_info())
		{
			$this->init = true;
		}
		else
		{
			$this->init = false;
		}

		return $this->init;
	}

	/**
	* Returns a text value that relates to the error condition, useable to prepare human readable error phrase varname strings
	*
	* @param	void
	*
	* @return	string
	*/
	public function fetch_error()
	{
		static $errors = array(
			0                          => 'no_error',
			ERRDB_MYSQL                => 'mysql',
			ERRDB_FIELD_DOES_NOT_EXIST => 'field_does_not_exist',
			ERRDB_FIELD_EXISTS         => 'field_already_exists',
			ERRDB_ENUM_DOES_NOT_EXIST  => 'enum_value_does_not_exist',
			ERRDB_ENUM_EXISTS          => 'enum_value_already_exists',
			ERRDB_FIELD_WRONG_TYPE     => 'enum_field_not_enum',
		);

		if (empty($errors["{$this->error_no}"]))
		{
			return 'undefined';
		}
		else
		{
			return $errors["{$this->error_no}"];
		}
	}

	/**
	* Returns error description, set manually or by database error handler
	*
	* @param	void
	*
	* @return	string
	*/
	public function fetch_error_message()
	{
		return $this->error_desc;
	}

	/**
	* Returns the table type, e.g. ISAM, MYISAM, InnoDB
	*
	* @param	void
	*
	* @return	string
	*/
	public function fetch_table_type()
	{
		return strtoupper($this->table_status_data[1]);
	}


	/**
	* Populates $this->table_index_data with index schema relating to $this->table_name
	*
	* @param	void
	*
	* @return	bool
	*/
	abstract protected function fetch_index_info();

	/**
	* Populates $this->table_field_data with column schema relating to $this->table_name
	*
	* @param	void
	*
	* @return	bool
	*/
	abstract protected function fetch_field_info();

	/**
	* Populates $this->table_status_data with table status relating to $this->table_name
	*
	* @param	void
	*
	* @return	bool
	*/
	abstract protected function fetch_table_status();


	/**
	* Drops an index
	*
	* @param	string	$fieldname	Name of index to drop
	*
	* @return	bool
	*/
	abstract public function drop_index($fieldname);

	/**
	* Creates an index. Can be single or multi-column index, normal, unique or fulltext
	*
	* @param	string	$fieldname	Name of index to drop
	* @param	mixed		$fields		Name of field to index.  Create a multi field index by sending an array of field names
	* @param	string	$type			Default is normal. Valid options are 'FULLTEXT' and 'UNIQUE'
	* @param	bool		$overwrite	true = delete an existing index, then add.  false = return false if index of same name already exists unless it matches exactly
	*
	* @return	bool
	*/
	abstract public function add_index($fieldname, $fields, $type = '', $overwrite = false);

	/**
	* Adds field. Can be single fields, or multiple fields. If a field already exists, false will be returned so to silently fail on duplicate fields
	* you would want to call this multiple times, creating a field one at a time.
	*
	* @param	array	$fields		Definition of field to index.  Create multiple fields by sending an array of definitions but see note above.
	* @param	bool	$overwrite	true = delete an existing field of same name, then create.  false = return false if a field of same name already exists
	*
	* @return	bool
	*/
	abstract public function add_field($fields, $overwrite = false);

	/**
	* Drops field. Can be single fields, or multiple fields. If a field doesn't exist, false will be returned so to silently fail on missing fields
	* you would want to call this multiple times, dropping a field one at a time.
	*
	* @param	mixed	$fields		Name of field to drop.  Drop multiple fields by sending an array of names but see note above.
	* @param	bool	$overwrite	true = delete an existing field of same name, then create.  false = return false if a field of same name already exists
	*
	* @return	bool
	*/
	abstract public function drop_field($fields);

	abstract public function add_enum($field, $value, $overwrite = false);

	abstract public function drop_enum($field, $value);

	/**
	* Public
	* Direct write query to the database with error trapping.  Useful when a collision isn't important
	*
	* @param	string	$query		Direct query string to perform
	* @param bool		$escape		true: escape_string $query false: use as-is
	*
	* @return	bool
	*/
	public function query($query, $escape = false) {}

	/**
	* Set the $error_no and $error_desc variables
	*
	* @param	integer	$errno	Errorcode - use values defined at top of class file
	* @param	string	$desc	Description of error. Manually set or returned by database error handler
	*
	* @return	void
	*/
	protected function set_error($errno = 0, $desc = '')
	{
		$this->error_no = $errno;
		$this->error_desc = $desc;
	}

	/**
	* Verifies that fetch_table_info() has been called for a valid table and sets current error condition to none
	* .. in other words verify that fetchTableInfo returns true before proceeding on
	*
	* @param	void
	*
	* @return	void
	*/
	protected function init_table_info()
	{
		global $vbulletin; // need registry!

		if (!$this->init)
		{
			$this->fetch_table_info();
		}

		if (!$this->init)
		{
			$message = '<strong>vB_Database_Alter</strong>: fetch_table_info() has not been called successfully.<br />' . $this->fetch_error_message();
			if ($vbulletin->GPC['ajax'])
			{
				$xml = new vB_XML_Builder_Ajax('text/xml');
				$xml->add_tag('error', $message);
				$xml->print_xml();
			}
			else
			{
				echo $message;
				exit;
			}
		}
		$this->set_error();
	}
}

class vB_Database_Alter_MySQL extends vB_Database_Alter
{

	protected function fetch_index_info()
	{
		$this->set_error();
		$this->table_index_data = array();

		$this->db->hide_errors();
		$tableinfos = $this->db->query_write("
			SHOW KEYS FROM " . TABLE_PREFIX . $this->db->escape_string($this->table_name)
		);
		$this->db->show_errors();
		if (!$tableinfos)
		{
			$this->set_error(ERRDB_MYSQL, $this->db->error());
			return false;
		}
		else
		{
			while ($tableinfo = $this->db->fetch_array($tableinfos))
			{
				$key = $tableinfo['Key_name'];
				$column = $tableinfo['Column_name'];
				if (!$tableinfo['Index_type'] AND $tableinfo['Comment'] == 'FULLTEXT')
				{
					$tableinfo['Index_type'] = 'FULLTEXT';
				}
				unset($tableinfo['Key_name'], $tableinfo['Column_name'], $tableinfo['Table']);
				$this->table_index_data["$key"]["$column"] = $tableinfo;
			}
			return true;
		}
	}

	protected function fetch_field_info()
	{
		$this->set_error();
		$this->table_field_data = array();

		$this->db->hide_errors();
		$tableinfos = $this->db->query_write("
			SHOW FULL COLUMNS FROM " . TABLE_PREFIX . $this->db->escape_string($this->table_name)
		);
		$this->db->show_errors();
		if (!$tableinfos)
		{
			$this->set_error(ERRDB_MYSQL, $this->db->error());
			return false;
		}
		else
		{
			while($tableinfo = $this->db->fetch_array($tableinfos))
			{
				$key = $tableinfo['Field'];
				unset($tableinfo['Field']);
				$this->table_field_data["$key"] = $tableinfo;
			}
			return true;
		}
	}

	protected function fetch_table_status()
	{

		$this->set_error();
		$this->table_status_data = array();

		$this->db->hide_errors();
		$tableinfo = $this->db->query_first("
			SHOW TABLE STATUS LIKE '" . TABLE_PREFIX . $this->db->escape_string($this->table_name) . "'", vB_Database::DBARRAY_NUM
		);
		$this->db->show_errors();

		if (!$tableinfo)
		{
			$this->set_error(ERRDB_MYSQL, $this->db->error());
			return false;
		}
		else
		{
			$this->table_status_data = $tableinfo;
			return true;
		}

	}

	/**
	* Converts table type, i.e. from ISAM to MYISAM
	*
	* @param	string
	*
	* @return	bool
	 */
	//no longer used, but keeping it because it might be useful later.
	private function convert_table_type($type)
	{
		$this->init_table_info();

		if (strtoupper($type) == strtoupper($this->table_status_data[1]))
		{
			// hmm the table is already this type...
			return true;
		}
		else
		{
			$this->sql = "
				{$this->tag}
				ALTER TABLE " . TABLE_PREFIX . $this->db->escape_string($this->table_name) . "
				ENGINE = " . $this->db->escape_string(strtoupper($type));

			$this->db->show_errors();
			$this->db->query_write($this->sql);
			$this->db->show_errors();
			if ($this->db->errno())
			{
				$this->set_error(ERRDB_MYSQL, $this->db->error());
				return false;
			}
			else
			{
				// refresh table_index_data with current information
				$this->fetch_table_info();

				return true;
			}
		}
	}

	public function drop_index($fieldname)
	{
		$this->init_table_info();

		$isPrimary = (strcasecmp($fieldname, 'primary') === 0);
		if ($isPrimary)
		{
			//primary is a keyword that is not case sensitive.  I don't trust it to
			//be consistant across MySql versions
			$indexExists = (!empty($this->table_index_data['primary']) OR !empty($this->table_index_data['PRIMARY']));

		}
		else
		{
			$indexExists = !empty($this->table_index_data["$fieldname"]);
		}

		if ($indexExists)
		{
			if (!$isPrimary)
			{
				$this->sql = "
					{$this->tag}
					ALTER TABLE " . TABLE_PREFIX . $this->db->escape_string($this->table_name) . "
					DROP INDEX " . $this->db->escape_string($fieldname);
			}
			else
			{
				$this->sql = "
					{$this->tag}
					ALTER TABLE " . TABLE_PREFIX . $this->db->escape_string($this->table_name) . "
					DROP PRIMARY KEY ";
			}

			$this->db->hide_errors();
			$this->db->query_write($this->sql);
			$this->db->show_errors();
			if ($this->db->errno())
			{
				$this->set_error(ERRDB_MYSQL, $this->db->error());
				return false;
			}
			else
			{
				// refresh table_index_data with current information
				$this->fetch_table_info();
				return true;
			}
		}
		else
		{
			$this->set_error(ERRDB_FIELD_DOES_NOT_EXIST, $fieldname);
			return false;
		}
	}

	public function add_index($fieldname, $fields, $type = '', $overwrite = false)
	{
		//note sure this does what it thinks it does -- at least centralize it
		$safe_field = $this->db->escape_string($fieldname);

		$this->init_table_info();

		if (!is_array($fields))
		{
			$fields = array($fields);
		}

		$failed = false;
		if (!empty($this->table_index_data["$fieldname"]))
		{
			// this looks for an existing index that matches what we want to create and uses it, Not exact .. doesn't check for defined length i.e. char(10)
			if (count($fields) == count($this->table_index_data["$fieldname"]))
			{
				foreach($fields AS $name)
				{
					//the type check here doesn't do what it thinks it does -- the function expects type to be primary/unique/fulltext/etc.  Index_type is Memory/BTREE/etc
					if (empty($this->table_index_data["$fieldname"]["$name"]) /*OR $this->table_index_data["$fieldname"]["$name"]['Index_type'] != strtoupper($type)*/)
					{
						$failed = true;
					}
				}
			}
			else
			{
				$failed = true;
			}

			if (!$failed)
			{
				return true;
			}
			else if ($overwrite)
			{
				$this->drop_index($fieldname);
				return $this->add_index($fieldname, $fields, $type);
			}
			else
			{
				$this->set_error(ERRDB_FIELD_EXISTS, $fieldname);
				return false;
			}
		}

		if (strtolower($type) == 'fulltext')
		{
			$type = 'FULLTEXT INDEX ' . $safe_field;
		}
		else if (strtolower($type) == 'unique')
		{
			$type = 'UNIQUE INDEX ' . $safe_field;;
		}
		else if (strtolower($type) == 'primary')
		{
			$type = 'PRIMARY KEY';
		}
		else
		{
			$type = 'INDEX ' . $safe_field;;
		}

		$this->db->hide_errors();

		$this->sql = "
			{$this->tag}
			ALTER TABLE " . TABLE_PREFIX . $this->db->escape_string($this->table_name) . "
			ADD $type (" . implode(',', $fields) . ")";

		$this->db->query_write($this->sql);
		$this->db->show_errors();
		if ($this->db->errno())
		{
			$this->set_error(ERRDB_MYSQL, $this->db->error());
			return false;
		}
		else
		{
			// refresh table_index_data with current information
			$this->fetch_table_info();

			return true;
		}
	}

	public function alter_field($fields)
	{
		$this->init_table_info();

		if (!is_array($fields[0]))
		{
			$fields = array($fields);
		}

		$schema = array();
		foreach ($fields AS $field)
		{
			if (empty($this->table_field_data[$field['name']]))
			{
				$this->set_error(ERRDB_FIELD_DOES_NOT_EXIST, $field['name']);
				return false;
			}
			else
			{
				$schema[] = $this->construct_field_def($field);
			}
		}

		// Now add fields.
		$this->sql = "
			{$this->tag}
			ALTER TABLE " . TABLE_PREFIX . $this->db->escape_string($this->table_name) . "
			MODIFY " . implode(",\n\t\t\t\MODIFY ", $schema);

		$this->db->hide_errors();
		$this->db->query_write($this->sql);
		$this->db->show_errors();
		if ($this->db->errno())
		{
			$this->set_error(ERRDB_MYSQL, $this->db->error());
			return false;
		}
		else
		{
			// refresh table_index_data with current information
			$this->fetch_table_info();
			return true;
		}
	}

	private function construct_field_def($field)
	{
		$name = $field['name'];

		$type = strtoupper($field['type']);
		if(!empty($field['length']))
		{
			$type .= '(' . $field['length'] . ')';
		}

		$attributes = $field['attributes'];

		$null = '';
		if(empty($field['null']))
		{
			$null = 'NOT NULL';
		}

		$default = '';
		if(isset($field['default']))
		{
			//quote the default value if it's not numeric
			$default = $field['default'];
			if (preg_match('#[^0-9]#', $default) OR $default === '')
			{
				$default = "'$default'";
			}

			$default = 'DEFAULT ' . $default;
		}

		$extra = '';
		if (isset($field['extra']))
		{
			$extra = $field['extra'];
		}

		$def = "$name $type $attributes $null $default $extra";

		return $def;
	}

	public function add_field($fields, $overwrite = false)
	{
		/*
			$fields = array(
				'name'       => 'foo',
				'type'       => 'varchar',
				'length'     => '20',
				'attributes' => '',
				'null'       => true,	// True = NULL, false = NOT NULL
				'default'    => '',
				'extra'      => '',
			);

		*/

		$this->init_table_info();

		if (!is_array($fields[0]))
		{
			$fields = array($fields);
		}

		$schema = array();
		foreach ($fields AS $field)
		{
			if (!empty($this->table_field_data["{$field['name']}"]))
			{
				if ($overwrite)
				{
					$this->drop_field($field['name']);
					return $this->add_field($field);
				}
				else
				{
					$this->set_error(ERRDB_FIELD_EXISTS, $field['name']);
					return false;
				}
			}
			else
			{
				if (preg_match('#[^0-9]#', $field['default']) OR $field['default'] === '')
				{
					$field['default'] = "'$field[default]'";
				}

				$schema[] =
					"$field[name] " .
					strtoupper($field['type']) . (!empty($field['length']) ? "($field[length])" : '') . ' ' .
					$field['attributes'] . ' ' .
					(!$field['null'] ? 'NOT NULL ' : ' ') .
					(isset($field['default']) ? "DEFAULT $field[default] " : ' ') .
					($field['extra'] != '' ? $field['extra'] : '');
			}
		}

		// Now add fields.
		$this->sql = "
			{$this->tag}
			ALTER TABLE " . TABLE_PREFIX . $this->db->escape_string($this->table_name) . "
			ADD " . implode(",\n\t\t\t\tADD ", $schema);

		$this->db->hide_errors();
		$this->db->query_write($this->sql);
		$this->db->show_errors();
		if ($this->db->errno())
		{
			$this->set_error(ERRDB_MYSQL, $this->db->error());
			return false;
		}
		else
		{
			// refresh table_index_data with current information
			$this->fetch_table_info();
			return true;
		}
	}

	public function query($query, $escape = false)
	{
		$this->db->hide_errors();
		$query = $escape ? $this->db->escape_string($query) : $query;
		$query = "
			{$this->tag}
			$query";
		$this->db->query_write($query);
		$this->db->show_errors();
		if ($this->db->errno())
		{
			$this->set_error(ERRDB_MYSQL, "<br ><pre>$query</pre>" . $this->db->error());
			return false;
		}
		else
		{
			// refresh table_index_data with current information in case we altered the current table
			$this->fetch_table_info();
			return true;
		}
	}

	public function drop_field($fields)
	{
		$this->init_table_info();

		if (!is_array($fields))
		{
			$fields = array($fields);
		}

		$badfields = array();
		foreach ($fields AS $name)
		{
			if (empty($this->table_field_data["$name"]))
			{
				$badfields[] = $name;
			}
		}

		if (!empty($badfields))
		{
			$this->set_error(ERRDB_FIELD_DOES_NOT_EXIST, implode(', ', $badfields));
			return false;
		}

		$this->sql = "
			{$this->tag}
			ALTER TABLE " . TABLE_PREFIX . $this->db->escape_string($this->table_name) . "
				DROP " . implode(",\n\t\t\t\tDROP ", $fields);

		$this->db->hide_errors();
		$this->db->query_write($this->sql);
		$this->db->show_errors();
		if ($this->db->errno())
		{
			$this->set_error(ERRDB_MYSQL, $this->db->error());
			return false;
		}
		else
		{
			// refresh table_index_data with current information
			$this->fetch_table_info();

			return true;
		}
	}

	public function add_enum($field, $value, $overwrite = false)
	{
		$this->init_table_info();

		if (empty($this->table_field_data["$field"]))
		{
			$this->set_error(ERRDB_FIELD_DOES_NOT_EXIST, $field);
			return false;
		}

		if (strpos($this->table_field_data["$field"]['Type'], 'enum(') !== 0)
		{
			$this->set_error(ERRDB_FIELD_WRONG_TYPE, $field);
			return false;
		}

		preg_match('/enum\((.*)\)/i', $this->table_field_data["$field"]['Type'], $matches);
		$enums = explode(',', $matches[1]);

		if (array_search("'$value'", $enums) AND !$overwrite)
		{
			$this->set_error(ERRDB_ENUM_EXISTS, $value);
			return false;
		}

		$enums[] = "'$value'";

		$this->_generate_enum($field, $enums);

		$this->db->hide_errors();
		$this->db->query_write($this->sql);
		$this->db->show_errors();
		if ($this->db->errno())
		{
			$this->set_error(ERRDB_MYSQL, $this->db->error());
			return false;
		}
		else
		{
			// refresh table_index_data with current information
			$this->fetch_table_info();

			return true;
		}

	}

	public function drop_enum($field, $value)
	{
		$this->init_table_info();

		if (empty($this->table_field_data["$field"]))
		{
			$this->set_error(ERRDB_FIELD_DOES_NOT_EXIST, $field);
			return false;
		}

		if (strpos($this->table_field_data["$field"]['Type'], 'enum(') !== 0)
		{
			$this->set_error(ERRDB_FIELD_WRONG_TYPE, $field);
			return false;
		}

		preg_match('/enum\((.*)\)/i', $this->table_field_data["$field"]['Type'], $matches);
		$enums = explode(',', $matches[1]);

		if (($key = array_search("'$value'", $enums)) === false)
		{
			$this->set_error(ERRDB_ENUM_DOES_NOT_EXIST, $field);
			return false;
		}

		unset($enums[$key]);

		$this->_generate_enum($field, $enums);

		$this->db->hide_errors();
		$this->db->query_write($this->sql);
		$this->db->show_errors();
		if ($this->db->errno())
		{
			$this->set_error(ERRDB_MYSQL, $this->db->error());
			return false;
		}
		else
		{
			// refresh table_index_data with current information
			$this->fetch_table_info();

			return true;
		}
	}

	private function _generate_enum($field, $enums)
	{

		$notnull = ($this->table_field_data["$field"]['Null'] == 'NO' ? ' NOT' : '') . ' NULL';

		$default_field = 'NULL';
		if ($this->table_field_data[$field]['Default'] !== NULL)
		{
			// make sure the default value exists.
			$default_field = "'" . ((array_search("'{$this->table_field_data[$field]['Default']}'", $enums) === false) ? '' : $this->table_field_data[$field]['Default']) . "'";
		}

		$default = " DEFAULT $default_field";

		$this->sql = "
			{$this->tag}
			ALTER TABLE " . TABLE_PREFIX . $this->db->escape_string($this->table_name) . "
				CHANGE $field $field ENUM(" . implode(',', $enums) . ")" . $notnull . $default;

	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 102399 $
|| #######################################################################
\*=========================================================================*/
