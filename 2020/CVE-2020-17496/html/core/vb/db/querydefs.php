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
abstract class vB_dB_QueryDefs
{
	use vB_Trait_NoSerialize;

	/** This class is called by the new vB_dB_Assertor database class
	 * It does the actual execution. See the vB_dB_Assertor class for more information

	 * $queryid can be either the id of a query from the dbqueries table, or the
	 * name of a table.
	 *
	 * if it is the name of a table , $params MUST include 'type' of either update, insert, select, or delete.
	 *
	 * $params includes a list of parameters. Here's how it gets interpreted.
	 *
	 * If the queryid was the name of a table and type was "update", one of the params
	 * must be the primary key of the table. All the other parameters will be matched against
	 * the table field names, and appropriate fields will be updated. The return value will
	 * be false if an error is generated and true otherwise
	 *
	 * If the queryid was the name of a table and type was "delete", one of the params
	 * must be the primary key of the table. All the other parameters will be ignored
	 * The return value will be false if an error is generated and true otherwise
	 *
	 * If the queryid was the name of a table and type was "insert", all the parameters will be
	 * matched against the table field names, and appropriate fields will be set in the insert.
	 * The return value is the primary key of the inserted record.
	 *
	 * If the queryid was the name of a table and type was "select", all the parameters will be
	 * matched against the table field names, and appropriate fields will be part of the
	 * "where" clause of the select. The return value will be a vB_dB_Result object
	 * The return value is the primary key of the inserted record.
	 *
	 * If the queryid is the key of a record in the dbqueries table then each params
	 * value will be matched to the query. If there are missing parameters we will return false.
	 * If the query generates an error we return false, and otherwise we return either true,
	 * or an inserted id, or a recordset.
	 *
	 **/

	/*Properties====================================================================*/


	/**
	 *	The database type
	 *
	 *	Should be overriden by child classes.
	 */
	protected $db_type = '';

	/**
	 * This is the definition for tables we will process through.  It saves a
	 *
	 * database query to put them here.
	 */
	protected $table_data = array();

	/**
	 * This is the definition for queries we will process through.  We could also
	 * put them in the database, but this eliminates a query.
	 */
	protected $query_data = array();

	/**
	 * This returns the table definitions
	 *
	 *	@return	mixed
	 */
	public function getTableData()
	{
		return $this->table_data;
	}

	/**
	 * This returns the query definitions
	 *
	 *	@return	mixed
	 */
	public function getQueryData()
	{
		return $this->query_data;
	}

	/**
	 *	Returns the resultset for a particular query string
	 *
	 *	Intend for use by method queries to reduce repetative code and increase
	 *	standardization
	 *
	 *	@param object $db -- the internal db connection object for this DB type
	 *	@param string $sql -- the query string for this DB type.
	 *	@param string $tag -- if provided this will append and indentifying comment to
	 *		the query to assist determining where the query resulted from.  This will
	 *		involve more than simply the tag text. (The tag should not contain
	 *		*any* user generated content -- if you don't know where it came from,
	 *		don't use it).
	 */
	protected function getResultSet($db, $sql, $tag = '')
	{
		if($tag)
		{
			$sql .= "\n/** $tag" . (defined('THIS_SCRIPT') ? '- ' . THIS_SCRIPT : '') . '**/';
		}

		$config = vB::getConfig();
		if (isset($config['Misc']['debug_sql']) AND $config['Misc']['debug_sql'])
		{
			echo "sql: $sql<br />\n";
		}

		$resultclass = 'vB_dB_' . $this->db_type . '_result';
		$result = new $resultclass($db, $sql);
		return $result;
	}

	protected function getQueryBuilder($db)
	{
		$className = 'vB_Db_' . $this->db_type . '_QueryBuilder';
		return new $className($db, false);
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 100959 $
|| #######################################################################
\*=========================================================================*/
