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
 * This class is a base intended to contain the backend specific details for converting
 * assertor conditions to query code.  The logic is contained in the base class for the
 * time being to allow additional sql backends to override specific functions as
 * much of it will be applicable.  We'll most likely need to heavily refactor this
 * when we add a second backend, but that will be more efficiently done when we know
 * what the requirements of that backend really are.
 *
 * Note that this class is intended to be cached and reused therefore anything that
 * is specific to a particular query needs to be passed as parameter to methods rather
 * than being stored in the class itself.  Only items specific to the db backend
 * should be class members.
 *
 * This is internal to the assertor interface and should not be called from the
 * Application code directly.
 *
 * @package vBDatabase
 */
class vB_dB_QueryBuilder
{
	use vB_Trait_NoSerialize;

	/**
	 * Mapping of operators to text.
	 */
	protected $operators = array (
		vB_dB_Query::OPERATOR_LT => '<',
		vB_dB_Query::OPERATOR_LTE => '<=',
		vB_dB_Query::OPERATOR_GT => '>',
		vB_dB_Query::OPERATOR_GTE => '>=',
		vB_dB_Query::OPERATOR_EQ => '=',
		vB_dB_Query::OPERATOR_NE => '<>',

		//handled special, value is not used.
		vB_dB_Query::OPERATOR_BEGINS => 'LIKE',
		vB_dB_Query::OPERATOR_ENDS => 'LIKE',
		vB_dB_Query::OPERATOR_INCLUDES => 'LIKE',
		vB_dB_Query::OPERATOR_ISNULL => '#',
		vB_dB_Query::OPERATOR_ISNOTNULL => '#',
		vB_dB_Query::OPERATOR_AND => '#',
		vB_dB_Query::OPERATOR_NAND => '#',
	);

	protected $bitOperators = array (
		vB_dB_Query::BITFIELDS_UNSET => '&~',
		vB_dB_Query::BITFIELDS_SET => '|'
	);

	protected $quote_char = "'";

	protected $db = null;
	protected $debug_sql = false;

	/** The character used for quoting in an sql string- usually '.
	 ***/
	protected $quotechar = "'";

	/**
	 * Construct the query builder
	 *
	 * @param $db The db backend specific interface object.
	 */
	public function __construct($db, $debug_sql)
	{
		$this->db = $db;
		$this->debug_sql = $debug_sql;
	}

	/**
	 * This matches a series of values against a query string
	 *
	 *	@param 	string		The query string we want to populate
	 *	@param	mixed			The array of values
	 *
	 *  It returns either a string with all the values inserted ready to execute,
	 *  or false;
	 */
	public function matchValues($queryid, $querystring, $values, $forcetext = array())
	{
		/*
		 * Ported from function in query.php.  Removed logic for table select queries because
		 * this does not appear to be called in that context and it made message passing difficult
		 */

		$replacements = array();
		//The replacements are like {1}
		foreach ($values as $key => $value)
		{
			if ($key == vB_dB_Query::TYPE_KEY OR $key == vB_dB_Query::CONDITIONS_KEY)
			{
				continue;
			}

			$this->quoteValue($key, $value, $forcetext);

			if (is_array($value))
			{
				$value = implode(',', $value);
			}

			$replacements['{' . $key . '}'] =  $value;
		}

		$replacements['{TABLE_PREFIX}'] = TABLE_PREFIX;

		//see if there are matches we don't have replacements for.
		$matches = array();
		preg_match_all('#\{\w{1,32}\}#', $querystring, $matches);
		foreach($matches[0] AS $match)
		{
			if(!isset($replacements[$match]))
			{
				throw new Exception('query_parameter_missing');
			}
		}

		// VBV-4659: Use strtr instead of str_replace to avoid searching within the replaced values
		$querystring = strtr($querystring, $replacements);
		$querystring .= "\n/**" . $queryid . (defined('THIS_SCRIPT') ? '- ' . THIS_SCRIPT : '') . "**/";
		$this->logQuery($querystring);
		return $querystring;
	}


	/**
	 * This function generates the query text against a table.
	 *
	 *	@param	char
	 *	@param	array
	 *
	 *	@return 	mixed
	 **/
	public function conditionsToFilter($conditions, $forcetext = array())
	{
		$limits = array();
		foreach($conditions AS $key => $filter)
		{
			if (is_array($filter) AND is_numeric($key) AND !isset($filter[0]))
			{
				//operator defaults to equals.
				if (!isset($filter[vB_dB_Query::OPERATOR_KEY]))
				{
					$filter[vB_dB_Query::OPERATOR_KEY] = vB_dB_Query::OPERATOR_EQ;
				}

				//check that we understand the current operator.  All recognized operators need to be
				//in the operators array even if we handle them specially.
				if (empty($this->operators[$filter[vB_dB_Query::OPERATOR_KEY]]))
				{
					throw new Exception('invalid_query_operator');
				}

				//field is always required.
				if (!isset($filter['field']))
				{
					throw new Exception('invalid_query_limit_parameters');
				}

				//value is required, except for the isnull operator.
				if (
					$filter[vB_dB_Query::OPERATOR_KEY] != vB_dB_Query::OPERATOR_ISNULL AND
					$filter[vB_dB_Query::OPERATOR_KEY] != vB_dB_Query::OPERATOR_ISNOTNULL AND
					!isset($filter['value'])
				)
				{
					throw new Exception('invalid_query_limit_parameters');
				}

				//if we have an array then the only valid operation is OPERATOR_EQ OR OPERATOR_NE
				if (
					isset($filter['value']) AND is_array($filter['value']) AND
					(($filter[vB_dB_Query::OPERATOR_KEY] != vB_dB_Query::OPERATOR_NE)
					AND ($filter[vB_dB_Query::OPERATOR_KEY] != vB_dB_Query::OPERATOR_EQ))
				)
				{
					throw new Exception('invalid_query_operator');
				}

				// Make sure we build correct SQL for an empty array
				if (isset($filter['value']) AND is_array($filter['value']) AND empty($filter['value']))
				{
					$filter[vB_dB_Query::OPERATOR_KEY] = vB_dB_Query::OPERATOR_FALSE;
				}

				switch ($filter[vB_dB_Query::OPERATOR_KEY])
				{
					//this is the common case, let it be first.
					case vB_dB_Query::OPERATOR_EQ:
					case vB_dB_Query::OPERATOR_NE:
						if (is_array($filter['value']))
						{
							if (in_array($filter['field'], $forcetext))
							{
								$isnumeric = false;
							}
							else
							{
								//we first need to know if it's a number or string.
								$isnumeric = true;
								foreach ($filter['value'] AS $sequence => $fieldval)
								{
									if (!is_numeric($fieldval))
									{
										$isnumeric = false;
										break;
									}
								}
							}

							if (!$isnumeric)
							{
								foreach ($filter['value'] AS $sequence => $fieldval)
								{
									$filter['value'][$sequence] = $this->quotechar . $this->db->escape_string($fieldval) . $this->quotechar;
								}
							}

							if ($filter[vB_dB_Query::OPERATOR_KEY] == vB_dB_Query::OPERATOR_NE)
							{
								$limits[] = $this->escapeField($filter['field']) . " NOT IN (" . implode(',', $filter['value']) . ")";
							}
							else
							{
								$limits[] = $this->escapeField($filter['field']) . " IN (" . implode(',', $filter['value']) . ")";
							}
						}
						//this duplicates the default behavior when the value isn't an array.  We could use failthrough instead,
						//but that's a small step down a bad path.  Better to clone the code.  If it becomes more than a few
						//lines duplicated, we should turn it into a function.
						else
						{
							if (is_object($filter['value']) AND is_a($filter['value'], 'vB_dB_Type'))
							{
								$filter['value'] = $filter['value']->escapeFieldValue();
							}
							else if (!is_numeric($filter['value']) OR in_array($filter['field'], $forcetext))
							{
								$filter['value'] = $this->quotechar . $this->db->escape_string($filter['value']) . $this->quotechar;
							}

							$limits[] = $this->escapeField($filter['field']) . ' ' . $this->operators[$filter['operator']] . ' ' . $filter['value'] . ' ';
						}
						break;

					case vB_dB_Query::OPERATOR_ISNULL:
						$limits[] = $this->escapeField($filter['field']) . ' IS NULL ';
						break;

					case vB_dB_Query::OPERATOR_ISNOTNULL:
						$limits[] = $this->escapeField($filter['field']) . ' IS NOT NULL ';
						break;

					case vB_dB_Query::OPERATOR_BEGINS:
						//escape_string_like also handles escape_string issues.
						$value = $this->quotechar . $this->db->escape_string_like($filter['value']) . '%' . $this->quote_char;
						$limits[] = $this->escapeField($filter['field']) . ' LIKE ' . $value . ' ';
						break;

					case vB_dB_Query::OPERATOR_ENDS:
						//escape_string_like also handles escape_string issues.
						$value = $this->quotechar  . '%' .  $this->db->escape_string_like($filter['value']) . $this->quote_char;
						$limits[] = $this->escapeField($filter['field']) . ' LIKE ' . $value . ' ';
						break;

					case vB_dB_Query::OPERATOR_INCLUDES:
						//escape_string_like also handles escape_string issues.
						$value = $this->quotechar  . '%' .  $this->db->escape_string_like($filter['value']) . '%' . $this->quote_char;
						$limits[] = $this->escapeField($filter['field']) . ' LIKE ' . $value . ' ';
						break;

					case vB_dB_Query::OPERATOR_AND:
						$value = intval($filter['value']);
						//this is true if and only if all of the bits in value are set in field.
						$limits[] = $this->escapeField($filter['field']) . ' & ' . $value . ' = ' . $value;
						break;

					case vB_dB_Query::OPERATOR_NAND:
						$value = intval($filter['value']);
						//this is true if none of the bits in value are set in field
						$limits[] = $this->escapeField($filter['field']) . ' & ' . $value . ' = 0';
						break;

					case vB_dB_Query::OPERATOR_FALSE:
						// SQL that will always find nothing
						$limits[] = '(1 = 0)';
						break;

					//anything that doesn't need special handling.
					default:
						if (is_object($filter['value']) AND is_a($filter['value'], 'vB_dB_Type'))
						{
							$filter['value'] = $value->escapeFieldValue();
						}
						else if (!is_numeric($filter['value']) OR in_array($filter['field'], $forcetext))
						{
							$filter['value'] = $this->quotechar . $this->db->escape_string($filter['value']) . $this->quotechar;
						}

						$limits[] = $this->escapeField($filter['field']) . ' ' . $this->operators[$filter['operator']] .
							' ' . $filter['value'] . ' ';
						break;
				}
			}
			else
			{
				if (is_object($filter) AND is_a($filter, 'vB_dB_Type'))
				{
					$filter = $filter->escapeFieldValue();
				}
				else if (!is_numeric($filter) OR in_array($key, $forcetext))
				{
					$this->quoteValue($key, $filter, $forcetext);
				}

				if (is_array($filter) AND empty($filter))
				{
					$limits[] = '(1 = 0)'; // SQL for an empty array, will always find nothing
				}
				else if (is_array($filter))
				{
					$limits[] = $this->escapeField($key) . ' IN (' . implode(',', $filter) . ')';
				}
				else
				{
					$limits[] = $this->escapeField($key) . ' = ' . $filter;
				}
			}
		}

		return implode(' AND ', $limits);
	}

	public function primaryKeyToFilter($primarykey, &$values, $forcetext = array())
	{
		$return = '';
		if (!is_array($primarykey))
		{
			if (isset($values[$primarykey]))
			{
				//this case is just a variant of the value array.  Left as a seperate function
				//in order to make things cleaner for the calling code.
				$return = $this->valueArrayToFilter(array($primarykey => $values[$primarykey]), $forcetext);
				unset($values[$primarykey]);
			}
		}
		else
		{
			$filtervalues = array();
			foreach ($primarykey as $key)
			{
				if (isset($values[$key]))
				{
					$filtervalues[$key] = $values[$key];
					unset($values[$key]);
				}
			}

			if ($filtervalues)
			{
				$return = $this->valueArrayToFilter($filtervalues, $forcetext);
			}
		}
		return $return;
	}

	public function valueArrayToFilter($values, $forcetext = array())
	{
		if (empty($values))
		{
			return NULL;
		}
		//Fields which are passed in the params but are not part of the filter.
		$ignore = array(
			vB_dB_Query::TYPE_KEY,
			vB_dB_Query::CONDITIONS_KEY,
			vB_dB_Query::PARAM_LIMIT,
			vB_dB_Query::PARAM_LIMITSTART,
			vB_dB_Query::PARAM_LIMITPAGE,
			vB_dB_Query::COLUMNS_KEY,
			vB_dB_Query::PRIORITY_QUERY,
		);
		foreach ($values as $key => $value)
		{
			//if key is an int, then we can get weird casting issues with some of the comparisons.
			//(If an int is compared to a string the string is converted to an it for the comparison)
			$key = (string) $key;

			if (!in_array($key, $ignore))
			{
				// Make sure we build correct SQL for an empty array
				if (is_array($value) && empty($value))
				{
					$value = '';
				}

				//if its an array we need to make an "in" clause
				if (is_array($value))
				{
					//we first need to know if it's a number or string.
					if (in_array($key, $forcetext))
					{
						$isnumeric = false;
					}
					else
					{
						$isnumeric = true;
						foreach ($value as $sequence => $fieldval)
						{
							if (!is_numeric($fieldval))
							{
								$isnumeric = false;
								break;
							}
						}
					}
					if (!$isnumeric)
					{
						foreach ($value as $sequence => $fieldval)
						{
							$value[$sequence] = $this->quotechar . $this->db->escape_string($fieldval) . $this->quotechar;
						}
					}

					$new_values[] = $this->escapeField($key) . " IN (" . implode(',',$value) . ")";
				}
				else if (is_object($value) AND is_a($value, 'vB_dB_Type'))
				{
					$new_values[] = $this->escapeField($key) . " = " . $value->escapeFieldValue();
				}
				else
				{
					if (!is_numeric($value) OR in_array($key, $forcetext))
					{
						$value = $this->quotechar . $this->db->escape_string($value) . $this->quotechar;
					}
					$new_values[] = $this->escapeField($key) . " = " . $value ;
				}

			}
		}

		if (!empty($new_values))
		{
			return implode(' AND ', $new_values);
		}
		else
		{
			return NULL;
		}
	}

	public function valueArrayToSetLine($values, $forcetext = array())
	{
		foreach ($values as $key => $value)
		{
			$key = (string) $key;

			if ($key == vB_dB_Query::BITFIELDS_KEY)
			{
				foreach ($value AS $setting)
				{
					if (
						!is_array($setting) OR
						empty($setting['value']) OR
						empty($setting['operator']) OR
						empty($setting['field']) OR
						empty($this->bitOperators[$setting['operator']])
					)
					{
						throw new Exception('invalid_data');
					}

					$safe_field = $this->escapeField($setting['field']);
					//if this isn't an integer value then the query doesn't make any sense.
					$safe_value = (int) $setting['value'];
					$operator =	 $this->bitOperators[$setting['operator']];
					$new_values[$setting['field'] . $setting['value']] = $safe_field . ' = ' . $safe_field . ' ' . $operator . ' ' . $safe_value;
				}
			}
			else if ($key != vB_dB_Query::TYPE_KEY AND $key != vB_dB_Query::CONDITIONS_KEY)
			{
				if ($value === vB_dB_Query::VALUE_ISNULL)
				{
					$new_values[$key] = $this->escapeField($key) . " = NULL";
				}
				else if (is_object($value) AND is_a($value, 'vB_dB_Type'))
				{
					$new_values[$key] = $this->escapeField($key) . "=" . $value->escapeFieldValue();
				}
				//treat as string if it's a numeric string with a leading zero.
				else if (is_numeric($value) AND !in_array($key, $forcetext) AND !(is_string($value) AND $value[0] == '0'))
				{
					$new_values[$key] = $this->escapeField($key) . "=" . $value;
				}
				else
				{
					$new_values[$key] = $this->escapeField($key) . "=" . $this->quotechar . $this->db->escape_string($value) . $this->quotechar;
				}
			}
		}

		return implode(',', $new_values);
	}

	public function makeSelectQuery($table, $filter, $sortorder, $structure, $params = array())
	{
		if (empty($params[vB_dB_Query::COLUMNS_KEY]))
		{
			$querystring = "SELECT * FROM " . TABLE_PREFIX . $table ;
		}
		else
		{
			if (is_array($params[vB_dB_Query::COLUMNS_KEY]))
			{
				$columns = $params[vB_dB_Query::COLUMNS_KEY];
			}
			else
			{
				$columns = array($params[vB_dB_Query::COLUMNS_KEY]);
			}

			foreach ($columns AS &$column)
			{
				if (!in_array($column, $structure))
				{
					throw new vB_Exception_Database('invalid_request');
				}
				$column = $this->escapeField($column);
			}
			$querystring = "SELECT " . implode(',', $columns) . " FROM " . TABLE_PREFIX . $table ;

		}

		if (!empty($filter))
		{
			$querystring .= "\n WHERE $filter " ;
		}

		if (!empty($sortorder))
		{
			if (is_array($sortorder))
			{
				if (isset($sortorder['field']) AND is_array($sortorder['field']))
				{
					$sorts = array();
					foreach ($sortorder['field'] as $key => $field)
					{

						if (!in_array($field, $structure))
						{
							throw new vB_Exception_Database('invalid_table_sort');
						}

						$sort = $this->escapeField($field);
						if (!empty($sortorder['direction']) AND !empty($sortorder['direction'][$key])
							AND (strtoupper( $sortorder['direction'][$key]) == vB_dB_Query::SORT_DESC))
						{
							$sort .=  ' ' . vB_dB_Query::SORT_DESC;
						}
						else
						{
							$sort .=  ' ' . vB_dB_Query::SORT_ASC;
						}

						$sorts[] = $sort;
					}
					if (!empty($sorts))
					{
						$querystring .= "\n ORDER BY " . implode(', ', $sorts);
					}
				}
				else if (!empty($sortorder['field']))
				{
					if (!in_array($sortorder['field'], $structure))
					{
						throw new vB_Exception_Database('invalid_table_sort');
					}
					$querystring .= "\n ORDER BY " . $this->escapeField($sortorder['field']);

					if (!empty($sortorder['direction']) AND (strtoupper($sortorder['direction']) == vB_dB_Query::SORT_DESC))
					{
						$querystring .= " " . $sortorder['direction'];
					}
				}
				else
				{
					//If we get here we should have just an array of fields.
					foreach ($sortorder as $key => $field)
					{
						if (!in_array($field, $structure))
						{
							throw new vB_Exception_Database('invalid_table_sort');
						}
						else
						{
							$sortorder[$key] = $this->escapeField($field);
						}
					}
					$querystring .= "\n ORDER BY " . implode(',', $sortorder);
				}
			}
			else
			{
				if (!in_array($sortorder, $structure))
				{
					throw new vB_Exception_Database('invalid_table_sort');
				}
				$querystring .= "\n ORDER BY " . $this->escapeField($sortorder);
			}
		}

		if (!empty($params[vB_dB_Query::PARAM_LIMIT]))
		{
			if (!empty($params[vB_dB_Query::PARAM_LIMITSTART]))
			{
				$querystring .= "\n LIMIT " . intval($params[vB_dB_Query::PARAM_LIMITSTART]) . ", " . intval($params[vB_dB_Query::PARAM_LIMIT]);
			}
			else
			{
				$querystring .= "\n LIMIT " . intval($params[vB_dB_Query::PARAM_LIMIT]);
			}

		}

		$this->logQuery($querystring);
		return $querystring;
	}

	public function makeCountQuery($table, $filter, $structure)
	{
		$querystring = "SELECT COUNT(*) AS count FROM " . TABLE_PREFIX . $table ;

		if (!empty($filter))
		{
			$querystring .= "\n WHERE $filter " ;
		}

		$this->logQuery($querystring);
		return $querystring;
	}


	public function makeDeleteQuery($table, $filter, $params = array())
	{
		//deletes need a where clause.
		if (empty($filter) AND (empty($params) OR $params !== vB_dB_Query::CONDITION_ALL))
		{
			throw new Exception('missing_query_condition');
		}

		$sql = "DELETE FROM " . TABLE_PREFIX . $table ;
		if (!empty($filter))
		{
			$sql .= "\n WHERE $filter " ;
		}
		$sql .= "\n/**" .$table . (defined('THIS_SCRIPT') ? '- ' . THIS_SCRIPT : '') . "**/";

		$this->logQuery($sql);
		return $sql;
	}

	public function makeUpdateQuery($table, $filter, $setline, $params = array())
	{
		if (empty($filter) AND (empty($params) OR $params !== vB_dB_Query::CONDITION_ALL))
		{
			throw new Exception('missing_query_condition');
		}
		$sql = "UPDATE " . TABLE_PREFIX . $table . " SET $setline ";
		if (!empty($filter))
		{
			$sql .= "\n WHERE ($filter) " ;
		}
		$sql .= "\n/**" .$table . (defined('THIS_SCRIPT') ? '- ' . THIS_SCRIPT : '') . "**/";
		$this->logQuery($sql);
		return $sql;
	}

	public function makeInsertQuery($table, $ignore, $values, $forcetext = array())
	{
		foreach ($values as $key => $value)
		{
			$key = (string) $key;
			if ($key != vB_dB_Query::TYPE_KEY)
			{
				if (is_object($value) AND is_a($value, 'vB_dB_Type'))
				{
					$new_values[$key] = $value->escapeFieldValue();
				}
				else if(is_array($value))
				{
					throw new Exception('Array passed to Insert Query');
				}
				else if (in_array(gettype($value), array('integer', 'double')) AND !in_array($key, $forcetext))
				{
					$new_values[$key] = $value;
				}
				else
				{
					$new_values[$key] = $this->quotechar . $this->db->escape_string($value) . $this->quotechar;
				}
			}
		}

		$ignore = ($ignore) ? ' IGNORE ' : '';

		$ins_fields = $this->escapeFields(array_keys($new_values));

		$sql = "
			INSERT $ignore INTO " . TABLE_PREFIX . $table . " (" . implode(',', $ins_fields) . ")
			VALUES(" . implode(',', $new_values) . ")" .
			"\n/**" . $table . (defined('THIS_SCRIPT') ? '- ' . THIS_SCRIPT : '') . "**/";

		$this->logQuery($sql);
		return $sql;
	}

	public function makeReplaceQuery($table, $values, $forcetext = array())
	{
		foreach ($values as $key => $value)
		{
			$key = (string) $key;
			if ($key != vB_dB_Query::TYPE_KEY)
			{
				if (is_object($value) AND is_a($value, 'vB_dB_Type'))
				{
					$new_values[$key] = $value->escapeFieldValue();
				}
				else if (in_array(gettype($value), array('integer', 'double')) AND !in_array($key, $forcetext))
				{
					$new_values[$key] = $value;
				}
				else
				{
					$new_values[$key] = $this->quotechar . $this->db->escape_string($value) . $this->quotechar;
				}
			}
		}

		$ins_fields = $this->escapeFields(array_keys($new_values));

		$sql = "
			REPLACE INTO " . TABLE_PREFIX . $table . " (" . implode(',', $ins_fields) . ")
			VALUES(" . implode(',', $new_values) . ")" .
			"\n/**" . $table . (defined('THIS_SCRIPT') ? '- ' . THIS_SCRIPT : '') . "**/";

		$this->logQuery($sql);
		return $sql;
	}

	public function makeInsertMultipleQuery($table, $values, $forcetext = array())
	{
		$ins_fields = $values[vB_dB_Query::FIELDS_KEY];
		$ins_values = array();
		$ins_fields_count = count($ins_fields);
		foreach ($values[vB_dB_Query::VALUES_KEY] AS $row)
		{
			if ($ins_fields_count != count($row))
			{
				// fields and values do not match
				continue;
			}

			$new_values = array();
			foreach ($row AS $key => $row_value)
			{
				if (is_object($row_value) AND is_a($row_value, 'vB_dB_Type'))
				{
					$new_values[] = $row_value->escapeFieldValue();
				}
				else if (is_numeric($row_value) AND !in_array($ins_fields[$key], $forcetext))
				{
					$new_values[] = $row_value;
				}
				else
				{
					$new_values[] = $this->quotechar . $this->db->escape_string($row_value) . $this->quotechar;
				}
			}
			$ins_values[] = '(' . implode(',', $new_values) . ')';
		}

		$ins_fields = $this->escapeFields($ins_fields);

		$sql = "
			INSERT INTO " . TABLE_PREFIX . $table . " (" . implode(',', $ins_fields) . ")
			VALUES " . implode(',', $ins_values) .
				"\n/**" . $table . (defined('THIS_SCRIPT') ? '- ' . THIS_SCRIPT : '') . "**/";
		$this->logQuery($sql);
		return $sql;
	}

	public function setDebugSQL($debug_sql)
	{
		$this->debug_sql = $debug_sql;
	}


	protected function quoteValue($key, &$value, $forcetext = array())
	{
		if (is_object($value) AND is_a($value, 'vB_dB_Type'))
		{
			$value = $value->escapeFieldValue();
		}
		else if (is_array($value))
		{
			//This is an array.  We need to implode it and set as an "IN' string
			if (in_array($key, $forcetext))
			{
				$use_string = true;
			}
			else
			{
				$use_string = false;
				foreach ($value as $fieldval)
				{
					if (!is_numeric($fieldval))
					{
						$use_string = true;
						break;
					}
				}
			}

			if ($use_string)
			{
				foreach ($value as $fieldkey => $fieldval)
				{
					$value[$fieldkey] = $this->quotechar . $this->db->escape_string($fieldval) . $this->quotechar;
				}
			}
		}
		else
		{
			if (!is_numeric($value) OR in_array($key, $forcetext))
			{
				$value =  $this->quotechar . $this->db->escape_string($value) . $this->quotechar;
			}
		}
	}

	/**
	 * Handle situations were the field name might be a reserved word.  Also allow for qualified names.
	 *
	 * @param string $field -- the field name
	 * @return string escaped version of the field name
	 */
	public function escapeField($field)
	{
		//don't allow backticks in the fieldname.  This isn't allowed by mysql and could allow
		//an attacker to break out of the escaping if user sourced data is used as a table name.
		$newField = str_replace('`', '', $field);

		//if the field is qualfied with a table name we want `table`.`field` not `table.field`
		//this means we won't properly handle table names with periods in them.  But would should
		//*have* table names with periods in them
		$newField = str_replace('.', '`.`', $newField);

		return '`' . $newField . '`';
	}

	/**
	 * Escapes a table name -- also qualifies it with the table prefix automatically.
	 *
	 * @param string $table -- the name of the table
	 * @return -- the table name with the appropriate prefixed and escaped for safe
	 * 	query use.
	 */
	public function escapeTable($table)
	{
	 	//This is mostly needed for querydef files where we might have a table crafted
	 	//from outside information.  The table queries validate the table name against
		//a set list of allowed possibilities, which is even more secure.  However, it's
		//good to keep all of the escape functions in one place

		return $this->escapeField(TABLE_PREFIX . $table);
	}

	/**
	 * Handle situations were the field name might be a reserved word.  Also allow for qualified names.
	 *
	 * Handles an array of fieldnames
	 *
	 * @param array $fields -- the field names
	 * @return array escaped version of the field names
	 */
	public function escapeFields(array $fields)
	{
		foreach ($fields as &$field)
		{
			$field = $this->escapeField($field);
		}
		return $fields;
	}

	//we might want to create a version of the "escape_string" db function here
	//to keep the escape functions in one place.  We'd have to call the db
	//object for mysql (since it's a mysql api function ultimately) but that's
	//not necesarily the case for all db backends, and it would provide some
	//isolation for a DB class we ultimately want to replace.

	protected function logQuery($sql)
	{
		if ($this->debug_sql)
		{
			echo 'sql: ' . $sql . "\n";
		}
	}

}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 103946 $
|| #######################################################################
\*=========================================================================*/
