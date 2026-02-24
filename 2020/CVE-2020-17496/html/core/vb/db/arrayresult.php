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
 * This class in intended to wrap an array for situations where a
 * resultset can be constructed without hitting the database.
 * This is likely a result of a method query hitting some case
 * where a default needs to be returned (and sending a query to the
 * db to produce a known result is kind of silly).
 *
 * it should match the vB_dB_Result interface as the two should be interchangable.
 * @package vBDatabase
 */
class vB_dB_ArrayResult extends ArrayIterator implements Iterator
{
	use vB_Trait_NoSerialize;

	private $recordset = array();
	private $db;

	/**
	 * standard constructor
	 *
	 * @param vB_Database	$db -- the standard vbulletin db object
	 * 	(not used but the result interface requires us to return it)
	 * @param array $recordset -- array of arrays mimicing a db resultset
	 */
	public function __construct($db, $recordset)
	{
		parent::__construct($recordset);
		$this->recordset = $recordset;
		$this->db = $db;
	}

	public function db()
	{
		return $this->db;
	}

	public function free()
	{
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
