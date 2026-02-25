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
* Class to do data save/delete operations for thread prefixes
*
* @package	vBulletin
* @version	$Revision: 99787 $
* @date		$Date: 2018-10-24 17:13:06 -0700 (Wed, 24 Oct 2018) $
*/
class vB_DataManager_Prefix extends vB_DataManager
{
	/**
	* Array of recognised and required fields for prefixes, and their types
	*
	* @var	array
	*/
	var $validfields = array(
		'prefixid'			=> array(vB_Cleaner::TYPE_STR,  vB_DataManager_Constants::REQ_YES, vB_DataManager_Constants::VF_METHOD),
		'prefixsetid'		=> array(vB_Cleaner::TYPE_STR,  vB_DataManager_Constants::REQ_YES),
		'displayorder'	=> array(vB_Cleaner::TYPE_UINT, vB_DataManager_Constants::REQ_YES),
		'options'				=> array(vB_Cleaner::TYPE_UINT, vB_DataManager_Constants::REQ_NO),
	);

	/**
	* Condition for update query
	*
	* @var	array
	*/
	var $condition_construct = array('prefixid = \'%1$s\'', 'prefixid');

	/**
	* The main table this class deals with
	*
	* @var	string
	*/
	var $table = 'vBForum:prefix';

	/**
	* Array to store stuff to save to prefixes table
	*
	* @var	array
	*/
	var $prefix = array();

	/**
	* Array to store information
	*
	* @var	array
	*/
	var $info = array(
		'title_plain' => null,
		'title_rich' => null
	);

	var $keyField = 'prefixid';

	/**
	* Verify that the prefix is specified and meets the correct format.
	*
	* @param	string	Prefix ID
	*
	* @return	boolean
	*/
	function verify_prefixid(&$prefixid)
	{
		if ($prefixid === '')
		{
			$this->error('please_complete_required_fields');
			return false;
		}

		if (!preg_match('#^[a-z0-9_]+$#i', $prefixid) OR $prefixid === '0')
		{
			$this->error('invalid_string_id_alphanumeric');
			return false;
		}

		if ($this->registry->db->query_first("SELECT prefixid FROM " . TABLE_PREFIX . "prefix WHERE prefixid = '" . $this->registry->db->escape_string($prefixid) . "'"))
		{
			$this->error('there_is_already_prefix_named_x', $prefixid);
			return false;
		}

		return true;
	}

	/**
	* Any checks to run immediately before saving. If returning false, the save will not take place.
	*
	* @param	boolean	Do the query?
	*
	* @return	boolean	True on success; false if an error occurred
	*/
	function pre_save($doquery = true)
	{
		if ($this->presave_called !== null)
		{
			return $this->presave_called;
		}

		// if (new insert or a new plain title specified) and the title is empty -> error
		if ((!$this->condition OR $this->info['title_plain'] !== null) AND strval($this->info['title_plain']) === '')
		{
			$this->error('please_complete_required_fields');
			$this->presave_called = false;
			return false;
		}

		// if (new insert or a new rich title specified) and the title is empty -> error
		if ((!$this->condition OR $this->info['title_rich'] !== null) AND strval($this->info['title_rich']) === '')
		{
			$this->error('please_complete_required_fields');
			$this->presave_called = false;
			return false;
		}

		$return_value = true;
		// Legacy Hook 'prefixdata_presave' Removed //

		$this->presave_called = $return_value;
		return $return_value;
	}

	/**
	* Additional data to update after a save call (such as denormalized values in other tables).
	* In batch updates, is executed for each record updated.
	*
	* @param	boolean	Do the query?
	*/
	function post_save_each($doquery = true)
	{
		// update phrase
		$db =& $this->registry->db;
		$vbulletin =& $this->registry;

		if (strval($this->info['title_plain']) !== '')
		{
			$db->query_write("
				REPLACE INTO " . TABLE_PREFIX . "phrase
					(languageid, fieldname, varname, text, product, username, dateline, version)
				VALUES
					(
						0,
						'global',
						'" . $db->escape_string('prefix_' . $this->fetch_field('prefixid') . '_title_plain') . "',
						'" . $db->escape_string($this->info['title_plain']) . "',
						'vbulletin',
						'" . $db->escape_string($vbulletin->userinfo['username']) . "',
						" . TIMENOW . ",
						'" . $db->escape_string($vbulletin->templateversion) . "'
					)
			");
		}

		if (strval($this->info['title_rich']) !== '')
		{
			$db->query_write("
				REPLACE INTO " . TABLE_PREFIX . "phrase
					(languageid, fieldname, varname, text, product, username, dateline, version)
				VALUES
					(
						0,
						'global',
						'" . $db->escape_string('prefix_' .  $this->fetch_field('prefixid') . '_title_rich') . "',
						'" . $db->escape_string($this->info['title_rich']) . "',
						'vbulletin',
						'" . $db->escape_string($vbulletin->userinfo['username']) . "',
						" . TIMENOW . ",
						'" . $db->escape_string($vbulletin->templateversion) . "'
					)
			");
		}

		if (!empty($this->existing['prefixsetid']) AND $this->existing['prefixsetid'] != $this->fetch_field('prefixsetid'))
		{
			// updating the prefix set. We need to determine where we used
			// to be able to use this set but can't any more.
			$old_set = $this->existing['prefixsetid'];
			$new_set = $this->fetch_field('prefixsetid');
			$allowed_channels = array(
				$old_set => array(),
				$new_set => array()
			);

			// find all forums where the new and old sets are usable
			$allowed_channels_sql = $db->query_read("
				SELECT prefixsetid, nodeid
				FROM " . TABLE_PREFIX . "channelprefixset
				WHERE prefixsetid IN (
					'" . $db->escape_string($old_set) . "',
					'" . $db->escape_string($new_set) . "'
				)
			");
			while ($allowed_channel = $db->fetch_array($allowed_channels_sql))
			{
				$allowed_channels["$allowed_channel[prefixsetid]"][] = $allowed_channel['nodeid'];
			}

			// remove this prefix from any threads in forums that were removed
			$removed_channels = array_diff($allowed_channels["$old_set"], $allowed_channels["$new_set"]);
			if ($removed_channels)
			{
				require_once(DIR . '/includes/adminfunctions_prefix.php');
				remove_prefixes_forum($this->fetch_field('prefixid'), $removed_channels);
			}
		}

		require_once(DIR . '/includes/adminfunctions_language.php');
		build_language();

		require_once(DIR . '/includes/adminfunctions_prefix.php');
		build_prefix_datastore();

		vB_Cache::instance()->event("vB_Language_languageCache");
		// Legacy Hook 'prefixdata_postsave' Removed //
	}

	/**
	* Additional data to update after a delete call (such as denormalized values in other tables).
	*
	* @param	boolean	Do the query?
	*/
	function post_delete($doquery = true)
	{
		$prefixid = $this->fetch_field('prefixid');
		$db = vB::getDbAssertor();
		$db->update('vBForum:node', array('prefixid' => ''), array('prefixid' => $prefixid));

		// need to rebuild last post info in forums that use this prefix
		require_once(DIR . '/includes/functions_databuild.php');

		$db->delete('phrase', array('varname' => array('prefix_' . $prefixid . '_title_plain', 'prefix_' . $prefixid . '_title_rich')));

		require_once(DIR . '/includes/adminfunctions_language.php');
		build_language();

		require_once(DIR . '/includes/adminfunctions_prefix.php');
		build_prefix_datastore();

		return true;
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
