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
* Construct a set of option tags for a <select> box consisting of prefixes.
* Note: if you only use one of the no- and any-prefix options, they will each have
* a value of ''; if you use both, any will be '' and none will be '-1'.
*
* @param	integer	if specified, only include prefixes available in a specific forum
* @param	string	The selected value
* @param	boolean	Whether to show a "no prefix" option
* @param	boolean	Whether to show an "any prefix" option
* @param	boolean	Whether to return the no/any options if there are no prefixes available
*
* @return	string	HTML for options
*/
function construct_prefix_options($nodeid = 0, $selectedid = '', $show_no_prefix = true, $show_any_prefix = false, $show_if_empty = false)
{
	global $vbulletin, $vbphrase;
	static $prefix_option_cache = array();

	$nodeid = intval($nodeid);

	if (!isset($prefix_option_cache["$nodeid"]))
	{
		$prefixsets = array();
		$prefixsets_sql = $vbulletin->db->query_read("
			SELECT prefixset.*
			FROM " . TABLE_PREFIX . "prefixset AS prefixset
			" . ($nodeid ?
				"INNER JOIN " . TABLE_PREFIX . "channelprefixset AS channelprefixset ON
					(channelprefixset.prefixsetid = prefixset.prefixsetid AND channelprefixset.nodeid = $nodeid)
				" : '') . "
			ORDER BY prefixset.displayorder
		");
		while ($prefixset = $vbulletin->db->fetch_array($prefixsets_sql))
		{
			$phrased_set = htmlspecialchars_uni($vbphrase["prefixset_$prefixset[prefixsetid]_title"]);
			if ($phrased_set)
			{
				$prefixsets["$phrased_set"] = array();
			}
		}

		$prefixes_sql = $vbulletin->db->query_read("
			SELECT *
			FROM " . TABLE_PREFIX . "prefix
			ORDER BY displayorder
		");
		while ($prefix = $vbulletin->db->fetch_array($prefixes_sql))
		{
			$phrased_set = htmlspecialchars_uni($vbphrase["prefixset_$prefix[prefixsetid]_title"]);
			if (isset($prefixsets["$phrased_set"]))
			{
				$prefixsets["$phrased_set"]["$prefix[prefixid]"] = htmlspecialchars_uni($vbphrase["prefix_$prefix[prefixid]_title_plain"]);
			}
		}

		$prefix_option_cache["$nodeid"] = $prefixsets;
	}

	$construct = $prefix_option_cache["$nodeid"];
	if (!$show_if_empty AND !$construct)
	{
		return '';
	}

	$beginning = array();
	if ($show_no_prefix AND $show_any_prefix)
	{
		$beginning[''] = $vbphrase['any_prefix_meta_gprefix'];
		$beginning['-1'] = $vbphrase['no_prefix_meta_gprefix'];
	}
	else if ($show_no_prefix OR $show_any_prefix)
	{
		$beginning[''] = ($show_no_prefix ? $vbphrase['no_prefix_meta_gprefix'] : $vbphrase['any_prefix_meta_gprefix']);
	}

	if (sizeof($beginning) > 0)
	{
		// don't use array merge -- it will renumber
		$construct = $beginning + $construct;
	}

	return construct_select_options($construct, $selectedid);
}

/**
* Builds the prefix cache datastore entry
*/
function build_prefix_datastore()
{
	vB_Library::instance('prefix')->buildDatastore();
}

/**
* Removes prefixes from threads in certain forums. Useful when a prefix or prefix set
* is no longer available in a forum.
*
* @param	array|string	Array of prefixes (or single one)
* @param	array|integer	Array of forumids (or a single one)
*/
function remove_prefixes_forum($prefixes, $forumids)
{
	global $vbulletin;

	if (!is_array($prefixes))
	{
		$prefixes = array($prefixes);
	}
	$prefixes = array_map(array(&$vbulletin->db, 'escape_string'), $prefixes);

	if (!is_array($forumids))
	{
		$forumids = array($forumids);
	}
	$forumids = array_map('intval', $forumids);

	if (empty($prefixes) OR empty($forumids))
	{
		return;
	}

	$vbulletin->db->query_write("
		UPDATE " . TABLE_PREFIX . "node SET
			prefixid = ''
		WHERE prefixid IN ('" . implode("', '", $prefixes) . "')
			AND nodeid IN (" . implode(',', $forumids) . ")
	");
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
