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

// ###################### Start makeAdminFaqRow #######################
function print_faq_admin_row($faq, $prefix = '')
{
	global $ifaqcache, $vbphrase, $vbulletin;

	$firstcolumntext = $prefix . '<b></b>';
	if(is_array($ifaqcache["$faq[faqname]"]))
	{
		$firstcolumntext .= '<a href="admincp/faq.php?' . vB::getCurrentSession()->get('sessionurl') . 'faq=' . urlencode($faq['faqname']) .
			"\" title=\"$vbphrase[show_child_faq_entries]\">$faq[title]</a>";
	}
	else
	{
		$firstcolumntext .= $faq['title'];
	}
	$firstcolumntext .= '<b></b>';

	$cell = array(
		$firstcolumntext,
		// second column
		"<input type=\"text\" class=\"bginput\" size=\"4\" name=\"order[$faq[faqname]]\" title=\"$vbphrase[display_order]\" tabindex=\"1\" value=\"$faq[displayorder]\" />",
		// third column
		construct_link_code($vbphrase['edit'], 'faq.php?' . vB::getCurrentSession()->get('sessionurl') . 'do=edit&amp;faq=' . urlencode($faq['faqname'])) .
		construct_link_code($vbphrase['add_child_faq_item'], "faq.php?" . vB::getCurrentSession()->get('sessionurl') . 'do=add&amp;faq=' . urlencode($faq['faqname'])) .
		construct_link_code($vbphrase['delete'], 'faq.php?' . vB::getCurrentSession()->get('sessionurl') . 'do=delete&amp;faq=' . urlencode($faq['faqname'])),
	);
	print_cells_row($cell);
}

// ###################### Start getFaqParents #######################
// get parent titles function for navbar
function fetch_faq_parents($faqname)
{
	global $ifaqcache, $faqcache, $parents, $vbulletin;
	static $i = 0;

	$faq = $faqcache["$faqname"];
	if (is_array($ifaqcache["$faq[faqparent]"]))
	{
		$key = iif($i++, 'faq.php?' . vB::getCurrentSession()->get('sessionurl') . "faq=$faq[faqname]");
		$parents["$key"] = $faq['title'];
		fetch_faq_parents($faq['faqparent']);
	}
}

// ###################### Start getifaqcache #######################
function cache_ordered_faq($gettext = false, $disableproducts = false, $languageid = null)
{
	global $vbulletin, $db, $faqcache, $ifaqcache;
	$assertor = vB::getDbAssertor();

	if ($languageid === null)
	{
		$languageid = LANGUAGEID;
	}

	// ordering arrays
	$displayorder = array();
	$languageorder = array();

	// data cache arrays
	$faqcache = array();
	$ifaqcache = array();
	$phrasecache = array();

	$fieldname = ($gettext) ? array('faqtitle', 'faqtext') : 'faqtitle';
	$phrases = $assertor->assertQuery('vBForum:phrase',
		array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'fieldname' => $fieldname,
			'languageid' => array(-1, 0, $languageid)
		)
	);
	if ( $phrases AND $phrases->valid() )
	{
		foreach($phrases AS $phrase)
		{
			$languageorder["$phrase[languageid]"][] = $phrase;
		}
	}

	ksort($languageorder);

	foreach($languageorder AS $phrases)
	{
		foreach($phrases AS $phrase)
		{
			$phrasecache["$phrase[varname]"] = $phrase['text'];
		}
	}
	unset($languageorder);

	$activeproducts = array(
		'', 'vbulletin'
	);
	if ($disableproducts)
	{
		foreach ($vbulletin->products AS $product => $active)
		{
			if ($active)
			{
				$activeproducts[] = $product;
			}
		}
	}

	// Legacy Hook 'faq_cache_query' Removed //

	/** TODO
	 * Handle hooks inside this query !
	 */

	$conditions = array();
	if ($disableproducts)
	{
		$conditions[] = array('field' => 'product','value' => $activeproducts, 'operator' => vB_dB_Query::OPERATOR_EQ);
	}
	$faqs = $assertor->assertQuery('vBForum:faq',
			array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT, vB_dB_Query::CONDITIONS_KEY => $conditions)
	);
	if ($faqs AND $faqs->valid())
	{
		foreach($faqs AS $faq)
		{
			$faq['title'] = $phrasecache["$faq[faqname]_gfaqtitle"];
			if ($gettext)
			{
				$faq['text'] = $phrasecache["$faq[faqname]_gfaqtext"];
			}
			$faqcache["$faq[faqname]"] = $faq;
			$displayorder["$faq[displayorder]"][] =& $faqcache["$faq[faqname]"];
		}
	}
	unset($faq);
	$vbulletin->db->free_result($faqs);

	unset($phrasecache);
	ksort($displayorder);

	$ifaqcache = array('faqroot' => array());

	foreach($displayorder AS $faqs)
	{
		foreach($faqs AS $faq)
		{
			$ifaqcache["$faq[faqparent]"]["$faq[faqname]"] =& $faqcache["$faq[faqname]"];
		}
	}
}

// ###################### Start getFaqParentOptions #######################
function fetch_faq_parent_options($thisitem = '', $parentname = 'faqroot', $depth = 1)
{
	global $ifaqcache, $parentoptions;
	if (!is_array($parentoptions))
	{
		$parentoptions = array();
	}

	foreach($ifaqcache["$parentname"] AS $faq)
	{
		if ($faq['faqname'] != $thisitem)
		{
			$parentoptions["$faq[faqname]"] = str_repeat('--', $depth) . ' ' . $faq['title'];
			if (is_array($ifaqcache["$faq[faqname]"]))
			{
				fetch_faq_parent_options($thisitem, $faq['faqname'], $depth + 1);
			}
		}
	}
}

// ###################### Start getFaqDeleteList #######################
function fetch_faq_delete_list($parentname)
{
	global $ifaqcache;

	if (!is_array($ifaqcache))
	{
		cache_ordered_faq();
	}

	static $deletelist;
	if (!is_array($deletelist))
	{
		$deletelist = array($parentname);
	}

	if (is_array($ifaqcache["$parentname"]))
	{
		foreach($ifaqcache["$parentname"] AS $faq)
		{
			$deletelist[] = $faq['faqname'];
			fetch_faq_delete_list($faq['faqname']);
		}
	}

	return $deletelist;
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
