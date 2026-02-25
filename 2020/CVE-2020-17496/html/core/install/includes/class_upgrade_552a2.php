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
/*
if (!isset($GLOBALS['vbulletin']->db))
{
	exit;
}
*/

class vB_Upgrade_552a2 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '552a2';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.5.2 Alpha 2';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.5.2 Alpha 1';

	/**
	* Beginning version compatibility
	*
	* @var	string
	*/
	public $VERSION_COMPAT_STARTS = '';

	/**
	* Ending version compatibility
	*
	* @var	string
	*/
	public $VERSION_COMPAT_ENDS   = '';

	public function step_1()
	{
		/*
			See the note on mysql schema, but in short having the parentid
			index by itself makes it available for mysql optimizer to use in
			some bad index merges when trying to fetch topics in a large channel,
			and anything that uses the parentid index solo can do so by using either
			node_parent_lastcontent(parentid, showpublished, showapproved, lastcontent, lastcontentid),
			or
			node_parent_inlist_lastcontent(parentid, inlist, lastcontent),
			indices, so we *shouldn't* be losing much.
			Dropping this index allows the mysql optimizer to use
			node_parent_lastcontent to short-circuit some specialized topic fetch queries

		 */
		$this->drop_index(
			sprintf($this->phrase['core']['altering_x_table'], 'node', 1, 3),
			'node',
			'node_parent'
		);
		$this->long_next_step();
	}

	public function step_2()
	{
		/*
			Note, node_parent_lastcontent actually works pretty well for the "first page"
			queries, (especially when we replace the showpublished > 0 & showapproved > 0
			to =1's to not inadvertently use range scans on what really should be boolean
			columns).
			However, it seems that this index performs better when there is no equals filter
			on showpublished & showapproved (e.g. an admin or mod viewing the channel).
		*/

		$this->add_index(
			sprintf($this->phrase['core']['altering_x_table'], 'node', 2, 3),
			'node',
			'node_parent_inlist_lastcontent',
			array('parentid', 'inlist', 'lastcontent')
		);
		$this->long_next_step();
	}

	public function step_3()
	{
		/*
			Add the parentid,userid index to support queries counting ignored/blacklisted users' topics
		*/

		$this->add_index(
			sprintf($this->phrase['core']['altering_x_table'], 'node', 3, 3),
			'node',
			'node_parent_userid',
			array('parentid', 'userid')
		);
	}
}

/*======================================================================*\
|| ####################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 101001 $
|| ####################################################################
\*======================================================================*/