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
* Class to do data save/delete operations for ANNOUNCEMENTS
*
* @package	vBulletin
* @version	$Revision: 99787 $
* @date		$Date: 2018-10-24 17:13:06 -0700 (Wed, 24 Oct 2018) $
*/
class vB_DataManager_Announcement extends vB_DataManager
{
	/**
	* Array of recognised and required fields for announcements, and their types
	*
	* @var	array
	*/
	protected $validfields = array(
		'announcementid'      => array(vB_Cleaner::TYPE_UINT,     vB_DataManager_Constants::REQ_INCR, vB_DataManager_Constants::VF_METHOD, 'verify_nonzero'),
		'nodeid'              => array(vB_Cleaner::TYPE_INT,      vB_DataManager_Constants::REQ_YES, vB_DataManager_Constants::VF_METHOD),
		'userid'              => array(vB_Cleaner::TYPE_UINT,     vB_DataManager_Constants::REQ_YES, vB_DataManager_Constants::VF_METHOD),
		'title'               => array(vB_Cleaner::TYPE_STR,      vB_DataManager_Constants::REQ_YES, vB_DataManager_Constants::VF_METHOD),
		'pagetext'            => array(vB_Cleaner::TYPE_STR,      vB_DataManager_Constants::REQ_YES, vB_DataManager_Constants::VF_METHOD),
		'startdate'           => array(vB_Cleaner::TYPE_UNIXTIME, vB_DataManager_Constants::REQ_YES),
		'enddate'             => array(vB_Cleaner::TYPE_UNIXTIME, vB_DataManager_Constants::REQ_YES),
		'views'               => array(vB_Cleaner::TYPE_UINT,     vB_DataManager_Constants::REQ_NO),
		'allowhtml'           => array(vB_Cleaner::TYPE_BOOL,     vB_DataManager_Constants::REQ_NO),
		'allowbbcode'         => array(vB_Cleaner::TYPE_BOOL,     vB_DataManager_Constants::REQ_NO),
		'allowsmilies'        => array(vB_Cleaner::TYPE_BOOL,     vB_DataManager_Constants::REQ_NO),
		'announcementoptions' => array(vB_Cleaner::TYPE_UINT,     vB_DataManager_Constants::REQ_NO)
	);

	/**
	* Array of field names that are bitfields, together with the name of the variable in the registry with the definitions.
	*
	* @var	array
	*/
	protected $bitfields = array('announcementoptions' => 'bf_misc_announcementoptions');

	/**
	* The main table this class deals with
	*
	* @var	string
	*/
	var $table = 'vBForum:announcement';

	//Primary Key
	protected $keyField = 'announcementid';

	/**
	* Verifies that the specified nodeid is valid
	*
	* @param	integer	Forum ID (allow -1 = all forums)
	*
	* @return	boolean
	*/
	protected function verify_nodeid(&$forumid)
	{
		$channels = vB_Api::instanceInternal('search')->getChannels(true);
		if ($forumid == -1 OR isset($channels["$forumid"]))
		{
			return true;
		}
		else
		{
			$this->error('invalid_channel_specified');
			return false;
		}
	}

	protected function verify_title(&$data)
	{
		return ($data != '');
	}

	protected function verify_pagetext(&$data)
	{
		return ($data != '');
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

		if ($this->fetch_field('startdate') >= $this->fetch_field('enddate'))
		{
			$this->error('begin_date_after_end_date');
		}

		$return_value = true;
		// Legacy Hook 'announcementdata_presave' Removed //

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
		// Legacy Hook 'announcementdata_postsave' Removed //

		return true;
	}

	/**
	* Additional data to update after a delete call (such as denormalized values in other tables).
	*
	* @param	boolean	Do the query?
	*/
	function post_delete($doquery = true)
	{
		$announcementid = intval($this->existing['announcementid']);
		//$db =& $this->registry->db;

		$this->assertor->delete('vBForum:announcementread', array('announcementid' => $announcementid));

		// Legacy Hook 'announcementdata_delete' Removed //
		return true;
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
