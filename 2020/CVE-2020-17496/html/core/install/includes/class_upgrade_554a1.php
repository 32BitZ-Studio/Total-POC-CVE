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

class vB_Upgrade_554a1 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '554a1';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.5.4 Alpha 1';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.5.3';

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
		$db = vB::getDbAssertor();
		$this->show_message(sprintf($this->phrase['vbphrase']['update_table'], TABLE_PREFIX . 'faq'));
		$db->delete('vBForum:faq', array('faqname' => 'general_facebook_publish'));
	}

	/**
	 * Add 'monitoredword' notification type to 'about' in privatemessage
	 */
	public function step_2()
	{
		if ($this->field_exists('privatemessage', 'about'))
		{
			$this->run_query(
			sprintf($this->phrase['core']['altering_x_table'], 'privatemessage', 1, 1),
				"ALTER TABLE " . TABLE_PREFIX . "privatemessage MODIFY COLUMN about ENUM(
					'" . vB_Library_Content_Privatemessage::NOTIFICATION_TYPE_VOTE . "',
					'" . vB_Library_Content_Privatemessage::NOTIFICATION_TYPE_VOTEREPLY . "',
					'" . vB_Library_Content_Privatemessage::NOTIFICATION_TYPE_RATE . "',
					'" . vB_Library_Content_Privatemessage::NOTIFICATION_TYPE_REPLY . "',
					'" . vB_Library_Content_Privatemessage::NOTIFICATION_TYPE_FOLLOW . "',
					'" . vB_Library_Content_Privatemessage::NOTIFICATION_TYPE_FOLLOWING . "',
					'" . vB_Library_Content_Privatemessage::NOTIFICATION_TYPE_VM . "',
					'" . vB_Library_Content_Privatemessage::NOTIFICATION_TYPE_COMMENT . "',
					'" . vB_Library_Content_Privatemessage::NOTIFICATION_TYPE_THREADCOMMENT . "',
					'" . vB_Library_Content_Privatemessage::NOTIFICATION_TYPE_SUBSCRIPTION . "',
					'" . vB_Library_Content_Privatemessage::NOTIFICATION_TYPE_MODERATE . "',
					'" . vB_Library_Content_Privatemessage::NOTIFICATION_TYPE_USERMENTION . "',
					'" . vB_Library_Content_Privatemessage::NOTIFICATION_TYPE_MONITOREDWORD . "',
					'" . vB_Api_Node::REQUEST_TAKE_OWNER . "',
					'" . vB_Api_Node::REQUEST_TAKE_MODERATOR . "',
					'" . vB_Api_Node::REQUEST_GRANT_OWNER . "',
					'" . vB_Api_Node::REQUEST_GRANT_MODERATOR . "',
					'" . vB_Api_Node::REQUEST_GRANT_MEMBER . "',
					'" . vB_Api_Node::REQUEST_TAKE_MEMBER . "',
					'" . vB_Api_Node::REQUEST_TAKE_SUBSCRIBER . "',
					'" . vB_Api_Node::REQUEST_GRANT_SUBSCRIBER . "',
					'" . vB_Api_Node::REQUEST_SG_TAKE_OWNER . "',
					'" . vB_Api_Node::REQUEST_SG_TAKE_MODERATOR . "',
					'" . vB_Api_Node::REQUEST_SG_GRANT_OWNER . "',
					'" . vB_Api_Node::REQUEST_SG_GRANT_MODERATOR . "',
					'" . vB_Api_Node::REQUEST_SG_GRANT_SUBSCRIBER . "',
					'" . vB_Api_Node::REQUEST_SG_TAKE_SUBSCRIBER . "',
					'" . vB_Api_Node::REQUEST_SG_GRANT_MEMBER . "',
					'" . vB_Api_Node::REQUEST_SG_TAKE_MEMBER . "'
				);"
			);
		}
		else
		{
			$this->skip_message();
		}
	}
}

/*======================================================================*\
|| ####################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 102210 $
|| ####################################################################
\*======================================================================*/
