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

class vB_Upgrade_511a7 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '511a7';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.1.1 Alpha 7';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.1.1 Alpha 6';

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


	/**
	 * Step 1 :
	 *		Add 'subscription' notification types to about in privatemessage
	 */
	public function step_1()
	{
		if ($this->field_exists('privatemessage', 'about'))
		{
			$this->run_query(
			sprintf($this->phrase['core']['altering_x_table'], 'privatemessage', 1, 1),
				"ALTER TABLE " . TABLE_PREFIX . "privatemessage MODIFY COLUMN about ENUM(
					'vote',
					'vote_reply',
					'rate',
					'reply',
					'follow',
					'following',
					'vm',
					'comment',
					'threadcomment',
					'subscription',
					'moderate',
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

	/**
	 * Change useragent from 100 to 255 chars (Basically replicates 4.2.3 Beta 4 Step 2)
	 */
	public function step_2()
	{
		if ($this->field_exists('session', 'useragent'))
		{
			$this->run_query(
				sprintf($this->phrase['core']['altering_x_table'], 'session', 1, 1),
				"ALTER TABLE " . TABLE_PREFIX . "session CHANGE useragent useragent CHAR(255) NOT NULL DEFAULT ''"
			);
		}
		else
		{
			$this->skip_message();
		}
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
