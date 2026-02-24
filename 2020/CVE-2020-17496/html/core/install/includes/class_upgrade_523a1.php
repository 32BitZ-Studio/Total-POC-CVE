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

class vB_Upgrade_523a1 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '523a1';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.2.3 Alpha 1';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.2.2';

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
		$this->drop_table('blog_attachmentlegacy');
	}

	public function step_2()
	{
		$this->drop_table('blog_category');
	}

	public function step_3()
	{
		$this->drop_table('blog_categorypermission');
	}

	public function step_4()
	{
		$this->drop_table('blog_categoryuser');
	}

	public function step_5()
	{
		$this->drop_table('blog_custom_block');
	}

	public function step_6()
	{
		$this->drop_table('blog_custom_block_parsed');
	}

	public function step_7()
	{
		$this->drop_table('blog_deletionlog');
	}

	public function step_8()
	{
		$this->drop_table('blog_editlog');
	}

	public function step_9()
	{
		$this->drop_table('blog_featured');
	}

	public function step_10()
	{
		$this->drop_table('blog_groupmembership');
	}

	public function step_11()
	{
		$this->drop_table('blog_grouppermission');
	}

	public function step_12()
	{
		$this->drop_table('blog_hash');
	}

	public function step_13()
	{
		$this->drop_table('blog_moderation');
	}

	public function step_14()
	{
		$this->drop_table('blog_moderator');
	}

	public function step_15()
	{
		$this->drop_table('blog_pinghistory');
	}

	public function step_16()
	{
		$this->drop_table('blog_rate');
	}

	public function step_17()
	{
		$this->drop_table('blog_read');
	}

	public function step_18()
	{
		$this->drop_table('blog_relationship');
	}

	public function step_19()
	{
		$this->drop_table('blog_search');
	}

	public function step_20()
	{
		$this->drop_table('blog_searchresult');
	}

	public function step_21()
	{
		$this->drop_table('blog_sitemapconf');
	}

	public function step_22()
	{
		$this->drop_table('blog_subscribeentry');
	}

	public function step_23()
	{
		$this->drop_table('blog_subscribeuser');
	}

	public function step_24()
	{
		$this->drop_table('blog_summarystats');
	}

	public function step_25()
	{
		$this->drop_table('blog_tachyentry');
	}

	public function step_26()
	{
		$this->drop_table('blog_text');
	}

	public function step_27()
	{
		$this->drop_table('blog_textparsed');
	}

	public function step_28()
	{
		$this->drop_table('blog_trackback');
	}

	public function step_29()
	{
		$this->drop_table('blog_trackbacklog');
	}

	public function step_30()
	{
		$this->drop_table('blog_user');
	}

	public function step_31()
	{
		$this->drop_table('blog_usercss');
	}

	public function step_32()
	{
		$this->drop_table('blog_usercsscache');
	}

	public function step_33()
	{
		$this->drop_table('blog_userstats');
	}

	public function step_34()
	{
		$this->drop_table('blog_views');
	}

	public function step_35()
	{
		$this->drop_table('blog_visitor');
	}

	public function step_36()
	{
		$this->drop_table('blog');
	}

	/*
		Step 1	-	Remove the "nodestats" (node_dailycleanup.php) cron
	*/
	public function step_37()
	{
		$assertor = vB::getDbAssertor();
		$this->show_message($this->phrase['version']['523a1']['remove_nodestats_cron']);
		$assertor->delete(
			'cron',
			array(
				array('field'=>'varname', 'value' => 'nodestats', vB_dB_Query::OPERATOR_KEY => vB_dB_Query::OPERATOR_EQ)
			)
		);
	}

	/*
		Step 38	-	Remove temporary table previously used by calculateStats queries (downstream of nodestats)
	*/
	public function step_38()
	{
		$this->drop_table('tmp_nodestats');
	}


	/*
		Steps 39 - 41 - ... Remove tables related to the removed nodestats cron
	*/
	public function step_39()
	{
		$this->drop_table('nodestats');
	}

	public function step_40()
	{
		$this->drop_table('nodevisits');
	}

	public function step_41()
	{
		$this->drop_table('nodestatreplies');
	}

	/*
		Clear user.status for banned users.
	 */
	public function step_42($data = null)
	{
		$assertor = vB::getDbAssertor();
		$processlist = $assertor->getRows('vBInstall:findBannedUserWithStatuses', array('timenow' => vB::getRequest()->getTimeNow()));

		if (empty($processlist))
		{
			if (empty($data))
			{
				$this->skip_message();
			}
			else
			{
				$this->show_message(sprintf($this->phrase['core']['process_done']));
			}
			$this->long_next_step();
			return;
		}

		if (!isset($data['startat']))
		{
			$data['startat'] = 0;
			$this->show_message($this->phrase['version']['523a1']['clear_banned_users_statuses']);
		}

		$userids = array();
		foreach ($processlist AS $row)
		{
			$userid = $row['userid'];
			$userids[$userid] = $userid;
		}

		$this->show_message(sprintf($this->phrase['core']['processing_records_x'], count($userids)));

		$assertor->update('user', array('status' => ''), array('userid' => $userids));


		return array('startat' => ++$data['startat']);
	}

	/*
		Steps 43 change user.status to varchar(1000)
	 */
	public function step_43($data = null)
	{
		if ($this->userStatusColumnIsMediumtext())
		{
			$assertor = vB::getDbAssertor();
			$assertor->assertQuery('vBInstall:alterUserStatusToVarchar');
			$this->show_message($this->phrase['version']['523a1']['modify_user_status']);
			return;
		}

		$this->skip_message();
	}

	private function userStatusColumnIsMediumtext()
	{
		$assertor = vB::getDbAssertor();
		$check = $assertor->getRows('vBInstall:showUserColumnStatus');
		if (!empty($check) AND is_array($check))
		{
			$check = reset($check);
			if (isset($check['Type']) AND $check['Type'] == 'mediumtext')
			{
				return true;
			}
		}
		return false;
	}

}
