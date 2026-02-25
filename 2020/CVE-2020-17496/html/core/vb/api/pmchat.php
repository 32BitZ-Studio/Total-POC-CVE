<?php

class vB_Api_Pmchat extends vB_Api
{
	protected $disableWhiteList = array('canUsePMChat');

	/**
	 * Checks if 1) the current user is logged in, 2) user is in a usergroup that is allowed
	 * to use the chat system, 3) the chat is enabled globally, and 4) user did not opt out
	 * of vB Messenger via user settings.
	 *
	 * @param	bool     $skipUserOption    (Optional) Default false. Set to true to check
	 *                                      only 1~3 (admin set options), and skip the check
	 *                                      for user opt out.
	 *                                      Useful to determine whether the user settings page
	 *                                      should show or hide the option
	 *
	 * @return array(bool, [string])
	 *             bool    'canuse'	   true if they can use the chat system
	 *             string  'reason'	   if 'canuse' is false, an accompanying reason why user is not allowed. Not set if 'canuse' is true.
	 */
	public function canUsePMChat($skipUserOption = false)
	{
		// Must be logged into send messages.
		$currentUser = vB::getCurrentSession()->get('userid');
		if (empty($currentUser))
		{
			return array(
				'canuse' => false,
				'reason' => 'not_logged_no_permission',
			);
		}

		// Can they use the PM system?
		$canUsePmSystem = vB_Api::instanceInternal('content_privatemessage')->canUsePmSystem();
		if (empty($canUsePmSystem))
		{
			return array(
				'canuse' => false,
				'reason' => 'not_logged_no_permission',
			);
		}


		// Can they use the PM Chat system?
		$vboptions = vB::getDatastore()->getValue('options');
		$systemOnline = ($vboptions['pmchat_enabled']);
		if (!$systemOnline)
		{
			return array(
				'canuse' => false,
				'reason' => 'pmchat_disabled_global',
			);
		}

		$userGroupAuthorized = vb::getUserContext()->hasPermission('pmpermissions', 'canusepmchat');
		if (!$userGroupAuthorized)
		{
			return array(
				'canuse' => false,
				'reason' => 'pmchat_disabled_usergroup',
			);
		}

		if (!$skipUserOption)
		{
			$userInfo = vB::getCurrentSession()->fetch_userinfo();
			if (!$userInfo['enable_pmchat'])
			{
				return array(
					'canuse' => false,
					'reason' => 'pmchat_disabled_user_optout',
				);
			}
		}

		return array(
			'canuse' => true,
		);
	}

	/**
	 * Checks if current user is a recipient of $nodeid
	 *
	 * @param	int     $nodeid
	 *
	 * @return array(bool)
	 *             bool    'result'	   true if they are a recipient
	 */
	public function isMessageParticipant($nodeid)
	{
		$userid = vB::getCurrentSession()->get('userid');

		// Authors or recipients will have a sentto record.
		$check = vB::getDbAssertor()->getRow('vBForum:sentto', array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'nodeid' => $nodeid, 'userid' => $userid));
		if (!empty($check) AND $check['userid'] == $userid AND $check['nodeid'] == $nodeid)
		{
			return array('result' => true);
		}

		return array('result' => false);
	}
}
