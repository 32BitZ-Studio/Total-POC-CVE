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
 * vB_Api_Announcement
 *
 * @package vBApi
 * @access public
 */
class vB_Api_Announcement extends vB_Api
{
	/**
	 * @var vB_dB_Assertor Instance of the database assertor class
	 * @todo Remove this and have this instance set in the parent class vB_Api for all APIs
	 */
	protected $assertor;

	/**
	 * Constructor
	 */
	protected function __construct()
	{
		parent::__construct();

		$this->assertor = vB::getDbAssertor();
	}

	/**
	 * Fetches announcements by channel ID
	 *
	 * @param  int              $channelid (optional) Channel ID
	 * @param  int              $announcementid (optional) Announcement ID
	 *
	 * @throws vB_Exception_Api no_permission if the user doesn't have permission to view the announcements
	 *
	 * @return array            Announcements, each element is an array containing all the fields
	 *                          in the announcement table and username, avatarurl, and the individual
	 *                          options from the announcementoptions bitfield-- dohtml, donl2br,
	 *                          dobbcode, dobbimagecode, dosmilies.
	 */
	public function fetch($channelid = 0, $announcementid = 0)
	{
		$usercontext = vB::getUserContext();
		$userapi = vB_Api::instanceInternal('user');
		$channelapi = vB_Api::instanceInternal('content_channel');
		$parentids = array();

		// Check channel permission
		if ($channelid)
		{
			// This is to verify $channelid
			$channelapi->fetchChannelById($channelid);

			if (!$usercontext->getChannelPermission('forumpermissions', 'canview', $channelid))
			{
				throw new vB_Exception_Api('no_permission');
			}

			$parents = vB_Library::instance('node')->getParents($channelid);
			foreach ($parents AS $parent)
			{
				if ($parent['nodeid'] != 1)
				{
					$parentids[] = $parent['nodeid'];
				}
			}
		}

		$data = array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
			vB_dB_Query::CONDITIONS_KEY => array(
				array('field' => 'startdate', 'value' => vB::getRequest()->getTimeNow(), 'operator' => vB_dB_Query::OPERATOR_LTE),
				array('field' => 'enddate', 'value' => vB::getRequest()->getTimeNow(), 'operator' => vB_dB_Query::OPERATOR_GTE),
			),
		);
		if ($parentids)
		{
			$parentids[] = -1; // We should always include -1 for global announcements
			$data[vB_dB_Query::CONDITIONS_KEY][] = array('field' => 'nodeid', 'value' => $parentids);
		}
		elseif ($channelid)
		{
			$channelid = array($channelid, -1); // We should always include -1 for global announcements
			$data[vB_dB_Query::CONDITIONS_KEY][] = array('field' => 'nodeid', 'value' => $channelid);
		}
		else
		{
			$data[vB_dB_Query::CONDITIONS_KEY][] = array('field' => 'nodeid', 'value' => '-1');
		}

		$announcements = $this->assertor->getRows('vBForum:announcement', $data, array(
			'field' => array('startdate', 'announcementid'),
			'direction' => array(vB_dB_Query::SORT_DESC, vB_dB_Query::SORT_DESC)
		));

		if (!$announcements)
		{
			return array();
		}
		else
		{
			$bbcodeLib = vB_Library::instance('bbcode');

			$results = array();
			$bf_misc_announcementoptions = vB::getDatastore()->getValue('bf_misc_announcementoptions');
			foreach ($announcements AS $k => $post)
			{
				$userinfo = $userapi->fetchUserinfo($post['userid'], array(vB_Api_User::USERINFO_AVATAR, vB_Api_User::USERINFO_SIGNPIC));
				$announcements[$k]['username'] = $userinfo['username'];
				$announcements[$k]['avatarurl'] = $userapi->fetchAvatar($post['userid']);

				$announcements[$k]['dohtml'] = ($post['announcementoptions'] & $bf_misc_announcementoptions['allowhtml']);

				if ($announcements[$k]['dohtml'])
				{
					$announcements[$k]['donl2br'] = false;
				}
				else
				{
					$announcements[$k]['donl2br'] = true;
				}

				$announcements[$k]['dobbcode'] = ($post['announcementoptions'] & $bf_misc_announcementoptions['allowbbcode']);
				$announcements[$k]['dobbimagecode'] = ($post['announcementoptions'] & $bf_misc_announcementoptions['allowbbcode']);
				$announcements[$k]['dosmilies'] = ($post['announcementoptions'] & $bf_misc_announcementoptions['allowsmilies']);

				if ($announcements[$k]['dobbcode'] AND
					$post['announcementoptions'] & $bf_misc_announcementoptions['parseurl'])
				{
					$announcements[$k]['pagetext'] = $bbcodeLib->convertUrlToBbcode($post['pagetext']);
				}
			}

			return $announcements;
		}
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 103194 $
|| #######################################################################
\*=========================================================================*/
