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

class vB_Channel
{
	use vB_Trait_NoSerialize;

	// Less obvious channel names.
	const MAIN_CHANNEL           = 'vbulletin-4ecbdf567f2773.55528984'; // Overall master root node
	//This constant is badly named and probably causes much confusion.  It's the "special" channel where we
	//store stuff that uses the node/channel system but doesn't really have a public hierarchy (like PMs)
	//We really shouldn't be defaulting anything to that channel (its children are well known and not
	//created/removed except at install/upgrade
	const DEFAULT_CHANNEL_PARENT = 'vbulletin-4ecbdf567f3341.44451100'; // 'Special' root channel
	const DEFAULT_FORUM_PARENT   = 'vbulletin-4ecbdf567f2c35.70389590'; // Forums root channel
	const MAIN_FORUM             = 'vbulletin-4ecbdf567f3341.44450667'; // Default Main Forum on new installations
	const MAIN_FORUM_CATEGORY    = 'vbulletin-4ecbdf567f3341.44450666'; // Default Main Category on new installations  Deprecated as of 5.1.0
	const DEFAULT_BLOG_PARENT    = 'vbulletin-4ecbdf567f3a38.99555305'; // Blogs root channel
	const DEFAULT_ARTICLE_PARENT = 'vbulletin-c-cmshome5229fa38b251e2.92227401'; // Articles root channel (CMS)

	// It should be obvious from the names of these what they are.
	const DEFAULT_SOCIALGROUP_PARENT         = 'vbulletin-4ecbdf567f3a38.99555306';
	const DEFAULT_UNCATEGORIZEDGROUPS_PARENT = 'vbulletin-4ecbdf567f3a38.99555307';
	const PRIVATEMESSAGE_CHANNEL             = 'vbulletin-4ecbdf567f3da8.31769341';
	const VISITORMESSAGE_CHANNEL             = 'vbulletin-4ecbdf567f36c3.90966558';
	const ALBUM_CHANNEL                      = 'vbulletin-4ecbdf567f3a38.99555303';
	const REPORT_CHANNEL                     = 'vbulletin-4ecbdf567f3a38.99555304';
	const INFRACTION_CHANNEL                 = 'vbulletin-4ecbdf567f3a38.99555308';

	// If any new default channels under "special" are added, please update getSpecialChannelGuids()

	// Keep notification $validSourceChannelTypes in sync with this (where appropriate)
	protected static $channelTypes = array(
		self::DEFAULT_FORUM_PARENT       => 'forum',
		self::DEFAULT_BLOG_PARENT        => 'blog',
		self::DEFAULT_ARTICLE_PARENT     => 'article',
		self::DEFAULT_SOCIALGROUP_PARENT => 'group',
		self::VISITORMESSAGE_CHANNEL     => 'vm',
		self::PRIVATEMESSAGE_CHANNEL     => 'pm',
		self::ALBUM_CHANNEL              => 'album',
		self::REPORT_CHANNEL             => 'report',
		self::INFRACTION_CHANNEL         => 'infraction',
	);

	protected static $channelLabels = array(
		'forum'      => 'forum',
		'blog'       => 'posttype_blog',
		'group'      => 'group',
		'vm'         => 'posttype_visitorMessage',
		'pm'         => 'private_message',
		'album'      => 'album',
		'report'     => 'report',
		'infraction' => 'infraction',
		'article'    => 'articles',
	);

	/**
	 * Moves all blog channels from the old blog channel parent to the new one.
	 * @param int $oldChannelId
	 * @param int $newChannelId
	 */
	public static function moveBlogChannels($oldChannelId, $newChannelId)
	{
		if (empty($oldChannelId))
		{
			$oldChannelId = vB::getDbAssertor()->getField('vBForum:channel', array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT, 'guid' => self::DEFAULT_BLOG_PARENT));
		}

		$children = vB::getDbAssertor()->assertQuery('vBForum:closure', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'parent' => $oldChannelId,
			'depth' => 1
		));

		$childrenIds = array();
		foreach ($children AS $child)
		{
			$childrenIds[] = $child['child'];
		}
		if (!empty($childrenIds))
		{
			vB_Api::instanceInternal('node')->moveNodes($childrenIds, $newChannelId);
		}
	}

	public static function getDefaultGUIDs()
	{
		return array(
			'MAIN_CHANNEL' => self::MAIN_CHANNEL,
			'MAIN_FORUM' => self::MAIN_FORUM,
			'DEFAULT_CHANNEL_PARENT' => self::DEFAULT_CHANNEL_PARENT,
			'DEFAULT_FORUM_PARENT' => self::DEFAULT_FORUM_PARENT,
			'DEFAULT_BLOG_PARENT' => self::DEFAULT_BLOG_PARENT,
			'DEFAULT_SOCIALGROUP_PARENT' => self::DEFAULT_SOCIALGROUP_PARENT,
			'DEFAULT_UNCATEGORIZEDGROUPS_PARENT' => self::DEFAULT_UNCATEGORIZEDGROUPS_PARENT,
			'DEFAULT_ARTICLE_PARENT' => self::DEFAULT_ARTICLE_PARENT,
			'PRIVATEMESSAGE_CHANNEL' => self::PRIVATEMESSAGE_CHANNEL,
			'VISITORMESSAGE_CHANNEL' => self::VISITORMESSAGE_CHANNEL,
			'ALBUM_CHANNEL' => self::ALBUM_CHANNEL,
			'REPORT_CHANNEL' => self::REPORT_CHANNEL,
			'INFRACTION_CHANNEL' => self::INFRACTION_CHANNEL,
		);
	}

	/** Rebuilds the map of channel to channel type.
	 */
	public static function rebuildChannelTypes()
	{
		$channelQry = vB::getDbAssertor()->assertQuery('vBAdmincp:getChannelTypes', array('guids' => array_keys(self::$channelTypes)));
		$channelTypes = array();
		foreach ($channelQry AS $channelType)
		{
			//Note that it's possible there could be more than one record for a given node. We sorted by depth descending, so the closest
			//one will be last.
			$channelTypes[$channelType['nodeid']] = self::$channelTypes[$channelType['guid']];
		}

		vB::getDatastore()->build('vBChannelTypes', serialize($channelTypes), 1);
	}

	public static function getChannelTypes()
	{
		$types = array();
		$vBChannelTypes = vB::getDbAssertor()->assertQuery('vBForum:channel', array('guid' => array_keys(self::$channelTypes)));

		foreach ($vBChannelTypes AS $channel)
		{
			$types[$channel['nodeid']] = array(
				'type'	=> self::$channelTypes[$channel['guid']],
				'GUID'	=> $channel['guid'],
				'label' => self::$channelLabels[self::$channelTypes[$channel['guid']]]
			);
		}

		return $types;
	}

	// these channels cannot be deleted via the channel API
	public static function getProtectedChannelGuids()
	{
		return array(
			'MAIN_CHANNEL' => self::MAIN_CHANNEL,
			'DEFAULT_CHANNEL_PARENT' => self::DEFAULT_CHANNEL_PARENT,
			'DEFAULT_FORUM_PARENT' => self::DEFAULT_FORUM_PARENT,
			'DEFAULT_BLOG_PARENT' => self::DEFAULT_BLOG_PARENT,
			'DEFAULT_SOCIALGROUP_PARENT' => self::DEFAULT_SOCIALGROUP_PARENT,
			'DEFAULT_ARTICLE_PARENT' => self::DEFAULT_ARTICLE_PARENT,
			'PRIVATEMESSAGE_CHANNEL' => self::PRIVATEMESSAGE_CHANNEL,
			'VISITORMESSAGE_CHANNEL' => self::VISITORMESSAGE_CHANNEL,
			'ALBUM_CHANNEL' => self::ALBUM_CHANNEL,
			'REPORT_CHANNEL' => self::REPORT_CHANNEL,
			'INFRACTION_CHANNEL' => self::INFRACTION_CHANNEL,
		);
	}

	public static function getSpecialChannelGuids()
	{
		return array(
			// DEFAULT_CHANNEL_PARENT = "Special" channel
			'DEFAULT_CHANNEL_PARENT' => self::DEFAULT_CHANNEL_PARENT,
			'PRIVATEMESSAGE_CHANNEL' => self::PRIVATEMESSAGE_CHANNEL,
			'VISITORMESSAGE_CHANNEL' => self::VISITORMESSAGE_CHANNEL,
			'ALBUM_CHANNEL' => self::ALBUM_CHANNEL,
			'REPORT_CHANNEL' => self::REPORT_CHANNEL,
			'INFRACTION_CHANNEL' => self::INFRACTION_CHANNEL,
		);
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 103400 $
|| #######################################################################
\*=========================================================================*/
