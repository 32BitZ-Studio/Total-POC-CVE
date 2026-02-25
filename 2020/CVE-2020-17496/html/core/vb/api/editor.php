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
 * vB_Api_Editor
 *
 * @package vBApi
 * @access public
 */
class vB_Api_Editor extends vB_Api
{
	/**
	 * @var array Smiley Locations
	 */
	protected $smilieImages = array();

	/**
	 * @var array Smiley Titles
	 */
	protected $smilieDescriptions = array();

	/**
	 * @var array Smiley Categories
	 */
	protected $smilieCategories = array();

	/**
	 * @var array Deprecated -- appears to not be used anywhere
	 */
	protected $smilieData = null;

	/**
	 * @var array
	 */
	protected $disableFalseReturnOnly = array('fetchAutoLoadText', 'fetchAllSmilies', 'fetchCustomBbcode');

	/**
	 * Constructor
	 */
	protected function __construct()
	{
		parent::__construct();
	}

	/**
	 * Returns the array of custom bbcode info
	 *
	 * @return array
	 */
	public function fetchCustomBbcode()
	{
		$bbcodeCache = vB::getDatastore()->get_value('bbcodecache');
		$data = array();
		if ($bbcodeCache)
		{
			foreach ($bbcodeCache AS $bbcode)
			{
				if ($bbcode['buttonimage'] != '')
				{
					$data[$bbcode['bbcodetag']] = array(
						'title'       => $bbcode['title'],
						'buttonimage' => $bbcode['buttonimage'],
						'twoparams'   => $bbcode['twoparams'],
					);
				}
			}
		}

		return $data;
	}

	/**
	 * Returns a hierarchical array of smilie data for displaying the smilies panel.
	 *
	 * @return array The smilies
	 */
	public function fetchAllSmilies()
	{
		$smilies = vB::get_db_assertor()->getRows('vBForum:fetchImagesSortedLimited',
			array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_METHOD,
				'table' => 'smilie',
			)
		);

		$options = vB::getDatastore()->get_value('options');

		$smilieInfo = array();
		$previewSmilies = array();
		$previewCount = 0;
		$smilieCount = 0;

		foreach ($smilies AS $smilie)
		{
			if (!isset($smilieInfo[$smilie['category']]))
			{
				$smilieInfo[$smilie['category']] = array();
			}

			$smilieInfo[$smilie['category']][$smilie['smilieid']] = array(
				'image' => $smilie['smiliepath'],
				'description' => vB_String::htmlSpecialCharsUni($smilie['title'] . ' ' . $smilie['smilietext']),
			);
			++$smilieCount;

			if ($previewCount < $options['wysiwyg_smtotal'])
			{
				$previewSmilies[$smilie['smilieid']] = $smilieInfo[$smilie['category']][$smilie['smilieid']];
			}
			++$previewCount;
		}

		return array(
			'categories'     => $smilieInfo,
			'previewSmilies' => $previewSmilies,
			'categoryCount'  => count($smilieInfo),
			'smilieCount'    => $smilieCount,
			'previewCount'   => count($previewSmilies),
			'moreSmilies'    => ($smilieCount > count($previewSmilies)),
		);
	}

	/**
	 * Convert CKEditor HTML into bbcode
	 * - Received from editor mode switch to source
	 *
	 * @param  string HTML text
	 *
	 * @return string BBcode text
	 */
	public function convertHtmlToBbcode($data)
	{
		return array('data' => vB_Api::instanceInternal('bbcode')->parseWysiwygHtmlToBbcode($data));
	}

	/**
	 * Fetch list of supported video types
	 *
	 * @return array List of providers and associated urls
	 */
	public function fetchVideoProviders()
	{
		$bbcodes = vB::getDbAssertor()->assertQuery('bbcode_video', array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT
			),
			array('field' => array('priority'), 'direction' => array(vB_dB_Query::SORT_ASC))
		);

		$codes = array();
		foreach ($bbcodes AS $bbcode)
		{
			$codes[$bbcode['provider']] = $bbcode['url'];
		}

		return array('data' => $codes);
	}

	/**
	 * Save autosave data from editor
	 *
	 * @param  int    Node ID
	 * @param  int    Parent ID
	 * @param  string Source or WYSIWYG mode ('source'|'wysiwyg')
	 * @param  string Post text
	 *
	 * @return bool   True if successful, false if not.
	 */
	public function autosave($nodeid, $parentid, $mode, $pagetext)
	{
		$options = vB::getDatastore()->get_value('options');
		if (!$options['autosave'])
		{
			return false;
		}

		// If we somehow implement autosave for guests, update the disable on JS end @ autoSave() function in plugin.js
		// User must be logged in
		if (!vB::getCurrentSession()->get('userid'))
		{
			return false;
		}

		if ($mode != 'source')
		{
			$pagetext = vB_Api::instanceInternal('bbcode')->parseWysiwygHtmlToBbcode($pagetext);
		}

		/*replace query*/
		vB::getDbAssertor()->replace('vBForum:autosavetext', array(
			'nodeid'   => intval($nodeid),
			'parentid' => intval($parentid),
			'userid'   => vB::getCurrentSession()->get('userid'),
			'pagetext' => $pagetext,
			'dateline' => vB::getRequest()->getTimeNow()
		));

		return true;
	}

	/**
	 * Discard autosave text
	 *
	 * @param  int    Node ID
	 * @param  int    Parent ID
	 *
	 * @return array  Array with "success" element containing true if successful, false if not.
	 */
	public function discardAutosave($nodeid, $parentid)
	{
		// User must be logged in
		if (!vB::getCurrentSession()->get('userid'))
		{
			throw new vB_Exception_Api('no_permission');
		}

		/*delete query*/
		vB::getDbAssertor()->delete('vBForum:autosavetext', array(
			'nodeid'   => intval($nodeid),
			'parentid' => intval($parentid),
			'userid'   => vB::getCurrentSession()->get('userid')
		));

		return array('success' => true);
	}

	/**
	 * Retrieve Autoload Text
	 *
	 * @param  int         Node ID
	 * @param  int         Parent ID
	 *
	 * @return array|false The autosave data array (row from the 'autosavetext' table) or false on failure
	 */
	public function fetchAutoLoadText($parentid, $nodeid)
	{
		$options = vB::getDatastore()->get_value('options');
		if (!$options['autosave'])
		{
			return false;
		}

		if (!vB::getCurrentSession()->get('userid'))
		{
			return false;
		}

		$row = vB::get_db_assertor()->getRow('vBForum:autosavetext',
			array(
				'nodeid'   => intval($nodeid),
				'parentid' => intval($parentid),
				'userid'   => vB::getCurrentSession()->get('userid')
			)
		);

		return $row;
	}

	public function fetchContentEntryLimits($channelInfo = array(), $conversation = array())
	{
		if (!empty($conversation['channelid']))
		{
			$nodeid = $conversation['channelid'];
		}
		else if (!empty($channelinfo['channelid']))
		{
			$nodeid = $channelinfo['channelid'];
		}
		else
		{
			// This is probably contententry_basic calling us.
			// TODO, set default values for this.
		}

		$options = vB::getDatastore()->get_value('options');

		$enableUsermention = (
			$options['allowedbbcodes'] & vB_Api_Bbcode::ALLOW_BBCODE_USER
			// TODO: AND usergroup limit > 0
		);

		return array(
			'enabled' => array(
				'bbcode_user' => $enableUsermention,
			),
			'limits' => array(
				'bbcode_user' => 0, // todo
			),
		);
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
