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

class vB_External_Export_Rss extends vB_External_Export
{
	// RSS information needed to fill format fields
	protected $rssinfo = array();

	// default language information
	protected $defaultLang = array();

	// assertor
	protected $assertor;

	protected function __construct()
	{
		parent::__construct();
		$this->loadDefLanguage();
		$this->assertor = vB::getDbAssertor();
	}

	protected function buildOutputFromItems($items, $options)
	{
		$this->loadRssInfo($options);
	}

	/**
	 * Loads default language data needed for RSS output
	 */
	protected function loadDefLanguage()
	{
		$langid = vB::getDatastore()->getOption('languageid');
		$languages = vB_Api::instanceInternal('language')->fetchAll();
		$this->defaultLang = $languages[$langid];
	}

	/**
	 * Loads information needed for RSS output
	 *
	 * @param 	array 	Options to be considered for feed.
	 */
	protected function loadRssInfo($options)
	{
		$description = $this->getPhraseFromGuid(vB_Page::PAGE_HOME, 'metadesc');

		$stylevars = vB_Api::instanceInternal('style')->fetchStylevars(array(vB::getDatastore()->getOption('styleid')));
		$imgdir = (!empty($stylevars['imgdir_misc']) AND !empty($stylevars['imgdir_misc']['imagedir'])) ? $stylevars['imgdir_misc']['imagedir'] : '';
		$this->rssinfo = array(
			'title' => vB::getDatastore()->getOption('bbtitle'),
			'link' => vB::getDatastore()->getOption('frontendurl'),
			'icon' => $imgdir . '/rss.png',
			'description' => $description,
			'ttl' => 60
		);

		$this->rssinfo = $this->applyRssOptions($options, $this->rssinfo);
	}


	/**
	 *
	 * Gather needed channel information for RSS items.
	 * Like htmltitle which is a clean version of channel title.
	 *
	 * @param 	Array 	List of items to fetch channel information for.
	 *
	 * @return 	Array 	Array containing the needed channels information.
	 */
	protected function getItemsChannelInfo($items)
	{
		$info = array();
		foreach ($items AS $id => $item)
		{
			if (!isset($info[$item['content']['channelid']]))
			{
				$info[$item['content']['channelid']] = vB_Library::instance('node')->getNodeBare($item['content']['channelid']);
			}
		}

		return $info;
	}

	/**
	 * Builds description tag content used in RSS outputs.
	 *
	 * 	@param 		String 	Text to build description from.
	 *	@param 		Array 	Options to consider building description.
	 *
	 * 	@return 	String 	Description.
	 *
	 */
	protected function getItemDescription($text, $options)
	{
		// @TODO VBV-11108 description should be plain text only, replace this to use plain text parser when implemented
		if (!empty($options['fulldesc']))
		{
			$description = vB_String::htmlSpecialCharsUni(
				vB_String::fetchCensoredText(
					vB_String::stripBbcode($text, true, false, true, true)
				)
			);
		}
		else
		{
			$description = vB_String::htmlSpecialCharsUni(
				vB_String::fetchCensoredText(
					vB_String::fetchTrimmedTitle(
						vB_String::stripBbcode($text, true, false, true, true), vB::getDatastore()->getOption('threadpreview')
					)
				)
			);
		}

		return $description;
	}

	/**
	 * Modifies RSS information used for output from given options
	 *
	 * @param 	array 	Options.
	 */
	private function applyRssOptions($options, $info)
	{
		foreach ($this->options AS $name => $val)
		{
			if (isset($options[$name]))
			{
				switch ($name)
				{
					case 'nodeid':
						if (sizeof($options[$name]) == 1)
						{
							$channel = $this->assertor->getRow('vBForum:getPageInfoFromChannelId', array(
								'nodeid' => $options[$name]
							));

							$info['title'] = vB_Phrase::fetchSinglePhrase('external_x_hyphen_y', array($info['title'], $this->getPhraseFromGuid($channel['guid'], 'title')));
							$info['description'] = $this->getPhraseFromGuid($channel['guid'], 'metadesc');
						}
						else
						{
							$info['title'] = vB_Phrase::fetchSinglePhrase('external_x_hyphen_y', array($info['title'], implode(', ', $options[$name])));
						}
						break;
					default:
						break;
				}
			}
		}

		return $info;
	}

	/**
	 * Get metadescription phrase from a given page.guid
	 *
	 * @param 	string 	GUID
	 * @param 	string 	Field to render phrase (title, metadesc)
	 *
	 * @return 	string 	Phrase
	 */
	private function getPhraseFromGuid($guid, $phrase)
	{
		$guidforphrase = vB_Library::instance('phrase')->cleanGuidForPhrase($guid);
		$rows = $this->assertor->getRows('vBForum:phrase', array('languageid' => array($this->defaultLang['languageid'], 0, -1),
			'varname' => ('page_' . $guidforphrase . '_' . $phrase)
		));

		$description = '';
		if (!empty($rows) AND is_array($rows) AND !isset($rows['errors']))
		{
			foreach ($rows AS $row)
			{
				// get default lang phrase if possible
				if ($row['languageid'] == $this->defaultLang['languageid'])
				{
					$description = $row['text'];
				}
				// default install set lang -1 for page phrases which change to the right langid or 0 on page edit/save.
				else if (in_array($row['languageid'], array(0, -1)))
				{
					$description = $row['text'];
				}
			}
		}
		else
		{
			$page = $this->assertor->getRow('vBForum:page', array('guid' => $guid));
			$description = $page[($phrase == 'title' ? $phrase : 'metadescription')];
		}

		return $description;
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
