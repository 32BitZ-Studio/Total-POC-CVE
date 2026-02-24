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

class vB_External_Export_Rss_2 extends vB_External_Export_Rss
{
	protected $type = 'RSS2';
	
	public function __construct()
	{
		parent::__construct();
	}

	protected function buildOutputFromItems($items, $options)
	{
		parent::buildOutputFromItems($items, $options);

		$xml = new vB_Xml_Builder();
		$xml->add_group('rss', array(
			'version'       => '2.0',
			'xmlns:dc'      => 'http://purl.org/dc/elements/1.1/',
			'xmlns:content' => 'http://purl.org/rss/1.0/modules/content/'
		));

		$xml->add_group('channel');
			$xml->add_tag('title', $this->rssinfo['title']);
			$xml->add_tag('link', $this->rssinfo['link'] . '/', array(), false, true);
			$xml->add_tag('description', $this->rssinfo['description']);
			$xml->add_tag('language', $this->defaultLang['languagecode']);
			$xml->add_tag('lastBuildDate', gmdate('D, d M Y H:i:s') . ' GMT');
			$xml->add_tag('generator', 'vBulletin');
			$xml->add_tag('ttl', $this->rssinfo['ttl']);
			$xml->add_group('image');
				$xml->add_tag('url', $this->rssinfo['icon']);
				$xml->add_tag('title', $this->rssinfo['title']);
				$xml->add_tag('link', $this->rssinfo['link'] . '/', array(), false, true);
			$xml->close_group('image');

		// gather channel info
		$channelsInfo = $this->getItemsChannelInfo($items);
		$items = $this->formatItems($items, $options);
		foreach ($items AS $id => $item)
		{
			$item = $item['content'];
			$xml->add_group('item');
				$xml->add_tag('title', $item['external_prefix_plain'] . vB_String::htmlSpecialCharsUni($item['external_title']));
				$xml->add_tag('link', vB_Api::instanceInternal('route')->getAbsoluteNodeUrl($item['external_nodeid']), array(), false, true);
				$xml->add_tag('pubDate', gmdate('D, d M Y H:i:s', $item['publishdate']) . ' GMT');
				$xml->add_tag('description', $this->getItemDescription($item['rawtext'], $options));

				if (empty($options['nohtml']))
				{
					$xml->add_tag('content:encoded', vB_Library::instance('bbcode')->doParse($item['rawtext']));
				}

				$xml->add_tag('category', $channelsInfo[$item['channelid']]['htmltitle'], array(
					'domain' => vB_Api::instanceInternal('route')->getAbsoluteNodeUrl($item['channelid'])
				));
				$xml->add_tag('dc:creator', vB_String::unHtmlSpecialChars($item['authorname']));
				$xml->add_tag('guid', vB_Api::instanceInternal('route')->getAbsoluteNodeUrl($item['external_nodeid']), array('isPermaLink' => 'true'));
			$xml->close_group('item');
		}

		$xml->close_group('channel');
		$xml->close_group('rss');
		return $xml->fetch_xml();
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
