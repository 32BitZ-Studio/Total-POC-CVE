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

class vB_External_Export_Rss_91 extends vB_External_Export_Rss
{
	protected $type = 'RSS';
	
	public function __construct()
	{
		parent::__construct();
	}

	protected function buildOutputFromItems($items, $options)
	{
		parent::buildOutputFromItems($items, $options);

		$xml = new vB_Xml_Builder();
		$xml->add_group('rss', array('version' => '0.91'));
			$xml->add_group('channel');
				$xml->add_tag('title', $this->rssinfo['title']);
				$xml->add_tag('link', $this->rssinfo['link'] . '/', array(), false, true);
				$xml->add_tag('description', $this->rssinfo['description']);
				$xml->add_tag('language', $this->defaultLang['languagecode']);
				$xml->add_group('image');
					$xml->add_tag('url', $this->rssinfo['icon']);
					$xml->add_tag('title', $this->rssinfo['title']);
					$xml->add_tag('link', $this->rssinfo['link'] . '/', array(), false, true);
				$xml->close_group('image');

				$dateformat = vB::getDatastore()->getOption('dateformat');
				$timeformat = vB::getDatastore()->getOption('timeformat');

				// gather channel info
				$channelsInfo = $this->getItemsChannelInfo($items);
				$items = $this->formatItems($items, $options);
				foreach ($items AS $id => $item)
				{
					$item = $item['content'];
					$xml->add_group('item');
					$xml->add_tag('title', $item['external_prefix_plain'] . vB_String::htmlSpecialCharsUni($item['external_title']));
					$xml->add_tag('link', vB_Api::instanceInternal('route')->getAbsoluteNodeUrl($item['external_nodeid']), array(), false, true);
					$xml->add_tag('description', vB_Phrase::fetchSinglePhrase('rss_91_forum_w_posted_by_x_post_time_y_at_z',
						array($channelsInfo[$item['channelid']]['htmltitle'], $item['authorname'], $this->callvBDate($dateformat, $item['publishdate']), 
							$this->callvBDate($timeformat, $item['publishdate'])
						)
					));
					$xml->close_group('item');
				}
			$xml->close_group('channel');
		$xml->close_group('rss');

		$output .= '<!DOCTYPE rss PUBLIC "-//RSS Advisory Board//DTD RSS 0.91//EN" "http://www.rssboard.org/rss-0.91.dtd">' . "\r\n";
		$output .= $xml->output();

		return $xml->fetch_xml_tag() . $output;
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
