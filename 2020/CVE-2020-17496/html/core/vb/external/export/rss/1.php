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

class vB_External_Export_Rss_1 extends vB_External_Export_Rss
{
	protected $type = 'RSS1';

	public function __construct()
	{
		parent::__construct();
	}

	protected function buildOutputFromItems($items, $options)
	{
		parent::buildOutputFromItems($items, $options);

		if ($this->rssinfo['ttl'] <= 60)
		{
			$updateperiod = 'hourly';
			$updatefrequency = round(60 / $this->rssinfo['ttl']);
		}
		else
		{
			$updateperiod = 'daily';
			$updatefrequency = round(1440 / $this->rssinfo['ttl']);
		}

		$xml = new vB_Xml_Builder();			
		$xml->add_group('rdf:RDF', array(
			'xmlns:rdf'     => 'http://www.w3.org/1999/02/22-rdf-syntax-ns#',
			'xmlns:dc'      => 'http://purl.org/dc/elements/1.1/',
			'xmlns:syn'     => 'http://purl.org/rss/1.0/modules/syndication/',
			'xmlns:content' => 'http://purl.org/rss/1.0/modules/content/',
			'xmlns'         => 'http://purl.org/rss/1.0/',
		));

		$xml->add_group('channel', array(
				'rdf:about' => $this->rssinfo['link']
			));
			$xml->add_tag('title', $this->rssinfo['title']);
			$xml->add_tag('link', $this->rssinfo['link'] . '/', array(), false, true);
			$xml->add_tag('description', $this->rssinfo['description']);
			$xml->add_tag('syn:updatePeriod', $updateperiod);
			$xml->add_tag('syn:updateFrequency', $updatefrequency);
			$xml->add_tag('syn:updateBase', '1970-01-01T00:00Z');
			$xml->add_tag('dc:language', $this->defaultLang['languagecode']);
			$xml->add_tag('dc:creator', 'vBulletin');
			$xml->add_tag('dc:date', gmdate('Y-m-d\TH:i:s') . 'Z');
			$xml->add_group('items');
				$xml->add_group('rdf:Seq');
					$xml->add_tag('rdf:li', '', array('rdf:resource' => $this->rssinfo['link'] . '/'));
				$xml->close_group('rdf:Seq');
			$xml->close_group('items');
			$xml->add_group('image');
				$xml->add_tag('url', $this->rssinfo['icon']);
				$xml->add_tag('title', $this->rssinfo['title']);
				$xml->add_tag('link', $this->rssinfo['link'] . '/', array(), false, true);
			$xml->close_group('image');
		$xml->close_group('channel');

		// gather channel info
		$channelsInfo = $this->getItemsChannelInfo($items);
		$items = $this->formatItems($items, $options);
		foreach ($items AS $id => $item)
		{
			$item = $item['content'];
			$xml->add_group('item', array('rdf:about' => vB_Api::instanceInternal('route')->getAbsoluteNodeUrl($item['external_nodeid'])));
		    	$xml->add_tag('title', $item['external_prefix_plain'] . vB_String::htmlSpecialCharsUni($item['external_title']));
		    	$xml->add_tag('link', vB_Api::instanceInternal('route')->getAbsoluteNodeUrl($item['external_nodeid']), array(), false, true);
				$xml->add_tag('description', $this->getItemDescription($item['rawtext'], $options));

				if (empty($options['nohtml']))
				{
					$xml->add_tag('content:encoded', vB_Library::instance('bbcode')->doParse($item['rawtext']));
				}

				$xml->add_tag('dc:date', gmdate('Y-m-d\TH:i:s', $item['publishdate']) . 'Z');
				$xml->add_tag('dc:creator', vB_String::unHtmlSpecialChars($item['authorname']));
				$xml->add_tag('dc:subject', $channelsInfo[$item['channelid']]['htmltitle']);
			$xml->close_group('item');
		}

		$xml->close_group('rdf:RDF');
		return $xml->fetch_xml();
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
