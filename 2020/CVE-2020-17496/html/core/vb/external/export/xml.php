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

class vB_External_Export_Xml extends vB_External_Export
{
	protected $type = 'XML';

	public function __construct()
	{
		parent::__construct();
	}

	protected function buildOutputFromItems($items, $options)
	{
		$xml = new vB_XML_Builder();
		$xml->add_group('source');
		$xml->add_tag('url', vB::getDatastore()->getOption('frontendurl') . '/');
		$items = $this->formatItems($items, $options);
		foreach ($items AS $id => $item)
		{
			$item = $item['content'];
			$xml->add_group('thread', array('id' => $item['external_nodeid']));
				$xml->add_tag('title', $item['external_prefix_plain'] . vB_String::unHtmlSpecialChars($item['external_title']));
				$xml->add_tag('author', vB_String::unHtmlSpecialChars($item['authorname']));
				$xml->add_tag('date', $this->callvBDate(vB::getDatastore()->getOption('dateformat'), $item['publishdate']));
				$xml->add_tag('time', $this->callvBDate(vB::getDatastore()->getOption('timeformat'), $item['publishdate']));
			$xml->close_group('thread');
		}

		$xml->close_group('source');
		return $xml->fetch_xml();
		
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
