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

class vB_External_Export_Js extends vB_External_Export
{
	// list of headers used by output type
	protected $headers = array();

	// JS thread object definition
	private $threadObj = "
	function thread(threadid, title, poster, threaddate, threadtime)
	{
		this.threadid = threadid;
		this.title = title;
		this.poster = poster;
		this.threaddate = threaddate;
		this.threadtime = threadtime;
	}
	";

	protected $type = 'JS';

	public function __construct()
	{
		parent::__construct();
	}

	protected function buildOutputFromItems($items, $options)
	{
		$output = $this->threadObj;
		$output .= "var threads = new Array(" . sizeof($items) . ");\r\n";
		$itemnum = 0;

		$items = $this->formatItems($items, $options);
		foreach ($items AS $item)
		{
			$item = $item['content'];
			$item['title'] = vB_Library_Functions::addSlashesJs(vB_String::htmlSpecialCharsUni($item['external_prefix_plain']) . $item['external_title']);
			$item['authorname'] = vB_Library_Functions::addSlashesJs($item['authorname']);
			$output .= "\tthreads[$itemnum] = new thread($item[external_nodeid], '$item[title]', '$item[authorname]', '" . vB_Library_Functions::addSlashesJs($this->callvBDate(vB::getDatastore()->getOption('dateformat'), $item['publishdate'])) . "', '" . vB_Library_Functions::addSlashesJs($this->callvBDate(vB::getDatastore()->getOption('timeformat'), $item['publishdate'])) . "');\r\n";
			$itemnum++;
		}

		return $output;
		
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
