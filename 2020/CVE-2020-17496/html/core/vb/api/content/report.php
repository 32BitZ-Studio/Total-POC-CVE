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
 * vB_Api_Content_Report
 *
 * @package vBApi
 * @author xiaoyu
 * @copyright Copyright (c) 2011
 * @version $Id: report.php 100591 2019-01-29 20:58:19Z ksours $
 * @access public
 */
class vB_Api_Content_Report extends vB_Api_Content_Text
{
	//override in client- the text name
	protected $contenttype = 'vBForum_Report';

	//The table for the type-specific data.
	protected $tablename = array('report', 'text');

	protected $reportChannel;

	/**
	 * Constructor, no external instantiation.
	 */
	protected function __construct()
	{
		parent::__construct();
		$this->library = vB_Library::instance('Content_Report');
		$this->reportChannel = $this->nodeApi->fetchReportChannel();
	}

	/**
	 * Adds a new node.
	 *
	 * @param  mixed            $data Array of field => value pairs which define the record.
	 * @param  array            Array of options for the content being created.
	 *                          Understands skipTransaction, skipFloodCheck, floodchecktime, skipDupCheck, skipNotification, nl2br, autoparselinks.
	 *                          - nl2br: if TRUE, all \n will be converted to <br /> so that it's not removed by the html parser (e.g. comments).
	 *                          - wysiwyg: if true convert html to bbcode.  Defaults to true if not given.
	 *
	 * @throws vB_Exception_Api
	 *
	 * @return integer          the new nodeid
	 */
	public function add($data, $options = array())
	{
		if (!$this->library->validate($data, vB_Library_Content::ACTION_ADD))
		{
			throw new vB_Exception_Api('no_create_permissions');
		}

		$vboptions = vB::getDatastore()->getValue('options');

		$text = '';
		if(!empty($data['pagetext']))
		{
			$text = $data['pagetext'];
		}
		else if(!empty($data['rawtext']))
		{
			$text = $data['rawtext'];
		}
		else
		{
			throw new vB_Exception_Api('invalid_data');
		}

		$wysiwyg = false;
		if(isset($options['wysiwyg']))
		{
			$wysiwyg = (bool) $options['wysiwyg'];
		}

		$strlen = vB_String::vbStrlen($this->library->parseAndStrip($text, $wysiwyg), true);
		if ($strlen < $vboptions['postminchars'])
		{
			throw new vB_Exception_Api('please_enter_message_x_chars', $vboptions['postminchars']);
		}

		if($vboptions['postmaxchars'] != 0 AND $strlen > $vboptions['postmaxchars'])
		{
			throw new vB_Exception_Api('maxchars_exceeded_x_y', array($vboptions['postmaxchars'], $strlen));
		}

		//this will be set by the library function as well, but cleanInput expects this to
		//exist in the input data and it not being set at this point will cause problems.
		$data['parentid'] = $this->reportChannel;
		$data = $this->cleanInput($data);
		$this->cleanOptions($options);


		$result = $this->library->add($data, $options, $wysiwyg);
		return $result['nodeid'];
	}

	/**
	 * Report is not allowed to be updated.
	 *
	 * @throws vB_Exception_Api
	 *
	 * @param  $nodeid
	 * @param  $data
	 *
	 * @return void
	 */
	public function update($nodeid, $data)
	{
		throw new vB_Exception_Api('not_implemented');
	}

	/**
	 * Opens or closes reports
	 *
	 * @param  array  $nodeids Array of node IDs
	 * @param  string $op 'open' or 'close'
	 *
	 * @return standard success array
	 */
	public function openClose($nodeids, $op)
	{
		$data = array();

		// We need to check the permissions of the nodeids that these reports apply to, not the report
		$reportNodeids = $this->getReportNodes($nodeids);
		if (!vB::getUserContext()->isModerator() OR !$this->library->validate($data, vB_Library_Content::ACTION_UPDATE, $reportNodeids))
		{
			throw new vB_Exception_Api('no_permission');
		}

		$this->library->openClose($nodeids, $op);
		return array('success' => true);
	}

	/**
	 * Deletes one or more reports
	 *
	 * @throws vB_Exception_Api
	 *
	 * @param  $nodeids
	 *
	 * @return standard success array
	 */
	public function bulkdelete($nodeids)
	{
		$data = array();

		// We need to check the permissions of the nodeids that these reports apply to, not the report
		$reportNodeids = $this->getReportNodes($nodeids);
		if (!vB::getUserContext()->isModerator() OR !$this->library->validate($data, vB_Library_Content::ACTION_UPDATE, $reportNodeids))
		{
			throw new vB_Exception_Api('no_permission');
		}

		$this->library->bulkdelete($nodeids);
		return array('success' => true);
	}

	/**
	 * Converts report nodes to associated nodes
	 *
	 * @param  array $nodeids
	 *
	 * @return array $nodeids
	 */
	protected function getReportNodes($nodeids)
	{
		$nodes = array();
		$results = vB::getDbAssertor()->getRows('vBForum:report', array(
			'nodeid' => $nodeids,
		));
		foreach ($results AS $node)
		{
			$nodes[] = $node['reportnodeid'];
		}

		return $nodes;
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 100591 $
|| #######################################################################
\*=========================================================================*/
