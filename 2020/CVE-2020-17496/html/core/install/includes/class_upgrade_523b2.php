<?php
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
/*
if (!isset($GLOBALS['vbulletin']->db))
{
	exit;
}
*/

class vB_Upgrade_523b2 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '523b2';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.2.3 Beta 2';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.2.3 Beta 1';

	/**
	* Beginning version compatibility
	*
	* @var	string
	*/
	public $VERSION_COMPAT_STARTS = '';

	/**
	* Ending version compatibility
	*
	* @var	string
	*/
	public $VERSION_COMPAT_ENDS   = '';

	public function step_1()
	{
		$mapper = new vB_Stylevar_Mapper();

		// Add mappings
		$mapper->addMapping('pmchat_chatwindow_content_background', 'vbmessenger_chatwindow_content_background', 'vbulletin', true);
		$mapper->addMapping('pmchat_chatwindow_message_mine_background', 'vbmessenger_chatwindow_message_mine_background', 'vbulletin', true);
		$mapper->addMapping('pmchat_chatwindow_message_theirs_background', 'vbmessenger_chatwindow_message_theirs_background', 'vbulletin', true);
		$mapper->addMapping('pmchat_chatwindow_participants_background', 'vbmessenger_chatwindow_participants_background', 'vbulletin', true);
		$mapper->addMapping('pmchat_chatwindow_widget_background', 'vbmessenger_chatwindow_widget_background', 'vbulletin', true);

		// Do the processing
		if ($mapper->load() AND $mapper->process())
		{
			$this->show_message($this->phrase['version']['408']['mapping_customized_stylevars']);
			$mapper->processResults();
		}
		else
		{
			$this->skip_message();
		}
	}
}

/*======================================================================*\
|| ####################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 101013 $
|| ####################################################################
\*======================================================================*/
