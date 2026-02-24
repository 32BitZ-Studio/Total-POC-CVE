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

class vB_Upgrade_512a5 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '512a5';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.1.2 Alpha 5';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.1.2 Alpha 4';

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

	// VBV-1375 -- remove unwanted widget
	public function step_1()
	{
		// widget guid: vbulletin-widget_groupnodes-4eb423cfd6dea7.34930864
		// template: widget_sgnodes
		// title phrase: widget_sgnodes_widgettitle

		$assertor = vB::getDbAssertor();

		$widgetid = $assertor->getRow('widget', array('guid' => 'vbulletin-widget_groupnodes-4eb423cfd6dea7.34930864'));
		if ($widgetid)
		{
			$this->show_message($this->phrase['version'][$this->SHORT_VERSION]['removing_unused_widget']);

			$widgetid = $widgetid['widgetid'];

			// delete widget instances
			$assertor->delete('widgetinstance', array('widgetid' => $widgetid));

			// delete the widget
			$assertor->delete('widget', array('guid' => 'vbulletin-widget_groupnodes-4eb423cfd6dea7.34930864'));

			// delete the widget's template
			$assertor->delete('template', array('title' => 'widget_sgnodes'));

			// delete the widget title phrase
			$assertor->delete('phrase', array('varname' => 'widget_sgnodes_widgettitle'));

			// note: this widget has no widget config definitions (widgetdefinition table) to delete.
		}
		else
		{
			$this->skip_message();
		}
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
