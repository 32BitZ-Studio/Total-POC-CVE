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

class vB_DataManager_StyleVarCustom extends vB_DataManager_StyleVar
{
	// Honestly, I don't know if we even need this; it is not being used right now...
	var $childfields = array();

	/**
	 * Adds a child field to the custom stylevar
	 *
	 * @param	string		The key used for storage
	 * @param	array		The descriptor data; IE: array(TYPE_INT, REQ_NO, VF_METHOD)
	 */
	public function add_child($key, $descriptor)
	{
		$this->childfields[$key] = $descriptor;
	}

	public $datatype = 'Custom';

}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
