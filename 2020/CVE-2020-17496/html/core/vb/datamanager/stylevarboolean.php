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

class vB_DataManager_StyleVarBoolean extends vB_DataManager_StyleVar
{
	var $childfields = array(
		'boolean'          => array(vB_Cleaner::TYPE_STR, vB_DataManager_Constants::REQ_NO),
		'stylevar_boolean' => array(vB_Cleaner::TYPE_STR, vB_DataManager_Constants::REQ_NO,  vB_DataManager_Constants::VF_METHOD, 'verify_value_stylevar'),
	);

	public $datatype = 'boolean';
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 103429 $
|| #######################################################################
\*=========================================================================*/
