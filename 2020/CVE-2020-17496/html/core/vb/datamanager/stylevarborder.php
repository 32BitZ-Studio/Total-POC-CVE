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

class vB_DataManager_StyleVarBorder extends vB_DataManager_StyleVar
{
	var $childfields = array(
		'width'               => array(vB_Cleaner::TYPE_NUM, vB_DataManager_Constants::REQ_NO),
		'style'               => array(vB_Cleaner::TYPE_STR, vB_DataManager_Constants::REQ_NO,  vB_DataManager_Constants::VF_METHOD,  'verify_borderstyle'),
		'color'               => array(vB_Cleaner::TYPE_STR, vB_DataManager_Constants::REQ_NO,  vB_DataManager_Constants::VF_METHOD),
		'units'               => array(vB_Cleaner::TYPE_STR, vB_DataManager_Constants::REQ_NO,  vB_DataManager_Constants::VF_METHOD,  'verify_units'),
		'stylevar_width'      => array(vB_Cleaner::TYPE_STR, vB_DataManager_Constants::REQ_NO,  vB_DataManager_Constants::VF_METHOD,  'verify_value_stylevar'),
		'stylevar_style'      => array(vB_Cleaner::TYPE_STR, vB_DataManager_Constants::REQ_NO,  vB_DataManager_Constants::VF_METHOD,  'verify_value_stylevar'),
		'stylevar_color'      => array(vB_Cleaner::TYPE_STR, vB_DataManager_Constants::REQ_NO,  vB_DataManager_Constants::VF_METHOD,  'verify_value_stylevar'),
		'stylevar_units'      => array(vB_Cleaner::TYPE_STR, vB_DataManager_Constants::REQ_NO,  vB_DataManager_Constants::VF_METHOD,  'verify_value_stylevar'),
		// inheritance transformation parameters for "stylevar_color"
		'inherit_param_color' => array(vB_Cleaner::TYPE_STR, vB_DataManager_Constants::REQ_NO,  vB_DataManager_Constants::VF_METHOD,  'verify_value_inherit_param_color'),
	);

	public $datatype = 'Dimension';

}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 102271 $
|| #######################################################################
\*=========================================================================*/
