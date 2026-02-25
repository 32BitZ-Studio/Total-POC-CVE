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

class vB_DataManager_StyleVarFont extends vB_DataManager_StyleVar
{
	var $childfields = array(
		'family'              => array(vB_Cleaner::TYPE_STR, vB_DataManager_Constants::REQ_NO, vB_DataManager_Constants::VF_METHOD, 'verify_fontfamily'),
		'units'               => array(vB_Cleaner::TYPE_STR, vB_DataManager_Constants::REQ_NO, vB_DataManager_Constants::VF_METHOD, 'verify_units'),
		'size'                => array(vB_Cleaner::TYPE_STR, vB_DataManager_Constants::REQ_NO, vB_DataManager_Constants::VF_METHOD, 'verify_font_size'),
		'lineheight'          => array(vB_Cleaner::TYPE_STR, vB_DataManager_Constants::REQ_NO, vB_DataManager_Constants::VF_METHOD, 'verify_lineheight'),
		'weight'              => array(vB_Cleaner::TYPE_STR, vB_DataManager_Constants::REQ_NO, vB_DataManager_Constants::VF_METHOD, 'verify_fontweight'),
		'style'               => array(vB_Cleaner::TYPE_STR, vB_DataManager_Constants::REQ_NO, vB_DataManager_Constants::VF_METHOD, 'verify_fontstyle'),
		'variant'             => array(vB_Cleaner::TYPE_STR, vB_DataManager_Constants::REQ_NO, vB_DataManager_Constants::VF_METHOD, 'verify_fontvariant'),
		'stylevar_family'     => array(vB_Cleaner::TYPE_STR, vB_DataManager_Constants::REQ_NO, vB_DataManager_Constants::VF_METHOD, 'verify_value_stylevar'),
		'stylevar_units'      => array(vB_Cleaner::TYPE_STR, vB_DataManager_Constants::REQ_NO, vB_DataManager_Constants::VF_METHOD, 'verify_value_stylevar'),
		'stylevar_size'       => array(vB_Cleaner::TYPE_STR, vB_DataManager_Constants::REQ_NO, vB_DataManager_Constants::VF_METHOD, 'verify_value_stylevar'),
		'stylevar_lineheight' => array(vB_Cleaner::TYPE_STR, vB_DataManager_Constants::REQ_NO, vB_DataManager_Constants::VF_METHOD, 'verify_value_stylevar'),
		'stylevar_weight'     => array(vB_Cleaner::TYPE_STR, vB_DataManager_Constants::REQ_NO, vB_DataManager_Constants::VF_METHOD, 'verify_value_stylevar'),
		'stylevar_style'      => array(vB_Cleaner::TYPE_STR, vB_DataManager_Constants::REQ_NO, vB_DataManager_Constants::VF_METHOD, 'verify_value_stylevar'),
		'stylevar_variant'    => array(vB_Cleaner::TYPE_STR, vB_DataManager_Constants::REQ_NO, vB_DataManager_Constants::VF_METHOD, 'verify_value_stylevar'),
	);

	public $datatype = 'Font';

}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 100449 $
|| #######################################################################
\*=========================================================================*/
