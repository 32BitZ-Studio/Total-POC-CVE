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

class vB_DataManager_StyleVarBackground extends vB_DataManager_StyleVar
{
	var $childfields = array(
		'image'                              => array(vB_Cleaner::TYPE_STR, vB_DataManager_Constants::REQ_NO, vB_DataManager_Constants::VF_METHOD,  'verify_image'),
		'color'                              => array(vB_Cleaner::TYPE_STR, vB_DataManager_Constants::REQ_NO, vB_DataManager_Constants::VF_METHOD),
		'repeat'                             => array(vB_Cleaner::TYPE_STR, vB_DataManager_Constants::REQ_NO, vB_DataManager_Constants::VF_METHOD,  'verify_repeat'),
		'units'                              => array(vB_Cleaner::TYPE_STR, vB_DataManager_Constants::REQ_NO, vB_DataManager_Constants::VF_METHOD,  'verify_units'),
		'x'                                  => array(vB_Cleaner::TYPE_STR, vB_DataManager_Constants::REQ_NO, vB_DataManager_Constants::VF_METHOD,  'verify_background_position'),
		'y'                                  => array(vB_Cleaner::TYPE_STR, vB_DataManager_Constants::REQ_NO, vB_DataManager_Constants::VF_METHOD,  'verify_background_position'),
		'gradient_type'                      => array(vB_Cleaner::TYPE_STR, vB_DataManager_Constants::REQ_NO, vB_DataManager_Constants::VF_METHOD,  'verify_gradient_type'),
		'gradient_direction'                 => array(vB_Cleaner::TYPE_STR, vB_DataManager_Constants::REQ_NO, vB_DataManager_Constants::VF_METHOD,  'verify_gradient_direction'),
		'gradient_start_color'               => array(vB_Cleaner::TYPE_STR, vB_DataManager_Constants::REQ_NO, vB_DataManager_Constants::VF_METHOD,  'verify_color'),
		'gradient_mid_color'                 => array(vB_Cleaner::TYPE_STR, vB_DataManager_Constants::REQ_NO, vB_DataManager_Constants::VF_METHOD,  'verify_color'),
		'gradient_end_color'                 => array(vB_Cleaner::TYPE_STR, vB_DataManager_Constants::REQ_NO, vB_DataManager_Constants::VF_METHOD,  'verify_color'),
		'stylevar_image'                     => array(vB_Cleaner::TYPE_STR, vB_DataManager_Constants::REQ_NO, vB_DataManager_Constants::VF_METHOD,  'verify_value_stylevar'),
		'stylevar_color'                     => array(vB_Cleaner::TYPE_STR, vB_DataManager_Constants::REQ_NO, vB_DataManager_Constants::VF_METHOD,  'verify_value_stylevar'),
		'stylevar_repeat'                    => array(vB_Cleaner::TYPE_STR, vB_DataManager_Constants::REQ_NO, vB_DataManager_Constants::VF_METHOD,  'verify_value_stylevar'),
		'stylevar_units'                     => array(vB_Cleaner::TYPE_STR, vB_DataManager_Constants::REQ_NO, vB_DataManager_Constants::VF_METHOD,  'verify_value_stylevar'),
		'stylevar_x'                         => array(vB_Cleaner::TYPE_STR, vB_DataManager_Constants::REQ_NO, vB_DataManager_Constants::VF_METHOD,  'verify_value_stylevar'),
		'stylevar_y'                         => array(vB_Cleaner::TYPE_STR, vB_DataManager_Constants::REQ_NO, vB_DataManager_Constants::VF_METHOD,  'verify_value_stylevar'),
		'stylevar_gradient_type'             => array(vB_Cleaner::TYPE_STR, vB_DataManager_Constants::REQ_NO, vB_DataManager_Constants::VF_METHOD,  'verify_value_stylevar'),
		'stylevar_gradient_direction'        => array(vB_Cleaner::TYPE_STR, vB_DataManager_Constants::REQ_NO, vB_DataManager_Constants::VF_METHOD,  'verify_value_stylevar'),
		'stylevar_gradient_start_color'      => array(vB_Cleaner::TYPE_STR, vB_DataManager_Constants::REQ_NO, vB_DataManager_Constants::VF_METHOD,  'verify_value_stylevar'),
		'stylevar_gradient_mid_color'        => array(vB_Cleaner::TYPE_STR, vB_DataManager_Constants::REQ_NO, vB_DataManager_Constants::VF_METHOD,  'verify_value_stylevar'),
		'stylevar_gradient_end_color'        => array(vB_Cleaner::TYPE_STR, vB_DataManager_Constants::REQ_NO, vB_DataManager_Constants::VF_METHOD,  'verify_value_stylevar'),
		// inheritance transformation parameters for the "color" values
		'inherit_param_color'                => array(vB_Cleaner::TYPE_STR, vB_DataManager_Constants::REQ_NO, vB_DataManager_Constants::VF_METHOD,  'verify_value_inherit_param_color'),
		'inherit_param_gradient_start_color' => array(vB_Cleaner::TYPE_STR, vB_DataManager_Constants::REQ_NO, vB_DataManager_Constants::VF_METHOD,  'verify_value_inherit_param_color'),
		'inherit_param_gradient_mid_color'   => array(vB_Cleaner::TYPE_STR, vB_DataManager_Constants::REQ_NO, vB_DataManager_Constants::VF_METHOD,  'verify_value_inherit_param_color'),
		'inherit_param_gradient_end_color'   => array(vB_Cleaner::TYPE_STR, vB_DataManager_Constants::REQ_NO, vB_DataManager_Constants::VF_METHOD,  'verify_value_inherit_param_color'),
	);

	public $datatype = 'Background';

}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 103485 $
|| #######################################################################
\*=========================================================================*/
