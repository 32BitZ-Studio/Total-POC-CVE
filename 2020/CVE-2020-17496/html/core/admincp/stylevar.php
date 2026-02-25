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

// ######################## SET PHP ENVIRONMENT ###########################
error_reporting(E_ALL & ~E_NOTICE);
@set_time_limit(0);

// ##################### DEFINE IMPORTANT CONSTANTS #######################
define('CVS_REVISION', '$RCSfile$ - $Revision: 103571 $');
define('NOZIP', true);


// #################### PRE-CACHE TEMPLATES AND DATA ######################
global $phrasegroups, $specialtemplates, $vbphrase;
$phrasegroups = array('style');
$specialtemplates = array();

// ########################## REQUIRE BACK-END ############################
require_once(dirname(__FILE__) . '/global.php');
require_once(DIR . '/includes/adminfunctions_template.php');
require_once(DIR . '/includes/class_stylevar.php');
$assertor = vB::getDbAssertor();
$userContext = vB::getUserContext();

// ######################## CHECK ADMIN PERMISSIONS #######################
if (!$userContext->hasAdminPermission('canadminstyles') AND !$userContext->hasAdminPermission('canadmintemplates'))
{
	print_cp_no_permission();
}

$vbulletin->input->clean_array_gpc('r', array(
	'dostyleid'    => vB_Cleaner::TYPE_INT,
));


// ############################# LOG ACTION ###############################
log_admin_action(iif($vbulletin->GPC['dostyleid'] != 0, "style id = " . $vbulletin->GPC['dostyleid']));

// ########################################################################
// ######################### START MAIN SCRIPT ############################
// ########################################################################

$vb5_config =& vB::getConfig();
$vboptions = vB::getDatastore()->getValue('options');

if ($vb5_config['report_all_php_errors'])
{
	@ini_set('display_errors', true);
}

if (empty($_REQUEST['do']))
{
	// If not told to do anything, list the stylevars for edit
	$_REQUEST['do'] = 'modify';
}

if (empty($vbulletin->GPC['dostyleid']))
{
	$vbulletin->GPC['dostyleid'] = ($vb5_config['Misc']['debug'] ? -1 : $vbulletin->options['styleid']);
}

if ($vbulletin->GPC['dostyleid'] == -1)
{
	$styleinfo = array(
		'styleid' => -1,
		'title'   => 'MASTER STYLE'
	);
}
else
{
	$styleinfo = $assertor->getRow('vBForum:style', array('styleid' => $vbulletin->GPC['dostyleid']));
	if (empty($styleinfo))
	{
		print_stop_message2('invalid_style_specified');
	}
}

$skip_wrappers = array(
	'fetchstylevareditor'
);

if (in_array($_REQUEST['do'], $skip_wrappers))
{
	define('NO_PAGE_TITLE', true);
}


// The Javascript may not all be relevant to all actions, but it's simpler to include
// it here. Javascript files will be cached anyway.
$extraheader = '<script type="text/javascript" src="core/clientscript/vbulletin_stylevars.js?v=' . $vboptions['simpleversion'] .'"></script>';
print_cp_header($vbphrase['stylevareditor'], '', $extraheader);


function construct_stylevar_form($title, $stylevarid, $values, $styleid)
{
	global $vbulletin;

	$stylecache = vB_Library::instance('Style')->fetchStyles(false, false, array('skipReadCheck' => true));

	$editstyleid = $styleid;

	if (isset($values[$stylevarid][$styleid]))
	{
		// customized or master
		if ($styleid == -1)
		{
			// master
			$hide_revert = true;
		}
	}
	else
	{
		// inherited
		while (!isset($values[$stylevarid][$styleid]))
		{
			$styleid = $stylecache[$styleid]['parentid'];
			if (!isset($stylecache[$styleid]) AND $styleid != -1)
			{
				trigger_error('Invalid style in tree: ' . $styleid, E_USER_ERROR);
				break;
			}
		}
		$hide_revert = true;
	}

	$stylevar = $values[$stylevarid][$styleid];

	$hide_revert = ($hide_revert ? 'hide_revert' : '');

	if ($stylevar['value'] == '')
	{
		// blank for value? use fall back
		$stylevar['value'] = $stylevar['failsafe'];
	}

	$svinstance = vB_StyleVar_factory::create($stylevar['datatype']);
	$svinstance->set_stylevarid($stylevarid);
	$svinstance->set_styleid($styleid);
	$svinstance->set_definition($stylevar);
	$svinstance->set_value(unserialize($stylevar['value']));	// remember, our value in db is ALWAYS serialized!

	if ($stylevar['stylevarstyleid'] == -1)
	{
		$svinstance->set_inherited(0);
	}
	else if ($stylevar['stylevarstyleid'] == $vbulletin->GPC['dostyleid'])
	{
		$svinstance->set_inherited(-1);
	}
	else
	{
		$svinstance->set_inherited(1);
	}

	$editor = $svinstance->print_editor();
	return $editor;
}

// ########################################################################
if ($_REQUEST['do'] == 'dfnadd' OR $_REQUEST['do'] == 'dfnedit')
{
	$vbulletin->input->clean_array_gpc('r', array(
		'stylevarid' => vB_Cleaner::TYPE_STR,
	));

	if ($vbulletin->GPC['stylevarid'])
	{
		// we have $vbulletin->GPC['stylevarid'] and $vbulletin->GPC['dostyleid'] from above
		$stylevar = $assertor->getRow('vBForum:stylevardfn', array('stylevarid' => $vbulletin->GPC['stylevarid'], 'styleid' => $vbulletin->GPC['dostyleid']));

		if (!empty($stylevar))
		{
			// select friendly name for current language
			$svname_result = $assertor->getRow('vBForum:phrase', array(
				'varname' => 'stylevar_' . $vbulletin->GPC['stylevarid'] . '_name'
			));

			if (!empty($svname_result))
			{
				$stylevar['friendlyname'] = $svname_result['text'];
			}

			// select description for current language
			$svdesc_result = $assertor->getRow('vBForum:phrase', array(
				'varname' => 'stylevar_' . $vbulletin->GPC['stylevarid'] . '_description'
			));

			if (!empty($svdesc_result))
			{
				$stylevar['description'] = $svdesc_result['text'];
			}

		}
	}

	// get stylevar groups
	$stylevarGroupRows = $assertor->getColumn('vBForum:getStylevarGroups', 'stylevargroup');
	$stylevarGroups = array();
	foreach ($stylevarGroupRows AS $stylevarGroupRow)
	{
		$stylevargroup_phrase_key = 'stylevargroup_' . strtolower($stylevarGroupRow) . '_name';
		$stylevargroup_phrase = !empty($vbphrase[$stylevargroup_phrase_key]) ? $vbphrase[$stylevargroup_phrase_key] : '~~' . $stylevargroup_phrase_key . ' ~~';

		$stylevarGroups[$stylevarGroupRow] = $stylevargroup_phrase;
	}
	asort($stylevarGroups);

	// add / editing definition
	print_form_header('admincp/stylevar', 'dfn_dosave', 0, 1);
	print_table_header($vbphrase[$vbulletin->GPC['stylevarid'] ? 'edit_stylevar' : 'add_new_stylevar']);
	print_select_row($vbphrase['product'], 'product', fetch_product_list(), $stylevar['product']);
	print_select_row($vbphrase['group'], 'svgroup', $stylevarGroups, $stylevar['stylevargroup']);
	print_input_row($vbphrase['stylevarid'], 'stylevarid', $stylevar['stylevarid']);
	print_input_row($vbphrase['friendly_name'], 'svfriendlyname', $stylevar['friendlyname']);
	print_input_row($vbphrase['description_gcpglobal'], 'svdescription', $stylevar['description']);
	// keys match with enum entry that we have, value should be mapped to a vbphrase
	$svtypesarray = array(
		$vbphrase['simple_types'] => array(
			'string'   => $vbphrase['string'],
			'numeric'  => $vbphrase['numeric'],
			'url'      => $vbphrase['url_gstyle'],
			'path'     => $vbphrase['path'],
			'color'    => $vbphrase['color_gstyle'],
			'imagedir' => $vbphrase['imagedir'],
			'image'    => $vbphrase['image'],
			'fontlist' => $vbphrase['fontlist'],
			'size'     => $vbphrase['size_gstyle'],
			'boolean'  => $vbphrase['boolean'],
		),
		$vbphrase['complex_types'] => array(
			'background'     => $vbphrase['background'],
			'font'           => $vbphrase['font_gstyle'],
			'textdecoration' => $vbphrase['text_decoration'],
			'texttransform'  => $vbphrase['text_transform'],
			'textalign'      => $vbphrase['text_align'],
			'dimension'      => $vbphrase['dimension'],
			'border'         => $vbphrase['border'],
			'padding'        => $vbphrase['padding'],
			'margin'         => $vbphrase['margin'],
		),
	);
	print_select_row($vbphrase['data_type'], 'svdatatype', $svtypesarray, $stylevar['datatype']);
	print_input_row($vbphrase['validation_regular_expression'] . '<br />' . $vbphrase['validation_re_optional'], 'svvalidation', $stylevar['validation']);
	$svunitsarray = array(
		''     => '',
		'%'    => '%',
		'px'   => 'px',
		'pt'   => 'pt',
		'em'   => 'em',
		'rem'  => 'rem',
		'ch'   => 'ch',
		'ex'   => 'ex',
		'pc'   => 'pc',
		'in'   => 'in',
		'cm'   => 'cm',
		'mm'   => 'mm',
		'vw'   => 'vw',
		'vh'   => 'vh',
		'vmin' => 'vmin',
		'vmax' => 'vmax',
	);
//not currently used by anything.
//	print_select_row($vbphrase['units'] . '<br />~~Optional, only used by numerics type, discarded by other datatypes~~', 'svunit', $svunitsarray, $stylevar['units']);
	construct_hidden_code('oldsvid', $stylevar['stylevarid']);
	print_submit_row($vbphrase['save']);
}

// ########################################################################
if ($_POST['do'] == 'dfn_dosave')
{
	if (!$userContext->hasAdminPermission('canadminstyles'))
	{
		print_cp_no_permission();
	}

	$vbulletin->input->clean_array_gpc('p', array(
		'product'        => vB_Cleaner::TYPE_STR,
		'svgroup'        => vB_Cleaner::TYPE_STR,
		'stylevarid'     => vB_Cleaner::TYPE_NOHTML,
		'svfriendlyname' => vB_Cleaner::TYPE_NOHTML,
		'svdescription'  => vB_Cleaner::TYPE_NOHTML,
		'svdatatype'     => vB_Cleaner::TYPE_STR,
		'svvalidation'   => vB_Cleaner::TYPE_STR,
		'svunit'         => vB_Cleaner::TYPE_STR,
		'oldsvid'        => vB_Cleaner::TYPE_STR,
	));

	// MEMO: we are always working with styleid -1 for the definitions as of right now, some time later,
	// this should be removed so the dostyleid is properly respected.
	$vbulletin->GPC['dostyleid'] = -1;

	if (!$vbulletin->GPC['oldsvid'])
	{
		$stylevar_dfn = $assertor->getRow('vBForum:stylevardfn', array('stylevarid' => $vbulletin->GPC['stylevarid']));

		if (!empty($stylevar_dfn))
		{
			print_stop_message2(array('stylevar_x_already_exists', $vbulletin->GPC['stylevarid']));
		}
	}

	// stylevars can only begin with a-z or _ as defined by the CSS spec
	if (!preg_match('#^[_a-z][a-z0-9_]*$#i', $vbulletin->GPC['stylevarid']))
	{
		print_stop_message2('invalid_stylevar_id');
	}

	if (!preg_match('#^[a-z0-9_]+$#i', $vbulletin->GPC['svgroup']))
	{
		print_stop_message2('invalid_group_name');
	}

	$validtypes = array(
		'numeric',
		'string',
		'color',
		'url',
		'path',
		'background',
		'imagedir',
		'fontlist',
		'textdecoration',
		'texttransform',
		'textalign',
		'dimension',
		'border',
		'padding',
		'margin',
		'font',
		'size',
		'boolean',
	);

	if (!in_array($vbulletin->GPC['svdatatype'], $validtypes))
	{
		// invalid type, map to string type
		$vbulletin->GPC['svdatatype'] = 'string';
	}

	$validunits = array(
		'',
		'%',
		'px',
		'pt',
		'em',
		'rem',
		'ch',
		'ex',
		'pc',
		'in',
		'cm',
		'mm',
		'vw',
		'vh',
		'vmin',
		'vmax',
	);
	if (!in_array($vbulletin->GPC['svunit'], $validunits) OR $vbulletin->GPC['svdatatype'] != "numeric")
	{
		// invalid unit, or does not require unit, strip it
		$vbulletin->GPC['svunit'] = '';
	}

	// time to store it
	$svdfndata = datamanager_init('StyleVarDefn', $vbulletin, vB_DataManager_Constants::ERRTYPE_CP, 'stylevar');

	if ($vbulletin->GPC['oldsvid'])
	{
		$existing = array('stylevarid' => $vbulletin->GPC['oldsvid']);
		$svdfndata->set_existing($existing);

		if (defined('DEV_AUTOEXPORT') AND DEV_AUTOEXPORT)
		{
			$stylevar_dfn = $assertor->getRow('vBForum:stylevardfn', array('stylevarid' => $vbulletin->GPC['oldsvid']));
		}
	}

	$svdfndata->set('product', $vbulletin->GPC['product']);
	$svdfndata->set('stylevargroup', $vbulletin->GPC['svgroup']);
	$svdfndata->set('stylevarid', $vbulletin->GPC['stylevarid']);
	$svdfndata->set('styleid', $vbulletin->GPC['dostyleid']);

	$svdfndata->set('parentid', 0); // Gets reset to -1 by DM validation
	$svdfndata->set('parentlist', '0,-1');
	$svdfndata->set('datatype', $vbulletin->GPC['svdatatype']);

	// check regular expression
	if (!empty($vbulletin->GPC['svvalidation']))
	{
		if (preg_match('#' . str_replace('#', '\#', $vbulletin->GPC['svvalidation']) . '#siU', '') === false)
		{
			print_stop_message2('regular_expression_is_invalid');
		}
		$svdfndata->set('validation', $vbulletin->GPC['svvalidation']);
	}
	$svdfndata->set('units', $vbulletin->GPC['svunit']);
	$svdfndata->set('uneditable', false);

	$svdfndata->save(true, false, false, true);

	$dfnid = $vbulletin->GPC['stylevarid'];

	// insert the friendly name into phrase
	$phraseVal[] = array(
		'languageid' => -1, 'varname' => 'stylevar_' . $dfnid . '_name', 'text' => $vbulletin->GPC['svfriendlyname'],
		'product' => $vbulletin->GPC['product'], 'fieldname' => 'style', 'username' => $vbulletin->userinfo['username'],
		'dateline' => vB::getRequest()->getTimeNow(), 'version' => $vbulletin->options['templateversion']
	);
	$assertor->assertQuery('replaceValues', array('values' => $phraseVal, 'table' => 'phrase'));
	unset($replaceValues);

	// insert the description into phrase
	$phraseVal[] = array(
		'languageid' => -1, 'varname' => 'stylevar_' . $dfnid . '_description', 'text' => $vbulletin->GPC['svdescription'],
		'product' => $vbulletin->GPC['product'], 'fieldname' => 'style', 'username' => $vbulletin->userinfo['username'],
		'dateline' => vB::getRequest()->getTimeNow(), 'version' => $vbulletin->options['templateversion']
	);
	$assertor->assertQuery('replaceValues', array('values' => $phraseVal, 'table' => 'phrase'));
	unset($phraseVal);

	// create an empty stylevar value if we created a new stylevar
	if (!$vbulletin->GPC['oldsvid'])
	{
		// saving a new stylevar definition, create an empty stylevar value record
		$stylevardata = datamanager_init('StyleVar', $vbulletin, vB_DataManager_Constants::ERRTYPE_CP, 'stylevar');
		$stylevardata->set('stylevarid', $vbulletin->GPC['stylevarid']);
		$stylevardata->set('styleid', $vbulletin->GPC['dostyleid']);
		$stylevardata->build();
		$stylevardata->save(true, false, false, true);
	}

	$autoexportProducts = array($stylevar_dfn['product'], $vbulletin->GPC['product']);

	// we changed the stylevarid, so copy the old stylevar value to the new one and delete the old stylevar definition.
	if ($vbulletin->GPC['oldsvid'] AND $vbulletin->GPC['oldsvid'] != $vbulletin->GPC['stylevarid'])
	{
		// copy the old stylevar value to the new stylevar
		$oldValue = $assertor->getRow('vBForum:stylevar', array(
			'stylevarid' => $vbulletin->GPC['oldsvid'],
			'styleid' => $vbulletin->GPC['dostyleid'],
		));
		$oldValue['stylevarid'] = $vbulletin->GPC['stylevarid'];
		$assertor->insert('vBforum:stylevar', $oldValue);

		// @todo - rebuild the new stylevar value in case the datatype changed?

		// remove the old stylevar value and defintion
		$stylevarinfo = $assertor->getRow('vBForum:stylevardfn', array('stylevarid' => $vbulletin->GPC['oldsvid']));

		$assertor->delete('vBForum:stylevar', array('stylevarid' => $vbulletin->GPC['oldsvid']));
		$assertor->delete('vBForum:stylevardfn', array('stylevarid' => $vbulletin->GPC['oldsvid']));

		if (!$stylevarinfo['product'])
		{
			$product = array('', 'vbulletin');
			$autoexportProducts[] = 'vbulletin';
		}
		else
		{
			$product = array($stylevarinfo['product']);
			$autoexportProducts[] = $stylevarinfo['product'];
		}

		// remove the phrases for the old stylevar
		vB::getDbAssertor()->assertQuery('vBForum:phrase', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_DELETE,
			vB_dB_Query::CONDITIONS_KEY => array(
				array('field'=> 'varname', 'value' => array("stylevar_" . $vbulletin->GPC['oldsvid'] . "_name", "stylevar_" . $vbulletin->GPC['oldsvid'] . "_description"), vB_dB_Query::OPERATOR_KEY => vB_dB_Query::OPERATOR_EQ),
				array('field'=> 'fieldname', 'value' => 'style', vB_dB_Query::OPERATOR_KEY => vB_dB_Query::OPERATOR_EQ),
				array('field'=> 'product', 'value' => $product, vB_dB_Query::OPERATOR_KEY => vB_dB_Query::OPERATOR_EQ)
			)
		));
	}

	// rebuild languages
	require_once(DIR . '/includes/adminfunctions_language.php');
	build_language(-1);

	if (defined('DEV_AUTOEXPORT') AND DEV_AUTOEXPORT)
	{
		$autoexportProducts = array_unique($autoexportProducts);
		require_once(DIR . '/includes/functions_filesystemxml.php');
		autoexport_write_style_and_language($vbulletin->GPC['dostyleid'], $autoexportProducts);
	}

	vB_Library::instance('Style')->setCssDate();
	print_stop_message2(array('saved_stylevardfn_x_successfully', $vbulletin->GPC['stylevarid']), 'stylevar',
		array('do' => 'fetchstylevareditor', 'dostyleid' => $vbulletin->GPC['dostyleid'], 'stylevarid[]' => $vbulletin->GPC['stylevarid']));
}

// ########################################################################
if ($_REQUEST['do'] == 'confirmrevert')
{
	if (!$userContext->hasAdminPermission('canadminstyles'))
	{
		print_cp_no_permission();
	}
	// confirm whether or not user wants to revert that particular stylevar
	$vbulletin->input->clean_array_gpc('r', array(
		'stylevarid' => vB_Cleaner::TYPE_STR,
		'rootstyle'  => vB_Cleaner::TYPE_INT,
	));

	$hidden = array();
	$hidden['dostyleid'] = $vbulletin->GPC['dostyleid'];

	print_delete_confirmation('stylevar', $vbulletin->GPC['stylevarid'], 'stylevar', 'dorevert', 'stylevar',
		$hidden, $vbphrase['please_be_aware_stylevar_is_inherited'], $vbulletin->GPC['rootstyle']);
}

// ########################################################################
if ($_POST['do'] == 'dorevert')
{
	if (!$userContext->hasAdminPermission('canadminstyles'))
	{
		print_cp_no_permission();
	}
	$vbulletin->input->clean_array_gpc('p', array(
		'stylevarid' => vB_Cleaner::TYPE_STR,
		'dostyleid'  => vB_Cleaner::TYPE_INT
	));

	if ($vbulletin->GPC['dostyleid'] == -1)
	{
		//Changing this to grab the dfn information.  We only grab this for the product
		//which isn't stored in the stylevar table in the first place.  Not strickly speaking
		//a filesystem xml change, but an obvious bug.
		$stylevarinfo = $assertor->getRow('vBForum:stylevardfn', array('stylevarid' => $vbulletin->GPC['stylevarid']));

		$assertor->delete('vBForum:stylevar', array('stylevarid' => $vbulletin->GPC['stylevarid']));
		$assertor->delete('vBForum:stylevardfn', array('stylevarid' => $vbulletin->GPC['stylevarid']));

		if (!$stylevarinfo['product'])
		{
			$product = array('', 'vbulletin');
		}
		else
		{
			$product = array($stylevarinfo['product']);
		}

		vB::getDbAssertor()->assertQuery('vBForum:phrase', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_DELETE,
			vB_dB_Query::CONDITIONS_KEY => array(
				array('field'=> 'varname', 'value' => array("stylevar_" . $vbulletin->GPC['stylevarid'] . "_name", "stylevar_" . $vbulletin->GPC['stylevarid'] . "_description"), vB_dB_Query::OPERATOR_KEY => vB_dB_Query::OPERATOR_EQ),
				array('field'=> 'fieldname', 'value' => 'style', vB_dB_Query::OPERATOR_KEY => vB_dB_Query::OPERATOR_EQ),
				array('field'=> 'product', 'value' => $product, vB_dB_Query::OPERATOR_KEY => vB_dB_Query::OPERATOR_EQ)
			)
		));

		// rebuild languages
		require_once(DIR . '/includes/adminfunctions_language.php');
		build_language(-1);

		if (defined('DEV_AUTOEXPORT') AND DEV_AUTOEXPORT)
		{
			require_once(DIR . '/includes/functions_filesystemxml.php');
			autoexport_write_style_and_language($vbulletin->GPC['dostyleid'], $stylevarinfo['product']);
		}

		vB_Library::instance('Style')->setCssDate();
		print_rebuild_style($vbulletin->GPC['dostyleid']);
		print_stop_message2(array('reverted_stylevar_x_successfully', $vbulletin->GPC['stylevarid']), 'stylevar',
			array('dostyleid' => $vbulletin->GPC['dostyleid']));
	}
	else
	{
		$assertor->delete('vBForum:stylevar', array('stylevarid' => $vbulletin->GPC['stylevarid'], 'styleid' => intval($vbulletin->GPC['dostyleid'])));

		print_rebuild_style($vbulletin->GPC['dostyleid']);
		print_stop_message2(array('reverted_stylevar_x_successfully', $vbulletin->GPC['stylevarid']), 'stylevar',
			array('dostyleid' => $vbulletin->GPC['dostyleid'], 'do' => 'fetchstylevareditor',
			'stylevarid[]' => $vbulletin->GPC['stylevarid']));
	}
}

// ########################################################################
if ($_POST['do'] == 'savestylevar')
{
	if (!$userContext->hasAdminPermission('canadminstyles'))
	{
		print_cp_no_permission();
	}

	// $_POST['stylevar'] is an array of one or more stylevars to save. The key is the
	// stylevarid (a string) and the value is either an array of stylevar data or a
	// string of stylevar data.
	$vbulletin->input->clean_array_gpc('p', array(
		'stylevar' => vB_Cleaner::TYPE_ARRAY_ARRAY,
	));

	// ensure that the data contained in $vbulletin->GPC['stylevar'] is the expected format </paranoia>
	$stylevar_data = $vbulletin->GPC['stylevar'];
	$vbulletin->GPC['stylevar'] = array();
	foreach ($stylevar_data AS $stylevar_data_key => $stylevar_data_value)
	{
		$stylevar_data_key = strval($stylevar_data_key);

		$stylevar_data_value_new = array();
		foreach ($stylevar_data_value AS $stylevar_data_value_k => $stylevar_data_value_v)
		{
			$stylevar_data_value_new[strval($stylevar_data_value_k)] = strval($stylevar_data_value_v);
		}
		$stylevar_data_value = $stylevar_data_value_new;

		$vbulletin->GPC['stylevar'][$stylevar_data_key] = $stylevar_data_value;
	}
	unset($stylevar_data, $stylevar_data_key, $stylevar_data_value, $stylevar_data_value_k, $stylevar_data_value_v, $stylevar_data_value_new);

	// get the submitted stylevars
	$stylevarids = array_keys($vbulletin->GPC['stylevar']);

	// get the existing stylevar values
	$stylevars_result = $assertor->getRows('vBForum:getExistingStylevars', array('stylevarids' => $stylevarids));

	$stylevars = array();
	foreach ($stylevars_result AS $sv)
	{
		$stylevars[$sv['stylevarid']][$sv['stylevarstyleid']] = $sv;
	}

	print_form_header('admincp/stylevar', 'savestylevar');
	construct_hidden_code('dostyleid', $vbulletin->GPC['dostyleid']);

	// check if the stylevar was changed
	$original_values = array();
	$stylecache = vB_Library::instance('Style')->fetchStyles(false, false);
	foreach ($vbulletin->GPC['stylevar'] AS $stylevarid => $value)
	{
		$styleid = $vbulletin->GPC['dostyleid'];

		if (isset($stylevars[$stylevarid][$styleid]))
		{
			// existing value from the database
			$original_value = unserialize($stylevars[$stylevarid][$styleid]['value']);
		}
		else
		{
			// get inherited value
			while (!isset($stylevars[$stylevarid][$styleid]))
			{
				$styleid = $stylecache[$styleid]['parentid'];
				if (!isset($stylecache[$styleid]))
				{
					$styleid = -1;
					break;
				}
			}

			if (!isset($stylevars[$stylevarid][$styleid]))
			{
				$original_value = array();
			}
			else
			{
				$original_value = unserialize($stylevars[$stylevarid][$styleid]['value']);
			}
		}

		// This duplicates some of the stuff we do below but oh well.
		$updated = false;
		foreach ($value AS $key => $element)
		{
			if (strpos($key, 'original_') === 0)
			{
				// This is the "original" value that may have actually come from another stylevar.
				// We use it for comparison later. ($element == $value['original_'.$key])
				continue;
			}

			if (strpos($key, 'stylevar_') === 0)
			{
				// We'll compare them later with their associated key like original_.
				continue;
			}

			if (!isset($original_value[$key]))
			{
				$original_value[$key] = '';
				$original_value['stylevar_' . $key] = '';
				$updated = true;
				continue;
			}

			// The original_value for $key might be different if it's actually using a stylevar.
			// Thus we use original_$key
			if ($element != $value['original_' . $key])
			{
				// If these don't match then the user wants to change the value
				$updated = true;
			}
			else if ($vb5_config['Misc']['debug'])
			{
				// otherwise, let's check the stylevar equivalent has changed if debug is on
				if (!isset($original_value['stylevar_' . $key]))
				{
					$original_value['stylevar_' . $key] = '';
				}

				if ($value['stylevar_' . $key] != $original_value['stylevar_' . $key])
				{
					$updated = true;
				}
			}
		}

		if ($updated AND !isset($original_values[$stylevarid]))
		{
			$original_values[$stylevarid] = $original_value;
		}
	}
	$updated_stylevars = array_keys($original_values);

	// save changes
	if (count($updated_stylevars))
	{
		$existing_result = $assertor->getRows('vBForum:stylevar', array(
			'styleid' => intval($vbulletin->GPC['dostyleid']), 'stylevarid' => $updated_stylevars
		));

		$updating = array();
		foreach ($existing_result AS $existing)
		{
			$updating[] = $existing['stylevarid'];
		}

		$existing_dfns = $assertor->getRows('vBForum:stylevardfn', array(
			'stylevarid' => $updated_stylevars
		));

		$dfns = array();
		foreach ($existing_dfns AS $dfn)
		{
			$dfns[$dfn['stylevarid']] = $dfn;
		}

		$dms = array();
		$errors = array();

		// actually manage the data
		foreach ($updated_stylevars AS $stylevarid)
		{
			$class ='vB_DataManager_StyleVar' . $dfns[$stylevarid]['datatype'];
			$svinstance = new $class(vB_DataManager_Constants::ERRTYPE_CP);

			//save these for later.  Leave the local loop variable in place for checking.
			$dms[$stylevarid] = $svinstance;

			if (in_array($stylevarid, $updating))
			{
				$svexisting = array('stylevarid' => $stylevarid, 'styleid' => $vbulletin->GPC['dostyleid']);
				$svinstance->set_existing($svexisting);
			}
			else
			{
				$svinstance->set('stylevarid', $stylevarid);
				$svinstance->set('styleid', $vbulletin->GPC['dostyleid']);
			}
			$svinstance->set('username', $vbulletin->userinfo['username']);

			$update_properties = array();

			if (isset($vbulletin->GPC['stylevar'][$stylevarid]['units']))
			{
				$update_properties[] = 'units';
			}

			switch ($dfns[$stylevarid]['datatype'])
			{
				case 'background':
					$update_properties[] = 'color';
					$update_properties[] = 'image';
					$update_properties[] = 'repeat';
					$update_properties[] = 'x';
					$update_properties[] = 'y';
					$update_properties[] = 'gradient_type';
					$update_properties[] = 'gradient_direction';
					$update_properties[] = 'gradient_start_color';
					$update_properties[] = 'gradient_mid_color';
					$update_properties[] = 'gradient_end_color';
					break;

				case 'textdecoration':
					$update_properties[] = 'none';
					$update_properties[] = 'underline';
					$update_properties[] = 'overline';
					$update_properties[] = 'line-through';
					break;

				case 'texttransform':
					$update_properties[] = 'texttransform';
					break;

				case 'textalign':
					$update_properties[] = 'textalign';
					break;

				case 'font':
					$update_properties[] = 'family';
					$update_properties[] = 'size';
					$update_properties[] = 'lineheight';
					$update_properties[] = 'weight';
					$update_properties[] = 'style';
					$update_properties[] = 'variant';
					break;

				case 'imagedir':
					$update_properties[] = 'imagedir';
					break;

				case 'string':
					$update_properties[] = 'string';
					break;

				case 'numeric':
					$update_properties[] = 'numeric';
					break;

				case 'url':
					$update_properties[] = 'url';
					break;

				case 'path':
					$update_properties[] = 'path';
					break;

				case 'fontlist':
					$update_properties[] = 'fontlist';
					break;

				case 'color':
					$update_properties[] = 'color';
					break;

				case 'size':
					$update_properties[] = 'size';
					break;

				case 'boolean':
					$update_properties[] = 'boolean';
					break;

				case 'border':
					$update_properties[] = 'width';
					$update_properties[] = 'style';
					$update_properties[] = 'color';
					break;

				case 'dimension':
					$update_properties[] = 'width';
					$update_properties[] = 'height';
					break;

				case 'padding':
				case 'margin':
					$update_properties[] = 'top';
					$update_properties[] = 'right';
					$update_properties[] = 'bottom';
					$update_properties[] = 'left';
					$update_properties[] = 'same';
					break;

				default:
					die("Failed to find " . $dfns[$stylevarid]['datatype']);
					// attempt to set the simple types as is, might be glitchy...
					$update_properties[] = $dfns[$stylevarid]['datatype'];
					break;
			}

			//Validation is a mess here.  The issue is that the "set_child" function only produces an error
			//*if* the field is required.  Otherwise we simply blank the field and move on.  So we can't
			//simply rely on the DM behavior to handle validation.  We also don't want to duplicate the
			//validation logic to validate the properties before we set the DMs.
			//
			//Probably the correct approach is to switch the validation to one of the options that
			//records errors rather than displaying them and handling the error processing here.
			//That will at least put all of the errors on an even footing.  However that opens up some
			//additional questions.  For now the likely failures are all on non required fields so
			//let's handle those errors and rely on the DMs for everything else.
			foreach ($update_properties AS $property)
			{
				$stylevar_vals = $vbulletin->GPC['stylevar'][$stylevarid];
				$orig_prop_name = 'original_' . $property;
				$stylevar_prop_name = 'stylevar_' . $property;
				$orig_stylevar_prop_name = 'original_stylevar_' . $property;
				$inherit_param_prop_name = 'inherit_param_' . $property;
				$orig_inherit_param_prop_name = 'original_inherit_param_' . $property;
				$removeInheritance = false;

				if (
					$vb5_config['Misc']['debug'] AND
					!empty($stylevar_vals[$stylevar_prop_name])
				)
				{
					// We're in debug mode and the stylevar inheritance field is not empty
					// so we potentially have inheritance from another stylevar.

					// Now, we have two options:

					//     A. If the literal value has changed and it doesn't match
					//        the inherited value, then we will consider it a literal
					//        value that the user wants to save instead of the inherited
					//        value.
					//     B. If the literal value hasn't changed, or if it matches
					//        the final calculated inherited value, then we want
					//        so save the inherited value. Note that the literal value
					//        input is also used as a preview of what the inherited value
					//        will be, which is why it may have changed when the user
					//        modifies the inheritance.

					// To facilitate checking A or B and avoid calling the template runtime
					// to actually generate the derived inherited value (including applying
					// the color inherit params), we can simplify the logic:

					//     A. If the literal value field ("<property>") has changed, but the
					//        inherited stylevar field hasn't, then use the literal value.
					//     B. If the inherited stylevar field ("stylevar_<property>") has
					//        changed, use the inheritance. Note that in this case, the
					//        literal value will have changed as well, since it's updated via
					//        JS as a preview of the inherited value.

					// If this simplification is problematic, e.g., if someone changes the inherit
					// field, *then* manually changes the literal field, and they want to use the
					// literal value, then we'll need to actually query and check if the literal
					// field matches the final calculcated inherited value, and only if they match
					// then we go with Case B. In real usage, it seems this shouldn't happen very
					// often, and we can deal with it if it does.

					$hasLiteralValueChanged = ($stylevar_vals[$property] != $stylevar_vals[$orig_prop_name]);
					$hasInheritedValueChanged = ($stylevar_vals[$stylevar_prop_name] != $stylevar_vals[$orig_stylevar_prop_name]);
					$hasInheritedColorParamChanged = ($stylevar_vals[$inherit_param_prop_name] != $stylevar_vals[$orig_inherit_param_prop_name]);
					$hasInheritanceChanged = ($hasInheritedValueChanged OR $hasInheritedColorParamChanged);

					if ($hasLiteralValueChanged AND !$hasInheritanceChanged)
					{
						// Case A -- Save literal value, remove inheritance.
						$svinstance->set_child($property, $stylevar_vals[$property]);
						$svinstance->set_child($stylevar_prop_name, '');
						$removeInheritance = true;
					}
					else if ($hasInheritanceChanged)
					{
						// Case B -- Remove literal value, save inheritance
						// literal value has to be removed so inheritance will apply
						$svinstance->set_child($property, '');
						$svinstance->set_child($stylevar_prop_name, $stylevar_vals[$stylevar_prop_name]);
					}
					else
					{
						// Nothing changed, set existing values in case the save goes
						// through, e.g., another property was changed.
						$svinstance->set_child($property, $original_values[$stylevarid][$property]);
						$svinstance->set_child($stylevar_prop_name, $original_values[$stylevarid][$stylevar_prop_name]);
					}
				}
				else if ($stylevar_vals[$property] != $stylevar_vals[$orig_prop_name])
				{
					// We're manually changing the property value. Thus, we should no longer be using
					// the stylevar_* (inheritance) property.
					if(!$svinstance->set_child($property, $stylevar_vals[$property]))
					{
						$errors[] = array('invalid_stylevar_value', $stylevarid, $property);
					}

					// clear inherited value
					$svinstance->set_child($stylevar_prop_name, '');
				}
				else if ($stylevar_vals[$stylevar_prop_name] !== $original_values[$stylevarid][$stylevar_prop_name])
				{
					// stylevar value is the same as original, BUT we unset or changed the "inherit from" bit
					$svinstance->set_child($property, $stylevar_vals[$property]);

					// set inherited value
					$svinstance->set_child($stylevar_prop_name, $stylevar_vals[$stylevar_prop_name]);
				}
				else
				{
					// We need to set the original properties in case anything else was saved.
					$svinstance->set_child($property, $original_values[$stylevarid][$property]);

					// set inherited value
					$svinstance->set_child($stylevar_prop_name, $original_values[$stylevarid][$stylevar_prop_name]);
				}

				// Add the inherit params for "color" stylevar properties.
				// We do this after adding doing the inheritance properites
				// above (the "stylevar_*" values), because we don't want
				// to inherit the inherit params themselves.
				// We could potentially allow that, but it's not a complication I want to get into
				// for the first iteration of this.
				// This currently applies to background, border, and color stylevar types
				if (substr($property, -5) == 'color')
				{
					$inherit_param_property_name = 'inherit_param_' . $property;

					if ($removeInheritance)
					{
						// inheritance is not being used
						$svinstance->set_child($inherit_param_prop_name, '');
					}
					else if ($stylevar_vals[$inherit_param_property_name] != $stylevar_vals['original_' . $inherit_param_property_name])
					{
						// value was modified
						$svinstance->set_child($inherit_param_property_name, $stylevar_vals[$inherit_param_property_name]);
					}
					else
					{
						// value was not modified, set to original value in case anything else was
						// modified and the save goes through.
						$svinstance->set_child($inherit_param_property_name, $original_values[$stylevarid][$inherit_param_property_name]);
					}

				}
			}
		}

		if(count($errors))
		{
			print_stop_message_array($errors);
		}

		//if we got this far, save the values.
		foreach($dms AS $svinstance)
		{
			$svinstance->build();
			$svinstance->save();
		}
		unset($dms);

		if (defined('DEV_AUTOEXPORT') AND DEV_AUTOEXPORT)
		{
			//we might have done something strange and selected stylvars from different products.
			$products = array();
			foreach ($dfns AS $dfn)
			{
				$products[$dfn['product']] = 1;
			}
			$products = array_keys($products);
			foreach($products AS $product)
			{
				require_once(DIR . '/includes/functions_filesystemxml.php');
				autoexport_write_style($vbulletin->GPC['dostyleid'], $product);
			}
		}
	}

	vB_Library::instance('Style')->setCssDate();
	print_rebuild_style($vbulletin->GPC['dostyleid']);
	print_stop_message2('stylevar_saved_successfully', 'stylevar',
			array('dostyleid' => $vbulletin->GPC['dostyleid'], 'do' => 'fetchstylevareditor',
			'stylevarid' => array_keys($vbulletin->GPC['stylevar'])));
}

// ########################################################################
if ($_REQUEST['do'] == 'fetchstylevareditor')
{
	if (!$userContext->hasAdminPermission('canadminstyles'))
	{
		print_cp_no_permission();
	}

	$vbulletin->input->clean_array_gpc('r', array(
		'stylevarid' => vB_Cleaner::TYPE_ARRAY_NOHTML
	));

	if (count($vbulletin->GPC['stylevarid']) == 0)
	{
		print_stop_message2(array('invalidid', 'stylevarid'));
	}
	else
	{
		$stylevarids = $vbulletin->GPC['stylevarid'];
	}

	$stylevars_result = $assertor->getRows('vBForum:getExistingStylevars', array('stylevarids' => $stylevarids));

	// Some checks to see if we need to show the download link.
	$groupHasCustomStyleVars = array();
	$groupHasCustomizationInThisStyleid = array();
	$styleParents = $styleinfo['parentlist'];
	$styleParentsByStyleid = array();
	if (is_string($styleParents))
	{
		$styleParents = explode(',', $styleParents);
	}
	if (is_array($styleParents))
	{
		foreach ($styleParents AS $__styleid)
		{
			$styleParentsByStyleid[$__styleid] = $__styleid;
		}
	}
	$alwaysShowDownloadLink = false;
	/*
		Okay, this doesn't quite work as expected when tested because the style exporter
		doesn't actually allow exporting the "default" style's stylevars if it's unchanged...
		So leaving this out for now.
	if ($vbulletin->GPC['dostyleid'] == -1 OR
		$vbulletin->GPC['dostyleid'] == $vbulletin->options['styleid']
	)
	{
		// Always allow exports for the "master" style or "default" styles
		$alwaysShowDownloadLink = true;
	}
	 */

	$stylevars = array();
	foreach ($stylevars_result AS $sv)
	{
		$__group = $sv['stylevargroup'];
		$stylevars[$__group][$sv['stylevarid']][$sv['stylevarstyleid']] = $sv;
		if (!isset($groupHasCustomStyleVars[$__group]))
		{
			$groupHasCustomStyleVars[$__group] = false;
			$groupHasCustomizationInThisStyleid[$__group] = false;
		}

		// if it's not -1, it's either customized in this style or inherited from parent. See the set_inherited() calls way above
		// If we need to differentiate, stylevarstyleid == dostyleid => customized here, otherwise it's inherited.
		if ($alwaysShowDownloadLink)
		{
			$groupHasCustomStyleVars[$__group]  = true;
			$groupHasCustomizationInThisStyleid[$__group] = true;
		}
		else if ($sv['stylevarstyleid'] != -1)
		{
			if (isset($styleParentsByStyleid[$sv['stylevarstyleid']]))
			{
				$groupHasCustomStyleVars[$__group]  = true;
				if ($sv['stylevarstyleid'] == $vbulletin->GPC['dostyleid'])
				{
					$groupHasCustomizationInThisStyleid[$__group] = true;
				}
			}
		}
	}

	echo '<div style="margin: 0 10px">';

	print_form_header('admincp/stylevar', 'savestylevar', false, true, 'cpform', '95%');
	construct_hidden_code('dostyleid', $vbulletin->GPC['dostyleid']);

	/*
		'filename'        => vB_Cleaner::TYPE_STR,
		'title'           => vB_Cleaner::TYPE_NOHTML,
		'mode'            => vB_Cleaner::TYPE_UINT,
		'product'         => vB_Cleaner::TYPE_STR,
		'remove_guid'     => vB_Cleaner::TYPE_BOOL,
		'stylevars_only'  => vB_Cleaner::TYPE_BOOL,
		'stylevar_groups' => vB_Cleaner::TYPE_ARRAY_UINT, // todo
	 */
	$__title = "";
	//$__mode = 1; // Get customizations in this style & all parents
	$__product = "vbulletin";
	$__remove_guid = 1;
	$__stylevars_only = 1;
	// "admincp/" is added via construct_link_code()
	$downloadStylevarsLinkPrefix = "template.php?do=files"
		. "&dostyleid=" . $vbulletin->GPC['dostyleid']
		. "&title=" . urlencode($styleinfo['title'])
		//. "&mode={$__mode}" // handled separately below
		. "&product=" . urlencode($__product)
		. "&remove_guid={$__remove_guid}"
		. "&stylevars_only={$__stylevars_only}"
		. "&skip_upload_form=true";


	// for each result record
	$stylevarids = array();
	foreach($stylevars AS $stylevargroup_name => $stylevargroup)
	{
		$__downloadLink = "";
		$__readonlyVars = array(
			'dostyleid' => true,
			'remove_guid' => true,
			'stylevars_only' => true,
		);
		if ($groupHasCustomStyleVars[$stylevargroup_name])
		{
			$__downloadLink = $downloadStylevarsLinkPrefix . "&stylevar_groups[]=" . urlencode($stylevargroup_name);
			// todo: better title & filename??
			$__filename = preg_replace('/[^A-Za-z0-9]/', "", $stylevargroup_name) . ".xml";
			$__downloadLink .= "&filename=" . urlencode($__filename);

			if ($groupHasCustomizationInThisStyleid[$__group] )
			{
				$__downloadLink .= "&mode=0";
			}
			else
			{
				$__downloadLink .= "&mode=1";
				$__readonlyVars['mode'] = true;
			}

			foreach ($__readonlyVars AS $__key => $__val)
			{
				$__downloadLink .= "&readonly[" . $__key . "]=" . $__val;
			}

			$__downloadLink = construct_link_code($vbphrase['download_stylevar_group'], $__downloadLink);
		}
		$stylevargroup_phrase_key = 'stylevargroup_' . strtolower($stylevargroup_name) . '_name';
		$stylevargroup_phrase = !empty($vbphrase[$stylevargroup_phrase_key]) ? $vbphrase[$stylevargroup_phrase_key] : '~~' . $stylevargroup_phrase_key . ' ~~';
		$editor .= "<h2>" . $stylevargroup_phrase . "</h2>" . $__downloadLink;

		foreach($stylevargroup AS $stylevarid => $stylevar_style)
		{
			$stylevarids[] = $stylevarid;
			$editor .= construct_stylevar_form($stylevarid, $stylevarid, $stylevargroup, $vbulletin->GPC['dostyleid']);
		}
	}

	echo $editor;
	print_submit_row($vbphrase['save']);

	echo '<script type="text/javascript">
		<!--
		vBulletin.init();
		-->
		</script>

		<script type="text/javascript">
		(function()
		{
			var stylevarids = ["' . implode('", "', $stylevarids) . '"],
				d = window.parent.document,
				optList = d.getElementById("varlist"),
				i,
				stylevarid,
				inheritanceLevel,
				$elm;

			// loop through the stylevars that are displayed in the iframe
			// and update the color to reflect their inherited or customized
			// status, since the stylevar list is not refreshed.
			for (i in stylevarids)
			{
				stylevarid = stylevarids[i];
				inheritanceLevel = window.vBulletinStylevarInheritance[stylevarid];
				$elm = $("#varlist_stylevar" + stylevarid, d);
				$elm.removeClass("col-c col-i col-g");
				switch (inheritanceLevel)
				{
					// customized in this style
					case -1:
						$elm.addClass("col-c");
						break;

					// customized in a parent/ancestor style and inherited here
					case 1:
						$elm.addClass("col-i");
						break;

					// not customized
					case 0:
						$elm.addClass("col-g");
						break;
				}
			}
		})();
		</script>
	';

	echo '</div>';
	define('NO_CP_COPYRIGHT', true);
}

// ########################################################################
if ($_REQUEST['do'] == 'showstylevartemplateusage')
{
	if (!$userContext->hasAdminPermission('canadminstyles'))
	{
		print_cp_no_permission();
	}
	echo '<h3>' . $vbphrase['stylevar_template_usage'] . ': (' . $vbphrase['master_style'] . ')</h3>';

	$stylevarGroups = fetch_stylevars_array();
	echo '<ul>';
	foreach ($stylevarGroups AS $group => $stylevars)
	{
		echo '<li><b><i>' . $group . '</i></b><ul>';
		foreach ($stylevars AS $stylevarid => $stylevar)
		{
			$templates = $assertor->getRows('template', array(
				vB_dB_Query::COLUMNS_KEY => array('title'),
				vB_dB_Query::CONDITIONS_KEY => array(
					array('field' => 'template_un', 'value' => $stylevarid, 'operator' => vB_dB_Query::OPERATOR_INCLUDES),
					'styleid' => -1,
				),
			), 'title');
			$templateNames = array();
			foreach ($templates AS $template)
			{
				if (!isset($templateNames[$template['title']]))
				{
					$templateNames[$template['title']] = 0;
				}
				++$templateNames[$template['title']];
			}
			echo '<li>';
			if (!empty($templateNames))
			{
				echo $stylevarid;
				echo '<ul>';
				foreach ($templateNames AS $templateName => $usageCount)
				{
					echo '<li>' . $templateName . ' (' . $usageCount . ')' . '</li>';

				}
				echo '</ul>';
			}
			else
			{
				echo '<b style="color:red">' . $stylevarid . '</b>';
			}
			echo '</li>';


		}
		echo '</ul></li>';
	}
	echo '</ul>';

	define('NO_CP_COPYRIGHT', true);
}

// ########################################################################
if ($_REQUEST['do'] == 'modify')
{
	if (!$userContext->hasAdminPermission('canadminstyles'))
	{
		print_cp_no_permission();
	}

	// prepend some JS & CSS
$prepend = '<script type="text/javascript">
<!--

function init(e)
{
	// activate special controls
	init_text_decoration_handler();
	init_margin_padding_handler();
}

function handle_stylevar_delete(e)
{
	var selector = YAHOO.util.Dom.get("varlist");
	var selected = Array();
	// get selected stylevars
	for (i=0; i<selector.length; i++)
	{
		if (selector.options[i].selected == true)
		{
			selected.push(selector.options[i].value);
		}
	}

	// build request string
	if (selected.length != 0)
	{
		var request_string = "";
		for (i=0; i<selected.length; i++)
		{
			request_string = request_string + "stylevarid=" + selected[i] + "&";
		}
		var url = "admincp/stylevar.php?" + SESSIONURL + "securitytoken=" + SECURITYTOKEN + "&adminhash=" + ADMINHASH + "&do=confirmrevert&" + request_string + "dostyleid=" + ' . $vbulletin->GPC['dostyleid'] . ';
		//var editorpane = YAHOO.util.Dom.get("edit_scroller");
		vBRedirect(url);
	}
}

function handle_ajax_request(ajax)
{
	// display the form
	var editorpane = YAHOO.util.Dom.get("editor");
	editorpane.innerHTML = ajax.responseText;
}

function handle_ajax_error(ajax)
{
	// notify user
}

function init_text_decoration_handler()
{
	var text_decs = YAHOO.util.Dom.getElementsByClassName("text-decoration", "fieldset", "editor");

	for (var i = 0; i < text_decs.length; i++)
	{
		if (typeof(txtdec_ctrls[text_decs[i].id]) != "object")
		{
			txtdec_ctrls[text_decs[i].id] = new TextDecorationControl(text_decs[i]);
		}
	}
}

function TextDecorationControl(element)
{
	this.id = element.id;
	this.controls = element.getElementsByTagName("input");

	for (var i = 0; i < this.controls.length; i++)
	{
		YAHOO.util.Event.on(this.controls[i], "click", this.handle_click, this, true);
	}
}

TextDecorationControl.prototype.handle_click = function(e)
{
	var target = YAHOO.util.Event.getTarget(e);

	if (target.id == this.id + ".none")
	{
		console.info("Text-Decoration:none");
		for (var i = 0; i < this.controls.length; i++)
		{
			if (this.controls[i].id != this.id + ".none")
			{
				this.controls[i].checked = false;
			}
		}
	}
	else
	{
		console.log("Text-Decoration:(not none)");
		YAHOO.util.Dom.get(this.id + ".none").checked = false;
	}
}

function init_margin_padding_handler()
{
	var bps = YAHOO.util.Dom.getElementsByClassName("margin-padding", "fieldset", "editor");

	for (var i = 0; i < bps.length; i++)
	{
		if (typeof(bp_ctrls[bps[i].id]) != "object")
		{
			bp_ctrls[bps[i].id] = new MarginPaddingControl(bps[i]);
			console.log(bps[i].id);
		}
	}
}

function MarginPaddingControl(element)
{
	this.id = element.id;
	this.same = YAHOO.util.Dom.get(this.id + ".same");
	this.dynamic_elements = new Array("right", "bottom", "left");

	YAHOO.util.Event.on(this.same, "click", this.set_state, this, true);
	YAHOO.util.Event.on(this.id + ".top", "keyup", this.set_state, this, true);

	this.set_state();
}

MarginPaddingControl.prototype.set_state = function()
{
	var value, current_element, i = null;

	value = YAHOO.util.Dom.get(this.id + ".top").value;

	for (i = 0; i < this.dynamic_elements.length; i++)
	{
		current_element = YAHOO.util.Dom.get(this.id + "." + this.dynamic_elements[i]);

		current_element.disabled = (this.same.checked ? "disabled" : "");

		if (this.same.checked)
		{
			current_element.value = value;
		}
	}
}

var txtdec_ctrls = new Object();
var bp_ctrls = new Object();

YAHOO.util.Event.on(window, "load", init);

//-->
</script>
<style type="text/css">
.leftcontrol {
	width:325px;
}

.leftcontrol-meta-row {
	margin-bottom: 5px;
}

.leftcontrol-meta-row:nth-child(3) {
	margin-bottom: 8px;
}

.leftcontrol-meta-row input[type="checkbox"] {
	margin: 0;
	vertical-align: bottom;
}

.toggle-link-selected {
	color: #000;
	text-decoration: none;
	font-weight: bold;
}


#varlist option {
	padding-left:20px;
}

#varlist option.optgroup {
	padding-left:0;
	font-weight:bold;
}

#varlist optgroup {
	font-style: normal;
}

#edit_container {
	position:relative;
}
#edit_scroller {
	width:100%;
	min-height:573px;
	border:inset 2px;
	background:white;
}
#editor {
	padding:0px 10px;
}

td {
	font:11px Verdana, Geneva, sans-serif;
}

fieldset {
	font:11px Verdana, Geneva, sans-serif;
	margin-bottom:10px;
}

legend {
	font:10pt Verdana, Geneva, sans-serif;
}

fieldset > div {
	float:left;
	margin-right:10px;
	margin-bottom:10px;
}

input, select {
	font:11px Verdana, Geneva, sans-serif;
}

label {
	display:block;
}

label:after {
	content:"";
}

input[type="text"], select {
	margin-top:2px;
}

input[type="text"] {
	width:150px;
}

.color input[type="text"] {
	width:100px;
}
.color input[type="button"] {
	background-color:#09F;
	width:25px;
	clear:both;
 	float:none;
}

.font-size input[type="text"],
.position input[type="text"],
.size input[type="text"],
.margin-padding input[type="text"] {
	width:50px;
	text-align:right;
}

.margin-padding .same {
	clear:both;
	float:none;
}
.margin-padding .same label:after {
	content:none;
}

.text-decoration {
	clear:both;
	float:none;
}

.text-decoration .label:after {
	content:":";
}

.text-decoration label {
	display:inline;
}

.text-decoration label:after {
	content:none;
}
</style>';

	echo $prepend;
	// table wrapper
	echo '
		<table width="100%" align="center" class="tborder" border="0" cellpadding="4" cellspacing="1">
			<tr>
				<th colspan="2" class="tcat">
					<b>' . $vbphrase['stylevareditor'] . ' - ' . $styleinfo['title'] . '</b>
				</th>
			</tr>
			<tr valign="top">
				<td class="alt2">
	';
	// show the search field and the checkboxes
	//TODO redisplay var checkbox when Friendly names are working.  "display:none" allows the element
	//to still exist for js purposes -- otherwise we'll need to remove the references to it in the js
	//to avoid errors.  That's more work now and more work later when we want to reenable it.  The
	//functionality is harmess even in its present state, so it doesn't hurt much to leave it in
	//like this.
	echo '
					<div class="js-stylevar-editor-data h-hide-imp" data-dostyleid="' . $vbulletin->GPC['dostyleid'] . '"></div>
					<div class="leftcontrol-meta-row"><a href="#" class="js-stylevar-editor__toggle-all-groups js-toggle-expand-all" data-action="expand-all">' . $vbphrase['expand_all_groups'] . '</a> | <a href="#" class="js-stylevar-editor__toggle-all-groups js-toggle-collapse-all toggle-link-selected" data-action="collapse-all">' . $vbphrase['collapse_all_groups'] . '</a></div>
					<div class="leftcontrol-meta-row"><input type="text" name="filterbox" class="bginput smallfont js-stylevar-editor__text-filter" size="20" value="" placeholder="' . $vbphrase['search_stylevar'] . '" title="' . $vbphrase['search_stylevar'] . '" /> <a href="#" class="js-stylevar-editor__clear-text-filter h-hide-imp">' . $vbphrase['clear_search'] . '</a></div>
					<div class="leftcontrol-meta-row"><label><input type="checkbox" class="js-stylevar-editor__customized-filter" /> ' . $vbphrase['show_customized_variables'] . '</label></div>
		';

	// show the form for the $vbulletin->GPC['dostyleid']
	$stylevars = fetch_stylevars_array();
	// $stylevars['group']['stylevarid']['styleid'] = $stylevar (record array from db);

	echo "
					<div><select size='25' multiple='multiple' class='leftcontrol js-varlist' id='varlist'>
	";

	$groups = array_keys($stylevars);

	foreach($groups AS $group)
	{
		// display using friendly name
		$stylevargroup_phrase_key = 'stylevargroup_' . strtolower($group) . '_name';
		$stylevargroup_phrase = !empty($vbphrase[$stylevargroup_phrase_key]) ? $vbphrase[$stylevargroup_phrase_key] : '~~' . $stylevargroup_phrase_key . ' ~~';
		echo "
						<optgroup label='$stylevargroup_phrase &raquo;' data-label-expanded='$stylevargroup_phrase &laquo;' data-label-collapsed='$stylevargroup_phrase &raquo;' class='js-varlist-optgroup'>
		";
		$stylevarids = array_keys($stylevars[$group]);
		foreach ($stylevarids AS $stylevarid)
		{
			if ($stylevarid)
			{
				//TODO use friendly name once we figure that out.
				$color = fetch_inherited_color($stylevars["$group"]["$stylevarid"]['styleid'], $vbulletin->GPC['dostyleid']);

				if ($vb5_config['Misc']['debug'] AND $vbulletin->GPC['dostyleid'] == -1 AND (empty($vbphrase["stylevar_{$stylevarid}_name"]) OR	empty($vbphrase["stylevar_{$stylevarid}_description"])))
				{
					$name = $stylevarid . ' (UNPHRASED)';
				}
				else
				{
					$name = $stylevarid;
				}

				echo "
					<option id='varlist_stylevar$stylevarid' class=\"$color js-varlist-option\" value='" . $stylevarid . "'>" . $name . "</option>
				";
			}
		}

		echo "</optgroup>";
	}
	echo '
					</select></div>
	';
	if ($vb5_config['Misc']['debug'] AND ($vbulletin->GPC['dostyleid'] == -1))
	{
		// show the add stylevardfn button
		echo '
					<input type="button" value="' . $vbphrase['add_new_stylevar'] . '" onclick="vBRedirect(\'admincp/stylevar.php?do=dfnadd\');" />
					<input type="button" value="' . $vbphrase['delete_stylevar'] . '" onclick="handle_stylevar_delete()" />
					<input type="button" value="' . $vbphrase['stylevar_template_usage'] . '" onclick="document.getElementById(\'edit_scroller\').src=\'admincp/stylevar.php?do=showstylevartemplateusage\';" />
		';
	}
	// table wrapper
	echo '
					<table cellpadding="4" cellspacing="1" border="0" class="tborder" width="100%">
					<tr align="center">
						<td class="tcat"><b>' . $vbphrase['color_key'] . '</b></td>
					</tr>
					<tr>
						<td class="alt2">
						<div class="darkbg" style="margin: 4px; padding: 4px; border: 2px inset; text-align: ' . vB_Template_Runtime::fetchStyleVar('left') . '">
						<span class="col-g">' . $vbphrase['stylevar_is_unchanged_from_the_default_style'] . '</span><br />
						<span class="col-i">' . $vbphrase['stylevar_is_inherited_from_a_parent_style'] . '</span><br />
						<span class="col-c">' . $vbphrase['stylevar_is_customized_in_this_style'] . '</span>
						</div>
						</td>
					</tr>
					</table>
				</td>
				<td width="100%" class="alt2">
	';
	// show the editor pane
	echo '
					<iframe id="edit_scroller" class="js-edit-scroller">
					</iframe>
	';
	// table wrapper
	echo '
				</td>
			</tr>
		</table>
	';

	$return_url = 'stylevar.php?' . vB::getCurrentSession()->get('sessionurl') . '&dostyleid=' . $vbulletin->GPC['dostyleid'];
	//echo construct_link_code($vbphrase['rebuild_all_styles'],
	//	'template.php?' . vB::getCurrentSession()->get('sessionurl') . 'do=rebuild&amp;goto=' . urlencode($return_url));
}

// #############################################################################
// do revert all StyleVars in a style
if ($_POST['do'] == 'dorevertall')
{
	if (!$userContext->hasAdminPermission('canadminstyles'))
	{
		print_cp_no_permission();
	}
	if ($vbulletin->GPC['dostyleid'] != -1 AND $style = $assertor->getRow('vBForum:style', array('styleid' => $vbulletin->GPC['dostyleid'])))
	{
		if (!$style['parentlist'])
		{
			$style['parentlist'] = '-1';
		}

		$stylevars = $assertor->getRows('vBForum:getStylevarsToRevert', array(
			'parentlist' => explode(',', $style['parentlist']),
			'styleid' => $style['styleid'],
		));

		if (count($stylevars) == 0)
		{
			print_stop_message2('nothing_to_do');
		}
		else
		{
			$deletestylevars = array();

			foreach ($stylevars AS $stylevar)
			{
				$deletestylevars[] = $stylevar['stylevarid'];
			}

			if (!empty($deletestylevars))
			{
				vB::getDbAssertor()->assertQuery('vBForum:stylevar', array(
					vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_DELETE,
					vB_dB_Query::CONDITIONS_KEY => array(
						array('field'=> 'stylevarid', 'value' => $deletestylevars, vB_dB_Query::OPERATOR_KEY => vB_dB_Query::OPERATOR_EQ),
						array('field'=> 'styleid', 'value' => $style['styleid'], vB_dB_Query::OPERATOR_KEY => vB_dB_Query::OPERATOR_EQ)
					)
				));
				print_rebuild_style($style['styleid']);
			}

			$args = array();
			parse_str(vB::getCurrentSession()->get('sessionurl'),$args);
			$args['do'] = 'modify';
			$args['dostyleid'] = $style['styleid'];
			print_cp_redirect2('stylevar', $args, 1, 'admincp');
			vB_Library::instance('Style')->setCssDate();
		}
	}
	else
	{
		print_stop_message2('invalid_style_specified');
	}
}

// #############################################################################
// revert all StyleVars in a style
if ($_REQUEST['do'] == 'revertall')
{
	if ($vbulletin->GPC['dostyleid'] != -1 AND $style = $assertor->getRow('vBForum:style', array('styleid' => $vbulletin->GPC['dostyleid'])))
	{
		if (!$style['parentlist'])
		{
			$style['parentlist'] = '-1';
		}

		$stylevars = $assertor->getRows('vBForum:getStylevarsToRevert', array(
			'parentlist' => explode(',', $style['parentlist']),
			'styleid' => $style['styleid'],
		));

		if (count($stylevars) == 0)
		{
			print_stop_message2('nothing_to_do');
		}
		else
		{
			$stylevarlist = '';
			foreach ($stylevars AS $stylevar)
			{
				$stylevarlist .= "<li>$stylevar[stylevarid]</li>\n";
			}

			echo "<br /><br />";

			print_form_header('admincp/stylevar', 'dorevertall');
			print_table_header($vbphrase['revert_all_stylevars']);
			print_description_row("
				<blockquote><br />
				" . construct_phrase($vbphrase["revert_all_stylevars_from_style_x"], $style['title'], $stylevarlist) . "
				<br /></blockquote>
			");
			construct_hidden_code('dostyleid', $style['styleid']);
			print_submit_row($vbphrase['yes'], 0, 2, $vbphrase['no']);
		}
	}
	else
	{
		print_stop_message2('invalid_style_specified');
	}
}

print_cp_footer();

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 103571 $
|| #######################################################################
\*=========================================================================*/
