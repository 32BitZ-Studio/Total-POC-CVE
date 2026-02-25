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
 * vB_Library_Options
 *
 * @package vBLibrary
 * @access public
 */
class vB_Library_Options extends vB_Library
{
	public function updateValue($varname, $value, $rebuild = true)
	{
		require_once(DIR . '/includes/functions_file.php');
		require_once(DIR . '/includes/adminfunctions_options.php');
		$retVal = vB::getDbAssertor()->update('setting', array('value' => $value),array('varname' => $varname));

		if ($rebuild)
		{
			vB::getDatastore()->build_options();
		}

		return array('success' => $retVal);
	}

	/**
	 * This function updates specified settings
	 * @param array $values
	 *	'varname' => $vbulletin->GPC['varname'],
	 *	'grouptitle' => $vbulletin->GPC['grouptitle'],
	 *	'optioncode' => $vbulletin->GPC['optioncode'],
	 *	'defaultvalue' => $vbulletin->GPC['defaultvalue'],
	 *	'displayorder' => $vbulletin->GPC['displayorder'],
	 *	'volatile' => $vbulletin->GPC['volatile'],
	 *	'datatype' => $vbulletin->GPC['datatype'],
	 *	'validationcode' => $vbulletin->GPC['validationcode'],
	 *	'product' => $vbulletin->GPC['product'],
	 *	'blacklist' => $vbulletin->GPC['blacklist'],
	 *	'title' => $vbulletin->GPC['title'],
	 *	'username' => $vbulletin->userinfo['username'],
	 *	'description' => $vbulletin->GPC['description']
	 * @return array, $response
	 */
	public function updateSetting($values)
	{
		require_once(DIR . '/includes/functions_file.php');
		require_once(DIR . '/includes/adminfunctions_options.php');
		require_once(DIR . '/includes/adminfunctions.php');
		$response = array();
		$langid = $values['volatile'] ? -1 : 0;

		vB::getDbAssertor()->assertQuery('setting',
		array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'grouptitle' => $values['grouptitle'],
			'optioncode' => $values['optioncode'],
			'defaultvalue' => $values['defaultvalue'],
			'displayorder' => $values['displayorder'],
			'volatile' => $values['volatile'],
			'datatype' => $values['datatype'],
			'validationcode' => $values['validationcode'],
			'product' => $values['product'],
			'blacklist' => $values['blacklist'],
			'ispublic' => $values['ispublic'],
			'adminperm' => (isset($values['adminperm']) ? $values['adminperm'] : ''),
			vB_dB_Query::CONDITIONS_KEY => array(
				array('field' => 'varname', 'value' => $values['varname'], 'operator' => vB_dB_Query::OPERATOR_EQ)
			)
		)
		);

		$phrases = vB::getDbAssertor()->assertQuery('vBForum:phrase', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
			'languageid' => array(-1,0),
			'fieldname' => 'vbsettings',
			'varname' => array("setting_" . $values['varname'] . "_title", "setting_" . $values['varname'] . "_desc")
		));

		$full_product_info = fetch_product_list(true);
		$product_version = $full_product_info[$values['product']]['version'];

		if ($phrases AND $phrases->valid())
		{
			$timeNow = vB::getRequest()->getTimeNow();

			foreach ($phrases AS $phrase)
			{
				if ($phrase['varname'] == "setting_" . $values['varname'] . "_title")
				{
					vB::getDbAssertor()->assertQuery('vBForum:phrase',
					array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_UPDATE,
						'languageid' => $langid,
						'text' => $values['title'],
						'product' => $values['product'],
						'username' => $values['username'],
						'dateline' => $timeNow,
						'version' => $product_version,
						vB_dB_Query::CONDITIONS_KEY => array(
							array('field' => 'languageid', 'value' => $phrase['languageid'], 'operator' => vB_dB_Query::OPERATOR_EQ),
							array('field' => 'varname', 'value' => "setting_" . $values['varname'] . "_title" , 'operator' => vB_dB_Query::OPERATOR_EQ)
						)
					)
					);
				}
				else if ($phrase['varname'] == "setting_" . $values['varname'] . "_desc")
				{
					vB::getDbAssertor()->assertQuery('vBForum:phrase',
					array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_UPDATE,
						'languageid' => $langid,
						'text' => $values['description'],
						'product' => $values['product'],
						'username' => $values['username'],
						'dateline' => $timeNow,
						'version' => $product_version,
						vB_dB_Query::CONDITIONS_KEY => array(
							array('field' => 'languageid', 'value' => $phrase['languageid'], 'operator' => vB_dB_Query::OPERATOR_EQ),
							array('field' => 'varname', 'value' => "setting_" . $values['varname'] . "_desc" , 'operator' => vB_dB_Query::OPERATOR_EQ)
						)
					)
					);
				}
			}
		}

		vB::getDatastore()->build_options();
		$response['update'] = true;
		return $response;
	}

}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 103332 $
|| #######################################################################
\*=========================================================================*/
