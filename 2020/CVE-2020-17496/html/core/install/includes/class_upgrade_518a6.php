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

class vB_Upgrade_518a6 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '518a6';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.1.8 Alpha 6';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.1.8 Alpha 5';

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

	/*
	 * Steps 1 & 2: VBV-14770 - Unset cansearch for the legacy content types that were added for vb4 mapi search reasons.
	 */
	public function step_1()
	{
		$this->show_message(sprintf($this->phrase['vbphrase']['update_table_x'], 'contenttype', 1, 2));

		$assertor = vB::getDbAssertor();

		// This package was added/verified in 518a2
		$package = $assertor->getRow('package', array('class' => 'vBBlog'));
		$contenttypes = $assertor->getRows(
			'vBForum:contenttype',
			array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
				vB_dB_Query::CONDITIONS_KEY => array(
					array('field' => 'class',		'value' => array('BlogEntry', 'BlogComment'),	'operator' =>  vB_dB_Query::OPERATOR_EQ),
					array('field' => 'packageid',	'value' => $package['packageid'],	'operator' =>  vB_dB_Query::OPERATOR_EQ),
					array('field' => 'cansearch',	'value' => 1, 						'operator' =>  vB_dB_Query::OPERATOR_EQ),
				)
			)
		);
		foreach ($contenttypes AS $contenttype)
		{
			$assertor->update('vBForum:contenttype',
				array(// update values
					'cansearch' => 0,
				),
				array(// update conditions
					'contenttypeid' => $contenttype['contenttypeid']
				)
			);
		}
	}

	public function step_2()
	{
		$this->show_message(sprintf($this->phrase['vbphrase']['update_table_x'], 'contenttype', 1, 2));

		$assertor = vB::getDbAssertor();

		// This package was added/verified in 518a3
		$package = $assertor->getRow('package', array('class' => 'vBCms'));
		$contenttypes = $assertor->getRows(
			'vBForum:contenttype',
			array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
				vB_dB_Query::CONDITIONS_KEY => array(
					array('field' => 'class',		'value' => 'Article',				'operator' =>  vB_dB_Query::OPERATOR_EQ),
					array('field' => 'packageid',	'value' => $package['packageid'],	'operator' =>  vB_dB_Query::OPERATOR_EQ),
					array('field' => 'cansearch',	'value' => 1, 						'operator' =>  vB_dB_Query::OPERATOR_EQ),
				)
			)
		);
		foreach ($contenttypes AS $contenttype)
		{
			$assertor->update('vBForum:contenttype',
				array(// update values
					'cansearch' => 0,
				),
				array(// update conditions
					'contenttypeid' => $contenttype['contenttypeid']
				)
			);
		}
	}
}

/*======================================================================*\
|| ####################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 101013 $
|| ####################################################################
\*======================================================================*/