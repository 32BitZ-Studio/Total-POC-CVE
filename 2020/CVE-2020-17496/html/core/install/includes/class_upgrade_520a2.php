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

class vB_Upgrade_520a2 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '520a2';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.2.0 Alpha 2';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.2.0 Alpha 1';

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
	 * Step1 : VBV-15341 Unset cansearch for legacy "StaticPage" type
	 */
	public function step_1()
	{
		$assertor = vB::getDbAssertor();

		$package = $assertor->getRow('package', array('class' => 'vBCms'));
		if (empty($package['packageid']))
		{
			// this is not an upgrade from a vb4 DB with vBCms package, nothing to do here.
			return $this->skip_message();
		}

		// Mostly copy pasted from 518a6 (VBV-14770)
		$contenttypes = $assertor->getRows(
			'vBForum:contenttype',
			array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
				vB_dB_Query::CONDITIONS_KEY => array(
					array('field' => 'class',       'value' => array('StaticPage'),	    'operator' =>  vB_dB_Query::OPERATOR_EQ),
					array('field' => 'packageid',   'value' => $package['packageid'],   'operator' =>  vB_dB_Query::OPERATOR_EQ),
					array('field' => 'cansearch',   'value' => 1,                       'operator' =>  vB_dB_Query::OPERATOR_EQ),
				)
			)
		);
		if (empty($contenttypes))
		{
			// Already done. Nothing to do here.
			return $this->skip_message();
		}

		$total = count($contenttypes);
		$i = 0;
		foreach ($contenttypes AS $contenttype)
		{
			$this->show_message(sprintf($this->phrase['vbphrase']['update_table_x'], 'contenttype', ++$i, $total));
			$assertor->update('vBForum:contenttype',
				array(// update values
					'cansearch' => 0,
				),
				array(// update conditions
					'contenttypeid' => $contenttype['contenttypeid']
				)
			);
		}

		// give the cache a kick.
		vB_Types::instance()->reloadTypes();
	}
}

/*======================================================================*\
|| ####################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 101013 $
|| ####################################################################
\*======================================================================*/
