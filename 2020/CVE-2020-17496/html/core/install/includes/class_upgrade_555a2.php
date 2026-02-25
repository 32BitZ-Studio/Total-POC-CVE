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

class vB_Upgrade_555a2 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '555a2';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.5.5 Alpha 2';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.5.5 Alpha 1';

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


	public function step_1()
	{
		$this->alter_field(
			sprintf($this->phrase['core']['altering_x_table'], 'contentpriority', 1, 1),
			'contentpriority',
			'prioritylevel',
			'double',
			array(
				'length' => '2,1',
			)
		);
	}

	public function step_2()
	{
		$this->show_message($this->phrase['version']['555a2']['remove_product_custom_phrases']);

		/*
			Delete invalid "custom" (languageid = 0) phrases that were added for fresh installs with
			language packs due to step_3() importing the product translation XMLs before step_13() could
			import the product XMLs (that contain the master phrases).

			While it's hypothetically possible that non-vbulletin products might've been affected, I'm
			trying to limit the scope of change to the ones we definitively saw on the affected cloud
			installs.
		 */
		$products = vB_Products::DEFAULT_VBULLETIN_PRODUCTS;
		if (!empty($products))
		{
			$assertor = vB::getDbAssertor();
			$assertor->delete('phrase', array('languageid' => 0, 'product' => $products));
		}
	}
}

/*======================================================================*\
|| ####################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 102724 $
|| ####################################################################
\*======================================================================*/
