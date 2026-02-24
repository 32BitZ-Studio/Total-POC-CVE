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

/*
if (!isset($GLOBALS['vbulletin']->db))
{
	exit;
}
*/

class vB_Upgrade_502b1 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '502b1';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.0.2 Beta 1';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.0.2 Alpha 2';

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

	/**
	 * Step 1 - Add Google Checkout
	 */
	public function step_1()
	{
		if (!vB::getDbAssertor()->getRow('vBForum:paymentapi', array('classname' => 'google')))
		{
			vB::getDbAssertor()->insert('vBForum:paymentapi', array(
				'title'     => 'Google',
				'currency'  => 'usd,gbp',
				'recurring' => 0,
				'classname' => 'google',
				'active'    => 0,
				'settings'  => serialize(array(
					'google_merchant_id' => array(
						'type'               => 'text',
						'value'              => '',
						'validate'           => 'string'
				),
					'google_merchant_key' => array(
						'type'     => 'text',
						'value'    => '',
						'validate' => 'string'
				),
					'sandbox' => array(
						'type' => 'yesno',
						'value' => 0,
						'validate' => 'boolean'
				))),
				'subsettings' => serialize(array(
					'show' => array(
						'type' => 'yesno',
						'value' => 1,
						'validate' => 'boolean'
					),
					'tax' => array(
						'type' => 'yesno',
						'value' => 0,
						'validate' => 'boolean'
					),
					'message' => array(
						'type'     => 'text',
						'value'    => '',
						'validate' => 'string'
				)))
			));
			$this->show_message(sprintf($this->phrase['vbphrase']['update_table_x'], 'paymentapi', 1, 1));
		}
		else
		{
			$this->skip_message();
		}
	}

	/**
	* Remove any volatile phrases
	*/
	function step_2()
	{
		$assertor = vB::getDbAssertor();
		$assertor->delete('vBForum:faq', array('volatile' => 1));

		//if any non-volatile faq names have been left orphaned by the delete, promote them to top level.  This will
		//likely require the admin to do some cleanup, but it means his articles won't randomly disappear.  Any structure
		//between nonvolatile articles will be preserved.
		$faq = $assertor->getColumn('vBForum:faq', 'faqname');
		if (count($faq))
		{
			$assertor->update('vBForum:faq', array('faqparent' => 'faqroot'),
				array(array('field' => 'faqparent', 'value' => $faq, 'operator' => vB_dB_Query::OPERATOR_NE))
			);
		}
		$this->show_message($this->phrase['version']['502b1']['removing_faq_entries']);
	}

	function step_3()
	{
		$db =& $this->db;
		require_once(DIR . '/install/mysql-schema.php');

		// insert the updated FAQ Structure
		$this->run_query (
			$this->phrase['version']['502b1']['updating_faq_entries'],
			$schema['INSERT']['query']['faq']
		);
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
