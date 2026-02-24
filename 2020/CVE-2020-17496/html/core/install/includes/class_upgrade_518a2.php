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

class vB_Upgrade_518a2 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '518a2';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.1.8 Alpha 2';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.1.8 Alpha 1';

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
		$this->show_message(sprintf($this->phrase['vbphrase']['update_table_x'], 'package', 1, 1));
		$db = vB::getDbAssertor();
		$package = $db->getRow('package', array('class' => 'vBBlog'));
		if (!$package)
		{
			//we need this for the legacy but there is no longer a blog product.
			$result = $db->insert('package', array(
				'productid' => 'vbulletin',
				'class' => 'vBBlog'
			));
		}
		else
		{
			if ($package['productid'] != 'vbulletin')
			{
				$db->update('package', array('productid' => 'vbulletin'), array('packageid' => $package['packageid']));
			}
		}
	}

	public function step_2()
	{
		$this->show_message(sprintf($this->phrase['vbphrase']['update_table_x'], 'contenttype', 1, 2));

		//legacy type information for the mobile API
		$db = vB::getDbAssertor();
		$contenttype = $db->getRow('vBForum:contenttype', array('class' => 'BlogEntry'));
		if(!$contenttype)
		{

			//we should have verified that this exits in step1
			$package = $db->getRow('package', array('class' => 'vBBlog'));

			$db->insert('vBForum:contenttype', array(
				'class' => 'BlogEntry',
				'packageid' => $package['packageid'],
				'canplace' => '0',
				'cansearch' => '0',
				'cantag' => '0',
				'canattach' => '1',
				'isaggregator' => '0'
			));
		}
	}


	public function step_3()
	{
		$this->show_message(sprintf($this->phrase['vbphrase']['update_table_x'], 'contenttype', 2, 2));

		//legacy type information for the mobile API
		$db = vB::getDbAssertor();
		$contenttype = $db->getRow('vBForum:contenttype', array('class' => 'BlogComment'));
		if(!$contenttype)
		{
			//we should have verified that this exits in step1
			$package = $db->getRow('package', array('class' => 'vBBlog'));

			$db->insert('vBForum:contenttype', array(
				'class' => 'BlogComment',
				'packageid' => $package['packageid'],
				'canplace' => '0',
				'cansearch' => '0',
				'cantag' => '0',
				'canattach' => '1',
				'isaggregator' => '0'
			));
		}
	}
}

/*======================================================================*\
|| ####################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 101013 $
|| ####################################################################
\*======================================================================*/
