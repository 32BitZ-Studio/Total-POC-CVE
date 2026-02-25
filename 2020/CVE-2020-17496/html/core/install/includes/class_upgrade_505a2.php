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

class vB_Upgrade_505a2 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '505a2';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION = '5.0.5 Alpha 2';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.0.5 Alpha 1';

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
	public $VERSION_COMPAT_ENDS = '';

	/**
	 * populating tagnode table based on tagcontent table
	 */
	public function step_1()
	{
		if ($this->tableExists('tagcontent'))
		{
			$log = vB::getDbAssertor()->getRow('vBInstall:upgradelog', array('script' => $this->SHORT_VERSION, 'step' => 1)); // Must match this step.

			if (empty($log))
			{
				$this->show_message($this->phrase['version']['505a2']['importing_tags']);
				vB::getDbAssertor()->assertQuery('vBInstall:importTagContent');
				$this->show_message(sprintf($this->phrase['core']['import_done']));
			}
			else
			{
				$this->skip_message();
			}
		}
		else
		{
			$this->skip_message();
		}
	}

	/**
	 * populating the taglist field in the node table
	 */
	public function step_2()
	{
		$log = vB::getDbAssertor()->getRow('vBInstall:upgradelog', array('script' => $this->SHORT_VERSION, 'step' => 2)); // Must match this step.

		if (empty($log))
		{
			$this->show_message($this->phrase['version']['505a2']['updating_node_tags']);
			vB::getDbAssertor()->assertQuery('vBInstall:updateNodeTags');
			$this->show_message(sprintf($this->phrase['core']['process_done']));
		}
		else
		{
			$this->skip_message();
		}
	}


	/**
	 * Change old page meta phrases from GLOBAL group to pagemeta group
	 */
	public function step_3()
	{
		$this->show_message($this->phrase['version']['505a2']['moving_page_metadata_phrases']);
		vB::getDbAssertor()->assertQuery('vbinstall:movePageMetadataPhrases');
		$this->show_message('done');

		// We don't need to rebuild language as it will be rebuilt in final upgrades
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
