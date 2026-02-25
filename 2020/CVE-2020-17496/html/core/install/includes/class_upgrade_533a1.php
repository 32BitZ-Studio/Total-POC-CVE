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

class vB_Upgrade_533a1 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '533a1';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.3.3 Alpha 1';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.3.2';

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
		$this->add_index(
			sprintf($this->phrase['core']['create_index_x_on_y'], 'infractednodeid', TABLE_PREFIX . 'infraction'),
			'infraction',
			'infractednodeid',
			array('infractednodeid')
		);
	}

	public function step_2()
	{
		$this->show_message(sprintf($this->phrase['core']['altering_x_table'], 'infraction', 1, 1));

		$db = vB::getDbAssertor();
		$db->assertQuery('vBInstall:updateOrphanInfractions');
	}

	public function step_3()
	{
		$this->show_message(sprintf($this->phrase['core']['altering_x_table'], 'channel', 1, 1));

		$db = vB::getDbAssertor();

		$nodeids = $db->getColumn('vBForum:channel', 'nodeid', array('guid' => array('vbulletin-4ecbdf567f3341.44451100', 'vbulletin-4ecbdf567f3a38.99555308')));

		if ($nodeids)
		{
			$db->update('vBForum:node', array('protected' => 1), array('nodeid' => $nodeids));
		}

		$this->long_next_step();
	}

	public function step_4()
	{
		$this->add_index(
			sprintf($this->phrase['core']['create_index_x_on_y'], 'showpublished', TABLE_PREFIX . 'node'),
			'node',
			'showpublished',
			array('showpublished')
		);
	}

	/*
	 * Prep for step_6: Need to import the settings XML in case this install doesn't have the new option yet.
	 */
	public function step_5()
	{
		$this->show_message(sprintf($this->phrase['vbphrase']['importing_file'], 'vbulletin-settings.xml'));

		vB_Library::clearCache();
		vB_Upgrade::createAdminSession();
		require_once(DIR . "/install/includes/class_upgrade_final.php");
		$finalUpgrader = new vB_Upgrade_final($this->registry, $this->phrase,$this->maxversion);
		$finalUpgrader->step_1();
	}

	// If using imagick, check ghostscript & enable or disable imagick_pdf_thumbnail option.
	public function step_6()
	{
		vB_Upgrade::createAdminSession();
		$options = vB::getDatastore()->getValue('options');
		if ($options['imagetype'] == 'Magick')
		{
			if (isset($options['imagick_pdf_thumbnail']))
			{
				$this->show_message($this->phrase['version']['533a1']['checking_ghostscript']);
				$pdfSupported = vB_Image::instance()->canThumbnailPdf();
				$this->set_option('imagick_pdf_thumbnail', 'imagesettings', $pdfSupported);
				if (!$pdfSupported)
				{
					$this->add_adminmessage(
						'after_upgrade_imagick_pdf_disabled',
						array(
							'dismissible' => 1,
							'execurl'     => 'options.php?do=options&dogroup=imagesettings',
							'method'      => 'get',
							'status'      => 'undone',
						)
					);
				}
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


}

/*======================================================================*\
|| ####################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 101013 $
|| ####################################################################
\*======================================================================*/
