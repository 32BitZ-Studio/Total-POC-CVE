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

class vB_Upgrade_513a1 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '513a1';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.1.3 Alpha 1';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.1.2';

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
		if ($this->tableExists('album'))
		{
			$Types = vB_Types::instance();
			$albumType = $Types->getContentTypeID('vBForum_Album');
			$galleryType = $Types->getContentTypeID('vBForum_Gallery');
			$photoType = $Types->getContentTypeID('vBForum_Photo');

			$this->show_message(sprintf($this->phrase['version']['513a1']['setting_private_albums_from_4'], 'forum'));
			vB::getDbAssertor()->assertQuery('vBInstall:setPrivateAlbums', array('albumtype' => $albumType, 'gallerytype' => $galleryType, 'phototype' => $photoType));
		}
		else
		{
			$this->skip_message();
		}
	}

	public function step_2()
	{
		$this->run_query(
			sprintf($this->phrase['core']['altering_x_table'], 'hook', 1, 1),
			"ALTER TABLE " . TABLE_PREFIX . "hook MODIFY COLUMN hookname  varchar(100)"
		);
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
