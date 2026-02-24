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

class vB_Upgrade_510a6 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '510a6';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.1.0 Alpha 6';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.1.0 Alpha 5';

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
	/**Set the moderatepublish flag for article channel */
	public function step_1()
	{
		// we should only run this once.  If completed this will show as step = 0 because it's the last.
		$check = vB::getDbAssertor()->assertQuery('vBInstall:upgradelog', array('script' => '510a6'));

		if ($check->valid())
		{
			$this->skip_message();
		}
		else
		{
			$this->show_message(sprintf($this->phrase['version']['510a6']['updating_article_options']));
			$parsedRaw = vB_Xml_Import::parseFile(DIR . '/includes/xml/bitfield_vbulletin.xml');
			foreach ($parsedRaw['bitfielddefs']['group'] AS $group)
			{
				if ($group['name'] == 'misc')
				{
					foreach($group['group'] AS $bfgroup)
					{
						if (($bfgroup['name'] == 'forumoptions'))
						{
							$optBits = array();
							foreach ($bfgroup['bitfield'] AS $bitfield)
							{
								if ($bitfield['name'] == 'moderatepublish')
								{
									$modPublish = $bitfield['value'];
									break;
								}
							}
						}
					}
				}
			}
			$articleChannel = vB_Library::instance('content_channel')->fetchChannelByGUID(vB_Channel::DEFAULT_ARTICLE_PARENT);
			vB::getDbAssertor()->assertQuery('vBInstall:updateChannelOptions', array('nodeids' => $articleChannel['nodeid'], 'setOption' => $modPublish));
		}
	}

}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
