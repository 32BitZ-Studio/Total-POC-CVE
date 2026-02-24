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

class vB_Upgrade_512a4 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '512a4';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.1.2 Alpha 4';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.1.2 Alpha 3';

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
	 * Correct the subnav bar to use the new search json if it has not been edited.
	 */
	public function step_1()
	{
		$assertor = vB::getDbAssertor();
		$this->show_message($this->phrase['version']['512a4']['updating_todays_post_url']);
		$sites = $assertor->assertQuery('vBForum:site');
		foreach ($sites AS $site)
		{
			$changed = false;
			$header = unserialize($site['headernavbar']);
			if (!empty($header))
			{
				foreach ($header as $key => $h)
				{
					if ($h['title'] == 'navbar_home')
					{
						foreach ($h['subnav'] AS $subKey => $subnav)
						{
							if ($subnav['title'] == 'navbar_todays_posts' AND !empty($subnav['url']))
							{
								//Found the correct item.  See if it has been edited.
								if ($subnav['url'] == 'search?searchJSON=%7B%22date%22%3A%7B%22from%22%3A%22lastDay%22%7D%2C%22view%22%3A%22topic%22%2C%22sort%22%3A%7B%22lastcontent%22%3A%22desc%22%7D%2C%22exclude_type%22%3A%5B%22vBForum_PrivateMessage%22%5D%7D')
								{
									$header[$key]['subnav'][$subKey]['url'] = 'search?searchJSON=%7B%22last%22%3A%7B%22from%22%3A%22lastDay%22%7D%2C%22view%22%3A%22topic%22%2C%22starter_only%22%3A+1%2C%22sort%22%3A%7B%22lastcontent%22%3A%22desc%22%7D%2C%22exclude_type%22%3A%5B%22vBForum_PrivateMessage%22%5D%7D';
									$changed = true;
									break;
								}
								else
								{
									return;
								}
							}
						}
					}
				}
			}
			if ($changed)
			{
				$assertor->update('vBForum:site', array('headernavbar' => serialize($header)), array('siteid' => $site['siteid']));
			}
		}
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
