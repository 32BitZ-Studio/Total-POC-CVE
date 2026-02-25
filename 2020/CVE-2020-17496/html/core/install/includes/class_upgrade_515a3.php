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

class vB_Upgrade_515a3 extends vB_Upgrade_Version
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/

	/**
	* The short version of the script
	*
	* @var	string
	*/
	public $SHORT_VERSION = '515a3';

	/**
	* The long version of the script
	*
	* @var	string
	*/
	public $LONG_VERSION  = '5.1.5 Alpha 3';

	/**
	* Versions that can upgrade to this script
	*
	* @var	string
	*/
	public $PREV_VERSION = '5.1.5 Alpha 2';

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
	 * Remove 'lastVisit' from the "New Topics" subnavbar search json it has not been edited.
	 * Mostly copied from 512a4 step_1
	 */
	public function step_1()
	{
		$assertor = vB::getDbAssertor();
		$this->show_message($this->phrase['version']['515a3']['updating_new_topics_url']);
		$sites = $assertor->assertQuery('vBForum:site');
		$oldUrl = 'search?searchJSON=%7B%22date%22%3A%22lastVisit%22%2C%22view%22%3A%22topic%22%2C%22unread_only%22%3A1%2C%22sort%22%3A%7B%22lastcontent%22%3A%22desc%22%7D%2C%22exclude_type%22%3A%5B%22vBForum_PrivateMessage%22%5D%7D';
		$newUrl = 'search?searchJSON=%7B%22view%22%3A%22topic%22%2C%22unread_only%22%3A1%2C%22sort%22%3A%7B%22lastcontent%22%3A%22desc%22%7D%2C%22exclude_type%22%3A%5B%22vBForum_PrivateMessage%22%5D%7D';

		foreach ($sites AS $site)
		{
			$doupdate = false;
			$header = unserialize($site['headernavbar']);
			if (!empty($header))
			{
				foreach ($header as $key => $h)
				{
					if ($h['title'] == 'navbar_home')
					{
						foreach ($h['subnav'] AS $subKey => $subnav)
						{
							if ($subnav['title'] == 'navbar_newtopics' AND !empty($subnav['url']))
							{
								//Found the correct item.  See if it has been edited.
								if ($subnav['url'] == $oldUrl)
								{
									$header[$key]['subnav'][$subKey]['url'] = $newUrl;
									$doupdate = true;
									break;
								}
								else
								{
									break;
								}
							}
						}
					}
				}
			}
			if ($doupdate)
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
