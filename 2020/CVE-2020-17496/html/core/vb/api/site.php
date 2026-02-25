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

/**
 * vB_Api_Site
 *
 * @package vBApi
 * @access public
 */

class vB_Api_Site extends vB_Api
{
	protected $disableWhiteList = array('loadHeaderNavbar', 'loadFooterNavbar');

	/**
	 * Stores the header navbar data.
	 *
	 * @param	int			The storing data siteid.
	 * @param	mixed		Array of elements containing data to be stored for header navbar. Elements might contain:
	 * 			title		--	string		Site title. *required
	 * 			url			--	string		Site url. *required
	 * 			usergroups	--	array		Array of ints.
	 * 			newWindow	--	boolean		Flag used to display site in new window. *required
	 * 			subnav		--	mixed		Array of subnav sites (containing same site data structure).
	 * 				id			--	int		Id of subnav site.
	 * 				title		--	string	Title of subnav site.
	 * 				url			--	string	Url of subnav site.
	 * 				usergroups	--	array	Array of ints.
	 * 				newWindow	--	boolean	Flag used to display subnav site in new window.
	 * 				subnav		--	mixed	Array of subnav sites (containing same site data structure).
	 * @return	boolean		To indicate if save was succesfully done.
	 */
	public function saveHeaderNavbar($siteId, $data)
	{
		$this->checkHasAdminPermission('canusesitebuilder');
		return vB_Library::instance('site')->saveHeaderNavbar($siteId, $data);
	}

	/**
	 * Stores the footer navbar data.
	 *
	 * @param	int			The storing data siteid.
	 * @param	mixed		Array of data to be stored for footer navbar.
	 * 			title		--	string		Site title.
	 * 			url			--	string		Site url.
	 * 			usergroups	--	array		Array of ints.
	 * 			newWindow	--	boolean		Flag used to display site in new window.
	 * 			subnav		--	mixed		Array of subnav sites (containing same site data structure).
	 * 				id			--	int		Id of subnav site.
	 * 				title		--	string	Title of subnav site.
	 * 				url			--	string	Url of subnav site.
	 * 				usergroups	--	array	Array of ints.
	 * 				newWindow	--	boolean	Flag used to display subnav site in new window.
	 * 				subnav		--	mixed	Array of subnav sites (containing same site data structure).
	 * @return	boolean		To indicate if save was succesfully done.
	 */
	public function saveFooterNavbar($siteId, $data)
	{
		$this->checkHasAdminPermission('canusesitebuilder');
		return vB_Library::instance('site')->saveFooterNavbar($siteId, $data);
	}

	/**
	 * Gets the header navbar data
	 *
	 * @param	int		Site id requesting header data.
	 * @param	string		URL
	 * @param	int		Edit mode so allow all links if user can admin sitebuilder
	 * @param	int		Channel ID (optional, used to determine current header navbar tab)
	 *
	 * @return	mixed	Array of header navbar data (Described in save method).
	 */
	public function loadHeaderNavbar($siteId, $url = false, $edit = false, $channelId = 0)
	{
		if ($this->disabled)
		{
			return array();
		}

		return vB_Library::instance('site')->loadHeaderNavbar($siteId, $url, $edit, $channelId);
	}

	/**
	 * Gets the footer navbar data
	 *
	 * @param	int		Site id requesting footer data.
	 * @param	string		URL
	 * @param	int		Edit mode so allow all links if user can admin sitebuilder
	 *
	 * @return	mixed	Array of footer navbar data (Described in save method).
	 */
	public function loadFooterNavbar($siteId, $url = false, $edit = false)
	{
		if ($this->disabled)
		{
			return array();
		}

		return vB_Library::instance('site')->loadFooterNavbar($siteId, $url, $edit);
	}

	/**
	 * Returns an array of general statistics for the site
	 *
	 * @return	array	Statistics.
	 */
	public function getSiteStatistics()
	{
		return vB_Library::instance('site')->getSiteStatistics();
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
