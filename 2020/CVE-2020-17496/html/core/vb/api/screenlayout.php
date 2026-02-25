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
 * vB_Api_ScreenLayout
 *
 * @package vBApi
 * @access public
 */
class vB_Api_ScreenLayout extends vB_Api
{
	/*
	 * Cache for screen layouts
	 */
	var $cache = null;

	protected function __construct()
	{
		parent::__construct();
	}

	/**
	 * Returns a list of all "selectable" screen layouts. Currently excludes the "bare full" layout, which is used specifically
	 * for the PM Chat window.
	 *
	 * @param	bool	Force reload
	 * @return	array
	 */
	public function fetchScreenLayoutList($skipcache = false)
	{
		if (!is_array($this->cache) OR $skipcache)
		{
			$db = vB::getDbAssertor();
			// VBV-16218 - exclude the bare-full layout from SB, as once set it cannot be undone (since sitebuilder header is not available on this layout) reasonably.
			$screenLayouts = $db->getRows(
				'screenlayout',
				array(
					vB_dB_Query::CONDITIONS_KEY => array(
						array('field' => 'guid', 'value' => 'vbulletin-screenlayout-bare-full-57433eecd10803.93763070', vB_dB_Query::OPERATOR_KEY => vB_dB_Query::OPERATOR_NE)
					)
				),
				array('displayorder', 'title'));

			if ($screenLayouts)
			{
				$this->cache = $screenLayouts;
			}
			else
			{
				$this->cache = array();
			}
		}

		return $this->cache;
	}

}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
