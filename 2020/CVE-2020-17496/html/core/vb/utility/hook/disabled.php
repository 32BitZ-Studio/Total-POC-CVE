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

/**
 *	@package vBUtility
 */

/**
 *	Dummy class for "hookless mode" avoids having to check the
 *	config within the live hook class.  Should implement the
 *	same public interface as the live class, but do absolutely
 *	nothing.
 *
 *	@package vBUtility
 */
class vB_Utility_Hook_Disabled
{
	use vB_Utility_Trait_NoSerialize;

	public function __construct() {}

	public function invoke($hook_name, $params) {}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
