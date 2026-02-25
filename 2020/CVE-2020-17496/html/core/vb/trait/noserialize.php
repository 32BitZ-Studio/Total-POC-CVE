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

trait vB_Trait_NoSerialize
{
	public function __sleep()
	{
		throw new Exception('Serialization not supported');
	}

	public function __wakeup()
	{
		throw new Exception('Serialization not supported');
	}

	public function __serialize()
	{
		throw new Exception('Serialization not supported');
	}

	public function __unserialize($serialized)
	{
		throw new Exception('Serialization not supported');
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 103882 $
|| #######################################################################
\*=========================================================================*/
