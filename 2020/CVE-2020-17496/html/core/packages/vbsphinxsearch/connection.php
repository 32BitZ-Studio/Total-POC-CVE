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

/*
 *	Sphinx uses the mysql libraries to connect to the sphinx daemon.
 *	The initial implementation piggybacked on the existing mysql classes
 *	which worked after a fashion, but starts causing problems because while
 *	the mysql libraries work, sphinx doesn't accept the same commands
 *	as mysql does so if we attempt to query mysql as part of the intialization
 *	or otherwise assume that we are connected to a mysql backend it can
 *	break sphinx.  We really need a seperate class to handle sphinx.
 *
 *	However, at this point we need to be risk adverse so we'll compromise.
 *	We'll create the class, but extend the existing class and override
 *	the bits that are currently failing.  This should not be considered
 *	a long term solution.  The goal is to remove the "extends" below,
 *	not to make this part of a real class hierarchy.
 */
class vBSphinxSearch_Connection extends vB_Database_MySQLi
{
	protected function set_charset($charset, $link)
	{
		//do nothing.  We don't set the charset for sphinx and the implementation
		//for mysql simply doesn't work (fatal error).
	}
}
/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 101013 $
|| #######################################################################
\*=========================================================================*/
