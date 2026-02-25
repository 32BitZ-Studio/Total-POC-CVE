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
* Abstract class for Constants
*
* @package	vBulletin
* @date		$Date: 2011-07-17
*/
class vB_DataManager_Constants
{
	use vB_Trait_NoSerialize;

	/*Constants=====================================================================*/

	/*
	 * ERRTYPE_
	 */
	const ERRTYPE_ARRAY     =   0;
	const ERRTYPE_STANDARD  =   1;
	const ERRTYPE_CP        =   2;
	const ERRTYPE_SILENT    =   3;
	const ERRTYPE_ARRAY_UNPROCESSED =   4;
	const ERRTYPE_UPGRADE   =   5;

	/*
	 * VF_
	 */
	const VF_TYPE           =   0;
	const VF_REQ            =   1;
	const VF_CODE           =   2;
	const VF_METHODNAME     =   3;
	const VF_METHOD         =   '_-_mEtHoD_-_';

	/*
	 * REQ_
	 */

	const REQ_NO            =   0;
	const REQ_YES           =   1;
	const REQ_AUTO          =   2;
	const REQ_INCR          =   3;
}
/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 102271 $
|| #######################################################################
\*=========================================================================*/
