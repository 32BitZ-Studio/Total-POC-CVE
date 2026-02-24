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

class Api_Interface_Light extends Api_Interface_Collapsed
{
	/**
	 * This enables a light session. The main issue is that we skip last activity, and shutdown queries.
	 */
	public function init()
	{
		if ($this->initialized)
		{
			return true;
		}

		//initialize core
		$config = vB5_Config::instance();

		//if this is AJAX, let's avoid showing warnings (notices etc)
		//nothing good will come of it.
		if (
			!$config->report_all_ajax_errors AND
			isset($_SERVER['HTTP_X_REQUESTED_WITH']) AND
			$_SERVER['HTTP_X_REQUESTED_WITH'] == 'XMLHttpRequest'
		)
		{
			vB::silentWarnings();
		}

		$request = new vB_Request_WebApi();
		vB::setRequest($request);

		//We normally don't allow the use of the backend classes in the front end, but the
		//rules are relaxed inside the api class and especially in the bootstrap dance of getting
		//things set up.  Right now getting at the options in the front end is nasty, but I don't
		//want the backend dealing with cookies if I can help it (among other things it makes
		//it nasty to handle callers of the backend that don't have cookies).  But we need
		//so information to determine what the cookie name is.  This is the least bad way
		//of handling things.
		$options = vB::getDatastore()->getValue('options');
		vB5_Cookie::loadConfig($options);

		// When we reach here, there's no user information loaded. What we can do is trying to load language from cookies.
		// Shouldn't use vB5_User::getLanguageId() as it will try to load userinfo from session
		$languageid = vB5_Cookie::get('languageid', vB5_Cookie::TYPE_UINT);
		if ($languageid)
		{
			$request->setLanguageid($languageid);
		}

		$this->createSession($request, $options);

		vB::skipShutdown(true);
		$this->initialized = true;
	}

}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
