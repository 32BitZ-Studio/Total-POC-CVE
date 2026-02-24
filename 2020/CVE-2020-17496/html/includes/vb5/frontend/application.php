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

class vB5_Frontend_Application extends vB5_ApplicationAbstract
{
	public static function init($configFile)
	{
		parent::init($configFile);

		self::$instance = new vB5_Frontend_Application();
		self::$instance->router = new vB5_Frontend_Routing();
		self::$instance->router->setRoutes();
		$styleid = vB5_Template_Stylevar::instance()->getPreferredStyleId();

		if ($styleid)
		{
			vB::getCurrentSession()->set('styleid', $styleid);
		}

		self::$instance->convertInputArrayCharset();
		self::setHeaders();

		return self::$instance;
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
