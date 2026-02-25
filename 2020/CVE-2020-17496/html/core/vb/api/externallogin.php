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
 * vB_Api_ExternalLogin
 *
 * depends on vB_Utility_Random
 *
 * @package vBApi
 * @access public
 */
class vB_Api_ExternalLogin extends vB_Api
{
	use vB_Trait_NoSerialize;


	protected $disableWhiteList = array(
		'getState',
		'showExternalLoginButton',
	);
	protected $disableFalseReturnOnly = array(
	);

	protected $library;

	/**
	 * Constructor
	 */
	protected function __construct()
	{
		parent::__construct();
		$this->library = vB_Library::instance('externallogin');
	}

	/*
	 * Custom packages should override this.
	 * Returns an array of three values, "enabled", "register_enabled", & "external_userid",
	 * where "enabled" means the library is enabled in the settings & has all individual
	 * settings required to function (e.g. api key & api secret),
	 * where "register_enabled" means the library supports auto-connection during new user
	 * registration, and has all the individual settings required to function,
	 * and where "external_userid" is not an empty string ("") iff the user has an existing
	 * link between their current vBulletin account and the external account
	 *
	 * @return array('enabled' => boolean, 'register_enabled' => boolean, 'external_userid' => str)
	 */
	public function getState()
	{
		return array(
			"enabled" => false,
			"register_enabled" => false,
			"external_userid" => '',
		);
	}

	/*
	 * Checks if third party login buttons should be shown on the login iframe.
	 * Custom packages can extend this, or implement hookShowExternalLoginButton() in their
	 * hooks. See hooks documentation for more details on the hook.
	 * If extending or overriding, it should at least return 'show' set to true to show the
	 * third party login buttons in the  login iframe.
	 *
	 * @return array('show' => boolean, 'buttons' => array)
	 */
	final public function showExternalLoginButton()
	{
		$options = vB::getDatastore()->getValue('options');
		$doShow = (bool)$options['facebookactive'];
		$buttons = array(
			'facebook' => (bool)$options['facebookactive'],
		);

		vB::getHooks()->invoke('hookShowExternalLoginButton', array(
			'buttons' => &$buttons,
		));

		$doShow = false;
		foreach ($buttons AS $__show)
		{
			if ($__show)
			{
				$doShow = true;
				break;
			}
		}

		return array(
			'show' => $doShow,
			'buttons' => $buttons,
		);
	}

	/*
	 * Check if the "Third-party Login Providers" block should be shown on the registration form.
	 * Custom packages can extend this, or implement hookShowExternalRegistrationBlock() in their
	 * hooks. See hooks documentation for more details on the hook.
	 * If extending or overriding, it should at least return 'show' set to true to show the
	 * third party login buttons in the  login iframe.
	 *
	 * @return array('show' => boolean, 'blocks' => array)
	 */
	final public function showExternalRegistrationBlock()
	{
		$options = vB::getDatastore()->getValue('options');
		/*
			Based on old check in the widget_register template, which did not check for
			facebookautoregister option, just facebookactive.
		 */
		$doShow = (bool)$options['facebookactive'];
		$blocks = array(
			'facebook' => (bool)$options['facebookactive'],
		);

		vB::getHooks()->invoke('hookShowExternalRegistrationBlock', array(
			'blocks' => &$blocks,
		));

		$doShow = false;
		foreach ($blocks AS $__show)
		{
			if ($__show)
			{
				$doShow = true;
				break;
			}
		}

		return array(
			'show' => $doShow,
			'blocks' => $blocks,
		);
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 101013 $
|| #######################################################################
\*=========================================================================*/
