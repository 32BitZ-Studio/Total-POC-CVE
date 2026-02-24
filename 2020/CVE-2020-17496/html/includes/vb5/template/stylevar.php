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

class vB5_Template_Stylevar
{

	protected static $instance;
	protected $cache = array();
	protected $stylePreference = array();

	/**
	 *
	 * @return vB5_Template_Stylevar
	 */
	public static function instance()
	{
		if (!isset(self::$instance))
		{
			$c = __CLASS__;
			self::$instance = new $c;
		}

		return self::$instance;
	}

	protected function __construct()
	{
		$this->getStylePreference();
		$this->fetchStyleVars();
	}

	/**
	 * Returns the styleid that should be used on this request
	 */
	public function getPreferredStyleId()
	{
		return intval(reset($this->stylePreference));
	}

	/**
	 * Gets the styles to be used ordered by preference
	 */
	protected function getStylePreference()
	{
		$stylePreference = array();

		try
		{
			$router = vB5_ApplicationAbstract::instance()->getRouter();
			if (!empty($router))
			{
				$arguments = $router->getArguments();

				// #1 check for a forced style in current route
				if (!empty($arguments) AND !empty($arguments['forceStyleId']) AND intval($arguments['forceStyleId']))
				{
					$stylePreference[] = $arguments['forceStyleId'];
				}
			}
		}
		catch (vB5_Exception $e)
		{
			// the application instance might not be initialized yet, so just ignore this first check
		}

		// #2 check for a style cookie (style chooser in footer)
		// If style is set in querystring, the routing component will set this cookie (VBV-3322)
		$cookieStyleId = vB5_Cookie::get('userstyleid', vB5_Cookie::TYPE_UINT);
		if (!empty($cookieStyleId))
		{
			$stylePreference[] = $cookieStyleId;
		}

		// #3 check for user defined style
		$userStyleId = vB5_User::get('styleid');
		if (!empty($userStyleId))
		{
			$stylePreference[] = $userStyleId;
		}

		// #4 check for a route style which is not forced
		if (!empty($arguments) AND isset($arguments['routeStyleId']) AND is_int($arguments['routeStyleId']))
		{
			$stylePreference[] = $arguments['routeStyleId'];
		}

		// #5 check for the overall site default style
		$defaultStyleId = vB5_Template_Options::instance()->get('options.styleid');
		if ($defaultStyleId)
		{
			$stylePreference[] = $defaultStyleId;
		}

		if (!empty($stylePreference[0]) AND $stylePreference[0] == '-1')
		{
				$stylePreference[0] = $defaultStyleId;
		}

		$styleid = Api_InterfaceAbstract::instance()->callApi('style', 'getValidStyleFromPreference', array($stylePreference));

		//if we run into an error, let's make sure we have a valid style.
		if (!is_numeric($styleid))
		{
			$styleid = $defaultStyleId;
		}

		//we may not have a session yet -- especially if we are trying to render
		//an error that happens very early in the bootstrap.
		$session = vB::getCurrentSession();
		if($session)
		{
			$session->set('styleid', $styleid);
		}

		//we need to pass the "preference" array to some API functions.  We should probably fix that, but it's a
		//bit complicated by the fact that we still need to validate the style when we pass it in.
		//however we should chuck the styles we already rejected.
		$this->stylePreference = array($styleid);
	}

	public function get($name)
	{
		$path = explode('.', $name);

		$var = $this->cache;
		foreach ($path AS $t)
		{
			if (isset($var[$t]))
			{
				$var = $var[$t];
			}
			else
			{
				return NULL;
			}
		}

		return $var;
	}

	protected function fetchStyleVars()
	{
		// PLEASE keep this function in sync with fetch_stylevars() in functions.php
		// in terms of setting fake/pseudo stylevars

		$res = Api_InterfaceAbstract::instance()->callApi('style', 'fetchStyleVars', array($this->stylePreference)); // api method returns unserealized stylevars

		if (empty($res) OR !empty($res['errors']))
		{
			return;
		}

		$pseudo = array();
		$user = vB5_User::instance();

		$ltr = (is_null($user['lang_options']) OR !empty($user['lang_options']['direction']));
		$dirmark = !empty($user['lang_options']['dirmark']);

		if ($ltr)
		{
			// if user has a LTR language selected
			$pseudo['textdirection'] = 'ltr';
			$pseudo['left'] = 'left';
			$pseudo['right'] = 'right';
			$pseudo['pos'] = '';
			$pseudo['neg'] = '-';
		}
		else
		{
			// if user has a RTL language selected
			$pseudo['textdirection'] = 'rtl';
			$pseudo['left'] = 'right';
			$pseudo['right'] = 'left';
			$pseudo['pos'] = '-';
			$pseudo['neg'] = '';
		}

		if ($dirmark)
		{
			$pseudo['dirmark'] = ($ltr ? '&lrm;' : '&rlm;');
		}

		// get the 'lang' attribute for <html> tags
		$pseudo['languagecode'] = $user['lang_code'];

		// get the 'charset' attribute
		$pseudo['charset'] = $user['lang_charset'];

		// add 'styleid' of the current style for the sprite.php call to load the SVG icon sprite
		$pseudo['styleid'] = $this->getPreferredStyleId();

		// add 'cssdate' for the cachebreaker for the sprite.php call to load the SVG icon sprite
		$options = vB5_Template_Options::instance();
		$cssdate = intval($options->get('miscoptions.cssdate'));
		if (!$cssdate)
		{
			$cssdate = time(); // fallback so we get the latest css
		}
		$pseudo['cssdate'] = $cssdate;


		foreach ($res AS $key => $value)
		{
			$this->cache[$key] = $value;
		}

		foreach($pseudo AS $key => $value)
		{
			$this->cache[$key] = array('datatype' => 'string', 'string' => $value);
		}
	}


}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 100454 $
|| #######################################################################
\*=========================================================================*/
