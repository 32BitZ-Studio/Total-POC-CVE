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
* General frontend bootstrapping class. As this is designed to be as backwards
* compatible as possible, there are loads of global variables. Beware!
*
* @package	vBulletin
*/
class vB_Bootstrap
{
	/**
	* A particular style ID to force. If specified, it will be used even if disabled.
	*
	* @var	int
	*/
	protected $force_styleid = 0;

	/**
	* Determines the called actions
	*
	* @var	array
	*/
	protected $called = array(
		'style'    => false,
		'template' => false
	);

	/**
	* A list of datastore entries to cache.
	*
	* @var	array
	*/
	public $datastore_entries = array();

	/**
	* A list of templates (names) that should be cached. Does not include
	* globally cached templates.
	*
	* @var	array
	*/
	public $cache_templates = array();

	// ============ MAIN BOOTSTRAPPING FUNCTIONS ===============

	/**
	* General bootstrap wrapper. This can be used to do virtually all of the
	* work that you'd usually want to do at the beginning. Style and template
	* setup are deferred until first usage.
	*/
	public function bootstrap()
	{
		global $VB_API_REQUESTS;

		$this->init();

		$this->load_language();
		$this->load_permissions();

		$this->read_input_context();

		if (!defined('NOCHECKSTATE') AND (!VB_API OR $VB_API_REQUESTS['api_m'] != 'api_init'))
		{
			$this->check_state();
		}
	}

	/**
	* Basic initialization of things like DB, session, etc.
	*/
	public function init()
	{
		global $vbulletin, $db, $show;

		$specialtemplates = $this->datastore_entries;

		$cwd = getcwd();

		if(is_link($cwd))
		{
			$cwd = dirname($_SERVER["SCRIPT_FILENAME"]);
		}
		else if (empty($cwd))
		{
			$cwd = '.';
		}

		define('CWD', $cwd);

		if (!defined('VB_API'))
		{
			define('VB_API', false);
		}

		require_once(CWD . '/includes/init.php');

		// Legacy Hook 'global_bootstrap_init_start' Removed //

		if (!defined('VB_ENTRY'))
		{
			define('VB_ENTRY', 1);
		}

		// Set Display of Ads to true - Set to false on non content pages
		if (!defined('CONTENT_PAGE'))
		{
			define('CONTENT_PAGE', true);
		}

		// Legacy Hook 'global_bootstrap_init_complete' Removed //
	}

	/**
	* Reads some context based on general input information
	*/
	public function read_input_context()
	{
		global $vbulletin;

		$vbulletin->input->clean_array_gpc('r', array(
			'referrerid' => vB_Cleaner::TYPE_UINT,
			'a'          => vB_Cleaner::TYPE_STR,
			'nojs'       => vB_Cleaner::TYPE_BOOL
		));

		$vbulletin->input->clean_array_gpc('p', array(
			'ajax' => vB_Cleaner::TYPE_BOOL,
		));

	}

	/**
	* Loads permissions for the currently logged-in user.
	*/
	public function load_permissions()
	{
		global $vbulletin;
		cache_permissions($vbulletin->userinfo);
	}

	/**
	* Loads the language information for the logged-in user.
	*/
	public function load_language()
	{
		global $vbulletin;

		fetch_options_overrides($vbulletin->userinfo);
		fetch_time_data();

		global $vbphrase;
		// Load language if we're not in the API or the API asks for it
		if (!VB_API OR (defined('VB_API_LOADLANG') AND VB_API_LOADLANG === true))
		{
			$vbphrase = init_language();

			// If in API, disable "Directional Markup Fix" from language options. API doesn't need it.
			if (VB_API AND !empty($vbulletin->userinfo['lang_options']))
			{
				if (is_numeric($vbulletin->userinfo['lang_options']))
				{
					$vbulletin->userinfo['lang_options'] -= $vbulletin->bf_misc_languageoptions['dirmark'];
				}
				else if (is_array($vbulletin->userinfo['lang_options']) AND isset($vbulletin->userinfo['lang_options']['dirmark']))
				{
					unset($vbulletin->userinfo['lang_options']['dirmark']);
				}
			}
		}
		else
		{
			$vbphrase = array();
		}

		// set a default username
		if ($vbulletin->userinfo['username'] == '')
		{
			$vbulletin->userinfo['username'] = $vbphrase['unregistered'];
		}
	}

	/**
	* Loads style information (selected style and style vars)
	*/
	public function load_style()
	{
		if ($this->called('style'))
		{
			return;
		}
		$this->called['style'] = true;

		global $style;
		$style = $this->fetch_style_record($this->force_styleid);
		define('STYLEID', $style['styleid']);

		global $vbulletin;
		$vbulletin->stylevars = unserialize($style['newstylevars']);
		fetch_stylevars($style, $vbulletin->userinfo);
	}

	/**
	* Checks the state of the request to make sure that it's valid and that
	* we have the necessary permissions to continue. Checks things like
	* CSRF and banning.
	*/
	public function check_state()
	{
		global $vbulletin, $show, $VB_API_REQUESTS;

		if (defined('CSRF_ERROR'))
		{
			exit;
		}

		// #############################################################################
		// check to see if server is too busy. this is checked at the end of session.php
		if (
			$this->server_overloaded() AND
			!($vbulletin->userinfo['permissions']['adminpermissions'] & $vbulletin->bf_ugp_adminpermissions['cancontrolpanel']) AND
			THIS_SCRIPT != 'login'
		)
		{
			exit;
		}

		// #############################################################################
		// check that board is active - if not admin, then display error
		if (
			!defined('BYPASS_FORUM_DISABLED') AND
			!$vbulletin->options['bbactive'] AND
			!in_array(THIS_SCRIPT, array('login', 'css'))	AND
			!($vbulletin->userinfo['permissions']['adminpermissions'] & $vbulletin->bf_ugp_adminpermissions['cancontrolpanel'])
		)
		{
			exit;
		}

		// #############################################################################
		// password expiry system
		if ($vbulletin->userinfo['userid'] AND $vbulletin->userinfo['permissions']['passwordexpires'])
		{
			$passworddaysold = floor((TIMENOW - $vbulletin->userinfo['passworddate']) / 86400);

			if ($passworddaysold >= $vbulletin->userinfo['permissions']['passwordexpires'])
			{
				if (THIS_SCRIPT == 'login')
				{
					$show['passwordexpired'] = true;
				}
				else
				{
					exit;
				}
			}
		}
		else
		{
			$show['passwordexpired'] = false;
		}
	}

	// ============ HELPER FUNCTIONS ===============

	/**
	* Determines whether a particular step of the bootstrapping has been called.
	*
	* @param	string	Name of the step
	*
	* @return	bool	True if called
	*/
	public function called($step)
	{
		return !empty($this->called[$step]);
	}

	/**
	* Determines the style that should be used either by parameter or permissions
	* and then fetches that information
	*
	* @param	integer	A style ID to force (ignoring permissions). 0 to not force any.
	*
	* @return	array	Array of style information
	*/
	protected function fetch_style_record($force_styleid = 0)
	{
		global $vbulletin;

		$userselect = (defined('THIS_SCRIPT') AND THIS_SCRIPT == 'css') ? true : false;

		// is style in the forum/thread set?
		if ($force_styleid)
		{
			// style specified by forum
			$styleid = $force_styleid;
			$vbulletin->userinfo['styleid'] = $styleid;
			$userselect = true;
		}
		else if ($vbulletin->userinfo['styleid'] > 0 AND ($vbulletin->options['allowchangestyles'] == 1 OR ($vbulletin->userinfo['permissions']['adminpermissions'] & $vbulletin->bf_ugp_adminpermissions['cancontrolpanel'])))
		{
			// style specified in user profile
			$styleid = $vbulletin->userinfo['styleid'];
		}
		else
		{
			// no style specified - use default
			$styleid = $vbulletin->options['styleid'];
			$vbulletin->userinfo['styleid'] = $styleid;
		}

		// #############################################################################
		// if user can control panel, allow selection of any style (for testing purposes)
		// otherwise only allow styles that are user-selectable
		$styleid = intval($styleid);
		$style = NULL;

		// Legacy Hook 'style_fetch' Removed //

		if (!is_array($style))
		{
			//call library to allow use of the same cache of styles we'll use elsewhere
			//no API call to get style record (may not be a good idea) so we call the
			//library directly.  This is not any more invasive than the direct
			//query we replaced.
			$styleLib = vB_Library::instance('style');
			$style = $styleLib->fetchStyleRecord($styleid, true);
		}
		return $style;
	}

	/**
	* Resolves the required templates for a particular action.
	*
	* @param	string	The action chosen
	* @param	array	Array of action-specific templates (for empty action, key 'none')
	* @param	array	List of global templates (always needed)
	*
	* @return	array	Array of required templates
	*/
	public static function fetch_required_template_list($action, $action_templates, $global_templates = array())
	{
		$action = (empty($action) ? 'none' : $action);

		if (!is_array($global_templates))
		{
			$global_templates = array();
		}

		if (!empty($action_templates["$action"]) AND is_array($action_templates["$action"]))
		{
			$global_templates = array_merge($global_templates, $action_templates["$action"]);
		}

		return $global_templates;
	}

	/**
	* Builds the collapse array based on a string representing collapse sections.
	*
	* @param	string	List of collapsed sections
	*
	* @return	array	Array with 3 values set for each collapsed section
	*/
	public static function build_vbcollapse($collapse_string)
	{
		$vbcollapse = array();
		if (!empty($collapse_string))
		{
			$val = preg_split('#\n#', $collapse_string, -1, PREG_SPLIT_NO_EMPTY);
			foreach ($val AS $key)
			{
				$vbcollapse["collapseobj_$key"] = 'display:none;';
				$vbcollapse["collapseimg_$key"] = '_collapsed';
				$vbcollapse["collapsecel_$key"] = '_collapsed';
			}
			unset($val);
		}

		return $vbcollapse;
	}

	/**
	* Determines if the server is over the defined load limits
	*
	* @return	bool
	*/
	protected function server_overloaded()
	{
		global $vbulletin;

		if (strtoupper(substr(PHP_OS, 0, 3)) != 'WIN' AND $vbulletin->options['loadlimit'] > 0)
		{
			if (!is_array($vbulletin->loadcache) OR $vbulletin->loadcache['lastcheck'] < (TIMENOW - $vbulletin->options['recheckfrequency']))
			{
				update_loadavg();
			}

			if ($vbulletin->loadcache['loadavg'] > $vbulletin->options['loadlimit'])
			{
				return true;
			}
		}

		return false;
	}

	public function force_styleid($styleid)
	{
		$this->force_styleid = $styleid;
	}
}

/**
* Bootstrapping for forum-specific actions.
*
* @package	vBulletin
*/
class vB_Bootstrap_Forum extends vB_Bootstrap
{
	public function read_input_context()
	{
		global $vbulletin;

		parent::read_input_context();

		//just in case something still relies on these being imported
		//at this point
		$vbulletin->input->clean_array_gpc('r', array(
			'postid'     => vB_Cleaner::TYPE_UINT,
			'threadid'   => vB_Cleaner::TYPE_UINT,
			'forumid'    => vB_Cleaner::TYPE_INT,
			'pollid'     => vB_Cleaner::TYPE_UINT,
		));
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 103536 $
|| #######################################################################
\*=========================================================================*/
