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

class Api_Interface_Collapsed extends Api_InterfaceAbstract
{
	protected $initialized = false;

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

		$session = $this->createSession($request, $options);

		// Update lastvisit/lastactivity
		$info = $session->doLastVisitUpdate(
			vB5_Cookie::get('lastvisit', vB5_Cookie::TYPE_UINT),
			vB5_Cookie::get('lastactivity', vB5_Cookie::TYPE_UINT)
		);

		if (!empty($info))
		{
			// for guests we need to set some cookies
			if (isset($info['lastvisit']))
			{
				vB5_Cookie::set('lastvisit', $info['lastvisit']);
			}

			if (isset($info['lastactivity']))
			{
				vB5_Cookie::set('lastactivity', $info['lastactivity']);
			}
		}

		$this->initialized = true;
	}

	public function callApi($controller, $method, array $arguments = array(), $useNamedParams = false, $byTemplate = false)
	{
		try
		{
			$c = vB_Api::instance($controller);
		}
		catch (vB_Exception_Api $e)
		{
			throw new vB5_Exception_Api($controller, $method, $arguments, array('Failed to create API controller.'));
		}

		if ($useNamedParams)
		{
			$result = $c->callNamed($method, $arguments);
		}
		else
		{
			$result = call_user_func_array(array(&$c, $method), $arguments);
		}

		// The core error handler has been rewritten and can be used here (by default)
		// The api call sets error/exception handlers appropriate to core. We need to reset.
		// But if the API is called by template ({vb:data}), we should use the core exception handler.
		// Otherwise we will have endless loop. See VBV-1682.
		if (!$byTemplate)
		{
			set_exception_handler(array('vB5_ApplicationAbstract', 'handleException'));
		}
		return $result;

	}


	public static function callApiStatic($controller, $method, array $arguments = array())
	{
		if (is_callable('vB_Api_'  . $controller, $method))
		{
			return call_user_func_array(array('vB_Api_'  . $controller, $method), $arguments);
		}
		throw new vB5_Exception_Api($controller, $method, $arguments, 'invalid_request');
	}


	public function relay($file)
	{
		$filePath = vB5_Config::instance()->core_path . '/' . $file;
		if ($file AND file_exists($filePath))
		{
			$core = realpath(vB5_Config::instance()->core_path);
			$filePath = realpath($filePath);

			//we don't want to include anything that isn't in the core directory
			if(strpos($filePath, $core) === 0)
			{
				//hack because the admincp/modcp files won't return so the remaining processing in
				//index.php won't take place.  If we better integrate the admincp into the
				//frontend, we can (and should) remove this.
				vB_Shutdown::instance()->add(array('vB5_Frontend_ExplainQueries', 'finish'));
				try
				{
					require_once($filePath);
				}
				catch (vB_Exception_404 $e)
				{
					throw new vB5_Exception_404($e->getMessage());
				}
				return;
			}
		}

		throw new vB5_Exception_404('invalid_page_url');
	}

	/*
	 *	Play nice and handle backend communication through the api class even though noncollapsed
	 *	mode is completely dead.  These are systems that don't really belong as part of the API, but
	 *	we really don't want to implement seperately for frontend/backend use.  By indirecting through
	 *	this class we maintain our goal of keeping the front end reasonable separate (hopefully ensuring
	 *	that backend functionality stands on its own for integration/extension purposes).
	 */
	public function cacheInstance($type)
	{
		return vB_Cache::instance($type);
	}

	public function stringInstance()
	{
		return vB::getString();
	}

	public function invokeHook($hook_name, $params)
	{
		vB::getHooks()->invoke($hook_name, $params);
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 103425 $
|| #######################################################################
\*=========================================================================*/
