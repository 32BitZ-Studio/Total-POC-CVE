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
 * vB_Api_Wrapper
 * This class is just a wrapper for API classes so that exceptions can be handled
 * and translated for the client.
 *
 * @package vBApi
 * @access public
 */
class vB_Api_Wrapper
{
	use vB_Trait_NoSerialize;

	protected $controller;
	protected $api;

	public function __construct($controller, $api)
	{
		$this->controller = $controller;
		$this->api = $api;
	}

	/**
	 * This method prevents catchable fatal errors when calling the API with missing arguments
	 * @param string $method
	 * @param array $arguments
	 */
	protected function validateCall($controller, $method, $arguments)
	{
		if (get_class($controller) == 'vB_Api_Null')
		{
			//No such Class in the core controllers but it may be defined in an extension
			return 0;
		}

		if (method_exists($controller, $method))
		{
			$reflection = new ReflectionMethod($controller, $method);
		}
		else
		{
			// No such Method in the core controller but it may be defined in an extension
			return 0;
		}

		if ($reflection->isStatic())
		{
			return 2;
		}

		if ($reflection->isConstructor())
		{
			return 3;
		}

		if ($reflection->isDestructor())
		{
			return 4;
		}

		$index = 0;
		foreach($reflection->getParameters() AS $param)
		{
			if (!isset($arguments[$index]))
			{
				if (!$param->allowsNull() AND !$param->isDefaultValueAvailable())
				{
					// cannot omit parameter
					throw new vB_Exception_Api('invalid_data_w_x_y_z', array('null', $param->getName(), get_class($controller), $method));
				}
			}
			else if ($param->isArray() AND !is_array($arguments[$index]))
			{
				// array type was expected
				throw new vB_Exception_Api('invalid_data');
			}

			$index++;
		}

		return 1;
	}


	/**
	 * Call the given api function by name with a named arguments list.
	 * Used primarily to translate REST requests into API calls.
	 *
	 * @param string $method -- the name of the method to call
	 * @param array $args -- The list of args to call.  This is a name => value map that will
	 *   be matched up to the names of the API method.  Order is not important.  The names are
	 *   case sensitive.
	 *
	 * @return The return of the method or an error if the method doesn't exist, or is
	 *   static, a constructor or destructor, or otherwise shouldn't be callable as
	 *   and API method.  It is also an error if the value of a paramater is not provided
	 *   and that parameter doesn't have a default value.
	 */
	//Without this method calls to callNamed get picked up by __call and transfered
	//vB_Api::callNamed without properly being processed for the actual Api method.
	//Among other things this skips the processing that handles the Api extensions.
	public function callNamed()
	{
		$function_args = func_get_args();
		list ($method, $args) = $function_args;

		if (!is_callable(array($this->api, $method)))
		{
			// if the method does not exist, an extension might define it
			// before we'd do something in __call and then pass to the API
			// callNamed function (which will just return);
			// with this function we never get there.  This preserves this
			// behavior.
			return $this->__call('callNamed', $function_args);
		}

		$reflection = new ReflectionMethod($this->api, $method);

		if (
			$reflection->isConstructor() OR
			$reflection->isDestructor() OR
			$reflection->isStatic() OR
			$method == "callNamed"
		)
		{
			//todo return error message
			return;
		}

		$php_args = array();
		foreach($reflection->getParameters() as $param)
		{
			// the param value can be null, so don't use isset
			if (array_key_exists($param->getName(), $args))
			{
				$php_args[] = &$args[$param->getName()];
			}
			else
			{
				if ($param->isDefaultValueAvailable())
				{
					$php_args[] = $param->getDefaultValue();
				}
				else
				{
					throw new Exception('Required argument missing: ' . htmlspecialchars($param->getName()));
				}
			}
		}

		return call_user_func_array(array($this, $method), $php_args);
	}

	public function __call($method, $arguments)
	{
		try
		{
			// check if API method is enabled
			//
			// Skip state check for the 'getRoute' and 'checkBeforeView' api calls, because
			// this state check uses the route info from getRoute and calls checkBeforeView  to
			// determine state. See VBV-11808 and the vB5_ApplicationAbstract::checkState calls
			// in vB5_Frontend_Routing::setRoutes.
			//
			// app light & controllers need to call checkCSRF before they make "real" api calls.
			//
			// callNamed should only be processed here when called from the implementation in this class
			// (done to allow extensions to nonexistant functions).  We should probably remove this from the
			// list of skipped items because if it *is* called through here then nothing will
			// do any state validation -- which would be bad.  Especially if something somehow slipped
			// through to an actual API function.
			//
			if (!in_array($method, array('callNamed', 'getRoute', 'checkBeforeView'))
					AND !($this->controller === 'state' AND $method === 'checkCSRF')
			)
			{
				if (!$this->api->checkApiState($method))
				{
					return false;
				}
			}

			$result = null;
			$type = $this->validateCall($this->api, $method, $arguments);

			if ($type)
			{
				if (is_callable(array($this->api, $method)))
				{
					$call = call_user_func_array(array(&$this->api, $method), $arguments);

					if ($call !== null)
					{
						$result = $call;
					}
				}
			}

			$elist = vB_Api_Extensions::getExtensions($this->controller);
			if ($elist)
			{
				foreach($elist AS $class)
				{
					if (is_callable(array($class, $method)))
					{
						$args = $arguments;
						array_unshift($args, $result);
						$call = call_user_func_array(array($class, $method), $args);

						if ($call !== null)
						{
							$result = $call;
						}
					}
				}
			}
		}
		catch (vB_Exception_Api $e)
		{
			$errors = $e->get_errors();
			$config = vB::getConfig();
			if (!empty($config['Misc']['debug']))
			{
				$trace = '## ' . $e->getFile() . '(' . $e->getLine() . ") Exception Thrown \n" . $e->getTraceAsString();
				$errors[] = array("exception_trace", $trace);
			}
			$result = array('errors' => $errors);

			try
			{
				//allow the caller to react to various errors differently based on
				//the user -- primarily guest vs logged in but might as well pass the id
				//in case the caller wants to get creative.
				$result['userid'] = vB::getCurrentSession()->get('userid');
			}
			//if we fail here, then stuff really isn't working and we should just log the error we have.
			catch(Exception $e){}
			catch (Error $e) {}
		}
		catch (vB_Exception_Database $e)
		{
			$config = vB::getConfig();
			if (!empty($config['Misc']['debug']) OR vB::getUserContext()->hasAdminPermission('cancontrolpanel'))
			{
				$errors = array('Error ' . $e->getMessage());
				$trace = '## ' . $e->getFile() . '(' . $e->getLine() . ") Exception Thrown \n" . $e->getTraceAsString();
				$errors[] = array("exception_trace", $trace);
				$result =  array('errors' => $errors);
			}
			else
			{
				// This text is purposely hard-coded since we don't have
				// access to the database to get a phrase
				$result = array('errors' => array(array('There has been a database error, and the current page cannot be displayed. Site staff have been notified.')));
			}
		}
		catch (Error $e)
		{
			$errors = array(array('unexpected_error', $e->getMessage()));
			$config = vB::getConfig();
			if (!empty($config['Misc']['debug']))
			{
				$trace = '## ' . $e->getFile() . '(' . $e->getLine() . ") Exception Thrown \n" . $e->getTraceAsString();
				$errors[] = array("exception_trace", $trace);
			}
			$result = array('errors' => $errors);
		}
		catch (Exception $e)
		{
			$errors = array(array('unexpected_error', $e->getMessage()));
			$config = vB::getConfig();
			if (!empty($config['Misc']['debug']))
			{
				$trace = '## ' . $e->getFile() . '(' . $e->getLine() . ") Exception Thrown \n" . $e->getTraceAsString();
				$errors[] = array("exception_trace", $trace);
			}
			$result = array('errors' => $errors);
		}

		//some array returns, unfortunately, don't follow the API conventions.  If we have a scalar
		//or the array looks like a list rather than a key=>value map then decline to add warnings to it.
		//unfortunately this isn't sufficient.  To many return values are assumed to be lists of
		//'name' => 'value' instead of fixed named fields.  The 'warnings' field gets interpreted as
		//just another item rather than being ingnored as its should be.  We'll revisit this when
		//we've normalized the API
		/*
		if (is_array($result) AND !isset($result[0]))
		{
			foreach(vB::getLoggedWarnings() AS $warning)
			{
				$result['warnings'][] = array('php_error_x', $warning);
			}
		}
		 */

		return $result;
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 102814 $
|| #######################################################################
\*=========================================================================*/
