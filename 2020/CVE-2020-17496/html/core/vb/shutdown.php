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
* Class to handle shutdown
*
* @package	vBulletin
* @version	$Revision: 99787 $
* @author	vBulletin Development Team
* @date		$Date: 2018-10-24 17:13:06 -0700 (Wed, 24 Oct 2018) $
*/
class vB_Shutdown
{
	use vB_Trait_NoSerialize;

	/**
	 * A reference to the singleton instance
	 *
	 * @var vB_Cache_Observer
	 */
	protected static $instance;

	/**
	 * An array of shutdown callbacks to call on shutdown
	 */
	protected $callbacks;

	protected $called = false;
	/**
	 * Constructor protected to enforce singleton use.
	 * @see instance()
	 */
	protected function __construct(){}

	/**
	 * Returns singleton instance of self.
	 *
	 * @return vB_Shutdown
	 */
	public static function instance()
	{
		if (!isset(self::$instance))
		{
			$class = __CLASS__;
			self::$instance = new $class();
		}

		return self::$instance;
	}

	/**
	* Add callback to be executed at shutdown
	*
	* @param array $callback					- Call back to call on shutdown
	*/
	public function add($callback)
	{
		if (!isset($this->callbacks) OR !is_array($this->callbacks))
		{
			$this->callbacks = array();
		}

		$this->callbacks[] = $callback;
	}

	// only called when an object is destroyed, so $this is appropriate
	public function shutdown()
	{
		if ($this->called)
		{
			return; // Already called once.
		}

		$session = vB::getCurrentSession();
		if (is_object($session))
		{
			$session->save();
		}

		if (!empty($this->callbacks))
		{
			foreach ($this->callbacks AS $callback)
			{
				call_user_func($callback);
			}

			unset($this->callbacks);
		}

		$this->setCalled();
	}

	public function __wakeup()
	{
		unset($this->callbacks);
	}

	public function setCalled()
	{
		$this->called = true;
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
