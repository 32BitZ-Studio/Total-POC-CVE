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
 * vB_Cache_Memory
 *
 * @package vBForum
 * @access public
 */

class vB_Cache_Memory extends vB_Cache
{
	/**
	 * This is a page-level cache handler. The contents are used for one page load only
	 */
	protected $events = array();

	protected $cache = array();

	protected static $instance;

	/**
	 * Constructor public to allow for separate automated unit testing. Actual code should use
	 * vB_Cache::instance();
	 * @see vB_Cache::instance()
	 */
	public function __construct($cachetype)
	{
		parent::__construct($cachetype);
		$this->cachetype = $cachetype;
	}

	/**
	 * Returns singleton instance of self.
	 *
	 * @return vB_Cache_Memory		- Reference to singleton instance of the cache handler
	 */
	public static function instance($type = self::CACHE_STD)
	{
		if (!isset(self::$instance))
		{
			$class = __CLASS__;
			self::$instance = new $class($type);
		}

		return self::$instance;
	}

	/**
	 * Writes the cache data to storage.
	 * @param array	includes key, data, expires
	 */
	protected function writeCache($cache)
	{
		$data = $cache['data'];
		$cacheKey = $cache['key'];
		$events = $cache['events'];

		if (empty($events))
		{
			$events = array();
		}
		else if (!is_array($events))
		{
			$events = array($events);
		}

		if (!empty($this->values_read[$cacheKey]['events']))
		{
			$oldevents = $this->values_read[$cacheKey]['events'];
			if(!is_array($oldevents))
			{
				$oldevents = array($oldevents);
			}

			foreach ($oldevents AS $eventKey)
			{
				unset($this->events[$eventKey][$cacheKey]);

				if (empty($this->events[$eventKey]))
				{
					unset($this->events[$eventKey]);
				}
			}
		}

		//we don't write to the values_read here -- that's handled by the parent class
		//(any thing we'd do here would get get overwritten).

		if (!empty($events))
		{
			$this->addEvents($cacheKey, $events);
		}
	}


	public function addEvents($key, $events)
	{
		if (!is_array($events))
		{
			$events = array($events);
		}

		foreach ($events AS $event)
		{
			if (empty($this->events[$event]))
			{
				$this->events[$event] = array();
			}
			$this->events[$event][$key] = $key;
		}
	}


	public function removeEvents($event)
	{
		if (isset($this->events[$event]))
		{
			unset($this->events[$event]);
		}
	}

	/**
	 * Reads the cache object from storage.
	 *
	 * @param string $key						- Id of the cache entry to read
	 *
	 * @return array	includes key, data, expires
	 */
	protected function readCache($key)
	{
		if (!isset($this->values_read[$key]))
		{
			return false;
		}

		$cache = $this->values_read[$key];

		if (($cache === false) OR
			( ($cache['expires'] > 0) AND ($this->timeNow > $cache['expires'])))
		{
			return 0;
		}
		return $cache['data'];
	}


	/**
	 * This unsets a variable in the cache
	 *
	 * @param mixed	a cache event key or array of keys
	 */
	public function event($events)
	{

		if (!is_array($events))
		{
			$events = array($events);
		}

		foreach ($events AS $event)
		{
			if (empty($event) OR !is_string($event))
			{
				throw new vB_Exception_Cache('invalid_data');
			}

			if (array_key_exists($event, $this->events))
			{
				$cacheKeys = $this->events[$event];
				foreach($cacheKeys AS $cacheKey)
				{
					$this->purgeCache($cacheKey);
				}
				unset($this->events[$event]);
			}
		}
	}


	/**
	 * Sets a cache entry as expired in storage. But sine we don't store, that means do nothing
	 *
	 * @param string $key						- Key of the cache entry to expire
	 */
	protected function expireCache($key){}

	/**
	 * Locks a cache entry.
	 *
	 * @param string $key						- Key of the cache entry to lock
	 * @return bool - TRUE iff the lock was obtained
	 */
	public function lock($key)
	{
		return true; //not needed
	}

	protected function getLoadedValue($key)
	{
		return $this->readCache($key);
	}

	/**
	 * Removes a cache object from storage.
	 *
	 * @param int $key							- Key of the cache entry to purge
	 * @return bool								- Whether anything was purged
	 */
	protected function purgeCache($cacheKey)
	{
		if (empty($cacheKey) OR !is_string($cacheKey))
		{
			return false;
		}

		if (isset($this->values_read[$cacheKey]))
		{
			unset($this->values_read[$cacheKey]);
			return true;
		}

		return false;
	}

	/**
	 * Cleans cache.
	 *
	 * @param bool $only_expired				- Only clean expired entries
	 */
	public function clean($only_expired = true)
	{
		//when something is expired we delete immediately
		if ($only_expired)
		{
			foreach($this->values_read as $cacheKey => $cacheRecord)
			{
				if (!empty($cacheRecord['expires']) AND ($cacheRecord['expires'] > $this->timeNow))
				{
					$this->purgeCache($cacheKey);
				}
			}

			if (self::$cacheLogging)
			{
				$this->logCacheAction(0, self::CACHE_LOG_CLEAR, $this->cachetype);
			}
		}
		else
		{
			$this->values_read = array();
			$this->events = array();
		}
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 102436 $
|| #######################################################################
\*=========================================================================*/
