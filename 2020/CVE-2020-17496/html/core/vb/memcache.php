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
 *  @package vBulletin
 */

/**
 * This implements an object wrapper for Memcache
 * @package vBulletin
 */
class vB_Memcache
{
	use vB_Trait_NoSerialize;

	/**
	 * A reference to the singleton instance
	 *
	 * @var vB_Memcached
	 */
	protected static $instance;

	/**
	 * Contains the config variables loaded from the config file
	 * @var array
	 */
	protected $config = null;

	/**
	* The Memcache object (can be either Memcache or Memcached)
	*/
	protected $memcached = null;

	protected $defaultExpiration;

	/**
	* To verify a connection is still active
	*
	* @var	boolean
	*/
	protected $memcached_connected = false;

	protected function __construct()
	{
		$this->memcached = new Memcache();
	}

	public static function instance()
	{
		if (!isset(self::$instance))
		{
			if (class_exists('Memcached', FALSE))
			{
				$class = 'vB_Memcached';
			}
			else if (class_exists('Memcache', FALSE))
			{
				$class = __CLASS__;
			}
			else
			{
				throw new Exception('Memcached is not installed');
			}

			self::$instance = new $class();
			self::$instance->config = vB::getConfig();
		}

		return self::$instance;
	}

	public function setConfig(&$config)
	{
		$this->config = & $config;
	}

	protected function addServers()
	{
		if (is_array($this->config['Misc']['memcacheserver']))
		{
			if (method_exists($this->memcached, 'addServer'))
			{
				$connected = false;
				foreach (array_keys($this->config['Misc']['memcacheserver']) AS $key)
				{
					$res = $this->memcached->addServer(
						$this->config['Misc']['memcacheserver'][$key],
						$this->config['Misc']['memcacheport'][$key],
						$this->config['Misc']['memcachepersistent'][$key],
						$this->config['Misc']['memcacheweight'][$key],
						$this->config['Misc']['memcachetimeout'][$key],
						$this->config['Misc']['memcacheretry_interval'][$key]
					);

					if ($res === true)
					{
						$connected = true;
					}
				}

				if (!$connected)
				{
					return 3;
				}
			}
			else if (!$this->memcached->connect($this->config['Misc']['memcacheserver'][1], $this->config['Misc']['memcacheport'][1], $this->config['Misc']['memcachetimeout'][1]))
			{
				return 3;
			}
		}
		else if (!$this->memcached->connect($this->config['Misc']['memcacheserver'], $this->config['Misc']['memcacheport']))
		{
			return 3;
		}

		return 1;
	}

	/**
	* Connect Wrapper for Memcache
	*
	* @return	integer	When a new connection is made 1 is returned, 2 if a connection already existed, 3 if problems on adding server
	*/
	public function connect()
	{
		if (!$this->memcached_connected)
		{
			if (($res = $this->addServers()) !== 3)
			{
				$this->memcached_connected = true;
			}

			return $res;
		}
		return 2;
	}

	/**
	 * Add an item under a new key
	 *
	 * @param string $key
	 * @param mixed $value
	 * @param $data = self::$memcached->get('key1');
	 * @return bool
	 */
	public function add($key, $value, $expiration = NULL)
	{
		if (!$this->memcached_connected)
		{
			return false;
		}

		if ($expiration === NULL)
		{
			$expiration = $this->defaultExpiration;
		}

		return $this->memcached->add($key, $value, MEMCACHE_COMPRESSED, $expiration);
	}

	/**
	 * Store an item
	 *
	 * @param string $key
	 * @param mixed $value
	 * @param $expiration
	 * @return bool
	 */
	public function set($key, $value, $expiration = NULL)
	{
		if (!$this->memcached_connected)
		{
			return false;
		}

		if ($expiration === NULL)
		{
			$expiration = $this->defaultExpiration;
		}

		return $this->memcached->set($key, $value, MEMCACHE_COMPRESSED, $expiration);
	}

	/**
	 * Retrieve an item
	 *
	 * @param mixed string or array of strings
	 * @return mixed
	 */
	public function get($keys)
	{
		if (!$this->memcached_connected)
		{
			return false;
		}
		return $this->memcached->get($keys);
	}

	/**
	 * Delete an item
	 *
	 * @param string $key
	 * @return bool
	 */
	public function delete($key)
	{
		if (!$this->memcached_connected)
		{
			return false;
		}

		if (empty($key))
		{
			return true;
		}

		// Despite being deprecated, the second paramater is still required by some implementations of memcache
		return $this->memcached->delete($key,0);
	}

	/**
	 * Invalidate all items in the cache
	 *
	 * @return bool
	 */
	public function flush()
	{
		if (!$this->memcached_connected)
		{
			return false;
		}

		return $this->memcached->flush();
	}

	/**
	 * Close any memcache open connections
	 *
	 * @return	Bool	Whether closing connection was success or failure.
	 */
	public function close()
	{
		if (!$this->memcached_connected)
		{
			return false;
		}

		$this->memcached_connected = false;
		return $this->memcached->close();
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99973 $
|| #######################################################################
\*=========================================================================*/
