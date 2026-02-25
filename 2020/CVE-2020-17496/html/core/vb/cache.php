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
 * Cache
 * Handler that caches and retrieves data.
 *
 * @tutorial
 *  // Application init
 *  $cache = vB_Cache::create('vB', 'Memcache');
 *
 *  // Read existing cache entry and lock for rebuild if it's expired
 *  $write_lock = true;
 *  if(!($data = $cache::read('hello_world', $write_lock)))
 *  {
 * 		// rebuild the cache entry
 *  	$data = 'Bonjour Tout Le Monde!';
 *
 *		if ($write_lock)
 *		{
 *			// write cache, last for 50 minutes and purge on event 'widget55.update'
 *			$cache->write('hello_world', $data, 50, "widget{$widgetid}.update");
 *		}
 *  }
 *
 *	// Use data
 * 	echo($data);
 *
 *  // Meanwhile... when widget 55 is updated, expire stale cache objects
 *  $cache->event("widget{$widgetid}.update");
 *
 * The cache handler also provides slam prevention.  Cache slams occur when a cache
 * entry expires and multiple connections attempt to rebuild it.
 * @see vB_Cache::lock()
 *
 * The code received a fairly significant rewrite in early 2013. Previously the cache information was stored in an object,
 * and there was a separate observer object which tracked events and cleared cache. The cache object is  now an array, and
 * the observer methods have all been collapsed into the cache object. This got rid of a lot of code and unnecessary processing.
 *
 *
 * @package vBulletin
 */
abstract class vB_Cache
{
	use vB_Trait_NoSerialize;

	/*Properties====================================================================*/

	/**
	 * A reference to the singleton instance
	 *
	 * @var vB_Cache
	 */
	protected static $instance = array();

	/*** array of values available from cache ***/
	protected $values_read = array();

	/*** array of values we know aren't in cache ***/
	protected $no_values = array();

	/*** meta cache lifetime meta or precache is a list of cache keys we know have been
		requested against this view or page ***/
	protected $metadata_life = 1440;

	/*** the minimum time from when we update the metacache key list to when
	* we are willing to again update it. ***/
	protected $metadata_update_min = 5;

	/*** the last metacache update time ***/
	protected $meta_info = false;

	/*** Array of keys we have used this time. This allows us to decide whether to
	* remove keys from precache list ***/
	protected $keys_used;

	protected $noCache = false;
	protected static $disableCache = false;
	/**
	 * Unique prefix for item's title, required for multiple forums on the same server using the same classes that read/write to memory
	 *
	 * @var	string
	 */
	protected $prefix = '';

	/**
	 * Cache type of current object.
	 *
	 * @var string
	 */
	protected $cachetype;

	/** The current time - this is used a lot so let's make it a member variable.
	 */
	protected $timeNow;

	/*** Flag indicated where meta cache data has been loaded ***/
	protected $meta_loaded = false;

	/* Cache types */
	const CACHE_STD   = 0;
	const CACHE_FAST  = 1;
	const CACHE_LARGE = 2;

	/*For debugging and troubleshooting only. */
	protected static $cacheLogging = false;

	protected static $actions = array(
		self::CACHE_STD => array(),
		self::CACHE_FAST => array(),
		self::CACHE_LARGE => array(),
		4 => array(),
	);

	const CACHE_LOG_WRITE = 1;
	const CACHE_LOG_READSUCCESS = 2;
	const CACHE_LOG_READFAIL = 3;
	const CACHE_LOG_HASVALUE = 4;
	const CACHE_LOG_NOVALUE = 5;
	const CACHE_LOG_CLEAR = 6;

	/*Construction==================================================================*/

	/**
	 * Constructor protected to enforce singleton use.
	 * @see instance()
	 */
	protected function __construct($cachetype)
	{
		$vb5_config =& vB::getConfig();

		if (self::$disableCache AND ($cachetype != self::CACHE_FAST))
		{
			$this->noCache = true;
		}

		if (!empty($vb5_config['Misc']['cacheLogging']))
		{
			//we need to have the cacheLog table.
			vB::getDbAssertor()->assertQuery('vBInstall:createCacheLogTable', array());
			self::$cacheLogging = true;
		}
		// we are using the same prefix as for the datastore
		$this->prefix = & $vb5_config['Datastore']['prefix'];
		$this->cachetype = $cachetype;
		//during install or in cli we don't have a session.
		try
		{
			$request = vB::getRequest();

			if (!empty($request) AND is_object($request))
			{
				$this->timeNow = $request->getTimeNow();
			}
			else
			{
				$this->timeNow = time();
			}
		}
		catch (exception $e)
		{
			$this->timeNow = time();
		}
	}

	/**
	 * Get the cache defaults.
	 */
	public static function getDefaults()
	{
		return array(
			self::CACHE_STD   => 'vB_Cache_Db',
			self::CACHE_FAST  => 'vB_Cache_Memory',
			self::CACHE_LARGE => 'vB_Cache_Db'
		);
	}

	/**
	 * Returns an instance of the global cache.
	 * The cache type used is defined in options.
	 *
	 * @return vB_Cache							- Reference to instance of the cache handler
	 */
	public static function instance($type = self::CACHE_STD)
	{
		$DEFAULTS_CACHETYPE = self::getDefaults();

		$vb5_config =& vB::getConfig();

		if (!empty($vb5_config['Misc']['debug']) AND !empty($_REQUEST['nocache']))
		{
			self::$disableCache = 1;
		}

		if (!isset(self::$instance[$type]))
		{
			if (!isset($vb5_config['Cache']) OR !isset($vb5_config['Cache']['class'])
				OR !is_array($vb5_config['Cache']['class'])
				OR !isset($vb5_config['Cache']['class'][$type]))
			{
				$cacheClass = $DEFAULTS_CACHETYPE[$type];
			}
			else
			{
				$cacheClass = $vb5_config['Cache']['class'][$type];
			}

			// if more than 1 of the 3 types (STD, FAST, LARGE) are using the same implementation,
			// don't create a new instance, just share the same one.
			foreach (array(self::CACHE_STD, self::CACHE_FAST, self::CACHE_LARGE) AS $cacheType)
			{
				if (!empty(self::$instance[$cacheType]) AND is_a(self::$instance[$cacheType], $cacheClass))
				{
				 self::$instance[$type] = self::$instance[$cacheType];
				 return self::$instance[$type];
				}
			}

			// call constructor directly.  Having static functions with the same name but different
			// semantics in the subclasses works, but its tacky.
			self::$instance[$type] = new $cacheClass($type); //call_user_func(array($cacheClass, 'instance'));
			vB_Shutdown::instance()->add(array(self::$instance[$type], 'shutdown'));
		}


		return self::$instance[$type];
	}

	/* Reset all active caches */
	public static function resetCache($expiredOnly = false)
	{
		$DEFAULTS_CACHETYPE = self::getDefaults();
		foreach(array_keys($DEFAULTS_CACHETYPE) as $cacheType)
		{
			self::instance($cacheType)->clean($expiredOnly);
		}

		if (self::$cacheLogging)
		{
			self::logCacheAction(0, self::CACHE_LOG_CLEAR);
		}
	}

	/* Reload all caches (even inactive ones) and reset them */
	public static function resetAllCache($expiredOnly = false)
	{
		self::$instance = array();
		$DEFAULTS_CACHETYPE = self::getDefaults();

		foreach(array_keys($DEFAULTS_CACHETYPE) as $cacheType)
		{
			self::instance($cacheType)->clean($expiredOnly);
		}
	}

	/*Cache=========================================================================*/

	/**
	 * Writes data as a cache object.
	 *
	 * A string key is required to uniquely identify a cache object.  Client
	 * code should add all information that would affect the individualisation of
	 * the cache object to the key.
	 *
	 * If lifetime_mins is supplied the cache object will be purged the next time it
	 * is read after the TTL has passed.
	 *
	 * If a cache object should be purged on triggered events then events should be
	 * supplied as an array of string id's of the form 'scope.event', for example
	 * 'widget55.updated' may be used to purge a cache of a defined widget with the
	 * id 55 when it is reconfigured.
	 *
	 *
	 * @param string $key						- Identifying key
	 * @param mixed $data						- Data to cache
	 * @param int $lifetime						- Lifetime of cache, in minutes
	 * @param array string $events				- Purge events to associate with the cache object
	 * @return string | bool						- Cache id or false
	 */
	public function write($key, $data, $lifetime_mins = false, $events = false)
	{
		// Check if caching is disabled, usually for debugging
		if ($this->noCache)
		{
			return false;
		}

		// If data is empty then there's nothing to write
		if (!$data)
		{
			$data == 0;
		}

		if (!is_array($events))
		{
			$events = array($events);
		}

		$cache = array(
			'key' => $key,
			'data' => $data,
			'events' => $events,
			'created' => $this->timeNow,
		);

		if ($lifetime_mins == 0)
		{
			$cache['expires'] = 0;
		}
		else
		{
			$cache['expires'] = $this->timeNow + (60 * $lifetime_mins);
		}


		// Write the cache object
		$this->writeCache($cache);

		// Unlock the cache entry
		$this->unlock($key);

		$this->values_read[$key] = $cache;
		unset($this->no_values[$key]);

		if (self::$cacheLogging)
		{
			self::logCacheAction($key, self::CACHE_LOG_WRITE, $this->cachetype, $this->getSize($cache));
		}
		return $key;
	}

	/**
	 * Writes the cache data to storage.
	 *
	 * @param array	includes key, data, expires
	 */
	abstract protected function writeCache( $cache);


	/**
	 * Based on the assumption that if we go back to a page we're likely to request
	 * a lot of the information we requested last time we were on that page, let's
	 * store the cached information.
	 */
	public function saveCacheInfo($cacheid)
	{
		//If the minimum time hasn't passed, then don't update
		if ($this->meta_info['last_update'] AND
			((($this->timeNow - $this->meta_info['last_update'])/60) < $this->metadata_update_min))
		{
			return true;
		}

		$changecount = 0;
		//If we don't have a method to retrieve the data, don't bother.
		if (method_exists($this, 'readCacheArray'))
		{
			//Let's dump cache keys that aren't being used.
			if (isset($this->meta_info['cacheids']))
			{
				foreach($this->meta_info['cacheids'] AS $cachekey => $last_used)
				{
					if (array_key_exists($cachekey, $this->keys_used))
					{
						$this->meta_info['cacheids'][$cachekey] = $this->timeNow;
					}
					else
					{
						$age = $this->timeNow - $last_used;

						if (($age/60) > $this->metadata_life)
						{
							unset($this->meta_info['cacheids'][$cachekey]);
							$changecount++;
						}
					}
				}
			}
			else
			{
				$this->meta_info['cacheids'] = array();
			}

			//Now see if we have new keys
			foreach ($this->keys_used as $key => $data)
			{
				if ( ! array_key_exists($key, $this->meta_info['cacheids']))
				{
					$changecount++;
					$this->meta_info['cacheids'][$key] = $this->timeNow;
				}
			}
			$info = array(
				'cacheids' => $this->meta_info['cacheids'],
				'last_update' => $this->timeNow
			);

			$this->write($cacheid, $info, $this->metadata_life);
			return true;
		}
		return false;
	}

	/**
	 * If we used saveCacheInfo to save data,
	 * this will get it back.
	 */
	public function restoreCacheInfo($cacheid)
	{
		//Only do this once.
		if ($this->meta_loaded)
		{
			return true;
		}

		$this->meta_loaded = true;
		//We need a method to retrieve the data.
		$this->meta_info = $this->read($cacheid);

		if ($this->meta_info AND isset($this->meta_info['cacheids']))
		{
			$keys = array_keys($this->meta_info['cacheids']);
			$this->readCacheArray($keys);
			return true;
		}
		return false;
	}

	/** has a value been loaded for this key?
	 *
	 * @param	string	the key
	 *
	 * @return 	bool
	 **/
	public function isLoaded($key)
	{
		return isset($this->values_read[$key]);
	}

	/**
	 * Reads a cache object and returns the data.
	 *
	 * Integrity checking should be performed by the client code, ensuring
	 * that the returned data is in the expected form.
	 *
	 * $key should be a string key with all of the identifying information
	 * for the required cache objects.  This must match the $key used to write
	 * the cache object.
	 *
	 * The implicit lock can be set to true to indicate that the client code will
	 * rebuild the cache on an expired read.  This allows cache handlers to lock the
	 * cache for the current connection.  Normally, if a cache entry is locked then
	 * subsequent reads should return the expired cache data until it is unlocked.
	 * This cannot be done for cache entries that don't yet exist, but can be used
	 * on existing entries to prevent cache slams - where multiple connections
	 * decide to rebuild the cache under a race condition.
	 *
	 * Cache handlers should ensure to implement an expiration on cache locks.
	 *
	 * @see cache::Write()
	 *
	 * @param mixed $key							- Identifying key. String or array of strings
	 * @param bool $write_lock						- Whether a failed read implies a lock for writing
	 * @return mixed								- The cached data (string or array of strings) or boolean false
	 */
	public function readSingle($key, &$write_lock = false, $save_meta = false)
	{
		$this->keys_used[$key] = 1;

		// Check if caching is disabled, usually for debugging
		if ($this->noCache)
		{
			return false;
		}

		if (isset($this->values_read[$key]))
		{

			if (self::$cacheLogging)
			{
				self::logCacheAction($key, self::CACHE_LOG_HASVALUE, $this->cachetype, $this->getSize($this->values_read[$key]));
			}
			return $this->values_read[$key]['data'];
		}
		else if (isset($this->no_values[$key]))
		{

			if (self::$cacheLogging)
			{
				self::logCacheAction($key, self::CACHE_LOG_NOVALUE, $this->cachetype);

			}
			return false;
		}

		$cache = $this->readCache($key);
		$this->values_read[$key] = $cache;

		if (self::$cacheLogging)
		{
			if ($cache === false)
			{
				self::logCacheAction($key, self::CACHE_LOG_READFAIL, $this->cachetype);
			}
			else
			{
				self::logCacheAction($key, self::CACHE_LOG_READSUCCESS, $this->cachetype, $this->getSize($cache));
			}
		}
		return $cache['data'];
	}

	/**
	 * Reads the cache object from storage.
	 *
	 * @param string $key						- Identifying key
	 * @return array	includes key, data, expires
	 */
	abstract protected function readCache($key);

	/**
	 * Purges a cache object.
	 *
	 * @param int $cache_id						- Id of the cache entry to purge
	 */
	public function purge($cacheid)
	{
		unset($this->values_read[$cacheid]);
		$this->purgeCache($cacheid);

		if (self::$cacheLogging)
		{
			self::logCacheAction($cacheid, self::CACHE_LOG_CLEAR, $this->cachetype);
		}
	}


	/**
	 * Removes a cache object from storage.
	 *
	 * @param int $cache_id						- Id of the cache entry to purge
	 */
	abstract protected function purgeCache($cache_id);


	/**
	 * Expires a cache object.
	 * This is preferred to purging a cache entry as it ensures that that the cache
	 * data can still be served while new cache data is being rebuilt.
	 *
	 * @param int/array $cache_ids						- Id of the cache entry to expire
	 */
	public function expire($cache_ids)
	{
		$this->expireCache($cache_ids);

		if (!is_array($cache_ids))
		{
			$cache_ids = array($cache_ids);
		}
		foreach ($cache_ids AS $cacheId)
		{
			unset($this->values_read[$cacheId]);
			$this->no_values[$cacheId] = $cacheId;
		}

		if (self::$cacheLogging)
		{
			foreach ($cache_ids AS $cacheid)
			{
				self::logCacheAction($cacheid, self::CACHE_LOG_CLEAR, $this->cachetype);
			}
		}
	}


	/**
	 * Sets a cache entry as expired in storage.
	 *
	 * @param int $cache_id						- Id of the cache entry to expire
	 * @return bool
	 */
	abstract protected function expireCache($cache_id);

	/**
	 * Expires cache objects based on a triggered event.
	 *
	 * @param string | array $event				- The name of the event
	 */
	abstract public function event($events);

	public static function allCacheEvent($events)
	{
		$DEFAULTS_CACHETYPE = self::getDefaults();
		foreach(array_keys($DEFAULTS_CACHETYPE) AS $cacheType)
		{
			self::instance($cacheType)->event($events);
		}
	}

	/**
	 * Locks a cache entry.
	 * This is done to prevent a cache slam where concurrent connections attempt to
	 * rebuild an expired cache entry.  While a cache entry is locked, it should be
	 * considered valid and served to all connections except the one that has the
	 * lock.  After the cache entry has been rebuilt it will be unlocked, allowing
	 * all new connections to consume the fresh entry.
	 *
	 * @param mixed		array of string $key						- Identifying key
	 * @return bool - TRUE iff the lock was obtained
	 */
	public function lock($keys){}//Only dB actually implements this.


	/**
	 * Unlocks a cache entry.
	 * Most implementations may unlock the cache during write, making this
	 * redundant.
	 *
	 * @param mixed		array of string $key						- Identifying key
	 */
	public function unlock($keys){}


/*Clean=========================================================================*/

	/**
	 * Cleans cache.
	 * $created_before should be a unix timestamp.
	 *
	 * @todo Provide more options
	 *
	 * @param bool $only_expired				- Only clean expired entries
	 */
	abstract public function clean($only_expired = true);

	/*Shutdown======================================================================*\

	/**
	 * Perform any finalisation on shutdown.
	 */
	public function shutdown()
	{
		if (self::$cacheLogging)
		{
			self::logCacheActivity();
		}
	}

	/**
	 * Tells the cache to trigger all events.
	 */
	public function cleanNow()
	{
		$this->values_read = array();
		$this->no_values = array();
		$this->meta_loaded = false;
		$this->meta_info = false;
	}

	/**
	 * Reads an array of cache objects from storage.
	 *
	 * @param 	string $keys						- Ids of the cache entry to read
	 * @param	bool	whether to lock the values
	 * @param	bool	whether to save this cache id and preload the value for the page next time.
	 *
	 * @return 	array of array	includes key, data, expires
	 */
	public function read($keys, $writeLock = false, $save_meta = false)
	{
		// Check if caching is disabled, usually for debugging
		if ($this->noCache)
		{
			return false;
		}

		$found = array();
		$notFound = array();

		if (!is_array($keys))
		{
			$keys = array($keys);
			$returnArray = false;
		}
		else
		{
			$returnArray = true;
		}

		foreach($keys AS $key)
		{
			if ($save_meta)
			{
				$this->keys_used[$key] = 1;
			}

			if (isset($this->values_read[$key]))
			{
				$found[$key] = $this->values_read[$key]['data'];

				if (self::$cacheLogging)
				{
					self::logCacheAction($key, self::CACHE_LOG_HASVALUE, $this->cachetype, $this->getSize($this->values_read[$key]['data']));
				}
			}
			else if (isset($this->no_values[$key]))
			{
				$found[$key] = false;

				if (self::$cacheLogging)
				{
					self::logCacheAction($key, self::CACHE_LOG_NOVALUE, $this->cachetype);
				}
			}
			else
			{
				if (method_exists($this, 'readCacheArray'))
				{
					$notFound[] = $key;
				}
				else
				{
					$cached = $this->readCache($key);

					if ($cached !== false)
					{
						$found[$key] = $cached['data'];
						$this->values_read[$key] = $cached;

						if (self::$cacheLogging)
						{
							self::logCacheAction($key, self::CACHE_LOG_READSUCCESS, $this->cachetype, $this->getSize($cached));
						}
					}
					else
					{
						$this->no_values[$key] = $key;
						$found[$key] = false;

						if (self::$cacheLogging)
						{
							self::logCacheAction($key, self::CACHE_LOG_READFAIL, $this->cachetype);
						}
					}
				}
			}
		}

		if (!empty($notFound))
		{
			$cached = $this->readCacheArray($notFound, $writeLock);

			foreach($notFound AS $key)
			{
				if (isset($cached[$key]) AND is_array($cached[$key]) AND isset($cached[$key]['data']))
				{
					$found[$key] = $cached[$key]['data'];
					$this->values_read[$key] = $cached[$key];

					if (self::$cacheLogging)
					{
						self::logCacheAction($key, self::CACHE_LOG_READSUCCESS, $this->cachetype, $this->getSize($cached[$key]['data']));
					}
				}
				else
				{
					$found[$key] = false;
					$this->no_values[$key] = $key;

					if (self::$cacheLogging)
					{
						self::logCacheAction($key, self::CACHE_LOG_READFAIL, $this->cachetype);
					}
				}
			}
		}

		//If the request was for one cacheid, we return the record
		if (!$returnArray)
		{
			return array_pop($found);
		}

		//If the request was for an array of id's, we return an array of cache results
		return $found;

	}

	/**
	 * This updates the time. It is useful only for testing.  Otherwise it does nothing
	 *
	 * 	@param	integer		timestamp- optional
	 */
	public function updateTime($time = false)
	{
		if(defined('VB_UNITTEST'))
		{
			if ($time)
			{
				$this->timeNow = $time;
			}
			else
			{
				$this->timeNow = time();
			}
		}
	}

	/**
	 * If cache logging is enabled this stores the page cache activity to be loggged.
	 *
	 */
	protected static function logCacheAction($cacheid, $action, $type = 4, $size = 0)
	{
		static $random;

		if (!isset($random))
		{
			$random = rand();
		}

		if (!isset(self::$actions[$type][$cacheid]))
		{
			self::$actions[$type][$cacheid] = array(
				'cacheid' => $cacheid,
				'randomkey' => $random,
				'type' => $type,
				'writes' =>0 ,
				'misses' => 0,
				'hits' => 0 ,
				'rereads' => 0,
				'remiss' => 0,
				'clears' => 0,
				'time' => vB::getRequest()->getTimeNow(),
				'size' => $size,
				'stacktrace' => '',
			);
		}

		// store the most recent stack trace
		self::$actions[$type][$cacheid]['stacktrace'] = vB_Utilities::getStackTrace();

		switch ($action)
		{
			case self::CACHE_LOG_WRITE :
				self::$actions[$type][$cacheid]['writes'] = 1;
				self::$actions[$type][$cacheid]['size'] = $size;
				break;
			case self::CACHE_LOG_READSUCCESS:
				self::$actions[$type][$cacheid]['hits']++;
				break;
			case self::CACHE_LOG_READFAIL :
				self::$actions[$type][$cacheid]['misses']++;
				break;
			case self::CACHE_LOG_HASVALUE :
				self::$actions[$type][$cacheid]['rereads']++;
				break;
			case self::CACHE_LOG_NOVALUE :
				self::$actions[$type][$cacheid]['remiss']++;
				break;
			case self::CACHE_LOG_CLEAR :
				self::$actions[$type][$cacheid]['clears']++;
				break;
		}

	}

	/**
	 * If cache logging is enabled this function writes the activity for this page to the database.
	 *
	 **/
	protected function logCacheActivity()
	{
		/**randomkey float , cacheid varbinary(64), cacheType SMALLINT, time INT(10),
		 writes SMALLINT, hits SMALLINT, misses SMALLINT, rereads SMALLINT,
		 remiss SMALLINT, clears SMALLINT)**/
		$assertor = vB::getDbAssertor();
		foreach (self::$actions as $type => $actions)
		{
			if (!empty($actions))
			{
				$assertor->assertQuery('vBInstall:cachelog', array(
					vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_MULTIPLEINSERT,
					vB_dB_Query::FIELDS_KEY => array(
						'cacheid',
						'randomkey',
						'cachetype',
						'writes',
						'misses',
						'hits',
						'rereads',
						'remiss',
						'clears',
						'time',
						'size',
						'stacktrace',
					),
					vB_dB_Query::VALUES_KEY => $actions,
				));
			}
		}
		self::$actions = array(
			self::CACHE_STD => array(),
			self::CACHE_FAST => array(),
			self::CACHE_LARGE => array(),
			4 => array(),
		);
	}

	protected function getSize($data)
	{
		if (is_string($data))
		{
			//this is exact
			return strlen($data);
		}
		//This is approximate only
		return strlen(json_encode($data));
	}


}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 102436 $
|| #######################################################################
\*=========================================================================*/
