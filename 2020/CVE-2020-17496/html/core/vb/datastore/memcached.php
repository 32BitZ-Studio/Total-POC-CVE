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
* Class for fetching and initializing the vBulletin datastore from a Memcache Server
*
* @package	vBulletin
* @version	$Revision: 99787 $
* @date		$Date: 2018-10-24 17:13:06 -0700 (Wed, 24 Oct 2018) $
*/
class vB_Datastore_Memcached extends vB_Datastore
{
	/**
	* The Memcache object
	*
	* @var	Memcache
	*/
	protected $memcache = null;

	/**
	* To prevent locking when the memcached has been restarted we want to use add rather than set
	*
	* @var	boolean
	*/
	protected $memcache_set = true;

	/**
	* Indicates if the result of a call to the register function should store the value in memory
	*
	* @var	boolean
	*/
	protected $store_result = false;

	public function __construct(&$config, &$db_assertor)
	{
		parent::__construct($config, $db_assertor);
		if (!empty($config['Cache']['memcacheprefix']))
		{
			$this->prefix = & $config['Cache']['memcacheprefix'];
		}

		$this->memcache = vB_Memcache::instance();
	}

	public function resetCache()
	{
		$this->memcache->flush();
	}

	/**
	* Fetches the contents of the datastore from a Memcache Server
	*
	* @param	array	Array of items to fetch from the datastore
	*
	* @return	void
	*/
	public function fetch($items)
	{
		if (!sizeof($items = $this->prepare_itemarray($items)))
		{
			return;
		}

		$this->fastDSFetch($items);

		if (empty($items))
		{
			return true;
		}
		$check = $this->memcache->connect();

		if ($check == 3)
		{ // Connection failed
			return parent::fetch($items);
		}

		$this->memcache_set = false;

		$unfetched_items = $this->do_fetch($items);

		$this->store_result = true;

		// some of the items we are looking for were not found, lets get them in one go
		if (!empty($unfetched_items))
		{
			if (!($result = $this->do_db_fetch($this->prepare_itemlist($unfetched_items))))
			{
				$this->memcache_set = true;
				return false;
			}
		}

		$this->memcache_set = true;
		$this->store_result = false;
		$this->check_options();

		return true;
	}

	/**
	* Fetches the data from memcache server and registers the items found.
	*
	* @param	mixed array of strings, each of which is a cache key
	*
	* @return	mixed array of strings, each of which is a cache key that is  not in memcache
	*/
	protected function do_fetch($items)
	{
		$cacheKeys = array();

		foreach ($items as $title)
		{
			$cacheKeys[$title] = $this->prefix . $title;
		}

		$found = $this->memcache->get($cacheKeys);

		if (empty($found))
		{
			return $items;
		}

		$unfetched_items = array();

		foreach($items as $title)
		{

			if (isset($found[$cacheKeys[$title]]))
			{
				$this->register($title, $found[$cacheKeys[$title]]);
			}
			else
			{
				$unfetched_items[] = $title;
			}
		}

		return $unfetched_items;
	}

	/**
	* Sorts the data returned from the cache and places it into appropriate places
	*
	* @param	string	The name of the data item to be processed
	* @param	mixed	The data associated with the title
	*
	* @return	void
	*/
	protected function register($title, $data, $unserialize_detect = 2)
	{
		if ($this->store_result === true)
		{
			$this->storeMemcache($title, $data);
		}

		parent::register($title, $data, $unserialize_detect);
	}

	/**
	* Updates the appropriate cache file
	*
	* @param	string	title of the datastore item
	*
	* @return	void
	*/
	public function build($title = '', $data = '', $unserialize = 0, $storelocal = true)
	{
		parent::build($title, $data, $unserialize, $storelocal);

		$this->storeMemcache($title, $data);
	}


	public function delete($title)
	{
		parent::delete($title);

		$check = $this->memcache->connect();
		if ($check == 3)
		{
			// Connection failed
			trigger_error('Unable to connect to memcache server', E_USER_ERROR);
		}
		$ptitle = $this->prefix . $title;
		$this->memcache->delete($ptitle);
	}

	protected function storeMemcache($title, $data)
	{
		$check = $this->memcache->connect();

		if ($check == 3)
		{
			// Connection failed
			trigger_error('Unable to connect to memcache server', E_USER_ERROR);
		}

		$ptitle = $this->prefix . $title;

		if ($this->memcache_set)
		{
			$this->memcache->set($ptitle, $data);
		}
		else
		{
			$this->memcache->add($ptitle, $data);
		}
	}

	/**
	 * This method is intended only for unit testing. Do NOT use it in other context.
	 * Clear all the cache class vars, useful to calculate every value again.
	 */
	public function clearValues()
	{
		if (!defined('VB_UNITTEST'))
		{
			throw new Exception('This method should be called only from unit tests');
		}
		else
		{
			$this->memcache_set = true;
			$this->store_result = false;
			$this->memcache->flush();
			parent::clearValues();
		}
	}

}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
