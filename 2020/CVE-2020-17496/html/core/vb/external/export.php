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

abstract class vB_External_Export
{
	use vB_Trait_NoSerialize;

	// list of headers used by output type
	protected $headers = array(
		'Pragma' => vB_Cleaner::TYPE_NOCLEAN,
		'Cache-Control' => vB_Cleaner::TYPE_UNIXTIME,
		'Expires' => vB_Cleaner::TYPE_UNIXTIME,
		'Last-Modified' => vB_Cleaner::TYPE_UNIXTIME,
		'ETag' => vB_Cleaner::TYPE_STR,
		'Content-Type' => vB_Cleaner::TYPE_STR
	);

	// valid external data provider options
	protected $options = array(
		'nodeid' => vB_Cleaner::TYPE_ARRAY_UINT,
		'count' => vB_Cleaner::TYPE_UINT,
		'fulldesc' => vB_Cleaner::TYPE_BOOL,
		'lastpost' => vB_Cleaner::TYPE_BOOL,
		'nohtml' => vB_Cleaner::TYPE_BOOL
	);

	// options used internally
	protected $internaloptions = array(
		'externalcutoff' => vB_Cleaner::TYPE_UNIXTIME,
		'ttl' => vB_Cleaner::TYPE_UINT
	);

	// data from output content(lastmodified, cachetime -- used for headers)
	protected $outputdata = array();

	// type of external data provider
	protected $type;

	protected function __construct()
	{}

	protected function getItemList($options)
	{
		// make sure options are properly set
		$options = $this->setOptionsData($options);

		$searchopts = array();
		$searchopts['channel'] = $options['nodeid'];

		$cacheKey = md5(
				$options['lastpost'] . '|' .
				$options['externalcutoff'] . '|' .
				implode(',', $options['nodeid']) . '|' .
				$options['count']
		);

		// check cache first
		$cache = vB_Cache::instance(vB_Cache::CACHE_LARGE);
		if ($cached = $cache->read($cacheKey))
		{
			return $cached;
		}

		// @TODO currently hard-coding 500 results per page, find a way to get result nodes with no limit if necessary.
		$searchopts['type'] = 'vBForum_Text';

		if (!empty($options['lastpost']))
		{
			$searchopts['view'] = 'activity';
			$searchopts['sort'] = array('last_post' => 'DESC');
		}
		else
		{
			$searchopts['starter_only'] = 1;
			$searchopts['sort'] = array('publishdate' => 'DESC');
		}

		if (!empty($options['externalcutoff']))
		{
			$searchopts['date'] = array('from' => $options['externalcutoff']);
		}

		$result = vB_Api::instanceInternal('search')->getInitialResults($searchopts, $options['count'], 1);

		//save to cache. search API caches the data too but that expires too soon so we have to cache the data again to have it last longer
		$cache->write($cacheKey, $result['results'], $options['ttl'], 'vB_External_Export');

		return $result['results'];
	}

	/**
	 * Builds an output based on the type from a given list of items (nodes) and options being passed.
	 *
	 * @param 	array 	List of nodes to build the output.
	 * @param 	array 	Options to be consider for external output (self::$options AND self::$internaloptions).
	 *					self::$options:
	 *						- nodeid => comma separated ids to fetch content from.
	 *						- count => number of results.
	 *						- fulldesc => whether description will be cut off (preview) or full (RSS 1 and 2 only.).
	 *						- lastpost => whether results will contain information from last post (if any).
	 *						- nohtml => whether display html or not (RSS 1 and 2 only.).
	 *					self::$internaloptions:
	 *						- externalcutoff => days to fetch newer content from.
	 *						- ttl => time to live for caching external output.
	 *
	 * @return 	string 	External data output generated
	 */
	protected function buildOutputFromItems($items, $options)
	{}

	/**
	 *	Builds an output regarding the implementation type.
	 *	Content from the output is basically content from the site including forum, blogs and groups.
	 * 	Options can be passed optionally.
	 *
	 *	@param 		array 	List of options to build the output.
	 *
	 * 	@return 	string 	External data output.
	 *
	 */
	public function output($options = array())
	{
		$items = $this->getItemList($options);
		$output = $this->buildOutputFromItems($items, $options);

		// set output data needed to fetch headers info
		$this->setOutputData($items, $options);
		return $output;
	}

	/**
	 * Common getter.
	 *
	 */
	public function getHeaders()
	{
		return $this->headers;
	}

	/**
	 * Mostly a wrapper of vbdate. Adding it since vbdate function should be ported to vB5 standards
	 * and we can easier replace when the time comes up.
	 */
	protected function callvBDate($format, $timestamp)
	{
		// @TODO should use new vbdate ported to vB5 instead of the old one in functions
		require_once(DIR . '/includes/functions.php');
		return vbdate($format, $timestamp);
	}

	/**
	 * Common getter
	 *
	 */
	public function getOptions()
	{
		return $this->options;
	}

	/**
	 * Formats fields if needed regarding the options.
	 *
	 * @param 	Array 	List of items for the external data provider output.
	 * @param 	Array 	Options.
	 *
	 * @return 	Array 	List of formatted items.
	 *
	 */
	public function formatItems($items, $options)
	{
		foreach ($items AS $id => $item)
		{
			// change content so lastpost info is displayed according to output
			if (!empty($options['lastpost']))
			{
				$items[$id]['content']['external_nodeid'] = $item['content']['starter'];
				$items[$id]['content']['external_title'] = $item['content']['startertitle'];
				$items[$id]['content']['external_prefix_plain'] = (!empty($item['content']['starterprefix_plain']) ? $item['content']['starterprefix_plain'] : '');
			}
			else
			{
				$items[$id]['content']['external_nodeid'] = $item['content']['nodeid'];
				$items[$id]['content']['external_title'] = $item['content']['title'];
				$items[$id]['content']['external_prefix_plain'] = (!empty($item['content']['prefix_plain']) ? $item['content']['prefix_plain'] : '');
			}
		}

		return $items;
	}

	/**
	 * Set information for output being created from the items.
	 * Used later for setting headers values (such as cache-control, expires, last-modified and etag).
	 *
	 */
	protected function setOutputData($items, $options)
	{
		$this->outputdata['headers'] = array(
			'lastmodified' => vB::getRequest()->getTimeNow(),
			'expires' => (($options['ttl'] * 60) + vB::getRequest()->getTimeNow()),
			'cachehash' => $this->getCacheHash($options)
		);

		$this->outputdata['options'] = $options;
	}

	/**
	 * Get a list of valid headers values from last external provider output and data specified.
	 * Notice this has to be called after output() gets called so needed data gets in place.
	 *
	 * 	@param 		array 	Headers data. Must contain valid 'lastmodified', 'expires', 'cachehash' keys.
	 *						- Content-Type => charset to consider in output content type.
	 *
	 * 	@return 	array 	List of valid headers filled out.
	 */
	public function getHeadersFromLastOutput($data)
	{
		if (empty($this->headers))
		{
			return array();
		}

		$this->outputdata['headers'] = array_merge($this->outputdata['headers'], $data);
		return $this->getHeadersFromData($this->outputdata);
	}

	/**
	 * Get a list of valid headers values from data specified. (vB_External_Export::$headers).
	 *
	 * 	@param 		array 	Headers data. Must contain valid 'lastmodified', 'expires', 'cachehash' keys.
	 *
	 * 	@return 	array 	List of valid headers filled out.
	 */
	protected function getHeadersFromData($data)
	{
		$headers = $data['headers'];
		if (empty($this->headers) AND !isset($headers['lastmodified']) OR !isset($headers['expires']) OR !isset($headers['cachehash']))
		{
			return array();
		}

		$options = $this->setOptionsData($data['options']);
		$cacheKey = md5(
			$headers['lastmodified'] . '|' .
			$headers['expires'] . '|' .
			$headers['cachehash'] . '|' .
			(!empty($headers['Content-Type']) ? $headers['Content-Type'] : '') . '|' .
			(!empty($headers['Pragma']) ? $headers['Pragma'] : '')
		);

		$cache = vB_Cache::instance(vB_Cache::CACHE_LARGE);
		if ($cached = $cache->read($cacheKey))
		{
			return $cached;
		}

		// set headers as needed
		$headers['Cache-Control'] = $headers['expires'];
		$headers['Expires'] = $headers['expires'];
		$headers['Last-Modified'] = $headers['lastmodified'];
		$headers['ETag'] = $headers['cachehash'];

		// set the rest
		$headers = $this->setHeaderData($headers);
		$cache->write($cacheKey, $headers, $options['ttl'], 'vB_External_Export');
		return $headers;
	}

	/**
	 * Set headers data for external data provider from given data.
	 * Data must be clean at this point.
	 *
	 * @param 	array 	Headers data.
	 *
	 * @return 	array 	Valid header data.
	 */
	protected function setHeaderData($data)
	{
		$result = array();
		foreach ($this->headers AS $name => $val)
		{
			if (isset($data[$name]))
			{
				switch ($name)
				{
					// VBIV-8269
					case 'Pragma':
						$result[$name] = '';
						break;
					// uses expires
					case 'Cache-Control':
						$result[$name] = 'max-age=' . $data[$name];
						break;
					case 'Expires':
					case 'Last-Modified':
						$result[$name] = gmdate('D, d M Y H:i:s', $data[$name]) . ' GMT';
						break;
					case 'ETag':
						$result[$name] = '"' . $data[$name] . '"';
						break;
					case 'Content-Type':
						$result[$name] = 'text/xml' . (!empty($data[$name]) ? '; charset=' . $data[$name] : '');
						break;
					default:
						break;
				}
			}
		}

		return $result;
	}

	/**
	 * Common getter
	 */
	public function getInternalOptions()
	{
		return $this->internaloptions;
	}

	/**
	 * Creates a cachehash from given options.
	 *
	 * @param 	array 	Options to build cachehash from.
	 *
	 * @return 	string 	Cache hash.
	 *
	 */
	public function getCacheHash($options)
	{
		$options = $this->setOptionsData($options);
		$md5 = md5(
			// always use option for cachehash
			(vB::getDatastore()->getOption('externalcutoff') . '|' .
			$options['ttl'] . '|' .
			$this->type . '|' .
			$options['lastpost'] . '|' .
			$options['nohtml'] . '|' .
			$options['fulldesc'] . '|' .
			$options['count'] . '|' .
			implode(',', $options['nodeid'])
		));

		return $md5;
	}

	/**
	 * Make sure default options are always being properly set.
	 *
	 */
	protected function setOptionsData($options)
	{
		foreach (array('externalcutoff' => 0, 'ttl' => 60, 'lastpost' => 0, 'nohtml' => 0, 'fulldesc' => 0, 'count' => 500, 'nodeid' => array(vB_Api::instanceInternal('content_channel')->fetchChannelIdByGUID(vB_Channel::MAIN_CHANNEL))
			) AS $name => $default)
		{
			if ($name == 'nodeid')
			{
				$options[$name] = ((!empty($options[$name]) AND is_array($options[$name])) ? $options[$name] : $default);
			}
			else
			{
				$options[$name] = (!empty($options[$name]) ? $options[$name] : $default);
			}
		}

		return $options;
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
