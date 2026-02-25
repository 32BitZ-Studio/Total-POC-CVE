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
 * vB_Api_External
 *
 * @package vBApi
 * @copyright Copyright (c) 2013
 * @version $Id: external.php 99787 2018-10-25 00:13:06Z ksours $
 * @access public
 */
class vB_Api_External extends vB_Api
{
	// js
	const TYPE_JS = 'js';

	// xml
	const TYPE_XML = 'xml';

	// rss 0.91
	const TYPE_RSS = 'rss';

	// rss 1.0
	const TYPE_RSS1 = 'rss1';

	// rss 2.0
	const TYPE_RSS2 = 'rss2';
	
	// external types instances
	private $instances = array();

	// cleaner
	protected $cleaner;

	/**
	 *
	 * @var vB_Library_External
	 */
	protected $library;

	// relation between type and class to load
	private $instancemap = array(
		'js' => 'vB_External_Export_Js',
		'xml' => 'vB_External_Export_Xml',
		'rss' => 'vB_External_Export_Rss_91',
		'rss1' => 'vB_External_Export_Rss_1',
		'rss2' => 'vB_External_Export_Rss_2'
	);

	protected function __construct()
	{
		parent::__construct();
		$this->cleaner = new vB_Cleaner();
		$this->library = vB_Library::instance('external');
	}

	/**
	 *
	 * Creates an external output from site depending on the type specified.
	 * Output will be formatted regarding the options being passed.
	 *
	 * @param 	string 	Type of external output to create.
	 * 					Supported: self::TYPE_JS, self::TYPE_XML, self::TYPE_RSS, self::TYPE_RSS1, self::TYPE_RSS2
	 * @param 	array 	Options to generate the output format. Will use default if none specified (vB_External_Export::$options).
	 *					- nodeid => comma separated ids to fetch content from.
	 *					- count => number of results.
	 *					- fulldesc => whether description will be cut off (preview) or full (RSS 1 and 2 only.).
	 *					- lastpost => whether results will contain information from last post (if any).
	 *					- nohtml => whether display html or not (RSS 1 and 2 only.).
	 *
	 * @return 	string 	External output.
	 *
	 */
	public function createExternalOutput($type, $options = array())
	{
		$result = $this->library->validateExternalType($type);
		if ($result['valid'] === false)
		{
			throw new vB_Exception_Api($result['phraseid']);
		}

		$external = $this->loadInstance($type);

		// clean and validate, nodeid are passed as comma separated integers
		if (isset($options['nodeid']) AND !empty($options['nodeid']))
		{
			$options['nodeid'] = explode(',', $options['nodeid']);
		}

		$options = $this->cleaner->cleanArray($options, $external->getOptions());
		$options = $this->validateOptions($options);
		return $external->output($options);
	}

	/**
	 * Builds an external data provider route depending on the type and extra data specified.
	 *
	 * 	@param 	string 	External data provider type
	 *					Supported: self::TYPE_JS, self::TYPE_XML, self::TYPE_RSS, self::TYPE_RSS1, self::TYPE_RSS2
	 *  @param 	array 	Options to be included in route. (see vB_External_Export::$options)
	 *
	 * 	@return array 	Route data information:
	 * 					Route -- the route
	 * 					active -- if external data provider is active
	 */
	public function buildExternalRoute($type, $data = array())
	{
		$type = trim(strtolower($type));
		$result = $this->library->validateExternalType($type);
		if ($result['valid'] === false)
		{
			return array('active' => false, 'route' => '');
		}

		if (isset($data['nodeid']) AND !is_array($data['nodeid']))
		{
			$data['nodeid'] = array($data['nodeid']);
		}

		$external = $this->loadInstance($type);

		// all unspecified option gets added to array as null
		$cleaned = $this->cleaner->cleanArray($data, $external->getOptions());

		$cleaned['type'] = $type;
		$route = $this->library->getExternalRoute($cleaned, $data);
		return array('active' => true, 'route' => $route);
	}

	/**
	 * Get a list of valid headers values from last output data regarding on the data and 
	 * external type specified. (vB_External_Export::$headers).
	 * Notice this has to be called after createExternalOutput() gets called so needed data gets in place.
	 *
	 *	@param 		string 	External type.
	 * 	@param 		array 	List of headers to be fill out.
	 *						- Content-Type => charset to consider in output content type.
	 *
	 * 	@return 	array 	List of valid headers filled out.
	 */
	public function getHeadersFromLastOutput($type, $data)
	{
		// needed data set from last output
		$result = $this->library->validateExternalType($type);
		if ($result['valid'] === false)
		{
			throw new vB_Exception_Api($result['phraseid']);
		}

		$external = $this->loadInstance($type);

		$data = $this->cleaner->cleanArray($data, $external->getHeaders());
		return $external->getHeadersFromLastOutput($data);
	}

	/**
	 * Gets useful information for external cache logic, such as cachetime and cachehash.
	 *
	 * @param 	string 	External type.
	 * @param 	array 	Options to build cachehash from.
	 *					- nodeid => comma separated ids to fetch content from.
	 *					- count => number of results.
	 *					- fulldesc => whether description will be cut off (preview) or full.
	 *					- lastpost => whether results will contain information from last post (if any).
	 *					- nohtml => whether display html or not.
	 *
	 * @return 	string 	Cache hash.
	 *
	 */
	public function getCacheData($type, $options = array())
	{
		// clean and validate, nodeid are passed as comma separated integers
		if (isset($options['nodeid']) AND !empty($options['nodeid']))
		{
			$options['nodeid'] = explode(',', $options['nodeid']);
		}

		// cachetime is in minutes, seconds are needed
		return array(
			'cachehash' => $this->getCacheHash($type, $options),
			'cachetime' => ($this->getCacheTime() * 60)
		);
	}

	/**
	 * Validate external data options (vB_External_Export::$options) 
	 * and set default values.
	 * 
	 * @param 	array 	List of options. 
	 */
	protected function validateOptions($options)
	{
		$result = array();
		foreach ($options AS $name => $val)
		{
			switch ($name)
			{
				case 'nodeid':
					if (!empty($val))
					{
						$nodes = vB_Api::instanceInternal('node')->getNodes($val);
						foreach ($nodes AS $node)
						{
							if ($node['contenttypeid'] == vB_Types::instance()->getContentTypeID('vBForum_Channel'))
							{
								$result['nodeid'][$node['nodeid']] = $node['nodeid'];
							}
						}

						if (empty($result['nodeid']))
						{
							throw new vB_Exception_Api('invalid_data_requested');
						}
					}
					break;
				case 'count':
					// limit is 15
					$result['count'] = $this->getCount($options['count']);
					break;
				default:
					$result[$name] = (bool)$val;
					break;
			}
		}

		// set externalcache and externalcutoff internally, limit is 24 hours
		$result['ttl'] = $this->getCacheTime();
		$result['externalcutoff'] = $this->getCutoff();

		return $result;
	}

	/**
	 * Loads a given external type instance and make sure is only loaded once.
	 *
	 * @param 	int 				External type to load.
	 *
	 * @return 	vB_External_Export 	Type instance.
	 *
	 */
	private function loadInstance($type)
	{
		if (!isset($this->instances[$type]))
		{
			$this->instances[$type] = new $this->instancemap[$type]();
		}

		return $this->instances[$type];
	}

	/**
	 * Gets a cachehash from given external type and options.
	 *
	 * @param 	string 	External type.
	 * @param 	array 	Options to build cachehash from.
	 *
	 * @return 	string 	Cache hash.
	 *
	 */
	private function getCacheHash($type, $options)
	{
		$result = $this->library->validateExternalType($type);
		if ($result['valid'] === false)
		{
			throw new vB_Exception_Api($result['phraseid']);
		}


		// no cachehash needed for JS
		if (trim(strtolower($type)) == 'js')
		{
			return '';
		}

		$external = $this->loadInstance($type);
		$data = $external->getOptions() + $external->getInternalOptions();
		$data = $this->cleaner->cleanArray($options, $data);

		// never highger than vb setting
		$count = (!empty($options['count']) ? $options['count'] : 0);
		$data['count'] = $this->getCount($count);

		// set default for internal
		if (empty($options['externalcutoff']))
		{
			$data['externalcutoff'] = $this->getCutoff();
		}

		if (empty($options['ttl']))
		{
			$data['ttl'] = $this->getCacheTime();
		}

		return $external->getCacheHash($data);
	}

	/**
	 * Gets cachetime from externalcache option, if not valid value then set a default.
	 *
	 */
	private function getCacheTime()
	{
		// default's 60
		$ttl = vB::getDatastore()->getOption('externalcache');
		return ((($ttl > 0) AND ($ttl <= 1440)) ? $ttl : 60);
	}

	/**
	 * Gets cutoff from externalcutoff option, if not valid value then use 0
	 *
	 */
	private function getCutoff()
	{
		$cutoff = intval(vB::getDatastore()->getOption('externalcutoff'));
		return (!$cutoff ? 0 : (vB::getRequest()->getTimeNow() - ($cutoff * 86400)));
	}

	/**
	 * Make sure count value gets consistent for external logic.
	 *
	 */
	private function getCount($count)
	{
		$count = intval($count);
		$externalcount = (vB::getDatastore()->getOption('externalcount') ? vB::getDatastore()->getOption('externalcount') : 15);
		if (!$count OR ($count > $externalcount))
		{
			$result = $externalcount;
		}
		else
		{
			$result = $count;
		}

		return $result;
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
