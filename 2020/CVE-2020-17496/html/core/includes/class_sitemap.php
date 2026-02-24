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
* Helper class for running a multi-page sitemap generation process.
*
* @package	vBulletin
*/
class vB_SiteMapRunner
{
	/**
	* The vBulletin registry object
	*
	* @var	vB_Registry
	*/
	protected $registry = null;

	/**
	* The current sitemap runner session. Tracks progress across pages.
	*
	* @var	array
	*/
	protected $session = array();

	/**
	* Stores if the environment is ok for execution.
	*
	* @var	bool|null	Null = unknown, otherwise treat as value
	*/
	protected $environment_ok = null;

	/**
	* If the entire sitemap generation process is known to be finished.
	*
	* @var	bool
	*/
	public $is_finished = false;

	/**
	* Name of the written out filename
	*
	* @var	string
	*/
	public $written_filename = '';

	/**
	* Constructor. Automatically sets up the session.
	*
	* @param	vB_Registry	Registry object
	*/
	public function __construct(vB_Registry $registry)
	{
		$this->registry = $registry;
		$this->session = self::fetch_session_from_db($registry);
	}

	/**
	* Fetches the session info for this run from the database.
	*
	* @param	vB_Registry
	*
	* @return	array	Array of session info; new session is created if needed
	*/
	public static function fetch_session_from_db(vB_Registry $registry)
	{
		global $vbulletin, $vbphrase;

		$sitemap_status = vB::getDbAssertor()->getRow('adminutil', array('title' => 'sitemapsession'));
		if ($sitemap_status)
		{
			$session = unserialize($sitemap_status['text']);
		}

		if (!is_array($session))
		{
			$contenttypes = array();
			$contenttypes['node'] = 'node';
			$contenttypes['starter'] = 'starter';
			$contenttypes['page'] = 'page';

			reset($contenttypes);
			$session = array(
				'types' => $contenttypes,
				'current_content' => current($contenttypes),
				'startat' => 0,
				'state' => 'start',
				'sitemaps' => array(),
			);
		}

		// Legacy Hook 'sitemap_add_content_types' Removed //

		return $session;
	}

	/**
	* Fetches the current, "in progress" session. This may differ from the state
	* in the DB if changes are pending.
	*
	* @return	array
	*/
	public function fetch_session()
	{
		return $this->session;
	}

	/**
	* Check that the environment is ok for building the sitemap.
	*
	* @return	array	Array of status information. Check 'error' key.
	*/
	public function check_environment()
	{
		$status = $this->check_environment_internal();
		$this->environment_ok = ($status['error'] != '');

		return $status;
	}

	/**
	* Internal function for checking the environment. This is where specific checks should be run.
	*
	* @return	array	Array of status info. Check 'error' key.
	*/
	protected function check_environment_internal()
	{
		$status = array(
			'error' => '',
			'loggable' => false
		);

		if ($this->session['state'] == 'failed')
		{
			$status['error'] = $this->session['failure_reason'];
			$status['loggable'] = false; // should be logged when it occurs, not each "hit"
		}
		$sitemap_path = vB::getDatastore()->getOption('sitemap_path');

		$path = resolve_server_path($sitemap_path);
		if (empty($sitemap_path) OR !is_writable($path))
		{
			$status['error'] = 'sitemap_path_not_writable';
			// only log on the first occurance in a session
			$status['loggable'] = ($this->session['state'] == 'start');
		}

		return $status;
	}

	/**
	* Generates one "page" worth of a sitemap and prepares for the next page or finalizes.
	*
	* @return	bool	True on success
	*/
	public function generate()
	{
		if ($this->environment_ok === null)
		{
			$status = $this->check_environment();
			if ($status['error'])
			{
				return false;
			}
		}

		$first_page = ($this->session['state'] == 'start');

		$this->set_state();

		$sitemap_obj = self::get_content_handler($this->session['current_content'], $this->registry);
		if (!$sitemap_obj)
		{
			$this->trigger_failure('invalid_sitemap_content_type');
			return false;
		}

		if ($first_page)
		{
			$sitemap_obj->remove_sitemaps();
		}

		$items_processed = $sitemap_obj->generate_sitemap($this->session['startat'], $this->registry->options['sitemap_url_perpage']);
		// Special case, if forum has 0 nodes, there will be no urls to add & write_sitemap will fail. So let's check that
		// $items_processed is not 0
		if ($items_processed AND !$this->write_sitemap($sitemap_obj))
		{
			$this->trigger_failure('sitemap_creation_failed');
			return false;
		}

		$this->is_finished = $this->is_finished($sitemap_obj);

		if ($this->is_finished)
		{
			return $this->finalize($sitemap_obj);
		}
		else
		{
			return $this->prepare_next_page();
		}
	}

	/**
	* Sets the session state at the beginning of generating a "page".
	*/
	protected function set_state()
	{
	}

	/**
	* Fetches the handler class for a particular type of content.
	*
	* @return	vB_Sitemap	Subclass of vB_Sitemap
	*/
	public static function get_content_handler($type, vB_Registry $registry)
	{
		if (empty($type))
		{
			return false;
		}

		$classname = 'vB_SiteMap_' . ucfirst(strtolower($type));
		if (class_exists($classname, false))
		{
			return new $classname($registry);
		}

		return false;
	}

	/**
	* Writes out the sitemap file for the current content.
	*
	* @param	vB_Sitemap	Current sitemap object
	*
	* @return	boolean
	*/
	protected function write_sitemap($sitemap_obj)
	{
		$filename_suffix = $this->session['current_content'] . '_' . count($this->session['sitemaps']);
		$this->written_filename = "vbulletin_sitemap_{$filename_suffix}.xml";

		if ($filename = $sitemap_obj->create_sitemap($filename_suffix))
		{
			$this->session['sitemaps'][] = array('loc' => $filename, 'lastmod' => vB::getRequest()->getTimeNow());
			return true;
		}
		else
		{
			return false;
		}
	}

	/**
	* Determines if the sitemap generation is finished. This manipulates the session
	* and helps prepare for the next page.
	*
	* @param	vB_Sitemap	Current sitemap object
	*
	* @return	boolean
	*/
	protected function is_finished($sitemap_obj)
	{
		$has_more = $sitemap_obj->has_more();
		if ($has_more === null)
		{
			// has_more wasn't definitive; use default handler
			$has_more = ($sitemap_obj->get_pagecount() == $this->registry->options['sitemap_url_perpage']);
		}

		if ($has_more)
		{
			$this->session['startat'] = $sitemap_obj->get_lastid() + 1;	// make sure startat is used inclusively in limits.
			return false;
		}
		else
		{
			$this->step_content_type_forward();
			return (count($this->session['types']) == 0);
		}
	}

	/**
	* Moves forward to the next content type.
	*/
	protected function step_content_type_forward()
	{
		array_shift($this->session['types']);

		$this->session['current_content'] = reset($this->session['types']);
		$this->session['startat'] = 0;
	}

	/**
	* Finalizes the sitemap build by writing an index and contacting the
	* selected search engines.
	*
	* @param	vB_Sitemap	Sitemap object
	*
	* @return	boolean
	*/
	protected function finalize($sitemap_obj)
	{
		global $vbphrase;

		if ($sitemap_obj)
		{
			// Ensure all sitemaps together (possibly existing sitemap index file)
			$sitemap_obj->set_sitemap_index(array_merge($sitemap_obj->get_sitemap_index(), $this->session['sitemaps']));

			// Create the sitemap index file and write it out
			if (!$sitemap_obj->create_sitemap_index())
			{
				$this->trigger_failure('sitemap_creation_failed');
				return false;
			}

			$sitemap_obj->ping_search_engines();
		}

		vB::getDbAssertor()->assertQuery('adminutil', array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_DELETE,
			vB_dB_Query::CONDITIONS_KEY => array('title' => 'sitemapsession')
		));

		return true;
	}

	/**
	* Prepares for the next page. This is only called when the build isn't finished.
	*
	* @return	boolean
	*/
	protected function prepare_next_page()
	{
		$this->write_session();

		return true;
	}

	/**
	* Writes the sitemap session out. Only needed when not finished.
	*/
	protected function write_session()
	{
		vB::getDbAssertor()->assertQuery('writeAdminUtilSession', array('session' => serialize($this->session)));
	}

	/**
	* Triggers a failure event. This prevents the sitemap from being built
	* any further until the error is resolved. Calling this updates
	* the sitemap session automatically.
	*
	* @param	string	Phrase key (in "error messages") that describes the error
	*/
	protected function trigger_failure($error_phrase)
	{
		$this->session['state'] = 'failed';
		$this->session['failure_reason'] = $error_phrase;
		$this->write_session();
	}
}

/**
* Sitemap runner that uses cron-specific checks and triggers.
*
* @package	vBulletin
*/
class vB_SiteMapRunner_Cron extends vB_SiteMapRunner
{
	/**
	* Information about the cron item that triggers the sitemap builds.
	*
	* @var	array
	*/
	protected $cron_item = array();

	/**
	* Information about the cron-triggered sitemap builds (particularly last build time).
	*
	* @var	array
	*/
	protected $build_info = array();

	/**
	* Constructor. Fetches session (via parent) and populates build_info.
	*
	* @param	vB_Registry
	*/
	public function __construct(vB_Registry $registry)
	{
		require_once(DIR . '/includes/functions_cron.php');

		parent::__construct($registry);

		if ($build_info = $registry->db->query_first("
			SELECT text
			FROM " . TABLE_PREFIX . "adminutil
			WHERE title = 'sitemapcronbuild'
		"))
		{
			$this->build_info = unserialize($build_info['text']);
		}
	}

	/**
	* Sets the cron item property.
	*
	* @param	array	Cron item info
	*/
	public function set_cron_item(array $cron_item)
	{
		$this->cron_item = $cron_item;
	}

	/**
	* Internal function for checking the environment. Checks cron-specific items
	* like being enabled and the last build time.
	*
	* @return	array	Array of status info. Check 'error' key.
	*/
	protected function check_environment_internal()
	{
		$status = parent::check_environment_internal();

		if ($this->session['state'] == 'running_admincp')
		{
			$status['error'] = 'sitemap_currently_generated_admincp';
			$status['loggable'] = false;
		}

		if (!$this->registry->options['sitemap_cron_enable'])
		{
			$status['error'] = 'sitemap_cron_option_not_enabled';
			$status['loggable']	= false;
		}

		if ($this->session['state'] == 'start'
			AND $this->build_info
			AND $this->build_info['last_build'] > (vB::getRequest()->getTimeNow() - $this->registry->options['sitemap_cron_frequency'] * 86400))
		{
			$status['error'] = 'sitemap_cron_build_not_scheduled';
			$status['loggable']	= false;
		}

		return $status;
	}

	/**
	* Sets the session state to running and updates the last build time if necessary.
	*/
	protected function set_state()
	{
		if ($this->session['state'] == 'start')
		{
			$this->build_info['last_build'] = vB::getRequest()->getTimeNow();

			$this->registry->db->query_write("
				REPLACE INTO " . TABLE_PREFIX . "adminutil
					(title, text)
				VALUES
					('sitemapcronbuild',
					'" . $this->registry->db->escape_string(serialize($this->build_info)) . "')
			");
		}
		$this->session['state'] = 'running_cron';
	}

	/**
	* Prepares for the next "page" of building. Handles parent functions and
	* updates the cron to run almost immediately (to allow a multi-page build
	* to be completed quickly.
	*
	* @return	boolean
	*/
	protected function prepare_next_page()
	{
		if (!parent::prepare_next_page())
		{
			return false;
		}

		if ($this->cron_item)
		{
			// if we have more to do, run the next step in approximately a minute
			$this->registry->db->query_write("
				UPDATE " . TABLE_PREFIX . "cron
				SET nextrun = " . (vB::getRequest()->getTimeNow() + 60) . "
				WHERE cronid = " . intval($this->cron_item['cronid'])
			);
			build_cron_next_run();
		}

		return true;
	}
}

/**
* Admin CP-based sitemap build helper.
*
* @package	vBulletin
*/
class vB_SiteMapRunner_Admin extends vB_SiteMapRunner
{
	/**
	* Internal function for checking the environment. Checks ACP-specific items
	* like whether the sitemap is being built by cron.
	*
	* @return	array	Array of status info. Check 'error' key.
	*/
	protected function check_environment_internal()
	{
		$status = parent::check_environment_internal();

		if ($this->session['state'] == 'running_cron')
		{
			$status['error'] = 'sitemap_running_cron';
		}

		return $status;
	}

	/**
	* Sets session state to running.
	*/
	protected function set_state()
	{
		$this->session['state'] = 'running_admincp';
	}
}

/**
* Abstract class to construct sitemap files and the index file. Must be subclassed for specific content types.
*
* @package	vBulletin
*/
abstract class vB_SiteMap
{
	/**
	* The last id of the content, for per_page
	*
	* @var	int
	*/
	protected $lastid = 0;

	/**
	* An array of custom Forum priorities forumid => priority
	*
	* @var	array
	*/
	protected $forum_custom_priority = array();

	/**
	 * An array of custom priorities contenttype => forumid => priority
	 *
	 * @var	array
	 */
	protected $custom_priority = array();

	/**
	* The vBulletin registry object
	*
	* @var	vB_Registry
	*/
	protected $registry = null;

	/**
	* The vBulletin database object
	*
	* @var	vB_Database
	*/
	protected $dbobject = null;

	/**
	* A vB_XML_Parser database object
	*
	* @var	vB_XML_Parser
	*/
	protected $xmlobject = null;

	/**
	* String to save the content of the sitemap while being generated before being written out
	*
	* @var	string
	*/
	protected $content = '';

	/**
	* Counter for the numbers of URLs added to the current sitemap content
	*
	* @var	int
	*/
	protected $pagecount = 0;

	/**
	* Determines if there is more of this content type to process.
	*
	* @var	boolean|null	Null is unknown, boolean otherwise
	*/
	protected $has_more = null;

	/**
	* Array to store any errors encountered while building data
	*
	* @var	array
	*/
	protected $errors = array();

	/**
	* Array to store currently generated (or listed) site maps. Used to generate sitemap index file (the master one). ['loc'] && ['lastmod']
	*
	* @var	array
	*/
	protected $sitemap_index = array();

	/**
	* Default name for sitemap_index file
	*
	* @var	string
	*/
	private $sitemap_index_filename = 'vbulletin_sitemap_index';


	/**
	* Default name for sitemap files, which is prepended by the sitemap file count
	*
	* @var	string
	*/
	private $sitemap_filename_prefix = 'vbulletin_sitemap_';

	const FLAG_PING_GOOGLE      = 0x1;
	const FLAG_PING_BING		= 0x2;

	/**
	* Array of search engine urls' for sitemap call back, populated with defaults from options
	*
	* @var 	array
	*/
	public $search_engines = array(
		self::FLAG_PING_GOOGLE      => 'http://www.google.com/webmasters/tools/ping?sitemap=',
		self::FLAG_PING_BING 		=> 'http://www.bing.com/webmaster/ping.aspx?siteMap=',
	);

	protected $sitemap_path; // path to the directory in which we write the sitemap files
	protected $tempfile = 'temp.tmp'; // name of the temporary file we write to because appending to string in memory causes memory issues


	/**
	* Constructor - checks that the registry object has been passed correctly.
	*
	* @param	vB_Registry		Instance of the vBulletin data registry object - expected to have the database
	* 	object as one of its $this->db member.
	*/
	public function __construct(vB_Registry $registry)
	{
		$this->dbobject = $registry->db;
		$this->registry = $registry;
		$this->sitemap_path = resolve_server_path(vB::getDatastore()->getOption('sitemap_path'));
	}

	### abstract ###

	/**
	* This function will generate the actual sitemap content.
	*/
	abstract protected function generate_sitemap();

	### Main ###

	/**
	* Gets the current data that will be used to build the sitemap index
	*
	* @return	array
	*/
	public function get_sitemap_index()
	{
		return $this->sitemap_index;
	}

	/**
	* Sets the current data that will be used to build the sitemap index
	*
	* @param	array
	*/
	public function set_sitemap_index($value)
	{
		$this->sitemap_index = $value;
	}

	/**
	* Returns indicator for whether there's more of this content to be processed.
	* Useful for the case where there is exactly the "per page" pieces of content.
	*
	* @return	boolean|null	Null is unknown, booling otherwise
	*/
	public function has_more()
	{
		return $this->has_more;
	}

	/**
	 * Returns the effective priority for a non-forum type
	 *
	 * @param 	string	content type
	 * @param	integer	content ID
	 *
	 * @return	float	Usable priority
	 */
	public function get_effective_priority($contenttype, $contentid)
	{
		$hasCustomPriority = (isset($this->custom_priority[$contenttype][$contentid]) AND
			($this->custom_priority[$contenttype][$contentid] !== false));

		return($hasCustomPriority	? $this->custom_priority[$contenttype][$contentid] : $this->registry->options['sitemap_priority']);
	}


	/**
	 * Accessor
	 *
	 * @return int
	 */
	public function get_pagecount()
	{
		return $this->pagecount;
	}


	/**
	 * Accessor
	 *
	 * @return int
	 */
	public function get_lastid()
	{
		return $this->lastid;
	}


	/**
	* Write out the sitemap index file using sitemap file refrences in $this->sitemap_index
	*
	* @return boolean indicates success.  On failure an error message will be recorded in $this->errors
	*/
	final function create_sitemap_index()
	{
		$content = '<?xml version="1.0" encoding="UTF-8"?>' . "\n" . '<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">';

		foreach ($this->sitemap_index AS $sitemap)
		{
			$content .= "\n" . '<sitemap>';
			$content .= "\n\t" . '<loc>' . htmlspecialchars($this->registry->options['bburl'] . '/xmlsitemap.php?fn=' . urlencode($sitemap['loc'])) . '</loc>';
			$content .= "\n\t" . '<lastmod>' . gmdate(DATE_W3C, $sitemap['lastmod']) . '</lastmod>';
			$content .= "\n" . '</sitemap>';
		}

		$content .= "\n" . '</sitemapindex>';

		// Compress and add extension
		if (function_exists('gzencode'))
		{
			$content = gzencode($content);
			$output_filename = $this->sitemap_index_filename . '.xml.gz';
		}
		else
		{
			$output_filename = $this->sitemap_index_filename . '.xml';
		}

		// Try to write file
		if ($fp = @fopen($this->sitemap_path . '/' . $output_filename, 'w'))
		{
			fwrite($fp, $content);
			fclose($fp);
			return true;
		}
		else
		{
			$this->errors[] = 'Error writing : ' . $this->sitemap_path . '/' . $output_filename;
			return false;
		}
	}


	/**
	 * Build the actual file for the sitemap
	 *
	 * @return boolean indicates success.  On failure an error message will be recorded in $this->errors
	 */
	final function create_sitemap($filename)
	{
		$tempFilename = $this->sitemap_path . '/' . $this->tempfile;

		$tempContents = file_get_contents($tempFilename);
		if (!$tempContents)
		{
			$this->errors[] = "Temp file was empty. This could mean that there were no URLs to write to $filename.";
			return false;
		}

		$content = '<?xml version="1.0" encoding="UTF-8"?' . '>' . "\n"
			.	'<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
			.	$tempContents . "\n"
			. '</urlset>';

		unset($tempContents);

		// Next file name
		$new_file = $this->sitemap_filename_prefix . $filename;

		// Check compression and add extension
		if (function_exists('gzencode'))
		{
			$new_file .= '.xml.gz';
			$content = gzencode($content);
		}
		else
		{
			$new_file .= '.xml';
		}

		$filepath = $this->sitemap_path . '/' . $new_file;
		if(!file_put_contents($filepath, $content))
		{
			$this->errors[] = 'Error writing : ' . $filepath;
			return false;
		}

		// Important! Clear file for next batch
		file_put_contents($tempFilename, '');
		return $new_file;
	}


	/**
	* Create a url XML text block for one URL
	*
	* @param	string		The URL (not encoded) to add to the sitemap
	* @param 	int			The unix timestamp of the last modifictaion time of the data in UTC
	* @param 	double		The priority of the data from 0.1 to 1.0
	* @param 	boolean		Enable formatting of the output
	*
	* @return	string		Formatted escaped <url> wrapped text
	*/
	protected function url_block($url, $lastmod, $pri = false, $formatting = false)
	{
		$l = "\n" . ($formatting ? "\t\t" : '');

		// Start block
		$data = "\n" . ($formatting ? "\t" : '') . '<url>';

		$url = $url;
		$data .= $l . '<loc>' . htmlspecialchars_uni(vB_String::vbChop($url, 2048)) . '</loc>';

		//if we have a null or 0 lastmod let's not publish a bogus date.
		//also skip the change frequency.  These are optional and the default behavior of
		//the search engine is preferable to bad data
		if ($lastmod)
		{
			$data .= $l . '<lastmod>' . htmlspecialchars_uni(gmdate(DATE_W3C, $lastmod)) . '</lastmod>';

			$changefreq = '';

			if ($lastmod + 600 >= vB::getRequest()->getTimeNow()) // 10 mins
			{
				$changefreq = 'always';
			}
			else if ($lastmod + 3600 >= vB::getRequest()->getTimeNow()) // 1 hour
			{
				$changefreq = 'hourly';
			}
			else if ($lastmod + 86400 >= vB::getRequest()->getTimeNow()) // 1 day
			{
				$changefreq = 'daily';
			}
			else if ($lastmod + 604800 >= vB::getRequest()->getTimeNow()) // 1 week
			{
				$changefreq = 'weekly';
			}
			else if ($lastmod + 2629743 >= vB::getRequest()->getTimeNow()) // 1 month
			{
				$changefreq = 'monthly';
			}
			else     // Yearly, for yearly and in place of never
			{
				$changefreq = 'yearly';
			}

			$data .= $l .'<changefreq>' . $changefreq . '</changefreq>';
		}


		if ($pri !== false)
		{
			$data .= $l .'<priority>' . floatval($pri) . '</priority>';
		}

		$data .= "\n" . ($formatting ? "\t" : '')  . '</url>';

		return $data;
	}


	/**
	* Delete all sitemaps named : '*_sitemap.xml' '*_sitemap.xml.gz' 'sitemap_index.xml'
	*
	* @return	boolean		FALSE on any fails
	*/
	final function remove_sitemaps()
	{
		$path = resolve_server_path(vB::getDatastore()->getOption('sitemap_path'));
		$success = true;

		$all = scandir($path);
		foreach ($all AS $filename)
		{
			$is_index_file = (
				$filename == $this->sitemap_index_filename . '.xml'
				OR $filename == $this->sitemap_index_filename . '.xml.gz'
			);

			$is_sitemap_file = (
				substr($filename, 0, strlen($this->sitemap_filename_prefix)) == $this->sitemap_filename_prefix
				AND (substr($filename, -4) == '.xml' OR substr($filename, -7) == '.xml.gz')
			);

			if ($is_index_file OR $is_sitemap_file)
			{
				if (!@unlink("$path/$filename"))
				{
					$this->errors[] = "No Permission to delete sitemap : {$path}/{$filename}";
					$success = false;
				}

			}
		}

		return $success;
	}


	/**
	* Ping the search engines
	*
	* @return	none		A blind call, no return currently parsed
	*/
	public function ping_search_engines()
	{
		if (!$this->registry->options['sitemap_se_submit'])
		{
			// value of 0 in bitfield means all search engines are disabled
			return;
		}

		$map_url = urlencode($this->registry->options['bburl'] . "/xmlsitemap.php");

		$vurl = vB::getUrlLoader();
		foreach ($this->search_engines AS $bit_option => $callback_url)
		{
			if ($this->registry->options['sitemap_se_submit'] & $bit_option)
			{
				$vurl->get($callback_url . $map_url);
			}
		}
	}
}

/**
* Specific class for generating node-associated sitemaps. Used to generate channel sitemaps, but extended by
*	vB_SiteMap_Starter
*
* @package	vBulletin
*/
class vB_SiteMap_Node extends vB_SiteMap
{
	protected static $channels;
	/**
	* Constructor - checks that the registry object has been passed correctly.
	*
	* @param	vB_Registry		Instance of the vBulletin data registry object - expected to have the database object as one of its $this->db member.
	* @param 	vB_XML_Parser 	Instance of the vBulletin XML parser.
	*/
	public function __construct(vB_Registry $registry, vB_XML_Parser $xml_handler = null)
	{
		parent::__construct($registry, $xml_handler);

		$this->set_node_priorities();

	}

	protected function set_node_priorities()
	{
		$node_priorities = vB::getDbAssertor()->getRows('contentpriority', array('contenttypeid' => 'node'));

		foreach ($node_priorities AS $priority)
		{
			$this->custom_priority['node'][$priority['sourceid']] = $priority['prioritylevel'];
		}
	}

	public function get_node_priority($nodeid)
	{
		if (isset($this->custom_priority['node'][$nodeid]))
		{
			return $this->custom_priority['node'][$nodeid];
		}

		return false;
	}

	public function get_allowed_channels()
	{
		if (empty(self::$channels))
		{
			$guestChannels = vB_Api::instanceInternal('node')->getGuestChannels();	// grab all channels visible to guests.
			$guestChannels = array_keys($guestChannels);

			$specialChannel = vB_Api::instanceInternal('Content_Channel')->fetchChannelByGUID(vB_Channel::DEFAULT_CHANNEL_PARENT);
			if (is_array($specialChannel))
			{
				$specialChannel = $specialChannel['nodeid'];
			}

			$allChannels = vB_Api::instanceInternal('search')->getChannels(true);
			foreach($allChannels AS $key => $channel)
			{
				// since getChannels grabs all the channels, we have to unset
				// any that a guest can't see.
				if (!in_array($key, $guestChannels) OR ($key == $specialChannel))
				{
					unset($allChannels[$key]);
				}
			}

			self::$channels = $allChannels;
		}

		return self::$channels;
	}

	/**
	* Adds the URLs to $this->content
	*
	* @param 	int		forumdid to start at
	* @param 	int		perpage limit defaults to 30000
	*/
	public function generate_sitemap($startat = 0, $perpage = 30000)
	{
		$tempFilename = $this->sitemap_path . '/' . $this->tempfile;

		$fp = @fopen($tempFilename, 'a');


		if ($fp === false)
		{
			$this->errors[] = 'Error opening temporary file : ' . $tempFilename;
			return false;
		}

		$channels = $this->get_allowed_channels();
			// grab 1 extra for the "has_more" check.
		$channels = array_slice($channels, $startat * $perpage, $perpage + 1, true);

		$this->lastid = $startat;
		$this->has_more = false;


		foreach ($channels AS $node)
		{
			// is this one part of the next batch?
			if ($this->pagecount + 1 > $perpage)
			{
				$this->has_more = true;
				break;
			}

			$this->pagecount++;

			$priority = $this->get_effective_priority('node', $node['nodeid']);
			if($priority < 0)
			{
				continue;
			}

			$content = $this->url_block(
				vB5_Route::buildUrl("{$node['routeid']}|fullurl", array('nodeid' => $node['nodeid'])),
				$node['lastcontent'],
				$priority
			);
			fwrite($fp, $content);
		}

		fclose($fp);

		// Return the amout done
		return $this->pagecount;
	}
}


/**
* Specific class for generating topic starter sitemaps
*
* @package	vBulletin
*/
class vB_SiteMap_Starter extends vB_SiteMap_Node
{
	protected static $channels;
	/**
	* Constructor - checks that the registry object has been passed correctly.
	*
	* @param	vB_Registry		Instance of the vBulletin data registry object - expected to have the database object as one of its $this->db member.
	* @param 	vB_XML_Parser 	Instance of the vBulletin XML parser.
	*/
	public function __construct(vB_Registry $registry, vB_XML_Parser $xml_handler = null)
	{
		parent::__construct($registry, $xml_handler);
	}

	/**
	* Adds the URLs to $this->content
	*
	* @param 	int		forumdid to start at
	* @param 	int		perpage limit defaults to 30000
	*/
	public function generate_sitemap($startat = 0, $perpage = 30000)
	{
		$tempFilename = $this->sitemap_path . '/' . $this->tempfile;

		$fp = @fopen($tempFilename, 'a');

		if ($fp === false)
		{
			$this->errors[] = 'Error opening temporary file : ' . $tempFilename;
			return false;
		}

		$startersQry = vB::getDbAssertor()->assertQuery('vBAdminCP:getGuestVisibleNodes',
			array(
				'startat' => $startat,
				'perpage' => $perpage + 1,	// grab one extra for "has_more" check
			)
		);

		// todo: why did we need the below loop? Do we have duplicate rows in the query or something?
		$starters = array();
		foreach ($startersQry AS $node)
		{
			$args = unserialize($node['arguments']);
			$starters[$node['nodeid']] = array(
				'routeid' => $node['routeid'],
				'nodeid' => $node['nodeid'],
				'lastpost' => $node['lastcontent'],
				'urlident' => $node['urlident'],
				'prefix' => $node['prefix'],
				'ishomeroute' => $node['ishomeroute'],
				'customUrl' => !empty($args['customUrl']),
			);
		}

		$datastore = vB::getDatastore();
		$frontendurl = $datastore->getOption('frontendurl');
		$routebynode = $datastore->getOption('routebynode');

		$this->has_more = false;
		foreach ($starters AS $node)
		{
			// is this one part of the next batch?
			if ($this->pagecount + 1 > $perpage)
			{
				$this->has_more = true;
				break;
			}

			$this->pagecount++;
			$this->lastid = $node['nodeid'];

			// I don't *think* regular prefix has any slashes at the beginning or end, but just in case
			$prefix = trim($node['prefix'], '/');
			if($node['ishomeroute'])
			{
				$prefix = '';
			}


			/*
			 *	vB5_Route::buildUrl was having some memory issues, probably due to hundreds of route instances being
			 *	created etc. So below is a cheap way to generate the full URL. This has no concept of query strings
			 *	or anchor tags, but that's okay since we're only dealing with topic STARTERS here (so no page# needed.)
			 *	In short this is an extremely simplified version of vB5_Route_Conversation's buildUrl()
			 */
			if ($node['customUrl'])
			{
				$url = $frontendurl . '/' . $prefix;
			}
			else
			{
				if($routebynode)
				{
					$url = $frontendurl . '/node/' . $node['nodeid'];
				}
				else
				{
					$url = $frontendurl . '/' . $prefix;
			 		if($prefix)
					{
						$url .= '/';
					}
					$url .= $node['nodeid'] . '-' . $node['urlident'];
				}
			}

			if (strtolower(vB_String::getCharset()) != 'utf-8')
			{
				$url = vB_String::encodeUtf8Url($url);
			}

			$content = $this->url_block(
				$url,
				$node['lastpost'],
				$this->get_effective_priority('node', $node['nodeid'])
			);
			fwrite($fp, $content);
 		}

		fclose($fp);

		// Return the amout done
		return $this->pagecount;
	}
}


/**
* Specific class for generating non-node-associated sitemaps, ex custom pages
*
* @package	vBulletin
*/
class vB_SiteMap_Page extends vB_SiteMap
{
	/**
	* Constructor - checks that the registry object has been passed correctly.
	*
	* @param	vB_Registry		Instance of the vBulletin data registry object - expected to have the database object as one of its $this->db member.
	* @param 	vB_XML_Parser 	Instance of the vBulletin XML parser.
	*/
	public function __construct(vB_Registry $registry, vB_XML_Parser $xml_handler = null)
	{
		parent::__construct($registry, $xml_handler);
		$this->set_priorities();
	}

	protected function set_priorities()
	{
		$page_priorities = vB::getDbAssertor()->getRows('contentpriority', array('contenttypeid' => 'page'));
		foreach ($page_priorities AS $priority)
		{
			$this->custom_priority['page'][$priority['sourceid']] = $priority['prioritylevel'];
		}
	}

	public function get_priority($pageid)
	{
		if (isset($this->custom_priority['page'][$pageid]))
		{
			return $this->custom_priority['page'][$pageid];
		}

		return false;
	}

	public function get_pages($startat = 0, $perpage = 0)
	{
		// A list of names of pages to skip in the sitemap. Custom pages shouldn't have a name, as far as I'm aware.
		// The ones commented out are ones to include in the sitemap
		$skipPagesWithTheseNames = array(
			'advanced_search',	// any reason this should be in the sitemap?
			'register',
			'lostpw',
			//'contact-us',
			//'help',
			'online_details',	// only admins should be able to see this
			'media',			// not sure what this is
			'editphoto',
			'search',			// any reason this should be in the sitemap?
			'blog',				// associated with a node, no need to duplicate in the sitemaps
			'sghome',			// same as 'blog', associated with a node.
			'activateuser', 	// any reason this should be in the sitemap?
			'activateemail',	// any reason this should be in the sitemap?
			'coppa-form',
			'css-examples',	// dev page, no reason this should be in the sitemap
			//'member_list',
			'markup-library', // dev page, exclude from sitemap
			'api-form',
			'pmchat',
			'reset-password',
		);

		$db = vB::getDbAssertor();
		if (!empty($perpage))
		{
			$pagesQry = $db->assertQuery('vBAdminCP:getPagesForSitemapWithLimit',
				array(
					"skipped_names" => $skipPagesWithTheseNames,
					"startat" => $startat,
					"perpage" => $perpage + 1,	// grab 1 extra for "has_more" check
				)
			);
		}
		else
		{
			$pagesQry = $db->assertQuery('vBAdminCP:getPagesForSitemap',
				array(
					"skipped_names" => $skipPagesWithTheseNames,
				)
			);
		}

		$pages = array();
		$titlePhraseKeys = array();
		foreach ($pagesQry AS $page)
		{
			$titlePhraseKeys[$page['pageid']] = 'page_' . vB_Library::instance('phrase')->cleanGuidForPhrase($page['guid']) . '_title';
			$page['url'] = vB5_Route::buildUrl("{$page['routeid']}|fullurl", array());
			unset($page['guid']);
			$pages[$page['pageid']] = $page;
		}

		// fetch title phrases in bulk
		$phrases = vB_Api::instanceInternal('phrase')->fetch($titlePhraseKeys);
		foreach ($pages AS $prefix => &$page)
		{
			$page['title'] = $phrases[$titlePhraseKeys[$page['pageid']]];
		}

		return $pages;
	}

	/**
	* Adds the URLs to $this->content
	*
	* @param 	int		forumdid to start at
	* @param 	int		perpage limit defaults to 30000
	*/
	public function generate_sitemap($startat = 0, $perpage = 30000)
	{
		$tempFilename = $this->sitemap_path . '/' . $this->tempfile;

		$fp = @fopen($tempFilename, 'a');


		if ($fp === false)
		{
			$this->errors[] = 'Error opening temporary file : ' . $tempFilename;
			return false;
		}

		$pages = self::get_pages($startat, $perpage);

		$this->has_more = false;
		foreach ($pages AS $page)
		{
			// is this one part of the next batch?
			if ($this->pagecount + 1 > $perpage)
			{
				$this->has_more = true;
				break;
			}

			$this->pagecount++;
			$this->lastid = $page['pageid'];

			$priority = $this->get_effective_priority('page', $page['pageid']);
			if($priority < 0)
			{
				continue;
			}

			$content = $this->url_block(
				$page['url'],
				0,	// yearly change frequency. Need to figure out a better representative last change date here...
				$priority
			);
			fwrite($fp, $content);
		}

		fclose($fp);

		// Return the amout done
		return $this->pagecount;
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 102830 $
|| #######################################################################
\*=========================================================================*/
