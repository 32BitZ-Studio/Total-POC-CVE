<?php

class vB5_Config
{

	private static $instance;
	private static $defaults = array(
		'no_template_notices' => false,
		'debug' => false,
		'report_all_php_errors' => true,
		'report_all_ajax_errors' => false,
		'no_js_bundles' => false,
		'render_debug' => false,
	);
	private $config = array();


	public static function instance()
	{
		if (!isset(self::$instance))
		{
			$c = __CLASS__;
			self::$instance = new $c;
		}

		return self::$instance;
	}

	/**
	 *
	 * @param string $file
	 */
	public function loadConfigFile($file)
	{
		if (is_link(dirname($_SERVER["SCRIPT_FILENAME"])))
		{
			$frontendConfigPath = dirname(dirname(dirname($_SERVER["SCRIPT_FILENAME"]))) . '/' . $file;
		}
		else
		{
			$frontendConfigPath = dirname(__FILE__) . '/../../' . $file;
		}

		if (!file_exists($frontendConfigPath))
		{
			// Since we require removal of the install directory for live sites after the installation,
			// we should only treat this as "new install" if the makeconfig file exists.
			$makeConfigPath = dirname(__FILE__) . '/../../core/install/makeconfig.php';
			if (file_exists($makeConfigPath))
			{


				/*
					Ideally, we would redirect them to the install URL, but we're not sure where we're at, and
					without a config file and possibly no DB, we can't rely on bburl/frontendurl.
				 */
				require_once($makeConfigPath);
				exit;
			}
			// If the makeconfig file (& probably the install dir) isn't there and we don't have a config file, something is horribly wrong.
			// Let the regular handling below deal with it.
		}

		require_once($frontendConfigPath);
		if (!isset($config))
		{
			die("Couldn't read config file $file");
		}

		$this->config = array_merge(self::$defaults, $config);
	}

	public function __get($name)
	{
		if (isset($this->config[$name]))
		{
			return $this->config[$name];
		}
		else
		{
			$trace = debug_backtrace();
			trigger_error("Undefined config property '$name' in " .
					$trace[0]['file'] . ' on line ' .
					$trace[0]['line'], E_USER_NOTICE);
			return null;
		}
	}

}
