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

if (!isset($GLOBALS['vbulletin']->db))
{
	exit(1);
}

class vB_Upgrade_Cli extends vB_Upgrade_Abstract
{
	/*Constants=====================================================================*/

	/*Properties====================================================================*/
	/**
	* The vBulletin registry object
	*
	* @var	vB_Registry
	*/
	protected $registry = null;

	/**
	* The object that will be used to execute queries
	*
	* @var	vB_Database
	*/
	protected $db = null;

	/**
	* vB_Upgrade Object
	*
	* @var vB_Upgrade
	*/
	protected $upgrade = null;

	/**
	* Identifier for this library
	*
	* @var	string
	*/
	protected $identifier = 'cli';

	/**
	* Limit Step Queries
	*
	* @var	boolean
	*/
	protected $limitqueries = false;

	/**
	* Command Line Options
	*
	* @var	array
	*/
	protected $options = array();

	/**
	 * CLI called with single verion specified
	 * @var bool
	 */
	private $versionselect = false;

	/**
	 * Location of the CLI config file relative to the site root
	 * @var string
	 */
	private static $cli_config_file = "includes/config_cli.php";

	/**
	 *
	 * @var array
	 */
	private static $config_cli = null;

	/**
	 * Constructor.
	 *
	 * @param	vB_Registry	Reference to registry object
	 */
	public function __construct(&$registry, $phrases, $setuptype = 'upgrade', $version = null, $options = array())
	{
		parent::__construct($registry, $phrases, $setuptype, $version, $options);
	}

	/**
	 * Stuff to setup specific to CLI upgrading - executes after upgrade has been established
	 *
	 * 	@param	string	the script to be process
	 * 	@param	bool	whether to process the script immediately
	 */
	protected function init($script, $process = true)
	{
		define('SUPPRESS_KEEPALIVE_ECHO', true);

		parent::init($script);

		$this->process_options();

		if (!empty($this->startup_errors))
		{
			$this->echo_phrase($this->phrase['core']['startup_errors_desc'] . "\r\n");
			foreach ($this->startup_errors AS $error)
			{
				$this->echo_phrase("* $error\r\n");
			}
			return;
		}

		if (!empty($this->startup_warnings))
		{
			$this->echo_phrase($this->phrase['core']['startup_warnings_desc'] . "\r\n");
			foreach ($this->startup_warnings AS $error)
			{
				$this->echo_phrase("* $error\r\n");
			}

			$response = $this->prompt(
				$this->phrase['core']['startup_warnings_instructions_cli'],
				array('1','2')
			);

			//if its 2 we want to continue;
			if ($response == 1)
			{
				return;
			}
		}

		$version = isset($this->versions[$this->registry->cli['cliver']]) ? $this->registry->cli['cliver'] : false;

		// Where does this upgrade need to begin?
		if ($script)
		{
			$this->scriptinfo['version'] = $script;
		}
		else if ($version)
		{
			$this->versionselect = true;
			$this->scriptinfo['version'] = $version;
			$this->scriptinfo['only'] = $this->registry->cli['clionly'];
			unset($this->scriptinfo['step'], $this->scriptinfo['startat']);
		}
		else
		{
			$this->scriptinfo = $this->get_upgrade_start();
		}

		if ($process)
		{
			$version = $this->scriptinfo['version'];
			$singlescript = $this->registry->cli['clionly'];

			//if the first step is "final" we want to run it, otherwise
			//it gets handled in process_script as part of the last
			//version run.
			do
			{
				$version = $this->process_script($this->scriptinfo['version']);
				if ($version != 'final' AND !$singlescript)
				{
					$this->scriptinfo = $this->get_upgrade_start($version);
				}
			}	while ($version != 'final' AND !$singlescript);


			if ($this->registry->options['storecssasfile'])
			{
				$this->echo_phrase($this->convert_phrase($this->phrase['core']['after_upgrade_cli']));
			}
		}
	}

	/**
	* Process Command Line options on $this->options
	*
	*/
	private function process_options()
	{
		if (in_array('skip_template_merge', $_SERVER['argv']))
		{
			$this->options['skiptemplatemerge'] = true;
		}
	}

	/**
	* Echo a phrase after converting to console charset
	*
	* @var	string	Phrase to do charset conversion on for
	*
	*/
	private function echo_phrase($string)
	{
		if (strtoupper(substr(PHP_OS, 0, 3)) == 'WIN')
		{
			echo to_charset($string, 'ISO-8859-1', 'IBM850');
		}
		else
		{
			echo $string;
		}
	}

	/**
	*	Attempt to make a standard phrase, with HTML markup, useable by the CLI system
	*
	*	@var	string	Phrase to do HTML rudimentery replacement on
	*
	* @return string
	*/
	protected function convert_phrase($phrase)
	{
		$phrase = str_replace('\r\n', "\r\n", $phrase);
		$search = array(
			'#<br\s+/?' . '>#i',
			'#</p>#i',
			'#<p>#i',
		);
		$replace = array(
			"\r\n",
			"",
			"\r\n",
		);
		$phrase = strip_tags(preg_replace($search, $replace, $phrase));
		if (!(preg_match("#\r\n$#si", $phrase)))
		{
			$phrase .= "\r\n";
		}

		return $phrase;
	}

	/**
	* Process a script
	*
	* @var	string	script version
	* @var	string	execute a single script
	*/
	protected function process_script($version)
	{
		$script = $this->load_script($version);

		if (!$this->verify_version($version, $script) AND !$this->versionselect)
		{
			if ($version == 'final')
			{
				end($this->versions);
				$version = key($this->versions);
			}
			$response = $this->prompt(sprintf($this->phrase['core']['wrong_version_cli'],
				$this->versions[$version], $this->registry->options['templateversion']), array('1','2'));
		}

		if (!$response OR $response == 1)
		{
			$startstep = isset($this->scriptinfo['step']) ? $this->scriptinfo['step'] : 1;
			$endstep = $script->stepcount;

			$this->echo_phrase("\r\n");
			if (in_array($this->scriptinfo['version'], $this->endscripts))
			{
				$this->echo_phrase($this->convert_phrase($this->phrase['core']['processing_' . $this->scriptinfo['version']]));
			}
			else
			{
				// <!-- "upgradeing" is a purposeful typo -->
				$this->echo_phrase($this->convert_phrase(sprintf($this->phrase['core']['upgradeing_to_x'], $script->LONG_VERSION)));
			}
			$this->echo_phrase("----------------------------------\r\n");

			if ($endstep)
			{
				for ($x = $startstep; $x <= $endstep; $x++)
				{
					$this->echo_phrase(sprintf($this->phrase['core']['step_x'], $x));
					$this->execute_step($x, $script);
					$script->log_upgrade_step($x);
				}
			}
			else
			{
				$script->log_upgrade_step(0);
			}
			$this->echo_phrase($this->convert_phrase($this->phrase['core']['upgrade_complete']));
			$version = $script->SHORT_VERSION;
		}
		else
		{
			$version = $this->fetch_short_version($this->registry->options['templateversion']);
		}

		if ($endstep)
		{
			$this->process_script_end();
		}
		return $version;
	}

	/**
	* Executes the specified step
	*
	* @param	int			Step to execute
	* @param		object	upgrade script object
	* @param	boolen	Check if table exists for create table commands
	* @param	array		Data to send to step (startat, prompt results, etc)
	*
	*/
	public function execute_step($step, $script, $check_table = true, $data = null, $recurse = true)
	{
		try
		{
			$data['options'] = $this->options;
			$result = $script->execute_step($step, $check_table, $data);
		}
		catch (vB_Exception_Api $e)
		{
			foreach($e->get_errors() AS $error)
			{
				$message = $this->render_phrase_array($error);
				$message = "Error $message on " .  $e->getFile() . ' : ' . $e->getLine();
				$this->echo_phrase($this->convert_phrase($message));
				$this->echo_phrase(unhtmlspecialchars(vB_Utilities::getStackTrace()));
			}
			exit(7);
		}
		catch (Error $e)
		{
			$message = 'Error ' . $e->getMessage() . ' on ' .  $e->getFile() . ' : ' . $e->getLine();
			$this->echo_phrase($this->convert_phrase($message));
			$this->echo_phrase(unhtmlspecialchars(vB_Utilities::getStackTrace()));
			exit(7);
		}
		catch (Exception $e)
		{
			$message = 'Error ' . $e->getMessage() . ' on ' .  $e->getFile() . ' : ' . $e->getLine();
			$this->echo_phrase($this->convert_phrase($message));
			$this->echo_phrase(unhtmlspecialchars(vB_Utilities::getStackTrace()));
			exit(7);
		}


		$output = false;
		if ($result['message'])
		{
			$count = 0;
			foreach ($result['message'] AS $message)
			{
				if (trim($message['value']))
				{
					$output = true;
					if ($count > 0)
					{
						$this->echo_phrase(str_pad('  ', strlen(sprintf($this->phrase['core']['step_x'], $step)), ' ', STR_PAD_LEFT));
					}
					$this->echo_phrase($this->convert_phrase($message['value']));
					$count++;
				}
			}
		}

		if ($result['error'])
		{
			foreach($result['error'] AS $error)
			{
				if ($error['fatal'])
				{
					switch ($error['code'])
					{
						case vB_Upgrade_Version::MYSQL_HALT:
							$this->echo_phrase("\r\n----------------------------------\r\n");
							$this->echo_phrase($error['value']['error']);
							$this->echo_phrase("\r\n----------------------------------\r\n");
							$this->echo_phrase($error['value']['message']);
							exit(2);
							break;
						case vB_Upgrade_Version::PHP_TRIGGER_ERROR:
							trigger_error($this->convert_phrase($error['value']), E_USER_ERROR);
							break;
						case vB_Upgrade_Version::APP_CREATE_TABLE_EXISTS:
							$response = $this->prompt(sprintf($this->phrase['core']['tables_exist_cli'], $error['value']), array('1',''));
							if ($response !== '1')
							{
								exit(2);
							}
							else
							{
								$this->execute_step($step, $script, false);
								if (!$output)
								{
									$output = true;
								}
							}
							break;

						case vB_Upgrade_Version::CLI_CONF_USER_DATA_MISSING:
							$this->echo_phrase("\r\n\r\n--- CLI_CONFIG_FILE_ERRORS: ---\r\n\r\n");
							foreach ($error['value'] AS $key => $value)
							{
								$this->echo_phrase("\r\n- $value -\r\n");
							}
							exit(6);

							break;
						default:
							break;
					}
				}
			}
		}

		if (!$output)
		{
			$this->echo_phrase(str_pad('  ', strlen(sprintf($this->phrase['core']['step_x'], $step)), ' ', STR_PAD_LEFT));
			$this->echo_phrase($this->phrase['upgrade']['no_message'] . "\r\n");
		}

		if ($result['returnvalue']['startat'])
		{
			$script->log_upgrade_step($step, $result['returnvalue']['startat']);

			if ($recurse)
			{
				$args = $result['returnvalue'];
				do
				{
					$detailResult = $this->execute_step($step, $script, true, $args, FALSE);
					$args = $detailResult['returnvalue'];
				}
				while (!empty($detailResult['returnvalue']['startat']));
			}
			else
			{
				return $result;
			}
		}
		else if ($result['returnvalue']['prompt'])
		{
			$response = $this->prompt($result['returnvalue']['prompt']);
			$result = $this->execute_step($step, $script, true, array('response' => $response, 'startat' => $result['returnvalue']['startat']));
		}
		return $result;
	}

	/**
	 * Output a command prompt
	 *
	 * @var	string	String to echo
	 * @var	array		Accepted responses
	 *
	 * @return	string	Response value
	 */
	protected function prompt($value, $responses = null)
	{
		$count = 1;
		do
		{
			$this->echo_phrase("\r\n----------------------------------\r\n");
			$this->echo_phrase($this->convert_phrase($value));
			$this->echo_phrase('>');
			$response = trim(@fgets(STDIN));

			if ($count++ >= 10 )
			{
				//This should happen only when we're in a script.
				throw new Exception($this->phrase['install']['cli_no_valid_response'],100);
			}
		}
		while (!empty($responses) AND is_array($responses) AND !in_array($response, $responses));

		$this->db->ping();

		return $response;
	}

	/**
	 * Fetches database/system configuration file when called from CLI
	 */
	private static function fetch_config_cli()
	{
		// parse the config file
		if (file_exists(CWD . '/' . self::$cli_config_file))
		{
			include(CWD . '/' . self::$cli_config_file);
		}
		else
		{
			if (defined('STDIN'))
			{
				return 5;
			}
			echo ('<br /><br /><strong>Configuration</strong>: core/includes/config_cli.php does not exist. Please fill out the data in config_cli.php.new and rename it to config_cli.php');
			return;
		}

		// TODO: this should be handled with an exception, the backend shouldn't produce output
		if (sizeof($config_cli) == 0)
		{
			// config.php exists, but does not define $config
			if (defined('STDIN'))
			{
				return 5;
			}
			echo('<br /><br /><strong>Configuration</strong>: core/includes/config_cli.php exists, but is not in the 3.6+ format. Please fill out the data in config_cli.php.new and rename it to config_cli.php.');
			return;
		}
		self::$config_cli = $config_cli;
	}

	/**
	 * Returns a by-reference the cli-config object
	 * @return array
	 */
	public static function &getConfigCLI()
	{
		if (!isset(self::$config_cli)) {
			self::fetch_config_cli();
		}

		return self::$config_cli;
	}

	/**
	 * Loads and setting from the command-line configuration file
	 */
	public function loadDSSettingsfromConfig()
	{
		$cliConfig = vB_Upgrade_Cli::getConfigCLI();

		if (!empty($cliConfig['cli']['settings']) AND is_array($cliConfig['cli']['settings']))
		{
			$datastore = vB::getDatastore();
			foreach ($cliConfig['cli']['settings'] as $name => $value)
			{
				$datastore->setOption($name,  $value);
			}
		}
	}

}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
