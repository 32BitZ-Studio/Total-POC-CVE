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
* Fetch upgrade lib based on PHP environment
*
* @package 		vBulletin
* @version		$Revision: 104293 $
* @date 		$Date: 2020-03-03 09:40:39 -0800 (Tue, 03 Mar 2020) $
*
*/
class vB_Upgrade
{
	/**
	* Singleton emulation: Select library
	*
	*	@var	vB_Registry object
	*	@var	string	Override library detection routine
	* @var	boolean	Upgrade/true, Install/false
	*/
	public static function &fetch_library(&$registry, $phrases, $library = '', $upgrade = true, $script = null, $forcenew = false, $options = array())
	{
		global $show;
		static $instance = false;

		if (!$instance OR $forcenew)
		{
			if ($library)
			{
				$chosenlib = $library;
			}
			else
			{
				$chosenlib = self::isCLI() ? 'cli' : 'ajax';
			}

			$selectclass = 'vB_Upgrade_' . $chosenlib;
			echo $selectclass;
			$chosenlib = strtolower($chosenlib);

			//allow the caller to include the class if they want to put it somewhere else
			if (!class_exists($selectclass))
			{
				echo 1;
				require_once(DIR . '/install/includes/class_upgrade_' . $chosenlib . '.php');
			}
			echo 2;
			$instance = new $selectclass($registry, $phrases, $upgrade ? 'upgrade' : 'install', $script, $options);
			echo 3;
		}

		return $instance;
	}

	public static function fetch_language()
	{
		static $phrases = false;

		if (!$phrases)
		{
			$languagecode = defined('UPGRADE_LANGUAGE') ? UPGRADE_LANGUAGE : 'en';
			$xmlobj = new vB_XML_Parser(false, DIR . '/install/upgrade_language_' . $languagecode . '.xml');
			$xml = $xmlobj->parse(defined('UPGRADE_ENCODING') ? UPGRADE_ENCODING : 'ISO-8859-1');

			foreach ($xml['group'] AS $value)
			{
				if (isset($value['group']) AND is_array($value['group']))
				{
					// step phrases
					foreach($value['group'] AS $value2)
					{
						if (!isset($value2['phrase'][0]))
						{
							$value2['phrase'] = array($value2['phrase']);
						}
						foreach($value2['phrase'] AS $value3)
						{
							$phrases[$value['name']][$value2['name']][$value3['name']] = $value3['value'];
						}
					}
				}
				else
				{
					if (!isset($value['phrase'][0]))
					{
						$value['phrase'] = array($value['phrase']);
					}
					foreach ($value['phrase'] AS $value2)
					{
						$phrases[$value['name']][$value2['name']] = $value2['value'];
					}
				}
			}
			$GLOBALS['vbphrase'] =& $phrases['vbphrase'];
		}

		return $phrases;
	}

	/**
	 * When running from the command line we don't have a session. So if
	 * we want to use API functions we need to create one
	 *
	 */
	public static function createAdminSession()
	{
		$session = vB::getCurrentSession();

		if(empty($session) OR ($session->get('userid') <= 0))
		{
			$userid = vB_PermissionContext::getAdminUser();
			$session = new vB_Session_Cli(vB::getDbAssertor(), vB::getDatastore(), vB::getConfig(),  $userid);
			$session->fetchCpsessionHash();
			vB::setCurrentSession($session);
		}
	}

	/**
	 * PHP-CLI mode check
	 *
	 * @return boolean    Returns true if PHP is running from the CLI even if on CGI-mode, or else false.
	 *
	 */
	public static function isCLI()
	{
		if(!defined('STDIN') AND self::isCgi())
		{
			return empty($_SERVER['REQUEST_METHOD']);
		}

		return defined('STDIN');
	}

	/**
	 * PHP-CGI mode check
	 *
	 * @return boolean   Returns true if PHP is running as CGI module or else false.
	 *
	 */
	public static function isCgi()
	{
		return (substr(PHP_SAPI, 0, 3) == 'cgi');
	}
}

abstract class vB_Upgrade_Abstract
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
	* Array of Steps Objects
	*
	*	@var object
	*/
	public $steps = array();

	/**
	* Upgrade start point
	*
	*	@var array
	*/
	protected $scriptinfo = array(
		'version' => null,
		'startat' => 0,
		'perpage' => 20,
		'step'    => 1,
	);

	/**
	* Startup warning messages
	*
	*	@var array
	*/
	protected $startup_warnings = array();

	/**
	* XML file versions
	*
	*	@var array
	*/
	protected $xml_versions = array(
		'language'  => null,
		'style'     => null,
		'adminhelp' => null,
		'settings'  => null
	);

	/**
	* Array of vBulletin versions supported for upgrade
	*
	* @var array
	*/
	protected $versions = array(
		'35*'    => '354',	// allow any version 3.5.x version that is 3.5.4 and greater..
		'360b1'  => '3.6.0 Beta 1',
		'360b2'  => '3.6.0 Beta 2',
		'360b3'  => '3.6.0 Beta 3',
		'360b4'  => '3.6.0 Beta 4',
		'360rc1' => '3.6.0 Release Candidate 1',
		'360rc2' => '3.6.0 Release Candidate 2',
		'360rc3' => '3.6.0 Release Candidate 3',
		'360'    => '3.6.0',
		'361'    => '3.6.1',
		'362'    => '3.6.2',
		'363'    => '3.6.3',
		'364'    => '3.6.4',
		'365'    => '3.6.5',
		'366'    => '3.6.6',
		'367'    => '3.6.7',
		'368'    => '3.6.8',
		'36*'    => '',
		'370b2'  => '3.7.0 Beta 2',
		'370b3'  => '3.7.0 Beta 3',
		'370b4'  => '3.7.0 Beta 4',
		'370b5'  => '3.7.0 Beta 5',
		'370b6'  => '3.7.0 Beta 6',
		'370rc1' => '3.7.0 Release Candidate 1',
		'370rc2' => '3.7.0 Release Candidate 2',
		'370rc3' => '3.7.0 Release Candidate 3',
		'370rc4' => '3.7.0 Release Candidate 4',
		'370'    => '3.7.0',
		'371'    => '3.7.1',
		'37*'    => '',
		'380a2'  => '3.8.0 Alpha 2',
		'380b1'  => '3.8.0 Beta 1',
		'380b2'  => '3.8.0 Beta 2',
		'380b3'  => '3.8.0 Beta 3',
		'380b4'  => '3.8.0 Beta 4',
		'380rc1' => '3.8.0 Release Candidate 1',
		'380rc2' => '3.8.0 Release Candidate 2',
		'380'    => '3.8.0',
		'381'	 => '3.8.1',
		'382'	 => '3.8.2',
		'383'	 => '3.8.3',
		'384'	 => '3.8.4',
		'385'	 => '3.8.5',
		'386'	 => '3.8.6',
		'387b1'	 => '3.8.7 Beta 1',
		'387'	 => '3.8.7',
		'38*'    => '', // Skips past any other 3.8.x versions
		'400a1'  => '4.0.0 Alpha 1',
		'400a2'  => '4.0.0 Alpha 2',
		'400a3'  => '4.0.0 Alpha 3',
		'400a4'  => '4.0.0 Alpha 4',
		'400a5'  => '4.0.0 Alpha 5',
		'400a6'  => '4.0.0 Alpha 6',
		'400b1'  => '4.0.0 Beta 1',
		'400b2'  => '4.0.0 Beta 2',
		'400b3'  => '4.0.0 Beta 3',
		'400b4'  => '4.0.0 Beta 4',
		'400b5'  => '4.0.0 Beta 5',
		'400rc1' => '4.0.0 Release Candidate 1',
		'400rc2' => '4.0.0 Release Candidate 2',
		'400rc3' => '4.0.0 Release Candidate 3',
		'400rc4' => '4.0.0 Release Candidate 4',
		'400rc5' => '4.0.0 Release Candidate 5',
		'400'    => '4.0.0',
		'401'    => '4.0.1',
		'402'    => '4.0.2',
		'403'    => '4.0.3',
		'404'    => '4.0.4',
		'405'    => '4.0.5',
		'406'    => '4.0.6',
		'407'    => '4.0.7',
		'408'    => '4.0.8',
		'410b1'  => '4.1.0 Beta 1',
		'410'    => '4.1.0',
		'411a1'  => '4.1.1 Alpha 1',
		'411b1'  => '4.1.1 Beta 1',
		'411'    => '4.1.1',
		'412b1'  => '4.1.2 Beta 1',
		'412'    => '4.1.2',
		'413b1'  => '4.1.3 Beta 1',
		'413'    => '4.1.3',
		'414b1'  => '4.1.4 Beta 1',
		'414'    => '4.1.4',
		'415b1'  => '4.1.5 Beta 1',
		'415'    => '4.1.5',
		'416b1'  => '4.1.6 Beta 1',
		'416'    => '4.1.6',
		'417b1'  => '4.1.7 Beta 1',
		'417'    => '4.1.7',
		'418b1'  => '4.1.8 Beta 1',
		'418'    => '4.1.8',
		'419b1'  => '4.1.9 Beta 1',
		'419'    => '4.1.9',
		'4110a1' => '4.1.10 Alpha 1',
		'4110a2' => '4.1.10 Alpha 2',
		'4110a3' => '4.1.10 Alpha 3',
		'4110b1' => '4.1.10 Beta 1',
		'4110'   => '4.1.10',
		'4111a1' => '4.1.11 Alpha 1',
		'4111a2' => '4.1.11 Alpha 2',
		'4111b1' => '4.1.11 Beta 1',
		'4111b2' => '4.1.11 Beta 2',
		'4111'   => '4.1.11',
		'4112a1' => '4.1.12 Alpha 1',
		'4112b1' => '4.1.12 Beta 1',
		'4112b2' => '4.1.12 Beta 2',
		'4112'   => '4.1.12',
		'420a1'  => '4.2.0 Alpha 1',
		'420b1'  => '4.2.0 Beta 1',
		'420'    => '4.2.0',
		'421a1'  => '4.2.1 Alpha 1',
		'421b1'  => '4.2.1 Beta 1',
		'421'    => '4.2.1',
		'422a1'  => '4.2.2 Alpha 1',
		'422b1'  => '4.2.2 Beta 1',
		'422'    => '4.2.2',
		'423a1'  => '4.2.3 Alpha 1',
		'423b1'  => '4.2.3 Beta 1',
		'423b2'  => '4.2.3 Beta 2',
		'423b3'  => '4.2.3 Beta 3',
		'423b4'  => '4.2.3 Beta 4',
		'423rc1' => '4.2.3 Release Candidate 1',
		'423'    => '4.2.3',
		'424b1'  => '4.2.4 Beta 1',
		'424b2'  => '4.2.4 Beta 2',
		'424b3'  => '4.2.4 Beta 3',
		'424rc1' => '4.2.4 Release Candidate 1',
		'424rc2' => '4.2.4 Release Candidate 2',
		'424rc3' => '4.2.4 Release Candidate 3',
		'424'    => '4.2.4',
		'425a1'  => '4.2.5 Alpha 1',
		'425a2'  => '4.2.5 Alpha 2',
		'425a3'  => '4.2.5 Alpha 3',
		'425b1'  => '4.2.5 Beta 1',
		'425b2'  => '4.2.5 Beta 2',
		'425b3'  => '4.2.5 Beta 3',
		'425b4'  => '4.2.5 Beta 4',
		'425rc1' => '4.2.5 Release Candidate 1',
		'425rc2' => '4.2.5 Release Candidate 2',
		'425'    => '4.2.5',
		'500a1'  => '5.0.0 Alpha 1',
		'500a2'  => '5.0.0 Alpha 2',
		'500a3'  => '5.0.0 Alpha 3',
		'500a4'  => '5.0.0 Alpha 4',
		'500a5'  => '5.0.0 Alpha 5',
		'500a6'  => '5.0.0 Alpha 6',
		'500a7'  => '5.0.0 Alpha 7',
		'500a8'  => '5.0.0 Alpha 8',
		'500a9'  => '5.0.0 Alpha 9',
		'500a10' => '5.0.0 Alpha 10',
		'500a11' => '5.0.0 Alpha 11',
		'500a12' => '5.0.0 Alpha 12',
		'500a13' => '5.0.0 Alpha 13',
		'500a14' => '5.0.0 Alpha 14',
		'500a15' => '5.0.0 Alpha 15',
		'500a16' => '5.0.0 Alpha 16',
		'500a17' => '5.0.0 Alpha 17',
		'500a18' => '5.0.0 Alpha 18',
		'500a19' => '5.0.0 Alpha 19',
		'500a20' => '5.0.0 Alpha 20',
		'500a21' => '5.0.0 Alpha 21',
		'500a22' => '5.0.0 Alpha 22',
		'500a23' => '5.0.0 Alpha 23',
		'500a24' => '5.0.0 Alpha 24',
		'500a25' => '5.0.0 Alpha 25',
		'500a26' => '5.0.0 Alpha 26',
		'500a27' => '5.0.0 Alpha 27',
		'500a28' => '5.0.0 Alpha 28',
		'500a29' => '5.0.0 Alpha 29',
		'500a30' => '5.0.0 Alpha 30',
		'500a31' => '5.0.0 Alpha 31',
		'500a32' => '5.0.0 Alpha 32',
		'500a33' => '5.0.0 Alpha 33',
		'500a34' => '5.0.0 Alpha 34',
		'500a35' => '5.0.0 Alpha 35',
		'500a36' => '5.0.0 Alpha 36',
		'500a37' => '5.0.0 Alpha 37',
		'500a38' => '5.0.0 Alpha 38',
		'500a39' => '5.0.0 Alpha 39',
		'500a40' => '5.0.0 Alpha 40',
		'500a41' => '5.0.0 Alpha 41',
		'500a42' => '5.0.0 Alpha 42',
		'500a43' => '5.0.0 Alpha 43',
		'500a44' => '5.0.0 Alpha 44',
		'500a45' => '5.0.0 Alpha 45',
		'500b1'  => '5.0.0 Beta 1',
		'500b2'  => '5.0.0 Beta 2',
		'500b3'  => '5.0.0 Beta 3',
		'500b4'  => '5.0.0 Beta 4',
		'500b5'  => '5.0.0 Beta 5',
		'500b6'  => '5.0.0 Beta 6',
		'500b7'  => '5.0.0 Beta 7',
		'500b8'  => '5.0.0 Beta 8',
		'500b9'  => '5.0.0 Beta 9',
		'500b10' => '5.0.0 Beta 10',
		'500b11' => '5.0.0 Beta 11',
		'500b12' => '5.0.0 Beta 12',
		'500b13' => '5.0.0 Beta 13',
		'500b14' => '5.0.0 Beta 14',
		'500b15' => '5.0.0 Beta 15',
		'500b16' => '5.0.0 Beta 16',
		'500b17' => '5.0.0 Beta 17',
		'500b18' => '5.0.0 Beta 18',
		'500b19' => '5.0.0 Beta 19',
		'500b20' => '5.0.0 Beta 20',
		'500b21' => '5.0.0 Beta 21',
		'500b22' => '5.0.0 Beta 22',
		'500b23' => '5.0.0 Beta 23',
		'500b24' => '5.0.0 Beta 24',
		'500b25' => '5.0.0 Beta 25',
		'500b26' => '5.0.0 Beta 26',
		'500b27' => '5.0.0 Beta 27',
		'500b28' => '5.0.0 Beta 28',
		'500rc1' => '5.0.0 Release Candidate 1',
		'500'    => '5.0.0',
		'501a1'  => '5.0.1 Alpha 1',
		'501a2'  => '5.0.1 Alpha 2',
		'501rc1' => '5.0.1 Release Candidate 1',
		'501'    => '5.0.1',
		'502a1'  => '5.0.2 Alpha 1',
		'502a2'  => '5.0.2 Alpha 2',
		'502b1'  => '5.0.2 Beta 1',
		'502rc1' => '5.0.2 Release Candidate 1',
		'502'    => '5.0.2',
		'503a1'  => '5.0.3 Alpha 1',
		'503a2'  => '5.0.3 Alpha 2',
		'503a3'  => '5.0.3 Alpha 3',
		'503b1'  => '5.0.3 Beta 1',
		'503rc1' => '5.0.3 Release Candidate 1',
		'503'    => '5.0.3',
		'504a1'  => '5.0.4 Alpha 1',
		'504a2'  => '5.0.4 Alpha 2',
		'504a3'  => '5.0.4 Alpha 3',
		'504rc1' => '5.0.4 Release Candidate 1',
		'504'    => '5.0.4',
		'505a1'  => '5.0.5 Alpha 1',
		'505a2'  => '5.0.5 Alpha 2',
		'505a3'  => '5.0.5 Alpha 3',
		'505a4'  => '5.0.5 Alpha 4',
		'505rc1' => '5.0.5 Release Candidate 1',
		'505rc2' => '5.0.5 Release Candidate 2',
		'505'    => '5.0.5',
		'506a1'  => '5.0.6 Alpha 1',
		'506'    => '5.0.6',
		'510a1'  => '5.1.0 Alpha 1',
		'510a2'  => '5.1.0 Alpha 2',
		'510a3'  => '5.1.0 Alpha 3',
		'510a4'  => '5.1.0 Alpha 4',
		'510a5'  => '5.1.0 Alpha 5',
		'510a6'  => '5.1.0 Alpha 6',
		'510a7'  => '5.1.0 Alpha 7',
		'510a8'  => '5.1.0 Alpha 8',
		'510a9'  => '5.1.0 Alpha 9',
		'510b1'  => '5.1.0 Beta 1',
		'510b2'  => '5.1.0 Beta 2',
		'510b3'  => '5.1.0 Beta 3',
		'510b4'  => '5.1.0 Beta 4',
		'510rc1' => '5.1.0 Release Candidate 1',
		'510'    => '5.1.0',
		'511a1'  => '5.1.1 Alpha 1',
		'511a2'  => '5.1.1 Alpha 2',
		'511a3'  => '5.1.1 Alpha 3',
		'511a4'  => '5.1.1 Alpha 4',
		'511a5'  => '5.1.1 Alpha 5',
		'511a6'  => '5.1.1 Alpha 6',
		'511a7'  => '5.1.1 Alpha 7',
		'511a8'  => '5.1.1 Alpha 8',
		'511a9'  => '5.1.1 Alpha 9',
		'511a10' => '5.1.1 Alpha 10',
		'511a11' => '5.1.1 Alpha 11',
		'511rc1' => '5.1.1 Release Candidate 1',
		'511'    => '5.1.1',
		'512a1'  => '5.1.2 Alpha 1',
		'512a2'  => '5.1.2 Alpha 2',
		'512a3'  => '5.1.2 Alpha 3',
		'512a4'  => '5.1.2 Alpha 4',
		'512a5'  => '5.1.2 Alpha 5',
		'512a6'  => '5.1.2 Alpha 6',
		'512b1'  => '5.1.2 Beta 1',
		'512b2'  => '5.1.2 Beta 2',
		'512rc1' => '5.1.2 Release Candidate 1',
		'512rc2' => '5.1.2 Release Candidate 2',
		'512'    => '5.1.2',
		'513a1'  => '5.1.3 Alpha 1',
		'513a2'  => '5.1.3 Alpha 2',
		'513a3'  => '5.1.3 Alpha 3',
		'513a4'  => '5.1.3 Alpha 4',
		'513a5'  => '5.1.3 Alpha 5',
		'513a6'  => '5.1.3 Alpha 6',
		'513b1'  => '5.1.3 Beta 1',
		'513b2'  => '5.1.3 Beta 2',
		'513rc1' => '5.1.3 Release Candidate 1',
		'513'    => '5.1.3',
		'514a1'  => '5.1.4 Alpha 1',
		'514a2'  => '5.1.4 Alpha 2',
		'514a3'  => '5.1.4 Alpha 3',
		'514a4'  => '5.1.4 Alpha 4',
		'514a5'  => '5.1.4 Alpha 5',
		'514a6'  => '5.1.4 Alpha 6',
		'514a7'  => '5.1.4 Alpha 7',
		'514a8'  => '5.1.4 Alpha 8',
		'514b1'  => '5.1.4 Beta 1',
		'514b2'  => '5.1.4 Beta 2',
		'514b3'  => '5.1.4 Beta 3',
		'514rc1' => '5.1.4 Release Candidate 1',
		'514'    => '5.1.4',
		'515a1'  => '5.1.5 Alpha 1',
		'515a2'  => '5.1.5 Alpha 2',
		'515a3'  => '5.1.5 Alpha 3',
		'515a4'  => '5.1.5 Alpha 4',
		'515a5'  => '5.1.5 Alpha 5',
		'515a6'  => '5.1.5 Alpha 6',
		'515a7'  => '5.1.5 Alpha 7',
		'515a8'  => '5.1.5 Alpha 8',
		'515b1'  => '5.1.5 Beta 1',
		'515b2'  => '5.1.5 Beta 2',
		'515b3'  => '5.1.5 Beta 3',
		'515'    => '5.1.5',
		'516a1'  => '5.1.6 Alpha 1',
		'516a2'  => '5.1.6 Alpha 2',
		'516a3'  => '5.1.6 Alpha 3',
		'516a4'  => '5.1.6 Alpha 4',
		'516a5'  => '5.1.6 Alpha 5',
		'516a6'  => '5.1.6 Alpha 6',
		'516a7'  => '5.1.6 Alpha 7',
		'516b1'  => '5.1.6 Beta 1',
		'516b2'  => '5.1.6 Beta 2',
		'516rc1' => '5.1.6 Release Candidate 1',
		'516'    => '5.1.6',
		'517a1'  => '5.1.7 Alpha 1',
		'517a2'  => '5.1.7 Alpha 2',
		'517a3'  => '5.1.7 Alpha 3',
		'517a4'  => '5.1.7 Alpha 4',
		'517a5'  => '5.1.7 Alpha 5',
		'517b1'  => '5.1.7 Beta 1',
		'517b2'  => '5.1.7 Beta 2',
		'517b3'  => '5.1.7 Beta 3',
		'517rc1' => '5.1.7 Release Candidate 1',
		'517'    => '5.1.7',
		'518a1'  => '5.1.8 Alpha 1',
		'518a2'  => '5.1.8 Alpha 2',
		'518a3'  => '5.1.8 Alpha 3',
		'518a4'  => '5.1.8 Alpha 4',
		'518a5'  => '5.1.8 Alpha 5',
		'518a6'  => '5.1.8 Alpha 6',
		'518a7'  => '5.1.8 Alpha 7',
		'518a8'  => '5.1.8 Alpha 8',
		'518rc1' => '5.1.8 Release Candidate 1',
		'518'    => '5.1.8',
		'519a1'  => '5.1.9 Alpha 1',
		'519a2'  => '5.1.9 Alpha 2',
		'519a3'  => '5.1.9 Alpha 3',
		'519a4'  => '5.1.9 Alpha 4',
		'519a5'  => '5.1.9 Alpha 5',
		'519a6'  => '5.1.9 Alpha 6',
		'519b1'  => '5.1.9 Beta 1',
		'519b2'  => '5.1.9 Beta 2',
		'519rc1' => '5.1.9 Release Candidate 1',
		'519rc2' => '5.1.9 Release Candidate 2',
		'519'    => '5.1.9',
		'5110a1' => '5.1.10 Alpha 1',
		'5110a2' => '5.1.10 Alpha 2',
		'5110a3' => '5.1.10 Alpha 3',
		'5110a4' => '5.1.10 Alpha 4',
		'5110a5' => '5.1.10 Alpha 5',
		'5110b1' => '5.1.10 Beta 1',
		'5110b2' => '5.1.10 Beta 2',
		'5110b3' => '5.1.10 Beta 3',
		'5110rc1' => '5.1.10 Release Candidate 1',
		'5110rc2'   => '5.1.10 Release Candidate 2',
		'5110'      => '5.1.10',
		'5111a1' => '5.1.11 Alpha 1',
		'5111a2' => '5.1.11 Alpha 2',
		'520a1'  => '5.2.0 Alpha 1',
		'520a2'  => '5.2.0 Alpha 2',
		'520a3'     => '5.2.0 Alpha 3',
		'520b1'     => '5.2.0 Beta 1',
		'520b2'     => '5.2.0 Beta 2',
		'520rc1'    => '5.2.0 Release Candidate 1',
		'520rc2'    => '5.2.0 Release Candidate 2',
		'520'       => '5.2.0',
		'521a1'     => '5.2.1 Alpha 1',
		'521a2'     => '5.2.1 Alpha 2',
		'521a3'     => '5.2.1 Alpha 3',
		'521a4'     => '5.2.1 Alpha 4',
		'521a5'     => '5.2.1 Alpha 5',
		'521a6'     => '5.2.1 Alpha 6',
		'521b1'     => '5.2.1 Beta 1',
		'521b2'     => '5.2.1 Beta 2',
		'521rc1'    => '5.2.1 Release Candidate 1',
		'521rc2'    => '5.2.1 Release Candidate 2',
		'521rc3'    => '5.2.1 Release Candidate 3',
		'521'       => '5.2.1',
		'522a1'     => '5.2.2 Alpha 1',
		'522a2'     => '5.2.2 Alpha 2',
		'522a3'     => '5.2.2 Alpha 3',
		'522a4'     => '5.2.2 Alpha 4',
		'522a5'     => '5.2.2 Alpha 5',
		'522b1'     => '5.2.2 Beta 1',
		'522b2'     => '5.2.2 Beta 2',
		'522rc1'    => '5.2.2 Release Candidate 1',
		'522'       => '5.2.2',
		'523a1'     => '5.2.3 Alpha 1',
		'523a2'     => '5.2.3 Alpha 2',
		'523a3'     => '5.2.3 Alpha 3',
		'523a4'     => '5.2.3 Alpha 4',
		'523a5'     => '5.2.3 Alpha 5',
		'523a6'     => '5.2.3 Alpha 6',
		'523b1'     => '5.2.3 Beta 1',
		'523b2'     => '5.2.3 Beta 2',
		'523rc1'    => '5.2.3 Release Candidate 1',
		'523rc2'    => '5.2.3 Release Candidate 2',
		'523rc3'    => '5.2.3 Release Candidate 3',
		'523rc4'    => '5.2.3 Release Candidate 4',
		'523'       => '5.2.3',
		'524a1'     => '5.2.4 Alpha 1',
		'524a2'     => '5.2.4 Alpha 2',
		'524a3'     => '5.2.4 Alpha 3',
		'524a4'     => '5.2.4 Alpha 4',
		'524a5'     => '5.2.4 Alpha 5',
		'524b1'     => '5.2.4 Beta 1',
		'524rc1'    => '5.2.4 Release Candidate 1',
		'524rc2'    => '5.2.4 Release Candidate 2',
		'524rc3'    => '5.2.4 Release Candidate 3',
		'524rc4'    => '5.2.4 Release Candidate 4',
		'524'       => '5.2.4',
		'525a1'     => '5.2.5 Alpha 1',
		'525a2'     => '5.2.5 Alpha 2',
		'525a3'     => '5.2.5 Alpha 3',
		'525a4'     => '5.2.5 Alpha 4',
		'525a5'     => '5.2.5 Alpha 5',
		'525a6'     => '5.2.5 Alpha 6',
		'525rc1'    => '5.2.5 Release Candidate 1',
		'525'       => '5.2.5',
		'526a1'     => '5.2.6 Alpha 1',
		'526a2'     => '5.2.6 Alpha 2',
		'526a3'     => '5.2.6 Alpha 3',
		'526a4'     => '5.2.6 Alpha 4',
		'526a5'     => '5.2.6 Alpha 5',
		'526a6'     => '5.2.6 Alpha 6',
		'526b1'     => '5.2.6 Beta 1',
		'526b2'     => '5.2.6 Beta 2',
		'526rc1'    => '5.2.6 Release Candidate 1',
		'526rc2'    => '5.2.6 Release Candidate 2',
		'526'       => '5.2.6',
		'527a1'     => '5.2.7 Alpha 1',
		'527a2'     => '5.2.7 Alpha 2',
		'527a3'     => '5.2.7 Alpha 3',
		'527a4'     => '5.2.7 Alpha 4',
		'530a1'     => '5.3.0 Alpha 1',
		'530b1'     => '5.3.0 Beta 1',
		'530b2'     => '5.3.0 Beta 2',
		'530rc1'    => '5.3.0 Release Candidate 1',
		'530'       => '5.3.0',
		'531a1'     => '5.3.1 Alpha 1',
		'531a2'     => '5.3.1 Alpha 2',
		'531a3'     => '5.3.1 Alpha 3',
		'531a4'     => '5.3.1 Alpha 4',
		'531b1'     => '5.3.1 Beta 1',
		'531b2'     => '5.3.1 Beta 2',
		'531rc1'    => '5.3.1 Release Candidate 1',
		'531'       => '5.3.1',
		'532a1'     => '5.3.2 Alpha 1',
		'532a2'     => '5.3.2 Alpha 2',
		'532a3'     => '5.3.2 Alpha 3',
		'532a4'     => '5.3.2 Alpha 4',
		'532b1'     => '5.3.2 Beta 1',
		'532b2'     => '5.3.2 Beta 2',
		'532rc1'    => '5.3.2 Release Candidate 1',
		'532rc2'    => '5.3.2 Release Candidate 2',
		'532'       => '5.3.2',
		'533a1'     => '5.3.3 Alpha 1',
		'533a2'     => '5.3.3 Alpha 2',
		'533a3'     => '5.3.3 Alpha 3',
		'533a4'     => '5.3.3 Alpha 4',
		'533b1'     => '5.3.3 Beta 1',
		'533b2'     => '5.3.3 Beta 2',
		'533rc1'    => '5.3.3 Release Candidate 1',
		'533rc2'    => '5.3.3 Release Candidate 2',
		'533rc3'    => '5.3.3 Release Candidate 3',
		'533'       => '5.3.3',
		'534a1'     => '5.3.4 Alpha 1',
		'534a2'     => '5.3.4 Alpha 2',
		'534a3'     => '5.3.4 Alpha 3',
		'534a4'     => '5.3.4 Alpha 4',
		'534b1'     => '5.3.4 Beta 1',
		'534b2'     => '5.3.4 Beta 2',
		'534rc1'    => '5.3.4 Release Candidate 1',
		'534rc2'    => '5.3.4 Release Candidate 2',
		'534rc3'    => '5.3.4 Release Candidate 3',
		'534'       => '5.3.4',
		'535a1'     => '5.3.5 Alpha 1',
		'535a2'     => '5.3.5 Alpha 2',
		'535a3'     => '5.3.5 Alpha 3',
		'535a4'     => '5.3.5 Alpha 4',
		'540a1'     => '5.4.0 Alpha 1',
		'540b1'     => '5.4.0 Beta 1',
		'540b2'     => '5.4.0 Beta 2',
		'540rc1'    => '5.4.0 Release Candidate 1',
		'540rc2'    => '5.4.0 Release Candidate 2',
		'540rc3'    => '5.4.0 Release Candidate 3',
		'540'       => '5.4.0',
		'541a1'     => '5.4.1 Alpha 1',
		'541a2'     => '5.4.1 Alpha 2',
		'541a3'     => '5.4.1 Alpha 3',
		'541a4'     => '5.4.1 Alpha 4',
		'541b1'     => '5.4.1 Beta 1',
		'541b2'     => '5.4.1 Beta 2',
		'541rc1'    => '5.4.1 Release Candidate 1',
		'541'       => '5.4.1',
		'542a1'     => '5.4.2 Alpha 1',
		'542a2'     => '5.4.2 Alpha 2',
		'542a3'     => '5.4.2 Alpha 3',
		'542a4'     => '5.4.2 Alpha 4',
		'542b1'     => '5.4.2 Beta 1',
		'542b2'     => '5.4.2 Beta 2',
		'542rc1'    => '5.4.2 Release Candidate 1',
		'542rc2'    => '5.4.2 Release Candidate 2',
		'542'       => '5.4.2',
		'543a1'     => '5.4.3 Alpha 1',
		'543a2'     => '5.4.3 Alpha 2',
		'543a3'     => '5.4.3 Alpha 3',
		'543a4'     => '5.4.3 Alpha 4',
		'543b1'     => '5.4.3 Beta 1',
		'543b2'     => '5.4.3 Beta 2',
		'543rc1'    => '5.4.3 Release Candidate 1',
		'543'       => '5.4.3',
		'544a1'     => '5.4.4 Alpha 1',
		'544a2'     => '5.4.4 Alpha 2',
		'544a3'     => '5.4.4 Alpha 3',
		'544a4'     => '5.4.4 Alpha 4',
		'544b1'     => '5.4.4 Beta 1',
		'544b2'     => '5.4.4 Beta 2',
		'544rc1'    => '5.4.4 Release Candidate 1',
		'544'       => '5.4.4',
		'545a1'     => '5.4.5 Alpha 1',
		'545a2'     => '5.4.5 Alpha 2',
		'545a3'     => '5.4.5 Alpha 3',
		'545a4'     => '5.4.5 Alpha 4',
		'545b1'     => '5.4.5 Beta 1',
		'545b2'     => '5.4.5 Beta 2',
		'545rc1'    => '5.4.5 Release Candidate 1',
		'545'       => '5.4.5',
		'546a1'     => '5.4.6 Alpha 1',
		'546a2'     => '5.4.6 Alpha 2',
		'550a1'     => '5.5.0 Alpha 1',
		'550a2'     => '5.5.0 Alpha 2',
		'550b1'     => '5.5.0 Beta 1',
		'550b2'     => '5.5.0 Beta 2',
		'550rc1'    => '5.5.0 Release Candidate 1',
		'550rc2'    => '5.5.0 Release Candidate 2',
		'550'       => '5.5.0',
		'551a1'     => '5.5.1 Alpha 1',
		'551a2'     => '5.5.1 Alpha 2',
		'551a3'     => '5.5.1 Alpha 3',
		'551a4'     => '5.5.1 Alpha 4',
		'551b1'     => '5.5.1 Beta 1',
		'551b2'     => '5.5.1 Beta 2',
		'551rc1'    => '5.5.1 Release Candidate 1',
		'551'       => '5.5.1',
		'552a1'     => '5.5.2 Alpha 1',
		'552a2'     => '5.5.2 Alpha 2',
		'552a3'     => '5.5.2 Alpha 3',
		'552a4'     => '5.5.2 Alpha 4',
		'552b1'     => '5.5.2 Beta 1',
		'552b2'     => '5.5.2 Beta 2',
		'552rc1'    => '5.5.2 Release Candidate 1',
		'552rc2'    => '5.5.2 Release Candidate 2',
		'552'       => '5.5.2',
		'553a1'     => '5.5.3 Alpha 1',
		'553a2'     => '5.5.3 Alpha 2',
		'553a3'     => '5.5.3 Alpha 3',
		'553a4'     => '5.5.3 Alpha 4',
		'553b1'     => '5.5.3 Beta 1',
		'553b2'     => '5.5.3 Beta 2',
		'553rc1'    => '5.5.3 Release Candidate 1',
		'553rc2'    => '5.5.3 Release Candidate 2',
		'553'       => '5.5.3',
		'554a1'     => '5.5.4 Alpha 1',
		'554a2'     => '5.5.4 Alpha 2',
		'554a3'     => '5.5.4 Alpha 3',
		'554a4'     => '5.5.4 Alpha 4',
		'554b1'     => '5.5.4 Beta 1',
		'554b2'     => '5.5.4 Beta 2',
		'554rc1'    => '5.5.4 Release Candidate 1',
		'554'       => '5.5.4',
		'555a1'     => '5.5.5 Alpha 1',
		'555a2'     => '5.5.5 Alpha 2',
		'555a3'     => '5.5.5 Alpha 3',
		'555a4'     => '5.5.5 Alpha 4',
		'555b1'     => '5.5.5 Beta 1',
		'555b2'     => '5.5.5 Beta 2',
		'555rc1'    => '5.5.5 Release Candidate 1',
		'555'       => '5.5.5',
		'556a1'     => '5.5.6 Alpha 1',
		'556a2'     => '5.5.6 Alpha 2',
		'556a3'     => '5.5.6 Alpha 3',
		'556a4'     => '5.5.6 Alpha 4',
		'556b1'     => '5.5.6 Beta 1',
		'556b2'     => '5.5.6 Beta 2',
		'556rc1'    => '5.5.6 Release Candidate 1',
		'556rc2'    => '5.5.6 Release Candidate 2',
		'556rc3'    => '5.5.6 Release Candidate 3',
		'556'       => '5.5.6',
		'557a1'     => '5.5.7 Alpha 1',
		'557a2'     => '5.5.7 Alpha 2',
		'560a1'     => '5.6.0 Alpha 1',
		'560a2'     => '5.6.0 Alpha 2',
		'560b1'     => '5.6.0 Beta 1',
		'560b2'     => '5.6.0 Beta 2',
		'560rc1'    => '5.6.0 Release Candidate 1',
		'560rc2'    => '5.6.0 Release Candidate 2',
		'560'       => '5.6.0',
	);

	/**
	* Array of non vB version scripts. 'final' must be at the end
	*
	* @var array
	*/
	protected $endscripts = array(
		'final',
	);

	/**
	* Array of products installed by suite
	*
	* @var array
	*/
	protected $products = array(
	);

	/**
	* Execution type, either 'browser' or 'cli'
	*
	* @var string
	*/
	protected $exectype = null;

	/**
	* Phrases
	*
	* @var	array
	*/
	protected $phrase = array();

	/**
	* Startup Errors
	*
	* @var	array
	*/
	protected $startup_errors = array();

	/**
	* Setup type, new install or upgrade?
	*
	* @var	string
	*/
	protected $setuptype = 'upgrade';

	/**
	* Constructor.
	*
	* @param	vB_Registry	Reference to registry object
	* @var	string	Setup type - 'install' or 'upgrade'
	*/
	public function __construct(&$registry, $phrases, $setuptype = 'upgrade', $script = null, $options = array())
	{
		echo 7;

		if (empty($registry))
		{
			$registry = vB::get_registry();
		}

		if (is_object($registry))
		{
			$this->registry =& $registry;
			$this->db =& $this->registry->db;
		}
		else
		{
			trigger_error('vB_Upgrade: $this->registry is not an object.', E_USER_ERROR);
		}

		$this->setuptype = $setuptype;
		$this->phrase = $phrases;

		require_once(DIR . '/includes/adminfunctions.php');

		$this->verify_environment();
		$this->setup_environment();
		$this->sync_database();

		$config = vB::getConfig();
		if (!empty($config['Misc']['debug']) AND file_exists(DIR . "/install/includes/class_upgrade_dev.php"))
		{
			array_unshift($this->endscripts, 'dev');
		}


		if (isset($options['execute']))
		{
			$this->init($script, $options['execute']);
		}
		else
		{
			$this->init($script);
			
		}
	}

	/**
	* Init
	*
	*  	@param	string	the script to be process
	* 	@param	bool	whether to process the script immediately
	*/
	protected function init($script, $process = true)
	{
		if (!defined('SKIPDB'))
		{
			if ($_REQUEST['firstrun'] == 'true' OR $_REQUEST['step'] == 1 OR $this->identifier == 'cli')
			{
				vB_Upgrade::createAdminSession();
				require_once(DIR . '/includes/class_bitfield_builder.php');
				vB_Bitfield_Builder::save($this->db);
			}
		}
		//Set version number, its needed by the upgrader.
		$this->registry->versionnumber =& $this->registry->options['templateversion'];

		// Where does this upgrade need to begin?
		$this->scriptinfo = $this->get_upgrade_start();
	}

	/**
	* Things to do after each script is processed
	*
	*/
	protected function process_script_end()
	{
		build_bbcode_cache();
		$this->registry->options = build_options();
		require_once(DIR . '/includes/functions_databuild.php');
		vB_Upgrade::createAdminSession();
		require_once(DIR . '/includes/class_bitfield_builder.php');
		vB_Bitfield_Builder::save($this->db);
	}

	/**
	*	Load an upgrade script and return object
	*
	*	@var	string	Version number
	*
	* @return object
	*/
	protected function load_script($version)
	{
		$versions = array_merge($this->endscripts, array_keys($this->versions), array('install'));
		$versions = array_filter($versions, function($var) {return !(strpos($var, '*'));});

		// ensure comparisons are done as strings
		$versions = array_map('strval', $versions);
		$version = (string) $version;

		$versionfile = DIR . "/install/includes/class_upgrade_$version.php";

		if(file_exists($versionfile))
		{
			require_once($versionfile);
			$classname = "vB_Upgrade_$version";
			$script = new $classname($this->registry, $this->phrase, end($this->versions));
		}
		else
		{
			//this version doesn't have it's own file
			$script = new vB_Upgrade_Version_Empty($this->registry, $this->phrase, $version, $this->versions);
		}

		$script->caller = $this->identifier;
		$script->limitqueries = $this->limitqueries;

		return $script;
	}

	/**
	*	Verify if specified version number is the next version that we should be upgrading to
	*
	*	@var	string	Version number
	*
	* @return bool
	*/
	protected function verify_version($version, $script)
	{
		if ($version == 'install')
		{
			return true;
		}

		if (
			version_compare($this->registry->options['templateversion'], $script->VERSION_COMPAT_STARTS, '>=') AND
			version_compare($this->registry->options['templateversion'], $script->VERSION_COMPAT_ENDS, '<')
		)
		{
			return true;
		}
		else if ($this->registry->options['templateversion'] == $script->PREV_VERSION)
		{
			return true;
		}
		else if (in_array($version, $this->endscripts) AND end($this->versions) == $this->registry->options['templateversion'])
		{
			return true;
		}
		else
		{
			return false;
		}
	}

	/**
	* Fetch the upgrade log information from the database - past upgrade process
	*
	* @var		string	If defined, start upgrade at this version
	*
	* @return	array	Version information about upgrade point at which to start
	*/
	protected function get_upgrade_start($version = null)
	{
		if ($this->setuptype == 'install' AND !$version)
		{
			return array(
				'version' => 'install',
			);
		}

		$shortversions = array();
		foreach ($this->versions AS $key => $foo)
		{
			$shortversions[] = strval($key);
		}

		$gotlog = false;

		if (!$version)
		{
			if ($log = $this->db->query_first("SELECT * FROM " . TABLE_PREFIX . "upgradelog ORDER BY upgradelogid DESC LIMIT 1"))
			{
				$gotlog = true;
			}
		}

		if ($gotlog)
		{
			if (!preg_match('/^upgrade_(\w+)\.php$/siU', $log['script'], $reg))
			{
				$gotlog = false;

				if (in_array($log['script'], $this->endscripts) OR preg_match('#^\d+((a|b|g|rc|pl)\d+)?$#si', $log['script']))
				{
					$gotlog = true;
					$scriptver = $log['script'];
				}
			}
			else
			{
				if (!array_search($reg[1], $shortversions))
				{
					$gotlog = false;
				}
				else
				{
					$scriptver = $reg[1];
					$oldscript = true;
				}
			}
		}

		if ($gotlog)
		{
			if ($log['step'] == 0)
			{
				// the last entry has step = 0, meaning the script completed...
				$versionkey = array_search($scriptver, $shortversions);
				$shorten = 0;

				while ($versionkey === false AND $wildversion != '*')
				{
					$wildversion = substr_replace($scriptver, '*', --$shorten);
					$versionkey = array_search($wildversion, $shortversions);
				}
				++$versionkey;

				/*
				if ($versionkey !== false AND $scriptver < $this->versions[$shortversions["$versionkey"]])
				{
					$versionkey = false;
				}
				*/

				// to handle the case when we are running the version before a wildcard version
				while (strpos($shortversions["$versionkey"], '*') !== false)
				{
					++$versionkey;
				}

				if ($versionkey !== false AND isset($shortversions["$versionkey"]))
				{
					$scriptinfo['version'] = $shortversions["$versionkey"];
				}
				else if (($currentkey = array_search($scriptver, $this->endscripts)) !== false)
				{
					$scriptinfo['version'] = $this->endscripts[$currentkey + 1];
				}
				else
				{
					$scriptinfo['version'] = $this->endscripts[count($this->products)];	// any non suite products
				}

				$scriptinfo['only'] = false;
			}
			else if ($log['startat'])
			{
				$scriptinfo['version'] = $scriptver;
				$scriptinfo['step']    = $log['step'];
				$scriptinfo['startat'] = $log['startat'] + $log['perpage'];
				$scriptinfo['only'] = $log['only'];
			}
			else
			{
				$scriptinfo['version'] = $scriptver;
				$scriptinfo['step']    = $log['step'] + 1;
				$scriptinfo['only'] = $log['only'];
			}

			if ($log['step'] != 0 AND $oldscript)
			{
				// If last upgrade was done with a 4.1+ upgrade script then $reg[1] will be set
				// $log['step'] has different meanings between pre 4.1 and post 4.1 so for pre 4.1, set the step at one since we now
				// track each individual query as a step rather than groups of queries.
				$log['step'] = 1;
			}
		}
		else
		{
			if ($version)
			{
				$shortver = $version;
			}
			else
			{
				$shortver = $this->fetch_short_version($this->registry->versionnumber);
			}

			if (!$version AND in_array($this->registry->options['templateversion'], $this->versions))
			{
				$key = array_search($this->registry->options['templateversion'], $this->versions, true);
				$versionkey =  array_search((string)$key, $shortversions, true);
			}
			else
			{
				$versionkey = array_search($shortver, $shortversions);
			}

			$shorten = 0;
			while ($versionkey === false AND $wildversion != '*')
			{
				$wildversion =  substr_replace($shortver, '*', --$shorten);
				$versionkey = array_search($wildversion, $shortversions);
			}

			++$versionkey;

			// to handle the case when we are running the version before a wildcard version
			while (strpos($shortversions["$versionkey"], '*') !== false)
			{
				++$versionkey;
			}

			$onproduct = false;
			if ($versionkey !== false AND isset($shortversions["$versionkey"]))
			{
				// we know what script this version needs to go to
				$scriptinfo['version'] = $shortversions["$versionkey"];
				$onproduct = true;
			}
			else if ($shortver != 'final' AND (($value = array_search($shortver, $this->endscripts)) !== false))
			{
				$scriptinfo['version'] = $this->endscripts[$value + 1];
				$onproduct = true;
			}
			else if (($version == 'install' OR ($versionkey == count($shortversions))))
			{
				$scriptinfo['version'] = $this->endscripts[0]; // 'vbblog'
				$onproduct = true;
			}

			if (!$onproduct)
			{
				if (in_array(intval($this->registry->versionnumber), array(3,4,5)))
				{
					// assume we are finished
					$scriptinfo['version'] = 'final';
				}
				else
				{
					// no log and invalid version, so assume it's 2.x
					$scriptinfo['version'] = '400';
				}
			}
		}

		return $scriptinfo;
	}

	protected function install_suite()
	{
		foreach ($this->products as $productid)
		{
			if (!file_exists(DIR . "/includes/xml/product-$productid.xml"))
			{
				return false;
			}
		}
		return true;
	}

	/**
	* Convert a "Long version" string into a short version
	*
	* @var string
	*
	* @return string
	*/
	protected function fetch_short_version($version, $typeonly = false)
	{
		if (preg_match('/^(\w+\s+)?(\d+)\.(\d+)\.(\d+)(\s+(a|alpha|b|beta|g|gamma|rc|release candidate|gold|stable|final|pl|patch level)(\s+(\d+))?)?$/siU', $version, $regs))
		{
			switch (strtolower($regs[6]))
			{
				case 'alpha':
					$type = -5;
					$regs[6] = 'a';
					break;
				case 'beta':
					$type = -4;
					$regs[6] = 'b';
					break;
				case 'gamma':
					$type = -3;
					$regs[6] = 'g';
					break;
				case 'release candidate':
					$type = -2;
					$regs[6] = 'rc';
					break;
				case 'patch level':
					$type = 1;
					$regs[6] = 'pl';
					break;
				case 'gold':
				case 'stable':
				case 'final':
					$type = -1;
					$regs[6] = '';
					break;
				default:
					$type = 0;
					break;
			}

			if ($typeonly)
			{
				return $type;
			}
			else
			{
				return $regs[2] . $regs[3] . $regs[4] . $regs[6] . $regs[8];
			}
		}
		else
		{
			if ($typeonly)
			{
				return 2; // Non standard type
			}
			else
			{
				return $version;
			}
		}
	}

	/**
	 * Database queries that need to be executed to ensure that the database is in a known state that is functional
	 * with the upgrade. Pre 3.6.0 there were quite a bit of queries here
	 */
	protected function sync_database()
	{
		if (defined('SKIPDB'))
		{
			return;
		}

		$this->db->hide_errors();


		//this is related to the file based datastore class.
		// need to do this here or we might get problems if options are built before the end of the script
		$this->db->query_write("REPLACE INTO " . TABLE_PREFIX . "adminutil (title, text) VALUES ('datastorelock', '0')");

		// post_parsed needs to be called postparsed for some of the rebuild functions to work correctly
		$this->startup_alter("ALTER TABLE " . TABLE_PREFIX . "post_parsed RENAME " . TABLE_PREFIX . "postparsed");

		// These tables are referenced by upgrade scripts that predate these modifications
		$this->startup_alter("ALTER TABLE " . TABLE_PREFIX . "upgradelog ADD only TINYINT NOT NULL DEFAULT '0'");
		$this->startup_alter("ALTER TABLE " . TABLE_PREFIX . "adminmessage ADD args MEDIUMTEXT");

		// When vB_Upgrade::init creates an adminsession to rebuild bitfields, the language
		// table is eventually accessed downstream in the fetchLanguage() stored query,
		// which explicitly selects the 'eventdateformatoverride' field. If this field is
		// not present, the admin user language setup then fails with the error "The requested
		// language does not exist, reset via tools.php", causing the upgrade to fail before
		// the upgrade step that creates the column can run. This matches the add_field
		// call in 531a2 step_1
		$this->startup_alter("ALTER TABLE " . TABLE_PREFIX . "language ADD eventdateformatoverride VARCHAR(50) NOT NULL default ''");
		// The same applies to the pickerdateformatoverride field.
		// This matches the add_field call in 532a4 step_1
		$this->startup_alter("ALTER TABLE " . TABLE_PREFIX . "language ADD pickerdateformatoverride VARCHAR(50) NOT NULL default ''");


		$this->db->show_errors();
	}

	/**
	 * Database queries that need to be executed to ensure that the database is in a known state that is functional
	 * with the upgrade. Pre 3.6.0 there were quite a bit of queries here.
	 *	Error: 1142 SQLSTATE: 42000 (ER_TABLEACCESS_DENIED_ERROR)
	 *	Message: %s command denied to user '%s'@'%s' for table '%s'
	 *	Error: 1143 SQLSTATE: 42000 (ER_COLUMNACCESS_DENIED_ERROR)
	 *	Message: %s command denied to user '%s'@'%s' for column '%s' in table '%s'	 *
	 *
	 * @param	string	Alter Query
	 *
	 */
	private function startup_alter($query)
	{
		static $found = false;

		if ($errorstate = $this->db->reporterror)
		{
			$this->db->hide_errors();
		}
		$this->db->query_write($query);
		if ($errorstate)
		{
			$this->db->show_errors();
		}

		if (!$found AND ($this->db->errno == 1142 OR $this->db->errno == 1143))
		{
			$this->startup_errors[] = $this->phrase['core']['no_alter_permission'];
			$found = true;
		}
	}

	/**
	 * Verify CSS dir can be written to
	 *
	 * @param	int	$styleid -- -1 to check all
	 *
	 * @return	boolean
	 */
	private function verify_cssdir($styleid = -1)
	{
		if ($this->setuptype == 'install' OR !$this->registry->options['storecssasfile'])
		{
			return true;
		}

		if ($styleid != -1)
		{
			if (!$this->verify_write_cssdir($styleid, 'ltr') OR !$this->verify_write_cssdir($styleid, 'rtl'))
			{
				return false;
			}
		}

		$db = vB::getDbAssertor();
		$childsets = $db->select('style', array('parentid' => $styleid), false, array('styleid'));
		foreach($childsets AS $childset)
		{
			if (!$this->verify_cssdir($childset['styleid']))
			{
				return false;
			}
		}

		return true;
	}

	/**
	 * Verify directory can be written to
	 *
	 * @param	int	Styelid
	 * @param	str	Text direction
	 *
	 * @return	boolean	Success
	 */
	private function verify_write_cssdir($styleid, $dir = 'ltr')
	{
		$styledir = vB_Api::instanceInternal('style')->getCssStyleDirectory($styleid, $dir);
		$styledir = $styledir['directory'];

		//if exists then it should be a directory and writable, otherwise we have a problem
		if (file_exists($styledir))
		{
			return (is_dir($styledir) AND is_writable($styledir));
		}

		static $cancreatewritable = null;

		if (is_null($cancreatewritable))
		{
			//attempt to create the directory.  We may or may not need a directory for each style
			//but we probably don't have the ability to check at this point -- the fields and
			//other relevant information simply may not exist yet, especially if this is a vB4
			//upgrade. But if we can create writiable directories for the styles, it will all
			//work out later, we don't actually need to create them here.  But the best way
			//to check that is to create a directory and then remove it.  We'll make the assumption
			//that if it works once, it will keep working to avoid doing this every time.

			//create the directory -- if it still exists try to continue with the existing dir
			if (!@mkdir($styledir))
			{
				$cancreatewritable= false;
			}
			else
			{
				$cancreatewritable = (is_dir($styledir) AND is_writable($styledir));
				@rmdir($styledir);
			}
		}

		return $cancreatewritable;
	}

	/**
	 * Verify conditions are acceptable to perform the upgrade/install
	 */
	protected function verify_environment()
	{
		//defines "install_versions" array -- seperated to a seperate file for easy editing.
		require_once(DIR . '/install/install_versions.php');

		// php version check
		if (version_compare(PHP_VERSION, $install_versions['php_required'], '<'))
		{
			$this->startup_errors[] = sprintf($this->phrase['core']['php_version_too_old'], $install_versions['php_required'], PHP_VERSION);
		}

		//if MYSQL_VERSION isn't defined its because we are in the installer and haven't figured out the database yet.  We'll
		//verify the version separately when do.  Note that if we change this logic we also need to change the verify_install_environment below.
		if (defined('MYSQL_VERSION'))
		{
			$this->checkDBVersion(MYSQL_VERSION, $install_versions);
		}

		// config file check
		if (!file_exists(DIR . '/includes/config.php'))
		{
			$this->startup_errors[] = $this->phrase['core']['cant_find_config'];
		}
		else if (!is_readable(DIR . '/includes/config.php'))
		{
			$this->startup_errors[] = $this->phrase['core']['cant_read_config'];
		}

		if (($err = verify_optimizer_environment()) !== true)
		{
			$this->startup_errors[] = $this->phrase['core'][$err];
		}

		if (function_exists('mmcache_get'))
		{
			$this->startup_errors[] = $this->phrase['core']['turck'];
		}

		if (!$this->verify_cssdir())
		{
			$this->startup_errors[] = $this->phrase['core']['css_not_writable'];
		}

		// Actually will never get here if the 'connect' function doesn't exist as we've already tried to connect
		if (!function_exists($this->db->functions['connect']))
		{
			$vb5_config =& vB::getConfig();
			$this->startup_errors[] = sprintf($this->phrase['core']['database_functions_not_detected'], 'mysqli');
		}

		try
		{
			fetch_random_string(20);
		}
		catch (Exception $e)
		{
			$this->startup_errors[] = $this->phrase['core']['required_psrng_missing'];
		}

		$this->verify_install_environment($install_versions);
		$this->verify_files();
	}

	protected function verify_files()
	{
		if (!empty($this->startup_errors) OR defined('SKIP_UPGRADE_FILE_CHECK'))
		{
			return;
		}

		$string = vB::getString();
		$hashChecker = new vB_Utility_Hashchecker(array(), $string);
		$check = $hashChecker->verifyFiles();

		if (!$check['success'])
		{
			foreach ($check['fatalErrors'] AS $__error)
			{
				$this->startup_warnings[] = $this->get_parsed_phrase($__error);
			}
			return;
		}

		$errorstring = '';

		if (!empty($check['startupWarnings']))
		{
			foreach ($check['startupWarnings'] AS $__phrase)
			{
				$this->startup_warnings[] = $this->get_parsed_phrase($__phrase);
			}
		}

		if (!empty($check['errors']))
		{
			$errorstring .= $this->phrase['core']['suspect_files_detected'];
		}

		foreach ($check['fileCounts'] AS $directory => $__filecount)
		{
			if (isset($check['errors'][$directory]))
			{
				foreach ($check['errors'][$directory] AS $file => $errors)
				{
					foreach ($errors AS $__key => $__val)
					{
						$errors[$__key] = $this->get_parsed_phrase($__val);
					}
					if ($directory == DIRECTORY_SEPARATOR)
					{
						$filename = DIRECTORY_SEPARATOR . $file;
					}
					else
					{
						$filename = $directory . DIRECTORY_SEPARATOR . $file;
					}
					$errorstring .= "\n<br /><strong>$filename</strong> - " . implode('<br />', $errors);
				}
			}
		}
		/*
		TODO: FLAG SKIPPED FOLDERS & FILES FOR MANUAL REVIEW - Skipping as it's new behavior not in scope,
		but need to revisit this later.
		if (!empty($check['skippedDirs']))
		{
		}
		if (!empty($check['skippedFiles']))
		{
		}
		 */

		if ($errorstring)
		{
			$this->startup_warnings[] = $errorstring;
		}
	}

	private function get_parsed_phrase($phraseData, $group = 'core')
	{
		/*
		We might get a {phraseid} or array({phraseid}, {phrasedata1}...)
		We can't quite just use construct_phrase() and call it a day
		because we have to exchange the phraseid for the raw phrase
		first.
		 */
		$ogphraseData = $phraseData;
		if (is_string($phraseData))
		{
			$phrase = $this->phrase[$group][$phraseData] ?? $phraseData;
		}
		else
		{
			$phraseData[0] = $this->phrase[$group][$phraseData[0]] ?? $phraseData[0];
			$phrase = construct_phrase_from_array($phraseData);
		}

		return $phrase;
	}

	protected function verify_install_environment($install_versions)
	{
		/* We always use vBulletin_5_Default because when upgrading
		from vB3 and vB4 we don't have the old cp styles any more. */
		$this->registry->options['cpstylefolder'] = 'vBulletin_5_Default';

		if (defined('SKIPDB'))
		{
			$vb5_config =& vB::getConfig();
			$this->db->hide_errors();

			$db_error = '';
			// make database connection
			try
			{
				$this->db->connect_using_dbconfig();
			}
			catch(vB_Exception_Database $e)
			{
				$db_error = $e->getMessage();
			}

			$connect_errno = $this->db->errno();
			$connect_error = ($this->db->error ? $this->db->error : $this->db->error());

			if ($this->db->connection_master)
			{
				$no_force_sql_mode = vB::getDbAssertor()->getNoForceSqlMode();
				if (empty($no_force_sql_mode) AND $this->db->connection_master)
				{
					$this->db->force_sql_mode('');
					// small hack to prevent the above query from generating an error below
					$this->db->query_read('SELECT 1 + 1');
				}
				//mysql version check on install
				$mysqlversion = $this->db->query_first("SELECT version() AS version");
				define('MYSQL_VERSION', $mysqlversion['version']);
				$this->checkDBVersion(MYSQL_VERSION, $install_versions);

				if ($connect_errno)
				{ // error found
					if ($connect_errno == 1049)
					{
						$this->db->create_database_using_dbconfig();
						$this->db->select_db_using_dbconfig();
						if ($this->db->errno() == 1049)
						{
							// unable to create database
							$this->startup_errors[] = sprintf($this->phrase['install']['unable_to_create_db']);
						}
					}
					else
					{ // Unknown Error
						$this->startup_errors[] = sprintf($this->phrase['install']['connect_failed'], $connect_errno, $connect_error);
					}
				}
			}
			else
			{
				// Unable to connect to database
				$error = ($connect_error ? $connect_error : $db_error);
				if ($error)
				{
					$this->startup_errors[] = sprintf($this->phrase['install']['db_error_desc'], $error);
				}
				$this->startup_errors[] = $this->phrase['install']['no_connect_permission'];
			}
			$this->db->show_errors();
		}
	}

	/**
	 *	Check the db version
	 *
	 *	Also will set an error in this->startup_errors if the check fails
	 *
	 *	@return boolean true if passed/false otherwise
	 */
	protected function checkDBVersion($versionString, $install_versions)
	{
		$versionInfo = explode('-', $versionString);

		//mysql just returns the version
		if(count($versionInfo) == 1)
		{
			$required_version = $install_versions['mysql_required'];
			$database_type = 'MySql';
		}
		else if ($versionInfo[1] == 'MariaDB')
		{
			$required_version = $install_versions['mariadb_required'];
			$database_type = 'MariaDB';
		}
		else
		{
			//if we don't know what we are dealing with pretend its mysql.
			//if we got this far it answered to mysql syntax and probably uses mysql versioning
			//its better to pass the check and fail on install than it is to refuse an install
			//that succeeds.
			$required_version = $install_versions['mysql_required'];
			$database_type = 'MySql';
		}

		if (version_compare($versionInfo[0], $required_version, '<'))
		{
			$this->startup_errors[] = sprintf(
				$this->phrase['core']['database_version_too_old'],
				$required_version,
				$versionInfo[0],
				$database_type
			);
			return false;
		}
		return true;
	}

	/**
	* Setup environment common to all upgrades
	*
	*/
	protected function setup_environment()
	{
		if (function_exists('set_time_limit'))
		{
			@set_time_limit(0);
		}

		if (!defined('VERSION'))
		{
			define('VERSION', defined('FILE_VERSION') ? FILE_VERSION : '');
		}

		// Notices
		$vb5_config =& vB::getConfig();
		if (!empty($vb5_config['Database']['no_force_sql_mode']))
		{
			// check to see if MySQL is running strict mode and recommend disabling it
			$this->db->hide_errors();
			$strict_mode_check = $this->db->query_first("SHOW VARIABLES LIKE 'sql\\_mode'");
			if (strpos(strtolower($strict_mode_check['Value']), 'strict_') !== false)
			{
				$this->startup_warnings[] = $this->phrase['core']['mysql_strict_mode'];
			}
			$this->db->show_errors();
		}

		if (is_array($this->phrase['stylevar']))
		{
			foreach ($this->phrase['stylevar'] AS $stylevarname => $stylevarvalue)
			{
				vB_Template_Runtime::addStyleVar($stylevarname, $stylevarvalue);
			}
		}

		// if it's an upgrade, use the previous default language's charset instead of the hard coded default value in the
		// upgrade_language_{languagecode}.xml file
		if ($this->setuptype == 'upgrade')
		{
			require_once(DIR . '/includes/adminfunctions_template.php');

			//we only want to warn if this is a site that exists prior
			//to 5.2.5.  People who installed on 5.2.5 or newer can have the
			//same charset mismatch, but *should not make the suggested change*
			//since they will not have run their site in the same broken configuration
			//(5.2.5 attempts to fix that problem but will break sites that were
			//already in that circumstance).
			$current = $this->registry->options['templateversion'];
			if (is_newer_version('5.2.5 Alpha 1', $current))
			{
				//if they've explicitly set the character set
				$db = vB::getDbAssertor();
				$legacydb = $db->getDBConnection();
				if (!$legacydb->hasConfigCharset())
				{
					$client_charset = $legacydb->getInitialClientCharset();
					$row = $db->getRow('vBInstall:getDatabaseCharacterSet');
					if (strcasecmp($row['db_charset'], $client_charset) != 0)
					{
						$this->startup_warnings[] = sprintf($this->phrase['core']['database_charset_mismatch'],
							$row['db_charset'], $client_charset);
					}
				}
			}

			$assertor = vB::getDbAssertor();
			$row = $assertor->getRow('setting', array('varname' => 'languageid'));
			if ($row AND isset($row['value']))
			{
				$charset = $assertor->getColumn('language', 'charset', array('languageid' => $row['value']));
				if (is_array($charset))
				{
					$charset = $charset[0];
				}
				vB_Template_Runtime::addStyleVar('charset', $charset);
			}
		}

		// Get versions of .xml files for header diagnostics
		foreach ($this->xml_versions AS $file => $null)
		{
			if ($fp = @fopen(DIR . '/install/vbulletin-' . $file . '.xml', 'rb'))
			{
				$data = @fread($fp, 400);
				if (
					($file != 'settings' AND preg_match('#vbversion="(.*?)"#', $data, $matches))
						OR
					($file == 'settings' AND preg_match('#<setting varname="templateversion".*>(.*)</setting>#sU', $data, $matches) AND preg_match('#<defaultvalue>(.*?)</defaultvalue>#', $matches[1], $matches))
				)
				{
					$this->xml_versions[$file] = $matches[1];
				}
				else
				{
					$this->xml_versions[$file] =  $this->phrase['core']['unknown'];
				}
				fclose($fp);
			}
			else
			{
				$this->xml_versions[$file] = $this->phrase['core']['file_not_found'];
			}
		}
	}

	public function loadDSSettingsfromConfig()
	{
		return true;
	}

	protected function render_phrase_array($array)
	{
		//we assume that the main vb phrase system isn't working
		//so we only check local phrases.  We don't load phrases until
		//the end so even if the code is in place the phrases will be
		//empty on install and a version out of date on upgrade.
		//
		//Phrases needed for install/upgrade should be copied to the
		//install/upgrade file
		if (isset($this->phrase['vbphrase'][$array[0]]))
		{
			$array[0] = $this->phrase['vbphrase'][$array[0]];
			return construct_phrase($array);
		}
		else
		{
			$phrasename = array_shift($array);
			$args = "";
			if (count($array))
			{
				$args = '"' . implode('", "', $array) . "'";
			}
			return sprintf($this->phrase['core']['phrase_not_found'], $phrasename, $args);
		}
	}
}

abstract class vB_Upgrade_Version
{
	/*Constants=====================================================================*/
	const MYSQL_ERROR_CANT_CREATE_TABLE       = 1005;
	const MYSQL_ERROR_TABLE_EXISTS            = 1050;
	const MYSQL_ERROR_COLUMN_EXISTS           = 1060;
	const MYSQL_ERROR_KEY_EXISTS              = 1061;
	const MYSQL_ERROR_UNIQUE_CONSTRAINT       = 1062;
	const MYSQL_ERROR_PRIMARY_KEY_EXISTS      = 1068;
	const MYSQL_ERROR_DROP_KEY_COLUMN_MISSING = 1091;
	const MYSQL_ERROR_TABLE_MISSING           = 1146;
	const FIELD_DEFAULTS                      = '__use_default__';
	const PHP_TRIGGER_ERROR                   = 1;
	const MYSQL_HALT                          = 2;
	const MYSQL_ERROR                         = 3;
	const APP_CREATE_TABLE_EXISTS             = 4;
	const CLI_CONF_USER_DATA_MISSING          = 5;

	/*Properties====================================================================*/
	/**
	* Number of substeps in this step
	*
	* @var int;
	*/
	public $stepcount = 0;

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
	* A list of modifications to be made when execute is called.
	*
	* @var	array
	*/
	protected $modifications = array();

	/**
	* List of various messages to send back to the delegate class
	*
	* @var	array
	*/
	protected $response = array();

	/**
	* A cache of table alter objects, to reduce the amount of overhead
	* when there are multiple alters to a single table.
	*
	* @var	array
	*/
	public $alter_cache = array();

	/**
	*	Do we support innodb?
	*
	* @var string
	*/
	protected $hightrafficengine = '';

	/**
	* Identifier of library that called this script - cli and ajax at present
	*
	* @var 	string
	*/
	public $caller = '';

	/**
	* Set to true if step queries are to be $perpage limited, yes for Ajax, no for CLI
	*
	* @var 	boolean
	*/
	public $limitqueries = true;

	/**
	 * Identifier of max upgrade version for library scripts
	 * @var	string
	 */
	public $maxversion = '';

	/**
 	 * The short version of the script
	 * @var	string
	 */
	public $SHORT_VERSION = '';

	/**
	 * The long version of the script
	 * @var	string
	 */
	public $LONG_VERSION  = '';

	/**
	 * Versions that can upgrade to this script
	 * @var	string
	 */
	public $PREV_VERSION = '';

	/**
	* Beginning version compatibility
	*
	* @var	string
	*/
	public $VERSION_COMPAT_STARTS = '';

	/**
	* Ending version compatibility
	*
	* @var	string
	*/
	public $VERSION_COMPAT_ENDS   = '';

	/**
	* Constructor.
	*
	* @param	vB_Registry	Reference to registry object
	* @param	Array		Phrases
	* @param	string	Max upgrade version
	*/
	public function __construct(&$registry, $phrase, $maxversion)
	{
		if (is_object($registry))
		{
			$this->registry =& $registry;
			$this->db =& $this->registry->db;
		}
		else
		{
			trigger_error('vB_Upgrade: $this->registry is not an object.', E_USER_ERROR);
		}

		$this->phrase =& $phrase;
		$this->maxversion = $maxversion;

		foreach(get_class_methods($this) AS $method_name)
		{
			if (preg_match('#^step_(\d+)$#', $method_name, $matches))
			{
				$this->stepcount++;
			}
		}

		// Maintain backwards compatibility with install system
		require_once(DIR . '/install/functions_installupgrade.php');

		//it turns out that we load this class even if we fail
		//verify_environment.  We really need to untangle that because
		//all kinds of things could be problematic if we have errors
		//but we need to get though this in order to display to the user
		//for now will just skip setting this if we fail to load
		//the engine for it.
		try
		{
			$this->hightrafficengine = get_innodb_engine($this->db);
		}
		catch(Exception $e)
		{
			//nothing to do here.
		}

		require_once(DIR . '/includes/class_dbalter.php');
	}

	//this duplicates the function in the vB_Upgrade_Abstract
	//class.  We pass the phrased array through but don't have a
	//way to get to the Upgrade controller class from here (the step class)
	//both the controllers and the steps need to render phrases
	//duplication is bad, but so is randomly exposing class instances
	//and in this case is the lesser evil.
	protected function render_phrase_array($array)
	{
		//we assume that the main vb phrase system isn't working
		//so we only check local phrases.  We don't load phrases until
		//the end so even if the code is in place the phrases will be
		//empty on install and a version out of date on upgrade.
		//
		//Phrases needed for install/upgrade should be copied to the
		//install/upgrade file
		if (isset($this->phrase['vbphrase'][$array[0]]))
		{
			$array[0] = $this->phrase['vbphrase'][$array[0]];
			return construct_phrase($array);
		}
		else
		{
			$phrasename = array_shift($array);
			$args = "";
			if (count($array))
			{
				$args = '"' . implode('", "', $array) . "'";
			}
			return sprintf($this->phrase['core']['phrase_not_found'], $phrasename, $args);
		}
	}
	/**
	* Tests to see if the specified field exists in a table.
	*
	* @param	string	Table to test. Do not include table prefix!
	* @param	string	Name of field to test
	*
	* @return	boolean	True if field exists, false if it doesn't
	*/
	protected function field_exists($table, $field)
	{
		$error_state = $this->db->reporterror;
		if ($error_state)
		{
			$this->db->hide_errors();
		}

		$this->db->query_write("SELECT $field FROM " . TABLE_PREFIX . "$table LIMIT 1");

		if ($error_state)
		{
			$this->db->show_errors();
		}

		if ($this->db->errno())
		{
			$this->db->errno = 0;
			return false;
		}
		else
		{
			return true;
		}
	}

	/**
	* Alters an existing field in a table.
	*
	* @param	string	Message to display
	* @param	string	Name of the table to alter. Do not include table prefix!
	* @param	string	Name of the field to add
	* @param	array	Extra attributes. Supports: length, attributes, null, default, extra. You may also use the define FIELD_DEFAULTS.
	*/
	protected function alter_field($message, $table, $field, $type, $extra)
	{
		$extra = $this->getFieldDefaults($type, $extra);
		$this->modifications[] = array(
			'modification_type' => 'alter_field',
			'alter'             => true,
			'message'           => $message,
			'data'              => array(
				'table'      => $table,
				'name'       => $field,
				'type'       => $type,
				'length'     => $extra['length'],
				'attributes' => $extra['attributes'],
				'null'       => (!empty($extra['null']) ? true : false),
				'default'    => $extra['default'],
				'extra'      => $extra['extra'],
				'ignorable_errors' => array(),
			)
		);
	}

	/**
	* Adds a field to a table.
	*
	* @param	string	Message to display
	* @param	string	Name of the table to alter. Do not include table prefix!
	* @param	string	Name of the field to add
	* @param	array	Extra attributes. Supports: length, attributes, null, default, extra. You may also use the define FIELD_DEFAULTS.
	*/
	protected function add_field($message, $table, $field, $type, $extra)
	{
		$extra = $this->getFieldDefaults($type, $extra);
		$this->modifications[] = array(
			'modification_type' => 'add_field',
			'alter'             => true,
			'message'           => $message,
			'data'              => array(
				'table'      => $table,
				'name'       => $field,
				'type'       => $type,
				'length'     => $extra['length'],
				'attributes' => $extra['attributes'],
				'null'       => (!empty($extra['null']) ? true : false),
				'default'    => $extra['default'],
				'extra'      => $extra['extra'],
				'ignorable_errors' => array(self::MYSQL_ERROR_COLUMN_EXISTS),
			)
		);
	}

	private function getFieldDefaults($type, $extra)
	{
		if ($extra == self::FIELD_DEFAULTS OR $extra['attributes'] == self::FIELD_DEFAULTS)
		{
			switch (strtolower($type))
			{
				case 'float':
				case 'double':
				{
					$defaults = array(
						'attributes' => '',
						'null'       => false,
						'default'    => 0,
						'extra'      => ''
					);
				}
				break;

				case 'tinyint':
				case 'smallint':
				case 'mediumint':
				case 'int':
				case 'bigint':
				{
					$defaults = array(
						'attributes' => 'UNSIGNED',
						'null'       => false,
						'default'    => 0,
						'extra'      => ''
					);
				}
				break;

				case 'char':
				case 'varchar':
				case 'binary':
				case 'varbinary':
				{
					if ($extra == self::FIELD_DEFAULTS)
					{
						$this->add_error("You must specify a length for fields of type $type to use the defaults.", self::PHP_TRIGGER_ERROR, true);
						return $this->response;
					}

					$defaults = array(
						'length'     => $extra['length'],
						'attributes' => '',
						'null'       => false,
						'default'    => '',
						'extra'      => ''
					);
				}
				break;

				case 'tinytext':
				case 'text':
				case 'mediumtext':
				case 'longtext':
				case 'tinyblob':
				case 'blob':
				case 'mediumblob':
				case 'longblob':
				{
					$defaults = array(
						'attributes' => '',
						'null'       => true,
						'extra'      => ''
					);
				}
				break;

				default:
				{
					$this->add_error("No defaults specified for fields of type $type.", self::PHP_TRIGGER_ERROR, true);
					return $this->response;
				}
			}

			if (is_array($extra))
			{
				unset($extra['attributes']);
				$extra = array_merge($defaults, $extra);
			}
			else
			{
				$extra = $defaults;
			}
		}

		if(!in_array(strtolower($type), array('float', 'double')))
		{
			$extra['length'] = intval($extra['length']);
		}

		return $extra;
	}

	/**
	* Drops a field from a table.
	*
	* @param	string	Message to display
	* @param	string	Table to drop from. Do not include table prefix!
	* @param	string	Field to drop
	*/
	protected function drop_field($message, $table, $field)
	{
		$this->modifications[] = array(
			'modification_type' => 'drop_field',
			'alter'             => true,
			'message'           => $message,
			'data'              => array(
				'table' => $table,
				'name'  => $field,
				'ignorable_errors' => array(self::MYSQL_ERROR_DROP_KEY_COLUMN_MISSING),
			)
		);
	}

	/**
	 *	Drops a table
	 *
	 *	@param $table -- name of the table without the table prefix.
	 */
	protected function drop_table($table)
	{
		//let's hide this both to reduce repetative code, but also so that
		//we can change it it without altering tons of additional code
		$this->run_query(
			sprintf($this->phrase['core']['dropping_old_table_x'], TABLE_PREFIX . $table),
			"DROP TABLE IF EXISTS " . TABLE_PREFIX . $table
		);
	}

	/**
	* Adds an index to a table. Can span multiple fields.
	*
	* @param	string			Message to display
	* @param	string			Table to add the index to. Do not include table prefix!
	* @param	string			Name of the index
	* @param	string|array	Fields to cover. Must be an array if more than one
	* @param	string			Type of index (empty defaults to a normal/no constraint index)
	* @param  boolean 		overwrite.  If true drop the index before we create the new one
	*/
	protected function add_index($message, $table, $index_name, $fields, $type = '', $overwrite = false)
	{
		$this->modifications[] = array(
			'modification_type' => 'add_index',
			'alter'             => true,
			'message'           => $message,
			'data'              => array(
				'table'  => $table,
				'name'   => $index_name,
				'fields' => (!is_array($fields) ? array($fields) : $fields),
				'type'   => $type,
				'ignorable_errors' => array(self::MYSQL_ERROR_KEY_EXISTS),
				'overwrite' => $overwrite
			)
		);
	}

	protected function add_cronjob($data)
	{
		if (!$this->db->query_first("SELECT filename FROM " . TABLE_PREFIX . "cron WHERE filename = '" . $this->db->escape_string($data['filename']) . "'"))
		{
			$this->run_query(
				sprintf($this->phrase['core']['altering_x_table'], 'cron', 1, 1),
				"INSERT INTO " . TABLE_PREFIX . "cron
					(nextrun, weekday, day, hour, minute, filename, loglevel, varname, volatile, product)
				VALUES
				(
					" . intval($data['nextrun']) . ",
					'" . intval($data['weekday']) . "',
					'" . intval($data['day']) ."',
					'" . intval($data['hour']) . "',
					'" . $this->db->escape_string($data['minute']) . "',
					'" . $this->db->escape_string($data['filename']) . "',
					'" . intval($data['loglevel']) . "',
					'" . $this->db->escape_string($data['varname']) . "',
					" . intval($data['volatile']) . ",
					'" . $this->db->escape_string($data['product']) . "'
				)"
			);
		}
		else
		{
			$this->skip_message();
		}
	}

	/**
	* Adds an adminmessage to the system. Checks if message already exists.
	*
	* @param	string			varname of message (unique)
	* @param	array				Adminmessage schema (dismissable, script, action, execurl, method, status)
	* @param	bool				Allow duplicate entry on varname?
	* @param	array				Values to send into the phrase at run time
	*/
	protected function add_adminmessage($varname, $data, $duplicate = false, $args = null)
	{
		$db = vB::getDbAssertor();

		if (!$duplicate)
		{
			$exists = $db->getRow('adminmessage', array('varname' => $varname, 'status' => 'undone'));
			if ($exists)
			{
				$this->skip_message();
				return;
			}
		}

		// This function takes "dismissible", but column name is "dismissable". This caused some confusion where quite a number of
		// callers passed in the latter. Accept the latter if former isn't set.
		if (!isset($data['dismissible']) && isset($data['dismissable']))
		{
			$data['dismissible'] = intval($data['dismissable']);
		}

		$this->run_query(
			sprintf($this->phrase['vbphrase']['update_table'], TABLE_PREFIX . "adminmessage"),
			"INSERT INTO " . TABLE_PREFIX . "adminmessage
				(varname, dismissable, script, action, execurl, method, dateline, status, args)
			VALUES
				(
					'" . $this->db->escape_string($varname) . "',
					" . intval($data['dismissible']) . ",
					'" . $this->db->escape_string($data['script']) . "',
					'" . $this->db->escape_string($data['action']) . "',
					'" . $this->db->escape_string($data['execurl']) . "',
					'" . $this->db->escape_string($data['method']) . "',
					" . TIMENOW . ",
					'" . $this->db->escape_string($data['status']) . "',
					'" . ($args ? $this->db->escape_string(@serialize($args)) : '') . "'
			)");
	}

	/**
	 * Adds a new contenttype
	 *
	 * @param	string	Productid (vbulletin, vbcms, vbblog, etc)
	 * @param	string	Package Class (vBForum, vBBlog, vBCms, etc)
	 * @param	string	Contenttype (Post, Thread, Forum, etc)
	 * @param	int		Can Place?
	 * @param	int		Can Search
	 * @param	int		Can Tag
	 * @param	int		Can Attach
	 * @param	int		Is aggregator
	 */
	protected function add_contenttype($productid, $package_class, $contenttype_class, $canplace = 0, $cansearch = 0, $cantag = 0, $canattach = 0, $isaggregator = 0)
	{
		$packageinfo = $this->db->query_first("
			SELECT packageid
			FROM " . TABLE_PREFIX . "package
			WHERE
				productid = '" . $this->db->escape_string($productid) . "'
					AND
				class = '" . $this->db->escape_string($package_class) . "'
		");
		if ($packageinfo)
		{
			$contenttypeinfo = $this->db->query_first("
				SELECT contenttypeid
				FROM " . TABLE_PREFIX . "contenttype
				WHERE
					packageid = {$packageinfo['packageid']}
						AND
					class = '" . $this->db->escape_string($contenttype_class) . "'
			");
			if (!$contenttypeinfo)
			{
				$this->run_query(
				sprintf($this->phrase['vbphrase']['update_table'], TABLE_PREFIX . "contenttype"),
				"INSERT IGNORE INTO " . TABLE_PREFIX . "contenttype
						(class, packageid, canplace, cansearch, cantag, canattach, isaggregator)
					VALUES
						(	'" . $this->db->escape_string($contenttype_class) . "',
							{$packageinfo['packageid']},
							'{$canplace}',
							'{$cansearch}',
							'{$cantag}',
							'{$canattach}',
							'{$isaggregator}'
						)
					"
				);

				return true;
			}
		}
		$this->skip_message();
	}
	/**
	* Drops an index from a table.
	*
	* @param	string	Message to display
	* @param	string	Table to drop the index from. Do not include table prefix!
	* @param	string	Name of the index to remove
	*/
	protected function drop_index($message, $table, $index_name)
	{
		$this->modifications[] = array(
			'modification_type' => 'drop_index',
			'alter'             => true,
			'message'           => $message,
			'data'              => array(
				'table' => $table,
				'name'  => $index_name,
				'ignorable_errors' => array(self::MYSQL_ERROR_DROP_KEY_COLUMN_MISSING),
			)
		);
	}

	/**
	* Executes the specified step
	*
	* @param	int			Step to execute
	* @param	boolen	Check if table exists for create table commands
	* @param	array		Data to send to step (startat, prompt results, etc)
	*
	* @return	mixed	Return array upon error
	*/
	public function execute_step($step, $check_table = true, $data = null)
	{
		$this->response = array();
		$stepname = "step_$step";

		// TODO: It looks like adding these two fields should/could
		// be done in the sync_database function, which I believe is
		// what it is for.
		//We have changed the datastore, and although this is expensive we need to call it here.
		//otherwise some ef the upgrade steps will fail.
		if (defined('VB_AREA') AND (VB_AREA == 'Upgrade') AND ($step == 1))
		{
			if (!$this->field_exists('setting', 'adminperm'))
			{
				// Create adminper field for settings
				$this->add_field(
					sprintf($this->phrase['core']['altering_x_table'], 'setting', 1, 2),
					'setting',
					'adminperm',
					'VARCHAR',
					array('length' => 32, 'default' => '')
				);
			}

			if (!$this->field_exists('settinggroup', 'adminperm'))
			{
				$this->add_field(
					sprintf($this->phrase['core']['altering_x_table'], 'settinggroup', 1, 2),
					'settinggroup',
					'adminperm',
					'VARCHAR',
					array('length' => 32, 'default' => '')
				);
			}
		}

		$result = $this->$stepname($data);

		return $this->execute($check_table, $result);
	}

	/**
	* Executes the specified modifications.
	*
	* @param	boolen	Check if table exists for create table commands
	* @param	array		return value from step execution
	*
	* @return	mixed	Return array upon error
	*/
	public function execute($check_table = true, $result = null)
	{
		$this->response['returnvalue'] = $result;

		if ($check_table AND !$this->check_table_conflict())
		{
			$this->add_message($this->phrase['core']['table_conflict']);
			$this->modifications = array();
			return $this->response;
		}

		foreach ($this->modifications AS $modification)
		{
			$this->add_message($modification['message'], 'STANDARD', $modification['replace'] ? $modification['replace'] : false);

			$data =& $modification['data'];

			if (!empty($modification['alter']))
			{
				$db_alter =& $this->setup_db_alter_class($data['table']);
			}
			else
			{
				unset($db_alter);
			}

			$alter_result = null;

			switch ($modification['modification_type'])
			{
				case 'add_field':
					$alter_result = $db_alter->add_field($data);
					$alter_result = $this->ignore_errors($alter_result, $this->db->errno(), $db_alter->error_no,
						$data['ignorable_errors'], array(ERRDB_FIELD_EXISTS));
					break;

				case 'alter_field':
					$alter_result = $db_alter->alter_field($data);
					$alter_result = $this->ignore_errors($alter_result, $this->db->errno(), $db_alter->error_no,
						$data['ignorable_errors'], array());
					break;

				case 'drop_field':
					$alter_result = $db_alter->drop_field($data['name']);
					$alter_result = $this->ignore_errors($alter_result, $this->db->errno(), $db_alter->error_no,
						$data['ignorable_errors'], array(ERRDB_FIELD_DOES_NOT_EXIST));
					break;

				case 'add_index':
					$alter_result = $db_alter->add_index($data['name'], $data['fields'], $data['type'], $data['overwrite']);

					//note that we do not ignore ERRDB_FIELD_EXISTS here deliberately.  This is only set if the
					//index exists and does not match the one being added.
					$alter_result = $this->ignore_errors($alter_result, $this->db->errno(), $db_alter->error_no,
						$data['ignorable_errors'], array());
					break;

				case 'drop_index':
					$alter_result = $db_alter->drop_index($data['name']);
					$alter_result = $this->ignore_errors($alter_result, $this->db->errno(), $db_alter->error_no,
						$data['ignorable_errors'], array(ERRDB_FIELD_DOES_NOT_EXIST));
					break;

				case 'run_query':
					$error_state = $this->db->reporterror;
					if ($error_state)
					{
						$this->db->hide_errors();
					}

					$query_result = $this->db->query_write("### vBulletin Database Alter ###\r\n" . $data['query']);

					if ($errno = $this->db->errno())
					{
						if (!in_array($errno, $data['ignorable_errors']))
						{
							if ($errno == self::MYSQL_ERROR_CANT_CREATE_TABLE)
							{
								if (stripos($this->db->error, 'errno: 121') !== false AND stripos($data['query'], 'engine=innodb'))
								{
									preg_match('#CREATE TABLE ([a-z0-9_]+)#si', $data['query'], $matches);
									$this->add_error(sprintf($this->phrase['core']['table_creation_x_failed'], $matches[1]), self::PHP_TRIGGER_ERROR, true);
									$this->modifications = array();
									return $this->response;
								}
							}

							$this->add_error(array(
								'message' => $data['query'],
								'error'   => $this->db->error(),
								'errno'   => $this->db->errno()
								),
								self::MYSQL_HALT,
								true);

							$this->modifications = array();
							return $this->response;
						}
						else
						{
							// error occurred, but was ignorable
							$this->db->errno = 0;
						}
					}

					if ($error_state)
					{
						$this->db->show_errors();
					}

					break;

				case 'show_message':
					// do nothing -- just show the message
					break;

				case 'debug_break':
				//	echo "</ul><div>Debug break point. Stopping execution.</div>";
				//	exit;

				default:
					$this->add_error(sprintf($this->phrase['core']['invalid_modification_type_x'], $modification['modification_type']), self::PHP_TRIGGER_ERROR, true);
					$this->modifications = array();
					return $this->response;
			}

			if ($alter_result === false)
			{
				if ($db_alter->error_no == ERRDB_MYSQL)
				{
					$this->db->show_errors();
					$this->db->sql = $db_alter->sql;
					$this->db->connection_recent = null;
					$this->db->error = $db_alter->error_desc;
					$this->db->errno = -1;

					$this->add_error(array(
						'message' => $this->db->sql,
						'error'   => $this->db->error,
						'errno'   => $this->db->errno
						), self::MYSQL_HALT, true);

					$this->modifications = array();
					return $this->response;
				}
				else
				{
					if (ob_start())
					{
						print_r($modification);
						$results = ob_get_contents();
						ob_end_clean();
					}
					else
					{
						$results = serialize($modification);
					}

					$this->add_error(array(
						'message' => $results,
						'error'   => $db_alter->error_desc,
						'errno'   => $db_alter->error_no
						), self::MYSQL_HALT, true);
					$this->modifications = array();
					return $this->response;
				}
			}
		}
		$this->modifications = array();

		return $this->response;
	}

	/**
	 * Checks if given error needs to be ignored.
	 * @param $alter_result
	 * @param $db_errno
	 * @param $alter_errno
	 * @param $db_allowed_errors
	 * @param $alter_allowed_errors
	 *
	 * @return bool
	 */
	protected function ignore_errors($alter_result, $db_errno, $alter_errno, $db_allowed_errors, $alter_allowed_errors)
	{
		if (!$alter_result)
		{
			//if we don't have some kind of error here then don't attempt to clear the flags, it
			//must be some other reason we failed.
			if ($db_errno OR $alter_errno)
			{

				//either we don't have an error or we have an error value we can skip.
				$is_db_valid = (!$db_errno OR in_array($db_errno, $db_allowed_errors));
				$is_alter_valid = (!$alter_errno OR in_array($alter_errno, $alter_allowed_errors));

				if($is_db_valid AND $is_alter_valid)
				{
					return true;
				}
			}
		}

		return $alter_result;
	}

	/**
	* Runs an arbitrary query. An error will stop execution unless
	* the error code is listed as ignored
	*
	* @param	string	Message to display
	* @param	string	Query to execute.
	* @param	array	List of error codes that should be ignored.
	*/
	protected function run_query($message, $query, $ignorable_errors = array())
	{
		$this->modifications[] = array(
			'modification_type' => 'run_query',
			'message'           => $message,
			'data'              => array(
				'query'            => $query,
				'ignorable_errors' => (!is_array($ignorable_errors) ? array($ignorable_errors) : $ignorable_errors)
			)
		);
	}

	/**
	* Shortcut for adding the "long next step" message
	*
	*/
	public function long_next_step()
	{
		$this->show_message($this->phrase['core']['next_step_long_time']);
	}

	/**
	* Shortcut for adding the "skipping step" message
	*
	*/
	public function skip_message()
	{
		$this->show_message($this->phrase['core']['skipping_not_needed']);
	}

	/**
	* Does nothing but shows a message.
	*
	* @param	string	Message to display
	* @param	boolean	Replace the previous message with this message, if the previous message also had $replace set
	*/
	public function show_message($message, $replace = false)
	{
		$this->modifications[] = array(
			'modification_type' => 'show_message',
			'message'           => $message,
			'data'              => array(),
			'replace'           => $replace,
		);
	}

	/**
	* This is a function useful for debugging. It will stop execution of the
	* modifications when this call is reached, allowing emulation of an upgrade
	* step that failed at a specific point.
	*/
	protected function debug_break()
	{
		$this->modifications[] = array(
			'modification_type' => 'debug_break',
			'message'           => '',
			'data'              => array()
		);
	}

	/**
	* Sets up a DB alter object for a table. Only called internally.
	*
	* @param	string	Table the object should be instantiated for
	*
	* @return	object	Instantiated alter object
	*/
	private function &setup_db_alter_class($table)
	{
		if (isset($this->alter_cache["$table"]))
		{
			return $this->alter_cache["$table"];
		}
		else
		{
			$this->alter_cache["$table"] = new vB_Database_Alter_MySQL($this->db);
			$this->alter_cache["$table"]->fetch_table_info($table);
			return $this->alter_cache["$table"];
		}
	}

	/**
	 * Retrieve schema about a table
	 * @param string $table Table Name
	 */
	protected function fetch_table_info($table)
	{
		$db_alter = $this->setup_db_alter_class($table);
		return $db_alter->table_field_data;
	}

	/**
	* Checks if a create table call will conflict with an existing table of the same name
	*
	* @return	array	Data about the success of the check, 'error' will be empty if the query is ok
	*/
	protected function check_table_conflict()
	{
		$error = false;
		foreach ($this->modifications AS $modification)
		{
			if (
				$modification['modification_type'] == 'run_query'
					AND
				preg_match('#^\s*create\s+table\s+' . TABLE_PREFIX . '([a-z0-9_\-]+)\s+\((.*)\)#si', $modification['data']['query'], $matches)
			)
			{
				$db_alter = $this->setup_db_alter_class($matches[1]);
				if ($this->alter_cache["$matches[1]"]->init)
				{
					$existingtable = array_keys($db_alter->table_field_data);
					$create = preg_split("#,\s*(\r|\t)#si", $matches[2], -1, PREG_SPLIT_NO_EMPTY);
					$newtable = array();

					foreach ($create AS $field)
					{
						$field = trim($field);
						if (preg_match('#^\s*(((fulltext|primary|unique)\s*)?key\s+|index\s+|engine\s*=)#si', $field))
						{
							continue;
						}
						if (preg_match('#^(`?)([a-z0-9_\-]+)(\\1)#si', $field, $matches2))
						{
							$newtable[] = $matches2[2];
						}
					}

					if (array_diff($existingtable, $newtable))
					{
						$this->add_error(TABLE_PREFIX . $matches[1], self::APP_CREATE_TABLE_EXISTS, true);
						$error = true;
					}
				}
			}
		}

		return !$error;
	}

	/**
	* Add an error
	*
	* @param	string	Data of item to be output
	* @param	int			Key of item
	* @param	boolean	This error signals stoppage of the upgrade process if true
	*/
	public function add_error($value = '', $code = '', $fatal = false)
	{
		$this->response['error'][] = array(
			'code'  => $code,
			'value' => $value,
			'fatal' => $fatal,
		);
	}

	/**
	* Add a message
	*
	* @param	string	Key of item
	* @param	string	Data of item to be output
	* @param	boolean	Replace previous message with this message, if it had $replace set as well..
	*/
	protected function add_message($value = '', $code = 'STANDARD', $replace = false)
	{
		$this->response['message'][] = array(
			'code'    => $code,
			'value'   => $value,
			'replace' => $replace,
		);
	}


	/**
	 * This sets an option. It's for where we need to change an existing value
	 *
	 *	@param string
	 *	@param string //we actually don't currently use this parameter
	 *	@param string
	 *
	 */
	protected function set_option($varname, $grouptitle, $value)
	{
		include_once DIR . '/includes/adminfunctions_options.php';
		$values = array($varname => $value);
		save_settings($values);
	}

	/**
	 * This sets an option. It should rarely used. Its primary use is for temporarily
	 * storing the version number from which this upgrade started. Any other use should be
	 * carefully considered as to why you don't just put in the XML file.
	 *
	 *	@param string
	 *	@param string //we actually don't currently use this parameter
	 *	@param string
	 */
	protected function set_new_option($varname, $grouptitle, $value, $datatype, $default_value = false, $optioncode = '', $product = 'vbulletin', $adminperm = '')
	{

		$row = vB::getDbAssertor()->getRow('setting', array('varname' => $varname));
		if (!$row)
		{
			$params = array(
					'product' => $product,
					'varname' => $varname,
					'grouptitle' => $grouptitle,
					'value' => $value,
					'datatype' => $datatype,
					'optioncode' => $optioncode,
					'adminperm' => $adminperm
			);
			if (!empty($default_value))
			{
				$params['default_value'] = $default_value;
			}
			vB::getDbAssertor()->assertQuery('replaceSetting', $params);
		}
		include_once DIR . '/includes/adminfunctions_options.php';
		$values = array($varname => $value);
		if ($default_value)
		{
			$values[$varname]['default_value'] = $default_value;
		}
		save_settings($values, array($row));

	}

	/**
	* Log the current location of the upgrade
	*
	* @param	string	Upgrade Step
	* @param	int			Startat value for multi step steps
	* @param	bool		Process only the current version upgrade
	*/
	public function log_upgrade_step($step, $startat = 0, $only = false)
	{
		$complete = ($step == $this->stepcount);
		$perpage = 0;
		$insertstep = true;

		if ($complete)
		{
			$step = 0;
			if ($this->SHORT_VERSION == 'final' OR $only)
			{
				//This needs an index on 'script' added
				$this->db->query_write("
					DELETE FROM " . TABLE_PREFIX . "upgradelog
					WHERE script IN ('final')
				");

				$insertstep = false;
			}
			else
			{
				require_once(DIR . '/includes/adminfunctions_template.php');
				if (is_newer_version($this->LONG_VERSION, $this->registry->options['templateversion']))
				{
					$this->db->query_write("UPDATE " . TABLE_PREFIX . "setting SET value = '" .
						$this->LONG_VERSION . "' WHERE varname = 'templateversion'");
				}
				if (!defined('SKIPDB'))
				{
					vB::getDatastore()->build_options();
				}

				$this->registry->options['templateversion'] = $this->LONG_VERSION;
			}
		}

		if ($insertstep AND !defined('SKIPDB'))
		{
			// use time() not TIMENOW to actually time the script's execution
			/*insert query*/
			$this->db->query_write("
				INSERT INTO " . TABLE_PREFIX . "upgradelog(script, steptitle, step, startat, perpage, dateline, only)
				VALUES (
					'" . $this->db->escape_string($this->SHORT_VERSION) . "',
					'',
					$step,
					$startat,
					$perpage,
					" . time() . ",
					" . intval($only) . "
			)");
		}
	}

	/**
	* Parse exception
	*
	* @param	string	error msg to parse
	*
	* @return	string
	*/
	protected function stop_exception($e)
	{
		$args = $e->getParams();
		vB_Upgrade::createAdminSession();
		$phraseAux = vB_Api::instanceInternal('phrase')->fetch(array($args[0]));
		$message = $phraseAux[$args[0]];

		if (sizeof($args) > 1)
		{
			$args[0] = $message;
			$message = call_user_func_array('construct_phrase', $args);
		}

		return $message;
	}

	/**
	 * Converts a version number string into an array that can be parsed
	 * to determine if which of several version strings is the newest.
	 *
	 * @param	string	Version string to parse
	 * @return	array	Array of 6 bits, in decreasing order of influence; a higher bit value is newer
	 */
	private function fetch_version_array($version)
	{
		// parse for a main and subversion
		if (preg_match('#^([a-z]+ )?([0-9\.]+)[\s-]*([a-z].*)$#i', trim($version), $match))
		{
			$main_version = $match[2];
			$sub_version = $match[3];
		}
		else
		{
			$main_version = $version;
			$sub_version = '';
		}

		$version_bits = explode('.', $main_version);

		// pad the main version to 4 parts (1.1.1.1)
		if (sizeof($version_bits) < 4)
		{
			for ($i = sizeof($version_bits); $i < 4; $i++)
			{
				$version_bits["$i"] = 0;
			}
		}

		// default sub-versions
		$version_bits[4] = 0; // for alpha, beta, rc, pl, etc
		$version_bits[5] = 0; // alpha, beta, etc number

		if (!empty($sub_version))
		{
			// match the sub-version
			if (preg_match('#^(A|ALPHA|B|BETA|G|GAMMA|RC|RELEASE CANDIDATE|GOLD|STABLE|FINAL|PL|PATCH LEVEL)\s*(\d*)\D*$#i', $sub_version, $match))
			{
				switch (strtoupper($match[1]))
				{
					case 'A':
					case 'ALPHA';
						$version_bits[4] = -4;
						break;

					case 'B':
					case 'BETA':
						$version_bits[4] = -3;
						break;

					case 'G':
					case 'GAMMA':
						$version_bits[4] = -2;
						break;

					case 'RC':
					case 'RELEASE CANDIDATE':
						$version_bits[4] = -1;
						break;

					case 'PL':
					case 'PATCH LEVEL';
						$version_bits[4] = 1;
						break;

					case 'GOLD':
					case 'STABLE':
					case 'FINAL':
					default:
						$version_bits[4] = 0;
						break;
				}

				$version_bits[5] = $match[2];
			}
		}

		// sanity check -- make sure each bit is an int
		for ($i = 0; $i <= 5; $i++)
		{
			$version_bits["$i"] = intval($version_bits["$i"]);
		}

		return $version_bits;
	}

	/**
	 * Compares two version strings. Returns true if the first parameter is
	 * newer than the second.
	 *
	 * @param	string	Version string; usually the latest version
	 * @param	string	Version string; usually the current version
	 *
	 * @return	bool	True if the first argument is newer than the second
	 */
	public function is_newer_version($new_version_str, $cur_version_str)
	{
		// if they're the same, don't even bother
		if ($cur_version_str != $new_version_str)
		{
			$cur_version = $this->fetch_version_array($cur_version_str);
			$new_version = $this->fetch_version_array($new_version_str);

			// iterate parts
			for ($i = 0; $i <= 5; $i++)
			{
				if ($new_version["$i"] != $cur_version["$i"])
				{
					// true if newer is greater
					return ($new_version["$i"] > $cur_version["$i"]);
				}
			}
		}

		return false;
	}

	protected function tableExists($tablename)
	{
		try
		{
			$tables = $this->db->query_first("
			SHOW TABLES LIKE '" . TABLE_PREFIX . "$tablename'");
			return (!empty($tables));
		}
		catch(Exception $e)
		{
			return false;
		}
	}

	protected function getBatchInfo($startat, $process, $total)
	{
		$batchInfo = array();

		$batchInfo['startat'] = $startat;
		$batchInfo['first'] = (($startat > 1)? (($startat - 1) * $process) : 0);
		$batchInfo['more'] = (($batchInfo['first'] < $total) ? true : false);
		$batchInfo['records'] = ((($batchInfo['first'] + $process) < $total) ? ($batchInfo['first'] + $process) : $total);
		$batchInfo['message'] = "";
		$batchInfo['returnInfo'] = "";
		if ($startat == 0)
		{
			if ($total)
			{
				$this->show_message(sprintf($this->phrase['core']['processing_records_x'], $total));
				$batchInfo['startat'] = 1;
				return $batchInfo;
			}
			else
			{
				$batchInfo['displaySkipMessage'] = 1;
				return $batchInfo;
			}
		}

		return $batchInfo;

	}

	protected function getDefaultGroupPerms()
	{
		require_once(DIR . '/includes/class_bitfield_builder.php');
		if (vB_Bitfield_Builder::build(false) !== false)
		{
			$myobj =& vB_Bitfield_Builder::init();
		}
		else
		{
			print_r(vB_Bitfield_Builder::fetch_errors());
		}

		$groupinfo = array();
		foreach ($myobj->data['ugp'] AS $grouptitle => $perms)
		{
			for ($x = 1; $x <= 10; $x++)
			{
				$groupinfo["$x"]["$grouptitle"] = 0;
			}

			foreach ($perms AS $permtitle => $permvalue)
			{
				if (empty($permvalue['group']))
				{
					continue;
				}

				if (!empty($permvalue['install']))
				{
					foreach ($permvalue['install'] AS $gid)
					{
						$groupinfo["$gid"]["$grouptitle"] += $permvalue['value'];
					}
				}
			}
		}

		return $groupinfo;
	}

	protected function createSystemGroups()
	{
		$groupinfo = $this->getDefaultGroupPerms();

		// KEEP THIS IN SYNC with mysql-schema's usergroup code (lines~ 4103) until we refactor this & get rid of dupe code.
		$pmquota = 500;
		$systemgroups = array(
			vB_Api_UserGroup::CHANNEL_OWNER_SYSGROUPID => $this->createUserGroupArray(
				vB_Api_UserGroup::CHANNEL_OWNER_SYSGROUPID,
				'channelowner_title',
				$groupinfo[9]
			),
			vB_Api_UserGroup::CHANNEL_MODERATOR_SYSGROUPID => $this->createUserGroupArray(
				vB_Api_UserGroup::CHANNEL_MODERATOR_SYSGROUPID,
				'channelmod_title',
				$groupinfo[10]
			),
			vB_Api_UserGroup::CHANNEL_MEMBER_SYSGROUPID => $this->createUserGroupArray(
				vB_Api_UserGroup::CHANNEL_MEMBER_SYSGROUPID,
				'channelmember_title',
				//this is wrong but still needs to be cleaned up VBV-12400
				$groupinfo[2]
			),
			vB_Api_UserGroup::CMS_AUTHOR_SYSGROUPID => $this->createUserGroupArray(
				vB_Api_UserGroup::CMS_AUTHOR_SYSGROUPID,
				'cms_author_title',
				//this is wrong but still needs to be cleaned up VBV-12400
				$groupinfo[2]
			),
			vB_Api_UserGroup::CMS_EDITOR_SYSGROUPID => $this->createUserGroupArray(
				vB_Api_UserGroup::CMS_EDITOR_SYSGROUPID,
				'cms_editor_title',
				//this is wrong but still needs to be cleaned up VBV-12400
				$groupinfo[2]
			),
		);

		$groupApi = vB_Api::instanceInternal('usergroup');
		$assertor = vB::getDbAssertor();
		foreach($systemgroups AS $groupid => $data)
		{
			//If the usergroup doesn't exist, the api throws an exception. That drives the behavior.
			try
			{
				$group = $groupApi->fetchUsergroupBySystemID($groupid);

				if (empty($group['usergroupid']))
				{
					$data[vB_dB_Query::TYPE_KEY] = vB_dB_Query::QUERY_INSERT;
					$assertor->assertQuery('usergroup', $data);
				}
			}
			catch(exception $e)
			{
				$data[vB_dB_Query::TYPE_KEY] = vB_dB_Query::QUERY_INSERT;
				$assertor->assertQuery('usergroup', $data);
			}
		}

		// rebuild usergroup cache
		vB_Library::instance('usergroup')->buildDatastore();
		$groupApi->fetchUsergroupList(true);
	}

	private function createUserGroupArray($systemgroupid, $titlephrase, $groupinfo)
	{
		// This function collapses the default values for the groups used *in this file*
		// which were mostly repeated.  If we need to make them different I recommend taking
		// the approach of batching which permissions belong together (for instance image size limits)
		// and creating an array for each different "package" and passing that in similarly to the
		// $groupinfo array.  (We don't necesarily need one for each group -- if there are two sets
		// of values for the five groups then we only need to arrays).  The goal is to avoid having
		// to constantly repeat massive arrays of identical values which will frequently fail to get
		// updated properly if we decide to change a default across the board.
		$pmquota = 500;
		$group = array(
			'title' => $this->phrase['install'][$titlephrase],
			'description' => '',
			'usertitle' => '',
			'passwordexpires' => 0,
			'passwordhistory' => 0,
			'pmquota' => $pmquota,
			'pmsendmax' => 5,
			'opentag' => '',
			'closetag' => '',
			'canoverride' => 0,
			'ispublicgroup' => 0,
			'attachlimit' => 0,
			'avatarmaxwidth' => 200,
			'avatarmaxheight' => 200,
			'avatarmaxsize' => 100000,
			'sigmaxrawchars' => 1000,
			'sigmaxchars' => 500,
			'sigmaxlines' => 0,
			'sigmaxsizebbcode' => 7,
			'sigmaximages' => 4,
			'sigpicmaxwidth' => 500,
			'sigpicmaxheight' => 100,
			'sigpicmaxsize' => 10000,
			'albumpicmaxwidth' => 600,
			'albumpicmaxheight' => 600,
			'albummaxpics' => 100,
			'albummaxsize' => 0,
			'pmthrottlequantity' => 0,
			'groupiconmaxsize' => 65535,
			'maximumsocialgroups' => 5,
			'systemgroupid' => $systemgroupid,

			//the group permissions contain a field that doesn't belong here.
			//let's only copy what we know we need to avoid errors.
			'forumpermissions' => $groupinfo['forumpermissions'],
			'forumpermissions2' => $groupinfo['forumpermissions2'],
			'pmpermissions' => $groupinfo['pmpermissions'],
			'calendarpermissions' => $groupinfo['calendarpermissions'],
			'wolpermissions' => $groupinfo['wolpermissions'],
			'adminpermissions' => $groupinfo['adminpermissions'],
			'genericpermissions' => $groupinfo['genericpermissions'],
			'genericpermissions2' => $groupinfo['genericpermissions2'],
			'signaturepermissions' => $groupinfo['signaturepermissions'],
			'genericoptions' => $groupinfo['genericoptions'],
			'usercsspermissions' => $groupinfo['usercsspermissions'],
			'visitormessagepermissions' => $groupinfo['visitormessagepermissions'],
			'socialgrouppermissions' => $groupinfo['socialgrouppermissions'],
			'albumpermissions' => $groupinfo['albumpermissions'],
		);

		return $group;
	}

	protected function syncNavbars($addNavBars = array())
	{
		if (!is_array($addNavBars))
		{
			$addNavBars = array($addNavBars);
		}
		$navbars = get_default_navbars();
		$headernavbar = $navbars['header'];

		// Get site's current navbar data
		$site = vB::getDbAssertor()->getRow('vBForum:site', array('siteid' => 1));

		$currentheadernavbar = @unserialize($site['headernavbar']);

		foreach ((array)$headernavbar as $j => $item)
		{
			$tabExists = false;
			// Check Tab
			foreach ((array)$currentheadernavbar as $k => $currentitem)
			{
				if ($currentitem['title'] == $item['title'])
				{
					$tabExists = true;
					// We have the tab, check for subnavs of the tab
					foreach ((array)$item['subnav'] as $subitem)
					{
						foreach ((array)$currentitem['subnav'] as $currentsubitem)
						{
							if ($subitem['title'] == $currentsubitem['title'])
							{
								// The site already has the subitem, skip to next one
								continue 2;
							}
						}
						// The site doesn't have the subitem, we insert it
						$currentheadernavbar[$k]['subnav'][] = $subitem;
					}
				}
			}
			/* If tab does not exist and was specified in the params, insert the tab.
			 * This is to prevent addition of any default items that the user deleted from the header nav bar.
			 * As such, when adding new nav bar item(s) to the header in functions_installupgrade.php's
			 * get_default_navbars(), the upgrade step calling syncNavBars() should specify the title(s) of the
			 * newly added navBar(s)
			 */
			if (!$tabExists AND in_array($item['title'], $addNavBars))
			{
				// insert the item into header @ default index
				array_splice($currentheadernavbar, $j, 0, array($item));
			}

		}

		$this->show_message(sprintf($this->phrase['vbphrase']['update_table'], TABLE_PREFIX . 'site'));
		vB::getDbAssertor()->update('vBForum:site',
			array(
				'headernavbar' => serialize($currentheadernavbar),
			),
			array(
				'siteid' => 1,
			)
		);

	}

	/**
	 *	Updates the header tab urls with new urls.
	 *
	 *	This is intended to update default urls in the headers if they changed.
	 *	We work with an exact match to replace.  We don't really worry about
	 *	where we matched because if a default url changed, it changed
	 *	(and by doing an exact match we don't have to worry as much about
	 *	a similar url we weren't expecting).
	 */
	protected function updateHeaderUrls($urls)
	{
		$assertor = vB::getDbAssertor();

		// Get site's current navbar data
		$site = $assertor->getRow('vBForum:site', array('siteid' => 1));

		$changed = false;
		$headernavbar = @unserialize($site['headernavbar']);
		foreach ((array)$headernavbar AS $key => $currentitem)
		{
			foreach($urls AS $old => $new)
			{
				if($headernavbar[$key]['url'] == $old)
				{
					$headernavbar[$key]['url'] = $new;
					$changed = true;
				}
			}

			// We have the tab, check for subnavs of the tab
			foreach ((array)$currentitem['subnav'] AS $subkey => $currentsubitem)
			{
				foreach($urls AS $old => $new)
				{
					if($headernavbar[$key]['subnav'][$subkey]['url'] == $old)
					{
						$headernavbar[$key]['subnav'][$subkey]['url'] = $new;
						$changed = true;
					}
				}

				$headernavbar[$key]['subnav'][$subkey]['url'] = vB_String::unHtmlSpecialChars($headernavbar[$key]['subnav'][$subkey]['url']);
			}
		}

		if($changed)
		{
			$assertor->update('vBForum:site',
				array(
					'headernavbar' => serialize($headernavbar),
				),
				array(
					'siteid' => 1,
				)
			);
		}

		$this->show_message(sprintf($this->phrase['vbphrase']['update_table'], TABLE_PREFIX . 'site'));
	}

	protected function iRan($function, $startat = 0, $showmsg = true)
	{
		/*
			Don't forget to add a dummy, empty last step if the caller to this would be the last step otherwise.
		 */
		$script = str_replace('vB_Upgrade_', '', get_class($this));
		$step = str_replace('step_', '', $function);
		$log = vB::getDbAssertor()->assertQuery('vBInstall:upgradelog', array('script' => $script, 'step' => $step, 'startat' => $startat));

		if ($log->valid())
		{
			if ($showmsg)
			{
				$this->show_message(sprintf($this->phrase['core']['skipping_already_ran'], $script, $step));
			}
			return true;
		}

		return false;
	}

	protected function getUGPBitfields($groupnames = array())
	{
		$requested = array();
		if (is_string($groupnames))
		{
			// Assume it's just 1 that's requested
			// todo: allow delimited string?
			$groupnames = array($groupnames);
		}

		if (!is_array($groupnames))
		{
			throw new Exception('Invalid groupnames');
		}

		foreach($groupnames AS $__groupname)
		{
			// for O(1) isset() check.
			$requested[$__groupname] = $__groupname;
		}

		// taken from 510a5 upgrade. TODO: refactor to remove dupe code.
		vB_Upgrade::createAdminSession();
		$parsedRaw = vB_Xml_Import::parseFile(DIR . '/includes/xml/bitfield_vbulletin.xml');
		$permBits = array();
		foreach ($parsedRaw['bitfielddefs']['group'] AS $group)
		{
			if ($group['name'] == 'ugp')
			{
				foreach($group['group'] AS $bfgroup)
				{
					if (($bfgroup['name'] == 'forumpermissions2') OR ($bfgroup['name'] == 'forumpermissions') OR
						($bfgroup['name'] == 'createpermissions') OR isset($requested[$bfgroup['name']])
					)
					{
						$permBits[$bfgroup['name']] = array();
						foreach ($bfgroup['bitfield'] AS $bitfield)
						{
							$permBits[$bfgroup['name']][$bitfield['name']] = intval($bitfield['value']);
						}
					}
				}
			}
		}

		return $permBits;
		/*
		use like
		$someNewPermsToSave['createpermissions'] |= $permBits['createpermissions']['vbforum_text'] |
		$permBits['createpermissions']['vbforum_gallery'] | $permBits['createpermissions']['vbforum_poll'] |
		$permBits['createpermissions']['vbforum_attach'] | $permBits['createpermissions']['vbforum_photo'] |
		$permBits['createpermissions']['vbforum_video'] | $permBits['createpermissions']['vbforum_link'];
			*/
	}


	//
	//	Upgrade step templates
	//
	//	There are some things we do a lot of and it would be good to abstract that here so that we
	//	aren't constantly rewriting the same code over and over. And so that the actual differences
	//	become clearer.  We've sort of down that with a few functions already (and we might want
	//	to move some functions down to this section).
	//


	/**
	 * Update in batches iterated over a table unique id field
	 *
	 * This will automatically run a query to generate the next id to avoid situations where
	 * gaps in the ids mean that the batch processing ends up taking longer than processing
	 * the actual records.  For example on instance where there were over a million missing
	 * ids that we iterated over 500 id numbers at a time -- selecting precisely 0 records
	 * to update each pass for *hours*.  This function ensures that each pass will process
	 * $batchsize records except for possibly the last step even if the numbers are not
	 * sequential.
	 *
	 * NOTE -- Do not blindly use this function if there is a better index to iterator
	 * 	over that better matches the records that need processing.  This is useful if
	 * 	we need to walk an entirely table based on the primary key either because we
	 * 	need to process every record or because we
	 *
	 * @param array $data -- The data array passed to the step
	 * @param int $batchsize -- The number of records to process per iteration
	 * @param string $maxquery -- Assertor queryname to get the max record id.  Unfortunately we
	 * 	can't currently get that information from a table query so we need to create a stored
	 * 	query and pass it seperately.
	 * @param string $table -- The table to iterate over.  Note that the actual update
	 * 	query doesn't need to confined to this table so long as the ID range being
	 * 	processed is on an id field in this table
	 * @param string $idfield -- The name of the field to iterate over.  This field
	 * 	*must* be an integer field and it must be indexed and the values in the field must
	 * 	be unique.  Otherwise we cannot guarentee that we'll process efficiently or that
	 * 	we will process every record in the table.
	 * 	Typically this will be the standard primary key for the table.
	 * @param callable $callback -- The function to call to handle this iteration.  This
	 * 	function should output a message via show_message.  The following parameters will
	 * 	be passed
	 * 	-- $startat the first id to process (will start at 0 even though we generally don't
	 * 		have an ID 0).  The callback should process an ID range *inclusive* of startat
	 * 	-- $nextid the next to process after this batch.  The callback should process an ID
	 * 		range *exclusive* of nextid
	 *
	 * @return array|null either a data array for step iteration or a null value
	 * 	if the process is complete.  Either way it's appropriate to return the
	 * 	value from a step without
	 */
	public function updateByIdWalk($data, $batchsize, $maxquery, $table, $idfield, $callback)
	{
		$db = vB::getDbAssertor();
		$startat = intval($data['startat']);

		//this doesn't really work because "max" isn't propagated in $data, but
		//leaving it in so that it will work if we fix that.
		if (!empty($data['max']))
		{
			$max = $data['max'];
		}
		else
		{
			$max = $db->getRow($maxquery);
			$max = $max['maxid'];

			//If we don't have any posts, we're done.
			if (intval($max) < 1)
			{
				$this->skip_message();
				return;
			}
		}

		if ($startat > $max)
		{
			$this->show_message(sprintf($this->phrase['core']['process_done']));
			return;
		}
		$nextrow = $db->getRows(
			$table,
			array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
				vB_dB_Query::CONDITIONS_KEY => array(
					array('field' => $idfield, 'value' => $startat, 'operator' =>  vB_dB_Query::OPERATOR_GT),
				),
				vB_dB_Query::COLUMNS_KEY => array($idfield),
				vB_Db_Query::PARAM_LIMIT => 1,
				vB_Db_Query::PARAM_LIMITSTART => $batchsize
			),
			$idfield
		);

		//if we don't have a row, we paged off the table so we just need to go from start to the end
		if($nextrow)
		{
			$nextrow = reset($nextrow);
			$nextid = $nextrow[$idfield];
		}
		else
		{
			//we don't include the next threadid in the query below so we need to go "one more than max"
			//to ensure that we process the last record and terminate on the next call.
			$nextid = $max + 1;
		}

		call_user_func($callback, $startat, $nextid);
		return array('startat' => $nextid, 'max' => $max);
	}


	public function reinstallProductPackage(
		$package = 'twitterlogin',
		$forceFreshInstall = false,
		$deferRebuild = false,
		$skipProductAutoInstallCheck = false
	)
	{
		// Call this to pick up any product XML changes between versions (including alpha/beta)
		$assertor = vB::getDbAssertor();
		$check = $assertor->getRow('product', array('productid' => $package));

		$datastore = vB::getDatastore();
		$hooksEnabled = $datastore->getOption('enablehooks');
		if (!empty($check) OR $forceFreshInstall)
		{
			vB_Upgrade::createAdminSession();


			if (!defined('VB_PKG_PATH'))
			{
				$packagesDir = realpath(DIR . '/packages') . '/';
			}
			else
			{
				$packagesDir = VB_PKG_PATH;
			}


			$xmlDir = $packagesDir . "$package/xml";
			$class = $package . '_Product';

			$overwrite = true;
			// todo: some extensions do not have a product php file, but rather the
			// extension class specifies the autoinstall, and vb_api_extensions handles autoinstall
			// (via the same vB_Library_Functions::installProduct()).
			// How do we specify those to be forcibly upgraded?
			$autoInstall = (
				class_exists($class) AND property_exists($class, 'AutoInstall') AND $class::$AutoInstall

			);

			if ($skipProductAutoInstallCheck OR $autoInstall)
			{
				if (empty($check))
				{
					$this->show_message(sprintf($this->phrase['final']['installing_product_x'], $package));
				}
				else
				{
					$this->show_message(sprintf($this->phrase['final']['updating_product_x'], $package));
				}
				$printInfo = false;
				$info = vB_Library_Functions::installProduct($package, $xmlDir, '', $overwrite, $printInfo, $deferRebuild);

				$disableProduct = true;
				$disableReason = "";

				/*
					If the product build was successful, info is an array of various information,
					with a 'need_merge' key pointing to a boolean true/false.
					If the product build threw an exception (e.g. due to dependency failures),
					vB_Library_Functions::installProductXML() returns boolean false.
					If build_all_styles() failed, install_product() returns the error string.
				 */
				if (is_string($info))
				{
					// This is *probably* a string error message. It's possibly from a style build failure
					$disableReason = $info;
				}
				elseif (is_array($info))
				{
					// success
					$disableProduct = false;
				}
				elseif ($info === false)
				{
					// exception, probably dependency failure.
					// ATM this doesn't get out of the exception catch.
					$disableReason = vB_Library_Functions::getLastError();
					if (empty($disableReason))
					{
						$disableReason = "Unknown Error. Possibly a product dependency check failure.";
					}
				}
				else
				{
					// unknown/undefined condition. Not known to happen at the moment
				}

				vB_Library::instance('product')->buildProductDatastore();
				if (!$hooksEnabled)
				{
					/*
						Re-installing the twitterlogin package automatically enables the hook system.
						If they had it disabled earlier, set it back to disabled.
						We could consider just skipping the re-install altogether if the hook system is
						disabled, but I worry that doing so would lead to data inconsistencies in the
						tester DBs. Note that we check for the existence of the twitterlogin package first,
						which implies (I think) that at *some* point, the product got installed and the
						hook/product system was enabled, then disabled by the admin.
					 */
					$assertor->update('setting', array('value' => 0), array('varname' => 'enablehooks'));
					vB::getDatastore()->build_options();
				}


				// Use title if it's available in the product table.
				// This is a bit sketchy, but we'd have to re-parse the XML to get the title if it's
				// a new install and it failed.
				if (!empty($check['title']))
				{
					$productTitle = $check['title'];
				}
				else
				{
					// If the install failed before the product DB insert, the only place remaining
					// that has the title is the XML. For now, just use the productid.
					$check2 = $assertor->getRow('product', array('productid' => $package));
					if (!empty($check2['title']))
					{
						$productTitle = $check2['title'];
					}
					else
					{
						$productTitle = $package;
					}
				}


				if ($disableProduct OR !empty($check) AND $check['active'] == 0)
				{
					// Either install failed, or this was previously disabled so we're setting it back to disabled.
					$assertor->update('product', array('active' => 0), array('productid' => $package));

					if (!empty($disableReason))
					{
						$this->show_message(sprintf($this->phrase['final']['product_x_disabled_reason_y'], $productTitle, $disableReason));
						$this->add_adminmessage(
							'disabled_product_x_y_z',
							array(
								'dismissable' => 1,
								'script'      => '',
								'action'      => '',
								'execurl'     => '',
								'method'      => '',
								'status'      => 'undone',
							),
							true,
							array($productTitle, $package, $disableReason)
						);
					}
					else
					{
						$this->show_message(sprintf($this->phrase['final']['product_x_updated_remains_disabled'], $package));
					}
				}
			}
			else
			{
				$this->skip_message();
			}
		}
		else
		{
			$this->skip_message();
		}
	}

	/**
	 * Replace the instances of a module ("old module") with instance of another module
	 * ("new module"), and then delete the old module & module definitions. The new module being
	 * used must already exist.
	 *
	 * This does *NOT* replace phrase keys or channel guids in the config data, but that
	 * will happen in upgrade_final, which should be fine.
	 */
	protected function replaceModule($oldWidgetGuid, $newWidgetGuid, $newDefaultAdminConfig = array())
	{
		$assertor = vB::getDbAssertor();

		$oldWidget = $assertor->getRow('widget', array('guid' => $oldWidgetGuid));
		$newWidget = $assertor->getRow('widget', array('guid' => $newWidgetGuid));

		$instancesDeleted = 0;
		$widgetDeleted = false;

		if ($oldWidget)
		{
			// convert instances of the old widget to instances of the new widget
			$oldInstances = $assertor->getRows('widgetinstance', array('widgetid' => $oldWidget['widgetid']));
			foreach ($oldInstances AS $oldInstance)
			{
				$conditions = array('widgetinstanceid' => $oldInstance['widgetinstanceid']);
				$values = array();

				// change to new  widgetid
				$values['widgetid'] = $newWidget['widgetid'];

				// change admin config to the new default
				// we simply copy the new default adminconfig, but
				// if the old adminconfig has any of the same config
				// settings as the new one, the old values are preserved
				// e.g., results per page or hide title, etc.
				$oldAdminConfig = array();
				$newAdminConfig = $newDefaultAdminConfig;
				if (!empty($oldInstance['adminconfig']))
				{
					$temp = unserialize($oldInstance['adminconfig']);
					if ($temp)
					{
						$oldAdminConfig = $temp;
					}
				}
				foreach ($newAdminConfig AS $k => $v)
				{
					if (isset($oldAdminConfig[$k]))
					{
						$newAdminConfig[$k] = $oldAdminConfig[$k];
					}
				}
				$values['adminconfig'] = serialize($newAdminConfig);

				// update
				$assertor->update('widgetinstance', $values, $conditions);

				++$instancesDeleted;
			}

			// delete the old widget & widget definition records
			$assertor->delete('widget', array('widgetid' => $oldWidget['widgetid']));
			$assertor->delete('widgetdefinition', array('widgetid' => $oldWidget['widgetid']));

			$widgetDeleted = true;
		}

		return array(
			'updated' => $widgetDeleted,
			'instancesDeleted' => $instancesDeleted,
		);
	}

	/**
	 * Updates a simple field value, split into batches.
	 *
	 * Usage: If using this function, it should be the only thing used in the upgrade
	 * step. The $data array should be passed through to and from the containing step
	 * function in the param and via return. See upgrade steps where this is used for
	 * examples.
	 *
	 * @param  array  The data array used by the step function for batching
	 * @param  string The table name where we want to update a field/fields
	 * @param  string The incrementing ID column name to control the updates
	 * @param  string The column to update
	 * @param  array  The old value (used to find the rows)
	 * @param  array  The new value (to update to)
	 * @param  int    Batch size (how many records to update on each iteration)
	 * @param  string Phrase to describe what we are updating in this step
	 *
	 * @return array  Returns the data array for step batching, or null if done
	 */
	protected function updateFieldValueBatch($data, $table, $idColumn, $updateColumn, $oldValue, $newValue, $batchSize, $phrase = null)
	{
		$db = vB::getDbAssertor();

		if (!$phrase)
		{
			$phrase = sprintf($this->phrase['vbphrase']['update_table'], TABLE_PREFIX . $table);

		}

		$conditions = array();
		$conditions[$updateColumn] = $oldValue;
		$conditions[vB_dB_Query::PARAM_LIMIT] = $batchSize;
		$rows = $db->getColumn($table, $idColumn, $conditions, $idColumn);

		// first iteration
		if (empty($data['startat']))
		{
			if (empty($rows))
			{
				// nothing to do
				$this->skip_message();

				return;
			}
			else
			{
				// run the first iteration
				$this->show_message($phrase);
				$data['startat'] = 0;
			}
		}

		if (empty($rows))
		{
			// done
			$this->show_message(sprintf($this->phrase['core']['process_done']));
		}
		else
		{
			// we have values to update
			$values = array();
			$values[$updateColumn] = $newValue;

			$conditions = array();
			$conditions[$updateColumn] = $oldValue;
			$conditions[] = array(
				'field' => $idColumn,
				'value' => min($rows),
				'operator' => vB_dB_Query::OPERATOR_GTE,
			);
			$conditions[] = array(
				'field' => $idColumn,
				'value' => max($rows),
				'operator' => vB_dB_Query::OPERATOR_LTE,
			);

			$updated = $db->update($table, $values, $conditions);

			$this->show_message(sprintf($this->phrase['core']['processing_records_x'], $updated));

			// force another iteration by returning a positive startat value
			// even though we don't use it to determine which rows to update
			return array('startat' => $data['startat'] + 1);
		}
	}
}

class vB_Upgrade_Version_Empty extends vB_Upgrade_Version
{
	/**
	 * Constructor.
	 *
	 * @param vB_Registry	$registry
	 * @param array $phrases
	 * @param string $version -- the current short version
	 * @param array $versions -- the calculated versions array
	 */
	public function __construct(&$registry, $phrase, $version, $versions)
	{
		parent::__construct($registry, $phrase, end($versions));

		$previous = false;
		foreach($versions AS $short => $long)
		{
			if ($short == $version)
			{
				break;
			}

			$previous = $long;
		}

		if(!$previous)
		{
			//this literally should never happen in production so don't want to
			//go through the effort of phrasing it it.
			throw new Exception('No previous version found for version ' . $version);
		}

		$this->SHORT_VERSION = $version;
		$this->LONG_VERSION = $versions[$version];
		$this->PREV_VERSION = $previous;

		//we don't handle situations where there isn't a single previous
		//version generically.  Even if its otherwise empty you'll need
		//a class to handle this case.
		$this->VERSION_COMPAT_STARTS = '';
		$this->VERSION_COMPAT_ENDS   = '';
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 104293 $
|| #######################################################################
\*=========================================================================*/
