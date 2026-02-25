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
 * vB_Api_Extensions
 *
 * @package vBApi
 * @access public
 */
class vB_Api_Extensions extends vB_Api
{
	/**
	 * Contains extensions for all API classes
	 * @var array
	 */
	protected static $extensions;

	/**
	 * stores the packages folder list
	 * @var array
	 */
	protected static $folders = array();

	/**
	 * Array of flags for controller loading
	 * @var array
	 */
	protected static $checked = array();

	/**
	 * Folders loaded flag
	 * @var array
	 */
	protected static $foldersLoaded = false;

	/**
	 * Name of the API module
	 * @var string
	 */
	protected $controller;

	/**
	 * Extension class name
	 * @var string
	 */
	public $extensionClass;

	// Varname used for passing results from core API or other extensions. All extended methods must use this name.
	protected $resultVarName = 'prevResult';

/*
	Default Extension Values
	The should normally be overridded by the each extension class
*/

	// Product id
	protected $product = 'vbulletin';

	// Extension Version
	// Defaults to current version.
	protected $version = '5.6.0';

	// Extension Developer
	protected $developer = '';

	// Extension Title
	protected $title = 'Extensions Default Title';

	// Minimum required vB version (> 5.0.0 Alpha 1)
	protected $minver = '5.0.0 Alpha 1';

	// Maximum Compatible vB version
	protected $maxver = '5.9.99';

	// Url for extension information (e.g. vb.org thread)
	protected $infourl = 'https://www.vbulletin.com';

	// Version check url
	protected $checkurl = '';

	// Extension Execution Order
	protected $extensionOrder = 10;

	// Auto Install Product XML if product not detected
	protected $AutoInstall = 0;

	// Classes that must exist for this extension to run
	protected $ClassDependancy = '';

	// Products that must be installed & enabled for this extension to run
	protected $ProductDependancy = '';


	// ********************
	// ** STATIC METHODS **
	// ********************

	/**
	 * Builds the class name for an extension using the file name
	 * @param string $extension
	 * @return string
	 */
	private static function getExtensionClass($controller, $product)
	{
		$safeid = preg_replace('#[^a-z0-9]#', '', strtolower($product));
		$c = ucfirst($safeid) . '_Api_' . implode('_', array_map('ucfirst', array_map('strtolower', explode('_',$controller)))) ;
		return $c;
	}

	/**
	 * Check if correct product, and compatible with current vB version.
	 */
	private static function isCompatible($class, $package, $options)
	{
		if (strtolower($class->product) != strtolower($package))
		{
			return false;
		}

		$MinOK = vB_Library_Functions::isNewerVersion($options['templateversion'], $class->minver, true);
		$MaxOK = vB_Library_Functions::isNewerVersion($class->maxver, $options['templateversion'], true);

		return ($MinOK AND $MaxOK);
	}

	/**
	 * Check if product/extension is enabled.
	 * Returns
	 * 0 = Disabled
	 * 1 = Enabled : Product Dependancy Failed
	 * 2 = Enabled : Class Dependancy Failed
	 * 3 = Enabled : Dependancy check is Ok
	 */
	private static function isEnabled($class, $products)
	{
		static $state = array();

		if (isset($state[$class->extensionClass]))
		{
			return $state[$class->extensionClass];
		}

		$enabled = 0; // Default as disabled.

		// Associated product is not installed.
		if (!isset($products[$class->product]))
		{
			$enabled = 3;
		}
		else
		{
			// Associated product is installed, and enabled.
			if ($products[$class->product] == 1)
			{
				$enabled = 3;
			}
		}

		if ($enabled AND $class->AutoInstall == 2)
		{
			// Autoinstall = 2 denotes that we are automatically dependant on the associated product.
			$class->ProductDependancy = empty($class->ProductDependancy) ? $class->product : $class->ProductDependancy . ',' . $class->product;
		}

		// Check any product dependancies
		if ($enabled > 0
			AND !empty($class->ProductDependancy)
			AND $list = explode(',', $class->ProductDependancy)
		)
		{
			foreach ($list as $dependancy)
			{
				$dependancy = trim($dependancy);
				$enabled = (isset($products[$dependancy]) AND $products[$dependancy]) ? $enabled : 1;
			}
		}

		// Check any class dependancies
		if ($enabled > 1
			AND !empty($class->ClassDependancy)
			AND $list = explode(',', $class->ClassDependancy)
		)
		{
			foreach ($list as $dependancy)
			{
				$dependancy = trim($dependancy);
				$enabled = class_exists($dependancy) ? $enabled : 2;
			}
		}

		$state[$class->extensionClass] = $enabled;

		return $enabled;
	}

	/**
	 * Check if product is installed and install if option is set.
	 */
	private static function autoInstall($product, $class, $xmlDir = '', $products)
	{
		if ($class->AutoInstall AND !isset($products[$product]))
		{
			vB_Library_Functions::installProduct($product, $xmlDir);
		}
	}

	/**
	 * load the actual extension for a package / $controller.
	 */
	private static function loadExtension($packagesDir, $package, $controller, $options)
	{
		$xmlDir = $packagesDir . DIRECTORY_SEPARATOR . $package . DIRECTORY_SEPARATOR . 'xml' ;
		$apiDir = $packagesDir . DIRECTORY_SEPARATOR . $package . DIRECTORY_SEPARATOR . 'api' ;

		if (!is_dir($apiDir))
		{
			return;
		}

		$file = $apiDir . DIRECTORY_SEPARATOR . str_replace('_', DIRECTORY_SEPARATOR, strtolower($controller)) . '.php';

		if (file_exists($file))
		{
			$products = vB::getDatastore()->getValue('products');

			$eClass = self::getExtensionClass($controller, $package);

			if (!class_exists($eClass))
			{
				throw new Exception(sprintf("Cannot find class %s", htmlspecialchars($eClass)));
			}

			if (!is_subclass_of($eClass, 'vB_Api_Extensions'))
			{
				// VBV-18185 Allow custom APIs to share name with existing APIs
				return;
				//throw new Exception(sprintf('Class %s is not a subclass of vB_Api_Extensions', htmlspecialchars($eClass)));
			}

			$class = new $eClass($controller);
			$enabled = self::isEnabled($class, $products);
			$compatible = self::isCompatible($class, $package, $options);

			if ($enabled AND $compatible)
			{
				if ($enabled == 3)
				{
					self::$extensions[$controller][] = $class;
				}

				// Only Dependancy failed, we still need to autoinstall
				self::autoInstall($package, $class, $xmlDir, $products);
			}

			unset($class);
		}
	}

	/**
	 * Loads extensions for a given controller
	 * @param string $controller
	 */
	private static function loadExtensions($controller)
	{
		$options = vB::getDatastore()->getValue('options');

		if (!$options['enablehooks'] OR defined('DISABLE_HOOKS'))
		{
			return false;
		}

		$packagesDir = DIR . DIRECTORY_SEPARATOR . 'packages';

		if (!isset(self::$checked[$controller]))
		{
			if (!self::$foldersLoaded)
			{
				self::$foldersLoaded = true;
				self::$folders = vB_Library::instance('product')->getPackages($packagesDir);
			}

			if (self::$folders)
			{
				foreach (self::$folders AS $package)
				{
					try
					{
						self::loadExtension($packagesDir, $package, $controller, $options);
					}
					/* Mark any broken class as checked,
					otherwise a bad fatal error can kill the site.
					Trigger a PHP error so something gets logged. */
					catch (error $e)
					{
						/* Not sure an error could occur
						on load, but let's catch it anyway */
						self::$checked[$controller] = true;
						trigger_error("Extension Class Load Error: {$package}_{$controller}", E_USER_ERROR);
					}
					catch (exception $e)
					{
						self::$checked[$controller] = true;
						trigger_error("Broken Extension Class: {$package}_{$controller}", E_USER_ERROR);
					}
				}

				if (isset(self::$extensions[$controller]))
				{
					uasort(self::$extensions[$controller], array('self', 'arraySort'));
				}
			}

			self::$checked[$controller] = true;
		}
	}

	/**
	 * Loads an array of all extensions
	 */
	public static function loadAllExtensions()
	{
		$options = vB::getDatastore()->getValue('options');
		$products = vB::getDatastore()->getValue('products');
		$packagesDir = DIR . DIRECTORY_SEPARATOR . 'packages';

		$folders = vB_Library::instance('product')->getPackages($packagesDir);

		$list = array();

		if ($folders)
		{
			foreach ($folders AS $package)
			{
				$apiDir = $packagesDir . DIRECTORY_SEPARATOR . $package . DIRECTORY_SEPARATOR . 'api' ;
				$res = self::loadExtensionList($apiDir, $package, $options, $products);
				$list = array_merge($list, $res);
			}
		}

		return $list;
	}

	/**
	 * gets the class data for a given extension file.
	 */
	private static function loadExtensionListFile($eDir, $file, $package, $options, $products, $prefix)
	{
		$check = $eDir . DIRECTORY_SEPARATOR . $file;

		if (is_dir($check))
		{
			return array('status' => 'folder', 'folderid' => $check);
		}
		else
		{
			// remove .php and check extension
			// Note original code assumes that there is only one
			// period in the file name.  Should be a reasonable assumption but
			// not guarenteed.  Not trying to account for that because if somebody
			// is doing that it will break there code over a trivial issue.
			// However using standard file part functions will have slightly
			// different behavior.
			$parts = explode('.', $file);

			if(strcasecmp($parts[count($parts)-1], 'php'))
			{
				return array('status' => 'skip');
			}

			$controller = $prefix . $parts[0];

			$eClass = self::getExtensionClass($controller, $package);
			if (!class_exists($eClass))
			{
				return array('status' => 'failed');
			}

			//write now the Extensions and New API classes are mixed up
			//Api classes shouldn't be listed as failed.
			if (!is_subclass_of($eClass, 'vB_Api_Extensions'))
			{
				if (is_subclass_of($eClass, 'vB_Api'))
				{
					return array('status' => 'skip');
				}
				else
				{
					return array('status' => 'failed');
				}
			}

			$class = new $eClass($controller);
			$hasproduct = (isset($products[$class->product]));
			$compatible = self::isCompatible($class, $package, $options);
			$dependancy = self::isEnabled($class, $products);
			$enabled = ($dependancy == 3);

			$extension = array(
				'class' => $class->extensionClass,
				'product' => $class->product,
				'version' => $class->version,
				'developer' => $class->developer,
				'title' => $class->title,
				'minver' => $class->minver,
				'maxver' => $class->maxver,
				'order' => $class->extensionOrder,
				'infourl' => $class->infourl,
				'controller' => $class->controller,
				'enabled' => $enabled,
				'compatible' => $compatible,
				'hasproduct' => $hasproduct,
				'package' => $package,
				'dependancy' => $dependancy,
			);
		}

		return array('status' => 'file', 'extension' => $extension);
	}

	/**
	 * gets the list of api classes in a given folder.
	 */
	private static function loadExtensionListFolder($eDir, $package, $options, $products, &$folders, $prefix = '')
	{
		if (is_dir($eDir))
		{
			if ($handle = opendir($eDir))
			{
				while (($file = readdir($handle)) !== false)
				{
					if (substr($file,0,1) != '.')
					{
						$result = self::loadExtensionListFile($eDir, $file, $package, $options, $products, $prefix);

						if ($result['status'] == 'file')
						{
							$folders[] = $result['extension'];
						}
						else if ($result['status'] == 'folder')
						{
							// Directory ......
							self::loadExtensionListFolder($result['folderid'], $package, $options, $products, $folders, $prefix . $file . '_');
						}
						else if ($result['status'] == 'failed')
						{
							$folders[]['__failed'][$eDir][] = $file;
						}
						else if ($result['status'] == 'skip')
						{
							continue;
						}
						else
						{
							throw new Exception("Invalid status for $eDir, $file");
						}
					}
				}

				closedir($handle);
			}
			else
			{
				throw new Exception("Could not open $eDir");
			}
		}
	}

	/**
	 * gets the list of api classes in a given package.
	 */
	private static function loadExtensionList($eDir, $package, $options, $products)
	{
		$folders = array();

		self::loadExtensionListFolder($eDir, $package, $options, $products, $folders);

		return $folders;
	}

	/**
	 * extensionOrder
	 * Returns comparison value for array sorter
	 * @param mixed value 1
	 * @param mixed value 2
	 * @return int -1, 0 or 1
	 */
	private static function arraySort($a, $b)
	{
	    return ($a->extensionOrder == $b->extensionOrder ? 0 : ($a->extensionOrder > $b->extensionOrder ? 1 : -1));
	}

	/**
	 * Returns all the extensions for a controller.
	 * @param string $controller
	 * @return array The extensions.
	 */
	public static function getExtensions($controller, $options = array())
	{
		if (!$options)
		{
			$options = vB::getDatastore()->getValue('options');
		}

		self::loadExtensions($controller, $options);
		if (isset(self::$extensions[$controller]) AND !empty(self::$extensions[$controller]))
		{
			return self::$extensions[$controller];
		}
		else
		{
			return false;
		}
	}

	// ************************
	// ** NON-STATIC METHODS **
	// ************************

	protected function __construct($controller)
	{
		$this->controller = $controller;
		$this->extensionClass = get_class($this);
	}

	protected function getExtensionOrder()
	{
		// Extensions with no order should be set high (so run last)
		return isset($this->extensionOrder) ? $this->extensionOrder : 9999 ;
	}

	/**
	 * @see vB_Api::callNamed
	 * @param mixed $current
	 * @param string $method -- the name of the method to call
	 * @param array $args -- The list of args to call.  This is a name => value map that will
	 *   be matched up to the names of the API method.  Order is not important.  The names are
	 *   case sensitive.
	 * @return mixed
	 */
	public function callNamed()
	{
		// since the parent method has different arguments,
		// we need to do this to avoid strict standards notice
		list($current, $method, $args) = func_get_args();

		if (!is_callable(array($this, $method)))
		{
			/* if the method does not exist then dont check anything,
			 just return the current value. */
			return $current;
		}

		// Check if the result varname is present
		$foundResultVarName = false;
		$reflection = new ReflectionMethod($this, $method);
		foreach($reflection->getParameters() as $param)
		{
			if($param->getName() == $this->resultVarName)
			{
				$foundResultVarName = true;
				break;
			}
		}
		if (!$foundResultVarName)
		{
			// The method is not using the result varname, so it's better to ignore it and return previous result
			// todo: log this error somewhere?
			return $current;
		}

		$args[$this->resultVarName] = $current;
		return parent::callNamed($method, $args);
	}


	// ************************************************
	// ** HELPER METHODS - Mostly useful for testing **
	// ************************************************

	/**
	 * clears the loaded folders & extensions.
	 */
	public static function resetExtensions()
	{
		self::clearFolders();
		self::clearExtensions();
	}

	/**
	 * Returns all the currently loaded extension.
	 */
	public static function getExtensionList()
	{
		return self::$extensions;
	}

	/**
	 * clears the loaded extensions.
	 */
	private static function clearExtensions()
	{
		self::$checked = array();
		self::$extensions = array();
	}

	/**
	 * clears the loaded folders.
	 */
	private static function clearFolders()
	{
		self::$folders = array();
		self::$foldersLoaded = false;
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
