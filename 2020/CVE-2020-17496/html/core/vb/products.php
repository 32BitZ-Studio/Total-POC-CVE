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
 * @package vBulletin
 */


/**
 * Class to handle product access and autoinstall
 *
 * @package vBulletin
 */
class vB_Products
{
	use vB_Trait_NoSerialize;

	private $options;
	private $products = array();
	private $packages = array();
	private $productObjects = array();
	private $packagesDir = "";

	// List of product IDs that will be installed by default (and kept updated at each upgrade)
	// via vB_Upgrade_final::step_13(). Kept here as a constant instead of hard-coded in
	// the upgrade step to make maintenance (unit tests etc) easier.
	// Array class constants possible as of PHP 5.6+
	const DEFAULT_VBULLETIN_PRODUCTS = array(
		'nativo',
		'viglink',
		'twitterlogin',
		'googlelogin',
		'vbfilescan',
	);

	/**
	 *	Construct the products object.
	 *
	 *	@param array products -- array of the form productname => isenabled for all installed products.
	 *		this would generally be taken from the
	 *	@param string packagesDir
	 */
	public function __construct($products, $packagesDir, $autoinstall)
	{
		$this->products = $products;
		$this->packages = $this->getPackagesInternal($packagesDir);
		$this->options = vB::getDatastore()->getValue('options');
		$this->packagesDir = $packagesDir;

		if ($autoinstall)
		{
			$this->autoinstall($this->packages, $products, $packagesDir);
		}

		foreach($this->products AS $name => $enabled)
		{
			//the vbulletin product isn't really a normal product/package
			//and will never have an object associated with it.
			if ($name == 'vbulletin')
			{
				continue;
			}

			if($enabled)
			{
				$class = $name . '_Product';

				if (class_exists($class))
				{
					$object = new $class;
					if ($this->isCompatible($object))
					{
						$this->productObjects[$name] = $object;
					}
 				}
			}
		}
	}

	/**
	 * Check if the product is compatible with the current vB version.
	 */
	private function isCompatible($object)
	{
		// Set some variables for below.
		$currentVersion = $this->options['templateversion'];

		// No vb minimum, use default.
		if (empty($object->vbMinVersion))
		{
			$minOk = true;
			$object->vbMinVersion = '';
		}
		else
		{
			$minOk = vB_Library_Functions::isNewerVersion($currentVersion, $object->vbMinVersion, true);
		}

		// No vb maximum, use default.
		if (empty($object->vbMaxVersion))
		{
			$maxOk = true;
			$object->vbMaxVersion = '';
		}
		else
		{
			$maxOk = vB_Library_Functions::isNewerVersion($object->vbMaxVersion, $currentVersion, true);
		}

		return ($minOk AND $maxOk);
	}

	private function autoinstall($packages, $products, $packagesDir)
	{
		//the product name *must* the same name as the package name for
		//any autoinstalled product otherwise unpleasant things happen
		foreach($packages AS $package)
		{
			if (!isset($products[$package]))
			{
				$xmlDir = "$packagesDir/$package/xml";
				$class = $package . '_Product';

				if (class_exists($class) AND property_exists($class, 'AutoInstall') AND $class::$AutoInstall)
				{
					$info = vB_Library_Functions::installProduct($package, $xmlDir);
					if ($info !== false)
					{
						$this->products[$package] = $info['active'];
					}
				}
			}
		}
	}

	/**
	 *	Compile a list of all of the hook classes from all of the active
	 *	products.
	 */
	public function getHookClasses()
	{
		$hookClasses = array();
		foreach($this->productObjects AS $name => $object)
		{
			if (isset($object->hookClasses) AND is_array($object->hookClasses))
			{
				foreach($object->hookClasses AS $hookClass)
				{
					$hookClasses[] = $hookClass;
				}
			}
		}
		return $hookClasses;
	}


	public function getApiClassesByProduct()
	{
		$list = array();

		foreach ($this->packages AS $package)
		{
			$apiDir = $this->packagesDir . DIRECTORY_SEPARATOR . $package . DIRECTORY_SEPARATOR . 'api' ;
			$res = $this->loadClassList($apiDir, $package);

			if($res)
			{
				$list[$package] = $res;
			}
		}

		return $list;
	}

	/**
	 * gets the list of api classes in a given package.
	 */
	private function loadClassList($eDir, $package)
	{
		$results = array();
		$this->loadExtensionListFolder($eDir, $package, $results);
		return $results;
	}


	/**
	 * gets the list of api classes in a given folder.
	 */
	private function loadExtensionListFolder($eDir, $package, &$results, $prefix = '')
	{
		if (is_dir($eDir))
		{
			foreach(new DirectoryIterator($eDir) AS $file)
			{
				if (!$file->isDot())
				{
					if ($file->isDir())
					{
						self::loadExtensionListFolder(
							$file->getPathname(),
							$package,
							$results,
							$prefix . $file->getBasename() . '_'
						);
					}

					//ignore files that don't have the php extension
					else if (strcasecmp($file->getExtension(), 'php') === 0)
					{
						//the directory iterator items inexplicably don't have a way to get the filename
						//with the extension stripped.  The getBasename allows stripping a suffix, but its
						//is specific and case sensitive.
						$controller = $package . ':'. $prefix . ucfirst(pathinfo($file->getFilename(), PATHINFO_FILENAME));
						$class = vB_Api::getApiClassName($controller);

						/* Class_exists check needs to disable calling autoload,
						otherwise unwanted fatal (cannot redeclare) errors can happen */

						//for the moment we handle Extensions seperately and they are also subclasses of
						//vB_Api.  So we waht to exclude them here.  Eventually we probably ought to
						//consolidate the reporting.
						$isApiClass = ($class
							AND class_exists($class, false)
							AND is_subclass_of($class, 'vB_Api')
							AND !is_subclass_of($class, 'vB_Api_Extensions')
						);

						if ($isApiClass)
						{
							$results[] = array('classname' => $class);
						}
					}
				}
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
	 *	Get the list of installed products.
	 *
	 *	This should be the same as the 'products' value in the datastore and the
	 *	function mostly exists so that the unit tests can verify that.
	 */
	public function getProducts()
	{
		return $this->products;
	}

	public function getPackages()
	{
		return $this->packages;
	}

	public function getProductObjects()
	{
		return $this->productObjects;
	}

	public function getDisabledProductObjects()
	{
		$disabled = array();
		foreach($this->products AS $name => $enabled)
		{
			//the vbulletin product isn't really a normal product/package
			//and will never have an object associated with it.
			if ($name == 'vbulletin')
			{
				continue;
			}

			$class = $name . '_Product';

			if (class_exists($class))
			{
				$object = new $class;
				if (!$this->isCompatible($object) OR !$enabled)
				{
					$disabled[$name] = $object;
				}
			}
		}

		return $disabled;
	}

	/**
	 * gets the list of packages (folder names).
	 */
	private function getPackagesInternal($packagesDir)
	{
		$folders = array();
		if (is_dir($packagesDir))
		{
			foreach(new DirectoryIterator($packagesDir) AS $file)
			{
				if (!$file->isDot() AND $file->isDir())
				{
					$folders[] = $file->getFilename();
				}
			}
		}
		return $folders;
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 102726 $
|| #######################################################################
\*=========================================================================*/
