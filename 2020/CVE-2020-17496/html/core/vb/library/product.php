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
 * vB_Library_Product
 *
 * @package vBLibrary
 * @access public
 */
class vB_Library_Product extends vB_Library
{
	private $fullProductList = false;

	/**
	 * Returns parsed xml for package xml files
	 *
	 * Returns the file list from loadProductXmlList but includes the
	 * parsed array from the xml contents instead of the filenames
	 *
	 * @param string $type
	 * @param boolean $typekey
	 * @return array
	 *
	 * @see vB_Library_Product::loadProductXmlList()
	 */
	public function loadProductXmlListParsed($type = '', $typekey = false)
	{
		$list = $this->loadProductXmlList($type, $typekey);
		foreach ($list AS $product => $file)
		{
			$xmlobj = new vB_XML_Parser(false, $file, false, false);
			$data = $xmlobj->parse();
			$list[$product] = $data;
		}

		return $list;
	}

	/**
	 * Loads an array of all package xml files (optionally of one type).
	 *
	 * Load from core\packages\packagename\xml as well as	core\includes\xml\ (for the vbulletin package)
	 * Files will be interpreted as:
	 * 	{type}_{subtype}.xml (or {type}_{subtype}_someotherstring.xml
	 *
	 * @param string $type -- the file prefix for the xml file to load. If the type of the file
	 * 	does not match the passed type it will be ignored.
	 * @param boolean $typekey -- whether to return the values by subtype.  If false then a single
	 * 	array of all files will be returned.  Otherwise the return will be an array of arrays
	 * 	by subtype.  If there is no subtype (for example sometype.xml) then "none" will be used.
	 *
	 * @return array either an array of file names or an array of the form $subtype => array(files)
	 *
	 */
	public function loadProductXmlList($type = '', $typekey = false)
	{
		$rootDir = DIR . DIRECTORY_SEPARATOR . 'includes';
		$packagesDir = DIR . DIRECTORY_SEPARATOR . 'packages';

		$folders = $this->getPackages($packagesDir, $rootDir);

		$list = array();

		if ($folders)
		{
			foreach ($folders AS $package)
			{
				if (strrpos($package, DIRECTORY_SEPARATOR))
				{
					$xmlDir = $package . DIRECTORY_SEPARATOR . 'xml' ;
				}
				else
				{
					$xmlDir = $packagesDir . DIRECTORY_SEPARATOR . $package . DIRECTORY_SEPARATOR . 'xml' ;
				}

				$res = $this->loadProductXml($xmlDir, $package, $type, $typekey);
				$list = array_merge($list, $res);
			}
		}

		return $list;
	}

	/**
	 * gets the list of xml files in a given folder (and of optional type).
	 */
	private function loadProductXml($eDir, $package, $xml = '', $typekey = true)
	{
		$folders = array();
		if (is_dir($eDir))
		{
			if (!($handle = opendir($eDir)))
			{
				throw new Exception("Could not open $eDir");
			}

			while (($file = readdir($handle)) !== false)
			{
				if (is_dir($eDir . DIRECTORY_SEPARATOR . $file))
				{
					continue;
				}

				if (substr($file,0,1) == '.')
				{
					continue;
				}
				list($name, $ext) = explode('.', $file);


				// reset variables that may or may not be set each iteration
				$types = array();
				$type = '';
				$subtype = 'none';

				// try to fetch the type & subtype.
				if ($xml)
				{
					// No trim() here. Let's not second guess the caller too much. They can specify $xml = 'abcdef_', but then the filename had better be something like 'abcdef__subtype.xml'.
					$prefix = $xml . "_";
					if ($name === $xml)
					{
						$type = $xml;
						$subtype = 'none';
					}
					elseif (strpos($name, $prefix) === 0)
					{
						$type = $xml;
						$subtype = substr($name, strlen($prefix));
						$subtype = preg_replace('#[^a-z0-9]#i', '', $subtype); // todo: is this necessary?
						if (empty($subtype))
						{
							// Filename was "$xml_.xml" | "$xml_[^a-z0-9]+.xml". Treat it as an "exact match" above
							$subtype = 'none';
						}
					}
					else
					{
						// This is not the desired $xml type, skip it.
						// This also includes "partial match" cases like $xml = 'foo' and $name = 'foobar_package1'
						continue;
					}
				}
				else
				{
					$types = explode('_', $name);
					if (count($types) > 1)
					{
						// e.g. If $name = 'abc_def_xyz', 'abc_def' should be the $type & 'xyz' should be the $subtype.
						// TODO: shouldn't subtype be empty or match $package?
						$subtype = array_pop($types);
						$subtype = preg_replace('#[^a-z0-9]#i', '', $subtype); // todo: is this necessary?
						if (empty($subtype))
						{
							// Filename was "$type_.xml" | "$type_[^a-z0-9]+.xml". Default '' to 'none'.
							$subtype = 'none';
						}
						$type = implode('_', $types);
					}
					else
					{
						$subtype = 'none';
						$type = $types[0];
					}
				}


				if ($ext != 'xml' OR ($xml AND $type != $xml))
				{
					continue;
				}

				//I suspect that $type must always be a true value given above.  In any
				//event the logic here doesn't make sense (we only access $type if its false)
				if ($type)
				{
					if (!$typekey)
					{
						$folders[] = $eDir . DIRECTORY_SEPARATOR . $file;
					}
					else
					{
						$folders[$subtype] = $eDir . DIRECTORY_SEPARATOR . $file;
					}
				}
				else
				{
					if (!$typekey)
					{
						$folders[$type][] = $eDir . DIRECTORY_SEPARATOR . $file;
					}
					else
					{
						$folders[$type][$subtype] = $eDir . DIRECTORY_SEPARATOR . $file;
					}
				}
			}

			closedir($handle);
		}
		return $folders;
	}

	/**
	 * gets the list of packages (folder names).
	 */
	public function getPackages($packagesDir, $folders = array())
	{
		if (!is_array($folders))
		{
			$folders = array($folders);
		}

		if (is_dir($packagesDir))
		{
			if ($handle = opendir($packagesDir))
			{
				$prefix = $packagesDir . DIRECTORY_SEPARATOR;

				while (($file = readdir($handle)) !== false)
				{
					if (substr($file,0,1) != '.' and filetype($prefix . $file) == 'dir')
					{
						$folders[] = $file;
					}
				}

				closedir($handle);
			}
			else
			{
				throw new Exception("Could not open $packagesDir");
			}
		}

		return $folders;
	}


	public function getFullProducts()
	{
		if ($this->fullProductList === false)
		{
			$productlist = array(
				'vbulletin' => array(
					'productid' => 'vbulletin',
					'title' => 'vBulletin',
					'description' => '',
					'version' => vB::getDatastore()->getOption('templateversion'),
					'active' => 1
				)
			);

			$products = vB::getDbAssertor()->assertQuery('product', array(), 'title');
			foreach ($products as $product)
			{
				$productlist["$product[productid]"] = $product;
			}

			$this->fullProductList = $productlist;
		}

		return $this->fullProductList;
	}

	public function getProducts()
	{
		$productstore = vB::getDatastore()->getValue('products');
		if (!is_array($productstore))
		{
			$this->buildProductDatastore();
			$productstore = $datastore->getValue('products');
		}
		return $productstore;
	}

	/**
	 * Saves the list of currently installed products into the datastore.
	 */
	public function buildProductDatastore()
	{
		$products = array('vbulletin' => 1);

		$productList = vB::getDbAssertor()->getRows(
			'product',
			array(
				vB_dB_Query::COLUMNS_KEY => array('productid', 'active')
			)
		);

		foreach ($productList AS $product)
		{
			$products[$product['productid']] = $product['active'];
		}

		vB::getDatastore()->build('products', serialize($products), 1);
		vB_Api_Wol::buildSpiderList();
		vB_Api::instanceInternal("Hook")->buildHookDatastore();
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 102970 $
|| #######################################################################
\*=========================================================================*/
