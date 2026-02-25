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

abstract class vB_Xml_Export
{
	use vB_Trait_NoSerialize;

	/**
	 *
	 * @var vB_dB_Assertor
	 */
	protected $db;

	protected $productid;

	public function __construct($product = 'vbulletin')
	{
		$this->db = vB::getDbAssertor();
		$this->productid = $product;
	}

	public static function createGUID($record, $source = 'vbulletin')
	{
		return vB_GUID::get("$source-");
	}

	/**
	 * Export objects to the specified filepath
	 */
	public function export($filepath, $overwrite = TRUE)
	{
		if (!$overwrite AND file_exists($filepath))
		{
			throw new Exception('Target file already exists');
		}

		file_put_contents($filepath, $this->getXml());
	}

	/**
	 * If an xml builder is passed it appends the objects. Otherwise, an XML string is returned.
	 */
	public abstract function getXml(vB_XML_Builder &$xml = NULL);
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
