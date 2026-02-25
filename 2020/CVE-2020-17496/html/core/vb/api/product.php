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

/*

########## Work in Progress ##########

The idea is to move everything product related from adminfunctions,
and adminfunctions_product into here, so the legacy functions can be deleted.
 */

/**
 * vB_Api_Product
 *
 * @package vBApi
 * @access public
 */
class vB_Api_Product extends vB_Api
{
	private $assertor;

	protected $disableWhiteList = array('loadProductJsRollups', 'loadProductCssRollups');

	protected function __construct()
	{
		parent::__construct();

		$this->assertor = vB::getDbAssertor();
	}

	/**
	 * Disables or deletes a set of products (does not run any uninstall code.
	 */
	public function removeProducts($products, $versions = array(), $echo = false, $disable_only = false, $reason = '')
	{
		if (!$products OR !$this->hasPermission())
		{
			return false;
		}

		if (!$versions)
		{
			$versions = array();
		}

		if ($disable_only)
		{
			$this->assertor->assertQuery(
				'disableProducts',
				array(
					'reason' => $reason,
					'products' => $products,
					vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_METHOD,
				)
			);
		}
		else
		{
			$first = true;

			foreach ($products as $pid)
			{
				$result = delete_product($pid);

				if ($result AND $echo)
				{
					if ($first)
					{
						$first = false;
						$msg = new vB_Phrase('hooks', 'products_removed');
						$this->message($msg, 1);
					}

					if ($versions[$pid])
					{
						$this->message($versions[$pid]['title'].' - '.$versions[$pid]['version'], 1);
					}
					else
					{
						$this->message($versions[$pid]['title'], 1);
					}
				}
			}
		}
	}


	/**
	 *	Parsed list of js rollup files
	 *
	 *	Looks for files prefixed with "jsrollup_" per vB_Library_Product::loadProductXmlListParsed
	 *
	 *	@return array of the form
	 *		'subtype' => content array
	 *
	 *	@see vB_Library_Product::loadProductXmlListParsed
	 */
	public function loadProductJsRollups()
	{
		$library = vB_Library::instance('product');
		return $library->loadProductXmlListParsed('jsrollup', true);
	}

	/**
	 *	Parsed list of css rollup files
	 *
	 *	Looks for files prefixed with "cssrollup_" per vB_Library_Product::loadProductXmlListParsed
	 *
	 *	@return array of the form
	 *		'subtype' => content array
	 *
	 *	@see vB_Library_Product::loadProductXmlListParsed
	 */
	public function loadProductCssRollups()
	{
		$library = vB_Library::instance('product');
		$rollups = $library->loadProductXmlListParsed('cssrollup', true);

		// ensure that if a CSS rollup only has one template, it will still be an array
		foreach ($rollups AS $k => $productInfo)
		{
			foreach ($productInfo['rollup'] AS $k2 => $productRollup)
			{
				if (is_string($productRollup['template']))
				{
					$rollups[$k]['rollup'][$k2]['template'] = array($rollups[$k]['rollup'][$k2]['template']);
				}
			}
		}

		return $rollups;
	}

	/**
	 *	Get list of cpnav files
	 *
	 *	Looks for files prefixed with "cpnav_" per vB_Library_Product::loadProductXmlList
	 *
	 *	@return array of the form
	 *		'subtype' => file array
	 *
	 *	@see vB_Library_Product::loadProductXmlList
	 */
	public function loadProductCpnavFiles()
	{
		$userContext = vB::getUserContext();
		if (!$userContext->hasAdminPermission('cancontrolpanel'))
		{
			throw new vB_Exception_Api('no_permission');
		}

		$library = vB_Library::instance('product');
		return $library->loadProductXmlList('cpnav', true);
	}

	/**
	 * Checks the user is an admin with product/plugin permission.
	 */
	private function hasPermission()
	{
		$userContext = vB::getUserContext();
		$allowed = $userContext->hasAdminPermission('canadminproducts');
		return (bool) $allowed;
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 100396 $
|| #######################################################################
\*=========================================================================*/
