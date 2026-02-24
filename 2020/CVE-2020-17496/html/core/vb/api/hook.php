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
 * vB_Api_Hook
 *
 * @package vBApi
 * @access public
 */
class vB_Api_Hook extends vB_Api
{
	private $assertor;

	protected function __construct()
	{
		parent::__construct();

		$this->assertor = vB::getDbAssertor();
	}

	public function getHookList($order = array(), $product = false)
	{
		$this->checkHookPermission();

		$conditions = array();
		if($product)
		{
			$conditions['product'] = $product;
		}

		$rows = $this->assertor->getRows('hook', $conditions, $order);

		if(!$this->hasAdminPermission('canadminproducts'))
		{
			$this->stripProductHooks($rows);
		}

		return $rows;
	}

	public function getHookProductList()
	{
		$this->checkHookPermission();
		$rows = $this->assertor->getRows('getHookProductInfo');

		if(!$this->hasAdminPermission('canadminproducts'))
		{
			$this->stripProductHooks($rows);
		}
		return $rows;
	}


	/**
	 *	Remove everything but the hooks associated with the default
	 *	vBulletin psudeo product.
	 */
	private function stripProductHooks(&$rows)
	{
		//it's probably mildly more efficient to try to strip these in the DB queries
		//but it's a bit more complicated -- especially because of the potential for
		//old blank values in the product (meaning its a vbulletin)

		foreach($rows AS $key => $row)
		{
			if(!($row['product'] == 'vbulletin' OR $row['product'] == ''))
			{
				unset($rows[$key]);
			}
		}
	}

	public function getXmlHooks()
	{
		$this->checkHookPermission();

		$typelist = array();
		$hooklocations = array();

		$types = $this->assertor->getRows('getHooktypePhrases');
		$hookfiles = vB_Library::instance('product')->loadProductXmlList('hooks');
		foreach ($types AS $type)
		{
			$typelist[] = $type['varname'];
		}

		$vbphrase = vB_Api::instanceInternal('phrase')->fetch($typelist);

		foreach ($hookfiles AS $file)
		{
			if (!preg_match('#hooks_(.*).xml$#i', $file, $matches))
			{
				continue;
			}

			$product = $matches[1];
			$phrased_product = $products[($product ? $product : 'vbulletin')];

			if (!$phrased_product)
			{
				$phrased_product = $product;
			}

			$xmlobj = new vB_XML_Parser(false, $location . $file);
			$xml = $xmlobj->parse();

			if (!is_array($xml['hooktype'][0]))
			{
				$xml['hooktype'] = array($xml['hooktype']);
			}

			foreach ($xml['hooktype'] AS $key => $hooks)
			{
				if (!is_numeric($key))
				{
					continue;
				}

				$phrased_type = isset($vbphrase["hooktype_$hooks[type]"]) ? $vbphrase["hooktype_$hooks[type]"] : $hooks['type'];

				$hooktype = /*$phrased_product . ' : ' . */$phrased_type;

				$hooklocations["#$hooktype#"] = $hooktype;

				if (!is_array($hooks['hook']))
				{
					$hooks['hook'] = array($hooks['hook']);
				}

				foreach ($hooks['hook'] AS $hook)
				{
					$hookid = trim(is_string($hook) ? $hook : $hook['value']);
					if ($hookid !== '')
					{
						$hooklocations[$hookid] = '--- ' . $hookid . ($product != 'vbulletin' ? " ($phrased_product)" : '');
					}
				}
			}
		}

		return $hooklocations;
	}

	public function deleteHook($hookid)
	{
		//for the save permission we'll actually require "canadminstyles"
		$this->checkHasAdminPermission('canadminstyles');

		if ($hookid)
		{
			//we could potentially check the permission first and only load the hook if we don't have it
			//not sure which is more efficient
			$hookdata = $this->getHookInfo($hookid);
			//but if we are saving to a product other than "vbulletin" we need to have product permissions too
			if($hookdata['product'] != 'vbulletin' AND $hookdata['product'] != '')
			{
				$this->checkHasAdminPermission('canadminproducts');
			}

			$ret = $this->assertor->delete('hook', array('hookid' => $hookid));
		}
		else
		{
			$ret = false;
		}

		$this->buildHookDatastore();

		return $ret;
	}

	public function encodeArguments($arguments)
	{
		if ($arguments AND $matches = preg_split("#[\n]+#", trim($arguments)))
		{
			$results = array();

			foreach($matches AS $argument)
			{
				list($varname, $key) = explode('=', trim($argument), 2);

				$varname = trim($varname);
				$list = array_reverse(explode('.', trim($key)));

				$result = 1;
				foreach($list AS $subkey)
				{
					$this->encodeLevel($result, $subkey);
				}

				$results[$varname] = $result;
			}

			return $results;
		}

		return array();
	}

	private function encodeLevel(&$array, $key)
	{
		$temp[$key] = $array;
		$array = $temp;
	}

	public function decodeArguments($arguments)
	{
		$result = '';
		foreach ($arguments AS $varname => $value)
		{
			$result .= $varname;

			if(is_array($value))
			{
				$this->decodeLevel($result, $value, '=');
			}

			$result .= "\n";
		}

		return $result;
	}

	private function decodeLevel(&$res, $array, $append = '.')
	{
		foreach ($array AS $varname => $value)
		{
			$res .= $append . $varname;

			if(is_array($value))
			{
				$this->decodeLevel($res, $value);
			}
		}
	}

	public function saveHook($hookid, $hookdata)
	{
		//for the save permission we'll actually require "canadminstyles"
		$this->checkHasAdminPermission('canadminstyles');

		//but if we are saving to a product other than "vbulletin" we need to have product permissions too
		//do *not* accept the old blank product id here.  We don't want to save it that way.
		if($hookdata['product'] != 'vbulletin')
		{
			$this->checkHasAdminPermission('canadminproducts');
		}

		$this->checkHookPermission();

		if(isset($hookdata['arguments']))
		{
			if (!is_array($hookdata['arguments']))
			{
				throw new vB_Exception_Api('invalid_data_w_x_y_z', array($hookdata['arguments'], 'hookdata[\'arguments\']', __CLASS__, __FUNCTION__));
			}

			$hookdata['arguments'] = serialize($hookdata['arguments']);
		}

		if ($hookid)
		{
			unset ($hookdata['hookid']); // Dont alter this
			$this->assertor->update('hook', $hookdata, array('hookid' => $hookid));
		}
		else
		{
			$hookid = $this->assertor->insert('hook', $hookdata);
			if (!empty($hookid['errors']))
			{
				throw new vB_Exception_Api('invalid_data');
			}
		}

		$this->buildHookDatastore();

		return $hookid;
	}

	public function updateHookStatus($hookdata)
	{
		$this->checkHasAdminPermission('canadminstyles');

		if ($hookdata)
		{
			$params = array('hookdata' => $hookdata);
			if(!$this->hasAdminPermission('canadminproducts'))
			{
				$params['productid'] = 'vbulletin';
			}

			$ret = $this->assertor->assertQuery('updateHookStatus', $params);
		}
		else
		{
			$ret = false;
		}

		$this->buildHookDatastore();

		return $ret;
	}

	public function getHookInfo($hookid)
	{
		$this->checkHookPermission();

		if ($hookid)
		{
			$ret = $this->assertor->getRow('getHookInfo', array('hookid' => $hookid));

			//unserialize the arguments array.  If its not an array something went
			//wrong and we'll make it an array.
			$ret['arguments'] = @unserialize($ret['arguments']);
			if (!is_array($ret['arguments']))
			{
				$ret['arguments'] = array();
			}
		}
		else
		{
			$ret = array();
		}

		return $ret;
	}

	/**
	* Saves the currently installed hooks to the datastore.
	*/
	public function buildHookDatastore()
	{
		$hooks = $this->assertor->getRows('getHookProductList');
		vB::getDatastore()->build('hooks', serialize($hooks), 1);
	}

	/**
	* Checks the user is an admin with product/plugin permission.
	*/
	private function checkHookPermission()
	{
		//allow either canadminproducts or canadminstyles.  We're switching primarily
		//to the second for hooks because we want to allow people to use template hooks
		//without necesarily being able to access products.  It's also not very useful
		//to have access to hooks without being able to create templates.  However
		//some of the API functions are used by the product export function and it
		//seems like breaking that because the user doesn't have access to hooks is bad
		//form.  It's not really a security issue to allow admins with canadminproducts
		//to have access to these functions.

		if(!$this->hasAdminPermission('canadminproducts'))
		{
			$this->checkHasAdminPermission('canadminstyles');
		}
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 103066 $
|| #######################################################################
\*=========================================================================*/
