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
 * vB_Library_External
 *
 */

class vB_Library_External extends vB_Library
{
	// external URL path
	const ROUTE_PATH = '/external';

	/**
	 * Check if the external data provider type is available and it actually produces a valid output for given channels.
	 *
	 * @param 	Array 	List of channel ids to check external status from.
	 * @param 	String 	External type.
	 *					Supported: vB_Api_External::TYPE_JS, vB_Api_External::TYPE_XML, 
	 *					vB_Api_External::TYPE_RSS, vB_Api_External::TYPE_RSS1, vB_Api_External::TYPE_RSS2
	 * 
	 * @return 	Array 	Associative array with external status information for each given channel.
	 *					Status will be added to each array element as '$type_enabled' key.
	 */
	public function checkExternalForChannels($channelids, $type)
	{
		$check = $this->validateExternalType($type);
		$enabled = true;
		if ($check['valid'] === false)
		{
			$enabled = false;
		}

		$result = array();
		$gcontext = vB::getUserContext(0);
		foreach ($channelids AS $channel)
		{
			$result[$channel][$type . '_enabled'] = ($enabled AND 
				$gcontext->getChannelPermission('forumpermissions', 'canview', $channel)) ? 1 : 0;
		}

		return $result;
	}

	/**
	 * Build external type route for each individual channel specified.
	 *
	 * @param 	Array 	Channels to get route for.
	 * @param 	String 	External type.
	 *					Supported: vB_Api_External::TYPE_JS, vB_Api_External::TYPE_XML, 
	 *					vB_Api_External::TYPE_RSS, vB_Api_External::TYPE_RSS1, vB_Api_External::TYPE_RSS2
	 * 
	 * @return 	Array 	Associative array with external route for each given channel.
	 *					Status will be added to each array element as '$type_route' key.
	 */
	public function getExternalRouteForChannels($channelids, $type)
	{
		$check = $this->validateExternalType($type);
		$enabled = true;
		if ($check['valid'] === false)
		{
			$enabled = false;
		}

		$result = array();
		foreach ($channelids AS $channel)
		{
			$result[$channel][$type . '_route'] = $this->getExternalRoute(array('nodeid' => $channel, 'type' => $type),
				array('nodeid' => '', 'type' => ''));
		}

		return $result;
	}

	/**
	 * Get external data information for each channel specified such as 
	 * external type is actually available, produces a valid output for channel and external route.
	 *
	 * @param 	Array 	Channels to get data for.
	 * @param 	String 	External type.
	 *					Supported: vB_Api_External::TYPE_JS, vB_Api_External::TYPE_XML, 
	 *					vB_Api_External::TYPE_RSS, vB_Api_External::TYPE_RSS1, vB_Api_External::TYPE_RSS2
	 * 
	 * @return 	Array 	Associative array with external data for each given channel.
	 *					Status will be added to each array element as '$type_enabled' key.
	 *					Status will be added to each array element as '$type_route' key.
	 */
	public function getExternalDataForChannels($channelids, $type)
	{
		$result = array();
		$routes = $this->getExternalRouteForChannels($channelids, $type);
		$status = $this->checkExternalForChannels($channelids, $type);
		foreach ($channelids AS $channel)
		{
			$result[$channel][$type . '_enabled'] = $status[$channel][$type . '_enabled'];
			$result[$channel][$type . '_route'] = ($status[$channel][$type . '_enabled'] ? $routes[$channel][$type . '_route'] : '');
		}

		return $result;
	}

	/**
	 * Perform checks on the given external type.
	 *
	 * @param 	string 	External type.
	 *
	 * @return 	Array 	'valid' defines whether external type is valid or not.
	 *					'phraseid' used in case of not valid type.
	 *
	 */
	public function validateExternalType($type)
	{
		$type = trim(strtolower($type));
		switch ($type)
		{
			case vB_Api_External::TYPE_JS:
				if (!vB::getDatastore()->getOption('externaljs'))
				{
					return array('valid' => false, 'phraseid' => 'external_js_disabled');
				}
				break;
			case vB_Api_External::TYPE_XML:
				if (!vB::getDatastore()->getOption('externalxml'))
				{
					return array('valid' => false, 'phraseid' => 'external_xml_disabled');
				}
				break;
			case vB_Api_External::TYPE_RSS:
			case vB_Api_External::TYPE_RSS1:
			case vB_Api_External::TYPE_RSS2:
				if (!vB::getDatastore()->getOption('externalrss'))
				{
					return array('valid' => false, 'phraseid' => 'external_rss_disabled');
				}
				break;
			default:
				return array('valid' => false, 'phraseid' => 'invalid_external_type');
				break;
		}

		return array('valid' => true, 'phraseid' => '');
	}

	/**
	 * Builds an external data provider route depending on the data specified and options to consider.
	 *
	 * @param 	array 	Data to build route querystring from. 
	 *					If specified, 'type' is the one and only exception on $options check since it always
	 *					gets added first.
	 * @param 	array 	Options to consider for querystring while building route.
	 *
	 * @return 	String 	External route.
	 *
	 */
	public function getExternalRoute($data = array(), $options = array())
	{
		$params = array();

		// always make sure type is the first in querystring.
		if (!empty($data['type']))
		{
			$params['type'] = 'type=' . $data['type'];
			unset($data['type']);
		}

		foreach ($data AS $name => $val)
		{
			if (isset($options[$name]))
			{
				$params[$name] = ($name . '=' . (is_array($val) ? implode(',', $val) : $val));
			}
		}

		return (
			!empty($params) ? (self::ROUTE_PATH . '?' . (implode('&', $params))) : self::ROUTE_PATH 
		);
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
