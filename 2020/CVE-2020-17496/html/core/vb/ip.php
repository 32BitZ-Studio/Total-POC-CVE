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

class vB_Ip
{
	use vB_Trait_NoSerialize;

	const IPV4_REGEX = '(\d{1,3})(?:\.(\d{1,3})){3}';

	/**
	 * Validates an IPv4 address
	 * @param string $ipAddress
	 * @return bool
	 */
	public static function isValidIPv4($ipAddress)
	{
		if (!preg_match('#^' . self::IPV4_REGEX . '$#', trim($ipAddress), $matches))
		{
			return false;
		}

		for($i=1; $i<count($matches); $i++)
		{
			if ((!is_numeric($matches[$i])) OR $matches[$i] < 0 OR $matches[$i] > 255)
			{
				return false;
			}
		}

		return true;
	}

	/**
	 * Validates an IPv6 string representation and returns the ip fields for storage. If representation is invalid it returns false.
	 * @param string $ipAddress
	 * @return mixed
	 */
	public static function validateIPv6($ipAddress)
	{
		$ipAddress = strtolower(trim($ipAddress));

		if (!$ipAddress)
		{
			return false;
		}

		if (strpos($ipAddress, '[') === 0)
		{
			if(substr($ipAddress, -1) == ']')
			{
				// remove square brackets
				$ipAddress = substr($ipAddress, 1, -1);
			}
			else
			{
				// unmatched square bracket
				return false;
			}
		}

		if ( substr_count($ipAddress, '::') > 1)
		{
			// only one group of zeroes can be compressed
			return false;
		}

		$fields = array(
			'ip_4' => '0',
			'ip_3' => '0',
			'ip_2' => '0',
			'ip_1' => '0'
		);

		// get part(s) of (compressed?) address
		$parts = explode('::', $ipAddress);

		$group_regex = '#^[a-f0-9]{1,4}$#';
		$canonical = array(0,0,0,0,0,0,0,0);

		// now validate each part, starting with lower order values
		if (isset($parts[1]) AND !empty($parts[1]))
		{
			$groups = explode(':', $parts[1]);
			$num_groups = count($groups);

			// we allow dotted-quad notation (::ffff:192.0.2.128)
			if (empty($parts[0]) AND $num_groups == 2 AND $groups[0] == 'ffff' AND self::isValidIPv4($groups[1]))
			{
				$fiels['ip_4'] = $fiels['ip_3'] = '0';
				$fields['ip_2'] = (string) 0xffff;
				$fields['ip_1'] = sprintf('%u', ip2long($groups[1]));

				return $fields;
			}
			else
			{
				for($i=0; $i<$num_groups; $i++)
				{
					if (preg_match($group_regex, $groups[$i], $matches) AND ($hex = hexdec($groups[$i])) <= 0xffff)
					{
						// add it to the last part of canonical
						$canonical[8 - $num_groups + $i] = $hex;
					}
					else
					{
						return false;
					}
				}
			}
		}

		// now high order values
		if ($parts[0])
		{
			$groups = explode(':', $parts[0]);
			$num_groups = count($groups);

			if (!isset($parts[1]) AND $num_groups < 8)
			{
				// some 2-byte groups are missing
				return false;
			}

			for($i=0; $i<$num_groups; $i++)
			{
				if (preg_match($group_regex, $groups[$i], $matches) AND ($hex = hexdec($groups[$i])) <= 0xffff)
				{
					$canonical[$i] = $hex;
				}
				else
				{
					return false;
				}
			}
		}

		// now use the canonical form to build the ip fields
		$fields['ip_4'] = sprintf('%u', ($canonical[0] << 16) + $canonical[1]);
		$fields['ip_3'] = sprintf('%u', ($canonical[2] << 16) + $canonical[3]);
		$fields['ip_2'] = sprintf('%u', ($canonical[4] << 16) + $canonical[5]);
		$fields['ip_1'] = sprintf('%u', ($canonical[6] << 16) + $canonical[7]);
		return $fields;
	}

	/**
	 * Gets ip fields for storage from a string representation of IP. If the IP string is invalid it returns false.
	 * @param string $ipAddress
	 * @return mixed
	 */
	public static function getIpFields($ipAddress)
	{
		$ipAddress = strtolower(trim($ipAddress));

		if (self::isValidIPv4($ipAddress))
		{
			return array(
				'ip_4' => '0',
				'ip_3' => '0',
				'ip_2' => (string) 0xffff,
				'ip_1' => sprintf('%u', ip2long($ipAddress))
			);
		}
		else
		{
			return self::validateIPv6($ipAddress);
		}
	}

	/**
	 * Determines if the IPS are the same.  Note that this should work ccross different
	 * formats
	 *
	 * Note that if either ip address string is invalid the function will always return
	 * false.
	 *
	 * Assumes the ip values are both strings
	 *
	 * @param string $ip1
	 * @param string $ip2
	 * @return boolean
	 */
	public static function areIpsEqual($ip1, $ip2)
	{
		$iparray1 = self::getIpFields($ip1);
		if (!$iparray1)
		{
			return false;
		}

		$iparray2 = self::getIpFields($ip2);
		if (!$iparray2)
		{
			return false;
		}

		foreach($iparray1 AS $key => $value)
		{
			if($value != $iparray2[$key])
			{
				return false;
			}
		}

		return true;
	}

	/**
	 * Determines if the ip is one of the IPs are the same based on the rules
	 * for areIpsEqual
	 *
	 * Assumes the ip values are all strings
	 *
	 * @param string $ip1
	 * @param array(string) $iparray
	 * @return boolean
	 */
	public static function ipInArray($ip, $iparray)
	{
		foreach($iparray AS $value)
		{
			if (self::areIpsEqual($ip, $value))
			{
				return true;
			}
		}
		return false;
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
