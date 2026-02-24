<?php
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

/*
 */
class vB_Utility_Ip
{
	use vB_Utility_Trait_NoSerialize;

	/**
	 * Checks if the string is a valid ip v4 address
	 *
	 * @param string $ip
	 * @return bool
	 */
	public function isIpV4($ip)
	{
		$result = filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4);
		return (bool) $result;
	}

	/**
	 * Checks if the string is a valid ip v6 address
	 *
	 * @param string $ip
	 * @return bool
	 */
	public function isIpV6($ip)
	{
		$result = filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6);
		return (bool) $result;
	}

	public function isValid($ip)
	{
		return (bool) filter_var($ip, FILTER_VALIDATE_IP);
	}

	/**
	 * Checks if this is a valid public IP address
	 *
	 * @param string $ip
	 * @return bool -- Returns true if the IP address is valid (v4 or v6) and not in a private or restricted range
	 */
	public function isPublic($ip)
	{
		return (bool) filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE);
	}

	/**
	 * Get the type of an ip address
	 *
	 * @param string $ip
	 * @return int -- Returns 4 if a valid v4 address, 6 if a valid v6 address, 0 if not a valid address
	 */
	public function iptype($ip)
	{
		if ($this->isIpV6($ip))
		{
			return 6;
		}

		if ($this->isIpV4($ip))
		{
			return 4;
		}

		return 0;
	}

	/**
	 * Normalizes an ip address string
	 *
	 * This is particularly important for ipv6 strings which have a number of shortcuts
	 * that will invalidate string matches.  This will also trim whitespace from the string.
	 *
	 * @param string $ip
	 */
	public function normalize($ip)
	{
		$trimmedip = trim($ip);
		//don't mess with ipV4 or garbage other then to trim it.
		//
		//It's not as critical for ipV4 and the v4 validation functions are somewhat
		//more fragile in terms of detecting (in retrospect, the normalization
		//appears to work on any ipV4 that passes validation -- though it doesn't
		//appear to *change* any of them).  Not sure if it's safer to normalize or
		//not given that it appears to be a don't care.
		//
		//And if we can't figure out what it is we *do not* want to change it.
		if (!$this->isIpV6($trimmedip))
		{
			return $trimmedip;
		}
		return inet_ntop(inet_pton($trimmedip));
	}

	/**
	 *	Check to see if the IP is in a list of IP addresses
	 *
	 * @param string $ip
	 * @param array $list -- array of ip address to check.  In addition to proper ip addresses,
	 *	it allows wildcard addresses that end in "*".  These will match any ip address for which
	 *	they are a prefix (so 127.0.* will match 127.0.0.1 as will 127.0*).  Note that no formatting
	 *	normalization will take place on these strings so "2607:f8b0:0000:*" will not match "2607:f8b0::4007:0:0:2004"
	 *
	 * @return bool -- true if the $ip matches anything in the list, false otherwise.
	 */
	public function isInList($ip, $list)
	{
		// Check all the entries
		foreach ($list AS $listip)
		{
			//if this is a wildcard
			if (substr($listip, -1) == '*')
			{
				if (strncasecmp($ip, $listip, strlen($listip) - 1) == 0)
				{
					return true;
				}
			}
			else
			{
				if ($ip == $listip)
				{
					return true;
				}
			}
		}

		return false;
	}

	/**
	 *	Truncate an ipv4 address based on the number of octets requested
	 *
	 *	This will return the requested number of octets for an ipV4 address.
	 *	An ipV6 address will be returned unchanged.  The IP address is not
	 *	validated and behavior for invalid IP addresses is not defined.
	 *
	 * 	@param $ip the ip address string
	 *	@param $octets -- the number of octets to return.  The number should be
	 *		between 1 and 4 inclusive, but is not validated.
	 */
	//This is mostly formalizing some existing behavior that we don't want to
	//change just yet.
	public function ipSubstring($ip, $octets)
	{
		//this implicitly does not affect ipV6 addresses, since they will never
		//contain a period.  If we change the logic we may need to explicitly
		//check what kind of IP we are dealing with
		return implode('.', array_slice(explode('.', $ip), 0, $octets));
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 101013 $
|| #######################################################################
\*=========================================================================*/
