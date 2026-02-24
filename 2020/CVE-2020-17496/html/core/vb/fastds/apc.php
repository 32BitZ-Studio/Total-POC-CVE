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

/* NOTE: This file contains the APC Implementation of vB_FastDS /**
 *
 * There is some data that is heavily used, not excessively large, and changes rarely.
 * There are a number of in-memory caches for php. The most common is probably APC, but
 * there are a number of others. By caching the appropriate data we believe we can
 * significantly improve performance.  The priority is:
 * first: stylevars:  About 60K
 * then phrases for the default language: 1 megabyte for the current default.
 * then datastore options: under 20k for the default.
 * then datastore: under a megabyte.
 * then all templates for the default style: around 3 megabytes.
 *
 * note that this is shared among all users. We should only implement this for
 * caches which live on the current server. If we access a remote server, we probably
 * will be no faster than the existing datastore/cache implementations.

 * @package vBulletin
 * @author vBulletin Development Team
 * @version $Revision: 99788 $
 * @since $Date: 2018-10-24 17:26:31 -0700 (Wed, 24 Oct 2018) $
 
 */
class vB_FastDS_APC extends vB_FastDS
{
	/** gets a value
	 *
	 * 	@param	string
	 * 	@param	mixed	string or array of string
	 *
	 *	@return	mixed	the value from fastDS
	 **/
	protected function getValue($prefix, $keys)
	{
		$success = null;

		if (is_array($keys))
		{
			$apcKeys = array();
			foreach($keys AS $key)
			{
				if (is_string($key))
				{
					$apcKeys[$key] = $this->prefix . $prefix . $key;
				}
			}
			$apc = apc_fetch($apcKeys, $success);

			if (!$success)
			{
				return false;
			}
			$result = array();
			foreach($apcKeys AS $key => $apcKey)
			{
				if (isset($apc[$apcKey]))
				{
					$result[$key] = $apc[$apcKey];
				}
			}
			return $result;
		}

		$apc = apc_fetch($this->prefix . $prefix . $keys, $success);

		if ($success)
		{
			return $apc;
		}
		return false;
	}

	/** sets a value
	 *
	 * 	@param	string	key
	 *	@param	mixed	value to be stored

	 *	@return	bool	true if it succeeded, otherwise false
	 **/
	protected function setValue($key, $value)
	{
		return apc_store($this->prefix . $key, $value);
	}

	/** clears a value
	 *
	 * 	@param	string	key
	 **/
	protected function clearValue($key)
	{

		return apc_delete($this->prefix . $key);
	}

}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99788 $
|| #######################################################################
\*=========================================================================*/
