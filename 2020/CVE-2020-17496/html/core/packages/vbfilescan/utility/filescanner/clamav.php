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

class Vbfilescan_Utility_Filescanner_Clamav extends vB_Utility_Filescanner
{
	protected $scannerInstance;
	protected $errors = array();

	protected function initialize($vboptions)
	{
		// Note that the 3rd party clamav class has the network option take precedence over local socket option.
		$options = array(
			'clamd_sock' => $vboptions['vbfilescan_clamd_sock'] ?? NULL,
			// removing this setting for now as I don't think it needs to be a
			// setting ATM and could cause unnecessary confusion
			//'clamd_sock_len' => $vboptions['vbfilescan_clamd_socklen'] ?? 20000,
			'clamd_ip' => $vboptions['vbfilescan_clamd_ip'] ?? NULL,
			'clamd_port' => $vboptions['vbfilescan_clamd_port'] ?? NULL,
		);
		// todo: how to secure vendor (3rd party) classes?
		// Do they need to use vb_trait_unserialize ?
		try
		{
			require_once(__DIR__ . '/../../vendor/clamav.php');
			$this->scannerInstance = new Clamav($options);
			// socket_connect() can display a warning if the socket path (or ip:port)
			// is not configured correctly
			$this->enabled = @ $this->scannerInstance->ping();
			if (!$this->enabled)
			{
				$this->errors[] = 'vbfilescan_error_please_verify_clamd';
			}
		}
		catch (Throwable $e)
		{
			$this->errors[] = array('vbfilescan_error_clamav_x', $e->getMessage());
			$this->enabled = false;
		}
	}

	protected function checkDependencies($vboptions)
	{
		// We need either the network IP & port options, or the local socket file option set.
		$usingNetwork = (!empty($vboptions['vbfilescan_clamd_ip']) AND !empty($vboptions['vbfilescan_clamd_port']));
		$usingLocal = !empty($vboptions['vbfilescan_clamd_sock']);
		if (!$usingNetwork AND !$usingLocal)
		{
			$this->errors[] = 'vbfilescan_error_missing_options';
			return false;
		}

		$hasExtension = extension_loaded('sockets');
		if (!$hasExtension)
		{
			$this->errors[] = 'vbfilescan_error_missing_sockets_extension';
			return false;
		}

		return true;
	}

	public function scanFile($filename)
	{
		$filename = realpath($filename);
		if (empty($filename))
		{
			return false;
		}

		$check = @ $this->scannerInstance->scan($filename);

		return $check;
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 102624 $
|| #######################################################################
\*=========================================================================*/
