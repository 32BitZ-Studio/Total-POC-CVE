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
 * vB_Library_Worker
 *
 * @package vBLibrary
 * @access public
 */

class vB_Library_Worker extends vB_Library
{
	/*
		Used to offload time-consuming tasks from the current connection (usually the main
		connection from browser) to avoid blocking subsequent requests.
	 */

	// String This forum's URL. Used to spawn a child thread to offload
	//	FCM requests from the initial request.
	protected $my_url_prefix = '';

	// Timeout, configurable. 3s default.
	protected $timeout = 3;

	/**
	 * Constructor
	 *
	 */
	protected function __construct()
	{
		$options = vB::getDatastore()->getValue('options');

		if (!empty($options['frontendurl']))
		{
			$this->my_url_prefix = $options['frontendurl'] . "/worker/";
		}

		if (!empty($options['fcm_worker_remote_timeout']) AND $options['fcm_worker_remote_timeout'] > 0)
		{
			$this->timeout = $options['fcm_worker_remote_timeout'];
		}


		return true;
	}

	public function testWorkerConnection()
	{
		$check = $this->callWorker("test");
		$decoded = array(
			'error' => "unknown error",
		);
		if (!empty($check['body']))
		{
			$decoded = json_decode($check['body'], true);
		}

		return $decoded;
	}

	public function callWorker($action, $postData = array())
	{
		if (empty($this->my_url_prefix))
		{
			return array(
				'error' => "missing_my_url",
			);
		}
		if (empty($action))
		{
			return array(
				'error' => "missing_action",
			);
		}
		$action = ltrim($action, '/');
		$url = $this->my_url_prefix . $action;

		$httpHeaders = array(
			'Content-Type: application/x-www-form-urlencoded',
		);

		$postFields = http_build_query($postData);

		/*
			Delegate task to an offshoot connection.
			This is to avoid incurring the processing time for the FCMs
			(mostly the wait time for the curl request to the google server
			for a number of FCMs) blocking subsequent AJAX requests due
			to "Connection: Keep-Alive".
		 */
		$vurl = vB::getUrlLoader(true);

		//no idea if this is actually needed, but I don't want to muck with prior behavior here.
		$vurl->setOption(vB_Utility_Url::CLOSECONNECTION, 1);
		$vurl->setOption(vB_Utility_Url::HTTPHEADER, $httpHeaders);
		$vurl->setOption(vB_Utility_Url::HEADER, 1);
		$vurl->setOption(vB_Utility_Url::TIMEOUT, $this->timeout);
		$result = $vurl->post($url, $postFields);

		return $result;
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 102970 $
|| #######################################################################
\*=========================================================================*/
