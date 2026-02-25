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
 * Assertor Exception
 * Exception thrown by assertor classes.
 */
class vB_Exception_Database extends vB_Exception
{
	protected $data;

	private $inDebugMode;

	/**
	 * Standard vB exception constructor for database exceptions.
	 *
	 *	@param	string	text message
	 * 	@param	mixed	array of data- intended for debug mode
	 * 	@code	mixed	normally an error flog.  If passed FALSE we won't send an email.
	 */
	public function __construct($message = "", $data = array(), $code = 0, $connectionfail = false)
	{
		$this->sql = $message;
		$this->data = $data;
		$this->inDebugMode = vB::getConfig()['Misc']['debug'];

		$mailBody = $this->createMessage();

		//mailbody always has debug info but we want to hide if we are not in
		//debug mode.
		if($this->inDebugMode AND $this->data)
		{
			$message = $mailBody;
		}

		//add the trace, which we really don't want for the message.
		if (!empty($this->data['trace']))
		{
			$mailBody .= "\n\n";
			$mailBody .= $this->getTraceString($this->data['trace']);
		}

		$subject = $this->createSubject();
		$config = vB::getConfig();

		parent::__construct($message, $code);

		// Try and stop e-mail flooding.
		$timenow = time();
		$tempdir = @sys_get_temp_dir();
		$unique = 'vb'.md5(vB_Request_Web::$COOKIE_SALT).'.err';
		$tempfile = realpath($tempdir).DIRECTORY_SEPARATOR.$unique;

		//we don't always have a data array so skip this part if we
		//don't have an errno to work with
		if(!empty($data['errno']))
		{
			//If its less than a minute since the last e-mail
			//and the error code is the same as last time, disable e-mail
			if ($filedata = @file_get_contents($tempfile))
			{
				$ecode = intval(substr($filedata, 10));
				$time = intval(substr($filedata, 0, 10));
				if ($time AND ($timenow - $time) < 60	AND intval($data['errno']) == $ecode)
				{
					$config['Database']['technicalemail'] = ''; // Stops the e-mail below.
				}
				else
				{
					$filedata = $timenow.intval($data['errno']);
					@file_put_contents($tempfile, $filedata);
				}
			}
			else
			{
				$filedata = $timenow.intval($data['errno']);
				@file_put_contents($tempfile, $filedata);
			}
		}

		if (!empty($config['Database']['technicalemail']) AND ($code !== FALSE))
		{
			vB_Mail::vbmail($config['Database']['technicalemail'], $subject, $mailBody, true, $config['Database']['technicalemail'], '', '', true);
		}

		//log message
		require_once(DIR . '/includes/functions_log_error.php');
		if (!$connectionfail AND function_exists('log_vbulletin_error'))
		{
			log_vbulletin_error($mailBody, 'database');
		}
	}

	//get the original error message in cases where we want to do our
	//own data formatting (most non default handling of the exception).
	public function getSql()
	{
		return $this->sql;
	}

	public function getData()
	{
		if($this->inDebugMode)
		{
			return array();
		}
		return $this->data;
	}

	/**
	 * Obtains the error mail subject
	 * @return string
	 */
	private function createSubject()
	{
		return "Database Error";
	}

	/**
	 * Obtains the error mail body
	 * @return string
	 */
	protected function createMessage()
	{
		if (empty($this->data))
		{
			// we have no info available
			return 'A database error occured, please check the database settings in the config file or enable debug mode for additional information.';
		}

		// This text is purposely hard-coded since we don't have
		// access to the database to get a phrase
		$message = "
			Database error in {$this->data['appname']} {$this->data['templateversion']}:

			{$this->sql}

			MySQL Error   : {$this->data['error']}
			Error Number  : {$this->data['errno']}
			Request Date  : {$this->data['requestdate']}
			Error Date    : {$this->data['date']}
			Script        : {$this->data['url']}
			Referrer      : {$this->data['referer']}
			IP Address    : {$this->data['ipaddress']}
			Username      : {$this->data['username']}
			Classname     : {$this->data['classname']}
			MySQL Version : {$this->data['mysqlversion']}
		";

		return $message;
	}

	/**
	 * Obtains the trace string.
	 * @param $trace
	 * @return string
	 */
	protected function getTraceString($trace)
	{
		$trace_output = "Stack Trace:\n";
		foreach ($trace AS $index => $trace_item)
		{
			$param = (
				in_array($trace_item['function'], array('require', 'require_once', 'include', 'include_once')) ?
					$trace_item['args'][0] : ''
			);

			// ensure we don't access undefined indexes
			foreach (array('file', 'class', 'type', 'function', 'line') AS $key)
			{
				if (!isset($trace_item[$key]))
				{
					$trace_item[$key] = '';
				}
			}

			// remove path
			$param = str_replace(DIR, '[path]', $param);
			$trace_item['file'] = str_replace(DIR, '[path]', $trace_item['file']);

			$trace_output .= "#$index $trace_item[class]$trace_item[type]$trace_item[function]($param) called in $trace_item[file] on line $trace_item[line]\n";
		}
		$trace_output .= "\n";
		return $trace_output;
	}


}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 100724 $
|| #######################################################################
\*=========================================================================*/
