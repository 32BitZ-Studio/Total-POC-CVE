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
* Log errors to a file
*
* @param	string	The error message to be placed within the log
* @param	string	The type of error that occured. php, database, security, etc.
*
* @return	boolean
*/
function log_vbulletin_error($errstring, $type = 'database')
{
	//if for some reason we can't get the datastore (for example the
	//database is borked) we don't know what to do.  But having
	//the error log function throw errors isn't going to help.
	try
	{
		$options = vB::getDatastore()->getValue('options');
	}
	catch(Exception $e)
	{
		return false;
	}

	// do different things depending on the error log type
	switch($type)
	{
		// log PHP E_USER_ERROR, E_USER_WARNING, E_WARNING to file
		case 'php':
			if (!empty($options['errorlogphp']))
			{
				$session = vB::getCurrentSession();
				if ($session)
				{
					$username = $session->fetch_userinfo();
					$username = $username['username'];
				}
				else
				{
					$username = 'unknown';
				}

				$request = vB::getRequest();
				if($request)
				{
					$ip = $request->getIpAddress();
				}
				else
				{
					$ip = '';
				}

				$errfile = $options['errorlogphp'];
				$errstring .= "\r\nDate: " . date('l dS \o\f F Y h:i:s A') . "\r\n";
				$errstring .= "Username: $username\r\n";
				$errstring .= 'IP Address: ' . $ip . "\r\n";
			}
			break;

		// log database error to file
		case 'database':
			if (!empty($options['errorlogdatabase']))
			{
				$errstring = preg_replace("#(\r\n|\r|\n)#s", "\r\n", $errstring);
				$errfile = $options['errorlogdatabase'];
			}
			break;

		// log admin panel login failure to file
		case 'security':
			if (!empty($options['errorlogsecurity']))
			{
				$request = vB::getRequest();
				if($request)
				{
					$server = $request->getVbHttpHost();
					$path = $request->getScriptPath();

					$script = "http://$server" . unhtmlspecialchars($path);
					$referrer = $request->getReferrer();
					$ip = $request->getIpAddress();
				}
				else
				{
					$script = '';
					$referrer = '';
					$ip = '';
				}

				$errfile = $options['errorlogsecurity'];
				$username = $errstring;
				$errstring  = 'Failed admin logon in vBulletin ' . $options['templateversion'] . "\r\n\r\n";
				$errstring .= 'Date: ' . date('l dS \o\f F Y h:i:s A') . "\r\n";
				$errstring .= "Script: $script\r\n";
				$errstring .= 'Referer: ' . $referrer . "\r\n";
				$errstring .= "Username: $username\r\n";
				$errstring .= 'IP Address: ' . $ip . "\r\n";
				$errstring .= "Strikes: $GLOBALS[strikes]/5\r\n";
			}
			break;
	}

	// if no filename is specified, exit this function
	if (!isset($errfile) OR !($errfile = trim($errfile)) OR (defined('DEMO_MODE') AND DEMO_MODE == true))
	{
		return false;
	}

	// rotate the log file if filesize is greater than $options[errorlogmaxsize]
	if (
		$options['errorlogmaxsize'] != 0 AND
		$filesize = @filesize("$errfile.log") AND
		$filesize >= $options['errorlogmaxsize']
	)
	{
		//don't assume that everything is working properly.
		$request = vB::getRequest();
		if($request)
		{
			$time = $request->getTimeNow();
		}
		else
		{
			$time = time();
		}

		@copy("$errfile.log", $errfile . $time . '.log');
		@unlink("$errfile.log");
	}

	// write the log into the appropriate file
	if ($fp = @fopen("$errfile.log", 'a+'))
	{
		@fwrite($fp, "$errstring\r\n=====================================================\r\n\r\n");
		@fclose($fp);
		return true;
	}
	else
	{
		return false;
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 101127 $
|| #######################################################################
\*=========================================================================*/
