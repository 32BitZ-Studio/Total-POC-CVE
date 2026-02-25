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
 * vB_Utilities
 *
 * @package vBApi
 * @access public
 */
class vB_Utilities
{
	use vB_Trait_NoSerialize;

	public static function vbmkdir($path, $mode = 0777)
	{
		if (is_dir($path))
		{
			if (!(is_writable($path)))
			{
				@chmod($path, $mode);
			}
			return true;
		}
		else
		{
			$oldmask = @umask(0);
			$partialpath = dirname($path);

			if (!self::vbmkdir($partialpath, $mode))
			{
				return false;
			}
			else
			{
				return @mkdir($path, $mode);
			}
		}
	}

	// #############################################################################
	/**
	 * Converts shorthand string version of a size to bytes, 8M = 8388608
	 *
	 * @param	string			The value from ini_get that needs converted to bytes
	 *
	 * @return	integer			Value expanded to bytes
	 */
	public static function ini_size_to_bytes($value)
	{
		$value = trim($value);
		$retval = intval($value);

		switch(strtolower($value[strlen($value) - 1]))
		{
			case 'g':
				$retval *= 1024;
			/* break missing intentionally */
			case 'm':
				$retval *= 1024;
			/* break missing intentionally */
			case 'k':
				$retval *= 1024;
				break;
		}

		return $retval;
	}


	/**
	 *	Attempt to extend the memory limit
	 *
	 *	This function will extend the memory limit to 256M if
	 *	a) The current limit is lower
	 *	b) ini_set('memory_limit') actually works.
	 *
	 * 	Part of the intent of this function is to allow adjusting the new limit centrally
	 * 	instead of having it encoded in various files.  Thus we deliberately do not pass
	 * 	it as a parameter.
	 *
	 *	@return none
	 */
	public static function extendMemoryLimit()
	{
		//if we need to extend this to different amounts in different places (and if you
		//think we do we probably don't).  Suggest a "scaling factor" instead of a hard
		//amount.  This is likely to need increasing -- assuming it doesn't become
		//irrelevant -- as hardware improves.
		$value = '256M';
		$new_memory_limit = self::ini_size_to_bytes($value);
		self::extendMemoryLimitBytes($new_memory_limit);
	}

	/**
	 *	Extend the memory limit to a specific byte value
	 *
	 *	Generally callers should use the extendMemoryLimit function.  But in some
	 *	cases we estimate how much memory is required and attempt to extend to
	 *	that amount rather than just some arbitrary value.  Like extendMemoryLimit
	 *	this will only affect the limit if the value is higher than the current
	 *	amount.
	 *
	 *	This function is not intended to be called with a constant value.  We should
	 *	keep the extention limit synced so that we can change it.  There isn't much
	 *	value in having different arbitrary limits for different processes (extending
	 *	the limit doesn't automatically use more memory).
	 *
	 *	@param int $value -- the memory limit in bytes.  Note that this does *not*
	 *		accept php.ini strings such at '256M'.  We do internal calcuations on the
	 *		value before passing it to ini_set which will fail.
	 */
	public static function extendMemoryLimitBytes($value)
	{
		$current_memory_limit = self::ini_size_to_bytes(ini_get('memory_limit'));
		//0 means unlimited
		if ($current_memory_limit > 0 AND $current_memory_limit < $value)
		{
			//one of the code blocks this function replaces wraps the exception buster, but
			//there is not clear indication of *why*. I don't think ini_set can throw exceptions.
			//But if it does we really don't want to stop execution.
			try
			{
				@ini_set('memory_limit', $value);
			}
			catch (Exception $e)
			{
				// just ignore
			}

		}
	}

	/**
	 * Generates a valid path and filename for a temp file. In the case
	 * of safe upload, this generates the filename, but not the file. In
	 * the case of tempnam(), the temp file is actually created.
	 *
	 * @param	string|int	Optional extra "entropy" for the md5 call, this would typically be an ID such as userid or avatarid, etc
	 * 	*for the current record* of whatever is being processed. If empty, it uses the *current user's* userid.
	 * @param	string		An optional prefix for the file name. Depending on OS and if tempnam is used, only the first 3 chars of this will be used.
	 * @param	string		An optional suffix for the file name, can be used to add a file extension if needed.
	 *
	 * @return	string|false	The path and filename of the temp file, or bool false if it failed.
	 */
	public static function getTmpFileName($entropy = '', $prefix = 'vb_', $suffix = '')
	{
		$options = vB::getDatastore()->getValue('options');

		if ($options['safeupload'])
		{
			if (empty($entropy))
			{
				$entropy = vB::getCurrentSession()->get('userid');
			}

			//it *usually* doesn't matter if we use the slash instead of the local OS seperator, but
			//if we pass the value to exec things can't go a bit wierd.
			$filename = $options['tmppath'] . DIRECTORY_SEPARATOR . $prefix . md5(uniqid(microtime()) . $entropy) . $suffix;
		}
		else
		{
			//this can get called in boot up.  We really need to fix that.
			$userContext = vB::getUserContext();
			if ($userContext AND $userContext->hasPermission('adminpermissions', 'cancontrolpanel'))
			{
				$filename = tempnam(self::getTmpDir(), $prefix);
			}
			else
			{
				$filename = @tempnam(self::getTmpDir(), $prefix);
			}

			if ($filename AND $suffix)
			{
				// tempnam doesn't support specifying a suffix
				unlink($filename);
				$filename = $filename . $suffix;
				touch($filename);
			}
		}

		return $filename;
	}

	/**
	 * Returns the temp directory that vBulletin should use.
	 *
	 * @return	string|false	Path to the temp directory, or false if ini_get failed.
	 */
	public static function getTmpDir()
	{
		$options = vB::getDatastore()->getValue('options');

		if ($options['safeupload'])
		{
			$path = $options['tmppath'];
		}
		else
		{
			$path = ini_get('upload_tmp_dir');
			if (!$path OR !is_writable($path))
			{
				$path = sys_get_temp_dir();
			}
		}

		return $path;
	}

	/**
	 * Returns a stack trace as a string
	 *
	 * @return	string	Stack trace
	 */
	public static function getStackTrace()
	{
		$trace = debug_backtrace();
		$trace_item_blank = array(
			'type' => '',
			'file' => '',
			'line' => '',
			'class' => '',
		);

		// rm 'core' from the end of DIR, since the path could be in core or presentation
		$dir = trim(DIR, '/\\');
		$dir = substr($dir, -4) == 'core' ? substr($dir, 0, -4) : $dir;
		$dir = trim($dir, '/\\');

		$traceString = '';
		foreach ($trace AS $index => $trace_item)
		{
			$trace_item += $trace_item_blank;

			if (in_array($trace_item['function'], array('require', 'require_once', 'include', 'include_once')))
			{
				// included files
				$param = array();
				foreach ($trace_item['args'] AS $arg)
				{
					$param[] = str_replace($dir, '[path]', $arg);
				}
				$param = implode(', ', $param);
			}
			else
			{
				// include some limited, strategic data on args
				$param = array();

				if (is_array($trace_item['args']))
				{
					foreach ($trace_item['args'] AS $arg)
					{
						$argType = gettype($arg);
						switch ($argType)
						{
							case 'integer':
							case 'double':
								$argVal = $arg;
								break;
							case 'string':
								$len = strlen($arg);
								$argVal = "'" . ($len > 30 ? substr($arg, 0, 25) . '[len:' . $len . ']' : $arg) . "'";
								break;
							case 'array':
								$argVal = 'array[len:' . count($arg) . ']';
								break;
							case 'boolean':
								$argVal = $arg ? 'true' : 'false';
								break;
							case 'object':
								$argVal = get_class($arg);
								break;
							case 'resource':
								$argVal = 'resource[type:' . get_resource_type($arg) . ']';
								break;
							default:
								$argVal = $argType;
								break;
						}
						$param[] = $argVal;
					}
				}
				$param = implode(', ', $param);
			}

			$trace_item['file'] = str_replace($dir, '[path]', $trace_item['file']);

			$traceString .= "#$index: " . $trace_item['class'] . $trace_item['type'] . $trace_item['function'] . "($param)" . ($trace_item['file'] ? ' called in ' . $trace_item['file'] . ' on line ' . $trace_item['line'] : '') . "\n";
		}

		// args may contain chars that need escaping
		$traceString = htmlspecialchars($traceString);

		return $traceString;
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
