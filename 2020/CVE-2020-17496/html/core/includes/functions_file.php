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

// These defines should match the constants in vB_Library_Filedata
if (!defined('ATTACH_AS_DB'))
{
	define('ATTACH_AS_DB', 0);
}
if (!defined('ATTACH_AS_FILES_OLD'))
{
	define('ATTACH_AS_FILES_OLD', 1);
}
if (!defined('ATTACH_AS_FILES_NEW'))
{
	define('ATTACH_AS_FILES_NEW', 2);
}

// ###################### Start checkattachpath #######################
// Returns Attachment path
//this is only being used in old upgrade steps and can probably be moved to the "legacy" section.
function fetch_attachment_path($userid, $attachmentid = 0, $type = vB_Api_Filedata::SIZE_FULL, $overridepath = '')
{
	$options = vB::getDatastore()->getValue('options');
	if (!empty($overridepath))
	{
		$filepath =& $overridepath;
	}
	else
	{
		$filepath =& $options['attachpath'];
	}

	if ($options['attachfile'] == ATTACH_AS_FILES_NEW) // expanded paths
	{
		$path = $filepath . '/' . implode('/', preg_split('//', $userid,  -1, PREG_SPLIT_NO_EMPTY));
	}
	else
	{
		$path = $filepath . '/' . $userid;
	}

	if ($attachmentid)
	{
		if ($type)
		{
			$type = vB_Api::instanceInternal('filedata')->sanitizeFiletype($type);
			switch ($type)
			{
				case vB_Api_Filedata::SIZE_ICON:
					return $path .= '/' . $attachmentid . '.' . vB_Api_Filedata::SIZE_ICON;
				case vB_Api_Filedata::SIZE_THUMB:
					return $path .= '/' . $attachmentid . '.' . vB_Api_Filedata::SIZE_THUMB;
				case vB_Api_Filedata::SIZE_SMALL:
					return $path .= '/' . $attachmentid . '.' . vB_Api_Filedata::SIZE_SMALL;
				case vB_Api_Filedata::SIZE_MEDIUM:
					return $path .= '/' . $attachmentid . '.' . vB_Api_Filedata::SIZE_MEDIUM;
				case vB_Api_Filedata::SIZE_LARGE:
					return $path .= '/' . $attachmentid . '.' . vB_Api_Filedata::SIZE_LARGE;
				default:
			}
			$path .= '/' . $attachmentid . '.attach';
		}
		else
		{
			$path .= '/' . $attachmentid . '.attach';
		}
	}

	return $path;
}

// ###################### Start vbmkdir ###############################
// Recursive creation of file path
function vbmkdir($path, $mode = 0777)
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
		if (!vbmkdir($partialpath, $mode))
		{
			return false;
		}
		else
		{
			return @mkdir($path, $mode);
		}
	}
}

// ###################### Start downloadFile #######################
// must be called before outputting anything to the browser
function file_download($filestring, $filename, $filetype = 'application/octet-stream')
{
	if (!isset($isIE))
	{
		static $isIE;
		$isIE = iif(is_browser('ie') OR is_browser('opera'), true, false);
	}

	if ($isIE AND $filetype == 'application/octet-stream')
	{
		$filetype = 'application/octetstream';
	}

	$filename_charset = vB_String::getCharset();
	if (preg_match('~&#([0-9]+);~', $filename))
	{
		if (function_exists('iconv'))
		{
			$filename = @iconv($filename_charset, 'UTF-8//IGNORE', $filename);
		}

		$filename = preg_replace_callback(
			'~&#([0-9]+);~',
			'convert_int_to_utf8_callback',
			$filename
		);
		$filename_charset = 'utf-8';
	}
	$filename = preg_replace('#[\r\n]#', '', $filename);

	//much of this is probably out of date, however this function is only called by the
	//admincp and generally with filenames we're setting.  At this point it's not worth getting
	//into the details unless there are specific customer complaints.
	// Opera and IE have not a clue about this, mozilla puts on incorrect extensions.
	if (is_browser('mozilla'))
	{
		$filename = "filename*=" . $filename_charset . "''" . rawurlencode($filename);
	}
	else
	{
		// other browsers seem to want names in UTF-8
		if ($filename_charset != 'utf-8' AND function_exists('iconv'))
		{
			$filename = @iconv($filename_charset, 'UTF-8//IGNORE', $filename);
		}

		// Should just make this (!is_browser('ie'))
		if (is_browser('opera') OR is_browser('konqueror') OR is_browser('safari'))
		{
			// Opera / konqueror does not support encoded file names
			$filename = 'filename="' . str_replace('"', '', $filename) . '"';
		}
		else
		{
			// encode the filename to stay within spec
			$filename = 'filename="' . rawurlencode($filename) . '"';
		}
	}

	header('Content-Type: ' . $filetype);
	header('Expires: ' . gmdate('D, d M Y H:i:s') . ' GMT');
	header('Content-Disposition: attachment; ' . $filename);
	header('Content-Length: ' . strlen($filestring));
	header('Cache-Control: private, must-revalidate, post-check=0, pre-check=0');
	header('Pragma: public');

	echo $filestring;
	exit;
}

// ###################### Start getmaxattachsize #######################
function fetch_max_upload_size()
{
	if ($temp = @ini_get('upload_max_filesize'))
	{
		if (preg_match('#^\s*(\d+(?:\.\d+)?)\s*(?:([mkg])b?)?\s*$#i', $temp, $matches))
		{
			switch (strtolower($matches[2]))
			{
				case 'g':
					return $matches[1] * 1073741824;
				case 'm':
					return $matches[1] * 1048576;
				case 'k':
					return $matches[1] * 1024;
				default: // no g, m, k, gb, mb, kb
					return $matches[1] * 1;
			}
		}
		else
		{
			return $temp;
		}
	}
	else
	{
		return 10485760; // approx 10 megabytes :)
	}
}

// Returns the error phrase array when the upload returns the error number instead the uploaded file
// error number must came from something like $_FILES["file"]["error"] or $vbulletin->GPC['file']['error']
 function get_error_phrase_from_upload_file($error_number)
 {
	 $phrase = array();
	 switch($error_number)
	 {
		case '1':
		case '2':
			$phrase = array('upload_file_exceeds_php_limit', ini_get('upload_max_filesize'));
			break;
		case '3':
			$phrase = array('upload_file_failed');
			break;
		case '4':
			$phrase = array('upload_err_no_file');
			break;
		case '6':
			$phrase = array('missing_temporary_folder');
			break;
		case '7':
			$phrase = array('upload_writefile_failed');
			break;
		case '8':
			$phrase = array('upload_stopped_by_extension');
			break;
		default:
			$phrase = array('upload_invalid_file');
	 }

	 return $phrase;
 }

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 102776 $
|| #######################################################################
\*=========================================================================*/
