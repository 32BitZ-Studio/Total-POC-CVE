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

if (!isset($GLOBALS['vbulletin']->db))
{
	exit;
}

/**
* Abstracted class that handles POST data from $_FILES
*
* @package	vBulletin
* @version	$Revision: 102888 $
* @date		$Date: 2019-09-20 13:47:54 -0700 (Fri, 20 Sep 2019) $
*/
abstract class vB_Upload_Abstract
{
	/**
	* Any errors that were encountered during the upload or verification process
	*
	* @var	array
	*/
	var $error = '';

	/**
	* Main registry object
	*
	* @var	vB_Registry
	*/
	var $registry = null;

	/**
	* Image object for verifying and resizing
	*
	* @var	vB_Image
	*/
	var $image = null;

	/**
	* Object for save/delete operations
	*
	* @var	vB_DataManager
	*/
	var $upload = null;

	/**
	* Information about the upload that we are working with
	*
	* @var	array
	*/
	var $data = null;

	/**
	* Width and Height up Uploaded Image
	*
	* @var	array
	*/
	var $imginfo = array();

	/**
	* Maximum size of uploaded file. Set to zero to not check
	*
	* @var	int
	*/
	var $maxuploadsize = 0;

	/**
	* Maximum pixel width of uploaded image. Set to zero to not check
	*
	* @var	int
	*/
	var $maxwidth = 0;

	/**
	* Maximum pixel height of uploaded image. Set to zero to not check
	*
	* @var	int
	*/
	var $maxheight = 0;

	/**
	* Information about user who owns the image being uploaded. Mostly we care about $userinfo['userid'] and $userinfo['attachmentpermissions']
	*
	* @var	array
	*/
	var $userinfo = array();

	/**
	* Whether to display an error message if the upload forum is sent in empty or invalid (false = Multiple Upload Forms)
	*
	* @var  bool
	*/
	var $emptyfile = true;

	/**
	* Whether or not animated GIFs are allowed to be uploaded
	*
	* @var boolean
	*/
	var $allowanimation = null;

	function __construct(&$registry)
	{
		$this->registry =& $registry;
		// change this to save a file as someone else
		$this->userinfo = $this->registry->userinfo;
	}

	/**
	* Set warning
	*
	* @param	string	Varname of error phrase
	* @param	mixed	Value of 1st variable
	* @param	mixed	Value of 2nd variable
	* @param	mixed	Value of Nth variable
	*/
	function set_warning()
	{
		$args = func_get_args();

		$this->error = call_user_func_array('fetch_error', $args);
	}

	/**
	* Set error state and removes any uploaded file
	*
	* @param	string	Varname of error phrase
	* @param	mixed	Value of 1st variable
	* @param	mixed	Value of 2nd variable
	* @param	mixed	Value of Nth variable
	*/
	function set_error()
	{
		$args = func_get_args();

		$this->error = call_user_func_array('fetch_error', $args);

		if (!empty($this->upload['location']))
		{
			@unlink($this->upload['location']);
		}
	}

	/**
	* Returns the current error
	*
	*/
	function &fetch_error()
	{
		return $this->error;
	}

	private function scanFile($filename)
	{
		$check = vB_Library::instance('filescan')->scanFile($filename);

		return $check;
	}

	/**
	* This function accepts a file via URL or from $_FILES, verifies it, and places it in a temporary location for processing
	*
	* @param	mixed	Valid options are: (a) a URL to a file to retrieve or (b) a pointer to a file in the $_FILES array
	*/
	function accept_upload(&$upload)
	{
		$this->error = '';

		if (!is_array($upload) AND strval($upload) != '')
		{
			$this->upload['extension'] = strtolower(file_extension($upload));

			// Check extension here so we can save grabbing a large file that we aren't going to use
			if (!$this->is_valid_extension($this->upload['extension']))
			{
				$this->set_error('upload_invalid_file');
				return false;
			}

			// Admins can upload any size file
			if ($this->registry->userinfo['permissions']['adminpermissions'] & $this->registry->bf_ugp_adminpermissions['cancontrolpanel'])
			{
				$this->maxuploadsize = 0;
			}
			else
			{
				$this->maxuploadsize = $this->fetch_max_uploadsize($this->upload['extension']);
				if (!$this->maxuploadsize)
				{
					$newmem = 20971520;
				}
			}

			if (!preg_match('#^((http|ftp)s?):\/\/#i', $upload))
			{
				$upload = 'http://' . $upload;
			}

			$filesize = $this->fetch_remote_filesize($upload);
			if ($filesize)
			{
				if ($this->maxuploadsize AND $filesize > $this->maxuploadsize)
				{
					$this->set_error('upload_remoteimage_toolarge');
					return false;
				}
				else
				{
					if (function_exists('memory_get_usage') AND $memory_limit = @ini_get('memory_limit') AND $memory_limit != -1)
					{
						// Make sure we have enough memory to process this file
						$memorylimit = vb_number_format($memory_limit, 0, false, null, '');
						$memoryusage = memory_get_usage();
						$freemem = $memorylimit - $memoryusage;
						$newmemlimit = !empty($newmem) ? $freemem + $newmem : $freemem + $filesize;

						vB_Utilities::extendMemoryLimitBytes($newmemlimit);
					}

					$vurl = vB::getUrlLoader();
					$vurl->setOption(vB_Utility_Url::FOLLOWLOCATION, 1);
					$vurl->setOption(vB_Utility_Url::HEADER, 1);
					$vurl->setOption(vB_Utility_Url::MAXSIZE, $this->maxuploadsize);
					$vurl->setOption(vB_Utility_Url::TEMPFILENAME, vB_Utilities::getTmpFileName('', 'vbupload'));
					$result = $vurl->get($upload);

					if(!$result)
					{
						switch ($vurl->getError())
						{
							case vB_Utility_Url::ERROR_MAXSIZE:
								$this->set_error('upload_remoteimage_toolarge');
								break;
							case vB_Utility_Url::ERROR_NOFILE:
								$this->set_error('upload_writefile_failed');
								break;
							case vB_Utility_Url::ERROR_NOLIB:
								$this->set_error('upload_fopen_disabled');
								break;
						}

						return false;
					}
					unset($vurl);
				}
			}
			else
			{
				$this->set_error('upload_invalid_url');
				return false;
			}

			// the body is the the file location we downloaded the content to
			$this->upload['location'] = $result['body'];

			if (!$this->scanFile($this->upload['location']))
			{
				// Note that set_error() unlinks the file.
				// This is set to be a tmp file above, so we can safely delete it.
				$this->set_error('filescan_fail_uploaded_file');
				return false;
			}

			$this->upload['filesize'] = @filesize($this->upload['location']);
			$this->upload['filename'] = basename($upload);
			$this->upload['extension'] = strtolower(file_extension($this->upload['filename']));
			$this->upload['thumbnail'] = '';
			$this->upload['filestuff'] = '';
			$this->upload['url'] = true;
		}
		else
		{
			$this->upload['filename'] = trim($upload['name']);
			$this->upload['filesize'] = intval($upload['size']);
			$this->upload['location'] = trim($upload['tmp_name']);
			$this->upload['extension'] = strtolower(file_extension($this->upload['filename']));
			$this->upload['thumbnail'] = '';
			$this->upload['filestuff'] = '';

			if ($this->registry->userinfo['permissions']['adminpermissions'] & $this->registry->bf_ugp_adminpermissions['cancontrolpanel'] AND $this->upload['error'])
			{
				// Encountered PHP upload error
				if (!($maxupload = @ini_get('upload_max_filesize')))
				{
					$maxupload = 10485760;
				}
				$maxattachsize = vb_number_format($maxupload, 1, true);

				switch($this->upload['error'])
				{
					case '1': // UPLOAD_ERR_INI_SIZE
					case '2': // UPLOAD_ERR_FORM_SIZE
						$this->set_error('upload_file_exceeds_php_limit', $maxattachsize);
						break;
					case '3': // UPLOAD_ERR_PARTIAL
						$this->set_error('upload_file_partially_uploaded');
						break;
					case '4':
						$this->set_error('upload_file_failed');
						break;
					case '6':
						$this->set_error('missing_temporary_folder');
						break;
					case '7':
						$this->set_error('upload_writefile_failed');
						break;
					case '8':
						$this->set_error('upload_stopped_by_extension');
						break;
					default:
						$this->set_error('upload_invalid_file');
				}

				return false;
			}
			else if (
				$this->upload['error'] OR
				$this->upload['location'] == 'none' OR
				$this->upload['location'] == '' OR
				$this->upload['filename'] == '' OR
				!$this->upload['filesize'] OR
				!is_uploaded_file($this->upload['location'])
			)
			{
				if ($this->emptyfile OR $this->upload['filename'] != '')
				{
					$this->set_error('upload_file_failed');
				}
				return false;
			}

			if (!$this->scanFile($this->upload['location']))
			{
				// Note that set_error() unlinks the file.
				// This should be safe to delete, as if it's not an uploaded file it will be caught in the
				// above elseif case.
				$this->set_error('filescan_fail_uploaded_file');
				return false;
			}

			if ($this->registry->options['safeupload'])
			{
				$temppath = $this->registry->options['tmppath'] . '/' . $this->registry->session->fetch_sessionhash();
				$moveresult = $this->registry->userinfo['permissions']['adminpermissions'] & $this->registry->bf_ugp_adminpermissions['cancontrolpanel'] ? move_uploaded_file($this->upload['location'], $temppath) : @move_uploaded_file($this->upload['location'], $temppath);
				if (!$moveresult)
				{
					$this->set_error('upload_unable_move');
					return false;
				}
				$this->upload['location'] = $temppath;
			}
		}

		// Check if the filename is utf8
		$this->upload['utf8_name'] = isset($upload['utf8_name']) AND $upload['utf8_name'];

		$return_value = true;
		// Legacy Hook 'upload_accept' Removed //

		return $return_value;

	}

	/**
	* Requests headers of remote file to retrieve size without downloading the file
	*
	* @param	string	URL of remote file to retrieve size from
	*/
	function fetch_remote_filesize($url)
	{
		if (!preg_match('#^((http|ftp)s?):\/\/#i', $url, $check))
		{
			$this->set_error('upload_invalid_url');
			return false;
		}

		$vurl = vB::getUrlLoader();
		$vurl->setOption(vB_Utility_Url::FOLLOWLOCATION, 1);
		$vurl->setOption(vB_Utility_Url::HEADER, 1);
		$vurl->setOption(vB_Utility_Url::NOBODY, 1);
		$vurl->setOption(vB_Utility_Url::CUSTOMREQUEST, 'HEAD');
		$vurl->setOption(vB_Utility_Url::CLOSECONNECTION, 1);
		$result = $vurl->get($url);

		if(!$result OR !$result['headers'])
		{
			return false;
		}

		$headers = $result['headers'];

		$length = intval($headers['content-length']);
		if ($length)
		{
			return $length;
		}

		if ($headers['http-response']['statuscode'] == '200')
		{
			// We have an HTTP 200 OK, but no content-length, return -1 and let the url class handle the max fetch size
			return -1;
		}

		return false;
	}

	/**
	 * Attempt to resize file if the filesize is too large after an initial resize to max dimensions or
	 * the file is already within max dimensions but the filesize is too large
	 *
	 * @param	bool	Has the image already been resized once?
	 * @param	bool	Attempt a resize
	 */
	function fetch_best_resize(&$jpegconvert, $resize = true)
	{
		if (!$jpegconvert AND $this->upload['filesize'] > $this->maxuploadsize AND $resize AND $this->image->isValidResizeType($this->imginfo[2]))
		{
			// Linear Regression
			switch($this->registry->options['thumbquality'])
			{
				case 65:
					// No Sharpen
					// $magicnumber = round(379.421 + .00348171 * $this->maxuploadsize);
					// Sharpen
					$magicnumber = round(277.652 + .00428902 * $this->maxuploadsize);
					break;
				case 85:
					// No Sharpen
					// $magicnumber = round(292.53 + .0027378 * $this-maxuploadsize);
					// Sharpen
					$magicnumber = round(189.939 + .00352439 * $this->maxuploadsize);
					break;
				case 95:
					// No Sharpen
					// $magicnumber = round(188.11 + .0022561 * $this->maxuploadsize);
					// Sharpen
					$magicnumber = round(159.146 + .00234146 * $this->maxuploadsize);
					break;
				default:	//75
					// No Sharpen
					// $magicnumber = round(328.415 + .00323415 * $this->maxuploadsize);
					// Sharpen
					$magicnumber = round(228.201 + .00396951 * $this->maxuploadsize);
			}

			$xratio = ($this->imginfo[0] > $magicnumber) ? $magicnumber / $this->imginfo[0] : 1;
			$yratio = ($this->imginfo[1] > $magicnumber) ? $magicnumber / $this->imginfo[1] : 1;

			if ($xratio > $yratio AND $xratio != 1)
			{
				$new_width = round($this->imginfo[0] * $xratio);
				$new_height = round($this->imginfo[1] * $xratio);
			}
			else
			{
				$new_width = round($this->imginfo[0] * $yratio);
				$new_height = round($this->imginfo[1] * $yratio);
			}
			if ($new_width == $this->imginfo[0] AND $new_height == $this->imginfo[1])
			{	// subtract one pixel so that requested size isn't the same as the image size
				$new_width--;
				$forceresize = false;
			}
			else
			{
				$forceresize = true;
			}

			try
			{
			    $this->upload['resized'] = $this->image->fetchThumbnail($this->upload['filename'], $this->upload['location'], $new_width, $new_height, $this->registry->options['thumbquality'], false, false, true, false);
			}
			catch (vB_Exception_Api $ex)
			{
			    if ($this->image->isValidThumbnailExtension(file_extension($this->upload['filename'])) AND $this->registry->userinfo['permissions']['adminpermissions'] & $this->registry->bf_ugp_adminpermissions['cancontrolpanel'])
			    {
				$this->set_error($ex->getMessage());
			    }
			    else
			    {
				$this->set_error('upload_file_exceeds_forum_limit', vb_number_format($this->upload['filesize'], 1, true), vb_number_format($this->maxuploadsize, 1, true));
			    }

			    return false;
			}

			$jpegconvert = true;
		}

		if (!$jpegconvert AND $this->upload['filesize'] > $this->maxuploadsize)
		{
			$this->set_error('upload_file_exceeds_forum_limit', vb_number_format($this->upload['filesize'], 1, true), vb_number_format($this->maxuploadsize, 1, true));
			return false;
		}
		else if ($jpegconvert AND $this->upload['resized']['filesize'] AND ($this->upload['resized']['filesize'] > $this->maxuploadsize OR $forceresize))
		{
			$ratio = $this->maxuploadsize / $this->upload['resized']['filesize'];

			$newwidth = $this->upload['resized']['width'] * sqrt($ratio);
			$newheight = $this->upload['resized']['height'] * sqrt($ratio);

			if ($newwidth > $this->imginfo[0])
			{
				$newwidth = $this->imginfo[0] - 1;
			}
			if ($newheight > $this->imginfo[1])
			{
				$newheight = $this->imginfo[1] - 1;
			}

			$this->upload['resized'] = $this->image->fetchThumbnail($this->upload['filename'], $this->upload['location'], $newwidth, $newheight, $this->registry->options['thumbquality'], false, false, true, false);
			if (empty($this->upload['resized']['filedata']))
			{
				if (!empty($this->upload['resized']['imageerror']) AND $this->registry->userinfo['permissions']['adminpermissions'] & $this->registry->bf_ugp_adminpermissions['cancontrolpanel'])
				{
					if (($error = $this->image->fetchError()) !== false AND $this->registry->userinfo['permissions']['adminpermissions'] & $this->registry->bf_ugp_adminpermissions['cancontrolpanel'])
					{
						$this->set_error('image_resize_failed_x', htmlspecialchars_uni($error));
						return false;
					}
					else
					{
						$this->set_error($this->upload['resized']['imageerror']);
						return false;
					}
				}
				else
				{
					$this->set_error('upload_file_exceeds_forum_limit', vb_number_format($this->upload['filesize'], 1, true), vb_number_format($this->maxuploadsize, 1, true));
					#$this->set_error('upload_exceeds_dimensions', $this->maxwidth, $this->maxheight, $this->imginfo[0], $this->imginfo[1]);
					return false;
				}
			}
			else
			{
				$jpegconvert = true;
			}
		}

		return true;
	}

	/**
	* Verifies a valid remote url for retrieval or verifies a valid uploaded file
	*
	*/
	function process_upload() {}

	/**
	* Saves a file that has been verified
	*
	*/
	function save_upload() {}

	/**
	* Public
	* Checks if supplied extension can be used
	*
	* @param	string	$extension 	Extension of file
	*
	* @return	bool
	*/
	function is_valid_extension($extension)
	{}

	/**
	* Public
	* Returns the maximum filesize for the specified extension
	*
	* @param	string	$extension 	Extension of file
	*
	* @return	integer
	*/
	function fetch_max_uploadsize($extension){}

	/**
	 * Public
	 * NCR encodes a unicode filename
	 *
	 * @return string
	 */
	function ncrencode_filename($filename)
	{
		$extension = file_extension($filename);
		$base = substr($filename, 0, (strpos($filename, $extension) - 1));
		$base = ncrencode($base, true);

		return $base . '.' . $extension;
	}
}

class vB_Upload_Userpic extends vB_Upload_Abstract
{
	function fetch_max_uploadsize($extension)
	{
		return $this->maxuploadsize;
	}

	function is_valid_extension($extension)
	{
		return !empty($this->image->info_extensions["{$this->upload['extension']}"]);
	}

	function process_upload($uploadurl = '')
	{
		if ($uploadurl == '' OR $uploadurl == 'http://www.')
		{
			$uploadstuff =& $this->registry->GPC['upload'];
		}
		else
		{
			if (is_uploaded_file($this->registry->GPC['upload']['tmp_name']))
			{
				$uploadstuff =& $this->registry->GPC['upload'];
			}
			else
			{
				$uploadstuff =& $uploadurl;
			}
		}

		if ($this->accept_upload($uploadstuff))
		{
			if ($this->imginfo = $this->image->fetchImageInfo($this->upload['location']))
			{
				if ($this->image->isValidThumbnailExtension(file_extension($this->upload['filename'])))
				{
					if (!$this->imginfo[2])
					{
						$this->set_error('upload_invalid_image');
						return false;
					}

					if ($this->image->fetchImagetypeFromExtension($this->upload['extension']) != $this->imginfo[2])
					{
						$this->set_error('upload_invalid_image_extension', $this->imginfo[2]);
						return false;
					}
				}
				else
				{
					$this->set_error('upload_invalid_image');
					return false;
				}

				if ($this->allowanimation === false AND $this->imginfo[2] == 'GIF' AND $this->imginfo['animated'])
				{
					$this->set_error('upload_invalid_animatedgif');
					return false;
				}

				if (($this->maxwidth AND $this->imginfo[0] > $this->maxwidth) OR ($this->maxheight AND $this->imginfo[1] > $this->maxheight) OR $this->image->fetchMustConvert($this->imginfo[2]))
				{
					// shrink-a-dink a big fat image or an invalid image for browser display (PSD, BMP, etc)
					$this->upload['resized'] = $this->image->fetchThumbnail($this->upload['filename'], $this->upload['location'], $this->maxwidth, $this->maxheight, $this->registry->options['thumbquality'], false, false, false, false);
					if (empty($this->upload['resized']['filedata']))
					{
						$this->set_error('upload_exceeds_dimensions', $this->maxwidth, $this->maxheight, $this->imginfo[0], $this->imginfo[1]);
						return false;
					}
					$jpegconvert = true;
				}
			}
			else
			{
				if ($this->registry->userinfo['permissions']['adminpermissions'] & $this->registry->bf_ugp_adminpermissions['cancontrolpanel'])
				{
					$this->set_error('upload_imageinfo_failed_x', htmlspecialchars_uni($this->image->fetchError()));
				}
				else
				{
					$this->set_error('upload_invalid_file');
				}
				return false;
			}

			if ($this->maxuploadsize > 0 AND (!$this->fetch_best_resize($jpegconvert)))
			{
				return false;
			}

			if (!empty($this->upload['resized']))
			{
				if (!empty($this->upload['resized']['filedata']))
				{
					$this->upload['filestuff'] =& $this->upload['resized']['filedata'];
					$this->upload['filesize'] =& $this->upload['resized']['filesize'];
					$this->imginfo[0] =& $this->upload['resized']['width'];
					$this->imginfo[1] =& $this->upload['resized']['height'];
				}
				else
				{
					$this->set_error('upload_exceeds_dimensions', $this->maxwidth, $this->maxheight, $this->imginfo[0], $this->imginfo[1]);
					return false;
				}
			}
			else if (!($this->upload['filestuff'] = @file_get_contents($this->upload['location'])))
			{
				$this->set_error('upload_file_failed');
				return false;
			}
			@unlink($this->upload['location']);

			return $this->save_upload();
		}
		else
		{
			return false;
		}
	}

	function save_upload()
	{
		$this->data->set('userid', $this->userinfo['userid']);
		$this->data->set('dateline', TIMENOW);
		$this->data->set('filename', $this->upload['filename']);
		$this->data->set('width', $this->imginfo[0]);
		$this->data->set('height', $this->imginfo[1]);
		$this->data->setr('filedata', $this->upload['filestuff']);
		$this->data->set_info('avatarrevision', $this->userinfo['avatarrevision']);
		$this->data->set_info('sigpicrevision', $this->userinfo['sigpicrevision']);
		$replace = (key_exists('sigpicurl', $this->registry->GPC) ? true : false);

		if (!($result = $this->data->save(true, false, false, $replace, false)))
		{
			if (empty($this->data->errors[0]) OR !($this->registry->userinfo['permissions']['adminpermissions'] & $this->registry->bf_ugp_adminpermissions['cancontrolpanel']))
			{
				$this->set_error('upload_file_failed');
			}
			else
			{
				$this->error =& $this->data->errors[0];
			}
		}

		unset($this->upload);

		return $result;
	}
}

class vB_Upload_Image extends vB_Upload_Abstract
{
	/**
	* Path that uploaded image is to be saved to
	*
	* @var	string
	*/
	var $path = '';

	function is_valid_extension($extension)
	{
		return !empty($this->image->info_extensions["{$this->upload['extension']}"]);
	}

	function process_upload($uploadurl = '')
	{
		if ($uploadurl == '' OR $uploadurl == 'http://www.')
		{
			$uploadstuff =& $this->registry->GPC['upload'];
		}
		else
		{
			if (is_uploaded_file($this->registry->GPC['upload']['tmp_name']))
			{
				$uploadstuff =& $this->registry->GPC['upload'];
			}
			else
			{
				$uploadstuff =& $uploadurl;
			}
		}

		if ($this->accept_upload($uploadstuff))
		{
			if ($this->image->isValidThumbnailExtension(file_extension($this->upload['filename'])))
			{
				if ($this->imginfo = $this->image->fetchImageInfo($this->upload['location']))
				{
					if (!$this->image->fetchMustConvert($this->imginfo[2]))
					{
						if (!$this->imginfo[2])
						{
							$this->set_error('upload_invalid_image');
							return false;
						}

						if ($this->image->fetchImagetypeFromExtension($this->upload['extension']) != $this->imginfo[2])
						{
							$this->set_error('upload_invalid_image_extension', $this->imginfo[2]);
							return false;
						}
					}
					else
					{
						$this->set_error('upload_invalid_image');
						return false;
					}
				}
				else
				{
					$this->set_error('upload_imageinfo_failed_x', htmlspecialchars_uni($this->image->fetchError()));
					return false;
				}
			}
			else
			{
				$this->set_error('upload_invalid_image');
				return false;
			}

			if (!$this->upload['filestuff'])
			{
				if (!($this->upload['filestuff'] = file_get_contents($this->upload['location'])))
				{
					$this->set_error('upload_file_failed');
					return false;
				}
			}
			@unlink($this->upload['location']);

			return $this->save_upload();
		}
		else
		{
			return false;
		}
	}

	function save_upload()
	{
		if (!is_writable($this->path) OR !($fp = fopen($this->path . '/' . $this->upload['filename'], 'wb')))
		{
			$this->set_error('cannot_write_to_x_path', $this->path);
			return false;
		}

		if (@fwrite($fp, $this->upload['filestuff']) === false)
		{
			$this->set_error('error_writing_x', $this->upload['filename']);
			return false;
		}

		@fclose($fp);
		return $this->path . '/' . $this->upload['filename'];
	}
}


/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 102888 $
|| #######################################################################
\*=========================================================================*/
