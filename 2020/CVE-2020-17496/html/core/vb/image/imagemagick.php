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
* Image class for ImageMagick
*
* @package 		vBulletin
* @version		$Revision: 103329 $
* @date 		$Date: 2019-10-31 10:00:48 -0700 (Thu, 31 Oct 2019) $
*
*/
class vB_Image_ImageMagick extends vB_Image
{

	/**
	* @private	string
	*/
	private $convertpath = '/usr/local/bin/convert';

	/**
	* @private	string
	*/
	private $identifypath = '/usr/local/bin/identify';

	/**
	* @var	integer
	*/
	var $returnvalue = 0;

	/**
	* @private  string
	*/
	private $identifyformat = '';

	/**
	 * Version of Imagemagick /convert
	 * @private	string
	 */
	private $version = null;

	/**
	* @private	string
	*/
	private $convertoptions = array(
		'width' => '100',
		'height' => '100',
		'quality' => '75',
	);

	/**
	* @private  string
	*
	*/
	private $error = '';

	/**
	* @private string
	*
	 */
	//this used to be overridden by an admin option.  It's still technically used in this
	//class for the border and labels of thumbnails, but we never actually call the
	//function with the border and labels options true.  For now leave hardcoded
	//in case we do use those.  If we need to make the color an option again all we need
	//to do is override this in the constructor.
	private $thumbcolor = 'black';

	/**
	* @private	array
	*/
	private $thumb_types = array();

	/**
	* Constructor
	* Sets ImageMagick paths to convert and identify
	*
	* @return	void
	*/
	public function __construct($options, $extras = array())
	{
		parent::__construct($options, $extras);
		$path = preg_replace('#[/\\\]+$#', '', $this->options['magickpath']);

		if (preg_match('#^WIN#i', PHP_OS))
		{
			$this->identifypath = $path . '\identify.exe';
			$this->convertpath = $path . '\convert.exe';
		}
		else
		{
			$this->identifypath = $path .  "/identify";
			$this->convertpath = $path . "/convert";
		}
		// wrap in quotes to make it a "single safe" argument (& handle things like
		// spaces in file paths)
		// Using escapeshellarg instead of our own quoting since the latter allows for
		// quotes & multiple commands in the path option itself.
		$this->identifypath = escapeshellarg($this->identifypath);
		$this->convertpath = escapeshellarg($this->convertpath);

		/*
			Thumbnails of these types will always be converted to a JPG
		 */
		$this->must_convert_types = array(
			'PSD'  => true,
			'BMP'  => true,
			'TIFF' => true,
			'PDF'  => true,
		);
		/*
			These types are allowed to be resized into thumbnails.
		 */
		$this->resize_types = array(
			'GIF'   => true,
			'JPEG'  => true,
			'PNG'   => true,
			'BMP'   => true,
			'TIFF'  => true
		);

		/*
			These can have thumbnails.
		 */
		$this->thumb_extensions = array(
			'gif'  => true,
			'jpg'  => true,
			'jpe'  => true,
			'jpeg' => true,
			'png'  => true,
			'psd'  => true,
			'pdf'  => true,
			'bmp'  => true,
			'tiff' => true,
			'tif'  => true,
		);
		// check ghostscript install, disable pdf thumb.
		if (empty($this->options['imagick_pdf_thumbnail']))
		{
			$this->disablePDFThumbnail();
		}
		$this->info_extensions =& $this->thumb_extensions;

		$this->thumb_types = array();
		foreach ($this->thumb_extensions AS $extension => $yes)
		{
			if ($yes)
			{
				$type = $this->fetchImagetypeFromExtension($extension);
				$this->thumb_types[$type] = true;
			}
		}

		// PDF. imagemagick only.
		$soi = hex2bin("2550" . "4446");
		$this->magic_numbers[$soi] = array('eoi' => '', 'type' => "PDF", 'extension' => 'pdf'); // thumb will be jpg. What should we store as the "extension"?
		$two = substr($soi, 0, 2);
		$this->magic_numbers_shortcut[$two][$soi] = $this->magic_numbers[$soi];
		$this->magic_numbers_types["PDF"] = true;
	}

	/**
	*
	* Generic call to imagemagick binaries
	*
	* @param	string	command         ImageMagick binary to execute
	* @param	string	optionsString    Option string to pass along to the binary. Do not
	*                                   directly feed arguments in here.
	* @param	Array	args            Arguments to replace placeholders in optionString
	*
	* @return	mixed
	*
	*/
	protected function fetchImExec($command, $optionsString, $args = array(), $needoutput = false, $dieongs = true)
	{
		/*
			If you call this on a file or string, make sure that the file or string is a white-listed file type!!!
			MVGs disguising as other types for ex can slip past and trigger RCE.

			Also, make sure that each individual argument that goes into the $args string is escaped! Particuarly
			filenames!
		 */

		if (!function_exists('exec'))
		{
			throw new vB_Exception_Api('php_error_exec_disabled');
		}

		$imcommands = array(
			'identify' => $this->identifypath,
			'convert'  => $this->convertpath,
		);

		if (!isset($imcommands["$command"]))
		{
			return false;
		}

		// Note, without setlocale(), escapeshellarg apparently can strip non-ASCII characters.
		// Not sure if we want to support non-ASCII filenames/options at the moment.
		$escapedArgs = array();
		foreach ($args AS $unsafe)
		{
			$escapedArgs[] = escapeshellarg($unsafe);
		}

		$optionsString = vsprintf($optionsString, $escapedArgs);


		$input = $imcommands["$command"] . ' ' . $optionsString . ' 2>&1';
		$exec = @exec($input, $output, $this->returnvalue);

		if ($this->returnvalue OR $exec === null)
		{	// error was encountered
			if (!empty($output))
			{	// command issued by @exec failed
				$outputText = strtolower(implode(' ', $output));
				if (
					strpos($outputText, 'postscript delegate failed') !== false OR
					strpos($outputText, 'pdfdelegatefailed') !== false	// IM 6.9.8
				)
				{
					throw new vB_Exception_Api('install_ghostscript_to_resize_pdf');
				}
				else if (strpos($outputText, 'image smaller than radius') !== false)
				{
					throw new vB_Exception_Api('im_error_bad_sharpen_x', array($outputText));
				}

				throw new vB_Exception_Api('im_exec_error_x', array($outputText));
			}
			else if (!empty($php_errormsg))
			{	// @exec failed so display error and remove path reveal
				throw new vB_Exception_Api('php_error_x', array(str_replace($this->options['magickpath'] . '\\', '', $php_errormsg)));
			}
			else if ($this->returnvalue == -1)
			{	// @exec failed but we don't have $php_errormsg to tell us why
				throw new vB_Exception_Api('php_error_unspecified_exec');
			}
			return false;
		}
		else
		{
			if (!empty($output))
			{	// $output is an array of returned text
				// This is for IM which doesn't return false for failed font
				$outputText = strtolower(implode(' ', $output));
				if (strpos($outputText, 'unable to read font') !== false)
				{
					throw new vB_Exception_Api('im_error_cannot_read_font_x', array($outputText));
				}

				if (
					strpos($outputText, 'postscript delegate failed') !== false OR
					strpos($outputText, 'pdfdelegatefailed') !== false	// IM 6.9.8
				)
				{	// this is for IM 6.2.4+ which doesn't return false for exec(convert.exe) on .pdf when GS isn't installed
					throw new vB_Exception_Api('install_ghostscript_to_resize_pdf');
				}

				if (strpos($outputText, 'image smaller than radius') !== false)
				{
					throw new vB_Exception_Api('im_error_bad_sharpen_x', array($outputText));
				}

				return $output;
			}
			else if (empty($output) AND $needoutput)
			{	// $output is empty and we expected something back
				return false;
			}
			else
			{	// $output is empty and we didn't expect anything back
				return true;
			}
		}
	}

	private function disablePDFThumbnail()
	{
		if (isset($this->thumb_extensions["pdf"]))
		{
			$this->thumb_extensions["pdf"] = false;
		}
		if (isset($this->info_extensions["pdf"]))
		{
			// if thumbnailing is disabled, it's probably because
			// we don't have ghostscript pdf delegate available,
			// in which case just trying to get image info (identify)
			// on it wil also fail.
			$this->info_extensions["pdf"] = false;
		}
	}

	public function canThumbnailPdf()
	{
		/*
			Ghostscript is required for PDF to JPEG conversion for creating thumbnails.
			If ghostscript is not installed, or isn't configured correctly, we should
			treat PDF as non-thumbnailable as to avoid errors.
			TODO: check for this @ upgrade at add adminCP error message?

			If ghostscript is installed but this function fails, it could be that either the
			checks below aren't sophisticated enough to handle the particular case,
			or imagemagick's delegate XML wasn't setup properly to point to the
			executable path of ghostscript
		 */
		$isWindows = (strtoupper(substr(PHP_OS, 0, 3)) == 'WIN');
		if ($isWindows)
		{
			try
			{
				$result = $this->fetchImExec(
					'convert',
					'-list delegate  |findstr /i "pdf" ',
					array(),
					true
				);
			}
			catch(Exception $e)
			{
				$result = false;
			}
		}
		else
		{
			try
			{
				$result = $this->fetchImExec(
					'convert',
					'-list delegate  |grep -i "pdf" ',
					array(),
					true
				);
			}
			catch(Exception $e)
			{
				$result = false;
			}
		}

		if (empty($result) OR !is_array($result))
		{
			// we can't do much if we didn't find something we can grep. Assume we cannot convert PDFs.

			return false;
		}

		foreach ($result AS $__line)
		{
			preg_match('#pdf<=>ps\s+"(?<gspath>[^"]*gs[^"]*)"#', $__line, $matches);
			if (!empty($matches["gspath"]))
			{
				break;
			}
		}


		// if we didn't find what we were looking for above, abort.
		if (empty($matches["gspath"]))
		{
			return false;
		}

		$command = escapeshellarg($matches["gspath"]) . ' -v  2>&1';
		$exec = @exec($command, $output, $returnValue);
		if (!empty($returnValue) OR stripos(implode(" ", $output), "ghostscript") === false)
		{
			return false;
		}

		// if we got here, then at least 1 delegate points to proper ghostscript executable.
		// At this point, it's uncertain if a more complex check is needed.
		return true;
	}

	/**
	*
	* Fetch Imagemagick Version
	*
	* @return	mixed
	*
	*/
	protected function fetchVersion()
	{
		if (is_null($this->version))
		{
			$result = $this->fetchImExec('convert', '-version', array(), true);
			if ($result AND preg_match('#ImageMagick (\d+\.\d+\.\d+)#', $result[0], $matches))
			{
				$this->version = $matches[1];
			}
			else
			{
				$this->version = false;
			}
		}

		return $this->version;
	}

	/**
	*
	* Identify an image
	*
	* @param	string	$filename File to obtain image information from
	*
	* @return	mixed
	*
	*/
	protected function fetchIdentifyInfo($filename)
	{
		/*
			Prevent un-whitelisted files from being sent into imagick. Imagetragick mitigation.
			The only caller ATM already does this, but better to be safe in case something else calls this in the future.
			This file may NOT be an image (e.g. PDF) but is explicitly white listed for us.
		 */
		$magictype = $this->magicWhiteList(file_get_contents($filename));
		//$isImage = $this->fileLocationIsImage($filename);
		if (!$magictype)
		{
			throw new vB_Exception_Api('invalid_file_content');
		}

		$fp = @fopen($filename, 'rb');
		$frame0 = "";
		if (($header = @fread($fp, 4)) == '%PDF')
		{	// this is a PDF so only look at frame 0 to save mucho processing time
			$frame0 = '[0]';
		}
		@fclose($fp);

		$execute = "";
		$args = array();
		if (!empty($this->identifyformat))
		{
			// On windows, escapeshellarg() removes % characters, so we cannot pass it in via $args
			// I'm not exactly keen on blindly passing it through either, even though it shouldn't be easy to
			// set the private property.
			// In reality we only have 1 hard-coded format, so let's just hard-code it here for windows.
			$isWindows = (strtoupper(substr(PHP_OS, 0, 3)) == 'WIN');
			if ($isWindows)
			{
				// double quotes for escaping on windows. %% escapes so vsprintf() doesn't try to replace them.
				$execute .= "-format \"%%g###%%w###%%h###%%m###%%n###%%r###%%z###\"";
			}
			else
			{
				$execute .= "-format %s";
				$args[] = $this->identifyformat;
			}
		}

		// filename
		// $frame0, or '[0]', is the Read Frames modifier (needs to be next to the filename)
		// http://www.imagemagick.org/Usage/files/#read_mods
		$execute .= " %s";
		$args[] = $filename . $frame0;

		if ($result = $this->fetchImExec('identify', $execute, $args, true))
		{
			if (empty($result) OR !is_array($result))
			{
				return false;
			}

			do
			{
				$last = array_pop($result);
			}
			while (!empty($result) AND $last == '');

			$temp = explode('###', $last);

			if (count($temp) < 6)
			{
				return false;
			}

			preg_match('#^(\d+)x(\d+)#', $temp[0], $matches);

			$imageinfo = array(
				2         => $temp[3],
				'bits'    => $temp[6],
				'scenes'  => $temp[4],
				'animated' => ($temp[4] > 1),
				'library' => 'IM',
			);

			if (version_compare($this->fetchVersion(), '6.2.6', '>='))
			{
				$imageinfo[0] = $matches[1];
				$imageinfo[1] = $matches[2];
			}
			else	//IM v6.2.5 and lower don't support -laters optimize
			{
				$imageinfo[0] = $temp[1];
				$imageinfo[1] = $temp[2];
			}

			switch($temp[5])
			{
				case 'PseudoClassGray':
				case 'PseudoClassGrayMatte':
				case 'PseudoClassRGB':
				case 'PseudoClassRGBMatte':
					$imageinfo['channels'] = 1;
					break;
				case 'DirectClassRGB':
					$imageinfo['channels'] = 3;
					break;
				case 'DirectClassCMYK':
					$imageinfo['channels'] = 4;
					break;
				default:
					$imageinfo['channels'] = 1;
			}

			return $imageinfo;
		}
		else
		{
			return false;
		}
	}

	/**
	* Private
	* Set image size for convert
	*
	* @param	width	Width of new image
	* @param	height	Height of new image
	* @param	quality Quality of Jpeg images
	* @param bool		Include image dimensions and filesize on thumbnail
	* @param bool		Draw border around thumbnail
	*
	* @return	void
	*
	*/
	protected function setConvertOptions(
		$width = 100,
		$height = 100,
		$quality = 75,
		$labelimage = false,
		$drawborder = false,
		$jpegconvert = false,
		$owidth = null,
		$oheight = null,
		$ofilesize = null,
		$do_orient = false,
		$do_strip = false
	)
	{
		$this->convertoptions['width'] = (int) $width;
		$this->convertoptions['height'] = (int) $height;
		// I don't believe the -quality option supports float precision,
		// but documentation is unclear.
		// https://imagemagick.org/script/command-line-options.php#quality
		$this->convertoptions['quality'] = (int) $quality;
		$this->convertoptions['labelimage'] = (bool) $labelimage;
		$this->convertoptions['drawborder'] = (bool) $drawborder;
		$this->convertoptions['jpegconvert'] = (bool) $jpegconvert;
		// These can be "null", but the way they're used, null casting to 0 works.
		$this->convertoptions['owidth'] = (int) $owidth;
		$this->convertoptions['oheight'] = (int) $oheight;
		$this->convertoptions['ofilesize'] = (int) $ofilesize;
		$this->convertoptions['do_orient'] = (bool) $do_orient;
		$this->convertoptions['do_strip'] = (bool) $do_strip;
	}

	/*
	// ended up not using this, but keeping it around for now.
	private function setSingleConvertOption($keyedArray)
	{
		$defaults = array(
			'width' => 100,
			'height' => 100,
			'quality' => 75,
			'labelimage' => false,
			'drawborder' => false,
			'jpegconvert' => false,
			'owidth' => null,
			'oheight' => null,
			'ofilesize' => null,
			'do_orient' => false,
			'do_strip' => false,
		);
		$options = array();
		foreach ($defaults AS $key => $__default)
		{
			if (!isset($this->convertoptions[$key]))
			{
				$options[$key] = $__default;
			}
			else
			{
				$options[$key] = $this->convertoptions[$key];
			}
		}

		foreach ($keyedArray AS $key => $__value)
		{
			if (isset($options[$key]))
			{
				$options = $__value;
			}
		}

		return call_user_func_array(array($this, "setConvertOptions"), $options);
	}
	*/

	/**
	*
	* Convert an image
	*
	* @param	string    $filename     Image file to convert
	* @param	string    $output       Filename to write converted image to
	* @param	array     $imageinfo    Array of information about the image, typically the result of fetchImageInfo($filename)
	* @param	boolean   $thumbnail    Generate a thumbnail for display in a browser
	* @param	boolean   $sharpen      Sharpen the output
	*
	* @return	mixed
	*
	*/
	protected function fetchConvertedImage($filename, $output, $imageinfo, $thumbnail = true, $sharpen = true)
	{
		/*
			Prevent un-whitelisted files from being sent into imagick. Imagetragick mitigation.
			The only caller ATM already does this, but better to be safe in case something else calls this in the future.
			This file may NOT be an image (e.g. PDF) but is explicitly white listed for us.
		 */
		$magictype = $this->magicWhiteList(file_get_contents($filename));
		if (!$magictype)
		{
			throw new vB_Exception_Api('invalid_file_content');
		}


		if ($thumbnail)
		{

			// Only specify scene 1 if this is a PSD or a PDF -- allows animated gifs to be resized..
			if ($imageinfo[2] === "PDF" OR $imageinfo[2] === "PSD")
			{
				// Read Frames modifier (needs to be next to the filename)
				// http://www.imagemagick.org/Usage/files/#read_mods
				// If converting PDFs and this is missing, imagemagick will output multiple files, one converted image file for each page.
				$filename .= '[0]';
			}
		}

		$execute = " %s";
		$args = array(
			$filename,
		);

		if ($imageinfo['scenes'] > 1 AND version_compare($this->fetchVersion(), '6.2.6', '>='))
		{
			$execute .= ' -coalesce ';
		}

		if ($this->convertoptions['width'] > 0 OR $this->convertoptions['height'] > 0)
		{
			if ($this->convertoptions['width'])
			{
				$size = $this->convertoptions['width'];
				// We can remove this & just convert the else if below to an if, but
				// I am not going to unnecessarily refactor for the current hardening work.
				if ($this->convertoptions['height'])
				{
					$size .= 'x' . $this->convertoptions['height'];
				}
			}
			else if ($this->convertoptions['height'])
			{
				// This is possibly incorrect. http://www.imagemagick.org/script/command-line-options.php?#size
				// shows xheight is optional, but does not specify whether or not width is optional.
				// Since this code is the same since vB4, I'm leaving it here.
				$size .= 'x' . $this->convertoptions['height'];
			}
			$execute .= " -size %s ";
			$args[] = $size;
		}

		if ($thumbnail)
		{
			if ($size)
			{
				// -thumbnail will strip everything otehr than the color profile. As such if we need to preserve EXIF data
				// we need to use -resize.
				if ($this->preserveExif)
				{
					$execute .= " -resize %s ";
					$args[] = $size;
				}
				else
				{
					// have to use -thumbnail here .. -sample looks BAD for animated gifs
					$execute .= " -thumbnail %s ";
					$args[] = $size;
				}
			}
		}
		$execute .= ($sharpen AND $imageinfo[2] == 'JPEG') ? " -sharpen 0x1 " : '';

		if ($imageinfo['scenes'] > 1 AND version_compare($this->fetchVersion(), '6.2.6', '>='))
		{
			$execute .= ' -layers optimize ';
		}

		// ### Convert a CMYK jpg to RGB since IE/Firefox will not display CMYK inline .. conversion is ugly since we don't specify profiles
		if ($this->imageinfo['channels'] == 4 AND $thumbnail)
		{
			$execute .= ' -colorspace RGB ';
		}

		if (!empty($this->convertoptions['do_orient']))
		{
			// Sidenote, it *should* be safe to do auto-orient multiple times in sequential converts,
			// because their docs state that this command "reads and resets the EXIF image profile setting 'Orientation'"
			// http://www.imagemagick.org/script/command-line-options.php#auto-orient
			$execute .= " -auto-orient ";
		}

		if (!empty($this->convertoptions['do_strip']))
		{
			// http://www.imagemagick.org/script/command-line-options.php#strip
			// If we want to preserve the color profile, we'll need to output that into a separate file,
			// and convert using that profile:
			// http://www.imagemagick.org/script/command-line-options.php#profile
			// http://stackoverflow.com/a/17516878   (See the commandline part of the answer)
			// todo: -strip & ICC profile preservation...
			$execute .= " -strip ";
		}

		if ($thumbnail)
		{
			$xratio = ($this->convertoptions['width'] == 0 OR $imageinfo[0] <= $this->convertoptions['width']) ? 1 : $imageinfo[0] / $this->convertoptions['width'];
			$yratio = ($this->convertoptions['height'] == 0 OR $imageinfo[1] <= $this->convertoptions['height']) ? 1 : $imageinfo[1] / $this->convertoptions['height'];

			if ($xratio > $yratio)
			{
				$new_width = round($imageinfo[0] / $xratio) - 1;
				$new_height = round($imageinfo[1] / $xratio) - 1;
			}
			else
			{
				$new_width = round($imageinfo[0] / $yratio) - 1;
				$new_height = round($imageinfo[1] / $yratio) - 1;
			}

#			if ($imageinfo[0] <= $this->convertoptions['width'] AND $imageinfo[1] <= $this->convertoptions['height'])
#			{
#				$this->convertoptions['labelimage'] = false;
#				$this->convertoptions['drawborder'] = false;
#			}

			if ($this->convertoptions['labelimage'])
			{
				if ($this->convertoptions['owidth'])
				{
					$dimensions = "{$this->convertoptions['owidth']}x{$this->convertoptions['oheight']}";
				}
				else
				{
					$dimensions = "$imageinfo[0]x$imageinfo[1]";
				}
				if ($this->convertoptions['ofilesize'])
				{
					$filesize = $this->convertoptions['ofilesize'];
				}
				else
				{
					$filesize = @filesize($filename);
				}
				if ($filesize / 1024 < 1)
				{
					$filesize = 1024;
				}
				$sizestring = (!empty($filesize)) ? vb_number_format($filesize, 0, true) : '';

				if (!$this->convertoptions['jpegconvert'] OR $imageinfo[2] == 'PSD' OR $imageinfo[2] == 'PDF')
				{
					$type = $imageinfo[2];
				}
				else
				{
					$type = 'JPEG';
				}

				// I absolutely do not understand any of the below. I am but a passenger in this voyage of madness.
				if (($new_width / strlen("$dimensions $sizestring $type")) >= 6)
				{
					$finalstring = "$dimensions $sizestring $type";
				}
				else if  (($new_width / strlen("$dimensions $sizestring")) >= 6)
				{
					$finalstring = "$dimensions $sizestring";
				}
				else if (($new_width / strlen($dimensions)) >= 6)
				{
					$finalstring = $dimensions;
				}
				else if (($new_width / strlen($sizestring)) >= 6)
				{
					$finalstring = $sizestring;
				}

				if ($finalstring)
				{	// confusing -flip statements added to workaround an issue with very wide yet short images. See http://www.imagemagick.org/discourse-server/viewtopic.php?t=10367
					$execute .= " -flip -background %s";
					$args[] = $this->thumbcolor;
					$execute .= " -splice 0x15 -flip -gravity South -fill white  -pointsize 11 -annotate 0 %s ";
					$args[] = $finalstring;
				}
			}

			if ($this->convertoptions['drawborder'])
			{
				$execute .= " -bordercolor %s -compose Copy -border 1 ";
				$args[] = $this->thumbcolor;
			}

			if (($imageinfo[2] == 'PNG' OR $imageinfo[2] == 'PSD') AND !$this->convertoptions['jpegconvert'])
			{
				$execute .= " -depth 8 -quality %s PNG:";
				$args[] = $this->convertoptions['quality'];
			}
			else if ($this->fetchMustConvert($imageinfo[2]) OR $imageinfo[2] == 'JPEG' OR $this->convertoptions['jpegconvert'])
			{
				$execute .= " -quality %s JPEG:";
				$args[] = $this->convertoptions['quality'];
			}
			else if ($imageinfo[2] == 'GIF')
			{
				$execute .= " -depth %s ";
				$args[] = $imageinfo['bits'];
			}
		}

		/*
			Note, the "type" prefix (PNG:{filename}, JPEG:{filename}) must come last in the command string
			right before the output filename. As such, if you add any subsequent options here, make sure that
			you add some kind of handling for the $thumbnail convertoptions bit above. Otherwise, the command
			will just "hang" forever due to the command still waiting for further input.
		 */

		$execute .= "%s";
		$args[] = $output;

		try
		{
			$zak = $this->fetchImExec('convert', $execute, $args);
		}
		catch (vB_Exception_Api $ex)
		{
			$errorMsg = strtolower($ex->getMessage());
			if ($sharpen AND (strpos($errorMsg, 'im_error_bad_sharpen_x') !== false))
			{
				// try to resize again, but without sharpen
				$zak = $this->fetchConvertedImage($filename, $output, $imageinfo, $thumbnail, false);
			}
			else
			{
				throw $ex;
			}
		}

		return $zak;
	}

	protected function forceRewriteImage($fileContents, $location)
	{
		/*
			By the time we get here, the caller should've verified that this is an image according to fileheaders/mimetype.
			We haven't checked EXIF yet, but we don't care because we're going to ignore & drop most of them (we'll use the orientation
			but drop it afterwards), and AFAIK neither GD nor ImageMagick has vulnerabilities involving exploitable EXIF data.
			If they did then god help us, because we're not gonna try to drop the exif with ANOTHER tool before passing the file into the
			underlying GD/Imagemagick calls.

			After we're done with this function, EXIF should be wiped clean, and we have written the wiped file. The Image class will then
			only deal with this "cleaned" file, and not the original file. If the "cleaned" file fails any security checks that come after this,
			then we've done all we can do and we cannot allow the original OR the internal image to remain on the server.

			AFAIK, Imagetragick vulnerability isn't triggered by EXIF or other meta data, only the "advanced" commands that certain image types can have.
			That is blocked by the magicwhitelist() check the caller performed - we check that the "certain image types" isn't masquerading as one of the
			simple image type that we believe are safe (jpeg, png, gif etc). So we should be safe to pass the file into identify or convert regardless of
			what other nasties might be hiding in the file footer or meta.
		 */

		/*
			Use of rand() instead of crypto-safe random_int() is intentional.
			This rand() is meant STRICTLY for md5 collision-avoidance, NOT cryptography, in the case
			when 2 guests upload an image at the same microtime(). So it makes sense to use a quick
			random source.
			We could alternatively pass in like	sessionhash or something, but this is probably simpler,
			faster & enough to dodge filename collisions from getTmpFileName().
			Unless you're unlucky to a divine level.
		 */
		$newfile = vB_Utilities::getTmpFileName(rand(), 'vB_');
		if (empty($newfile))
		{
			// something happened (like we can't access the tempdir) and we can't get a write location.
			return "";
		}

		/*
			We could potentially do the resize before we printImage()
			However that'd require significant refactor on the attach LIB end to pass in all the size information.
			Since for non-vector images, the resize itself is lossy, I think that the compression loss due to
			writing here as fullsize, then re-writing later as "largest allowed" (not thumbnail) from attachLib->resizeImage()
			is negligible.
			If it becomes a problem though, we should just OPEN the image resource handle, do all the transformations including
			rotate & resize, then write only at the very end and return that below.
		 */


		$width = 0;
		$height = 0;
		$quality = 100;
		$labelimage = false;
		$drawborder = false;
		$jpegconvert = false;
		$owidth = null;
		$oheight = null;
		$ofilesize = null;
		$do_orient = true;	// orient
		$do_strip = true;	// strip exif
		if ($this->preserveExif)
		{
			$do_strip = false;
		}

		$this->setConvertOptions(
			$width,
			$height,
			$quality,
			$labelimage,
			$drawborder,
			$jpegconvert,
			$owidth,
			$oheight,
			$ofilesize,
			$do_orient,
			$do_strip
		);

		/*
			It might be preferred by some uesrs if we could go through each exif tag and individually strip
			"problematic" ones, but AFAIK there's only a way to fully strip meta data /entire exif profile, but not
			individual exif tags.
		 */
		//http://stackoverflow.com/questions/13646028/how-to-remove-exif-from-a-jpg-without-losing-image-quality



		$imageinfo = $this->getUnsafeImageInfo($fileContents, $location);

		$write = $this->fetchConvertedImage($location, $newfile, $imageinfo, false, false);
		if (!$write)
		{
			return "";
		}

		return $newfile;
	}

	/**
	*
	* See function definition in vB_Image
	*
	*/
	public function fetchImageInfo($filename)
	{
		// verifyImageFile() will call magicWhiteList to check file signature.
		// Without that check, the followup identify may be susceptible to imagetragick exploits
		$fileContents = @file_get_contents($filename);

		if (!$this->verifyImageFile($fileContents, $filename))
		{
			throw new vB_Exception_Api('invalid_file_content');
		}

		return $this->getUnsafeImageInfo($fileContents, $filename);
	}


	/*
		Only time we want to use this without verifyImageFile() is right before we *write* out the image file in an
		attempt to kill off any bad exif or 'non-image-y' data to sanitize the image.
	 */
	private function getUnsafeImageInfo($fileContents, $filename)
	{
		/*
			Everything calling this should've already gone through the whitelist, as to avoid allowing SVG's and other uknown filetypes that might
			trigger imagetragick vuln from hitting `identify`.

			For ex. fetchImageInfo() calls verifyImageFile() which does that, and forceRewriteImage() should only be called by the time the file has
			passed the whitelist.

			This is just an overabundance of caution and paranoia.

			Check that the file type is whitelisted, and seems to be what it claims to be
		 */


		// imagetragick filetype whitelist check.
		if (!$this->magicWhiteList($fileContents))
		{
			throw new vB_Exception_Api('upload_invalid_image');
		}

		$this->identifyformat = '%g###%w###%h###%m###%n###%r###%z###';
		$this->imageinfo = $this->fetchIdentifyInfo($filename);
		return $this->imageinfo;
	}


	public function fetchImageInfoForThumbnails($filename)
	{
		if ($this->fileLocationIsImage($filename))
		{
			return $this->fetchImageInfo($filename);
		}

		/*
			If we got here, then either there are nasties in the headers/exif, or it's a PDF or some other
			"not an image but can be passed into identify and be eventually converted into an image" file
			that we must explicitly whitelist.
		 */
		$fileContents = @file_get_contents($filename);
		$safe = $this->verifyFileHeadersAndExif($fileContents, $filename);
		if (!$safe)
		{
			throw new vB_Exception_Api('invalid_file_content');
		}

		$magictype = $this->magicWhiteList($fileContents);

		if (!$magictype)
		{
			throw new vB_Exception_Api('invalid_file_content');
		}

		if (!isset($this->thumb_types[$magictype]))
		{
			throw new vB_Exception_Api('invalid_file_content');
		}

		/*
			SECURITY WARNING
			Note, at this point we're explicitly allowing a NON-IMAGE file to be passed into identify right here.
			We whitelisted the files, so we *should* be safe. Assuming that the current whitelist is safe.
		 */

		$this->identifyformat = '%g###%w###%h###%m###%n###%r###%z###';
		$this->imageinfo = $this->fetchIdentifyInfo($filename);
		return $this->imageinfo;
	}

	/**
	*
	* See function definition in vB_Image
	*
	*/
	public function fetchThumbnail(
		$filename,
		$location,
		$maxwidth = 100,
		$maxheight = 100,
		$quality = 75,
		$labelimage = false,
		$drawborder = false,
		$jpegconvert = false,
		$sharpen = true,
		$owidth = null,
		$oheight = null,
		$ofilesize = null
	)
	{
		// we check the whitelist before we call convert @ fetchConvertedImage()

		$thumbnail = array(
			'filedata'   => '',
			'filesize'   => 0,
			'dateline'   => 0,
			'imageerror' => '',
		);

		if ($this->isValidThumbnailExtension(file_extension($filename)))
		{
			// This file might not be an image yet, allow passthrough to identify but do not
			// check that it's image. This is specifically to allow PDFs to work.
			if ($imageinfo = $this->fetchImageInfoForThumbnails($location))
			{
				$thumbnail['source_width'] = $imageinfo[0];
				$thumbnail['source_height'] = $imageinfo[1];
				if ($this->fetchImagetypeFromExtension(file_extension($filename)) != $imageinfo[2])
				{
					throw new vB_Exception_Api('thumbnail_notcorrectimage');
				}
				else if ($imageinfo[0] > $maxwidth OR $imageinfo[1] > $maxheight OR $this->fetchMustConvert($imageinfo[2]))
				{
					$tmpname = vB_Utilities::getTmpFileName('', 'vbimagick');
					if (!$tmpname)
					{
						throw new vB_Exception_Api('thumbnail_nogetimagesize');
					}

					// Previously we were not stripping meta data off of thumbnails.
					// Added -strip & -auto-orient flags to keep it consistent with imagick.
					$do_orient = true;
					$do_strip = true;
					if ($this->preserveExif)
					{
						$do_strip = false;
					}
					$this->setConvertOptions(
						$maxwidth,
						$maxheight,
						$quality,
						$labelimage,
						$drawborder,
						$jpegconvert,
						$owidth,
						$oheight,
						$ofilesize,
						$do_orient,
						$do_strip
					);

					if ($result = $this->fetchConvertedImage($location, $tmpname, $imageinfo, true, $sharpen))
					{
						if ($imageinfo = $this->fetchImageInfo($tmpname))
						{
							$thumbnail['width'] = $imageinfo[0];
							$thumbnail['height'] = $imageinfo[1];
						}
						$extension = strtolower(file_extension($filename));
						if ($jpegconvert)
						{
							$thumbnail['filename'] = preg_replace('#' . preg_quote(file_extension($filename), '#') . '$#', 'jpg', $filename);
						}
						$thumbnail['filesize'] = filesize($tmpname);
						$thumbnail['dateline'] = vB::getRequest()->getTimeNow();
						$thumbnail['filedata'] = file_get_contents($tmpname);
					}
					else
					{
						throw new vB_Exception_Api('thumbnail_nogetimagesize');
					}
					@unlink($tmpname);
				}
				else
				{
					// image is a thumbnail size already
					if ($imageinfo[0] > 0 AND $imageinfo[1] > 0)
					{
						$thumbnail['filedata'] = @file_get_contents($location);
						$thumbnail['width'] = $imageinfo[0];
						$thumbnail['height'] = $imageinfo[1];
					}
					else
					{
						throw new vB_Exception_Api('thumbnail_nogetimagesize');
					}
				}
			}
			else
			{
				throw new vB_Exception_Api('thumbnail_nogetimagesize');
			}
		}
		else
		{
			throw new vB_Exception_Api('thumbnail_nosupport');
		}

		if (!empty($thumbnail['filedata']))
		{
			$thumbnail['filesize'] = strlen($thumbnail['filedata']);
			$thumbnail['dateline'] = vB::getRequest()->getTimeNow();
		}
		return $thumbnail;
	}

	public function cropImg($imgInfo, $maxwidth = 100, $maxheight = 100, $forceResize = false)
	{
		$thumbnail = array(
			'filedata'   => '',
			'filesize'   => 0,
			'dateline'   => 0,
			'imageerror' => '',
		);

		$execute = '';
		$filename = $imgInfo['filename'];
		$fh = fopen($filename, 'w');
		fwrite($fh, $imgInfo['filedata']);
		fclose($fh);

		if ($this->isValidThumbnailExtension($imgInfo['extension']))
		{
			$thumbnail['source_width'] = $width  = $imgInfo['width'];
			$thumbnail['source_height'] = $height = $imgInfo['height'];

			if ($forceResize OR $imgInfo['width'] >= $maxwidth OR $imgInfo['height'] >= $maxheight )
			{
				$xratio = ($maxwidth == 0) ? 1 : $width / $maxwidth;
				$yratio = ($maxheight == 0) ? 1 : $height / $maxheight;
				if ($xratio > $yratio)
				{
					$new_width = round($width / $xratio);
					$new_height = round($height / $xratio);
				}
				else
				{
					$new_width = round($width / $yratio);
					$new_height = round($height / $yratio);
				}

				// We could also use vB_Utilities::getTmpFileName() here.
				$tempdir = vB_Utilities::getTmpDir();
				$time = time();
				$tmpFileNew = $tempdir . DIRECTORY_SEPARATOR . $time . '-0.' . $imgInfo['extension'];

				$geometry1 = intval($width) . "x" . intval($height);
				$geometry2 = $new_width . "x" . $new_height;
				$offset = floatval($imgInfo['x1']) . "+" . floatval($imgInfo['y1']);

				$execute = $this->convertpath . " %s -crop %s +repage -resize %s %s  2>&1";
				$args = array(
					$filename,
					$geometry1 . "+" . $offset,
					$geometry2,
					$tmpFileNew,
				);

				$escapedArgs = array();
				foreach ($args AS $unsafe)
				{
					$escapedArgs[] = escapeshellarg($unsafe);
				}
				$execute = vsprintf($execute, $escapedArgs);
				exec($execute);

				if (file_exists($tmpFileNew))
				{
					if ($imageinfo = $this->fetchImageInfo($tmpFileNew))
					{
						$thumbnail['width'] = $imageinfo[0];
						$thumbnail['height'] = $imageinfo[1];
					}
					$extension = strtolower(file_extension($filename));

					$thumbnail['filename'] = preg_replace('#' . preg_quote(file_extension($filename), '#') . '$#', 'jpg', $filename);

					$thumbnail['filesize'] = filesize($tmpFileNew);
					$thumbnail['dateline'] = vB::getRequest()->getTimeNow();
					$thumbnail['filedata'] = file_get_contents($tmpFileNew);
				}
				else
				{
					throw new vB_Exception_Api('thumbnail_nogetimagesize');
				}
				@unlink($tmpFileNew);
			}
			else
			{
				// image is a thumbnail size already
				if ($imgInfo['width'] > 0 AND $imgInfo['height'] > 0)
				{
					$thumbnail['filedata'] = @file_get_contents($filename);
					$thumbnail['width'] = $imgInfo['width'];
					$thumbnail['height'] = $imgInfo['height'];
				}
				else
				{
					throw new vB_Exception_Api('thumbnail_nogetimagesize');
				}
			}
		}
		else
		{
			throw new vB_Exception_Api('thumbnail_nosupport');
		}

		if (!empty($thumbnail['filedata']))
		{
			$thumbnail['filesize'] = strlen($thumbnail['filedata']);
			$thumbnail['dateline'] = vB::getRequest()->getTimeNow();
		}
		return $thumbnail;
	}

	/**
	* See function definition in vB_Image
	*/
	public function getImageFromString($string, $moveabout = true)
	{
		$tmpname = vB_Utilities::getTmpFileName('', 'vbimagick');
		if (!$tmpname)
		{
			throw new vB_Exception_Api('temp_file_create_error');
		}

		// Command start for no background image
		$execute = ' -size 201x61 xc:white ';
		$args = array();


		$position = 10;
		$fonts = $this->fetchRegimageFonts();
		if ($moveabout)
		{
			$backgrounds = $this->fetchRegimageBackgrounds();

			if (!empty($backgrounds))
			{
				$index = mt_rand(0, count($backgrounds) - 1);
				$background = $backgrounds["$index"];

				// replace Command start with background image
				$execute = " %s -resize 201x61! -swirl " . mt_rand(10, 100);
				$args = array($background);

				// randomly rotate the background image 180 degrees
				$execute .= (vB::getRequest()->getTimeNow() & 2) ? ' -rotate 180 ' : '';
			}

			// Randomly move the letters up and down
			for ($x = 0; $x < strlen($string); $x++)
			{
				if (!empty($fonts))
				{
					$index = mt_rand(0, count($fonts) - 1);
					if ($this->regimageoption['randomfont'])
					{
						$font = $fonts["$index"];
					}
					else
					{
						if (!$font)
						{
							$font = $fonts["$index"];
						}
					}
				}
				else
				{
					$font = 'Helvetica';
				}

				if ($this->regimageoption['randomshape'])
				{
					// Stroke Width, 1 or 2
					$strokewidth = mt_rand(1, 2);
					// Pick a random color
					$r = mt_rand(50, 200);
					$b = mt_rand(50, 200);
					$g = mt_rand(50, 200);
					// Pick a Shape

					/*
						Current total canvas size is 201x61, and we only draw in
						200x60 of it. (I think it's to not draw on the 1px border
						though I'm not sure why we allow drawing on the (0,*),
						(*,0) lines in that case).
						Always ensure we'll have a few pixels (9px atm) of "wiggle
						room" for the (x2,y2) vertex.
					 */
					$x1 = mt_rand(0, 190);
					$y1 = mt_rand(0, 50);
					/*
						Something about imagemagick or its dependencies changed and
						it now causes errors (e.g. non-conforming drawing primitive
						definition `roundrectangle) if the second vertex of the
						rectangular draw boundary of roundrectangle is not to the
						right & lower than the first vertex. I haven't tested the
						other shapes, and the randomized testing didn't show errors
						for the others, but applying changes generally since it
						won't hurt.
						Guarantee that the second vertex position will be greater
						than the first by setting the lower bound of the random pool
						to the first vertex position + 1.
					 */
					$x2 = mt_rand($x1+1, 200);
					$y2 = mt_rand($y1+1, 60);
					$start = mt_rand(0, 360);
					$end = mt_rand(0, 360);
					switch(mt_rand(1, 5))
					{
						case 1:
							$shape = "roundrectangle $x1,$y1 $x2,$y2 $start,$end";
							break;
						case 2:
							$shape = "arc $x1,$y1 $x2,$y2 20,15";
							break;
						case 3:
							$shape = "ellipse $x1,$y1 $x2,$y2 $start,$end";
							break;
						case 4:
							$shape = "line $x1,$y1 $x2,$y2";
							break;
						case 5:
							$x3 = mt_rand(0, 200);
							$y3 = mt_rand(0, 60);
							$x4 = mt_rand(0, 200);
							$y4 = mt_rand(0, 60);
							$shape = "polygon $x1,$y1 $x2,$y2 $x3,$y3 $x4,$y4";
							break;
					}
					// before or after
					$place = mt_rand(1, 2);

					$finalshape = " -flatten -stroke %s -strokewidth %s -fill none -draw %s -stroke none ";
					$stroke = "rgb($r,$b,$g)";

					if ($place == 1)
					{
						$execute .= $finalshape;
						$args[] = $stroke;
						$args[] = $strokewidth;
						$args[] = $shape;
					}
				}

				$slant = (($x <= 1 OR $x == 5) AND $this->regimageoption['randomslant']) ? true : false;
				$execute .= $this->annotate($string["$x"], $font, $slant, true, $position);
				$position += rand(25, 35);

				if ($this->regimageoption['randomshape'] AND $place == 2)
				{
					$execute .= $finalshape;
					$args[] = $stroke;
					$args[] = $strokewidth;
					$args[] = $shape;
				}
			}
		}
		else
		{
			if (!empty($fonts))
			{
				$font = $fonts[0];
			}
			else
			{
				$font = 'Helvetica';
			}
			$execute .= $this->annotate($string, $font, false, false, $position);
		}

		// Swirl text, stroke inner border of 1 pixel and output as GIF
		$execute .= ' -flatten ';

		$execute .= ($moveabout AND $this->regimageoption['randomslant']) ? ' -swirl 20 ' : '';
		$execute .= " -stroke black -strokewidth 1 -fill none -draw \"rectangle 0,60 200,0\" -depth 8 PNG:%s";
		$args[] = $tmpname;

		if ($result = $this->fetchImExec('convert', $execute, $args))
		{
			$filedata = @file_get_contents($tmpname);
			$fileSize = 0;
			if ($tmpSize = @filesize($tmpname))
			{
				$fileSize = $tmpSize;
			}
			else
			{
				$fileSize = strlen($filedata);
			}

			@unlink($tmpname);

			// return imageinfo
			return array('filedata' => $filedata, 'filetype' => 'png', 'filesize' => $fileSize, 'contentType' => 'image/png');
		}
		else
		{
			@unlink($tmpname);
			return false;
		}
	}

	/**
	*
	* Return a letter position command. The returned string is already escaped for exec.
	* Do not (manually) re-escape the string as that may make the contents unsafe or
	* break the command options.
	*
	* @param	string	letter	Character to position
	*
	* @return	string
	*/
	protected function annotate($letter, $font, $slant = false, $random = true, $position = 10)
	{
		// Start position
		static $r, $g, $b;

		// Character Slant
		static $slants = array(
			'0x0',     # Normal
			'0x30',    # Slant Right
			'20x20',   # Slant Down
			'315x315', # Slant Up
			'45x45',
			'0x330',
		);

		// Can't use slants AND swirl at the same time, it just looks bad ;)
		if ($slant)
		{
			$coord = mt_rand(1, count($slants) - 1);
			$coord = $slants["$coord"];
		}
		else
		{
			$coord = $slants[0];
		}

		if ($random)
		{
			// Y Axis position, random from 32 to 48
			$y = mt_rand(32, 48);

			if ($this->regimageoption['randomcolor'] OR empty($r))
			{
				// Generate a random color..
				$r = mt_rand(50, 200);
				$b = mt_rand(50, 200);
				$g = mt_rand(50, 200);
			}

			$pointsize = $this->regimageoption['randomsize'] ? mt_rand(28, 36) : 32;
		}
		else
		{
			$y = 40;
			$pointsize = 32;
			$r = $b = $g = 0;
		}

		$args = array(
			$font,
			$pointsize,
			"rgb($r,$b,$g)", // fill
			"$coord+$position+$y", // annotate
			$letter,
		);
		$escapedArgs = array();
		foreach ($args AS $unsafe)
		{
			$escapedArgs[] = escapeshellarg($unsafe);
		}

		$output = " -font %s -pointsize %s -fill %s -annotate %s %s ";
		$output = vsprintf($output, $escapedArgs);

		return $output;
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 103329 $
|| #######################################################################
\*=========================================================================*/
