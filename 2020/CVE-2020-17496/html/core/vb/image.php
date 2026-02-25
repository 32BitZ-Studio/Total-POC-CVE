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
* Class for image processing
*
* @package 		vBulletin
* @version		$Revision: 103452 $
* @date 		$Date: 2019-11-15 17:25:38 -0800 (Fri, 15 Nov 2019) $
*
*/
abstract class vB_Image
{
	use vB_Trait_NoSerialize;

	/**
	 * Class constants
	 */

	/**
	 * Global image type defines used by serveral functions
	 */
	const GIF = 1;
	const JPG = 2;
	const PNG = 3;

	/**
	* These make up the bit field to enable specific parts of image verification
	*/
	const ALLOW_RANDOM_FONT = 1;
	const ALLOW_RANDOM_SIZE = 2;
	const ALLOW_RANDOM_SLANT = 4;
	const ALLOW_RANDOM_COLOR = 8;
	const ALLOW_RANDOM_SHAPE = 16;

	/**
	* Options from datastore
	*
	* @var	array
	*/
	var $options = null;

	/**
	* @var	array
	*/
	var $thumb_extensions = array();

	/**
	* @var	array
	*/
	var $info_extensions = array();

	/**
	* @var	array
	*/
	var $must_convert_types = array();

	/**
	* @var	array
	*/
	var $resize_types = array();

	/**
	* @var	mixed
	*/
	var $imageinfo = null;

	/**
	* @var	array $extension_map
	*/
	var $extension_map = array(
		'gif'  => 'GIF',
		'jpg'  => 'JPEG',
		'jpeg' => 'JPEG',
		'jpe'  => 'JPEG',
		'png'  => 'PNG',
		'bmp'  => 'BMP',
		'tif'  => 'TIFF',
		'tiff' => 'TIFF',
		'psd'  => 'PSD',
		'pdf'  => 'PDF',
	);

	/**
	 * It's not very clear if $extension_map was supposed to be mimetype => extension, or extension => "type".
	 * It's currently used for both, which doesn't make a lot of sense, so I'm adding the following to make $extension_map
	 * into extension => "type", then "type" to "canonical extension" with below
	 * @var
	 */
	var $type_to_canonical_extension = array(
		'GIF'   => 'gif',
		'JPEG'  => 'jpg',	// apparently .jpg is more common than .jpeg
		'PNG'   => 'png',
		'BMP'   => 'bmp',
		'TIFF'  => 'tiff',
		'PSD'   => 'psd',
		'PDF'   => 'pdf',
	);

	/*
	 * @var	bool	invalid file
	 */
	var $invalid = false;

	/**
	* @var	array	$regimageoption
	*/
	var $regimageoption = array(
		'randomfont'  => false,
		'randomsize'  => false,
		'randomslant' => false,
		'randomcolor' => false,
		'randomshape'  => false,
	);

	/**
	 * Used to translate from imagetype constants to extension name.
	 * @var	array	$imagetype_constants
	 */
	var $imagetype_constants = array(
		1 => 'GIF',
		2 => 'JPEG',
		3 => 'PNG',
		5 => 'PSD',
		6 => 'BMP',
		7 => 'TIFF',
		8 => 'TIFF'
	);

	protected $imagefilelocation = null;

	protected $preserveExif = false;

	/**
	* Constructor
	* Don't allow direct construction of this abstract class
	* Sets registry
	*
	* @return	void
	*/
	public function __construct($options, $extras = array())
	{
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

		if (!defined('IMAGEGIF'))
		{
			if (function_exists('imagegif'))
			{
				define('IMAGEGIF', true);
			}
			else
			{
				define('IMAGEGIF', false);
			}
		}

		if (!defined('IMAGEJPEG'))
		{
			if (function_exists('imagejpeg'))
			{
				define('IMAGEJPEG', true);
			}
			else
			{
				define('IMAGEJPEG', false);
			}
		}


		if (!defined('IMAGEPNG'))
		{
			if (function_exists('imagepng'))
			{
				define('IMAGEPNG', true);
			}
			else
			{
				define('IMAGEPNG', false);
			}
		}

		vB_Utilities::extendMemoryLimit();

		$this->options = $options;
		$this->regimageoption['randomfont'] = $this->options['regimageoption'] & self::ALLOW_RANDOM_FONT;
		$this->regimageoption['randomsize'] = $this->options['regimageoption'] & self::ALLOW_RANDOM_SIZE;
		$this->regimageoption['randomslant'] = $this->options['regimageoption'] & self::ALLOW_RANDOM_SLANT;
		$this->regimageoption['randomcolor'] = $this->options['regimageoption'] & self::ALLOW_RANDOM_COLOR;
		$this->regimageoption['randomshape'] = $this->options['regimageoption'] & self::ALLOW_RANDOM_SHAPE;


		/*
			Whitelist of known & accepted file signatures that our image classes can process.
		 */
		$this->magic_numbers = array(
			// start of image => end of image
			// gif
			hex2bin("4749" . "4638" . "3961") => array('eoi' => '', 'type' => "GIF", 'extension' => 'gif'),	// GIF89a
			hex2bin("4749" . "4638" . "3761") => array('eoi' => '', 'type' => "GIF", 'extension' => 'gif'),	// GIF87a
			// jpeg
			hex2bin("ffd8") => array('eoi' => hex2bin("ffd9"), 'type' => "JPEG", 'extension' => 'jpg'),
			// png
			hex2bin("8950" . "4e47" . "0d0a" . "1a0a") => array('eoi' => '', 'type' => "PNG", 'extension' => 'png'),
			// bmp
			hex2bin("424d") => array('eoi' => '', 'type' => "BMP", 'extension' => 'bmp'),
			// tiff
			hex2bin("4d4d" . "002a") => array('eoi' => '', 'type' => "TIFF", 'extension' => 'tiff'),
			hex2bin("4949" . "2a00") => array('eoi' => '', 'type' => "TIFF", 'extension' => 'tiff'),
			// psd
			hex2bin("3842" . "5053") => array('eoi' => '', 'type' => "PSD", 'extension' => 'psd'),	// are PSDs safe??
			// pdf - not really an image, but imagemagick accepts this for thumbnail purposes...
			//hex2bin("2550" . "4446") => array('eoi' => '', 'type' => "PDF"), // PDF added for imagemagick only.
			// MVG, SVG & possibly other "complex" formats allow external file inclusion.
		);
		$this->magic_numbers_shortcut = array();
		$this->magic_numbers_types = array();
		foreach ($this->magic_numbers AS $soi => $filetypeData)
		{
			$two = substr($soi, 0, 2);
			$this->magic_numbers_shortcut[$two][$soi] = $filetypeData;
			$this->magic_numbers_types[$filetypeData['type']] = true;
		}

		if (!empty($extras['preserveExif']))
		{
			$this->preserveExif = true;
		}
	}

	/**
	* Select image library
	*
	* @return	object
	*/
	public static function instance($type = 'image', $additionalOptions = array())
	{
		$vboptions = vB::getDatastore()->getValue('options');

		// Library used for thumbnails, image functions
		if ($type == 'image')
		{
			$check = $vboptions['imagetype'];
		}
		// Library used for Verification Image
		else
		{
			$check = $vboptions['regimagetype'];
		}

		if (!isset($additionalOptions['preserveExif']))
		{
			$additionalOptions['preserveExif'] = false;
			$config = vB::getConfig();
			if (!empty($config['Misc']['preserve_exif']))
			{
				$additionalOptions['preserveExif'] = true;
			}
		}

		switch($check)
		{
			// todo: Allow for any (rather than whitelist) that exist?
			case 'Imagick':
				$selectclass = 'vB_Image_Imagick';
				break;
			case 'Magick':
				$selectclass = 'vB_Image_ImageMagick';
				break;
			default:
				$selectclass = 'vB_Image_GD';
				break;
		}
		$object = new $selectclass($vboptions, $additionalOptions);
		return $object; // function defined as returning & must return a defined variable
	}

	/**
	*
	* Fetches image files from the backgrounds directory
	*
	* @return array
	*
	*/
	protected function &fetchRegimageBackgrounds()
	{
		// Get backgrounds
		$backgrounds = array();
		if ($handle = @opendir(DIR . '/images/regimage/backgrounds/'))
		{
			while ($filename = @readdir($handle))
			{
				if (preg_match('#\.(gif|jpg|jpeg|jpe|png)$#i', $filename))
				{
					$backgrounds[] = DIR . "/images/regimage/backgrounds/$filename";
				}
			}
			@closedir($handle);
		}
		return $backgrounds;
	}

	/**
	*
	* Fetches True Type fonts from the fonts directory
	*
	* @return array
	*
	*/
	protected function &fetchRegimageFonts()
	{
		// Get fonts
		$fonts = array();
		if ($handle = @opendir(DIR . '/images/regimage/fonts/'))
		{
			while ($filename =@ readdir($handle))
			{
				if (preg_match('#\.ttf$#i', $filename))
				{
					$fonts[] = DIR . "/images/regimage/fonts/$filename";
				}
			}
			@closedir($handle);
		}
		return $fonts;
	}

	/**
	*
	*
	*
	* @param	string	$type		Type of image from $info_extensions
	*
	* @return	bool
	*/
	final public function fetchMustConvert($type)
	{
		return !empty($this->must_convert_types["$type"]);
	}

	/**
	*
	* Checks if supplied extension can be used by fetchImageInfo
	*
	* @param	string	$extension 	Extension of file
	*
	* @return	bool
	*/
	final public function isValidInfoExtension($extension)
	{
		return !empty($this->info_extensions[strtolower($extension)]);
	}

	/**
	*
	* Checks if supplied extension can be resized into a smaller permanent image, not to be used for PSD, PDF, etc as it will lose the original format
	*
	* @param	string	$type 	Type of image from $info_extensions
	*
	* @return	bool
	*
	*/
	final public function isValidResizeType($type)
	{
		return !empty($this->resize_types["$type"]);
	}

	/**
	*
	* Checks if supplied extension can be used by fetchThumbnail
	*
	* @param	string	$extension 	Extension of file
	*
	* @return	bool
	*
	*/
	final public function isValidThumbnailExtension($extension)
	{
		return !empty($this->thumb_extensions[strtolower($extension)]);
	}

	/**
	*
	* Checks if supplied extension can be used by fetchThumbnail
	*
	* @param	string	$extension 	Extension of file
	*
	* @return	bool
	*
	*/
	final public function fetchImagetypeFromExtension($extension)
	{
		$extension = strtolower($extension);

		if (isset($this->extension_map[$extension]))
		{
			return $this->extension_map[$extension];
		}
		else
		{
			return false;
		}
	}

	/*
	 *	Returns the "orientation" exif data for image file at specified location
	 *
	 * @param String	$location	File location. Must be readable.
	 *
	 * @return int	0 for undefined or invalid. 1-8 if found & valid.
	 *
	 * @access protected
	 */
	final public function getOrientation($location)
	{
		/*
			This function does not care about security.
			It's not vulnerable to anything I'm aware of (unless exif_read_data has a vulnerability)
			but it also doesn't care if someone stuck in code in the exif data.

			Note, children may have their own library methods of getting this data. This is a fallback.
		 */
		if (function_exists('exif_read_data'))
		{
			$fileinfo = @exif_read_data($location);
			if (isset($fileinfo['Orientation']))
			{
				$orientation = intval($fileinfo['Orientation']);
				if ($orientation >= 1 AND $orientation <= 8)
				{
					return $orientation;
				}
			}
		}

		return 0;
	}

	protected function orientationToAnglesCW($orientation)
	{
		// source: https://beradrian.wordpress.com/2008/11/14/rotate-exif-images/
		$angles = 0;
		switch ($orientation)
		{
			case 3:
				$angles = 180;
				break;
			case 5:
				$angles = 90; // and flop
				break;
			case 6:
				$angles = 90;
				break;
			case 7:
				$angles = 270; // and flop
				break;
			case 8:
				$angles = 270;
				break;
			default:
				break;
		}

		return $angles;
	}

	protected function orientationToFlipFlop($orientation)
	{
		// source: https://beradrian.wordpress.com/2008/11/14/rotate-exif-images/
		$flip = 0; // about x
		$flop = 0; // about y
		switch ($orientation)
		{
			case 2:
				$flop = 1;
				break;
			case 4: // top to bottom
				$flip = 1;
				break;
			case 5:
				$flop = 1;
				break;
			case 7:
				$flop = 1;
				break;
			default:
				break;
		}

		return array(
			'flip' => $flip,
			'flop' => $flop,
		);
	}

	/*
	 * Returns false if $data does not contain the a known file signature for
	 * images we support. Returns the type in the format of $extension_map if identified.
	 *
	 * @param  String  $data
	 *
	 * @return	String|false
	 *
	 * @access protected
	 */
	protected function magicWhiteList($data, $return_extension = false)
	{
		$magicNumbers = $this->magic_numbers;
		$shortCut = $this->magic_numbers_shortcut;

		$checked = false;

		$two = substr($data, 0, 2);
		if (!isset($shortCut[$two]))
		{
			return false;
		}

		foreach ($shortCut[$two] AS $soi => $filetypeData)
		{
			$eoi = $filetypeData['eoi'];
			$temp_begin = substr($data, 0, strlen($soi));
			// one liner for below block: $temp_end = substr($data, -strlen($eoi), strlen($eoi));
			if (!empty($eoi))
			{
				$temp_end = substr($data, -strlen($eoi));
			}
			else
			{
				$temp_end = '';
			}


			$valid = ($temp_begin === $soi AND $temp_end === $eoi);
			// Special JPEG eoi check
			if (!$valid AND $filetypeData['type'] == 'JPEG' AND $temp_begin === $soi)
			{
				/*
					VBV-16527 Sometimes, jpegs can have some extraneous bytes (sometimes up to a few hundred bytes) after the end of image marker.
					JPEG specs aren't very clear about whether this is allowed, and such files pass other checks like finfo.
					Let's just check to see if the end of image bytes exist period rather than check that it's at the end of file.
					This is not always correct, as the bytes might exist as part of another block (or as part of an embedded thumbnail), but
					to do something more complex we'll need a full on jpeg parser, which we cannot maintain.

					Note, this could be bad for very large files.

					We already checked for start of image bytes @ start of file in the outer if.
					We know for certain that the end of image will NOT be at position 0, so we don't care about 0 or false.
					TODO: Use strrpos() instead?
				 */
				if (strpos($data, $eoi) > 0)
				{
					$valid = true;
				}

			}

			if ($valid)
			{
				if ($return_extension AND isset($filetypeData['extension']))
				{
					return $filetypeData['extension'];
				}
				else
				{
					return $filetypeData['type'];
				}
			}
		}

		return false;
	}

	/**
	 * Checks for HTML tags that can be exploited via IE, & scripts in exif tags
	 *
	 * @param string   $fileContents		Contents of the file e.g. file_get_contents($location)
	 * @param string   $location            Full filepah
	 *
	 * @return bool
	 *
	 */
	public function verifyFileHeadersAndExif($fileContents, $location)
	{
		if (empty($fileContents) OR empty($location))
		{
			throw new vB_Exception_Api('upload_invalid_image');
		}

		// Verify that file is playing nice
		$header = substr($fileContents, 0, 256);
		if ($header)
		{
			if (preg_match('#<html|<head|<body|<script|<pre|<plaintext|<table|<a href|<img|<title#si', $header))
			{
				throw new vB_Exception_Api('upload_invalid_image');
			}
		}
		else
		{
			return false;
		}

		if (function_exists('exif_read_data') AND function_exists('exif_imagetype'))
		{
			$filetype = @exif_imagetype($location);
			if (in_array($filetype, array(
				IMAGETYPE_TIFF_II,
				IMAGETYPE_TIFF_MM,
				IMAGETYPE_JPEG
			)))
			{
				if ($fileinfo = @exif_read_data($location))
				{
					$this->invalid = false;
					array_walk_recursive($fileinfo, array($this, 'checkExif'));
					if ($this->invalid)
					{
						return false;
					}
				}
			}
		}

		return true;
	}

	/**
	 * Checks for HTML tags that can be exploited via IE, scripts in exif tags, and checks file signature
	 * against a whitelist of image signatures (currently only support gif, jpg, bmp, tif, psd)
	 *
	 * @param string   $fileContents		Contents of the file e.g. file_get_contents($location)
	 * @param string   $location            Full filepah
	 *
	 * @return bool		True if nothing was detected, false if headers were not found, throws an exception
	 *					if possible nasty was detected.
	 *
	 */
	public function verifyImageFile($fileContents, $location)
	{
		/*
			Maintenance note:
			Any non image-specific validation/sanitation we add to this should also be applied to
			fetchImageInfoForThumbnails()
		 */

		if (!$this->verifyFileHeadersAndExif($fileContents, $location))
		{
			return false;
		}

		/*
			do NOT use ImageMagick identify for verifying images.
			Older versions of imagick will be vulnerable to imagetragick exploit.
		 */


		// imagetragick filetype whitelist check.
		if (!$this->magicWhiteList($fileContents) OR
			!$this->fileLocationIsImage($location)
		)
		{
			throw new vB_Exception_Api('upload_invalid_image');
		}

		return true;
	}

	/*	Scan string for data that "could" be used to exploit an image but
	 *  would require a badly configured server.
	 *
	 * @param	string String to check for possible invalid data
	 *
	 * @return	bool
	 */
	protected function checkExif($value, $key)
	{
		if (preg_match('#<\?|<script#si', $value))
		{
			$this->invalid = true;
		}
	}

	/**
	*
	* Retrieve info about image
	*
	* @param	string	filename	Location of file
	* @param	string	extension	Extension of file name
	*
	* @return	array	[0]			int		width
	*					[1]			int		height
	*					[2]			string	type ('GIF', 'JPEG', 'PNG', 'PSD', 'BMP', 'TIFF',) (and so on)
	*					[scenes]	int		scenes
	*					[channels]	int		(DEPRECATED) Number of channels
	*					[bits]		int		Number of bits per pixel
	*					[library]	string	Library Identifier
	*
	*/
	abstract public function fetchImageInfo($filename);

	/*
	 * See fetchImageInfo()
	 */
	public function fetchImageInfoForThumbnails($filename)
	{
		return $this->fetchImageInfo($filename);
	}

	/**
	*
	* Output an image based on a string
	*
	* @param	string		string	String to output
	* @param 	bool		moveabout	move text about
	*
	* @return	array		Array containing imageInfo: filedata, filesize, filetype and htmltype
	*
	*/
	abstract public function getImageFromString($string, $moveabout = true);

	/**
	*
	* Returns an array containing a thumbnail, creation time, thumbnail size and any errors
	*
	* @param    string      filename	filename of the source file
	* @param    string      location	location of the source file
	* @param    int         maxwidth
	* @param    int         maxheight
	* @param    int         quality		Jpeg Quality
	* @param    bool        labelimage	DEPRECATED. Include image dimensions and filesize on thumbnail
	* @param    bool        drawborder	Draw border around thumbnail
	* @param    bool        jpegconvert
	* @param    bool        sharpen
	* @param    int|null    owidth
	* @param    int|null    oheight
	* @param    int|null    ofilesize
	*
	* @return	array
	*
	*/
	abstract public function fetchThumbnail($filename, $location, $maxwidth = 100, $maxheight = 100, $quality = 75, $labelimage = false, $drawborder = false, $jpegconvert = false, $sharpen = true, $owidth = null, $oheight = null, $ofilesize = null);

	/** Crop the profile image
	 *
	 * 	@param 	array $imgInfo contains all the required information
	 * 	* filename
	 * 	* extension
	 * 	* filedata
	 * 	* width
	 * 	* height
	 * 	* x1
	 * 	* y1
	 * 	@param	int	$maxwidth
	 * 	@param	int	$maxheight
	 * 	@param	bool $forceResize force generation of a new file
	 *
	 *	@return	mixed	array of data with the cropped image info:
	 *	* width
	 *	* height
	 *	* filedata
	 *	* filesize
	 *	* dateline
	 *	* imageerror (not used)
	 *	* filename (not used)
	 **/
	abstract public function cropImg($imgInfo, $maxwidth = 100, $maxheight = 100, $forceResize = false);

	/**
	 * Fetch a resize image from an existing filedata
	 *
	 * @param	array	$record File information
	 * @param string $type One of the vB_Api_Filedata type constants other than full
	 * 	(which should be handled without resizing).  It does not accept a direct size
	 * 	value like the public functions.  Use the vB_Api/Library sanitizeFiletype
	 * 	function to convert those to a valid type string.
	 */
	private function fetchResizedImageFromFiledata(&$record, $type)
	{
		$options = vB::getDatastore()->getValue('options');
		$sizes = @unserialize($options['attachresizes']);

		$filename = 'temp.' . $record['extension'];
		if (empty($sizes[$type]))
		{
			throw new vB_Exception_Api('thumbnail_nosupport');
		}

		if ($options['attachfile'])
		{
			if ($options['attachfile'] == ATTACH_AS_FILES_NEW) // expanded paths
			{
				$path = $options['attachpath'] . '/' . implode('/', preg_split('//', $record['userid'],  -1, PREG_SPLIT_NO_EMPTY)) . '/';
			}
			else
			{
				$path = $options['attachpath'] . '/' . $record['userid'] . '/';
			}
			$location = $path . $record['filedataid'] . '.attach';
		}
		else
		{
			// Must save filedata to a temp file as the img operations require a file read
			$location = vB_Utilities::getTmpFileName($record['userid'], 'vbimage');
			@file_put_contents($location, $record['filedata']);
		}

		$resized = $this->fetchThumbnail($filename, $location, $sizes[$type], $sizes[$type], $options['thumbquality']);

		$record['resize_dateline'] = $resized['dateline'];
		$record['resize_filesize'] = strlen($resized['filedata']);

		if ($options['attachfile'])
		{
			if ($options['attachfile'] == ATTACH_AS_FILES_NEW) // expanded paths
			{
				$path = $options['attachpath'] . '/' . implode('/', preg_split('//', $record['userid'],  -1, PREG_SPLIT_NO_EMPTY)) . '/';
			}
			else
			{
				$path = $options['attachpath'] . '/' . $record['userid'] . '/';
			}
			@file_put_contents($path .  $record['filedataid'] . '.' . $type, $resized['filedata']);
		}
		else
		{
			$record['resize_filedata'] = $resized['filedata'];
		}

 		vB::getDbAssertor()->assertQuery('vBForum:replaceIntoFiledataResize', array(
 			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_STORED,
 			'filedataid'      => $record['filedataid'],
 			'resize_type'     => $type,
			'resize_filedata' => $options['attachfile'] ? '' : $record['resize_filedata'],
			'resize_filesize' => $record['resize_filesize'],
			'resize_dateline' => vB::getRequest()->getTimeNow(),
			'resize_width'    => $resized['width'],
			'resize_height'   => $resized['height'],
			'reload'          => 0,
 		));

		if (!$options['attachfile'])
		{
			@unlink($location);
		}
	}

	/* Load information about a file base on the data
	 *
	 * @param 	mixed	database record
	 * @param	mixed	size of image requested [ICON/THUMB/SMALL/MEDIUM/LARGE/FULL]
	 * @param	bool	should we include the image content
	 *
	 * @return	mixed	array of data, includes filesize, dateline, htmltype, filename, extension, and filedataid
	 */
	public function loadFileData($record, $type = vB_Api_Filedata::SIZE_FULL, $includeData = true)
	{
		$options = vB::getDatastore()->getValue('options');
		$type = vB_Api::instanceInternal('filedata')->sanitizeFiletype($type);

		// Correct any improper paths. See See VBV-13389.
		// @TODO this block of code can be removed in a future version,
		// when we no longer want to support this instance of bad data.
		if ($options['attachfile'] == ATTACH_AS_FILES_NEW) // expanded paths
		{
			$testpath = $options['attachpath'] . '/' . implode('/', preg_split('//', $record['userid'],  -1, PREG_SPLIT_NO_EMPTY)) . '/';
			$testfile = $testpath . $record['filedataid'] . '.attach';

			// If the path doesn't exist, try alternative (incorrect) paths where
			// we *may* be storing the image, if the admin converted image storage
			// from the database to the filesystem between vB5.0 and vB5.1.3
			// This is basically using ATTACH_AS_FILES_OLD even though the option is
			// set to ATTACH_AS_FILES_NEW. See VBV-13389 for more details.
			if (!file_exists($testfile))
			{
				$testpath = $options['attachpath'] . '/' . $record['userid'] . '/';
				$testfile = $testpath . $record['filedataid'] . '.attach';

				if (file_exists($testfile))
				{
					// We found the incorrectly stored file; let's copy it to the
					// correct location, which will allow this function to display
					// it and/or generate the requested resized version of it.
					// Don't remove the old file, in case the copy fails, and since
					// viewing a resource should never have the possible side effect
					// of deleting it. An upgrade step will fix the bad storage.
					$newpath = vB_Library::instance('filedata')->fetchAttachmentPath($record['userid'], ATTACH_AS_FILES_NEW) . '/';
					$newfile = $newpath . $record['filedataid'] . '.attach';
					copy($testfile, $newfile);
				}
			}
		}
		// end VBV-13389

		if ($type != vB_Api_Filedata::SIZE_FULL)
		{
			if ($options['attachfile'])
			{
				if ($options['attachfile'] == ATTACH_AS_FILES_NEW) // expanded paths
				{
					$path = $options['attachpath'] . '/' . implode('/', preg_split('//', $record['userid'],  -1, PREG_SPLIT_NO_EMPTY)) . '/';
				}
				else
				{
					$path = $options['attachpath'] . '/' . $record['userid'] . '/';
				}
				$path .= $record['filedataid'] . '.' . $type;
			}

			// Resized image wasn't found
			if (
				empty($record['resize_type']) OR
				empty($record['resize_filesize']) OR
				(empty($record['resize_filedata']) AND !$options['attachfile']) OR
				($options['attachfile'] AND	!file_exists($path)) OR
				$record['reload']
			)
			{
				$this->fetchResizedImageFromFiledata($record, $type);
			}

			$results = array(
				'filesize'   => $record['resize_filesize'],
				'dateline'   => $record['resize_dateline'],
				'headers'    => vB_Library::instance('content_attach')->getAttachmentHeaders(strtolower($record['extension'])),
				'filename'   => $type . '_' . $record['filedataid'] . "." . strtolower($record['extension']),
				'extension'  => $record['extension'],
			   	'filedataid' => $record['filedataid'],
			);

			if ($options['attachfile'] AND $includeData)
			{
				$results['filedata'] = @file_get_contents($path);
			}
			else if ($includeData)
			{
				$results['filedata'] = $record['resize_filedata'];
			}
		}
		else
		{
			$results = array(
				'filesize'   => $record['filesize'],
				'dateline'   => $record['dateline'],
				'headers'    => vB_Library::instance('content_attach')->getAttachmentHeaders(strtolower($record['extension'])),
				'filename'   => 'image_' . $record['filedataid'] . "." . strtolower($record['extension']),
				'extension'  => $record['extension'],
				'filedataid' => $record['filedataid'],
			);

			if ($options['attachfile'] AND $includeData)
			{

				if ($options['attachfile'] == ATTACH_AS_FILES_NEW) // expanded paths
				{
					$path = $options['attachpath'] . '/' . implode('/', preg_split('//', $record['userid'],  -1, PREG_SPLIT_NO_EMPTY)) . '/';
				}
				else
				{
					$path = $options['attachpath'] . '/' . $record['userid'] . '/';
				}

				$results['filedata'] = file_get_contents($path .  $record['filedataid'] . '.attach');

			}
			else if ($includeData)
			{
				$results['filedata'] = $record['filedata'];

			}
		}

		return $results;
	}

	/**
	 * standard getter
	 *
	 *	@return	mixed	array of file extension-to-type maps , like 'gif' => "GIF'
	 *  **/
	public function getExtensionMap()
	{
		return $this->extension_map;
	}

	/**
	 * standard getter
	 *
	 * @return mixed	array of must conver types
	 */
	final public function getConvertTypes()
	{
		// todo: test only? remove
		return $this->must_convert_types;
	}

	/**
	 * standard getter
	 *
	 * @return mixed	array of valid extensions
	 */
	final public function getInfoExtensions()
	{
		// todo: test only? remove
		return $this->info_extensions;
	}

	/**
	 * standard getter
	 *
	 * @return mixed	array of resize types
	 */
	final public function getResizeTypes()
	{
		// todo: test only? remove
		return $this->resize_types;
	}

	/**
	 * standard getter
	 *
	 * @return mixed	array of thumbnail ext
	 */
	final public function getThumbExtensions()
	{
		// todo: test only? remove
		return $this->thumb_extensions;
	}

	/**
	 * Attempt to resize file if the filesize is too large after an initial resize to max dimensions or the file is already within max dimensions but the filesize is too large
	 *
	 * @param	bool	Has the image already been resized once?
	 * @param	bool	Attempt a resize
	 */
	function bestResize($width, $height)
	{
		// Linear Regression
		$maxuploadsize = vB::getUserContext()->getLimit('avatarmaxsize');
		switch(vB::getDatastore()->getOption('thumbquality'))
		{
			case 65:
				// No Sharpen
				// $magicnumber = round(379.421 + .00348171 * $this->maxuploadsize);
				// Sharpen
				$magicnumber = round(277.652 + .00428902 * $maxuploadsize);
				break;
			case 85:
				// No Sharpen
				// $magicnumber = round(292.53 + .0027378 * $maxuploadsize);
				// Sharpen
				$magicnumber = round(189.939 + .00352439 * $maxuploadsize);
				break;
			case 95:
				// No Sharpen
				// $magicnumber = round(188.11 + .0022561 * $maxuploadsize);
				// Sharpen
				$magicnumber = round(159.146 + .00234146 * $maxuploadsize);
				break;
			default:	//75
				// No Sharpen
				// $magicnumber = round(328.415 + .00323415 * $maxuploadsize);
				// Sharpen
				$magicnumber = round(228.201 + .00396951 * $maxuploadsize);
		}

		$xratio = ($width > $magicnumber) ? $magicnumber / $width : 1;
		$yratio = ($height > $magicnumber) ? $magicnumber / $height : 1;

		if ($xratio > $yratio AND $xratio != 1)
		{
			$new_width = round($width * $xratio);
			$new_height = round($height * $xratio);
		}
		else
		{
			$new_width = round($width * $yratio);
			$new_height = round($height * $yratio);
		}
		if ($new_width == $width AND $new_height == $height)
		{	// subtract one pixel so that requested size isn't the same as the image size
			$new_width--;
		}
		return array('width' => $new_width, 'height' => $new_height);
	}

	/**
	 * Determine if the given extension should be treated as an image for
	 * size $type as far as HTML is concerned. These types also align with
	 * the cangetimgattachment permission.
	 *
	 * @param	String	$extension	File extension, usually from filedata.extension.
	 * @param	String	$type	One of vB_Api_Filedata::SIZE_X strings
	 *
	 * @return	bool
	 */
	final public function isImageExtension($extension, $type = vB_Api_Filedata::SIZE_FULL)
	{
		/*
			Extensions don't really matter in terms of validation, only use this
			for purposes of "should I use an <img > or <a > for this file inclusion
			in HTML?

			TODO: deprecate this & move out into bbcode parsers.
		 */
		$extension = trim(strtolower($extension), " \t\n\r\0\x0B.");
		$type = vB_Api::instanceInternal('filedata')->sanitizeFiletype($type);
		$isImage = false;
		// We can support these as images at fullsize:
		$currentlySupportedImageExtensions = $this->fetchImageExtensions();

		/*
		Note, the reason we use the above list instead of $this->isValidInfoExtension() is
		that even if the image tool can "get the image info", this doesn't mean we converted the
		file to an image. For example, with imagemagick we could get the "image info" of a PDF,
		but the fullsize file is still gonna be a PDF.
		As far as I know, the only time we convert a file to a "simple" image
		(i.e. a type in the above list) is when we request a resize. As such, I'm going with
		only bothering to check the library-specific lists for resizes, and sticking with the
		above list for full-size images.
		Above is a subset of https://developer.mozilla.org/en-US/docs/Web/HTML/Element/img#Supported_image_formats
		 */

		// If requesting a fullsize, determine if it's one of the "basic" images...
		// otherwise, always force them to download etc.
		if ($type == vB_Api_Filedata::SIZE_FULL)
		{
			$isImage = isset($currentlySupportedImageExtensions[$extension]);
		}
		else
		{
			// This means a resize of the image should be provided instead.
			$isImage = $this->imageThumbnailSupported($extension);
		}


		return (bool) $isImage;
	}

	// todo: clean this up?
	final public function fetchImageExtensions()
	{
		// We can support these as images at fullsize:
		$currentlySupportedImageExtensions = array(
			'png' => true,
			'bmp' => true, // this is currently "disabled" by app light due to an IE xss issue...?
			'jpeg' => true,
			'jpg' => true,
			'jpe' => true,
			'gif' => true,
		);

		$return = array();
		foreach ($currentlySupportedImageExtensions AS $__ext => $__nothing)
		{
			$return[$__ext] = $__ext;
		}

		return $return;
	}

	/**
	 * Determine if the given location holds a whitelisted image file. Return false
	 * if not an image or not whitelisted.
	 *
	 * @param	String	$location	Full file path
	 *
	 * @return	bool
	 */
	final public function fileLocationIsImage($location)
	{
		/*
			If *any* of the available checks fail, assume it's not an image.
			Report it as image only if *all* available checks pass.
			This might be a bit strict, but is safer.
		 */
		$isImage = false;

		if (function_exists('exif_imagetype'))
		{
			$imageType = @exif_imagetype($location);
			$isImage = (bool)$imageType;
			if (!$isImage)
			{
				return false;
			}
		}

		if (function_exists('finfo_open') AND function_exists('finfo_file'))
		{
			/*
			 * TODO: When pdf thumbnail support is fixed, this check might have to be updated.
			 */

			// Just in case exif_imagetype is not there. finfo extension should be installed
			// by default (except windows), and is an alternative way to detect
			// if this is an image.
			// In the future, perhaps we can just use below to set the mimetype in the database,
			// and have the fetchImage functions return the mimetype as well rather than
			// trying to set it based on the filedata.extension (which may not be correct).
			$finfo = finfo_open(FILEINFO_MIME_TYPE);
			$mimetype = finfo_file($finfo, $location);
			if ($mimetype)
			{
				$mimetype = explode('/', $mimetype);
				$toplevel = $mimetype[0];
				if ($toplevel != 'image')
				{
					$isImage = false;
				}
				else
				{
					$isImage = true;
				}
			}
			else
			{
				$isImage = false;
			}
			if (!$isImage)
			{
				return false;
			}
		}


		if (function_exists('getimagesize'))
		{
			$imageData = @getimagesize($location);
			if (empty($imageData))
			{
				return false;
			}
		}

		// Finally... a hard-coded whitelist. This is probably the hardest bit to maintain in the future,
		// and most likely to throw a false flag.
		$magictype = $isImage = $this->magicWhiteList(file_get_contents($location));
		if (!$isImage)
		{
			return false;
		}

		/* Experimental, may not be required
		$filebits = explode('.', $location);
		if (count($filebits) < 2)
		{
			return false;
		}
		$extension = end($filebits);
		$type = $this->fetchImagetypeFromExtension($extension);
		if ($type !== $magictype)
		{
			return false;
		}
		*/

		return (bool) $isImage;
	}

	final public function getExtensionFromFileheaders($location)
	{
		return $this->magicWhiteList(file_get_contents($location), true);
	}

	final public function compareExtensionToFilesignature($extension, $location)
	{
		$magictype = $this->magicWhiteList(file_get_contents($location));

		$type = $this->fetchImagetypeFromExtension($extension);
		if (!isset($this->magic_numbers_types[$type]))
		{
			$type = false;
		}

		return ($type === $magictype);
	}

	/**
	 * Determine if the given extension can have an image thumbnail. Basically
	 * an alias for isValidThumbnailExtension().
	 * Mostly for the PDF to image thumbnail handling for imagemagick.
	 *
	 * @param	String	$extension	File extension, usually from filedata.extension.
	 *
	 * @return	bool
	 */
	final public function imageThumbnailSupported($extension)
	{
		return $this->isValidThumbnailExtension($extension);
	}

	// GD will just strip exif on write after orient/rotation
	// imagemagick should go through exif, do the check & strip it if it would fail.
	abstract protected function forceRewriteImage($fileContents, $location);

	protected function skipWriteImage($fileContents, $location)
	{
		return false;
	}

	/**
	 * CALLER MUST CLEAN UP/REMOVE OLD FILE. This is to prevent the image class from removing unknown files that it
	 * didn't create.
	 */
	final public function loadImage($location)
	{
		/*
			Note
			We should never write to an unknown location, only the temp directory.
			(This means the CALLER must handle cleaning up the old data.)
			This way, no matter where this gets called in the future, it won't be able to accidentally/
			maliciously delete a core/system file, for ex.
		 */
		if (empty($location))
		{
			return false;
		}
		$location = realpath($location); // apparently windows has issues w/o full path + imagick.

		$fileContents = file_get_contents($location);
		if (empty($fileContents))
		{
			return false;
		}

		/*
			do NOT use ImageMagick identify for verifying images.
			Older versions of imagick will be vulnerable to imagetragick exploit.
		 */


		// imagetragick filetype whitelist check.
		if (!$this->magicWhiteList($fileContents) OR
			!$this->fileLocationIsImage($location)
		)
		{
			return false;
			//throw new vB_Exception_Api('upload_invalid_image');
		}

		/*
			At this point, all we know is that the file's file headers & mimetypes indicate that it is an image.
			There might still be dangerous data in the exif fields, php code in the tail, etc.
			Passing the file through GD/IM & writing it out as an image (with meta explicitly stripped in IM case) is accepted as the safe method to "clean"
			such dangerous meta data.
		 */

		 /*
			ATM we don't care if the original was safe. Only that the re-written (or file copied, in the GD animated GIF case) is safe.
		  */
		//$orig_safe = $this->verifyImageFile($fileContents, $location);

		/*
			GD Gif bypass.
		 */
		$skipWriteImage = $this->skipWriteImage($fileContents, $location);
		if ($skipWriteImage)
		{
			$newFileLocation = vB_Utilities::getTmpFileName(rand(), 'vB_');
			if (empty($newFileLocation))
			{
				// something happened (like we can't access the tempdir) and we can't get a write location.
				return false;
			}
			// Since the caller will always dump the "original" file, make a copy.
			// Could this be an issue when very large gifs are constantly uploaded?
			$try = copy($location, $newFileLocation);
			if (!$try)
			{
				@unlink($newFileLocation);
				return false;
			}
		}
		else
		{
			// This should include orient image.
			$newFileLocation = $this->forceRewriteImage($fileContents, $location);

			// forceRewriteImage() may return an empty string if something went wrong, e.g.
			// tempdir not available, imagick load failed due to corrupted image...
			if (empty($newFileLocation))
			{
				return false;
			}
		}
		// let's not refer to the old location again. That's for the caller to deal with.
		unset($location);

		// If something called us before, and didn't bother saving the data before loading a new image, kill it.
		// We might need to change this in the future.
		$this->unloadImage();
		$this->imagefilelocation = $newFileLocation;


		/*
			We've stripped EXIF, & re-written the file using GD or Imagemagick, which should hypothetically strip any non-image-y nasty bits.
			If something still remains on the newly written image file that triggers one of our security checks, kill the new file, return false
			to let the caller know to deal with the potentially dangerous original file.
		*/
		$safe = $this->verifyImageFile(file_get_contents($this->imagefilelocation), $this->imagefilelocation);
		if (!$safe)
		{
			$this->unloadImage();
			// Let's leave it to the caller to delete the *original* dangerous image.
			// I don't want to allow accidental/arbitrary deletes by this function.
			return false;
		}



		// we already check these multiple times internally, so there's probably a way to make this more efficient, but
		// not really worth the microopt ATM.
		$imgExtension = $this->getExtensionFromFileheaders($this->imagefilelocation);
		$extension_map = $this->getExtensionMap();

		$fileDataArray = array(
			// 'name' => // this would be provided by caller, but we don't care about it.
			'size'     => filesize($this->imagefilelocation),
			'type'     => 'image/' . $extension_map[$imgExtension],
			'tmp_name' => $this->imagefilelocation
		);


		return $fileDataArray;
	}

	final public function __destruct()
	{
		$this->unloadImage();
	}

	final public function unloadImage()
	{
		if (!empty($this->imagefilelocation))
		{
			@unlink($this->imagefilelocation);
		}

		$this->imagefilelocation = null;
	}

	/**
	 * Returns true if it can detect that the required libraries for supporting
	 * jpg thumbnails for PDFs are installed and available.
	 * Currently used by upgrade scripts & setting validation code to check if
	 * GhostScript is installed and configured in the delegates file when using
	 * the ImageMagick library, or attempt a sample PDF conversion when using
	 * the Imagick library.
	 * Do not add this check as part of init/startup, as it can be slow. It should
	 * only be called infrequently as required!
	 *
	 * @return	bool
	 */
	public function canThumbnailPdf()
	{
		return false;
	}

	final public function fileIsAnimatedGif($filename)
	{
		// THIS FUNCTION DOES NOT CHECK VALIDITY/SECURITY. Only that it's a gif & that it's animated.
		// Caller must verify that verifyImageFile() is called if needed.
		$extension = $this->getExtensionFromFileheaders($filename);
		if ($extension === 'gif')
		{
			return $this->is_animated_gif($filename);

		}
		else
		{
			return false;
		}
	}

	protected function is_animated_gif($filename)
	{
		/*
			This function is based on :
			http://php.net/manual/en/function.imagecreatefromgif.php#104473
			&
			https://stackoverflow.com/a/42191495

		 */
		$fh = @fopen($filename, 'rb');
		if(!$fh)
		{
			return false;
		}

		$count = 0;
		//an animated gif contains multiple "frames", with each frame having a
		//header made up of:
		// * a static 4-byte sequence (\x00\x21\xF9\x04)
		// * 4 variable bytes
		// * a static 2-byte sequence (\x00\x2C) (some variants may use \x00\x21 ?)

		// We read through the file til we reach the end of the file, or we've found
		// at least 2 frame headers
		while(!feof($fh) && $count < 2)
		{


			// TODO: What if the marker is split between 2 chunks?

			$chunk = fread($fh, 1024 * 100); //read 100kb at a time
			$count += preg_match_all('#\x00\x21\xF9\x04.{4}\x00(\x2C|\x21)#s', $chunk, $matches);

			// Edge case that I have not hit, but adding this just in case.
			// Catch the case where marker is split between 2 chunks.
			$currentPosition = ftell($fh);
			// each frame "block" is 10 bytes, so if we keep the entire last 10 bytes of this 100kb chunk, there's
			// no way a frame will end up split between 2 chunks.
			if (!feof($fh) && $count < 2)
			{
				fseek($fh, $currentPosition - 10);
			}
		}

		/*
			This method goes through the file byte-by-byte rather than larger chunks.
			Originally, this was deviced to deal with the "marker split between chunks" case & to
			avoid using preg_match_all() in a loop.
			Unfortunately, in practice, this method was about 20 ~ 60 times slower than the above
			method of doing preg_match on 100kb chunks for the unit tests.
			As such, leaving the original implementation above with a slight modification for catching
			the marker split case, and leaving below comment out unless we hit a new reason to use the
			slower method.
		 */
		/*
		while(!feof($fh) && $count < 2)
		{
			$currentPosition = ftell($fh);

			// read 1 byte, moving pointer by 1 byte
			if (fread($fh, 1) === "\x00")
			{
				// needs to be followed by \x21\xF9\x04 (block-size \x04 might be variable, but going with
				// the common practice I saw
				if (
					fread($fh, 3) === "\x21\xF9\x04"
					AND
					// ... followed by 4 bytes, though this is probably dependent on block-size, but sticking with the above \x04
					fread($fh, 4)
					AND
					// finally closing with either \x00\x2c OR \x00\x21
					$__frameEnd = fread($fh, 2) // please forgive me.
					AND ($__frameEnd === "\x00\x2C" OR $__frameEnd === "\x00\x21" )
				)
				{
					$count++;
				}
				else
				{
					// fread()'s moved the file pointer by anywhere from 3 bytes to 3+4+2 bytes after our first, outermost 1-byte read.
					// This means if the sequence just happened to be something like 00 00 21 F9 04, we'd miss that unless we check
					// single-byte at a time, so we have to rewind back.
					// Unless we've hit the end of file, rewind back to the next byte and start checking this chunk
					if (!feof($fh))
					{
						fseek($fh, $currentPosition + 1);
					}
				}
			}
		}
		*/

		fclose($fh);
		return ($count > 1);
	}

	final public function fileContentIsAnimatedGif($filecontent)
	{
		$extension = $this->magicWhiteList($filecontent, true);
		if ($extension == "gif")
		{
			$frames = preg_match_all('#\x00\x21\xF9\x04.{4}\x00(\x2C|\x21)#s', $filecontent, $matches);

			return ($frames AND $frames > 1);
		}

		return false;
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 103452 $
|| #######################################################################
\*=========================================================================*/
