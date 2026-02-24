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
* Image class wrapper for Imagick PECL library
*
* @package 		vBulletin
* @version		$Revision: 103542 $
* @date 		$Date: 2019-12-03 11:24:41 -0800 (Tue, 03 Dec 2019) $
*
*/
class vB_Image_Imagick extends vB_Image
{
	private $convert_pdfs = false;

	/**
	 * Version of Imagemagick /convert
	 * @private	string
	 */
	private $version = null;

	private $class_ready = false;

	// checkInstallation() being called multiple times per page load is a waste of time,
	// cache it locally. Need to use a static property instead of instance as we don't
	// use singletons for vB_Image classes
	private static $checkInstallationResult = array();

	/**
	* Constructor
	* Sets ImageMagick paths to convert and identify
	*
	* @return	void
	*/
	public function __construct($options, $extras = array())
	{
		parent::__construct($options, $extras);




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
			For example, GD apparently cannot resize BMP or TIFF
			(although as of PHP 7.2, GD now has imagecreatefrombmp(),
			so we should probably update the GD class)
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
			'pdf'  => false,
			'bmp'  => true,
			'tiff' => true,
			'tif'  => true,
		);

		$this->info_extensions =& $this->thumb_extensions;


		$check = static::checkInstallation();

		$this->class_ready = $check['class_exists'];

		// check ghostscript install, disable pdf thumb.
		if (!empty($this->options['imagick_pdf_thumbnail']) AND
			!empty($check['pdf_support'])
		)
		{
			// todo...
			$this->convert_pdfs = true;
			$this->addPdfMagicNumbers();

			// if thumbnailing is disabled, it's probably because
			// we don't have ghostscript pdf delegate available,
			// in which case just trying to get image info (identify)
			// on it wil also fail. So $this->info_extensions['pdf']
			// follows that of $this->thumb_extensions.
			$this->thumb_extensions["pdf"] = true;
			$this->info_extensions["pdf"] = true;
		}

	}

	private function addPdfMagicNumbers()
	{
		/*
			Note, Imagick PECL extension is also vulnerable to delegate security issues
			https://stackoverflow.com/a/37056622

			So it is recommended to maintain the whitelist checks ... .
		 */

		// PDF. imagemagick only.
		$soi = hex2bin("2550" . "4446");
		$this->magic_numbers[$soi] = array('eoi' => '', 'type' => "PDF", 'extension' => 'pdf'); // thumb will be jpg. What should we store as the "extension"?
		$two = substr($soi, 0, 2);
		$this->magic_numbers_shortcut[$two][$soi] = $this->magic_numbers[$soi];
		$this->magic_numbers_types["PDF"] = true;
	}

	public static function checkInstallation()
	{
		if (empty(static::$checkInstallationResult))
		{
			$check = array(
				'class_exists' => false,
				'supported_formats_count' => 0,
				'pdf_support' => false,
				'errors' => array(),
			);
			$check['class_exists'] = class_exists("Imagick");
			if ($check['class_exists'])
			{
				try
				{
					/*
						PHP >= 5.1.3 and ImageMagick >= 6.2.4 is required. The amount of file formats
						supported by Imagick depends entirely upon the amount of formats supported by
						your ImageMagick installation. For example, Imagemagick requires ghostscript
						to conduct PDF operations.
						- https://www.php.net/manual/en/imagick.requirements.php
						Unfortunately, queryFormats() doesn't seem to actually have any information about
						whether the particular format is fully supported (dependencies are properly
						configured).
						So even if queryFormats() returns "PDF", if ghostscript isn't installed, or if
						the delegates file for the imagemagick installation isn't pointing to ghostscript
						properly, actually trying to identify/convert a PDF will fail with an error like
						"API returned error: 'PDFDelegateFailed".
						At the moment, not sure how to check dependencies short of just keeping a minimal
						test PDF file handy so we can call identify on it and see if it errors out.
					 */
					$formats = Imagick::queryFormats();
					$check['supported_formats_count'] = count($formats);
					// Note, PDF support still needs ghostscript installed (& delegated?)
					if (!empty($formats))
					{
						$check['pdf_support'] = in_array('PDF', $formats);
					}
				}
				catch(Throwable $e)
				{
					$check['errors'][] = $e->getMessage();
				}

			}

			static::$checkInstallationResult = $check;
		}

		return static::$checkInstallationResult;
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
		if (!$this->class_ready)
		{
			return false;
		}

		if (is_null($this->version))
		{
			$result = Imagick::getVersion();
			/*
			The versions is a bit weird:
			var_dump( IMagick::getVersion()  );
			array(2) {
			  ["versionNumber"]=>
			  int(1683)
			  ["versionString"]=>
			  string(65) "ImageMagick 6.9.3-7 Q16 x86 2016-03-27 http://www.imagemagick.org"
			}

			ATM I'm not entirely sure how the "versionNumber" maps to the imagemagick API version it was built against,
			so I'm going to use the versionString and pregMatch it.
			 */
			if (!empty($result['versionString']) AND preg_match('#ImageMagick (\d+\.\d+\.\d+)#', $result['versionString'], $matches))
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
	* Retrieve info about image
	*
	* @param	string	filename	Location of file
	* @param	string	extension	Extension of file name
	*
	* @return	array	[0]           int       width
	*					[1]           int       height
	*					[2]           string    type ('GIF', 'JPEG', 'PNG', 'PSD', 'BMP', 'TIFF',) (and so on)
	*					[scenes]      int       Number of scenes
	*					[colorspace]  int       imagick::COLORSPACE_* constant (e.g. COLORSPACE_RGB,
	*                                           COLORSPACE_sRGB, COLORSPACE_CMYK etc)
	*					[bits]        int       Number of bits per pixel (bit depth)
	*					[library]     string    Library Identifier
	*
	*/
	public function fetchImageInfo($filename)
	{
		$filename = realpath($filename);

		// verifyImageFile() will call magicWhiteList to check file signature.
		// Without that check, the followup identify may be susceptible to imagetragick exploits
		$fileContents = @file_get_contents($filename);

		if (!$this->verifyImageFile($fileContents, $filename))
		{
			throw new vB_Exception_Api('invalid_file_content');
		}

		return $this->fetchImageInfoInternal($filename);
	}

	private function fetchImageInfoInternal($filename)
	{

		$image = new Imagick();

		/*
			If their version of Imagick was compiled against imagemagick 6.2.9+ they can use pingImage()
			which is apparently lightweight (based on PHP.net documentation for pingImageFile(), a function
			which is similar to pingImage() but accepts a filehandle instead of filepath).

			We're only going to support imagick 3.4.0+ since that version added PHP 7 support. The minimum
			imagemagick version for imagick3.4.0 was imagemagick 6.5.3-10. Imagick::pingImage() has been in
			imagick since 2.0.0, so I think at this point we can assume that pingImage() exists and is
			functional. Removed the version & function_exists checks.
		 */
		$image->pingImage($filename);

		$scenes = $image->getNumberImages();
		/*
			Certain formats like like PDFs & GIFs have multiple scenes.
			For gifs, different scenes can have different geometry (not sure about other
			characteristics likedepth, colorspace ETC). For some reason, by default
			the internal iterator points to the last frame, which can have the "wrong"
			dimension. This is because each scene/image is just the "difference" from
			the first frame for gifs, so if the difference is small then the geometry
			of that scene may be smaller.
			I'm not certain at this point if the first scene ever has a smaller geometry
			than the full page geometry, but I am currently assuming that does not happen.
		 */
		if ($scenes > 1)
		{
			// set to first scene which *should* have the full page width & height.
			$image->setFirstIterator();
		}

		$width = $image->getImageWidth();
		$height = $image->getImageHeight();
		// strtoupper here just to keep things consistent. As far as I can tell, all the
		// "detected" formats seem to be in upper case, but if you set the format in order to
		// convert an image via setImageFormat(), and use lower caps, the value returned is
		// in lower case.
		$type = strtoupper($image->getImageFormat());

		/*
			There doesn't seem to be just a "get number of channels" function.
			The old code used to have a hard-coded list of "image type & colorspace string"
			to # of channels (e.g. DirectClassRGB : 3, DirectClassCMYK : 4) but the list was
			very outdated (e.g. missing sRGB), and didn't consider things like RGB with
			transparency (alpha) channel having 4 channels.
			As far as I can tell, this was only used to check if a jpg image was using the CMYK
			colorspace then converting the thumbnail to RGB colorspace due to apparently Firefox & IE
			not being able to render CMYK images inline.
			However, since RGB with alpha can have 4 channels as well, this check doesn't seem very reliable.
			I'll replace it with a different check for this class.

			Edit:
			On further testing, it doesn't seem like just counting is sufficient to match the commandline
			identify outputs. E.g. for a simple sRGB png without transparency, the commandline output reports
			red, green & blue as the channels under the "channel depth" & "channel statistics" outputs.
			However, imagick's channelstatics list 6 channels, 3 of them with mean, minima & maxima like:
				[mean] => 0
				[minima] => 1.7976931348623E+308
				[maxima] => -1.7976931348623E+308
			which seem like they're not actually used. The documentation is sparse, but it might mean that we have
			to heuristically determine & filter out channels that are "unused".
			Since the # of channels is not actually useful for our purposes (as far as I can tell), and what we
			really care about is the colorspace, I've decided to drop the channels parameter and not pursue this
			further.
		 */
		/*
		$channelStats = $image->getImageChannelStatistics();
		$channels = count($channelStats);
		*/

		// https://www.php.net/manual/en/imagick.constants.php#imagick.constants.colorspace
		$colorspace = $image->getImageColorspace();

		$bits = $image->getImageDepth();

		$return = array(
			0 => $width,
			1 => $height,
			2 => $type,
			'scenes' => $scenes,
			//'channels' => $channels,
			'colorspace' => $colorspace,
			'bits' => $bits,
			'library' => 'imagick',
		);

		$image->clear();

		return $return;
	}

	public function fetchImageInfoForThumbnails($filename)
	{
		$filename = realpath($filename);
		if (empty($filename))
		{
			throw new vB_Exception_Api('invalid_file_content');
		}

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

		$extension = $this->type_to_canonical_extension[$magictype] ?? "invalid";
		// legacy imagemagick used to define a thumb_types property which seemed to be a copy of
		// thumb_extensions property... let's just use the latter here.

		if (!isset($this->thumb_extensions[$extension]))
		{
			throw new vB_Exception_Api('invalid_file_content');
		}

		/*
			SECURITY WARNING
			Note, at this point we're explicitly allowing a NON-IMAGE file to be passed into identify right here.
			We whitelisted the files, so we *should* be safe. Assuming that the current whitelist is safe.
		 */

		return $this->fetchImageInfoInternal($filename);
	}

	public function getImageFromString($string, $moveabout = true)
	{
		// used for "image library" human verification
		// Generate a random image showing the $string.

		$imageWidth = 201;
		$imageHeight = 61;

		// If moveabout, pick a random background. Otherwise apparently we just use blank canvas.
		$image = $this->fetchImageWithBackground($imageWidth, $imageHeight, $moveabout);

		if ($moveabout)
		{
			// legacy imagemagick behavior
			// swirl the background. Note that we're also going to swirl 20 after annotation.
			$image->swirlImage(mt_rand(10, 100));
		}

		// Now we should have a properly sized $image object that we can annotate.
		$this->annotateImage($image, $string, $moveabout);

		if ($moveabout AND $this->regimageoption['randomslant'])
		{
			// legacy imagemagick behavior
			$image->swirlImage(20);
		}

		// Enforce PNG for simplifying 'contentType' below
		$image->setImageFormat('PNG');

		$fileData = $image->getImageBlob();
		$fileSize = strlen($fileData);

		// return imageinfo
		return array('filedata' => $fileData, 'filetype' => 'png', 'filesize' => $fileSize, 'contentType' => 'image/png');
	}

	private function annotateImage(&$image, $string, $random)
	{
		// Default starting font (for non $random)
		$fonts = $this->fetchRegimageFonts();
		if (!empty($fonts))
		{
			$fontsKey = array_rand($fonts);
			$font = $fonts[$fontsKey];
		}
		else
		{
			$font = 'Helvetica';
		}

		// Starting values
		$x = 10;
		$y = 40;
		$slant = 0;
		$pointsize = 32;
		$r = $b = $g = 0;

		/*
			Note, we are NOT supporting multibyte characters at the moment:
			* The legacy image codes do not support MB charsets.
			* There isn't an established way to walk through an MB string by
			each character.
			* I'm not sure if imagick functions support multibyte strings.

			If $random, access each character one by one and move them around.
		 */
		$strings = array($string);
		$length = 1;
		if ($random)
		{
			$strings = $string;
			$length = strlen($string);
		}
		unset ($string);

		$draw = new ImagickDraw();
		$pixel = new ImagickPixel();
		$placeShape = 0;
		$shapeDraw = new ImagickDraw();
		$shapePixel = new ImagickPixel();
		for ($i = 0; $i < $length; $i++)
		{
			$string = $strings[$i];

			if ($random)
			{
				if ($this->regimageoption['randomfont'] AND !empty($fonts))
				{
					$fontsKey = array_rand($fonts);
					$font = $fonts[$fontsKey];
				}


				/*
					GD does a random (-20, 60) slant for each character, but no swirl.
					Legacy Imagemagick does a swirl on the background, slant the 1st & 5th character,
					(presumably these functions are tuned for 5 character "HV answers"?)
					then swirls again at the end. Apparently the reason why the 2-4 characters are
					not slanted is because slant + swirl 20 looks bad.
					However, when I'm testing it for some reason just slanting the 1st & 5th doesn't
					look very good (not very random?), so for now I'm going to go with slanting
					every character.
				 */
				// todo: annotateImage()'s $angle parameter is poorly documented. It's a float
				// but it's unclear what its units are (degrees? radians? percentage?)
				$slant = $this->regimageoption['randomslant'] ? mt_rand(-20, 60) : 0;

				$pointsize =  $this->regimageoption['randomsize'] ? mt_rand(20, 32) : 24;

				if ($this->regimageoption['randomcolor'] OR empty($r))
				{
					// Generate a random color..
					$r = mt_rand(50, 200);
					$g = mt_rand(50, 200);
					$b = mt_rand(50, 200);
				}

				// Y Axis position, random from 32 to 48
				$y = mt_rand(32, 48);

				if ($this->regimageoption['randomshape'])
				{
					// before or after
					$placeShape = mt_rand(1, 2);

					$shapeDraw->clear();

					// Stroke Width, 1 or 2
					$shapeDraw->setStrokeWidth(mt_rand(1, 2));

					// Pick a random color
					$shapeR = mt_rand(50, 200);
					$shapeG = mt_rand(50, 200);
					$shapeB = mt_rand(50, 200);
					$shapePixel->setColor("rgb($shapeR,$shapeG,$shapeB)");
					$shapeDraw->setStrokeColor($shapePixel);
					$shapeDraw->setFillOpacity(0);

					// shape placement boundaries
					$maxCanvasWidth = 200;
					$maxCanvasHeight = 60;

					// Pick a Shape
					$shape = mt_rand(1, 5);
					$x1 = mt_rand(0, $maxCanvasWidth);
					$y1 = mt_rand(0, $maxCanvasHeight);
					$x2 = mt_rand(0, $maxCanvasWidth);
					$y2 = mt_rand(0, $maxCanvasHeight);
					$start = mt_rand(0, 360);
					$end = mt_rand(0, 360);
					switch($shape)
					{
						case 1:
							$width = abs($x2 - $x1);
							$height = abs($y2 - $y1);
							/*
								rx and ry are basically how far from the "center" of the top/bottom and left/right,
								respectively, the "rounding" begins, not "corner radiuses".
								Essentially, Rx makes the top/bottom more rounded and can range from 0 to width/2,
								while Rx makes the left/right more rounded and can range from 0 to height/2
								You can test this visually with
								https://phpimagick.com/ImagickDraw/roundRectangle
							 */
							$rx = mt_rand(0, $width);
							$ry = mt_rand(0, $height);
							$shapeDraw->roundRectangle($x1, $y1, $x2, $y2, $rx, $ry);
							break;
						case 2:
							//$shape = "\"arc $x1,$y1 $x2,$y2 20,15\"";
							$shapeDraw->arc($x1, $y1, $x2, $y2, $start, $end);
							break;
						case 3:
							$shapeDraw->ellipse($x1, $y1, $x2, $y2, $start, $end);
							break;
						case 4:
							$shapeDraw->line($x1, $y1, $x2, $y2);
							break;
						case 5:
							$corners = array(
								array('x' => $x1, 'y' => $y1),
								array('x' => $x2, 'y' => $y2),
							);
							$n = mt_rand(4, 6);
							for ($j = 2; $j < $n; $j++)
							{
								$corners[] = array(
									'x' => mt_rand(0, $maxCanvasWidth),
									'y' => mt_rand(0, $maxCanvasHeight),
								);
							}
							$shapeDraw->polygon($corners);
							break;
					}
				}
			}

			$pixel->setColor("rgb($r,$g,$b)");
			//$draw->setStrokeColor($pixel);
			$draw->setFillColor($pixel);

			$draw->setFont($font);
			$draw->setFontSize($pointsize);

			if ($placeShape === 1)
			{
				$image->drawImage($shapeDraw);
			}

			/* Write the text on the image */
			$image->annotateImage( $draw, $x, $y, $slant, $string );

			if ($placeShape === 2)
			{
				$image->drawImage($shapeDraw);
			}

			// apparently x always processes by 25~35 random units even when $random = false
			$x += rand(25, 35);

		}

	}


	private function fetchImageWithBackground($imageWidth, $imageHeight, $randomBackground)
	{
		$defaultBackground = 'white';
		$backgroundFetched = false;
		if ($randomBackground)
		{
			$backgrounds = $this->fetchRegimageBackgrounds();

			do
			{
				$index = array_rand($backgrounds);
				$background = realpath($backgrounds[$index]);
				try
				{
					$image = new Imagick($background);
					if ($image->getImageWidth() AND $image->getImageHeight())
					{
						$backgroundFetched = true;
					}
					else
					{
						$image->clear();
					}
				}
				catch(Throwable $e)
				{
					// If there was an error with initializing the background image, let's just move on.
					unset($backgrounds[$index]);
				}
			}
			while (!$backgroundFetched AND !empty($backgrounds));

			// We want to unset the original filename because if we loaded a background image, doing
			// $image->writeImage(Null); will ovewrite that original file. We're passing the $image
			// object out, so we have no way to control what the caller does with it, so we should
			// take this precaution.
			if ($backgroundFetched)
			{
				// Initially I tried creating a temp file and setting that here, but
				// that just ended up needlessly creating empty tmpfiles every time
				// the HV image generation was invoked.
				// From what I can tell of the documentation,
				// http://magickwand.org/MagickWriteImage.html ,
				// http://magickwand.org/MagickSetImageFilename.html , and unit tests,
				// we can set an empty string as the filename, and that will prevent
				// writing back to the original file.
				$image->setImageFilename('');
			}
		}

		if (!$backgroundFetched)
		{
			$image = new Imagick();
			$bg = new ImagickPixel();
			$bg->setColor($defaultBackground);

			$image->newImage($imageWidth, $imageHeight, $bg);
			$image->setImageFormat('PNG');
		}
		else
		{
			if (
				$image->getImageWidth() != $imageWidth
				OR $image->getImageHeight() != $imageHeight
			)
			{
				// Due to development overhead required, I'm going to assume that we
				// currently do not support animated gif background images for this.
				// If this changes, see code in cropImg() for example where we have
				// to loop through each scene & resize/crop independently in order to
				// not lose the animation.
				//$type = strtoupper($image->getImageFormat());

				$image->resizeImage($imageWidth, $imageHeight, Imagick::FILTER_LANCZOS, 1);
			}

			//$image->setImageCompressionQuality(100);
			$this->rotateImageAndStripExif($image);
		}


		return $image;
	}


	/**
	*
	* Returns an array containing a thumbnail, creation time, thumbnail size and any errors
	*
	* @param	string	filename	UNUSED
	* @param	string	location	location of the source file
	* @param	int		maxwidth
	* @param	int		maxheight
	* @param	int		quality		Jpeg Quality
	* @param bool		labelimage	Include image dimensions and filesize on thumbnail
	* @param bool		drawborder	Draw border around thumbnail
	* @param	bool	jpegconvert
	* @param	bool	sharpen
	* @param	int 	owidth
	* @param	int		oheight
	* @param			ofilesize
	*
	* @return	array
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
		// Legacy image libraries used this to detect extension and do some things with it like
		// ensure the stated extension matches the filetype detected...
		unset($filename);

		$location = realpath($location);

		/*
		fetchImageInfoForThumbnails() will check magictype against $this->thumb_extensions &
		throw an invalid_file_content exception before it calls fetchImageInfoInternal(),
		so we're skipping this.
		If we want this function to have more granular/detailed exceptions, we should re-instate
		this check.

		$magictype = $this->magicWhiteList(file_get_contents($location));
		$magicExtension = $this->type_to_canonical_extension[$magictype] ?? "invalid";

		if ($this->isValidThumbnailExtension($magicExtension))
		{
			throw new vB_Exception_Api('thumbnail_nosupport');
		}
		 */

		try
		{
			$imageinfo = $this->fetchImageInfoForThumbnails($location);
		}
		catch (Throwable $e)
		{
			$imageinfo = null;
		}

		if (empty($imageinfo))
		{
			throw new vB_Exception_Api('thumbnail_nosupport');
		}


		/*
			todo, reinstate following?:

			if ($this->fetchImagetypeFromExtension(file_extension($filename)) != $imageinfo[2])
			{
				throw new vB_Exception_Api('thumbnail_notcorrectimage');
			}
		 */


		$type = $imageinfo[2];
		$thumbnail = array(
			'filedata'   => '',
			'filesize'   => 0,
			'dateline'   => 0,
			'imageerror' => '',
			'source_width' => $imageinfo[0],
			'source_height' => $imageinfo[1],
			'type' => $type,
		);

		$needToThumbnail = (
			$imageinfo[0] > $maxwidth OR
			$imageinfo[1] > $maxheight OR
			$this->fetchMustConvert($type) OR
			($jpegconvert AND $type !== 'JPG')
		);

		// in case of $jpegconvert = true, we could have a case where the image is already at or smaller
		// than the specified dimensions, but we need to convert anyways. Avoid enlarging the image.
		$maxwidth = min($maxwidth, $imageinfo[0]);
		$maxheight = min($maxheight, $imageinfo[1]);

		if (!$needToThumbnail)
		{
			// TODO: force rewrite image?????
			// This is usually only called by the content_attach api/lib on an
			// already-re-written image, but we need a way to ensure that...
			// Maybe a "force rewrite" flag on this function?
			$thumbnail['filedata'] = @file_get_contents($location);
			$thumbnail['width'] = $imageinfo[0];
			$thumbnail['height'] = $imageinfo[1];
			$thumbnail['filesize'] = strlen($thumbnail['filedata']);
			$thumbnail['dateline'] = vB::getRequest()->getTimeNow();

			return $thumbnail;
		}


		// begin resize
		/*
		There's are thumbnailImage(), scaleImage(), and resizeImage() functions...
		which is best?
		One comment states resizeImage() suprisingly produces smaller file-sizes,
		while scaleImage() may apparently cause additional blurring(?) but thumbnailImage()
		seems simplest.

		Note, resizeImage($columns, $rows) with either $columns or $rows set to 0 will do
		a proportional resize (no squishing) but we have to specify our own filter & blur
		explicitly.

		Update: In order to preserve EXIF data, we must use resizeImage() instead of
		thumbnailImage() ( https://stackoverflow.com/a/23181112 )
		 */

		// For pdfs and the like with multiple scenes, let's just go with the first page.
		//if ($imageinfo['scenes'] > 1)
		// Edit: legacy code only limited the thumbnail to the first scene for PSD & PDF, not GIF.
		// Legacy behavior: if PSD or PDF, always limit to first scene.
		// If others (e.g. GIF) with multiple scenes, let's only go with the first scene iff we're
		// converting it to JPG.
		if (
			$type == 'PSD' OR
			$type == 'PDF' OR
			($imageinfo['scenes'] > 1 AND $jpegconvert)
		)
		{
			$location .= '[0]';

		}

		$image = new Imagick($location);

		// Deal with animated gifs
		if ($imageinfo['scenes'] > 1 AND !$jpegconvert)
		{
			// Source: https://stackoverflow.com/a/19469380
			$image = $image->coalesceImages();
			do
			{
				// todo: how to handle labeling gifs? Do we really want to label every frame?
				$this->thumbnailImageInternal(
					$image,
					$imageinfo,
					$maxwidth,
					$maxheight,
					$labelimage,
					$drawborder,
					$jpegconvert,
					$sharpen,
					$owidth,
					$oheight,
					$ofilesize
				);
			} while ($image->nextImage());
			$image = $image->deconstructImages();

			$thumbnail['filedata'] = $image->getImagesBlob();
			// reset iterator so dimensions refer to the first scene (important for gifs)
			$image->setFirstIterator();
		}
		else
		{
			$quality = max(0, min(100, $quality));
			$image->setImageCompressionQuality($quality);

			$this->thumbnailImageInternal(
				$image,
				$imageinfo,
				$maxwidth,
				$maxheight,
				$labelimage,
				$drawborder,
				$jpegconvert,
				$sharpen,
				$owidth,
				$oheight,
				$ofilesize
			);

			// we can get the raw blob or writeImage() to the temp location.
			// apparently this can take a while.
			$thumbnail['filedata'] = $image->getImageBlob();
		}


		$thumbnail['width'] = $image->getImageWidth();
		$thumbnail['height'] = $image->getImageHeight();
		$thumbnail['filesize'] = strlen($thumbnail['filedata']);
		$thumbnail['dateline'] = vB::getRequest()->getTimeNow();
		$thumbnail['type'] = strtoupper($image->getImageFormat());

		return $thumbnail;
	}

	private function thumbnailImageInternal(
		&$image,
		$imageinfo,
		$maxwidth,
		$maxheight,
		$labelimage,
		$drawborder,
		$jpegconvert,
		$sharpen,
		$owidth,
		$oheight,
		$ofilesize
	)
	{
		// todo: is it better to thumbnail THEN sharpen etc, or other way around?
		// I think sharpening before thumbnailing it might be weird... but we'll have to see.
		if ($this->preserveExif)
		{
			$image->resizeImage($maxwidth, $maxheight, Imagick::FILTER_LANCZOS, 1, true);
		}
		else
		{
			$image->thumbnailImage($maxwidth, $maxheight, true);
		}

		/*
			UNIMPLEMENTED.
			ATM nothing calls this function with $labelimage == true, and we'll be deprecating $labelimage for the other
			image classes.
		 */
		if ($labelimage AND false)
		{
			// todo
			//$image->annotateImage(...);
			$owidth = intval($owidth ?? $imageinfo[0]);
			$oheight = intval($oheight ?? $imageinfo[1]);
			$dimensions = $owidth . 'x' . $oheight;
			$ofilesize = intval($ofilesize ?? @filesize($location));
			$sizestring = vb_number_format($ofilesize, 0, true);

			/*
			// "$dimensions $sizestring $type";
			// TODO: determine based on image size (width)? whether it's best to try to fit
			// all 3 component, or just the first 2 or 1 component(s).
			// annotation string like 100x200 40KB png
			$draw = new ImagickDraw();
			$draw->setStrokeColor

			// confusing -flip statements added to workaround an issue with very wide yet short images. See http://www.imagemagick.org/discourse-server/viewtopic.php?t=10367
					$execute .= " -flip -background \"{$this->thumbcolor}\" -splice 0x15 -flip -gravity South -fill white  -pointsize 11 -annotate 0 \"$finalstring\" ";
			*/
		}

		// Note, currently the border goes *outside* of the image, causing the size to be 1px larger on each edge.
		if ($drawborder)
		{
			// default $thumbcolor property in other image classes
			$borderColor = 'black';
			// hard-coded border size
			$borderHeight = $borderWidth = 1;
			$image->borderImage($borderColor, $borderWidth, $borderHeight);
		}

		if ($jpegconvert OR $this->fetchMustConvert($imageinfo[2]))
		{
			// Handle alpha channels turning into black backgrounds
			// source: https://www.php.net/manual/en/imagick.flattenimages.php#116665
			$image->setImageBackgroundColor('white');
			$image->setImageAlphaChannel(imagick::ALPHACHANNEL_REMOVE);
			$image->mergeImageLayers(imagick::LAYERMETHOD_FLATTEN);

			$image->setImageFormat('JPG');
		}

		if ($sharpen)
		{
			// we have a choice of adaptiveSharpenImage() (v6.2.9+) or sharpenImage()
			// first one might be more interesting / higher quality, but we'd probably need
			// some live testing...
			$radius = 0;
			$sigma = 1;
			$image->sharpenImage($radius, $sigma);
		}

		/*
		$tmpname = vB_Utilities::getTmpFileName('', 'vbimagick');
		if (!$tmpname)
		{
			throw new vB_Exception_Api('thumbnail_nogetimagesize');
		}
		*/

		// Remove meta data, but keep rotation.
		// todo: test this.
		$this->rotateImageAndStripExif($image);
	}

	/*
	 * 	@param  array $imgInfo contains all the required information
	 * 	* filename
	 * 	* width
	 * 	* height
	 * 	* x1		Note, x & y coordinates are from top left corner.
	 * 	* y1
	 * 	@param  int   $maxwidth
	 * 	@param  int   $maxheight
	 * 	@param  bool  $forceResize force generation of a new file. Badly named, but is actually the flag
	 *                             to force cropping *without* resizing.
	 *
	 *	@return	mixed	array of data with the cropped image info:
	 *	* width
	 *	* height
	 *	* filedata
	 *	* filesize
	 *	* dateline
	 */
	public function cropImg($imgInfo, $maxwidth = 100, $maxheight = 100, $forceResize = false)
	{
		$thumbnail = array(
			'filedata'   => '',
			'filesize'   => 0,
			'dateline'   => 0,
			'imageerror' => '',
		);

		/*
			ATM imgInfo comes with filename & filedata, and the only caller (vB_Library_User::uploadAvatar())
			currently calls loadImage() in order to rewrite the image into a tmp file and passes that around.
			So In usage, the two should be pointing to the same data, but it's still not great design since
			at the end of the day this function has to make a decision on which we're going to take.
			The legacy code does some weird stuff, which is to take the filedata & write it into the file at filename,
			which I don't quite agree with. Let's just keep one and drop the other and not do any weird overwriting.

		 */

		$filename = realpath($imgInfo['filename']);
		$width = $imgInfo['width'];
		$height = $imgInfo['height'];
		$x1 = $imgInfo['x1'];
		$y1 = $imgInfo['y1'];

		// Unsetting this isn't to help with memory (it won't free up memory because the caller still holds the
		// filedata in memory...) but let's just not use unreliable caller data.
		unset($imgInfo);

		// Legacy behavior, only accept "supported extensions". Modified slightly to "supported types" ignoring
		// the "provided extension" that legacy code used to check since file extensions can be spoofed.
		$magictype = $this->magicWhiteList(file_get_contents($filename));
		$magicExtension = $this->type_to_canonical_extension[$magictype] ?? "invalid";
		if (!$this->isValidThumbnailExtension($magicExtension))
		{
			throw new vB_Exception_Api('thumbnail_nosupport');
		}

		try
		{
			$image = new Imagick($filename);
		}
		catch (Throwable $e)
		{
			// This may be an ImagickException if the image at $location is corrupted, for example.
			// Very unlikely to occur in the wild, as the caller should've put the file through other checks
			// already which would've already caught this & thrown a 'dangerous_image_rejected' error.
			throw new vB_Exception_Api('upload_invalid_image');
		}

		$scenes = $image->getNumberImages();
		if ($scenes > 1)
		{
			$image->setFirstIterator();
		}
		$thumbnail['source_width'] = $image->getImageWidth();
		$thumbnail['source_height'] = $image->getImageHeight();
		$type = strtoupper($image->getImageFormat());


		if ($forceResize OR $width >= $maxwidth OR $height >= $maxheight)
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

			if ($scenes > 1)
			{
				// Meant for cropping animated gifs.
				// Heavily sourced from https://www.php.net/manual/en/imagick.coalesceimages.php#110393
				$image = $image->coalesceImages();
				do
				{
					$image->cropImage($width, $height, $x1, $y1);
					if ($xratio != 1 AND $yratio != 1)
					{
						$image->resizeImage($new_width, $new_height, Imagick::FILTER_LANCZOS, 1);
					}
					// Apparently when cropping gifs, there can be issues with blank space due to
					// retaining original canvas/page
					// https://www.php.net/manual/en/imagick.cropimage.php#97232
					$image->setImagePage($new_width, $new_height, 0, 0);
				} while ($image->nextImage());
				$image = $image->deconstructImages();

				$thumbnail['filedata'] = $image->getImagesBlob();
				$image->setFirstIterator();
			}
			else
			{
				$image->cropImage($width, $height, $x1, $y1);
				// only resize if we have to. Most times we just want to crop.
				if ($xratio != 1 AND $yratio != 1)
				{
					// Filter selection is based on hearsay that Lanczos is slow but high quality (minimal artifacts).
					// Going for quality over speed for now.
					// Blur = 1 (> 1 is blurry, < 1 is sharp)
					$image->resizeImage($new_width, $new_height, Imagick::FILTER_LANCZOS, 1);
				}
				$thumbnail['filedata'] = $image->getImageBlob();
			}

			$thumbnail['width'] = $image->getImageWidth();
			$thumbnail['height'] = $image->getImageHeight();
		}
		else
		{
			// image is a thumbnail size already
			if ($width > 0 AND $height > 0)
			{
				$thumbnail['filedata'] = @file_get_contents($filename);
				$thumbnail['width'] = $width;
				$thumbnail['height'] = $height;
			}
			else
			{
				throw new vB_Exception_Api('thumbnail_nogetimagesize');
			}
		}


		if (!empty($thumbnail['filedata']))
		{
			$thumbnail['filesize'] = strlen($thumbnail['filedata']);
			$thumbnail['dateline'] = vB::getRequest()->getTimeNow();
		}

		return $thumbnail;
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
		$newfile = realpath($newfile);
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

		/*
			It might be preferred by some users if we could go through each exif tag and individually strip
			"problematic" ones, but AFAIK there's only a way to fully strip meta data /entire exif profile, but not
			individual exif tags.
		 */
		//http://stackoverflow.com/questions/13646028/how-to-remove-exif-from-a-jpg-without-losing-image-quality

		// Caller must ensure $location holds $fileContents data. We pass both around mainly out of convenience,
		// and we need one or the other for this function.
		unset($fileContents);
		$location = realpath($location);
		try
		{
			$image = new Imagick($location);
		}
		catch (Throwable $e)
		{
			// This may be an ImagickException if the image at $location is corrupted, for example.
			return "";
		}

		/*
			Maintain old behavior, explicitly convert PSD & PDF to jpegs.
			$imageinfo[2] == 'PSD' OR $imageinfo[2] == 'PDF'
			TODO: pre-check the format & only pull first page for PDF via "{$location}[0]" suffix?
		 */
		$type = strtoupper($image->getImageFormat());
		if ($type === 'PSD' OR $type === 'PDF')
		{
			// Handle alpha channels turning into black backgrounds
			// source: https://www.php.net/manual/en/imagick.flattenimages.php#116665
			$image->setImageBackgroundColor('white');
			$image->setImageAlphaChannel(imagick::ALPHACHANNEL_REMOVE);
			$image->mergeImageLayers(imagick::LAYERMETHOD_FLATTEN);

			$image->setImageFormat('JPG');
		}

		if ($type === 'GIF')
		{
			// Source: https://stackoverflow.com/a/19469380
			$image = $image->coalesceImages();
			do
			{
				// we can resize each image in the sequence like so:
				//$image->resizeImage(120, 120, Imagick::FILTER_BOX, 1);

				/*
					It's unclear if we need to individually set this on every
					single image, or if just one is sufficient... I'm also
					entirely unclear on whether the few gif-supported meta data
					like comments can even be set on a single frame, or just the
					entire image, and how imagick treats it...

					According to the magickwand docs (http://www.magickwand.org/MagickStripImage.html):
						bool MagickStripImage( MagickWand mgck_wnd )
						Strips the current active image of all profiles and comments.
					It references the "current active image", so I'm going to assume that
					it's better to iterate & strip from each image.
				 */

				// GIFs do not compress like static images, and manually setting this to 100
				// does very weird things (bloat size). TODO: test that not explicitly setting
				// 100 visually degrades gifs.
				//$image->setImageCompressionQuality(100);
				$this->rotateImageAndStripExif($image);
			} while ($image->nextImage());
			$image = $image->deconstructImages();

			/*
				todo: are there any other images with multiple scenes than GIFs that require us to call
				writeImages(..., true)?
			 */
			$check = $image->writeImages($newfile, true);
		}
		else
		{
			/*
				Setting this to 100 causes serious image size bloat (VBV-19814).
				We skipped this param in the legacy imagemagick code & let the underlying
				libraries handle it automatically, which they can do better than we can
				with the hamfisted "100 quality".
			 */
			//$image->setImageCompressionQuality(100);
			$this->rotateImageAndStripExif($image);
			/*
				Note: there are some reports that this doesn't work for mysterious reasons, and
				either doing $image->writeImageFile(...), or
				file_put_contents($newfile, $image->getImageBlob()) may be more reliable.
				I guess we'll see if anyone reports weird issues in the wild.
			 */
			$check = $image->writeImage($newfile);
		}

		if (!$check)
		{
			return "";
		}

		$image->clear();

		return $newfile;
	}

	private function rotateImageAndStripExif(&$image)
	{
		// Source: https://www.php.net/manual/en/imagick.getimageorientation.php#111448

		$orientation = $image->getImageOrientation();

		switch($orientation)
		{
			case imagick::ORIENTATION_BOTTOMRIGHT:
				$image->rotateimage("#000", 180); // rotate 180 degrees
				break;
			case imagick::ORIENTATION_RIGHTTOP:
				$image->rotateimage("#000", 90); // rotate 90 degrees CW
				break;
			case imagick::ORIENTATION_LEFTBOTTOM:
				$image->rotateimage("#000", -90); // rotate 90 degrees CCW
				break;
			default:
				// no rotation
				break;
		}

		// Apparently after rotation, the image page isn't automatically rotated too.
		// https://www.php.net/manual/en/imagick.rotateimage.php#119455
		$image->setImagePage($image->getImageWidth(), $image->getImageHeight(), 0, 0);

		// After rotating, we need to reset the orientation exif data
		$image->setImageOrientation(imagick::ORIENTATION_TOPLEFT);

		if ($this->preserveExif)
		{
			return;
		}

		// Strip all meta data
		$image->stripImage();

	}

	/**
	*
	* See function definition in vB_Image
	*
	*/
	public function canThumbnailPdf()
	{
		// todo: figure out a way to reduce duplicate code between this & diagnostics()

		$check = static::checkInstallation();
		if (!$check['class_exists'] OR !empty($check['errors']) OR empty($check['pdf_support']))
		{
			return false;
		}

		$sampleFile = realpath(DIR . '/images/regimage/misc/sample.pdf');
		if (!file_exists($sampleFile))
		{
			// If the sample file is missing we can't perform the check.
			return false;
		}

		try
		{
			$image = new Imagick();
			$image->readImage($sampleFile . '[0]');
			$image->setImageFilename('');
			$image->setImageFormat('PNG');
			$fileData = $image->getImageBlob();
			$image->clear();
			unset($image);
			if (!empty($fileData))
			{
				return true;
			}
		}
		catch (Throwable $e)
		{
		}

		return false;
	}

	public static function diagnostics()
	{
		$data = array(
			'pdf_thumbnail_sample' => '',
			'errors' => array(),
		);
		/*
			imagick requires 3 things for thumbnailing PDF.
			* PDF has to be a supported format in queryFormats()
			* ghostscript is installed
			* imagemagick delegates are correctly set for PDF
		 */
		$check = static::checkInstallation();
		if (!$check['class_exists'])
		{
			$data['errors'][] = 'Imagick class was not found. Is the Imagick extension installed?';

			return $data;
		}
		if (!empty($check['errors']))
		{
			$data['errors'][] = "Querying for Imagick supported formats failed with the following errors:\n"
				. implode("\n", $check['errors']);

			return $data;
		}

		$commonFormats = array(
			'JPEG',
			'GIF',
			'PNG',
			'BMP',
			'TIFF',
			// PDF checked separately below, look for $check['pdf_support']
			/*
			todo: will we support these in the future?
			'PSD',
			'SVG',
			 */
		);
		foreach ($commonFormats AS $__format)
		{
			$__check = Imagick::queryFormats($__format);
			if (empty($__check))
			{
				$data['errors'][] = "Common image format {$__format} not supported by the current installation of the Imagick extension."
				. " This may cause problems when this image type is uploaded.";
			}
		}


		$tmpname = vB_Utilities::getTmpFileName('', 'vbimagick');
		if (!$tmpname)
		{
			$data['errors'][] = 'Fetching a temporary filename failed. This will cause various problems in image processing.';

			return $data;
		}

		/*
		I had some thoughts about executing ghostscript directly to see if it exists, but it may
		not be available on the current environment/path. Furthermore, if using imagick, we may not
		know where imagemagick executable is located either, so we can't scan its delegates output
		like in vB_Image_Imagemagick to try to fetch the ghostscript executable path either.
		As such, we're going with the option of "just try it and see if it errors out" approach.
		*/

		$sampleFile = realpath(DIR . '/images/regimage/misc/sample.pdf');
		if (!file_exists($sampleFile))
		{
			$data['errors'][] = 'Failed to find the sample PDF file under images/regimage/misc/sample.pdf . Cannot test PDF features.';

			return $data;
		}

		if (empty($check['pdf_support']))
		{
			$data['errors'][] = 'PDF filetype is not supported by the current installation of the Imagick extension.';
		}
		else
		{
			try
			{
				/*
					todo: currently the PDF thumbnails are pretty low quality.
					Might want to poke around setResolution() & setImageQuality() functions
					to see if we can improve them.
				 */
				$image = new Imagick();
				//$image->setResolution(72, 72);
				// 300x300 gives pretty high quality, but we need to set the width/height as well.
				//$image->setResolution(300, 300);
				$image->readImage($sampleFile . '[0]');
				$image->setImageFilename('');
				$image->setImageFormat('PNG');
				$fileData = $image->getImageBlob();
				$data['pdf_thumbnail_sample'] = $fileData;
				$image->clear();
				unset($image);
			}
			catch (Throwable $e)
			{
				$data['errors'][] = "Imagick API returned an error when processing a PDF:\n" . $e->getMessage();
			}
		}


		return $data;
	}

}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 103542 $
|| #######################################################################
\*=========================================================================*/
