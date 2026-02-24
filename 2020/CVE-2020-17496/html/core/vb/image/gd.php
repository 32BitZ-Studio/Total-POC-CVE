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
* Image class for GD Image Library
*
* @package 		vBulletin
* @version		$Revision: 102901 $
* @date 		$Date: 2019-09-23 19:29:15 -0700 (Mon, 23 Sep 2019) $
*
*/
class vB_Image_GD extends vB_Image
{
	/**
	 * @var string
	 */
	//this used to be overridden by an admin option.  It's still technically used in this
	//class for the border and labels of thumbnails, but we never actually call the
	//function with the border and labels options true.  For now leave hardcoded
	//in case we do use those.  If we need to make the color an option again all we need
	//to do is override this in the constructor.
	protected $thumbcolor = array(
		'r' => 0,
		'b' => 0,
		'g' => 0
	);

	/**
	* Constructor. Sets up resizable types, extensions, etc.
	*
	* @return	void
	*/
	public function __construct($options, $extras = array())
	{
		parent::__construct($options, $extras);

		$this->info_extensions = array(
			'gif'  => true,
			'jpg'  => true,
			'jpe'  => true,
			'jpeg' => true,
			'png'  => true,
			'psd'  => true,
			'bmp'  => true,
			'tiff' => true,
			'tif'  => true,
		);

		$this->thumb_extensions = array(
			'gif'  => true,
			'jpg'  => true,
			'jpe'  => true,
			'jpeg' => true,
			'png'  => true,
		);

		$this->resize_types = array(
			'JPEG' => true,
			'PNG'  => true,
			'GIF'  => true,
		);
	}

	/**
	*
	* Output an image
	*
	* @param	object    $image      Image file to convert. Will be destroyed!
	* @param	string    $type       Output image type
	* @param	bool      $headers    [DEPRECATED]	Generate image header
	* @param	int       $quality    Jpeg Quality. Not used if $type != 'JPEG'
	* @param	string    $filename   Optional. File write destination. If not provided, image stream will be output directly.
	*
	* @return	void
	*
	*/
	// ###################### Start printImage #######################
	protected function printImage(&$image, $type = 'JPEG', $headers = true, $quality = 75, $filename = null)
	{
		// Determine what image type to output
		switch($type)
		{
			case 'GIF':
				if (!IMAGEGIF)
				{
					if (IMAGEJPEG)
					{
						$type = 'JPEG';
					}
					else if (IMAGEPNG)
					{
						$type = 'PNG';
					}
					else // nothing!
					{
						imagedestroy($image);
						return false;
					}
				}
				break;

			case 'PNG':
				if (!IMAGEPNG)
				{
					if (IMAGEJPEG)
					{
						$type = 'JPEG';
					}
					else if (IMAGEGIF)
					{
						$type = 'GIF';
					}
					else // nothing!
					{
						imagedestroy($image);
						return false;
					}
				}
				break;

			default:	// JPEG
				if (!IMAGEJPEG)
				{
					if (IMAGEGIF)
					{
						$type = 'GIF';
					}
					else if (IMAGEPNG)
					{
						$type = 'PNG';
					}
					else // nothing!
					{
						imagedestroy($image);
						return false;
					}
				}
				else
				{
					$type = 'JPEG';
				}
				break;
		}

		switch ($type)
		{
			case 'GIF':
				imagesavealpha($image, true);
				imagealphablending($image, false);
				imagegif($image, $filename);
				imagedestroy($image);
				return 'gif';

			case 'PNG':
				imagesavealpha($image, true); // preserve transparency
				imagealphablending($image, false); // must be off to use savealpha
				imagepng($image, $filename);
				imagedestroy($image);
				return 'png';

			case 'JPEG':
				imagejpeg($image, $filename, $quality);
				imagedestroy($image);
				return 'jpg';

			default:
				imagedestroy($image);
				return false;
		}
	}

	////////////////////////////////////////////////////////////////////////////////////////////////
	////
	////                  p h p U n s h a r p M a s k
	////
	////		Original Unsharp mask algorithm by Torstein H�nsi 2003.
	////		thoensi@netcom.no
	////		Formatted for vBulletin usage by Freddie Bingham
	////
	///////////////////////////////////////////////////////////////////////////////////////////////
	/**
	*
	* Sharpen an image
	*
	* @param	object		finalimage
	* @param	int			float
	* @param	radius		float
	* @param	threshold	float
	*
	* @return	void
	*/
	protected function unsharpmask(&$finalimage, $amount = 50, $radius = 1, $threshold = 0)
	{
		// $finalimg is an image that is already created within php using
		// imgcreatetruecolor. No url! $img must be a truecolor image.

		// Attempt to calibrate the parameters to Photoshop:
		if ($amount > 500)
		{
			$amount = 500;
		}
		$amount = $amount * 0.016;
		if ($radius > 50)
		{
			$radius = 50;
		}
		$radius = $radius * 2;
		if ($threshold > 255)
		{
			$threshold = 255;
		}

		$radius = abs(round($radius)); 	// Only integers make sense.
		if ($radius == 0)
		{
			return true;
		}

		$w = imagesx($finalimage);
		$h = imagesy($finalimage);
		$imgCanvas = imagecreatetruecolor($w, $h);
		$imgBlur = imagecreatetruecolor($w, $h);

		// Gaussian blur matrix:
		//
		//	1	2	1
		//	2	4	2
		//	1	2	1
		//
		//////////////////////////////////////////////////

		$gdinfo = gd_info();
		if (function_exists('imageconvolution') && strstr($gdinfo['GD Version'], 'bundled'))
		{
			$matrix = array(
				array( 1, 2, 1 ),
				array( 2, 4, 2 ),
				array( 1, 2, 1 )
			);
			imagecopy ($imgBlur, $finalimage, 0, 0, 0, 0, $w, $h);
			imageconvolution($imgBlur, $matrix, 16, 0);
		}
		else
		{
			// Move copies of the image around one pixel at the time and merge them with weight
			// according to the matrix. The same matrix is simply repeated for higher radii.
			for ($i = 0; $i < $radius; $i++)
			{
				imagecopy ($imgBlur, $finalimage, 0, 0, 1, 0, $w - 1, $h); // left
				imagecopymerge ($imgBlur, $finalimage, 1, 0, 0, 0, $w, $h, 50); // right
				imagecopymerge ($imgBlur, $finalimage, 0, 0, 0, 0, $w, $h, 50); // center
				imagecopy ($imgCanvas, $imgBlur, 0, 0, 0, 0, $w, $h);

				imagecopymerge ($imgBlur, $imgCanvas, 0, 0, 0, 1, $w, $h - 1, 33.33333 ); // up
				imagecopymerge ($imgBlur, $imgCanvas, 0, 1, 0, 0, $w, $h, 25); // down
			}
		}

		if($threshold > 0)
		{
			// Calculate the difference between the blurred pixels and the original
			// and set the pixels
			for ($x = 0; $x < $w - 1; $x++) // each row
			{
				for ($y = 0; $y < $h; $y++) // each pixel
				{
					$rgbOrig = ImageColorAt($finalimage, $x, $y);
					$rOrig = (($rgbOrig >> 16) & 0xFF);
					$gOrig = (($rgbOrig >> 8) & 0xFF);
					$bOrig = ($rgbOrig & 0xFF);

					$rgbBlur = ImageColorAt($imgBlur, $x, $y);

					$rBlur = (($rgbBlur >> 16) & 0xFF);
					$gBlur = (($rgbBlur >> 8) & 0xFF);
					$bBlur = ($rgbBlur & 0xFF);

					// When the masked pixels differ less from the original
					// than the threshold specifies, they are set to their original value.
					$rNew = (abs($rOrig - $rBlur) >= $threshold) ? max(0, min(255, ($amount * ($rOrig - $rBlur)) + $rOrig)) : $rOrig;

					$gNew = (abs($gOrig - $gBlur) >= $threshold) ? max(0, min(255, ($amount * ($gOrig - $gBlur)) + $gOrig)) : $gOrig;

					$bNew = (abs($bOrig - $bBlur) >= $threshold) ? max(0, min(255, ($amount * ($bOrig - $bBlur)) + $bOrig)) : $bOrig;



					if (($rOrig != $rNew) OR ($gOrig != $gNew) OR ($bOrig != $bNew))
					{
					    $pixCol = ImageColorAllocate($finalimage, $rNew, $gNew, $bNew);
					    ImageSetPixel($finalimage, $x, $y, $pixCol);
					}
				}
			}
		}
		else
		{
			for ($x = 0; $x < $w; $x++) // each row
			{
				for ($y = 0; $y < $h; $y++) // each pixel
				{
					$rgbOrig = ImageColorAt($finalimage, $x, $y);
					$rOrig = (($rgbOrig >> 16) & 0xFF);
					$gOrig = (($rgbOrig >> 8) & 0xFF);
					$bOrig = ($rgbOrig & 0xFF);

					$rgbBlur = ImageColorAt($imgBlur, $x, $y);

					$rBlur = (($rgbBlur >> 16) & 0xFF);
					$gBlur = (($rgbBlur >> 8) & 0xFF);
					$bBlur = ($rgbBlur & 0xFF);

					$rNew = ($amount * ($rOrig - $rBlur)) + $rOrig;
					if ($rNew > 255)
					{
						$rNew = 255;
					}
					elseif ($rNew < 0)
					{
						$rNew = 0;
					}

					$gNew = ($amount * ($gOrig - $gBlur)) + $gOrig;
					if ($gNew > 255)
					{
						$gNew = 255;
					}
					elseif ($gNew < 0)
					{
						$gNew = 0;
					}

					$bNew = ($amount * ($bOrig - $bBlur)) + $bOrig;
					if ($bNew > 255)
					{
						$bNew = 255;
					}
					elseif ($bNew < 0)
					{
						$bNew = 0;
					}

					$rgbNew = ($rNew << 16) + ($gNew << 8) + $bNew;
					ImageSetPixel($finalimage, $x, $y, $rgbNew);
				}
			}
		}
		imagedestroy($imgCanvas);
		imagedestroy($imgBlur);

		return true;
	}

	/**
	*
	* See function definition in vB_Image
	*
	*/
	public function getImageFromString($string, $moveabout = true)
	{
		$image_width = 201;
		$image_height = 61;

		$backgrounds = $this->fetchRegimageBackgrounds();

		if ($moveabout)
		{
			$notdone = true;

			while ($notdone AND !empty($backgrounds))
			{
				$index = mt_rand(0, count($backgrounds) - 1);
				$background = $backgrounds["$index"];
				switch(strtolower(file_extension($background)))
				{
					case 'jpg':
					case 'jpe':
					case 'jpeg':
						if (!function_exists('imagecreatefromjpeg') OR !$image = @imagecreatefromjpeg($background))
						{
							unset($backgrounds["$index"]);
						}
						else
						{
							$notdone = false;
						}
						break;
					case 'gif':
						if (!function_exists('imagecreatefromgif') OR !$image = @imagecreatefromgif($background))
						{
							unset($backgrounds["$index"]);
						}
						else
						{
							$notdone = false;
						}
						break;
					case 'png':
						if (!function_exists('imagecreatefrompng') OR !$image = @imagecreatefrompng($background))
						{
							unset($backgrounds["$index"]);
						}
						else
						{
							$notdone = false;
						}
						break;
				}
				sort($backgrounds);
			}
		}

		if (!empty($image))
		{
			// randomly flip
			if (vB::getRequest()->getTimeNow() & 2)
			{
				$image = $this->flipimage($image);
			}
			$gotbackground = true;
		}
		else
		{
			$image = $this->fetchImageResource($image_width, $image_height);
		}

		if (function_exists('imagettftext') AND $fonts = $this->fetchRegimageFonts())
		{
			if ($moveabout)
			{
				// Randomly move the letters up and down
				for ($x = 0; $x < strlen($string); $x++)
				{
					$index = mt_rand(0, count($fonts) - 1);
					if ($this->regimageoption['randomfont'])
					{
						$font = $fonts["$index"];
					}
					else
					{
						if (empty($font))
						{
							$font = $fonts["$index"];
						}
					}
					$image = $this->annotatettf($image, $string["$x"], $font);
				}
			}
			else
			{
				$image = $this->annotatettf($image, $string, $fonts[0], false);
			}
		}

		if ($moveabout)
		{
			$blur = .9;
		}

		$text_color = imagecolorallocate($image, 0, 0, 0);

		// draw a border
		imageline($image, 0, 0, $image_width, 0, $text_color);
		imageline($image, 0, 0, 0, $image_height, $text_color);
		imageline($image, $image_width - 1, 0, $image_width - 1, $image_height, $text_color);
		imageline($image, 0, $image_height - 1, $image_width, $image_height - 1, $text_color);

		ob_start();
		$ext = $this->printImage($image, 'PNG', false, 100);
		$output = ob_get_clean();

		// return imageinfo
		return array('filedata' => $output, 'filetype' => $ext, 'filesize' => strlen($output), 'contentType' => 'image/' . $ext);
	}

	/**
	*
	* Create blank image
	*
	* @param int width	Width of image
	* @param int height	Height of image
	*
	* @return resource
	*
	*/
	protected function &fetchImageResource($width, $height)
	{
		$image = imagecreatetruecolor($width, $height);
		$background_color = imagecolorallocate($image, 255, 255, 255); //white background
		imagefill($image, 0, 0, $background_color); // For GD2+

		return $image;
	}

	/**
	*
	* Return a letter position command
	*
	* @param	resource	image		Image to annotate
	* @param	string	letter	Character to position
	* @param boolean	random 	Apply effects
	*
	* @return	string
	*/
	protected function &annotategd($image, $letter, $random = true)
	{

		// Start position
		static $r, $g, $b, $xposition = 10;

		if ($random)
		{
			if ($this->regimageoption['randomcolor'] OR empty($r))
			{
				// Generate a random color..
				$r = mt_rand(50, 200);
				$b = mt_rand(50, 200);
				$g = mt_rand(50, 200);
			}

			$yposition = mt_rand(0, 5);

			$text_color = imagecolorallocate($image, $r, $g, $b);
			imagechar($image, 5, $xposition, $yposition, $letter, $text_color);
			$xposition += mt_rand(10, 25);
		}
		else
		{
			$text_color = imagecolorallocate($image, 0, 0, 0);
			$yposition = 2;
			imagechar($image, 5, $xposition, $yposition, $letter, $text_color);
			$xposition += 10;
		}

		return $image;
	}

	/**
	*
	* Return a letter position command
	*
	* @param	resource	image		Image to annotate
	* @param	string	letter	Character to position
	* @param string	font		Font to annotate (path)
	* @param boolean	slant		Slant fonts left or right
	* @param boolean	random 	Apply effects
	*
	* @return	string
	*/
	protected function annotatettf($image, $letter, $font, $random = true)
	{
		if ($random)
		{
			// Start position
			static $r, $g, $b, $position = 15;

			// Y Axis position, random from 35 to 48
			$y = mt_rand(35, 48);

			if ($this->regimageoption['randomcolor'] OR empty($r))
			{
				// Generate a random color..
				$r = mt_rand(50, 200);
				$b = mt_rand(50, 200);
				$g = mt_rand(50, 200);
			}

			if ($this->regimageoption['randomshape'])
			{
				if (function_exists('imageantialias'))
				{	// See http://bugs.php.net/bug.php?id=28147
					imageantialias($image, true);
				}
				// Stroke Width, 2 or 3
				imagesetthickness($image, mt_rand(2, 3));
				// Pick a random color
				$shapecolor = imagecolorallocate($image, mt_rand(50, 200), mt_rand(50, 200), mt_rand(50, 200));

				// Pick a Shape
				$x1 = mt_rand(0, 200);
				$y1 = mt_rand(0, 60);
				$x2 = mt_rand(0, 200);
				$y2 = mt_rand(0, 60);
				$start = mt_rand(0, 360);
				$end = mt_rand(0, 360);
				switch(mt_rand(1, 4))
				{
					case 1:
						imagearc($image, $x1, $y1, $x2, $y2, $start, $end, $shapecolor);
						break;
					case 2:
						imageellipse($image, $x1, $y1, $x2, $y2, $shapecolor);
						break;
					case 3:
						imageline($image, $x1, $y1, $x2, $y2, $shapecolor);
						break;
					case 4:
						imagepolygon($image, array(
							$x1, $y1,
							$x2, $y2,
							mt_rand(0, 200), mt_rand(0, 60),
							mt_rand(0, 200), mt_rand(0, 60),
							),
							4, $shapecolor
						);
						break;
				}
			}

			// Angle
			$slant = $this->regimageoption['randomslant'] ? mt_rand(-20, 60) : 0;
			$pointsize =  $this->regimageoption['randomsize'] ? mt_rand(20, 32) : 24;
			$text_color = imagecolorallocate($image, $r, $g, $b);
		}
		else
		{
			$position = 10;
			$y = 40;
			$slant = 0;
			$pointsize =  24;
			$text_color = imagecolorallocate($image, 0, 0, 0);
		}

		if (!$result = @imagettftext($image, $pointsize, $slant, $position, $y, $text_color, $font, $letter))
		{
			return false;
		}
		else
		{
			$position += rand(25, 35);
			return $image;
		}
	}

	/**
	*
	* mirror an image horizontally. Can be extended to other flips but this is all we need for now
	*
	* @param	image	image			Image file to convert
	*
	* @return	object	image
	*/
	protected function &flipimage(&$image)
	{
		$width = imagesx($image);
		$height = imagesy($image);

		$output = imagecreatetruecolor($width, $height);

		for($x = 0; $x < $height; $x++)
		{
			imagecopy($output, $image, 0, $height - $x - 1, 0, $x, $width, 1);
      }

		return $output;
	}

	/**
	*
	* Apply a swirl/twirl filter to an image
	*
	* @param	image	image			Image file to convert
	* @param	float	output			Degree of twirl
	* @param	bool	randirection	Randomize direction of swirl (clockwise/counterclockwise)
	*
	* @return	object	image
	*/
	protected function &swirl(&$image, $degree = .005, $randirection = true)
	{
		$image_width = imagesx($image);
		$image_height = imagesy($image);

		$temp = imagecreatetruecolor($image_width, $image_height);

		if ($randirection)
		{
			$degree = (mt_rand(0, 1) == 1) ? $degree : $degree * -1;
		}

		$middlex = floor($image_width / 2);
		$middley = floor($image_height / 2);

		for ($x = 0; $x < $image_width; $x++)
		{
			for ($y = 0; $y < $image_height; $y++)
			{
				$xx = $x - $middlex;
				$yy = $y - $middley;

				$theta = atan2($yy, $xx);

				$radius = sqrt($xx * $xx + $yy * $yy);

				$radius -= 5;

				$newx = $middlex + ($radius * cos($theta + $degree * $radius));
				$newy = $middley + ($radius * sin($theta + $degree * $radius));

				if (($newx > 0 AND $newx < $image_width) AND ($newy > 0 AND $newy < $image_height))
				{
					$index = imagecolorat($image, $newx, $newy);
					$colors = imagecolorsforindex($image, $index);
					$color = imagecolorresolve($temp, $colors['red'], $colors['green'], $colors['blue']);
				}
				else
				{
					$color = imagecolorresolve($temp, 255, 255, 255);
				}

				imagesetpixel($temp, $x, $y, $color);
			}
		}

		return $temp;
	}

	/**
	*
	* Apply a wave filter to an image
	*
	* @param	image	image			Image  to convert
	* @param	int		wave			Amount of wave to apply
	* @param	bool	randirection	Randomize direction of wave
	*
	* @return	image
	*/
	protected function &wave(&$image, $wave = 10, $randirection = true)
	{
		$image_width = imagesx($image);
		$image_height = imagesy($image);

		$temp = imagecreatetruecolor($image_width, $image_height);

		if ($randirection)
		{
			$direction = (vB::getRequest()->getTimeNow() & 2) ? true : false;
		}

		$middlex = floor($image_width / 2);
		$middley = floor($image_height / 2);

		for ($x = 0; $x < $image_width; $x++)
		{
			for ($y = 0; $y < $image_height; $y++)
			{

				$xo = $wave * sin(2 * 3.1415 * $y / 128);
				$yo = $wave * cos(2 * 3.1415 * $x / 128);

				if ($direction)
				{
					$newx = $x - $xo;
					$newy = $y - $yo;
				}
				else
				{
					$newx = $x + $xo;
					$newy = $y + $yo;
				}

				if (($newx > 0 AND $newx < $image_width) AND ($newy > 0 AND $newy < $image_height))
				{
					$index = imagecolorat($image, $newx, $newy);
               $colors = imagecolorsforindex($image, $index);
               $color = imagecolorresolve($temp, $colors['red'], $colors['green'], $colors['blue']);
				}
				else
				{
					$color = imagecolorresolve($temp, 255, 255, 255);
				}

				imagesetpixel($temp, $x, $y, $color);
			}
		}

		return $temp;
	}

	/**
	*
	* Apply a blur filter to an image
	*
	* @param	image	image			Image  to convert
	* @param	int		radius			Radius of blur
	*
	* @return	image
	*/
	protected function &blur(&$image, $radius = .5)
	{
		$radius = ($radius > 50) ? 100 : abs(round($radius * 2));

		if ($radius == 0)
		{
			return $image;
		}

		$w = imagesx($image);
		$h = imagesy($image);


		$imgCanvas = imagecreatetruecolor($w, $h);
		$imgBlur = imagecreatetruecolor($w, $h);
		imagecopy ($imgCanvas, $image, 0, 0, 0, 0, $w, $h);

		// Gaussian blur matrix:
		//
		//	1	2	1
		//	2	4	2
		//	1	2	1
		//
		//////////////////////////////////////////////////

		// Move copies of the image around one pixel at the time and merge them with weight
		// according to the matrix. The same matrix is simply repeated for higher radii.
		for ($i = 0; $i < $radius; $i++)
		{
			imagecopy($imgBlur, $imgCanvas, 0, 0, 1, 1, $w - 1, $h - 1); // up left
			imagecopymerge($imgBlur, $imgCanvas, 1, 1, 0, 0, $w, $h, 50); // down right
			imagecopymerge($imgBlur, $imgCanvas, 0, 1, 1, 0, $w - 1, $h, 33.33333); // down left
			imagecopymerge($imgBlur, $imgCanvas, 1, 0, 0, 1, $w, $h - 1, 25); // up right
			imagecopymerge($imgBlur, $imgCanvas, 0, 0, 1, 0, $w - 1, $h, 33.33333); // left
			imagecopymerge($imgBlur, $imgCanvas, 1, 0, 0, 0, $w, $h, 25); // right
			imagecopymerge($imgBlur, $imgCanvas, 0, 0, 0, 1, $w, $h - 1, 20 ); // up
			imagecopymerge($imgBlur, $imgCanvas, 0, 1, 0, 0, $w, $h, 16.666667); // down
			imagecopymerge($imgBlur, $imgCanvas, 0, 0, 0, 0, $w, $h, 50); // center
			imagecopy($imgCanvas, $imgBlur, 0, 0, 0, 0, $w, $h);
		}
		imagedestroy($imgBlur);
		return $imgCanvas;
	}

	/**
	*
	* See function definition in vB_Image
	*
	*/
	public function fetchImageInfo($filename)
	{
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
		static $types = array(
			1 => 'GIF',
			2 => 'JPEG',
			3 => 'PNG',
			4 => 'SWF',
			5 => 'PSD',
			6 => 'BMP',
			7 => 'TIFF',
			8 => 'TIFF',
			9 => 'JPC',
			10=> 'JP2',
			11=> 'JPX',
			12=> 'JB2',
			13=> 'SWC',
			14=> 'IFF',
			15=> 'WBMP',
			16=> 'XBM',
		);

		// use PHP's getimagesize if it works
		if ($imageinfo = getimagesize($filename))
		{
 			$this->imageinfo = array(
				0          => $imageinfo[0],
				1          => $imageinfo[1],
				2          => $types["$imageinfo[2]"],
				'bits'     => isset($imageinfo['bits']) ? $imageinfo['bits'] : 0,
				'scenes'   => 1,
				'library'  => 'GD',
				'animated' => false,
			);

			if (isset($imageinfo['channels']))
			{
				$this->imageinfo['channels'] = $imageinfo['channels'];
			}

			if ($this->imageinfo[2] == 'GIF')
			{	// get scenes
				$data = file_get_contents($filename);
				// Look for a Global Color table char and the Image seperator character
				// The scene count could be broken, see #26591
				$this->imageinfo['scenes'] = count(preg_split('#\x00[\x00-\xFF]\x00\x2C#', $data)) - 1;

				$this->imageinfo['animated']  = (strpos($data, 'NETSCAPE2.0') !== false);
				unset($data);
			}

			return $this->imageinfo;
		}
		// getimagesize barfs on some jpegs but we can try to create an image to find the dimensions
		else if (function_exists('imagecreatefromjpeg') AND $img = @imagecreatefromjpeg($filename))
		{
			$this->imageinfo = array(
				0          => imagesx($img),
				1          => imagesy($img),
				2          => 'JPEG',
				'channels' => 3,
				'bits'     => 8,
				'library'  => 'GD',
			);
			imagedestroy($img);

			return $this->imageinfo;
		}
		else
		{
			return false;
		}
	}

	protected function skipWriteImage($fileContents, $location)
	{
		$extension = $this->getExtensionFromFileheaders($location);
		if ($extension === 'gif')
		{
			$safe = $this->verifyImageFile($fileContents, $location);
			$animated = $this->is_animated_gif($location);
			$doSkip = ($safe AND $animated);
			return $doSkip;
		}
		else
		{
			return false;
		}
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

		$imageinfo = $this->getUnsafeImageInfo($fileContents, $location);
		$image = $this->getImage($location, $imageinfo);

		/**
		 * Rotate image from $fileContents as specified by 'orientation' exif tag.
		 */
		$orientation = $this->getOrientation($location);
		if (!empty($orientation))
		{
			$rotatedimage = $this->orientImageInternalGD($image, $orientation);
			if ($rotatedimage)
			{
				imagedestroy($image);
				$image = $rotatedimage;
			}
			// else rotation failed, let's just continue copying.
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


		// Ideally we would want to minimize quality loss from compression while rotating/flipping,
		// but setting jpeg quality to 100 seems to cause significant file bloat, VBV-17131
		$jpegQuality= vB::getDatastore()->getOption('gdresizequality');
		$jpegQuality = max(min($jpegQuality, 100), 0);

		$extension = $this->printImage($image, $imageinfo[2], false, $jpegQuality, $newfile);
		// imagedestroy($image); // not required ATM as printImage() does this.

		if (empty($extension))
		{
			// For some reason writing the image failed.
			return "";
		}

		// It'd be nice if GD handled icc profiles. But it doesn't.

		// Writing an image via GD will wipe the Exif data, so there's nothing else to do here.

		return $newfile;
	}

	/**
	 * Rotate/flip/flop image from $fileContents as specified by 'orientation' exif tag. Caller must perform file-write using
	 * the image resource.
	 *
	 * @param	Resource  $image           GD Image resource from $this->getImage(). Return value of one of the imagecreatefrom_x() GD functions.
	 * @param	int       $orientation     image orientation from exif data, typically result of getOrientation($location)
	 *
	 * @access protected
	 */
	protected function orientImageInternalGD($image, $orientation)
	{
		// Do not make this public. Don't call this outside of orientImage().

		$angles = (360 - $this->orientationToAnglesCW($orientation)); // GD wants CCW angles. imagick wants CW angles.
		$newimage = imagerotate($image, $angles, 0);

		if (!$newimage)
		{
			// imagerotate failed for some reason.
			return false;
		}

		$flipFlop = $this->orientationToFlipFlop($orientation);
		if ($flipFlop['flip'] OR $flipFlop['flip'])
		{
			$mode = null;
			if ($flipFlop['flip'] AND $flipFlop['flop'])
			{
				$mode = IMG_FLIP_BOTH;
			}
			else if ($flipFlop['flip'])
			{
				$mode = IMG_FLIP_VERTICAL;
			}
			else
			{
				$mode = IMG_FLIP_HORIZONTAL;
			}
			$check = imageflip($newimage, $mode);
			if (!$check)
			{
				imagedestroy($newimage);
				// flip failed.
				return false;
			}
		}
		else
		{
			// no flip. continue on.
		}

		return $newimage;
	}


	/*
	 * Returns an image resource created from $location
	 *
	 * @param	String	$location
	 * @param	array	$imageinfo	Resulting array from fetchImageInfo($location)
	 *
	 * @return	resource|false	Image resource if successful, false otherwise.
	 * @throws 	vB_Exception_Api()
	 *				- thumbnail_notenoughmemory	: Ran out of memory
	 *				- thumbnail_nosupport		: Missing library for particular image type (gif/jpg/png)
	 *				- thumbnail_nocreateimage_gif|jpg|png	: GD library imagecreate...() function errors
	 *
	 * @access	private
	 */
	private function getImage($location, $imageinfo = null)
	{
		$image = false;

		/*
			TODO: get rid of "thumbnail" from error messages.
			We plan to use this for non-thumbnails as well.
		 */
		if (is_null($imageinfo))
		{
			$imageinfo = $this->fetchImageInfo($location);
			if (empty($imageinfo))
			{
				return false;
			}
		}
		$width = $imageinfo[0];
		$height = $imageinfo[1];

		/*
			Cthulu note:
			I have absolutely no idea where the magic spell below came from.
			I moved this from fetchThumbnail() and kept the memory check as I found it.
			I won't pretend to understand why there's an always true $memoryok, or where
			the magic numbers 7372.8 & 166000 came frome.
			Where do you even get get 0.8 bytes??? Did circuit city sell memory in .8 byte
			increments? Is that why they went out of business?
			I'm going to stop looking at this because it's driving me insane.
		 */
		$memoryok = true;
		$checkmem = false;
		if (function_exists('memory_get_usage') AND $memory_limit = @ini_get('memory_limit') AND $memory_limit != -1)
		{
			$memorylimit = vb_number_format($memory_limit, 0, false, null, '');
			$memoryusage = memory_get_usage();
			$freemem = $memorylimit - $memoryusage;
			$checkmem = true;
			$tmemory = $width * $height * ($imageinfo[2] == 'JPEG' ? 5 : 2) + 7372.8 + sqrt(sqrt($width * $height));
			$tmemory += 166000; // fudge factor, object overhead, etc

			if ($freemem > 0 AND $tmemory > $freemem AND $tmemory <= ($memorylimit * 3))
			{
				// attempt to increase memory within reason, no more than triple
				vB_Utilities::extendMemoryLimitBytes($memorylimit + $tmemory);

				$memory_limit = @ini_get('memory_limit');
				$memorylimit = vb_number_format($memory_limit, 0, false, null, '');
				$memoryusage = memory_get_usage();
				$freemem = $memorylimit - $memoryusage;
			}
		}

		switch($imageinfo[2])
		{
			case 'GIF':
				if (function_exists('imagecreatefromgif'))
				{
					if ($checkmem)
					{
						if ($freemem > 0 AND $tmemory > $freemem)
						{
							throw new vB_Exception_Api('thumbnail_notenoughmemory');
						}
					}
					if ($memoryok AND !$image = @imagecreatefromgif($location))
					{
						throw new vB_Exception_Api('thumbnail_nocreateimage_gif');
					}
					imagesavealpha($image, true);
					imagealphablending($image, false);
				}
				else
				{
					throw new vB_Exception_Api('thumbnail_nosupport');
				}
				break;
			case 'JPEG':
				if (function_exists('imagecreatefromjpeg'))
				{
					if ($checkmem)
					{
						if ($freemem > 0 AND $tmemory > $freemem)
						{
							throw new vB_Exception_Api('thumbnail_notenoughmemory');
						}
					}

					if ($memoryok AND !$image = @imagecreatefromjpeg($location))
					{
						throw new vB_Exception_Api('thumbnail_nocreateimage_jpeg');
					}
				}
				else
				{
					throw new vB_Exception_Api('thumbnail_nosupport');
				}
				break;
			case 'PNG':
				if (function_exists('imagecreatefrompng'))
				{
					if ($checkmem)
					{
						if ($freemem > 0 AND $tmemory > $freemem)
						{
							throw new vB_Exception_Api('thumbnail_notenoughmemory');
						}
					}
					if ($memoryok AND !$image = @imagecreatefrompng($location))
					{
						throw new vB_Exception_Api('thumbnail_nocreateimage_png');
					}
					imagesavealpha($image, true);
					imagealphablending($image, false);
				}
				else
				{
					throw new vB_Exception_Api('thumbnail_nosupport');
				}
				break;
		}


		return $image;
	}


	/**
	 * @see vB_Image::fetchThumbnail()
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
		$thumbnail = array(
			'filedata' => '',
			'filesize' => 0,
			'dateline' => 0,
			'imageerror' => '',
		);

		if ($validfile = $this->isValidThumbnailExtension(file_extension($filename)) AND $imageinfo = $this->fetchImageInfo($location))
		{
			$thumbnail['source_width'] = $new_width = $width = $imageinfo[0];
			$thumbnail['source_height'] = $new_height = $height = $imageinfo[1];

			if ($this->fetchImagetypeFromExtension(file_extension($filename)) != $imageinfo[2])
			{
				// TODO: Do we really care that they renamed the extension??
				throw new vB_Exception_Api('thumbnail_notcorrectimage');
			}
			else if ($width > $maxwidth OR $height > $maxheight)
			{
				$image = $this->getImage($location, $imageinfo);

				if ($image)
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

					if ($drawborder)
					{
						$create_width = $new_width + 2;
						$create_height = $new_height + 2;
						$dest_x_start = 1;
						$dest_y_start = 1;
					}
					else
					{
						$create_width = $new_width;
						$create_height = $new_height;
						$dest_x_start = 0;
						$dest_y_start = 0;
					}

					if ($labelimage)
					{
						$font = 2;
						$labelboxheight = ($drawborder) ? 13 : 14;

						if ($ofilesize)
						{
							$filesize = $ofilesize;
						}
						else
						{
							$filesize = @filesize($location);
						}

						if ($filesize / 1024 < 1)
						{
							$filesize = 1024;
						}
						if ($owidth)
						{
							$dimensions = $owidth . 'x' . $oheight;
						}
						else
						{
							$dimensions = (!empty($width) AND !empty($height)) ? "{$width}x{$height}" : '';
						}

						$sizestring = (!empty($filesize)) ? vb_number_format($filesize , 0, true) : '';

						if (($string_length = (strlen($string = "$dimensions $sizestring $imageinfo[2]") * imagefontwidth($font))) < $new_width)
						{
							$finalstring = $string;
							$finalwidth = $string_length;
						}
						else if (($string_length = (strlen($string = "$dimensions $sizestring") * imagefontwidth($font))) < $new_width)
						{
							$finalstring = $string;
							$finalwidth = $string_length;
						}
						else if (($string_length = (strlen($string = $dimensions) * imagefontwidth($font))) < $new_width)
						{
							$finalstring = $string;
							$finalwidth = $string_length;
						}
						else if (($string_length = (strlen($string = $sizestring) * imagefontwidth($font))) < $new_width)
						{
							$finalstring = $string;
							$finalwidth = $string_length;
						}

						if (!empty($finalstring))
						{
							$create_height += $labelboxheight;
							if ($drawborder)
							{
								$label_x_start = ($new_width - ($finalwidth)) / 2 + 2;
								$label_y_start =  ($labelboxheight - imagefontheight($font)) / 2 + $new_height + 1;
							}
							else
							{
								$label_x_start =  ($new_width - ($finalwidth)) / 2 + 1;
								$label_y_start =  ($labelboxheight - imagefontheight($font)) / 2 + $new_height;
							}
						}
					}
					if (!($finalimage = @imagecreatetruecolor($create_width, $create_height)))
					{
						imagedestroy($image);
						throw new vB_Exception_Api('thumbnail_nocreateimage_truecolor');
					}

					// preserve transparency
					// imagesavealpha() set @ printImage() before write.
					$transparency = imagecolortransparent($image);
					if ($transparency > 0) // GIFs (& sometimes PNGs)
					{
						// note, GIFs tend to leave behind a border when resized...
						imagefill($finalimage, 0, 0, $transparency);
						imagecolortransparent($finalimage, $transparency);
					}
					else
					{
						// PNGs, but seems like JPGs are fine with this instead of a black background.
						$bgcolor = imagecolorallocatealpha($finalimage, 0, 0, 0, 127);
						imagefill($finalimage, 0, 0, $bgcolor);
					}
					@imagecopyresampled($finalimage, $image, $dest_x_start, $dest_y_start, 0, 0, $new_width, $new_height, $width, $height);
					imagedestroy($image);


					if ($sharpen AND $this->imageinfo[2] != 'GIF' AND $this->imageinfo[2] != 'PNG')
					{
						/*
							The currently sharpen code doesn't work nicely with PNGs that has any level of transparency.
							While testing out adding transparency support to unsharpmask(), I found that just backfilling
							the blur mask with a transparent background then doing a "naive" blending of the alpha channel
							creates low quality thumbnails (note without this, the thumbnails end up with black color instead
							of transparent).
							The current guassian blur "thickens" any groups of pixels with transparency, and this has the effect
							at the final unsharpening of "washing out" partially-trasparent pixels.
							We probably need to figure out a way to weigh/blur the alpha channel better if we really want
							to sharpen images that support transparency.

							Generally speaking trying to sharpen a PNG thumbnail does not seem to work out very well. Since PNGs
							are lossless, sharpening/hi-passing it is probably not necessary, even undesirable.
						 */
						$this->unsharpmask($finalimage);
					}

					if ($labelimage AND !empty($finalstring))
					{
						$bgcolor = imagecolorallocate($finalimage, $this->thumbcolor['r'], $this->thumbcolor['g'], $this->thumbcolor['b']);
						$recstart = ($drawborder) ? $create_height - $labelboxheight - 1 : $create_height - $labelboxheight;
						imagefilledrectangle($finalimage, 0, $recstart, $create_width, $create_height, $bgcolor);
						$textcolor = imagecolorallocate($finalimage, 255, 255, 255);
						imagestring($finalimage, $font, $label_x_start, $label_y_start, $finalstring, $textcolor);
					}

					if ($drawborder)
					{
						$bordercolor = imagecolorallocate($finalimage, $this->thumbcolor['r'], $this->thumbcolor['g'], $this->thumbcolor['b']);
						imageline($finalimage, 0, 0, $create_width, 0, $bordercolor);
						imageline($finalimage, 0, 0, 0, $create_height, $bordercolor);
						imageline($finalimage, $create_width - 1, 0, $create_width - 1, $create_height, $bordercolor);
						imageline($finalimage, 0, $create_height - 1, $create_width, $create_height - 1, $bordercolor);
					}


					ob_start();
						$new_extension = $this->printImage($finalimage, $jpegconvert ? 'JPEG' : $imageinfo[2], false, $quality);
						$thumbnail['filedata'] = ob_get_contents();
					ob_end_clean();
					$thumbnail['width'] = $create_width;
					$thumbnail['height'] = $create_height;
					$extension = file_extension($filename);
					if ($new_extension != $extension)
					{
						$thumbnail['filename'] = preg_replace('#' . preg_quote($extension, '#') . '$#', $new_extension, $filename);
					}
				}
			}
			else
			{
				if ($imageinfo[0] == 0 AND $imageinfo[1] == 0) // getimagesize() failed
				{
					throw new vB_Exception_Api('thumbnail_nogetimagesize');
				}
				else
				{
					// image is a thumbnail size already
					$thumbnail['filedata'] = @file_get_contents($location);
					$thumbnail['width'] = $imageinfo[0];
					$thumbnail['height'] = $imageinfo[1];
				}
			}
		}
		else if (!$validfile)
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
			'filedata' => '',
			'filesize' => 0,
			'dateline' => 0,
			'imageerror' => '',
		);
		$filename = $imgInfo['filename'];
		$imgInfo['extension'] = strtoupper($imgInfo['extension']);

		if ($imgInfo['extension'] == 'JPG')
		{
			$imgInfo['extension'] = 'JPEG';
		}
		if ($validfile = $this->isValidThumbnailExtension($imgInfo['extension']))
		{
			$thumbnail['source_width'] = $new_width = $width = $imgInfo['width'];
			$thumbnail['source_height'] = $new_height = $height = $imgInfo['height'];

			if ($forceResize OR $width >= $maxwidth OR $height >= $maxheight)
			{
				$memoryok = true;
				$checkmem = false;
				if (function_exists('memory_get_usage') AND $memory_limit = @ini_get('memory_limit') AND $memory_limit != -1)
				{
					$memorylimit = vb_number_format($memory_limit, 0, false, null, '');
					$memoryusage = memory_get_usage();
					$freemem = $memorylimit - $memoryusage;
					$checkmem = true;
					$tmemory = $width * $height * ($imgInfo['extension'] == 'JPEG' ? 5 : 2) + 7372.8 + sqrt(sqrt($width * $height));
					$tmemory += 166000; // fudge factor, object overhead, etc

					if ($freemem > 0 AND $tmemory > $freemem AND $tmemory <= ($memorylimit * 3))
					{
						// attempt to increase memory within reason, no more than triple
						vB_Utilities::extendMemoryLimitBytes($memorylimit + $tmemory);

						$memory_limit = @ini_get('memory_limit');
						$memorylimit = vb_number_format($memory_limit, 0, false, null, '');
						$memoryusage = memory_get_usage();
						$freemem = $memorylimit - $memoryusage;
					}
				}

				$fh = fopen($filename, 'w');
				fwrite($fh, $imgInfo['filedata']);
				fclose($fh);

				switch($imgInfo['extension'])
				{
					case 'GIF':
						if (function_exists('imagecreatefromgif'))
						{
							if ($checkmem)
							{
								if ($freemem > 0 AND $tmemory > $freemem)
								{
									throw new vB_Exception_Api('thumbnail_notenoughmemory');
								}
							}
							if ($memoryok AND !$image = @imagecreatefromgif($filename))
							{
								throw new vB_Exception_Api('thumbnail_nocreateimage_gif');
							}
						}
						else
						{
							throw new vB_Exception_Api('thumbnail_nosupport');
						}
						break;
					case 'JPEG':
						if (function_exists('imagecreatefromjpeg'))
						{
							if ($checkmem)
							{
								if ($freemem > 0 AND $tmemory > $freemem)
								{
									throw new vB_Exception_Api('thumbnail_notenoughmemory');
								}
							}

							if ($memoryok AND !$image = @imagecreatefromjpeg($filename))
							{
								throw new vB_Exception_Api('thumbnail_nocreateimage_jpeg');
							}
						}
						else
						{
							throw new vB_Exception_Api('thumbnail_nosupport');
						}
						break;
					case 'PNG':
						if (function_exists('imagecreatefrompng'))
						{
							if ($checkmem)
							{
								if ($freemem > 0 AND $tmemory > $freemem)
								{
									throw new vB_Exception_Api('thumbnail_notenoughmemory');
								}
							}
							if ($memoryok AND !$image = @imagecreatefrompng($filename))
							{
								throw new vB_Exception_Api('thumbnail_nocreateimage_png');
							}
						}
						else
						{
							throw new vB_Exception_Api('thumbnail_nosupport');
						}
						break;
				}

				if ($image)
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
				}

				if (!($finalimage = @imagecreatetruecolor($new_width, $new_height)))
				{
					imagedestroy($image);
					throw new vB_Exception_Api('thumbnail_nocreateimage_truecolor');
				}

				// preserve transparency
				$transparency = imagecolortransparent($image);
				if ($transparency > 0) // GIFs (& sometimes PNGs)
				{
					imagefill($finalimage, 0, 0, $transparency);
					imagecolortransparent($finalimage, $transparency);
				}
				else
				{
					// PNGs, but seems like JPGs are fine with this instead of a black background.
					$bgcolor = imagecolorallocatealpha($finalimage, 0, 0, 0, 127);
					imagefill($finalimage, 0, 0, $bgcolor);
				}
				imagecopyresampled($finalimage, $image, 0, 0, $imgInfo['x1'], $imgInfo['y1'], $new_width, $new_height, $imgInfo['width'], $imgInfo['height']);
				imagedestroy($image);
				if ($imgInfo['extension'] != 'GIF' AND $imgInfo['extension'] != 'PNG')
				{
					$this->unsharpmask($finalimage);
				}


				ob_start();
					$new_extension = $this->printImage($finalimage, $imgInfo['extension'], false, 75);
					$thumbnail['filedata'] = ob_get_contents();
				ob_end_clean();

				$thumbnail['width'] = $new_width;
				$thumbnail['height'] = $new_height;
				$extension = $imgInfo['extension'];
				if ($new_extension != $extension)
				{
					$thumbnail['filename'] = preg_replace('#' . preg_quote($extension, '#') . '$#', $new_extension, $filename);
				}
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
		else if (!$validfile)
		{
			throw new vB_Exception_Api('thumbnail_nosupport');
		}

		if (!empty($thumbnail['filedata']))
		{
			$thumbnail['filesize'] = strlen($thumbnail['filedata']);
			$thumbnail['dateline'] = vB::getRequest()->getTimeNow();
		}

		@unlink($filename);
		return $thumbnail;
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 102901 $
|| #######################################################################
\*=========================================================================*/
