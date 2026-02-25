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

class vB_Template_Runtime
{
	use vB_Trait_NoSerialize;

	public static $units = array(
		'%',
		'px',
		'pt',
		'em',
		'rem',
		'ch',
		'ex',
		'pc',
		'in',
		'cm',
		'mm',
		'vw',
		'vh',
		'vmin',
		'vmax',
	);

	public static function date($timestamp, $format = 'r', $doyestoday=0, $adjust=1)
	{
		if (empty($format))
		{
			$format = 'r';
		}
		return vbdate($format, intval($timestamp), $doyestoday, true, $adjust);
	}

	public static function time($timestamp)
	{
		if (empty($timestamp))
		{
			$timestamp = 0;
		}
		return vbdate(vB::getDatastore()->getOption('timeformat'), $timestamp);
	}

	/**
	 * This method is defined just to avoid errors while saving the template. The real implementation
	 * is in the presentation layer.
	 * @param <type> $var
	 * @return string
	 */
	public static function datetime($timestamp, $format = 'date, time', $formatdate = '', $formattime = '')
	{
		return '';
	}

	public static function escapeJS($javascript)
	{
		return str_replace(array("'", "\n", "\r"), array("\'", ' ', ' '), $javascript);
	}

	public static function numberFormat($number, $decimals = 0)
	{
		return vb_number_format($number, $decimals);
	}

	public static function urlEncode($text)
	{
		return urlencode($text);
	}

	public static function parsePhrase($phraseName)
	{
		global $vbphrase;
		$arg_list = func_get_args();
		if (isset($vbphrase[$phraseName]))
		{
			$arg_list[0] = $vbphrase[$phraseName];
			return construct_phrase_from_array($arg_list);
		}

		$phraseArr = vB_Api::instanceInternal('phrase')->fetch(array($phraseName));
		if (isset($phraseArr[$phraseName]))
		{
			$phrase = $phraseArr[$phraseName];
			$arg_list[0] = $phrase;
			return construct_phrase_from_array($arg_list);
		}
		else
		{
			// Should we do something else here if phrase wasn't found?
			return '';
		}
	}

	public static function addStyleVar($name, $value, $datatype = 'string')
	{
		global $vbulletin;

		switch ($datatype)
		{
			case 'string':
				$vbulletin->stylevars["$name"] = array(
					'datatype' => $datatype,
					'string'   => $value,
				);
			break;
			case 'imgdir':
				$vbulletin->stylevars["$name"] = array(
					'datatype' => $datatype,
					'imagedir' => $value,
				);
			break;
		}
	}

	/**
	 * Converts a number from decimal to hexadecimal representation with 0 padding to two places.
	 *
	 * @param  int    The number in decimal representation.
	 * @return string The number in hexadecimal representation, uppercase, with 0 padding.
	 */
	private static function dechexpadded($dec)
	{
		$hex = dechex($dec);

		// zero pad for two-char hex numbers
		if (strlen($hex) < 2)
		{
			$hex = '0' . $hex;
		}

		return strtoupper($hex);
	}

	/**
	 * Converts to and from various color formats. Supported formats are hex, rgb, rgba, and array.
	 * The hex format supports 3-char and 6-char versions (#XXX and #XXXXXX). The array format
	 * is an array containing red, green, blue, and optionally alpha elements. All formats are supported
	 * for both input and output. The hex format always outputs the 6-char version (#XXXXXX).
	 * hsl, hsla, and predefined color names are not supported at this time.
	 *
	 * @param string|array The source color value
	 * @param string The name of the target format (hex, rgb, rgba, array)
	 * @return string|array The color in the target format
	 */
	private static function convertColorFormat($input, $targetFormat)
	{
		// NOTE: There are 3 convertColorFormat() functions-- the two template
		// runtimes, and the JS version in class_stylevar.php Please keep all 3 in sync.

		$format = $red = $green = $blue = '';
		$alpha = '1';

		$len = !is_array($input) ? strlen($input) : 0;

		// array
		if (is_array($input))
		{
			$format = 'array';

			$red = $input['red'];
			$green = $input['green'];
			$blue = $input['blue'];
			$alpha = $input['alpha'];
		}
		// hex
		else if (substr($input, 0, 1) == '#' AND ($len == 4 OR $len == 7))
		{
			$format = 'hex';

			$hexVal = substr($input, 1);

			if (strlen($hexVal == 3))
			{
				$rr = substr($hexVal, 0, 1);
				$gg = substr($hexVal, 1, 1);
				$bb = substr($hexVal, 2, 1);
				$rr = $rr . $rr;
				$gg = $gg . $gg;
				$bb = $bb . $bb;
			}
			else
			{
				$rr = substr($hexVal, 0, 2);
				$gg = substr($hexVal, 2, 2);
				$bb = substr($hexVal, 4, 2);
			}

			$red = hexdec($rr);
			$green = hexdec($gg);
			$blue = hexdec($bb);
		}
		// rgb, rgba
		else if (preg_match('#(rgba?)\(([^)]+)\)#', $input, $matches))
		{
			$format = $matches[1];

			$values = explode(',', $matches[2]);

			$red = $values[0];
			$green = $values[1];
			$blue = $values[2];

			if ($matches[1] == 'rgba')
			{
				$alpha = $values[3];
			}
		}

		$returnValue = array();
		$returnValue['format'] = $format;

		switch ($targetFormat)
		{
			case 'array':
				$returnValue['value'] = array(
					'red' => $red,
					'green' => $green,
					'blue' => $blue,
					'alpha' => $alpha,
				);
				break;

			case 'hex':
				$returnValue['value'] = '#' . self::dechexpadded($red) . self::dechexpadded($green) . self::dechexpadded($blue);
				break;

			case 'rgb':
				$returnValue['value'] = 'rgb(' . $red . ', ' . $green . ', ' . $blue . ')';
				break;

			case 'rgba':
				$returnValue['value'] = 'rgba(' . $red . ', ' . $green . ', ' . $blue . ', ' . $alpha . ')';
				break;

			default:
				throw new Exception('Unexpected color format in convertColorFormat(): ' . htmlspecialchars($targetFormat));
				break;
		}

		return $returnValue;
	}

	/**
	 * Generates an array of information about the color, including originalValue, originalFormat
	 * (which will be one of the formats supported by convertColorFormat()), red, green, blue, and
	 * alpha.
	 *
	 * @param string|array The color value.
	 * @param return       The array of information about the color.
	 */
	private static function getColorFormatInfo($originalValue)
	{
		// NOTE: There are 3 getColorFormatInfo() functions-- the two template
		// runtimes, and the JS version in class_stylevar.php Please keep all 3 in sync.

		$returnValue = array(
			'originalValue' => $originalValue,
			'originalFormat' => '',
			'red' => '',
			'green' => '',
			'blue' => '',
			'alpha' => '',
		);

		$converted = self::convertColorFormat($originalValue, 'array');

		$returnValue['originalFormat'] = $converted['format'];
		$returnValue['red'] = $converted['value']['red'];
		$returnValue['green'] = $converted['value']['green'];
		$returnValue['blue'] = $converted['value']['blue'];
		$returnValue['alpha'] = $converted['value']['alpha'];

		return $returnValue;
	}

	/**
	 * Transforms a color based on the transformation parameters (inherit_param_color) set in the stylevar.
	 *
	 * @param  int   Red color value for the Original color [OR] (decimal, 0-255)
	 * @param  int   Green color value for the Original color [OG] (decimal, 0-255)
	 * @param  int   Blue color value for the Original color [OB] (decimal, 0-255)
	 * @param  float The Alpha/opacity value for the Original color [OA] (0.0 - 1.0)
	 * @param  int   Red color value for the Inherited color [IR] (decimal, 0-255)
	 * @param  int   Green color value for the Inherited color [IG] (decimal, 0-255)
	 * @param  int   Blue color value for the Inherited color [IB] (decimal, 0-255)
	 * @param  float The Alpha/opacity value for the Inherited color [IA] (0.0 - 1.0)
	 * @param  int   The first color transformation Param (applies to the red value of the Original color) (signed int)
	 * @param  int   The second color transformation Param (applies to the green value of the Original color) (signed int)
	 * @param  int   The third color transformation Param (applies to the blue value of the Original color) (signed int)
	 * @param  float The fourth color transformation Param (applies to the alpha/opacity value of the Original color) (signed float)
	 * @return array An array of information for the new/transformed color (red, green, blue, alpha).
	 */
	private static function transformColor($or, $og, $ob, $oa, $ir, $ig, $ib, $ia, $p1, $p2, $p3, $p4)
	{
		// NOTE: There are 3 transformColor() functions-- the two template
		// runtimes, and the JS version in class_stylevar.php Please keep all 3 in sync.
		// Also keep transformColor and generateTransformParams in sync, as
		// they both depend on the same general algorithm.

		// I think I owe the reader an explanation of how the transformation works.
		//
		// The 4 transformation parameters correspond to Red, Green, Blue, and Opactity values.
		//
		// The first 3 params are for colors. They are a positive or negative int value that
		// represents how far to move the inherited decimal color (0-255). If the inherited color
		// is 150 and the param is -20, then reduce the 150 by 20. A positive param (20) means move
		// toward the outer bound (either 0 or 255), and a negative param (-20) means move in
		// the opposite direction. The outer bound is either 0 or 255, whichever the current value
		// is closer to. So if the current color value is 60, then the outer bound is 0 and a param
		// of 25 would convert it to 35. If the param were -25, it would convert to 85. If the
		// current color is 210, then the outer bound would be 255 and a param of 25 (a positive
		// param) would convert it to 235.
		//
		// The 3 color params correspond (in order) to the red, green, and blue values of the
		// *original* inherited color. Original meaning the one in the MASTER_STYLE. However,
		// these are NOT necessarily matched up in order with the red, green, and blue values
		// of the inherited color that we want to transform. Instead they are matched in terms
		// of intensity. In other words, the highest of the three from the original inherited
		// color is matched with the highest of the current inherited colors and so forth.
		// So if the MASTER_STYLE has a light pink rgb(255, 230, 230), but the current inherited
		// color is a light blue rgb(200, 200, 255), and our three color transformation params
		// are -30, -50, -50. We would normally apply these and darken red by 30, while darkening
		// green and blue by 50. But since the current inherited color is now a light blue, we
		// match the -30 to the red value of the original, and the red value is matched to the
		// blue value of the current inherited color.  This means that even if the user changes
		// the inherited stylevar, we can still apply our transformation because it will keep the
		// same hue/color that the user specified, while still applying the darkening/lightening
		// that we have specified.
		//
		// The opacity value is a positive or negative float and will add or subtract from the
		// inherited opacity value. If the inherited value doesn't specify opacity (as with hex
		// or rgb colors), then it defaults to fully opaque 1.0. If the param introduces
		// transparencey (anything less than 100% opacity) that the inherited color doesn't have,
		// then the output will automatically be converted to rgba, otherwise the output tries
		// to match the input value. Opacity is obviously constrained to the range of 0.0 (completely
		// transparent) to 1.0 (completely opaque).

		// Match the original (MASTER_STYLE) r, g, b values to the corresponding
		// transform parameters 1, 2, 3 in order.
		$parts = array(
			array(
				'original' => $or,
				'transform' => $p1,
				'new' => '',
			),
			array(
				'original' => $og,
				'transform' => $p2,
				'new' => '',
			),
			array(
				'original' => $ob,
				'transform' => $p3,
				'new' => '',
			),
		);

		// Set up the inherited color parts, specifying which is red, green, and blue value
		$inheritedParts = array(
			array(
				'color' => 'red',
				'inherited' => $ir,
			),
			array(
				'color' => 'green',
				'inherited' => $ig,
			),
			array(
				'color' => 'blue',
				'inherited' => $ib,
			),
		);

		// Calculate what the deviation is from the mid point (128) for both the
		// orginal (MASTER_STYLE) and inherited values to determine which direction
		// the outer bound (0 or 255) is.
		foreach ($parts AS $key => $part)
		{
			// get the deviation from the midpoint, which is 128 for the range 0-255 (original)
			$parts[$key]['deviation'] = abs($part['original'] - 128);
		}

		foreach ($inheritedParts AS $key => $inheritedPart)
		{
			// get the deviation from the midpoint, which is 128 for the range 0-255 (inherited)
			$inheritedParts[$key]['inherited_deviation'] = abs($inheritedPart['inherited'] - 128);
			// get the direction that the color deviates in
			$inheritedParts[$key]['direction'] = $inheritedPart['inherited'] - 128 > 0 ? '+' : '-';
		}

		// Sort by deviation. This allows us to match the most intense color from the original
		// with the most intense color of the inherited, the second most intense with the
		// second most intense, etc.
		usort($parts, function ($a, $b)
		{
			if ($a['deviation'] == $b['deviation'])
			{
				return 0;
			}

			return $a['deviation'] > $b['deviation'] ? -1 : 1;
		});

		usort($inheritedParts, function ($a, $b)
		{
			if ($a['inherited_deviation'] == $b['inherited_deviation'])
			{
				return 0;
			}

			return $a['inherited_deviation'] > $b['inherited_deviation'] ? -1 : 1;
		});

		foreach (range(0, 2) AS $i)
		{
			$parts[$i]['color'] = $inheritedParts[$i]['color'];
			$parts[$i]['inherited'] = $inheritedParts[$i]['inherited'];
			$parts[$i]['inherited_deviation'] = $inheritedParts[$i]['inherited_deviation'];
			$parts[$i]['direction'] = $inheritedParts[$i]['direction'];
		}

		$returnValue = array();

		// Do the transformation
		foreach ($parts AS $key => $part)
		{
			if ($part['direction'] == '+')
			{
				$parts[$key]['transformedValue'] = $part['inherited'] + $part['transform'];
			}
			else
			{
				$parts[$key]['transformedValue'] = $part['inherited'] - $part['transform'];
			}

			$returnValue[$part['color']] = $parts[$key]['transformedValue'];
		}

		// ensure colors are in range (min:0, max:255)
		foreach ($returnValue AS $key => $value)
		{
			$returnValue[$key] = max(0, min(255, $value));
		}

		// handle alpha values if present
		if ($ia != '' AND $p4)
		{
			$returnValue['alpha'] = $ia + $p4;
			// constrain to a range of 0.0 to 1.0
			$returnValue['alpha'] = max(0, min(1, $returnValue['alpha']));
		}
		else
		{
			$returnValue['alpha'] = $ia;
		}

		return $returnValue;
	}

	/**
	 * Wrapper function that applies the inheritance color transformation values to the
	 * inherited color and returns the resultant color value.
	 *
	 * @param  string The inherited color value
	 * @param  string The inheritance color transformation parameters (inherit_param_color)
	 *                NOTE: The format for these params is: <c>|<r>,<g>,<b>[,<a>] where:
	 *                <c> The original inherited color (the inherited color in the MASTER_STYLE) in hex, rgb, or rgba
	 *                <r> (signed int) The 1st transformation param, applies to the RED value of the original color
	 *                <g> (signed int) The 2nd transformation param, applies to the GREEN value of the original color
	 *                <b> (signed int) The 3rd transformation param, applies to the BLUE value of the original color
	 *                <a> (signed float) The 4th transformation param, applies to the opacity/alpha value
	 *                See transformColor() for a closer look at how the transformation works and
	 *                what these values actually do.
	 * @return string The new color produced by the transformation.
	 */
	public static function applyStylevarInheritanceParameters($inheritedValue, $inheritParameters)
	{
		// NOTE: There are 3 applyStylevarInheritanceParameters() functions-- the two template
		// runtimes, and the JS version in class_stylevar.php Please keep all 3 in sync.

		// NOTE: This function currently only applies to "color" stylevar properties
		// (color, border, and background)

		list($originalColor, $params) = explode('|', $inheritParameters);
		$params = explode(',', $params);
		$originalInfo = self::getColorFormatInfo($originalColor);
		$inheritedInfo = self::getColorFormatInfo($inheritedValue);

		if (empty($inheritedInfo['originalFormat']))
		{
			// return without applying any transformation because the
			// source format is an unexpected value
			return $inheritedValue;
		}

		// apply transformation
		$transformed = self::transformColor(
			$originalInfo['red'],
			$originalInfo['green'],
			$originalInfo['blue'],
			$originalInfo['alpha'],
			$inheritedInfo['red'],
			$inheritedInfo['green'],
			$inheritedInfo['blue'],
			$inheritedInfo['alpha'],
			$params[0],
			$params[1],
			$params[2],
			isset($params[3]) ? $params[3] : '1'
		);

		// format the color (back to the original if possible, or rgba if not 100% opaque)
		$colorFormat = $inheritedInfo['originalFormat'];
		if ($transformed['alpha'] < 1)
		{
			$colorFormat = 'rgba';
		}
		$converted = self::convertColorFormat($transformed, $colorFormat);

		return $converted['value'];
	}

	private static function outputStyleVar($base_stylevar, $parts = array(), $withUnits = false)
	{
		global $vbulletin;

		if (isset($base_stylevar['value']) AND $base_stylevar['value'] == false)
		{
			// Invalid stylevar value
			return;
		}

		// apply stylevar inheritance
		if (!empty($base_stylevar))
		{
			$stylevar_value_prefix = 'stylevar_';
			foreach ($base_stylevar AS $key => $value)
			{
				if ($key == 'datatype' OR strpos($key, $stylevar_value_prefix) === 0 OR strpos($key, 'inherit_param_') === 0)
				{
					continue;
				}

				$stylevar_value_key = $stylevar_value_prefix . $key;
				if (empty($value) AND !empty($base_stylevar[$stylevar_value_key]))
				{
					// set the inherited value
					$base_stylevar[$key] = self::fetchStyleVar($base_stylevar[$stylevar_value_key]);

					// if the current part is a *color* part, apply the inheritance transformation params
					if (!empty($base_stylevar['inherit_param_' . $key]) AND substr($key, -5) == 'color')
					{
						$base_stylevar[$key] = self::applyStylevarInheritanceParameters($base_stylevar[$key], $base_stylevar['inherit_param_' . $key]);
					}
				}


				// Don't give access to the stylevars directly.
				unset($base_stylevar[$stylevar_value_key]);
			}
		}

		// Set up the background gradient for "background" type stylevars for
		// both branches below
		if (isset($base_stylevar['datatype']) AND $base_stylevar['datatype'] == 'background')
		{
			foreach (array('gradient_type', 'gradient_direction', 'gradient_start_color', 'gradient_mid_color', 'gradient_end_color') AS $key)
			{
				if (!isset($base_stylevar[$key]))
				{
					$base_stylevar[$key] = '';
				}
			}

			$colorSteps = array();
			foreach (array('gradient_start_color', 'gradient_mid_color', 'gradient_end_color') AS $colorStep)
			{
				if (!empty($base_stylevar[$colorStep]))
				{
					$colorSteps[] = $base_stylevar[$colorStep];
				}
			}

			if (
				$base_stylevar['gradient_type'] AND
				$base_stylevar['gradient_direction'] AND
				count($colorSteps) >= 2
			)
			{
				$base_stylevar['gradient'] = $base_stylevar['gradient_type'] . '(' .
					$base_stylevar['gradient_direction'] . ', ' .
					implode(', ', $colorSteps) . ')';
			}
			else
			{
				$base_stylevar['gradient'] = '';
			}
		}


		// Output a stylevar *part*, for example, myBackgroundStylevar.backgroundImage
		if (isset($parts[1]))
		{
			$types = array(
				'background' => array(
					'backgroundColor' => 'color',
					'backgroundImage' => 'image',
					'backgroundRepeat' => 'repeat',
					'backgroundPositionX' => 'x',
					'backgroundPositionY' => 'y',
					'backgroundPositionUnits' => 'units',
					'backgroundGradient' => 'gradient',
					// make short names valid too
					'color' => 'color',
					'image' => 'image',
					'repeat' => 'repeat',
					'x' => 'x',
					'y' => 'y',
					'units' => 'units',
					'gradient' => 'gradient',
					'gradient_type' => 'gradient_type',
					'gradient_direction' => 'gradient_direction',
					'gradient_start_color' => 'gradient_start_color',
					'gradient_mid_color' => 'gradient_mid_color',
					'gradient_end_color' => 'gradient_end_color',
				),

				'font' => array(
					'fontWeight' => 'weight',
					'units' => 'units',
					'fontSize' => 'size',
					'lineHeight' => 'lineheight',
					'fontFamily' => 'family',
					'fontStyle' => 'style',
					'fontVariant' => 'variant',
					// make short names valid too
					'weight' => 'weight',
					'size' => 'size',
					'lineheight' => 'lineheight',
					'family' => 'family',
					'style' => 'style',
					'variant' => 'variant',
				),

				'padding' => array(
					'units' => 'units',
					'paddingTop' => 'top',
					'paddingRight' => 'right',
					'paddingBottom' => 'bottom',
					'paddingLeft' => 'left',
					// make short names valid too
					'top' => 'top',
					'right' => 'right',
					'bottom' => 'bottom',
					'left' => 'left',
				),

				'margin' => array(
					'units' => 'units',
					'marginTop' => 'top',
					'marginRight' => 'right',
					'marginBottom' => 'bottom',
					'marginLeft' => 'left',
					// make short names valid too
					'top' => 'top',
					'right' => 'right',
					'bottom' => 'bottom',
					'left' => 'left',
				),

				'border' => array(
					'borderStyle' => 'style',
					'units' => 'units',
					'borderWidth' => 'width',
					'borderColor' => 'color',
					// make short names valid too
					'style' => 'style',
					'width' => 'width',
					'color' => 'color',
				),
			);

			//handle is same for margin and padding -- allows the top value to be
			//used for all padding values
			if (isset($base_stylevar['datatype']) AND in_array($base_stylevar['datatype'], array('padding', 'margin')) AND $parts[1] <> 'units')
			{
				if (isset($base_stylevar['same']) AND $base_stylevar['same'])
				{
					$parts[1] = $base_stylevar['datatype'] . 'Top';
				}
			}

			if (isset($base_stylevar['datatype']) AND isset($types[$base_stylevar['datatype']]))
			{
				$mapping = $types[$base_stylevar['datatype']][$parts[1]];
				// If a particular stylevar has not been updated since a new "part" was
				// added to its stylevar type, it won't have the array element here. For
				// this reason, check if the array element exists before accessing it.
				// Eg. the 'lineheight' value that was added to the Font stylevar type.
				$output = isset($base_stylevar[$mapping]) ? $base_stylevar[$mapping] : null;
			}
			else
			{
				$output = $base_stylevar;
				for ($i = 1; $i < sizeof($parts); $i++)
				{
					$output = $output[$parts[$i]];
				}
			}

			// add units if required
			if ($withUnits)
			{
				// default to px
				$output .= !empty($base_stylevar['units']) ? $base_stylevar['units'] : 'px';
			}
		}
		// Output the full/combined value of a stylevar
		else
		{
			$output = '';

			switch($base_stylevar['datatype'])
			{
				case 'color':
					$output = $base_stylevar['color'];
					break;

				case 'background':
					$base_stylevar['x'] = !empty($base_stylevar['x']) ? $base_stylevar['x'] : '0';
					$base_stylevar['y'] = !empty($base_stylevar['y']) ? $base_stylevar['y'] : '0';
					$base_stylevar['repeat'] = !empty($base_stylevar['repeat']) ? $base_stylevar['repeat'] : '';
					$base_stylevar['units'] = !empty($base_stylevar['units']) ? $base_stylevar['units'] : '';
					switch ($base_stylevar['x'])
					{
						case 'stylevar-left':
							$base_stylevar['x'] = $vbulletin->stylevars['left']['string'];
							break;
						case 'stylevar-right':
							$base_stylevar['x'] = $vbulletin->stylevars['right']['string'];
							break;
						default:
							$base_stylevar['x'] = $base_stylevar['x'] . $base_stylevar['units'];
							break;
					}
					// The order of the background layers is important. Color is lowest,
					// then gradient, then the image is the topmost layer.
					// Keep syncronized with the other runtime outputStyleVar() implementation
					// and the previewBackground() Javascript funtion in class_stylevar.php
					$backgroundLayers = array();
					$backgroundLayers[] = (!empty($base_stylevar['image']) ? "$base_stylevar[image]" : 'none') . ' ' .
						$base_stylevar['repeat'] . ' ' . $base_stylevar['x'] . ' ' .
						$base_stylevar['y'] .
						$base_stylevar['units'];
					if (!empty($base_stylevar['gradient']))
					{
						$backgroundLayers[] = $base_stylevar['gradient'];
					}
					if (!empty($base_stylevar['color']))
					{
						$backgroundLayers[] = $base_stylevar['color'];
					}
					$output = implode(', ', $backgroundLayers);
					break;

				case 'textdecoration':
					if ($base_stylevar['none'])
					{
						$output = 'none';
					}
					else
					{
						unset($base_stylevar['datatype'], $base_stylevar['none']);
						$output = implode(' ', array_keys(array_filter($base_stylevar)));
					}
					break;

				case 'texttransform':
					$output = !empty($base_stylevar['texttransform']) ? $base_stylevar['texttransform'] : 'none';
					break;

				case 'textalign':
					// Default to left and not inherit or initial because the select menu in the stylevar editor
					// defaults to left (the first option). If they create the stylevar, see it's set to left and
					// don't edit it to actually save the value, we'll have an empty value here and should use left.
					$output = !empty($base_stylevar['textalign']) ? $base_stylevar['textalign'] : 'left';
					// if it's left/right, use the left/right stylevar value,
					// which changes to the opposite in RTL. See VBV-15458.
					if ($output == 'left')
					{
						$output = $vbulletin->stylevars['left']['string'];
					}
					else if ($output == 'right')
					{
						$output = $vbulletin->stylevars['right']['string'];
					}
					break;

				case 'font':
					$fontSizeKeywords = array(
						'xx-small',
						'x-small',
						'small',
						'medium',
						'large',
						'x-large',
						'xx-large',
						'smaller',
						'larger',
						'initial',
						'inherit',
					);
					$fontSize = $base_stylevar['size'];
					if (!in_array($fontSize, $fontSizeKeywords, true))
					{
						$fontSize .= $base_stylevar['units'];
					}
					$fontLineHeight = !empty($base_stylevar['lineheight']) ? '/' . $base_stylevar['lineheight'] : '';
					$output = $base_stylevar['style'] . ' ' .
						$base_stylevar['variant'] . ' ' .
						$base_stylevar['weight'] . ' ' .
						$fontSize .
						$fontLineHeight . ' ' .
						$base_stylevar['family'];
					break;

				case 'imagedir':
					$output = $base_stylevar['imagedir'];
					break;

				case 'string':
					$output = $base_stylevar['string'];
					break;

				case 'numeric':
					$output = $base_stylevar['numeric'];
					break;

				case 'size':
					$output = $base_stylevar['size'] . $base_stylevar['units'];
					break;

				case 'boolean':
					$output = $base_stylevar['boolean'];
					break;

				case 'url':
					$output = $base_stylevar['url'];
					break;

				case 'path':
					$output = $base_stylevar['path'];
					break;

				case 'fontlist':
					$output = implode(',', preg_split('/[\r\n]+/', trim($base_stylevar['fontlist']), -1, PREG_SPLIT_NO_EMPTY));
					break;

				case 'border':
					$output = $base_stylevar['width'] . $base_stylevar['units'] . ' ' .
						$base_stylevar['style'] . ' ' . $base_stylevar['color'];
					break;

				case 'dimension':
					$output = 'width: ' . intval($base_stylevar['width'])  . $base_stylevar['units'] .
						'; height: ' . intval($base_stylevar['height']) . $base_stylevar['units'] . ';';
					break;

				case 'padding':
				case 'margin':
					foreach (array('top', 'right', 'bottom', 'left') AS $side)
					{
						if (isset($base_stylevar[$side]) AND $base_stylevar[$side] != 'auto')
						{
							$base_stylevar[$side] = $base_stylevar[$side] . $base_stylevar['units'];
						}
					}
					if (isset($base_stylevar['same']) AND $base_stylevar['same'])
					{
						$output = $base_stylevar['top'];
					}
					else
					{
						if (vB_Template_Runtime::fetchStyleVar('textdirection') == 'ltr')
						{
							$output = $base_stylevar['top'] . ' ' . $base_stylevar['right'] . ' ' . $base_stylevar['bottom'] . ' ' . $base_stylevar['left'];
						}
						else
						{
							$output = $base_stylevar['top'] . ' ' . $base_stylevar['left'] . ' ' . $base_stylevar['bottom'] . ' ' . $base_stylevar['right'];
						}
					}
					break;
			}
		}

		return $output;
	}

	public static function fetchStyleVar($stylevar, $withUnits = false)
	{
		global $vbulletin;

		$parts = explode('.', $stylevar);
		if (empty($parts[0]) OR !isset($vbulletin->stylevars[$parts[0]]))
		{
			return;
		}

		return self::outputStyleVar($vbulletin->stylevars[$parts[0]], $parts, $withUnits);
	}

	public static function fetchCustomStylevar($stylevar, $user = false)
	{
		$parts = explode('.', $stylevar);

		// Both fetchStyleVar() and fetchCustomStylevar() need to fetch the stylevars
		// based on the same styleid. fetchStyleVar() uses $vbulletin->stylevars which
		// is set in css.php based on $_GET[styleid], so we need to use the same styleid
		// to fetch customized stylevars for the profile.
		// We could globalize $cssStyleid (from css.php) and use that, but using the
		// superglobal seems more explicit. This should probably be refactored in both
		// functions so we pass the styleid through. See VBV-14934 and VBV-14279.
		$cssStyleid = (int) $_GET['styleid'];

		$customstylevar = vB_Api::instanceInternal('stylevar')->get($parts[0], $user, true, $cssStyleid);

		// if there is no user passed and the customstylevar is empty (there is no session) fetch the sitedefault value
		// VBV-2213: Hiding customizations for users that have this setting enabled
		if (empty($customstylevar[$parts[0]]) OR $user === false)
		{
			return self::fetchStyleVar($stylevar);
		}

		return self::outputStyleVar($customstylevar[$parts[0]], $parts);
	}

	public static function runMaths($str)
	{
		//this would usually be dangerous, but none of the units make sense
		//in a math string anyway.  Note that there is ambiguty between the '%'
		//unit and the modulo operator.  We don't allow the latter anyway
		//(though we do allow bitwise operations !?)
		$units_found = array();
		foreach (self::$units AS $unit)
		{
			if (strpos($str, $unit))
			{
				$units_found[] = $unit;
			}
		}

		//mixed units.
		if (count($units_found) > 1)
		{
			return "/* ~~cannot perform math on mixed units ~~ found (" .
				implode(",", $units_found) . ") in $str */";
		}

		$str = preg_replace('#([^+\-*=/\(\)\d\^<>&|\.]*)#', '', $str);

		if (empty($str))
		{
			$str = '0';
		}
		else
		{
			//hack: if the math string is invalid we can get a php parse error here.
			//a bad expression or even a bad variable value (blank instead of a number) can
			//cause this to occur.  This fails quietly, but also sets the status code to 500
			//(but, due to a bug in php only if display_errors is *off* -- if display errors
			//is on, then it will work just fine only $str below will not be set.
			//
			//This can result is say an almost correct css file being ignored by the browser
			//for reasons that aren't clear (and goes away if you turn error reporting on).
			//We can check to see if eval hit a parse error and, if so, we'll attempt to
			//clear the 500 status (this does more harm then good) and send an error
			//to the file.  Since math is mostly used in css, we'll provide error text
			//that works best with that.

			try
			{
				$status = @eval("\$str = $str;");
			}
			catch(Error $e)
			{
				$status = false;
			}

			if ($status === false)
			{
				if (!headers_sent())
				{
					http_response_code(200);
				}
				return "/* Invalid math expression */";
			}

			if (count($units_found) == 1)
			{
				$str = $str.$units_found[0];
			}
		}

		return $str;
	}

	public static function linkBuild($type, $info = array(), $extra = array(), $primaryid = null, $primarytitle = null)
	{
		//allow strings of form of query strings for info or extra.  This allows us to hard code some values
		//in the templates instead of having to pass everything in from the php code.  Limitations
		//in the markup do not allow us to build arrays in the template so we need to use strings.
		//We still can't build strings from variables to pass here so we can't mix hardcoded and
		//passed values, but we do what we can.

		if (is_string($info))
		{
			parse_str($info, $new_vals);
			$info = $new_vals;
		}

		if (is_string($extra))
		{
			parse_str($extra, $new_vals);
			$extra = $new_vals;
		}

		return fetch_seo_url($type, $info, $extra, $primaryid, $primarytitle);
	}

	/**
	 * This method is defined just to avoid errors while saving the template. The real implementation
	 * is in the presentation layer.
	 * @param <type> $var
	 * @return array
	 */
	public static function parseData()
	{
		// This used to return an empty string, which caused fatal errors during eval() when saving the template.
		// So now it returns an empty array(), which is what API functions are supposed to return anyways, see VBV-12504
		return array();
	}

	/**
	 * This method is defined just to avoid errors while saving the template. The real implementation
	 * is in the presentation layer.
	 * @param <type> $var
	 * @return string
	 */
	public static function parseAction()
	{
		return '';
	}

	/**
	 * Includes a template
	 *
	 * This includeTemplate functionality is mainly included since CSS is rendered in core
	 * and we use template includes in CSS files. Otherwise this would use the presentation
	 * layer implementation.
	 *
	 * @param	string	$templateName	Template to include
	 * @param	array	$arguments	Any number items which are the name/value pairs to pass to the template as variables.
	 *
	 * @return string	Rendered template
	 */
	public static function includeTemplate($templateName, $arguments = array())
	{
		$templater = vB_Template::create($templateName);

		if (!empty($arguments))
		{
			$templater->quickRegister($arguments);
		}

		return $templater->render();
	}

	/**
	 * This method is defined just to avoid errors while saving the template. The real implementation
	 * is in the presentation layer.
	 * @param <type> $var
	 * @return string
	 */
	public static function parseJSON()
	{
		return '';
	}

	/**
	 * This method is defined just to avoid errors while saving the template. The real implementation
	 * is in the presentation layer.
	 * @param <type> $var
	 * @return string
	 */
	public static function includeCss()
	{
		return '';
	}

	/**
	 * This method is defined just to avoid errors while saving the template. The real implementation
	 * is in the presentation layer.
	 * @param <type> $var
	 * @return string
	 */
	public static function includeCssFile()
	{
		return '';
	}

	/**
	 * Returns the full path/URL to the sprite file. This is implemented in the core
	 * runtime implementation because CSS is rendered (via css.php) in core. There
	 * is currently no implementation in the frontend runtime class.
	 *
	 * @var string Sprite template name.
	 *
	 * @return string Sprite URL
	 */
	public static function includeSpriteFile($filename)
	{
		$styleLib = vB_Library::instance('style');
		$styleApi = vB_Api::instanceInternal('style');
		$datastore =  vB::getDatastore();

		$textdirection = vB_Template_Runtime::fetchStyleVar('textdirection');
		$styleid = vB_Template_Runtime::fetchStyleVar('styleid');

		$usecssfiles = $styleLib->useCssFiles($styleid);

		$vboptions = $datastore->getValue('options');

		// build sprite path
		if ($usecssfiles)
		{
			$spritepath = $styleApi->getCssStyleUrlPath($styleid, $textdirection);
			$spritepath = $spritepath['directory'] . '/';
		}
		else
		{
			$spritepath = 'sprite.php?styleid=' . $styleid . '&td=' . $textdirection . '&sprite=';
		}

		$baseurl = $vboptions['cdnurl'];
		if (!$baseurl)
		{
			$baseurl = '';
		}
		else
		{
			$baseurl .= '/';
		}

		$spritepath = $baseurl . $spritepath;

		// add sprite filename to sprite path
		if ($usecssfiles)
		{
			$cssfiledate = $styleLib->getCssFileDate($styleid);
			$fullpath = $spritepath . $cssfiledate . '-' . $filename;
		}
		else
		{
			$miscoptions = $datastore->getValue('miscoptions');
			if (!($cssdate = intval($miscoptions['cssdate'])))
			{
				$cssdate = time(); // fallback so we get the latest css
			}

			$joinChar = (strpos($spritepath, '?') === false) ? '?' : '&';
			$fullpath = $spritepath . $filename . "{$joinChar}ts=$cssdate";
		}

		return $fullpath;
	}

	/**
	 * This method is defined just to avoid errors while saving the template. The real implementation
	 * is in the presentation layer.
	 * @param <type> $var
	 * @return string
	 */
	public static function includeJs()
	{
		return '';
	}

	/**
	 * This method is defined just to avoid errors while saving the template. The real implementation
	 * is in the presentation layer.
	 * @param <type> $var
	 * @return string
	 */
	public static function includeHeadLink()
	{
		return '';
	}

	/**
	 * This method is defined just to avoid errors while saving the template. The real implementation
	 * is in the presentation layer.
	 * @param <type> $var
	 * @return string
	 */
	public static function doRedirect()
	{
		return '';
	}

	/**
	 * This method is defined just to avoid errors while saving the template. The real implementation
	 * is in the presentation layer.
	 * @param <type> $var
	 * @return string
	 */
	public static function buildUrlAdmincpTemp()
	{
		return '';
	}

	/**
	 * This method is defined just to avoid errors while saving the template. The real implementation
	 * is in the presentation layer.
	 * @param <type> $var
	 * @return string
	 */
	public static function buildUrl()
	{
		return '';
	}

	/**
	 * This method is defined just to avoid errors while saving the template. The real implementation
	 * is in the presentation layer.
	 * @param <type> $var
	 * @return string
	 */
	public static function hook($hook)
	{
		return '';
	}

	public static function vBVar($value)
	{
		return vB_String::htmlSpecialCharsUni($value);
	}

	/**
	 * This method is defined just to avoid errors while saving the template. The real implementation
	 * is in the presentation layer.
	 * @return string
	 */
	public static function parseDataWithErrors()
	{
		return '';
	}

	/**
	 * This method is defined just to avoid errors while saving the template. The real implementation
	 * is in the presentation layer.
	 * @return string
	 */
	public static function parseSchema($schemaInfo = array())
	{
		return '';
	}

	/**
	 * This method is defined just to avoid errors while saving the template. The real implementation
	 * is in the presentation layer.
	 * @param <type> $var
	 * @return string
	 */
	public static function debugExit()
	{
		return '';
	}

	/**
	 * This method is defined just to avoid errors while saving the template. The real implementation
	 * is in the presentation layer.
	 * @param string timer name
	 * @return string
	 */
	public static function debugTimer($timerName)
	{
		return '';
	}

	/**
	 * This method is defined just to avoid errors while saving the template. The real implementation
	 * is in the presentation layer.
	 *
	 * This should *never* be implemented in this class.
	 * @param string $code
	 * @return string
	 */
	public static function evalPhp($code)
	{
		return '';
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 103571 $
|| #######################################################################
\*=========================================================================*/
