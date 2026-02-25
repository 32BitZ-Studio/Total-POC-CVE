<?php
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

class vB5_Template_Runtime
{
	//This is intended to allow the runtime to know that template it is rendering.
	//It's ugly and shouldn't be used lightly, but making some features widely
	//available to all templates is uglier.
	private static $templates = array();

	public static function startTemplate($template)
	{
		array_push(self::$templates, $template);
	}

	public static function endTemplate()
	{
		array_pop(self::$templates);
	}

	private static function currentTemplate()
	{
		return end(self::$templates);
	}

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

	public static function date($timestamp, $format = '', $doyestoday = 1, $adjust = 1)
	{
		/* It appears that in vB5 its not customary to pass
		the dateformat from the template so we load it here.

		Dates formatted in templates need to be told what format to
		use and if today/yesterday/hours ago is to be used (if enabled)

		This function needs to accept most of vbdate's options if
		we still allow the admin to dictate formats and we still
		use today/yesterday/hours ago in some places and not in others.
		*/
		if (!$format)
		{
			$format = vB5_Template_Options::instance()->get('options.dateformat');
		}

		// Timenow.
		if (strtolower($timestamp) == 'timenow')
		{
			$timestamp = time();
		}
		else
		{
			/* Note that negative
			timestamps are allowed in vB5 */
			$timestamp = intval($timestamp);
		}

		return self::vbdate($format, $timestamp, $doyestoday, true, $adjust);
	}

	public static function time($timestamp, $timeformat = '')
	{
		if (!$timeformat)
		{
			$timeformat = vB5_Template_Options::instance()->get('options.timeformat');
			$userLangLocale = vB5_User::get('lang_locale');
			if ($userLangLocale OR vB5_User::get('lang_timeoverride'))
			{
				$timeformat = vB5_User::get('lang_timeoverride');
			}
		}

		if (empty($timestamp))
		{
			$timestamp = 0;
		}

		return self::vbdate($timeformat, $timestamp, true);
	}

	public static function datetime($timestamp, $format = 'date, time', $formatdate = '', $formattime = '')
	{
		$options = vB5_Template_Options::instance();

		if (!$formatdate)
		{
			$formatdate = $options->get('options.dateformat');
		}

		if (!$formattime)
		{
			$formattime = $options->get('options.timeformat');
			$userLangLocale = vB5_User::get('lang_locale');
			if (($userLangLocale OR vB5_User::get('lang_timeoverride')))
			{
				$formattime = vB5_User::get('lang_timeoverride');
			}
		}

		// Timenow.
		$timenow = time();
		if (strtolower($timestamp) == 'timenow')
		{
			$timestamp = $timenow;
		}
		else
		{
			/* Note that negative
			timestamps are allowed in vB5 */
			$timestamp = intval($timestamp);
		}


		$date = self::vbdate($formatdate, $timestamp, true);
		if ($options->get('options.yestoday') == 2)
		{
			// Process detailed "Datestamp Display Option"
			// 'Detailed' will show times such as '1 Minute Ago', '1 Hour Ago', '1 Day Ago', and '1 Week Ago'.
			$timediff = $timenow - $timestamp;

			if ($timediff >= 0 AND $timediff < 3024000)
			{
				return $date;
			}
		}

		$time = self::vbdate($formattime, $timestamp, true);

		return str_replace(array('date', 'time'), array($date, $time), $format);
	}

	public static function escapeJS($javascript)
	{
		return str_replace(array('"', "'", "\n", "\r"), array('\"', "\'", ' ', ' '), $javascript);
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
		$phrase = vB5_Template_Phrase::instance();

		//allow the first paramter to be a phrase array	( array($phraseName, $arg1, $arg2, ...)
		//otherwise the parameter is the phraseName and the args list is the phrase array
		//this allows us to pass phrase arrays around and use them directly without unpacking them
		//in the templates (which is both difficult and inefficient in the template code)
		if (is_array($phraseName))
		{
			return $phrase->register($phraseName);
		}
		else
		{
			return $phrase->register(func_get_args());
		}
	}

	// See vB_Template_Runtime for the full docblock
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

	// See vB_Template_Runtime for the full docblock
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

	// See vB_Template_Runtime for the full docblock
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

	// See vB_Template_Runtime for the full docblock
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

	// See vB_Template_Runtime for the full docblock
	private static function applyStylevarInheritanceParameters($inheritedValue, $inheritParameters)
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
		$stylevars = vB5_Template_Stylevar::instance();

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
			if (in_array($base_stylevar['datatype'], array('padding', 'margin')) AND $parts[1] <> 'units')
			{
				if (isset($base_stylevar['same']) AND $base_stylevar['same'])
				{
					$parts[1] = $base_stylevar['datatype'] . 'Top';
				}
			}

			if (isset($types[$base_stylevar['datatype']]))
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
							$base_stylevar['x'] = $stylevars->get('left.string');
							break;
						case 'stylevar-right':
							$base_stylevar['x'] = $stylevars->get('right.string');
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
						$output = $stylevars->get('left.string');
					}
					else if ($output == 'right')
					{
						$output = $stylevars->get('right.string');
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
					if (filter_var($base_stylevar['url'], FILTER_VALIDATE_URL))
					{
						$output = $base_stylevar['url'];
					}
					else
					{
						// Assume that the url is relative url
						$output = /**vB5_Template_Options::instance()->get('options.frontendurl') . '/' . **/ $base_stylevar['url'];
					}
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
						if (self::fetchStyleVar('textdirection') == 'ltr')
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
		$parts = explode('.', $stylevar);

		return self::outputStyleVar(vB5_Template_Stylevar::instance()->get($parts[0]), $parts, $withUnits);
	}

	public static function fetchCustomStylevar($stylevar, $user = false)
	{
		$parts = explode('.', $stylevar);
		$api = Api_InterfaceAbstract::instance();

		// get user info for the currently logged in user
		$customstylevar  = $api->callApi('stylevar', 'get', array($parts[0], $user));
		//$customstylevar = vB_Api::instanceInternal('stylevar')->get($parts[0], $user);
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
				$str = $str . $units_found[0];
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

	public static function parseData()
	{
		$arguments = func_get_args();
		$controller = array_shift($arguments);
		$method = array_shift($arguments);

		$api = Api_InterfaceAbstract::instance();
		$result = $api->callApi($controller, $method, $arguments, false, true);

		if (is_array($result) AND isset($result['errors']))
		{
			throw new vB5_Exception_Api($controller, $method, $arguments, $result['errors']);
		}

		return $result;
	}

	public static function parseDataWithErrors()
	{
		$arguments = func_get_args();
		$controller = array_shift($arguments);
		$method = array_shift($arguments);

		$api = Api_InterfaceAbstract::instance();
		$result = $api->callApi($controller, $method, $arguments);

		return $result;
	}

	public static function parseAction()
	{
		$arguments = func_get_args();
		$controller = array_shift($arguments);
		$method = array_shift($arguments);

		$controller = str_replace(':', '.', $controller);
		$class = vB5_Frontend_Routing::getControllerClassFromName($controller);
		if (!class_exists($class) || !method_exists($class, $method))
		{
			return null;
		}

		$result =  call_user_func_array(array($class, $method), $arguments);

		return $result;
	}

	public static function parseJSON()
	{
		$arguments = func_get_args();
		$searchJSON = array_shift($arguments);
		$arguments = array_pop($arguments);
		$search_structure = json_decode($searchJSON, true);
		if(empty($search_structure))
		{
			return "{}";
		}
		$all_arguments = array();

		foreach ($arguments as $argument)
		{
			if (!is_array($argument))
			{
				continue;
			}

			// Stick widgetConfig.module_filter_node into searchJSON.
			if (isset($argument['module_filter_nodes']) AND !isset($search_structure['filterChannels']))
			{
				// Special handling for dynamically replacing "current channel". If channelid exists
				// (e.g. from page var), replaceJSON() will dynamically set this.
				// The search criteria receives this in add_inc_exc_channel_filter().
				$argument['module_filter_nodes']['currentChannelid'] = array('param' => 'channelid');

				$search_structure['module_filter_nodes'] = $argument['module_filter_nodes'];
			}

			$all_arguments = array_merge($argument, $all_arguments);
		}
		$search_structure = self::replaceJSON($search_structure, $all_arguments);

		return json_encode($search_structure);
	}

	protected static function replaceJSON($search_structure, $all_arguments)
	{
		foreach ($search_structure AS $filter => $value)
		{
			if(is_array($value))
			{
				if(array_key_exists("param", $value))
				{
					$param_name = $value['param'];
					$param_value = null;
					if(array_key_exists($param_name, $all_arguments))
					{
						$search_structure[$filter] = (string) $all_arguments[$param_name];
					}
					else
					{
						unset($search_structure[$filter]);
						// re-indexing an indexed array so it won't be considered associative
						if(is_numeric($filter))
						{
							$search_structure = array_values($search_structure);
						}
					}
				}
				else
				{
					$val = self::replaceJSON($value, $all_arguments);
					if($val === null)
					{
						unset($search_structure[$filter]);
					}
					else
					{
						$search_structure[$filter] = $val;
					}
				}
			}
		}
		if(empty($search_structure))
		{
			$search_structure = null;
		}

		return $search_structure;
	}

	public static function includeTemplate()
	{
		$arguments = func_get_args();

		$template_id = array_shift($arguments);
		$args = array_shift($arguments);

		$cache = vB5_Template_Cache::instance();

		return $cache->register($template_id, $args);
	}

	public static function includeJs()
	{
		$scripts = func_get_args();

		if (!empty($scripts) AND ($scripts[0] == 'insert_here' OR $scripts[0] == '1'))
		{
			$scripts = array_slice($scripts, 1);
			if (!empty($scripts))
			{
				$javascript = vB5_Template_Javascript::instance();
				$rendered =  $javascript->insertJsInclude($scripts);
				return $rendered;
			}

			return '';
		}

		$javascript = vB5_Template_Javascript::instance();

		return $javascript->register($scripts);
	}

	public static function includeHeadLink()
	{
		$link = func_get_args();
		$headlink = vB5_Template_Headlink::instance();

		return $headlink->register(array_shift($link));
	}

	public static function includeCss()
	{
		$stylesheets = func_get_args();
		foreach ($stylesheets AS $key => $stylesheet)
		{
			//For when we remove a record per below
			if (empty($stylesheet))
			{
				unset($stylesheets[$key]);
				continue;
			}

			if ((substr($stylesheet, -7, 7) == 'userid=' ))
			{
				if (($key < count($stylesheets) - 1) AND (is_numeric($stylesheets[$key + 1])))
				{
					$stylesheets[$key] .= $stylesheets[$key + 1];
					unset($stylesheets[$key + 1]);
				}
				if (isset($stylesheets[$key + 2]) AND isset($stylesheets[$key + 3]) AND
					($stylesheets[$key + 2] == '&showusercss=') OR ($stylesheets[$key + 2] == '&amp;showusercss='))
				{
					$stylesheets[$key] .= $stylesheets[$key + 2] . $stylesheets[$key + 3];
					unset($stylesheets[$key + 2]);
					unset($stylesheets[$key + 3]);
				}
			}
		}
		$stylesheet = vB5_Template_Stylesheet::instance();

		return $stylesheet->register($stylesheets);
	}

	public static function includeCssFile()
	{
		$stylesheets = func_get_args();
		$stylesheet = vB5_Template_Stylesheet::instance();

		return $stylesheet->getCssFile($stylesheets[0]);
	}

	/**
	 * This is a no-op here, and is implemented in the core vB_Template_Runtime,
	 * since CSS is rendered in the back end via css.php, and the {vb:spritepath}
	 * tag is only used in CSS files.
	 */
	public static function includeSpriteFile($filename)
	{
		return '';
	}

	public static function doRedirect($url, $bypasswhitelist = false)
	{
		$application = vB5_ApplicationAbstract::instance();
		if (!$bypasswhitelist AND !$application->allowRedirectToUrl($url))
		{
			throw new vB5_Exception('invalid_redirect_url');
		}

		if (vB5_Request::get('useEarlyFlush'))
		{
			echo '<script type="text/javascript">window.location = "' . $url . '";</script>';
		}
		else
		{
			header('Location: ' . $url);
		}

		die();
	}

	/**
	 * Formats a UNIX timestamp into a human-readable string according to vBulletin prefs
	 *
	 * Note: Ifvbdate() is called with a date format other than than one in $vbulletin->options[],
	 * set $locale to false unless you dynamically set the date() and strftime() formats in the vbdate() call.
	 *
	 * @param	string	Date format string (same syntax as PHP's date() function). It also supports the following vB specific date/time format:
	 *                  'registered' - Format For Registration Date
	 *                  'cal1' - Format For Birthdays with Year Specified
	 *                  'cal2' - Format For Birthdays with Year Unspecified
	 *                  'event' - Format event start date in the upcoming events module
	 *                  'log' - Log Date Format
	 * @param	integer	Unix time stamp
	 * @param	boolean	If true, attempt to show strings like "Yesterday, 12pm" instead of full date string
	 * @param	boolean	If true, and user has a language locale, use strftime() to generate language specific dates
	 * @param	boolean	If true, don't adjust time to user's adjusted time .. (think gmdate instead of date!)
	 * @param	boolean	If true, uses gmstrftime() and gmdate() instead of strftime() and date()
	 *
	 * @return	string	Formatted date string
	 */

	protected static function vbdate($format, $timestamp = 0, $doyestoday = false, $locale = true, $adjust = true, $gmdate = false)
	{
		$timenow = time();
		if (!$timestamp)
		{
			$timestamp = $timenow;
		}

		$options = vB5_Template_Options::instance();

		$uselocale = false;

		// TODO: use vB_Api_User::fetchTimeOffset() for maintainnability...
		$timezone = vB5_User::get('timezoneoffset');
		if (vB5_User::get('dstonoff') || (vB5_User::get('dstauto') AND $options->get('options.dstonoff')))
		{
			// DST is on, add an hour
			$timezone++;
		}
		$hourdiff = (date('Z', time()) / 3600 - $timezone) * 3600;

		if (vB5_User::get('lang_locale'))
		{
			$userLangLocale = vB5_User::get('lang_locale');
		}

		if (!empty($userLangLocale))
		{
			$uselocale = true;
			$currentlocale = setlocale(LC_TIME, 0);
			setlocale(LC_TIME, $userLangLocale);
			if (substr($userLangLocale, 0, 5) != 'tr_TR')
			{
				setlocale(LC_CTYPE, $userLangLocale);
			}
		}

		if ($uselocale AND $locale)
		{
			if ($gmdate)
			{
				$datefunc = 'gmstrftime';
			}
			else
			{
				$datefunc = 'strftime';
			}
		}
		else
		{
			if ($gmdate)
			{
				$datefunc = 'gmdate';
			}
			else
			{
				$datefunc = 'date';
			}
		}

		// vB Specified format
		switch ($format)
		{
			case 'registered':
				if (($uselocale OR vB5_User::get('lang_registereddateoverride')) AND $locale)
				{
					$format = vB5_User::get('lang_registereddateoverride');
				}
				else
				{
					$format = $options->get('options.registereddateformat');
				}
				break;

			case 'cal1':
				if (($uselocale OR vB5_User::get('lang_calformat1override')) AND $locale)
				{
					$format = vB5_User::get('lang_calformat1override');
				}
				else
				{
					$format = $options->get('options.calformat1');
				}
				break;

			case 'cal2':
				if (($uselocale OR vB5_User::get('lang_calformat2override')) AND $locale)
				{
					$format = vB5_User::get('lang_calformat2override');
				}
				else
				{
					$format = $options->get('options.calformat2');
				}
				break;

			case 'event':
				if (($uselocale OR vB5_User::get('lang_eventdateformatoverride')) AND $locale)
				{
					$format = vB5_User::get('lang_eventdateformatoverride');
				}
				else
				{
					$format = $options->get('options.eventdateformat');
				}
				break;

			// NOTE: We don't handle the lang_pickerdateformatoverride item here,
			// since it is only used by flatpickr, and not by any template {vb:date} calls
			// AND since the format tokens are specific to flatpickr, not PHP's date or strftime.

			case 'log':
				if (($uselocale OR vB5_User::get('lang_logdateoverride')) AND $locale)
				{
					$format = vB5_User::get('lang_logdateoverride');
				}
				else
				{
					$format = $options->get('options.logdateformat');
				}
				break;
		}

		if (!$adjust)
		{
			$hourdiff = 0;
		}

		if ($timestamp < 0)
		{
			$timestamp_adjusted = $timestamp;
		}
		else
		{
			$timestamp_adjusted = max(0, $timestamp - $hourdiff);
		}

		if ($format == $options->get('options.dateformat') AND ($uselocale OR vB5_User::get('lang_dateoverride')) AND $locale)
		{
			$format = vB5_User::get('lang_dateoverride');
		}

		if (!$uselocale AND $format == vB5_User::get('lang_dateoverride'))
		{
			if ($gmdate)
			{
				$datefunc = 'gmstrftime';
			}
			else
			{
				$datefunc = 'strftime';
			}
		}
		if (!$uselocale AND $format == vB5_User::get('lang_timeoverride'))
		{
			if ($gmdate)
			{
				$datefunc = 'gmstrftime';
			}
			else
			{
				$datefunc = 'strftime';
			}
		}

		if (($format == $options->get('options.dateformat') OR $format == vB5_User::get('lang_dateoverride')) AND $doyestoday AND $options->get('options.yestoday'))
		{
			if ($options->get('options.yestoday') == 1)
			{
				if (!defined('TODAYDATE'))
				{
					define('TODAYDATE', self::vbdate('n-j-Y', $timenow, false, false));
					define('YESTDATE', self::vbdate('n-j-Y', $timenow - 86400, false, false));
					define('TOMDATE', self::vbdate('n-j-Y', $timenow + 86400, false, false));
				}

				$datetest = @date('n-j-Y', $timestamp - $hourdiff);

				if ($datetest == TODAYDATE)
				{
					$returndate = self::parsePhrase('today');
				}
				else if ($datetest == YESTDATE)
				{
					$returndate = self::parsePhrase('yesterday');
				}
				else
				{
					$returndate = $datefunc($format, $timestamp_adjusted);
				}
			}
			else
			{
				$timediff = $timenow - $timestamp;

				if ($timediff >= 0)
				{
					if ($timediff < 120)
					{
						$returndate = self::parsePhrase('1_minute_ago');
					}
					else if ($timediff < 3600)
					{
						$returndate = self::parsePhrase('x_minutes_ago', intval($timediff / 60));
					}
					else if ($timediff < 7200)
					{
						$returndate = self::parsePhrase('1_hour_ago');
					}
					else if ($timediff < 86400)
					{
						$returndate = self::parsePhrase('x_hours_ago', intval($timediff / 3600));
					}
					else if ($timediff < 172800)
					{
						$returndate = self::parsePhrase('1_day_ago');
					}
					else if ($timediff < 604800)
					{
						$returndate = self::parsePhrase('x_days_ago', intval($timediff / 86400));
					}
					else if ($timediff < 1209600)
					{
						$returndate = self::parsePhrase('1_week_ago');
					}
					else if ($timediff < 3024000)
					{
						$returndate = self::parsePhrase('x_weeks_ago', intval($timediff / 604900));
					}
					else
					{
						$returndate = $datefunc($format, $timestamp_adjusted);
					}
				}
				else
				{
					$returndate = $datefunc($format, $timestamp_adjusted);
				}
			}
		}
		else
		{
			if ($format == 'Y' AND $uselocale AND $locale)
			{
				$format = '%Y'; // For copyright year
			}

			if ($format == 'r' AND $uselocale AND $locale)
			{
				$datefunc = 'date'; // For debug
			}
			$returndate = $datefunc($format, $timestamp_adjusted);
		}

		if (!empty($userLangLocale))
		{
			setlocale(LC_TIME, $currentlocale);
			if (substr($currentlocale, 0, 5) != 'tr_TR')
			{
				setlocale(LC_CTYPE, $currentlocale);
			}
		}

		return $returndate;
	}

	public static function buildUrlAdmincpTemp($route, array $parameters = array())
	{
		$config = vB5_Config::instance();

		static $baseurl = null;
		if ($baseurl === null)
		{
			$baseurl = vB5_Template_Options::instance()->get('options.frontendurl');
		}

		// @todo: this might need to be a setting
		$admincp_directory = 'admincp';

		// @todo: This would be either index.php or empty, depending on use of mod_rewrite
		$index_file = 'index.php';

		$url = "$baseurl/$admincp_directory/$index_file";

		if (!empty($route))
		{
			$url .= '/' . htmlspecialchars($route);
		}
		if (!empty($parameters))
		{
			$url .= '?' . http_build_query($parameters, '', '&amp;');
		}

		return $url;
	}

	/**
	 * Returns the URL for a route with the passed parameters
	 * @param mixed $route - Route identifier (routeid or name)
	 * @param array $data - Data for building route
	 * @param array $extra - Additional data to be added
	 * @param array $options - Options for building URL
	 *					- noBaseUrl: skips adding the baseurl
	 *					- anchor: anchor id to be added
	 * @return type
	 * @throws vB5_Exception_Api
	 */
	public static function buildUrl($route, $data = array(), $extra = array(), $options = array())
	{
		return vB5_Template_Url::instance()->register($route, $data, $extra, $options);
	}

	public static function hook($hookName, $vars = array())
	{
		$hooks = Api_InterfaceAbstract::instance()->callApi('template','fetchTemplateHooks', array('hookName' => $hookName));

		$placeHolders = '';
		if ($hooks)
		{
			foreach ($hooks AS $templates)
			{
				foreach($templates AS $template => $arguments)
				{
					$passed = self::buildVars($arguments, $vars);
					$placeHolders .= self::includeTemplate($template, $passed) . "\r\n";
				}
			}

			unset($vars);
		}

		// Check whether or not we should show the hook positions and the "add hook" links, but only once
		// per page load.
		static $showhookposition, $addhooklink;
		if (is_null($showhookposition))
		{
			$showhookposition = vB5_Template_Options::instance()->get('options.showhookposition');
			$addhooklink = false;
			if ($showhookposition)
			{
				$showhooklinkOption = vB5_Template_Options::instance()->get('options.showhooklink');
				switch ($showhooklinkOption)
				{
					case 2:
						$addhooklink = true;
						break;
					case 1: // show to can admin products
						$userContext = vB::getUserContext();
						$addhooklink = $userContext->hasAdminPermission('canadminproducts');
						break;
					case 0:
					default:
						// do not show the links
						break;
				}
			}
		}

		if ($showhookposition)
		{
			$htmlSafeHookName = htmlentities($hookName);

			$placeHolders = "<!-- BEGIN_HOOK: $htmlSafeHookName -->" . $placeHolders . "<!-- END_HOOK: $htmlSafeHookName -->";
			if ($addhooklink)
			{
				$placeHolders = "
						<div>
						<a class=\"debug-hook-info\" href=\"admincp/hook.php?do=add&hookname=" . htmlentities(urlencode($hookName)). "\" title=\"$htmlSafeHookName\">
							ADD HOOK ($hookName)
						</a>
						</div>
					" . $placeHolders;
			}
		}

		return $placeHolders;
	}

	public static function buildVars($select, &$master)
	{
		$args = array();

		foreach ($select AS $argname => $argval)
		{
			$result = array();

			foreach ($argval AS $varname => $value)
			{
				if(is_array($value))
				{
					self::nextLevel($result, $value, $master[$varname]);
				}
				else
				{
					$result = $master[$varname];
				}
			}

			$args[$argname] = $result;
		}

		return $args;
	}

	public static function nextLevel(&$res, $array, &$master)
	{
		foreach ($array AS $varname => $value)
		{
			if(is_array($value))
			{
				self::nextLevel($res, $value, $master[$varname]);
			}
			else
			{
				$res = $master[$varname];
			}
		}
	}

	/**
	* Browser detection system - returns whether or not the visiting browser is the one specified
	*
	* @param	string	Browser name (opera, ie, mozilla, firebord, firefox... etc. - see $is array)
	* @param	float	Minimum acceptable version for true result (optional)
	*
	* @return	boolean
	*/
	public static function isBrowser($browser, $version = 0)
	{
		static $is;
		if (!is_array($is))
		{
			$useragent = strtolower($_SERVER['HTTP_USER_AGENT']); //strtolower($_SERVER['HTTP_USER_AGENT']);
			$is = array(
				'opera'     => 0,
				'ie'        => 0,
				'mozilla'   => 0,
				'firebird'  => 0,
				'firefox'   => 0,
				'camino'    => 0,
				'konqueror' => 0,
				'safari'    => 0,
				'webkit'    => 0,
				'webtv'     => 0,
				'netscape'  => 0,
				'mac'       => 0
			);

			// detect opera
				# Opera/7.11 (Windows NT 5.1; U) [en]
				# Mozilla/4.0 (compatible; MSIE 6.0; MSIE 5.5; Windows NT 5.0) Opera 7.02 Bork-edition [en]
				# Mozilla/4.0 (compatible; MSIE 6.0; MSIE 5.5; Windows NT 4.0) Opera 7.0 [en]
				# Mozilla/4.0 (compatible; MSIE 5.0; Windows 2000) Opera 6.0 [en]
				# Mozilla/4.0 (compatible; MSIE 5.0; Mac_PowerPC) Opera 5.0 [en]
			if (strpos($useragent, 'opera') !== false)
			{
				preg_match('#opera(/| )([0-9\.]+)#', $useragent, $regs);
				$is['opera'] = $regs[2];
			}

			// detect internet explorer
				# Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; Q312461)
				# Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; .NET CLR 1.0.3705)
				# Mozilla/4.0 (compatible; MSIE 5.22; Mac_PowerPC)
				# Mozilla/4.0 (compatible; MSIE 5.0; Mac_PowerPC; e504460WanadooNL)
			if (strpos($useragent, 'msie ') !== false AND !$is['opera'])
			{
				preg_match('#msie ([0-9\.]+)#', $useragent, $regs);
				$is['ie'] = $regs[1];
			}

			// Detect IE11(+)
				# Mozilla/5.0 (IE 11.0; Windows NT 6.3; Trident/7.0; .NET4.0E; .NET4.0C; rv:11.0)
			if (strpos($useragent, 'trident') !== false AND !$is['opera'] AND !$is['ie'])
			{
				// Trident = IE, So look for rv number
				preg_match('#rv:([0-9\.]+)#', $useragent, $regs);
				$is['ie'] = $regs[1];
			}

			// detect macintosh
			if (strpos($useragent, 'mac') !== false)
			{
				$is['mac'] = 1;
			}

			// detect safari
				# Mozilla/5.0 (Macintosh; U; PPC Mac OS X; en-us) AppleWebKit/74 (KHTML, like Gecko) Safari/74
				# Mozilla/5.0 (Macintosh; U; PPC Mac OS X; en) AppleWebKit/51 (like Gecko) Safari/51
				# Mozilla/5.0 (Windows; U; Windows NT 6.0; en) AppleWebKit/522.11.3 (KHTML, like Gecko) Version/3.0 Safari/522.11.3
				# Mozilla/5.0 (iPhone; U; CPU like Mac OS X; en) AppleWebKit/420+ (KHTML, like Gecko) Version/3.0 Mobile/1C28 Safari/419.3
				# Mozilla/5.0 (iPod; U; CPU like Mac OS X; en) AppleWebKit/420.1 (KHTML, like Gecko) Version/3.0 Mobile/3A100a Safari/419.3
			if (strpos($useragent, 'applewebkit') !== false)
			{
				preg_match('#applewebkit/([0-9\.]+)#', $useragent, $regs);
				$is['webkit'] = $regs[1];

				if (strpos($useragent, 'safari') !== false)
				{
					preg_match('#safari/([0-9\.]+)#', $useragent, $regs);
					$is['safari'] = $regs[1];
				}
			}

			// detect konqueror
				# Mozilla/5.0 (compatible; Konqueror/3.1; Linux; X11; i686)
				# Mozilla/5.0 (compatible; Konqueror/3.1; Linux 2.4.19-32mdkenterprise; X11; i686; ar, en_US)
				# Mozilla/5.0 (compatible; Konqueror/2.1.1; X11)
			if (strpos($useragent, 'konqueror') !== false)
			{
				preg_match('#konqueror/([0-9\.-]+)#', $useragent, $regs);
				$is['konqueror'] = $regs[1];
			}

			// detect mozilla
				# Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.4b) Gecko/20030504 Mozilla
				# Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.2a) Gecko/20020910
				# Mozilla/5.0 (X11; U; Linux 2.4.3-20mdk i586; en-US; rv:0.9.1) Gecko/20010611
			if (strpos($useragent, 'gecko') !== false AND !$is['safari'] AND !$is['konqueror'] AND !$is['ie'])
			{
				// See bug #26926, this is for Gecko based products without a build
				$is['mozilla'] = 20090105;
				if (preg_match('#gecko/(\d+)#', $useragent, $regs))
				{
					$is['mozilla'] = $regs[1];
				}

				// detect firebird / firefox
					# Mozilla/5.0 (Windows; U; WinNT4.0; en-US; rv:1.3a) Gecko/20021207 Phoenix/0.5
					# Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.4b) Gecko/20030516 Mozilla Firebird/0.6
					# Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.4a) Gecko/20030423 Firebird Browser/0.6
					# Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.6) Gecko/20040206 Firefox/0.8
				if (strpos($useragent, 'firefox') !== false OR strpos($useragent, 'firebird') !== false OR strpos($useragent, 'phoenix') !== false)
				{
					preg_match('#(phoenix|firebird|firefox)( browser)?/([0-9\.]+)#', $useragent, $regs);
					$is['firebird'] = $regs[3];

					if ($regs[1] == 'firefox')
					{
						$is['firefox'] = $regs[3];
					}
				}

				// detect camino
					# Mozilla/5.0 (Macintosh; U; PPC Mac OS X; en-US; rv:1.0.1) Gecko/20021104 Chimera/0.6
				if (strpos($useragent, 'chimera') !== false OR strpos($useragent, 'camino') !== false)
				{
					preg_match('#(chimera|camino)/([0-9\.]+)#', $useragent, $regs);
					$is['camino'] = $regs[2];
				}
			}

			// detect web tv
			if (strpos($useragent, 'webtv') !== false)
			{
				preg_match('#webtv/([0-9\.]+)#', $useragent, $regs);
				$is['webtv'] = $regs[1];
			}

			// detect pre-gecko netscape
			if (preg_match('#mozilla/([1-4]{1})\.([0-9]{2}|[1-8]{1})#', $useragent, $regs))
			{
				$is['netscape'] = "$regs[1].$regs[2]";
			}
		}

		// sanitize the incoming browser name
		$browser = strtolower($browser);
		if (substr($browser, 0, 3) == 'is_')
		{
			$browser = substr($browser, 3);
		}

		// return the version number of the detected browser if it is the same as $browser
		if ($is["$browser"])
		{
			// $version was specified - only return version number if detected version is >= to specified $version
			if ($version)
			{
				if ($is["$browser"] >= $version)
				{
					return $is["$browser"];
				}
			}
			else
			{
				return $is["$browser"];
			}
		}

		// if we got this far, we are not the specified browser, or the version number is too low
		return 0;
	}

	public static function vBVar($value)
	{
		return vB5_String::htmlSpecialCharsUni($value);
	}

	/**
	 *
	 * @param array $schemaInfo
	 *				- id (string)
	 *				- itemprop (string)
	 *				- itemscope (bool)
	 *				- itemref (string)
	 *				- itemtype (string)
	 *				- datetime (int)
	 *				- tag (string)
	 * @return string
	 */
	public static function parseSchema($schemaInfo = array())
	{
		$schemaEnabled = vB5_Template_Options::instance()->get('options.schemaenabled');
		$attributes = array('id', 'itemprop', 'itemscope', 'itemref', 'itemtype', 'datetime', 'content', 'rel');
		$allowedTags = array('meta', 'link');

		if ($schemaEnabled AND !empty($schemaInfo) AND is_array($schemaInfo))
		{
			$output = '';
			foreach ($attributes AS $name)
			{
				if (!empty($schemaInfo[$name]))
					switch($name)
					{
						case 'itemscope':
							$output .= " itemscope";
							break;

						case 'datetime':
							$output .= " $name=\"" . date('Y-m-d\TH:i:s', $schemaInfo[$name]) . '"';
							break;

						default:
							$output .= " $name=\"{$schemaInfo[$name]}\"";
							break;
				}
			}

			if (!empty($schemaInfo['tag']) AND in_array($schemaInfo['tag'], $allowedTags))
			{
				return "<{$schemaInfo['tag']} $output />";
			}
			else
			{
				return trim($output);
			}
		}
		else
		{
			return '';
		}
	}

	/**
	 * Implements {vb:debugexit}, which allows placing a "breakpoint" in a template
	 * for debugging purposes.
	 */
	public static function debugExit()
	{
		echo ob_get_clean();
		echo "<br />\n";
		echo "=======================<br />\n";
		echo "======= vB Exit =======<br />\n";
		echo "=======================<br />\n";
		exit;
	}

	/**
	 * Implements {vb:debugtimer}, which allows timing exectution time
	 * takes from one call to another.
	 *
	 * @param  string timer name
	 * @return string rendered time
	 */
	public static function debugTimer($timerName)
	{
		static $timers = array();

		if (!isset($timers[$timerName]))
		{
			// start timer
			$timers[$timerName] = microtime(true);

			return '';
		}
		else
		{
			// stop timer and return elapsed time
			$elapsed = microtime(true) - $timers[$timerName];

			return '<div style="border:1px solid red;padding:10px;margin:10px;">' . htmlspecialchars($timerName) . ': ' . $elapsed . '</div>';
		}
	}

	public static function evalPhp($code)
	{
		//only allow the PHP widget template to do this.  This prevents a malicious user
		//from hacking something into a different template.
		if (self::currentTemplate() != 'widget_php')
		{
			return '';
		}
		ob_start();
		eval($code);
		$output = ob_get_contents();
		ob_end_clean();
		return $output;
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 103485 $
|| #######################################################################
\*=========================================================================*/
