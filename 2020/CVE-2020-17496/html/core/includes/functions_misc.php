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

// ###################### Start microtime_diff #######################
// get microtime difference between $starttime and NOW
function fetch_microtime_difference($starttime, $addtime = 0)
{
	$finishtime = microtime();
	$starttime = explode(' ', $starttime);
	$finishtime = explode(' ', $finishtime);
	return $finishtime[0] - $starttime[0] + $finishtime[1] - $starttime[1] + $addtime;
}

// ###################### Start getlanguagesarray #######################
function fetch_language_titles_array($titleprefix = '', $getall = true)
{
	global $vbulletin;

	$out = array();

	$languages = $vbulletin->db->query_read_slave("
		SELECT languageid, title
		FROM " . TABLE_PREFIX . "language
		" . iif($getall != true, ' WHERE userselect = 1')
	);
	while ($language = $vbulletin->db->fetch_array($languages))
	{
		$out["$language[languageid]"] = $titleprefix . $language['title'];
	}

	asort($out);

	return $out;
}


// ###################### Start vbmktime #######################
/**
 *	Convert an array into a unix timestamp taking into account the timezone correction as per
 *	the vbmktime function.
 *
 *	@param array $time -- any fields not in the array will be assumed to be zero
 *		The names of the fields intentionally match values in existing controls and
 *		are therefore not consistant with the vbmktime parameter names.
 *			int year
 *			int month
 *			int day
 *			int hour
 *			int minute
 *			int second
 *	@return int -- the unix timestamp
 */
function vbmktime_array($time)
{
	return vbmktime(
		isset($time['hour']) ? $time['hour'] : 0,
		isset($time['minute']) ? $time['minute'] : 0,
		isset($time['second']) ? $time['second'] : 0,
		isset($time['month']) ? $time['month'] : 0,
		isset($time['day']) ? $time['day'] : 0,
		isset($time['year']) ? $time['year'] : 0
	);
}

function vbmktime($hours = 0, $minutes = 0, $seconds = 0, $month = 0, $day = 0, $year = 0)
{
	$userinfo = vB::getCurrentSession()->fetch_userinfo();
	return mktime(intval($hours), intval($minutes), intval($seconds), intval($month),
		intval($day), intval($year)) + $userinfo['servertimediff'];
}

// ###################### Start gmvbdate #####################
function vbgmdate($format, $timestamp, $doyestoday = false, $locale = true)
{
	return vbdate($format, $timestamp, $doyestoday, $locale, false, true);
}

/**
 * Tries to convert a character to it's closest non extended ascii equivelant
 *
 * @param string $chr							- The character to convert
 * @returns string								- The result
 */
function fetch_try_to_ascii($chr)
{
	$conv = array(
		'�' => 'a', '�' => 'a', '�' => 'a', '�' => 'a', '�' => 'a', '�' => 'a', '�' => 'e', '�' => 'c',
		'�' => 'e', '�' => 'e', '�' => 'e', '�' => 'e', '�' => 'i', '�' => 'i', '�' => 'i', '�' => 'i',
		'�' => 'd', '�' => 'n', '�' => 'o', '�' => 'o', '�' => 'o', '�' => 'o', '�' => 'o', '�' => 'o',
		'�' => 'u', '�' => 'u', '�' => 'u', '�' => 'u', '�' => 'y', '�' => 'a', '�' => 'a', '�' => 'a',
		'�' => 'a', '�' => 'a', '�' => 'a', '�' => 'c', '�' => 'e', '�' => 'e', '�' => 'e', '�' => 'e',
		'�' => 'i', '�' => 'i', '�' => 'i', '�' => 'i', '�' => 'n', '�' => 'o', '�' => 'o', '�' => 'o',
		'�' => 'o', '�' => 'o', '�' => 'u', '�' => 'u', '�' => 'u', '�' => 'u', '�' => 'y', '�' => 'y'
	);

	return (isset($conv[$chr]) ? $conv[$chr] : $chr);
}


// ###################### Start array2bits #######################
// takes an array and returns the bitwise value
function convert_array_to_bits(&$arry, $_FIELDNAMES, $unset = 0)
{
	$bits = 0;
	foreach($_FIELDNAMES AS $fieldname => $bitvalue)
	{
		if ($arry["$fieldname"] == 1)
		{
			$bits += $bitvalue;
		}
		if ($unset)
		{
			unset($arry["$fieldname"]);
		}
	}
	return $bits;
}

// ###################### Start bitwise #######################
// Returns 1 if the bitwise is successful, 0 other wise
// usage bitwise($perms, UG_CANMOVE);
function bitwise($value, $bitfield)
{
	// Do not change this to return true/false!

	return iif(intval($value) & $bitfield, 1, 0);
}

/**
* Replaces legacy variable names in templates with their modern equivalents
*
* @param	string	Template to be processed
* @param	boolean	Handle replacement of vars outside of quotes
*
* @return	string
*/
function replace_template_variables($template, $do_outside_regex = false)
{
	// matches references to specifc arrays in templates and maps them to a better internal format
	// this function name is a slight misnomer; it can be run on phrases with variables in them too!

	// include the $, but escape it in the key
	static $variables = array(
		'\$vboptions'  => 'vB::getDatastore()->getOption',
		'\$bbuserinfo' => 'vB::getCurrentSession()->fetch_userinfo_value',
		'\$session'    => 'vB::getCurrentSession()->getAllVars()',
		'\$stylevar'   => 'vB_Template_Runtime::fetchStylevar',
	);

	// regexes to do the replacements; __FINDVAR__ and __REPLACEVAR__ are replaced before execution
	static $basic_find = array(
		'#\' \. __FINDVAR__\[(\'|)(\w+)\\1\] \. \'#',
		'#\{__FINDVAR__\[(\\\\?\'|"|)([\w$[\]]+)\\1\]\}#',
		'#__FINDVAR__\[\$(\w+)\]#',
		'#__FINDVAR__\[(\w+)\]#',
	);
	static $basic_replace1 = array(
		'\' . __REPLACEVAR__[$1$2$1] . \'',
		'" . __REPLACEVAR__[$1$2$1] . "',
		'" . __REPLACEVAR__[$$1] . "',
		'" . __REPLACEVAR__[\'$1\'] . "',
	);
	static $basic_replace2 = array(
		'\' . __REPLACEVAR__($1$2$1) . \'',
		'" . __REPLACEVAR__($1$2$1) . "',
		'" . __REPLACEVAR__($$1) . "',
		'" . __REPLACEVAR__(\'$1\') . "',
	);

	global $replacevar, $findvar;
	foreach ($variables AS $findvar => $replacevar)
	{
		if ($do_outside_regex)
		{
			// this is handles replacing of vars outside of quotes
			do
			{
				$new_template = preg_replace_callback(
					array(
						'#^([^"]*?("(?>(?>(\\\\{2})+?)|\\\\"|[^"])*"([^"]*?))*)' . $findvar . '\[(\\\\?\'|"|)([\w$[\]]+)\\5\]#sU',
						'#^([^"]*?("(?>(?>(\\\\{2})+?)|\\\\"|[^"])*"([^"]*?))*)' . $findvar . '([^[]|$)#sU',
					),
/*
					array(
						$_replacevar,
						'$1' . $replacevar . '$5',
					),
*/
					'replace_replacevar'
					,
					$template
				);
				if ($new_template == $template)
				{
					break;
				}
				$template = $new_template;
			}
			while (true);
		}

		if ($replacevar[0] == '$')
		{
			$basic_replace =& $basic_replace1;
		}
		else
		{
			$basic_replace =& $basic_replace2;
		}

		// these regular expressions handle replacement of vars inside quotes
		$this_find = str_replace('__FINDVAR__', $findvar, $basic_find);
		$this_replace = str_replace('__REPLACEVAR__', $replacevar, $basic_replace);

		$template = preg_replace($this_find, $this_replace, $template);
	}

	// straight replacements - for example $scriptpath becomes $GLOBALS['vbulletin']->scriptpath
	$template = str_replace('$scriptpath', '" . vB::getRequest()->getScriptPath() . "', $template);
	return $template;
}

function replace_replacevar($matches)
{
	global $replacevar, $findvar;
	if ($replacevar[0] == '$')
	{
		if (count($matches) == 6)
		{
			return $matches[1] . $replacevar . $matches[5];
		}
		else
		{
			return $matches[1] . $replacevar . '[' . $matches[5] . $matches[6] . $matches[5] . ']';
		}
	}
	else
	{
		if (count($matches) == 6 AND $findvar == '\$stylevar')
		{
			// This doesn't really work since $stylevar doesn't exist .. but it stops a parse error
			return $matches[1] . '$stylevar' . $matches[5];
		}
		if (!$matches[5])
		{
			$matches[5] = "'";
		}
		return $matches[1] . $replacevar . '(' . $matches[5] . $matches[6] . $matches[5] . ')';
	}
}

/**
* Returns a hidden input field containing the serialized $_POST array
*
* @return	string	HTML code containing hidden fields
*/
function construct_post_vars_html()
{
	global $vbulletin;

	$vbulletin->input->clean_gpc('p', 'postvars', vB_Cleaner::TYPE_BINARY);
	if ($vbulletin->GPC['postvars'] != '' AND verify_client_string($vbulletin->GPC['postvars']) !== false)
	{
		return '<input type="hidden" name="postvars" value="' . htmlspecialchars_uni($vbulletin->GPC['postvars']) . '" />' . "\n";
	}
	else if (sizeof($_POST) > 0)
	{
		$string = json_encode($_POST);
		return '<input type="hidden" name="postvars" value="' . htmlspecialchars_uni(sign_client_string($string)) . '" />' . "\n";
	}
	else
	{
		return '';
	}
}

function validate_string_for_interpolation($string)
{
	$start = '{$';
	$end = '}';

	$pos = 0;
	$start_count = 0;
	$content_start = 0;

	while ($pos < strlen($string))
	{
		if($start_count == 0)
		{
			$pos = strpos($string, $start, $pos);

			//no curlies
			if ($pos === false)
			{
				break;
			}

			$pos += strlen($start);

			$start_count = 1;
			$content_start = $pos;
		}
		else
		{
			$start_pos = strpos($string, $start, $pos);
			$end_pos = strpos($string, $end, $pos);

			//nothing more to find.
			if ($start_pos === false AND $end_pos === false)
			{
				break;
			}

			//end_pos is the next position found
			else if ($start_pos === false OR ($end_pos < $start_pos))
			{
				$start_count--;
				$pos = $end_pos + strlen($end);
			}

			//otherwise start_pos must've been next
			else
			{
				$start_count++;
				$pos = $end_pos + strlen($end);
			}

			if ($start_count == 0)
			{
				//this is the string from contentstart to the place before the last brace
				$curly_content = substr($string, $content_start, $pos-$content_start-1);
				if (!preg_match('#^[-\p{L}0-9_>\\[\\]"\'\\s]*$#', $curly_content))
				{
					return false;
				}
			}
		}
	}

	return true;
}

/*
	This will escape any dangerous interpolation expressions so they they display literally
	instead of being replaced (and executing potentially dangerious code).
	This is used were attempting to validate the string and/or displaying an error is problematic.
	This allows us to have *somthing* to display.
*/
function make_string_interpolation_safe($string)
{
	$start = '{$';
	$end = '}';

	$pos = 0;
	$start_count = 0;
	$content_start = 0;

	while ($pos < strlen($string))
	{
		if($start_count == 0)
		{
			$pos = strpos($string, $start, $pos);

			//no curlies
			if ($pos === false)
			{
				break;
			}

			$pos += strlen($start);

			$start_count = 1;
			$content_start = $pos;
		}
		else
		{
			$start_pos = strpos($string, $start, $pos);
			$end_pos = strpos($string, $end, $pos);

			//nothing more to find.
			if ($start_pos === false AND $end_pos === false)
			{
				break;
			}

			//end_pos is the next position found
			else if ($start_pos === false OR ($end_pos < $start_pos))
			{
				$start_count--;
				$pos = $end_pos + strlen($end);
			}

			//otherwise start_pos must've been next
			else
			{
				$start_count++;
				$pos = $end_pos + strlen($end);
			}

			if ($start_count == 0)
			{
				//this is the string from contentstart to the place before the last brace
				$curly_content = substr($string, $content_start, $pos-$content_start-1);
				if (!preg_match('#^[A-Za-z0-9-_>\\[\\]"\'\\s]*$#', $curly_content))
				{
					$count = 0;
					$curly_content = '{\\$' . str_replace('{$', '{\\$', $curly_content, $count) . '}';

					$string = substr_replace($string, $curly_content, $content_start - strlen($start),
						$pos-$content_start-1+strlen($start)+strlen($end));

					//adjust the pos to account for the fact that we've added characters to the string.  After this, pos
					//should still be on the closing brace of the curly expression.
					$pos += ($count + 1);
				}
			}
		}
	}

	return $string;
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 101127 $
|| #######################################################################
\*=========================================================================*/
