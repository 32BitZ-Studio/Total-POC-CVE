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

/**
 * String
 *
 * @package vBulletin
 * @author vBulletin Development Team
 * @version $Revision: 103731 $
 * @since $Date: 2019-12-30 17:18:31 -0800 (Mon, 30 Dec 2019) $

 */
class vB5_String
{

	/**
	 * Converts an integer into a UTF-8 character string
	 *
	 * @param	integer	Integer to be converted
	 *
	 * @return	string
	 */
	public static function convertIntToUtf8($intval)
	{
		$intval = intval($intval);
		switch ($intval)
		{
			// 1 byte, 7 bits
			case 0:
				return chr(0);
			case ($intval & 0x7F):
				return chr($intval);

			// 2 bytes, 11 bits
			case ($intval & 0x7FF):
				return chr(0xC0 | (($intval >> 6) & 0x1F)) .
					chr(0x80 | ($intval & 0x3F));

			// 3 bytes, 16 bits
			case ($intval & 0xFFFF):
				return chr(0xE0 | (($intval >> 12) & 0x0F)) .
					chr(0x80 | (($intval >> 6) & 0x3F)) .
					chr(0x80 | ($intval & 0x3F));

			// 4 bytes, 21 bits
			case ($intval & 0x1FFFFF):
				return chr(0xF0 | ($intval >> 18)) .
					chr(0x80 | (($intval >> 12) & 0x3F)) .
					chr(0x80 | (($intval >> 6) & 0x3F)) .
					chr(0x80 | ($intval & 0x3F));
		}

		return '';
	}

	/**
	 * Attempts to intelligently wrap excessively long strings onto multiple lines
	 *
	 * @param	integer max word wrap length
	 * @param	string	Text to be wrapped
	 * @param	string	Text to insert at the wrap point
	 *
	 * @return	string
	 */
	public static function fetchWordWrappedString($text, $limit, $wraptext = ' ')
	{
		$limit = intval($limit);

		$utf8Modifier = (strtolower(self::getTempCharset()) == 'utf-8') ? 'u' : '';

		if ($limit > 0 AND !empty($text)) {
			return preg_replace('
				#((?>[^\s&/<>"\\-\[\]]|&[\#a-z0-9]{1,7};){' . $limit . '})(?=[^\s&/<>"\\-\[\]]|&[\#a-z0-9]{1,7};)#i' . $utf8Modifier,
				'$0' . $wraptext,
				$text
			);
		}
		else
		{
			return $text;
		}
	}

	/**
	 * Unicode-safe version of htmlspecialchars()
	 *
	 * @param	string	Text to be made html-safe
	 *
	 * @return	string
	 */
	public static function htmlSpecialCharsUni($text, $entities = true)
	{
		if ($entities)
		{
			$text = preg_replace_callback(
				'/&((#([0-9]+)|[a-z]+);)?/si',
				array(__CLASS__, 'htmlSpecialCharsUniCallback'),
				$text
			);
		}
		else
		{
			$text = preg_replace(
				// translates all non-unicode entities
				'/&(?!(#[0-9]+|[a-z]+);)/si',
				'&amp;',
				$text
			);
		}

		return str_replace(
			// replace special html characters
			array('<', '>', '"'),
			array('&lt;', '&gt;', '&quot;'),
			$text
		);
	}

	protected static function htmlSpecialCharsUniCallback($matches)
	{
		if (count($matches) == 1)
		{
			return '&amp;';
		}

		if (strpos($matches[2], '#') === false)
		{
			// &gt; like
			if ($matches[2] == 'shy')
			{
				return '&shy;';
			}
			else
			{
				return "&amp;$matches[2];";
			}
		}
		else
		{
			// Only convert chars that are in ISO-8859-1
			if (($matches[3] >= 32 AND $matches[3] <= 126)
				OR
				($matches[3] >= 160 AND $matches[3] <= 255)
			)
			{
				return "&amp;#$matches[3];";
			}
			else
			{
				return "&#$matches[3];";
			}
		}
	}

	// To be used as callback function
	/**
	 *
	 * @param string $val
	 * @return bool
	 */
	public static function isEmpty($val)
	{
		return !empty($val);
	}

	/**
	 * Tests a string to see if it's a valid email address
	 *
	 * @param	string	Email address
	 *
	 * @return	boolean
	 */
	public static function isValidEmail($email)
	{
		// checks for a valid email format
		return preg_match('#^[a-z0-9.!\#$%&\'*+-/=?^_`{|}~]+@([0-9.]+|([^\s\'"<>@,;]+\.+[a-z]{2,63}))$#si', $email);
	}

	/**
	 * Replaces any non-printing ASCII characters with the specified string.
	 * This also supports removing Unicode characters automatically when
	 * the entered value is >255 or starts with a 'u'.
	 *
	 * @param	string	Text to be processed
	 * @param	string	String with which to replace non-printing characters
	 *
	 * @return	string
	 */
	public static function stripBlankAscii($text, $replace, $blankasciistrip)
	{
		static $blanks = null;

		if ($blanks === null AND trim($blankasciistrip) != '')
		{
			$blanks = array();

			$charset = self::getTempCharset();

			$charset_unicode = (strtolower($charset) == 'utf-8');

			$raw_blanks = preg_split('#\s+#', $blankasciistrip, -1, PREG_SPLIT_NO_EMPTY);
			foreach ($raw_blanks AS $code_point)
			{
				if ($code_point[0] == 'u') {
					// this is a unicode character to remove
					$code_point = intval(substr($code_point, 1));
					$force_unicode = true;
				}
				else
				{
					$code_point = intval($code_point);
					$force_unicode = false;
				}

				if ($code_point > 255 OR $force_unicode OR $charset_unicode) {
					// outside ASCII range or forced Unicode, so the chr function wouldn't work anyway
					$blanks[] = '&#' . $code_point . ';';
					$blanks[] = self::convertIntToUtf8($code_point);
				}
				else
				{
					$blanks[] = chr($code_point);
				}
			}
		}

		if ($blanks)
		{
			$text = str_replace($blanks, $replace, $text);
		}

		return $text;
	}

	/**
	 * Case-insensitive version of strpos(). Defined if it does not exist.
	 *
	 * @param	string		Text to search for
	 * @param	string		Text to search in
	 * @param	int			Position to start search at
	 *
	 * @param	int|false	Position of text if found, false otherwise
	 */
	public static function stripos($haystack, $needle, $offset = 0)
	{
		if (!function_exists('stripos'))
		{
			$foundstring = stristr(substr($haystack, $offset), $needle);
			return $foundstring === false ? false : strlen($haystack) - strlen($foundstring);
		}
		else
		{
			return stripos($haystack, $needle, $offset);
		}
	}

	/**
	 * Returns a string where HTML entities have been converted back to their original characters
	 *
	 * @param	string	String to be parsed
	 * @param	boolean	Convert unicode characters back from HTML entities?
	 *
	 * @return	string
	 */
	public static function unHtmlSpecialChars($text, $doUniCode = false)
	{
		if ($doUniCode)
		{
			$text = preg_replace_callback('/&#([0-9]+);/siU', function($matches)
			{
				return vB5_String::convertIntToUtf8($matches[1]);

			}, $text);
		}

		return str_replace(array('&lt;', '&gt;', '&quot;', '&amp;'), array('<', '>', '"', '&'), $text);
	}


	/**
	 * Chops off a string at a specific length, counting entities as once character
	 * and using multibyte-safe functions if available.
	 *
	 * @param	string	String to chop
	 * @param	integer	Number of characters to chop at
	 *
	 * @return	string	Chopped string
	 */
	public static function vbChop($string, $length)
	{
		$length = intval($length);
		if ($length <= 0) {
			return $string;
		}

		// Pretruncate the string to something shorter, so we don't run into memory problems with
		// very very very long strings at the regular expression down below.
		//
		// UTF-32 allows 0x7FFFFFFF code space, meaning possibility of code point: &#2147483647;
		// If we assume entire string we want to keep is in this butchered form, we need to keep
		// 13 bytes per character we want to output. Strings actually encoded in UTF-32 takes 4
		// bytes per character, so 13 is large enough to cover that without problem, too.
		//
		// ((Unlike the regex below, no memory problems here with very very very long comments.))
		$pretruncate = 13 * $length;
		$string = substr($string, 0, $pretruncate);

		if (preg_match_all('/&(#[0-9]+|lt|gt|quot|amp);/', $string, $matches, PREG_OFFSET_CAPTURE)) {
			// find all entities because we need to count them as 1 character
			foreach ($matches[0] AS $match)
			{
				$entity_length = strlen($match[0]);
				$offset = $match[1];

				// < since length starts at 1 but offset starts at 0
				if ($offset < $length) {
					// this entity happens in the chop area, so extend the length to include this
					// -1 since the entity should still count as 1 character
					$length += strlen($match[0]) - 1;
				}
				else
				{
					break;
				}
			}
		}

		$substr = '';
		if (function_exists('mb_substr')) {
			$charset = self::getTempCharset();
			$substr = $charset ? @mb_substr($string, 0, $length, $charset) : @mb_substr($string, 0, $length);
		}

		if ($substr != '') {
			return $substr;
		}
		else
		{
			return substr($string, 0, $length);
		}
	}

	/**
	 * Attempts to do a character-based strlen on data that might contain HTML entities.
	 * By default, it only converts numeric entities but can optional convert &quot;,
	 * &lt;, etc. Uses a multi-byte aware function to do the counting if available.
	 *
	 * @param	string	String to be measured
	 * @param	boolean	If true, run unhtmlspecialchars on string to count &quot; as one, etc.
	 *
	 * @return	integer	Length of string
	 */
	public static function vbStrlen($string, $unHtmlSpecialChars = false)
	{
		$string = preg_replace('#&\#([0-9]+);#', '_', $string);
		if ($unHtmlSpecialChars) {
			// don't try to translate unicode entities ever, as we want them to count as 1 (above)
			$string = self::unHtmlSpecialChars($string, false);
		}

		if (function_exists('mb_strlen') AND $length = @mb_strlen($string, self::getTempCharSet())) {
			return $length;
		}
		else
		{
			return strlen($string);
		}
	}

	/**
	 * This is a temporary function used to get the stylevar 'charset' (added for presentation).
	 *
	 * @return string, stylevar charset value
	 */
	public static function getTempCharset()
	{
		// first check for user info
		$encoding = vB5_User::get('lang_charset');

	   	if (!$encoding)
		{
			//todo: we don't have a charset variable, although users can add one.
	   		$encoding = vB5_Template_Runtime::fetchStyleVar('charset');
	   	}

	   	return strtoupper($encoding);
	}

	/**
	 * This gets the charset based on the current language
	 *
	 * @return string, stylevar charset value
	 */
	public static function getCharset()
	{
		// first check for user info
		$encoding = vB5_User::get('lang_charset');

		if (!$encoding)
		{
			$encoding = Api_InterfaceAbstract::instance()->callApi('phrase', 'getLanguageid', array('getCharset' => true));

			if (empty($encoding['charset']))
			{
				return 'UTF-8';
			}
			$encoding = $encoding['charset'];
		}

		return strtoupper($encoding);
	}

	// These functions are copied from vB4 core for charset conversion.
	// #############################################################################
	/**
	 * Converts Unicode entities of the format %uHHHH where each H is a hexadecimal
	 * character to &#DDDD; or the appropriate UTF-8 character based on current charset.
	 *
	 * @param	Mixed		array or text
	 *
	 * @return	string	Decoded text
	 */
	public static function convertUrlencodedUnicode($text)
	{
		if (is_array($text)) {
			foreach ($text AS $key => $value)
			{
				$text["$key"] = self::convertUrlencodedUnicode($value);
			}
			return $text;
		}

		$charset = self::getTempCharset();

		$return = preg_replace_callback(
			'#%u([0-9A-F]{1,4})#i',
			function($matches) use ($charset)
			{
				return vB5_String::convertUnicodeCharToCharset(hexdec($matches[1]), $charset);
			},
			$text
		);

		$lower_charset = strtolower($charset);

		if ($lower_charset != 'utf-8' AND function_exists('html_entity_decode')) {
			// this converts certain &#123; entities to their actual character
			// set values; don't do this if using UTF-8 as it's already done above.
			// note: we don't want to convert &gt;, etc as that undoes the effects of STR_NOHTML
			$return = preg_replace('#&([a-z]+);#i', '&amp;$1;', $return);

			if ($lower_charset == 'windows-1251') {
				// there's a bug in PHP5 html_entity_decode that decodes some entities that
				// it shouldn't. So double encode them to ensure they don't get decoded.
				$return = preg_replace('/&#(128|129|1[3-9][0-9]|2[0-4][0-9]|25[0-5]);/', '&amp;#$1;', $return);
			}

			$return = @html_entity_decode($return, ENT_NOQUOTES, $charset);
		}

		return $return;
	}

	/**
	 * Converts a single unicode character to the desired character set if possible.
	 * Attempts to use iconv if it's available.
	 * Callback function for the regular expression in vB5_String::convertUrlencodedUnicode().
	 *
	 * @param	integer	Unicode code point value
	 * @param	string	Character to convert to
	 *
	 * @return	string	Character in desired character set or as an HTML entity
	 */
	public static function convertUnicodeCharToCharset($unicode_int, $charset)
	{
		$is_utf8 = (strtolower($charset) == 'utf-8');

		if ($is_utf8) {
			return self::convertIntToUtf8($unicode_int);
		}

		if (function_exists('iconv')) {
			// convert this character -- if unrepresentable, it should fail
			$output = @iconv('UTF-8', $charset, self::convertIntToUtf8($unicode_int));
			if ($output !== false AND $output !== '') {
				return $output;
			}
		}

		return "&#$unicode_int;";
	}

	/**
	 * Poor man's urlencode that only encodes specific characters and preserves unicode.
	 * Use urldecode() to decode.
	 *
	 * @param	string	String to encode
	 * @return	string	Encoded string
	 */
	public static function urlencodeUni($str)
	{
		return preg_replace_callback(
			'`([\s/\\\?:@=+$,<>\%"\'\.\r\n\t\x00-\x1f\x7f]|(?(?<!&)#|#(?![0-9]+;))|&(?!#[0-9]+;)|(?<!&#\d|&#\d{2}|&#\d{3}|&#\d{4}|&#\d{5});)`',
			function($matches)
			{
				return urlencode($matches[1]);
			},
			$str
		);
	}

	/**
	 * Encodes a value as a JSON string, attempting to correct invalid UTF8 characters
	 * that would otherwise make PHP's json_encode fail.
	 *
	 * @param  mixed  Value to encode
	 * @param  int    Options for json_encode
	 *
	 * @return string Encoded string
	 */
	public static function jsonEncode($value, $options = 0)
	{
		// We may want to incorporate detecting and converting
		// string values to UTF8 as part of this function.

		$encoded = json_encode($value, $options);

		$error = json_last_error();
		switch ($error)
		{
			case JSON_ERROR_UTF8:
				// try (re-)encoding to UTF8 to remove invalid characters
				$value = self::toCharset($value, 'UTF-8', 'UTF-8');
				$encoded = json_encode($value, $options);
				break;
		}

		return $encoded;
	}

	/**
	 * Converts a string to utf8
	 *
	 * @param	string	The variable to clean
	 * @param	string	The source charset
	 * @param	bool	Whether to strip invalid utf8 if we couldn't convert
	 * @return	string	The reencoded string
	 */
	public static function toUtf8($in, $charset = false, $strip = true)
	{
		if ('' === $in OR false === $in OR is_null($in)) {
			return $in;
		}

		// Fallback to UTF-8
		if (!$charset) {
			$charset = 'UTF-8';
		}

		// Try iconv
		if (function_exists('iconv')) {
			$out = @iconv($charset, 'UTF-8//IGNORE', $in);
			return $out;
		}

		// Try mbstring
		if (function_exists('mb_convert_encoding')) {
			return @mb_convert_encoding($in, 'UTF-8', $charset);
		}

		if (!$strip) {
			return $in;
		}

		// Strip non valid UTF-8
		// TODO: Do we really want to do this?
		$utf8 = '#([\x09\x0A\x0D\x20-\x7E]' . # ASCII
			'|[\xC2-\xDF][\x80-\xBF]' . # non-overlong 2-byte
			'|\xE0[\xA0-\xBF][\x80-\xBF]' . # excluding overlongs
			'|[\xE1-\xEC\xEE\xEF][\x80-\xBF]{2}' . # straight 3-byte
			'|\xED[\x80-\x9F][\x80-\xBF]' . # excluding surrogates
			'|\xF0[\x90-\xBF][\x80-\xBF]{2}' . # planes 1-3
			'|[\xF1-\xF3][\x80-\xBF]{3}' . # planes 4-15
			'|\xF4[\x80-\x8F][\x80-\xBF]{2})#S'; # plane 16

		$out = '';
		$matches = array();
		while (preg_match($utf8, $in, $matches))
		{
			$out .= $matches[0];
			$in = substr($in, strlen($matches[0]));
		}

		return $out;
	}

	/**
	 * Converts a string from one character encoding to another.
	 * If the target encoding is not specified then it will be resolved from the current
	 * language settings.
	 *
	 * @param	string|array	The string/array to convert
	 * @param	string	The source encoding
	 * @param string 	The target encoding -- defaults to the current encoding
	 * @param string	Whether to do ncr encoding of special characters.
	 * @return	string	The target encoding
	 */
	public static function toCharset($in, $in_encoding, $target_encoding = false, $do_ncr = true)
	{
		if (!$target_encoding)
		{
			if (!($target_encoding = self::getTempCharset()))
			{
				return $in;
			}
		}

		if (is_object($in))
		{
			foreach ($in as $key => $val)
			{
				$in->$key = self::toCharset($val, $in_encoding, $target_encoding);
			}

			return $in;
		}
		else if (is_array($in))
		{
			foreach ($in as $key => $val)
			{
				$in["$key"] = self::toCharset($val, $in_encoding, $target_encoding);
			}

			return $in;
		}
		else if (is_string($in))
		{
			// ISO-8859-1 or other Western charset doesn't support Asian ones so that we need to NCR them
			// Iconv will ignore them
			if ($do_ncr AND preg_match("/^[LATIN1|ISO|Windows|IBM|MAC|CP]/i", $target_encoding))
			{
				$in = self::ncrencode($in, true, true);
			}

			// Try iconv
			if (function_exists('iconv'))
			{
				// Try iconv
				$out = @iconv($in_encoding, $target_encoding . '//IGNORE', $in);
				if ($out === false)
				{
					//some implementations don't appear to like the '//IGNORE' flag,
					//particularly MUSL used by alpine linux
					$out = @iconv($in_encoding, $target_encoding, $in);
				}

				if($out !== false)
				{
					return $out;
				}
			}

			// Try mbstring
			if (function_exists('mb_convert_encoding'))
			{
				return @mb_convert_encoding($in, $target_encoding, $in_encoding);
			}

			//this isn't good, but there isn't much else we can do if they don't have
			//the tools installed. However its better than setting everything to null
			error_log('Could not do charset conversion -- install mbstring php extension');
			return $in;
		}
		else
		{
			// if it's not a string, array or object, don't modify it
			return $in;
		}

	}

	/**
	 * Strips NCRs from a string.
	 *
	 * @param	string	The string to strip from
	 * @return	string	The result
	 */
	public static function stripncrs($str)
	{
		return preg_replace('/(&#[0-9]+;)/', '', $str);
	}

	/**
	 * Checks if PCRE supports unicode
	 *
	 * @return bool
	 */
	protected static function isPcreUnicode()
	{
		static $enabled;

		if (NULL !== $enabled)
		{
			return $enabled;
		}

		return $enabled = @preg_match('#\pN#u', '1');
	}

	/**
	 * Converts a UTF-8 string into unicode NCR equivelants.
	 *
	 * @param	string	String to encode
	 * @param	bool	Only ncrencode unicode bytes
	 * @param	bool	If true and $skip_ascii is true, it will skip windows-1252 extended chars
	 * @return	string	Encoded string
	 */
	public static function ncrencode($str, $skip_ascii = false, $skip_win = false)
	{
		if (!$str)
		{
			return $str;
		}

		if (function_exists('mb_encode_numericentity'))
		{
			if ($skip_ascii)
			{
				if ($skip_win)
				{
					$start = 0xFE;
				}
				else
				{
					$start = 0x80;
				}
			}
			else
			{
				$start = 0x0;
			}
			return mb_encode_numericentity($str, array($start, 0xffff, 0, 0xffff), 'UTF-8');
		}

		if (self::isPcreUnicode())
		{
			return preg_replace_callback(
				'#\X#u',
				function ($matches) use($skip_ascii, $skip_win)
				{
					return vB5_String::ncrencodeMatches($matches, (int)$skip_ascii , (int)$skip_win);
				},
				$str
			);
		}

		return $str;
	}

	/**
	 * NCR encodes matches from a preg_replace.
	 * Single byte characters are preserved.
	 *
	 * @param	string	The character to encode
	 * @return	string	The encoded character
	 */
	public static function ncrencodeMatches($matches, $skip_ascii = false, $skip_win = false)
	{
		$ord = self::ordUni($matches[0]);

		if ($skip_win) {
			$start = 254;
		}
		else
		{
			$start = 128;
		}

		if ($skip_ascii AND $ord < $start) {
			return $matches[0];
		}

		return '&#' . self::ordUni($matches[0]) . ';';
	}

	/**
	 * Gets the Unicode Ordinal for a UTF-8 character.
	 *
	 * @param	string	Character to convert
	 * @return	int		Ordinal value or false if invalid
	 */
	public static function ordUni($chr)
	{
		// Valid lengths and first byte ranges
		static $check_len = array(
			1 => array(0, 127),
			2 => array(192, 223),
			3 => array(224, 239),
			4 => array(240, 247),
			5 => array(248, 251),
			6 => array(252, 253)
		);

		// Get length
		$blen = strlen($chr);

		// Get single byte ordinals
		$b = array();
		for ($i = 0; $i < $blen; $i++)
		{
			$b[$i] = ord($chr[$i]);
		}

		// Check expected length
		foreach ($check_len AS $len => $range)
		{
			if (($b[0] >= $range[0]) AND ($b[0] <= $range[1])) {
				$elen = $len;
			}
		}

		// If no range found, or chr is too short then it's invalid
		if (!isset($elen) OR ($blen < $elen)) {
			return false;
		}

		// Normalise based on octet-sequence length
		switch ($elen)
		{
			case (1):
				return $b[0];
			case (2):
				return ($b[0] - 192) * 64 + ($b[1] - 128);
			case (3):
				return ($b[0] - 224) * 4096 + ($b[1] - 128) * 64 + ($b[2] - 128);
			case (4):
				return ($b[0] - 240) * 262144 + ($b[1] - 128) * 4096 + ($b[2] - 128) * 64 + ($b[3] - 128);
			case (5):
				return ($b[0] - 248) * 16777216 + ($b[1] - 128) * 262144 + ($b[2] - 128) * 4096 + ($b[3] - 128) * 64 + ($b[4] - 128);
			case (6):
				return ($b[0] - 252) * 1073741824 + ($b[1] - 128) * 16777216 + ($b[2] - 128) * 262144 + ($b[3] - 128) * 4096 + ($b[4] - 128) * 64 + ($b[5] - 128);
		}
	}

	/**
	 * UTF-8 Safe Parse_url
	 * http://us3.php.net/manual/en/function.parse-url.php
	 *
	 * @param	string	$url
	 * @param	int		$component
	 *
	 * @return	mixed
	 */
	public static function parseUrl($url, $component = -1)
	{
		$removeScheme = false;

		if (strpos($url, '//') === 0)
		{
			// Schemeless URLS like '//www.vbulletin.com/actualpath' are treated as being a huge path
			// rather than having a domain. This is fixed in PHP 5.4.7+, but let's make it consistent
			// since we're supporting PHP 5.3+.
			$removeScheme = true;
			$url = 'http:' . $url;
		}

		$return = parse_url(
			self::encodeUtf8Url($url),
			$component
		);

		if ($removeScheme)
		{
			if (is_array($return))
			{
				unset($return['scheme']);
			}
			else if ($component == PHP_URL_SCHEME AND $return !== false)
			{
				$return = null;
			}
		}

		if (is_array($return))
		{
			foreach ($return as $key => $value)
			{
				$return[$key] = self::decodeUtf8Url($value);
			}

			if (isset($return['port']))
			{
				// Port is supposed to return an integer. The rest are strings.
				$return['port'] = intval($return['port']);
			}
		}
		else if ($component != PHP_URL_PORT AND !empty($return))
		{
			$return = self::decodeUtf8Url($return);
		}

		return $return;
	}

	/**
	 *  Encode a variable to a JSON string using the local charset.
	 *
	 *  If the local charset isn't utf-8, $value will be converted to utf-8 and the
	 *  resultant json string will be convert back to the local charset
	 *
	 *  @param $value -- value to encode
	 *  @param $options -- json encoding options JSON_UNESCAPED_UNICODE is automatically added
	 *  @param $depth -- per json_encode
	 */
	//this is an awkward fit for this, but we need a static function for compatibilty
	//with the template code and that doesn't work with the new string class.
	//we should be hollowing this class out by backing the functions onto the
	//utility string class.
	public static function jsonEncodeLocalCharset($value, $options = 0, $depth = 512)
	{
		$string = Api_InterfaceAbstract::instance()->stringInstance();

		if ($string->isDefaultCharset('utf-8'))
		{
			return json_encode($value, JSON_UNESCAPED_UNICODE | $options, $depth);
		}
		else
		{
			$newvalue = $string->toUtf8($value);
			$newvalue = json_encode($newvalue, JSON_UNESCAPED_UNICODE | $options, $depth);
			$newvalue = $string->toDefault($newvalue, 'utf-8');
			return $newvalue;
		}
	}

	/**
	 * Encode a UTF-8 Encoded URL and urlencode it while leaving control characters in tact.
	 * (It can also work with single byte encodings, but its purpose is to supply UTF-8 urls on non UTF-8 forums.)
	 *
	 * @param	string	url
	 *
	 * @return	string
	 */
	public static function encodeUtf8Url($url)
	{

		static $controlCharsArr = array();

		if (empty($controlCharsArr))
		{
			// special url control characters needed for parsing urls
			// per http://tools.ietf.org/html/rfc3986#section-2.2    "Reserved Characters"
			// note that the % *must* go last.  The array version of str_replace acts sequentially through
			// the array so that
			// $x = str_replace(array('a', 'b'), array('x', 'y'), $x);
			//
			// is the same as
			// $x = str_replace('a', 'x', $x);
			// $x = str_replace('b', 'y', $x);
			//
			// in particular
			// $x = str_replace(array('a', 'b'), array('b', 'y'), $x);
			//
			// will have the same end result as
			// $x = str_replace(array('a', 'b'), array('y', 'y'), $x);
			//
			// what this means here is if you have a string like
			// http://site.com?x=this%2Fthat
			//
			// then the intial urlencode will convert that to
			//
			// http://site.com?x=this%252Fthat
			//
			// but if the % preceded the & in the control chars string then we will first do the replace
			// for it to
			//
			// http://site.com?x=this%2Fthat
			//
			// and then for the & to
			//
			// http://site.com?x=this&that
			//
			// which is a very different URL than the one we started with.  Given that the purpose of this
			// function is to encode the UTF8 chars without affecting the control chars, this is is a problem.
			// Also a good lesson on what encode everything and decode the stuff you didn't want encoded is
			// a problematic approach in general.
			$controlChars = '!@#$^&*()+?/:;"\'\\,.<>=[]%';
			$controlCharsCount = strlen($controlChars);

			for ($char = 0; $char < $controlCharsCount; $char++)
			{
				$controlCharsArr[urlencode($controlChars[$char])] = $controlChars[$char];
			}
		}

		return str_replace(array_keys($controlCharsArr), array_values($controlCharsArr), urlencode($url));
	}

	public static function decodeUtf8Url($url)
	{
		static $controlCharsArr = array();

		if (empty($controlCharsArr))
		{
			//the percent needs to be at the beginning for much the same reason it needs to be at
			//end in the encode function.
			$controlChars = '%!@#$^&*()+?/:;"\'\\,.<>=[]';
			$controlCharsCount = strlen($controlChars);

			for ($char = 0; $char < $controlCharsCount; $char++)
			{
				$code = urlencode($controlChars[$char]);
				$controlCharsArr[$code] = urlencode($code);
			}

			//this is hacked all to hell but we are unescaping spaces in ways that break things
			//we need to figure out way to do this while no escaping an unescaping at random
			//but it's really hard to figure out what we need to do
			$controlCharsArr['+'] = urlencode('+');
			$controlCharsArr['%20'] = urlencode('%20');
		}

		$result = urldecode(str_replace(array_keys($controlCharsArr), array_values($controlCharsArr), $url));
		return $result;
	}

	/**
	 * Monitors the text for the words specified in options[monitorwords] and returns
	 * any that are found.
	 *
	 * @param array|string String or array of strings to check for the monitored words
	 *
	 * @return array       Array of monitored words that were found (or an empty array)
	 */
	public static function getMonitoredWords($text)
	{
		// Since the separation of core and the presentation layer
		// isn't really a thing, let's avoid duplication and keep
		// the code in one place for now.
		vB_String::getMonitoredWords($text);
	}

	/**
	 * Replaces any instances of words censored in $options['censorwords'] with $options['censorchar']
	 *
	 * @param	string	Text to be censored
	 *
	 * @return	string
	 */
	public static function fetchCensoredText($text)
	{
		static $censorwords;

		if (!$text)
		{
			// return $text rather than nothing, since this could be '' or 0
			return $text;
		}

		$options = vB5_Template_Options::instance()->getOptions();
		$options = $options['options'];

		if ($options['enablecensor'] AND !empty($options['censorwords']))
		{
			if (empty($censorwords))
			{
				$options['censorwords'] = preg_quote($options['censorwords'], '#');
				$censorwords = preg_split('#[ \r\n\t]+#', $options['censorwords'], -1, PREG_SPLIT_NO_EMPTY);
			}

			foreach ($censorwords AS $censorword)
			{
				if (substr($censorword, 0, 2) == '\\{')
				{
					if (substr($censorword, -2, 2) == '\\}')
					{
						// prevents errors from the replace if the { and } are mismatched
						$censorword = substr($censorword, 2, -2);
					}

					// ASCII character search 0-47, 58-64, 91-96, 123-127
					$nonword_chars = '\x00-\x2f\x3a-\x40\x5b-\x60\x7b-\x7f';

					// words are delimited by ASCII characters outside of A-Z, a-z and 0-9
					$text = preg_replace(
						'#(?<=[' . $nonword_chars . ']|^)' . $censorword . '(?=[' . $nonword_chars . ']|$)#si',
						str_repeat($options['censorchar'], self::vbStrlen($censorword)),
						$text
					);
				}
				else
				{
					$text = preg_replace("#$censorword#si", str_repeat($options['censorchar'], self::vbStrlen($censorword)), $text);
				}
			}
		}

		return $text;
	}

	/**
	 * Trims a string to the specified length while keeping whole words.
	 *
	 * @param	string		String to be trimmed.
	 * @param	integer		Number of characters to aim for in the trimmed string. If 0 then return
	 * 	the title unchanged.
	 * @param  	boolean 	Append "..." to shortened text.
	 *
	 * @return	string 		Trimmed string.
	 */
	public static function fetchTrimmedTitle($title, $chars, $append = true)
	{
		if ($chars)
		{
			// limit to 10 lines (\n{240}1234567890 does weird things to the thread preview)
			$titlearr = preg_split('#(\r\n|\n|\r)#', $title);
			$title = '';
			$i = 0;
			foreach ($titlearr AS $key)
			{
				$title .= "$key \n";
				$i++;
				if ($i >= 10)
				{
					break;
				}
			}
			$title = trim($title);
			unset($titlearr);

			if (self::vbStrlen($title) > $chars)
			{
				$title = self::vbChop($title, $chars);
				if (($pos = strrpos($title, ' ')) !== false)
				{
					$title = substr($title, 0, $pos);
				}
				if ($append)
				{
					$title .= '...';
				}
			}
		}

		return $title;
	}


	public static function isVbCharset($charset)
	{
		return self::areCharsetsEqual($charset, self::getCharset());
	}

	public static function areCharsetsEqual($charset1, $charset2)
	{
		//applying rules 1 & 2 from
		//http://www.unicode.org/reports/tr22/tr22-7.html#Charset_Alias_Matching
		//declining to apply rule three because its trickier and I've never seen a
		//charset that would trigger it.
		$re = '#[^a-zA-Z0-9]#';
		$charset1 = preg_replace($re, '', $charset1);
		$charset2 = preg_replace($re, '', $charset2);

		return (strcasecmp($charset1, $charset2) == 0);
	}


	/**
	* Strips away bbcode from a given string, leaving plain text
	*
	* @param	string	Text to be stripped of bbcode tags
	* @param	boolean	If true, strip away quote tags AND their contents
	* @param	boolean	If true, use the fast-and-dirty method rather than the shiny and nice method
	* @param	boolean	If true, display the url of the link in parenthesis after the link text
	* @param	boolean	If true, strip away img/video tags and their contents
	* @param	boolean	If true, keep [quote] tags. Useful for API.
	*
	* @return	string
	*/
	public static function stripBbcode($message, $stripquotes = false, $fast_and_dirty = false, $showlinks = true, $stripimg = false, $keepquotetags = false)
	{
		$find = array();
		$replace = array();
		$block_elements = array(
			'code',
			'php',
			'html',
			'quote',
			'indent',
			'center',
			'left',
			'right',
			'video',
		);

		if ($stripquotes)
		{
			// [quote=username] and [quote]
			$message = strip_quotes($message);
		}

		if ($stripimg)
		{
			$find[] = '#\[(attach|img|video).*\].+\[\/\\1\]#siU';
			$replace[] = '';
		}

		// a really quick and rather nasty way of removing vbcode
		if ($fast_and_dirty)
		{

			// any old thing in square brackets
			$find[] = '#\[.*/?\]#siU';
			$replace[] = '';

			$message = preg_replace($find, $replace, $message);
		}
		// the preferable way to remove vbcode
		else
		{

			// simple links
			$find[] = '#\[(email|url)=("??)(.+)\\2\]\\3\[/\\1\]#siU';
			$replace[] = '\3';

			// named links
			$find[] = '#\[(email|url)=("??)(.+)\\2\](.+)\[/\\1\]#siU';
			$replace[] = ($showlinks ? '\4 (\3)' : '\4');

			// replace links (and quotes if specified) from message
			$message = preg_replace($find, $replace, $message);

			if ($keepquotetags)
			{
				$regex = '#\[(?!quote)(\w+?)(?>[^\]]*?)\](.*)(\[/\1\])#siU';
			}
			else
			{
				$regex = '#\[(\w+?)(?>[^\]]*?)\](.*)(\[/\1\])#siU';
			}

			// strip out all other instances of [x]...[/x]
			while(preg_match_all($regex, $message, $regs))
			{
				foreach($regs[0] AS $key => $val)
				{
					$message = str_replace($val, (in_array(strtolower($regs[1]["$key"]), $block_elements) ? "\n" : '') . $regs[2]["$key"], $message);
				}
			}
			$message = str_replace('[*]', ' ', $message);
		}

		return trim($message);
	}

}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 103731 $
|| #######################################################################
\*=========================================================================*/
