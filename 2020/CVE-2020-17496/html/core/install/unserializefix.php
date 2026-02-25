<?php

class vB_Install_UnserializeFix
{
	public static function unserialize($string)
	{
		$index = 0;
		$strlen = strlen($string);
		$value = self::getValue($index, $strlen, $string);

		if ($index != $strlen)
		{
			throw new Exception('Finished but not at end of string');
		}

		return $value;
	}

	private static function getValue(&$index, $strlen, $string)
	{
		switch($string[$index])
		{
			case 'a':
				return self::getArray($index, $strlen, $string);
				break;
			case 's':
				$length = (int) self::getPrefix($index, $strlen, $string, ':');
				return self::getString($index, $strlen, $string, $length);
				break;
			case 'i':
				return (int) self::getPrefix($index, $strlen, $string, ';');
				break;
			case 'd':
				$value = self::getPrefix($index, $strlen, $string, ';');
				return (double) $value;
				break;
			case 'b':
				return (boolean) self::getPrefix($index, $strlen, $string, ';');
				break;
			case 'N':
				return self::getNull($index, $strlen, $string);
				break;
			default:
				throw new Exception('Invalid unserialize type: ' . $string[$index] . ' at position ' . $index);
				break;
		}
	}

	private static function getArray(&$index, $strlen, $string)
	{
		$length = (int) self::getPrefix($index, $strlen, $string, ':');
		if ($index+1 >= $strlen)
		{
			throw new Exception('Unexpected end of string');
		}

		if ($string[$index] != '{')
		{
			throw new Exception('Expected { at position ' .  $index);
		}
		$index++;

		$array = array();

		for($i = 0; $i < $length; $i++)
		{
			$keystart = $index;
			$key = self::getValue($index, $strlen, $string);
			if(!(is_int($key) OR is_string($key)))
			{
				throw new Exception('Invalid key type ' . gettype($key) . ' at index ' . $keystart);
			}

			$value = self::getValue($index, $strlen, $string);
			$array[$key] = $value;
		}

		if ($string[$index] != '}')
		{
			throw new Exception('Expected } at position ' .  $index);
		}
		$index++;

		return $array;
	}

	private static function getNull(&$index, $strlen, $string)
	{
		if ($index+1 >= $strlen)
		{
			throw new Exception('Unexpected end of string');
		}

		$index++;

		if ($string[$index] != ';')
		{
			throw new Exception('Expected ; at position ' .  $index);
		}

		$index++;
		return null;
	}

	private static function getPrefix(&$index, $strlen, $string, $lastchar)
	{
		$start = $index+2;
		if ($start >= $strlen)
		{
			throw new Exception('Unexpected end of string');
		}

		if ($string[$index+1] != ':')
		{
			throw new Exception('Expected : at position ' .  $index + 1);
		}

		$end = strpos($string, $lastchar, $start);

		if($end === false)
		{
			throw new Exception('Expected ' . $lastchar . ', reached end of string');
		}

		$value = substr($string, $start, $end - ($start));

		$index += (2+strlen($value));
		if ($string[$index] != $lastchar)
		{
			throw new Exception('Expected ' . $lastchar . ' at position ' .  $index);
		}
		$index++;

		return $value;
	}

	private static function getString(&$index, $strlen, $string, $length)
	{
		//start + value length + 2 quote chars
		if ($index + 2 + $length >= $strlen)
		{
			throw new Exception('Unexpected end of string');
		}

		if ($string[$index] != '"')
		{
			throw new Exception('Expected " at position ' .  $index);
		}

		//this string is broken, let's try to guess it
		if ($string[$index + $length + 1] != '"')
		{
			return self::guessString($index, $strlen, $string, $length);
		}

		$value = substr($string, $index+1, $length);

		$index += $length + 1;

		//reduntant with the check above, but let's leave it in to
		//catch weird bugs.
		if ($string[$index] != '"')
		{
			throw new Exception('Expected " at position ' .  $index);
		}

		$index++;

		if ($string[$index] != ';')
		{
			throw new Exception('Expected " at position ' .  $index);
		}

		$index++;
		return $value;
	}

	private static function guessString(&$index, $strlen, $string, $length)
	{
		//this isn't guarenteed to be correct since "; could appear as data
		//in the string.  But it's not that likely and we have to try something
		$pos = strpos($string, '";', $index+1);
		if($pos === false)
		{
			throw new Exception('Could not find end of broken string starting at position ' .  $index);
		}

		$start = $index + 1;
		$value = substr($string, $start, $pos - $start);

		$index = $pos+2;
		return $value;
	}
}

?>
