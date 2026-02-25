<?php

class vB_Utility_Unserialize
{
	use vB_Utility_Trait_NoSerialize;

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
			if (!(is_int($key) OR is_string($key)))
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
			throw new Exception('Expected : at position ' .  ($index + 1));
		}

		$end = strpos($string, $lastchar, $start);

		if ($end === false)
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
		if ($index+2+$length >= $strlen)
		{
			throw new Exception('Unexpected end of string');
		}

		if ($string[$index] != '"')
		{
			throw new Exception('Expected " at position ' .  $index);
		}

		$value = substr($string, $index+1, $length);

		$index += $length+1;

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
}

?>
