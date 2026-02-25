<?php

class vB_Utility_Random
{
	use vB_Utility_Trait_NoSerialize;

	private static $alphanum = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' .
		'abcdefghijklmnopqrstuvwxyz' .
		'0123456789';

	/**
	* Generates a random string of alphanumeric characters
	*
	*	Calls the string function with an alphabet of lower case and upper case
	*	latin characters and numbers
	*
	* @param integer $length
  * @return string -- random string of length $length
	*/
	public function alphanumeric($length)
	{
		return $this->string(self::$alphanum, $length);
	}

	/**
	 *	Generate a randon string from a given alphabet
	 *
	 *	@param string $characters -- the alphabet of characters to use
	 *  @param integer $length
	 *
	 * 	@return string -- random string of length $length
	 */
	public function string($characters, $length)
	{
		if ($length <= 0 OR !is_int($length))
		{
			throw new Exception("Length must be a positive integer.");
		}

		if (!is_string($characters) OR !$characters)
		{
			throw new Exception("Charaacters must be a non empty string.");
		}

		$min = 0;
		$max = strlen($characters) - 1;
		/*
			62 possible characters, 62^$length possible permutations.
			Compared to a substr(sha1(), 0, $length), which would be  (16 possible characters) ^ $lenth permutations,
			this is a larger pool. But in the context of a brute force attack, this isn't that much better.
			Be sure to have ways to limit the rate of attack if the result is used for security purposes.
			Usage for nonces should be fine.
		 */

		$output = '';
		for ($i = 0; $i < $length; $i++)
		{
			$output .= $characters[random_int($min, $max)];
		}
		return $output;
	}

	// #############################################################################
	/**
	* Approximation of old fetch_random_string() function in terms of output set, not distribution.
	*
	* @param	integer	Length of desired hash
	*/
	public function hex($length = 32)
	{
		if ($length <= 0 OR !is_int($length))
		{
			throw new Exception("Length must be a positive integer.");
		}
		/*
			If we just want to use a hash function like sha1 or md5, we can use
			random_bytes({some length}) to generate a seed for the hash.
			Old function returned a substr of a sha1() of a weak seed.
			I do not want to return a substr of a hash function result, and we want
			to use a stronger seed. Since sha1() returns a hex, the output should be
			a $length character hexadecimal number.
			Each byte will give us 2 characters of hex. We still need to substr
			if the desired length is odd.

			BEWARE THAT random_bytes() COULD GIVE YOU UNPRINTABLE CHARACTERS IN WHATEVER
			ENCODING YOU'RE HOPING TO USE. If you need to use the string as more than a hash seed,
			convert it to something safe via bin2hex(), base64encode(), etc.
			For further reading: http://haacked.com/archive/2012/01/30/hazards-of-converting-binary-data-to-a-string.aspx/
		 */
		$bytes = ceil($length / 2);
		$printable_hex = bin2hex(random_bytes($bytes));
		$digits = strlen($printable_hex);
		if ($digits < $length)
		{
			// I don't think this will ever happen unless for some reason bin2hex goes nuts and starts
			// returning single digits instead of 0x0[0-f] for bytes starting with 0b0000
			throw new Exception('Unexpected error: Generated hex was shorter than expected');
		}
		else if ($digits > $length)
		{
			// This happens every time $length is odd.
			$printable_hex = substr($printable_hex, 0, $length);
		}

		return $printable_hex;
	}

	// #############################################################################
	/**
	 * vBulletin's hash fetcher, note this may change from a-f0-9 to a-z0-9 in future.
	 *
	 * Note that the caller should not depend on format of the returned string other
	 * then it should be printable.  If a hex string is specificially needed, call
	 * the hex function.
	 *
	 * @param	integer	Length of desired hash
	 * @return string
	 */
	public function vbhash($length = 32)
	{
		//currently just an alias for hex.  But we want to be able to change that
		return $this->hex($length);
	}

	/**
	 * Generates a random string of alphanumeric characters.  Exactly like alphanumeric but
	 * uses a random number generator that is not cryptographically secure.
	 *
	 * Calls the nonsecureString function with an alphabet of lower case and upper case
	 * latin characters and numbers
	 *
	 * @param integer $length
	 * @return string -- random string of length $length
	 */
	public function nonsecureAlphanumeric($length)
	{
		return $this->nonsecureString(self::$alphanum, $length);
	}

	/**
	 *	This is the same as string, but uses a random generator that is not cryptographically secure
	 *
	 *	This function is faster than string and does not use up "entropy" in the secure random
	 *	number generater.  Therefore it's preferred for uses that don't require cryptographic security
	 *	(for example, unique identifiers that are entirely internal and therefore can't be guessed/spoofed or
	 *	situations where we validate security in other ways -- such as were the id will only be accepted from
	 *	a validated user account where we've already told the user what the id is).
	 *
	 * 	@param string $characters -- the alphabet of characters to use
	 *  @param integer $length
	 *
	 * 	@return string -- random string of length $length
	 */
	public function nonsecureString($characters, $length)
	{
		if ($length <= 0 OR !is_int($length))
		{
			throw new Exception("Length must be a positive integer.");
		}

		if (!is_string($characters) OR !$characters)
		{
			throw new Exception("Charaacters must be a non empty string.");
		}

		$min = 0;
		$max = strlen($characters) - 1;

		$output = '';
		for ($i = 0; $i < $length; $i++)
		{
			//seeding mt_rand is not required.  The old practice of seeding every call was
			//extremely dubious and likely caused more problems than it solved.
			$output .= $characters[mt_rand($min, $max)];
		}
		return $output;
	}
}
?>
