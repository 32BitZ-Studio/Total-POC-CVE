<?PHP
#
# Name:      random_password()
#
# Author:    Chris Hunt, Jeremy Ashcraft
#
# Date:      May 1999, October 2000
#
# Purpose:   Returns a random word for use as a password. Consonants and vowels
#            are alternated to give a (hopefully) pronouncable, and hence
#            memorable, result.
#
# Usage:     $my_new_password  = random_password();
#
# (c)1999 Chris Hunt. Permission is freely granted to include this script in
# your programs. provided this header is left intact.
#
# October 2000 - JA - ported perl code to PHP

function random_password() {

   $maxlen =  6;   # Default to 6

   # Build tables of vowels & consonants. Single vowels are repeated so that
   # resultant words are not dominated by dipthongs

   $vowel = array ("a","e", "i", "o", "u", "y", "ai", "au", "ay", "ea", "ee", "eu", "ia", "ie", "io", "oa", "oi", "oo", "oy");
   $consonant = array ("b", "c", "d", "f", "g", "h", "j", "k", "l", "m", "n", "p", "qu", "r", "s", "t", "v", "w", "x", "z", "th", "st", "sh", "ph", "ng", "nd");
   $password = "";

   srand((double) microtime()*1000000);
   $vowelnext = (int)rand(0,1);  # Initialise to 0 or 1 (ie true or false)

   do {
      if ($vowelnext) {
         $password = $password.$vowel[rand(0,sizeof($vowel))];
      } else {
         $password = $password.$consonant[rand(0,sizeof($consonant))];
      }

      $vowelnext = !$vowelnext;    # Swap letter type for the next one

   } while (strlen($password) <$maxlen);

   return $password;

}

?>
