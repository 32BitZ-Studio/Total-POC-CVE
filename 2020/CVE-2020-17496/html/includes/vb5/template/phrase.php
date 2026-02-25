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

class vB5_Template_Phrase
{
	const PLACEHOLDER_PREFIX = '<!-- ##phrase_';
	const PLACEHOLDER_SUFIX = '## -->';

	private static $instance;
	private $cache = array();
	private $pending = array();
	private $stack = array();
	private $options = array();

	public static function instance()
	{
		if (!isset(self::$instance))
		{
			$c = __CLASS__;
			self::$instance = new $c;
		}

		return self::$instance;
	}

	public function register($args, $options = null)
	{
		$phraseName = $args[0];
		$pos = isset($this->pending[$phraseName]) ? count($this->pending[$phraseName]) : 0;

		if (count($args) < 2)
		{
			// If it doesn't have other arguments, assume that this is a phrase with no variables.
			// There's no reason to re-construct this phrase, so let's not bother adding it to the stack.
			// TODO: Maybe we should deep-cache argument-less phrases for each language so we don't try
			// to construct it/call sprintf on it every time? We'll need to check how much more performant
			// it'd be, and how many unique phrase:arguments pairs there are in a typical page load.
			$pos = 0;
		}

		$placeHolder = $this->getPlaceholder($phraseName, $pos);

		$this->pending[$phraseName][$placeHolder] = $args;
		$this->stack[$placeHolder] = $phraseName;

		if(is_array($options))
		{
			$this->options[$placeHolder] = $options;
		}

		return $placeHolder;
	}

	/**
	 * The use of this function should be avoided when possible because it forces the controller to fetch all missing phrases immediately.
	 *
	 * @var string phraseName
	 * @var mixed parameter1
	 * @var mixed parameter2
	 * @return type
	 */
	public function getPhrase()
	{
		$args = func_get_args();
		$phraseName = $args[0];

		// first check if we already have the phrase, if not force fetching
		if (!isset($this->cache[$phraseName]))
		{
			// note: the placeholder won't be used in this case
			$this->pending[$phraseName][] = $args;
			$this->fetchPhrases();
		}

		$args[0] = isset($this->cache[$phraseName]) ? $this->cache[$phraseName] : $args[0];
		return $this->constructPhraseFromArray($args);
	}

	public function resetPending()
	{
		$this->pending = array();
		$this->stack = array();
	}

	public function replacePlaceholders(&$content)
	{
		$this->fetchPhrases();
		$placeholders = array();
		end($this->stack);

		// Phrase {shortcode} replacements
		// This replacement happens in several places. Please keep them synchronized.
		// You can search for {shortcode} in php and js files.
		$shortcode_replace_map = array (
			'{sitename}'        => vB5_Template_Options::instance()->get('options.bbtitle'),
			'{musername}'       => vB5_User::get('musername'),
			'{username}'        => vB5_User::get('username'),
			'{userid}'          => vB5_User::get('userid'),
			'{registerurl}'     => vB5_Route::buildUrl('register|fullurl'),
			'{activationurl}'   => vB5_Route::buildUrl('activateuser|fullurl'),
			'{helpurl}'         => vB5_Route::buildUrl('help|fullurl'),
			'{contacturl}'      => vB5_Route::buildUrl('contact-us|fullurl'),
			'{homeurl}'         => vB5_Template_Options::instance()->get('options.frontendurl'),
			'{date}'            => vB5_Template_Runtime::date('timenow', '', false),
			// ** leave deprecated codes in to avoid breaking existing data **
			// deprecated - the previous *_page codes have been replaced with the *url codes
			'{register_page}'   => vB5_Route::buildUrl('register|fullurl'),
			'{activation_page}' => vB5_Route::buildUrl('activateuser|fullurl'),
			'{help_page}'       => vB5_Route::buildUrl('help|fullurl'),
			// deprecated - session url codes are no longer needed
			'{sessionurl}'      => '',
			'{sessionurl_q}'    => '',
		);
		$shortcode_find = array_keys($shortcode_replace_map);
		while (!is_null($placeholder_id = key($this->stack)))
		{
			$phraseName = current($this->stack);
			$phraseInfo = $this->pending[$phraseName][$placeholder_id];
			$phraseInfo[0] = isset($this->cache[$phraseName]) ? $this->cache[$phraseName] : $phraseInfo[0];

			// phrase shortcode replacements
			// do parameter replacements in phrases, since we don't want
			// the extra overhead of pulling these phrases in the api method
			$phraseInfo[0] = str_replace($shortcode_find, $shortcode_replace_map, $phraseInfo[0]);

			$replace = $this->constructPhraseFromArray($phraseInfo);

			$options = $this->options[$placeholder_id] ?? null;

			//we don't want special parsing unless we specifically request it.
			//1) It will be a performance drag
			//2) There is too much regression risk if we send all of the phrases through this processing
			if($options AND (empty($options['allowhtml']) OR !empty($options['allowbbcode']) OR !empty($options['allowsmilies'])))
			{
				$replace = $this->parseSpecialPhrase($replace, $options);
			}

			$placeholders[$placeholder_id] = $replace;
			prev($this->stack);
		}

		// If we passed any phrases as parameters to other phrases, we will
		// still have those placeholders in the "replace" content, for example:
		//   {vb:phrase have_x_posts_in_topic_last_y, {vb:var topic.dot_postcount}, {vb:date {vb:var topic.dot_lastpostdate}}}
		// since the date call can return phrases (today, yesterday, etc.).
		// This only goes one level deep (e.g., it's not recursive), since that's
		// all we need at this time.
		// This searches the replace text to see if there are any placeholders
		// left in them, and if so, replaces those placeholders with the phrase text.
		foreach ($placeholders AS $k => $replace)
		{
			if (strpos($replace, '<!-- ##phrase_') !== false OR strpos($replace, '&lt;!-- ##phrase_') !== false)
			{
				if (preg_match_all('/(?:<|&lt;)!-- ##phrase_([a-z0-9_]+)_[0-9]+## --(?:>|&gt;)/siU', $replace, $matches, PREG_SET_ORDER))
				{
					foreach ($matches AS $match)
					{
						$placeholder_id = $match[0];
						$phrase_varname = $match[1];

						$placeholder_id_lookup = str_replace(array('&lt;', '&gt;'), array('<', '>'), $placeholder_id);

						$phraseInfo = $this->pending[$phrase_varname][$placeholder_id_lookup];
						$phraseInfo[0] = isset($this->cache[$phrase_varname]) ? $this->cache[$phrase_varname] : $phraseInfo[0];

						$phraseText = $this->constructPhraseFromArray($phraseInfo);

						$placeholders[$k] = str_replace($placeholder_id, $phraseText, $placeholders[$k]);
					}
				}
			}
		}

		if (!empty($placeholders))
		{
			$content = str_replace(array_keys($placeholders), $placeholders, $content);
		}
	}

	/**
	 */
	private function parseSpecialPhrase($text, $bbcodeOptions)
	{
		$api = Api_InterfaceAbstract::instance();

		$allowBbcode = $bbcodeOptions['allowbbcode'] ?? false;
		$parseUrl = $bbcodeOptions['parseurl'] ?? false;

		//parse url isn't going to do any good if we don't also change
		//the added bbcode to actual links
		if($allowBbcode AND $parseUrl)
		{
			//not sure how to handle and error response (which isn't likely) so let's just
			//skip the link processing in that instance.
			$response = $api->callApi('bbcode', 'convertUrlToBbcode', array('messagetext' => $text));
			if(!isset($response['error']))
			{
				$text = $response;
			}
		}

		$parser = new vB5_Template_BbCode();
		$parser->setRenderImmediate(true);

		// Get full text
		// This assumes on_nl2br is always true and that we don't have a specific html state
		// (htmlstate will overwrite the allowhtml/on_nl2br options (we should clean that up)
		$parsed = $parser->doParse(
			$text,
			$bbcodeOptions['allowhtml'] ?? false,
			$bbcodeOptions['allowsmilies'] ?? false,
			$allowBbcode,
			$allowBbcode,
			true, // do_nl2br
			false
		);

		return $parsed;
	}

	private function getPlaceholder($phraseName, $pos)
	{
		return self::PLACEHOLDER_PREFIX . $phraseName . '_' . $pos . self::PLACEHOLDER_SUFIX;
	}

	private function fetchPhrases()
	{
		$missing = array_diff(array_keys($this->pending), array_keys($this->cache));

		if (!empty($missing))
		{
			$response = Api_InterfaceAbstract::instance()->callApi('phrase', 'fetch', array('phrases' => $missing));
			foreach ($response as $key => $value)
			{
				$this->cache[$key] = $value;
			}
		}
	}

	/**
	 * Construct Phrase from Array
	 *
	 * this function is actually just a wrapper for sprintf but makes identification of phrase code easier
	 * and will not error if there are no additional arguments. The first element of the array is the phrase text, and
	 * the (unlimited number of) following elements are the variables to be parsed into that phrase.
	 *
	 * @param	array	array containing phrase and arguments
	 *
	 * @return	string	The parsed phrase
	 */
	private function constructPhraseFromArray($phrase_array)
	{
		$numargs = sizeof($phrase_array);

		// if we have only one argument then its a phrase
		// with no variables, so just return it
		if ($numargs < 2)
		{
			return $phrase_array[0];
		}

		// if the second argument is an array, use their values as variables
		if (is_array($phrase_array[1]))
		{
			array_unshift($phrase_array[1], $phrase_array[0]);
			$phrase_array = $phrase_array[1];
		}

		// call sprintf() on the first argument of this function
		$phrase = @call_user_func_array('sprintf', $phrase_array);
		if ($phrase !== false)
		{
			return $phrase;
		}
		else
		{
			// if that failed, add some extra arguments for debugging
			for ($i = $numargs; $i < 10; $i++)
			{
				$phrase_array["$i"] = "[ARG:$i UNDEFINED]";
			}

			if ($phrase = @call_user_func_array('sprintf', $phrase_array))
			{
				return $phrase;
			}

			// if it still doesn't work, just return the un-parsed text
			else
			{
				return $phrase_array[0];
			}
		}
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 103383 $
|| #######################################################################
\*=========================================================================*/
