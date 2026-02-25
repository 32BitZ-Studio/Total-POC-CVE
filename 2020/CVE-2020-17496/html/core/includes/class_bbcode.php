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
* BB code parser's start state. Looking for the next tag to start.
*/
define('BB_PARSER_START', 1);

/**
* BB code parser's "this range is just text" state.
* Requires $internal_data to be set appropriately.
*/
define('BB_PARSER_TEXT', 2);

/**
* Tag has been opened. Now parsing for option and closing ].
*/
define('BB_PARSER_TAG_OPENED', 3);

/**
* Stack based BB code parser.
*
* @package 		vBulletin
* @version		$Revision: 102574 $
* @date 		$Date: 2019-08-16 14:48:22 -0700 (Fri, 16 Aug 2019) $
*
*/
class vB_BbCodeParser
{
	/**
	* A list of tags to be parsed.
	* Takes a specific format. See function that defines the array passed into the c'tor.
	*
	* @var	array
	*/
	var $tag_list = array();

	/**
	* The stack that will be populated during final parsing. Used to check context.
	*
	* @var	array
	*/
	var $stack = array();

	/**
	* Holder for the output of the BB code parser while it is being built.
	*
	* @var	string
	*/
	var $parse_output = '';

	/**
	* Used alongside the stack. Holds a reference to the node on the stack that is
	* currently being processed. Only applicable in callback functions.
	*/
	var $current_tag = null;

	/**
	* Whether this parser is parsing for printable output
	*
	* @var	bool
	*/
	var $printable = false;

	/**
	* Reference to the main registry object
	*
	* @var	vB_Registry
	*/
	var $registry = null;

	/**
	* Holds various options such what type of things to parse and cachability.
	*
	* @var	array
	*/
	var $options = array();

	/**
	* Holds the cached post if caching was enabled
	*
	* @var	array	keys: text (string), has_images (int)
	*/
	var $cached = array();

	/**
	* Reference to attachment information pertaining to this post
	*
	* @var	array
	*/
	var $attachments = null;

	/**
	* Whether this parser unsets attachment info in $this->attachments when an inline attachment is found
	*
	* @var	bool
	*/
	var $unsetattach = false;

	/**
	 * Id of the forum the source string is in for permissions
	 *
	 * @var integer
	 */
	var $forumid = 0;

	/**
	 * Id of the outer container, if applicable
	 *
	 * @var mixed
	 */
	var $containerid = 0;

	/**
	* True if custom tags have been fetched
	*
	* @var	bool
	*/
	var $custom_fetched = false;

	/**
	* Local cache of smilies for this parser. This is per object to allow WYSIWYG and
	* non-WYSIWYG versions on the same page.
	*
	* @var array
	*/
	var $smilie_cache = array();

	/**
	* If we need to parse using specific user information (such as in a sig),
	* set that info in this member. This should include userid, custom image revision info,
	* and the user's permissions, at the least.
	*
	* @var	array
	*/
	var $parse_userinfo = array();

	/**
	* The number that is the maximum node when parsing for tags. count(nodes)
	*
	* @var	int
	*/
	var $node_max = 0;

	/**
	* When parsing, the number of the current node. Starts at 1. Note that this is not
	* necessary the key of the node in the array, but reflects the number of nodes handled.
	*
	* @var	int
	*/
	var $node_num = 0;

	/** Template for generating quote links. We need to override for cms comments" **/
	protected $quote_printable_template = 'bbcode_quote_printable';

	/** Template for generating quote links. We need to override for cms comments" **/
	protected $quote_template =  'bbcode_quote';

	/**Additional parameter(s) for the quote template. We need for cms comments **/
	protected $quote_vars = false;

	/**
	*	Display full size image attachment if an image is [attach] using without =config, otherwise display a thumbnail
	*
	*/
	protected $displayimage = false;

	protected $userImagePermissions = array();


	/**
	* Constructor. Sets up the tag list.
	*
	* @param	vB_Registry	Reference to registry object
	* @param	array		List of tags to parse
	* @param	bool		Whether to append customer user tags to the tag list
	*/
	function __construct(&$registry, $tag_list = array(), $append_custom_tags = true)
	{
		$this->registry =& $registry;
		$this->tag_list = $tag_list;

		if ($append_custom_tags)
		{
			$this->append_custom_tags();
		}

		// Legacy Hook 'bbcode_create' Removed //
	}

	/**
	* Loads any user specified custom BB code tags into the $tag_list
	*/
	function append_custom_tags()
	{
		if ($this->custom_fetched == true)
		{
			return;
		}

		$this->custom_fetched = true;
		$loaded = false;
		// this code would make nice use of an interator
		if ($this->registry->bbcodecache !== null) // get bbcodes from the datastore
		{
			$has_errors = false;
			foreach($this->registry->bbcodecache AS $customtag)
			{
				// the datastore record is not valid, we have to load the values
				if (
					!is_array($customtag)
					OR !array_key_exists('twoparams', $customtag)
					OR !array_key_exists('bbcodereplacement', $customtag)
					OR !array_key_exists('strip_empty', $customtag)
					OR !array_key_exists('stop_parse', $customtag)
					OR !array_key_exists('disable_smilies', $customtag)
					OR !array_key_exists('disable_wordwrap', $customtag)
				)
				{
					$has_errors = true;
					break;
				}
				$has_option = $customtag['twoparams'] ? 'option' : 'no_option';
				$customtag['bbcodetag'] = strtolower($customtag['bbcodetag']);

				$this->tag_list["$has_option"]["$customtag[bbcodetag]"] = array(
					'html'             => $customtag['bbcodereplacement'],
					'strip_empty'      => $customtag['strip_empty'],
					'stop_parse'       => $customtag['stop_parse'],
					'disable_smilies'  => $customtag['disable_smilies'],
					'disable_wordwrap' => $customtag['disable_wordwrap'],
				);
			}
			$loaded = !$has_errors;
		}

		//it's not available in the datastore or it has failed
		if (!$loaded) // query bbcodes out of the database
		{
			$this->registry->bbcodecache = array();

			$bbcodes = vB_Library::instance('bbcode')->fetchBBCodes();
			foreach($bbcodes as $customtag)
			{
				$has_option = $customtag['twoparams'] ? 'option' : 'no_option';
				$customtag['bbcodetag'] = strtolower($customtag['bbcodetag']);
				$this->tag_list["$has_option"]["$customtag[bbcodetag]"] = array(
					'html'             => $customtag['bbcodereplacement'],
					'strip_empty'      => (intval($customtag['options']) & $this->registry->bf_misc['bbcodeoptions']['strip_empty']) ? 1 : 0 ,
					'stop_parse'       => (intval($customtag['options']) & $this->registry->bf_misc['bbcodeoptions']['stop_parse']) ? 1 : 0 ,
					'disable_smilies'  => (intval($customtag['options']) & $this->registry->bf_misc['bbcodeoptions']['disable_smilies']) ? 1 : 0 ,
					'disable_wordwrap' => (intval($customtag['options']) & $this->registry->bf_misc['bbcodeoptions']['disable_wordwrap']) ? 1 : 0
				);

				$this->registry->bbcodecache["$customtag[bbcodeid]"] = $customtag;
			}
		}
	}

	/**
	* Sets the user the BB code as parsed as. As of 3.7, this function should
	* only be called for parsing signatures (for sigpics and permissions).
	*
	* @param	array	Array of user info to parse as
	* @param	array	Array of user's permissions (may come through $userinfo already)
	*/
	function set_parse_userinfo($userinfo, $permissions = null)
	{
		$this->parse_userinfo = $userinfo;
		if ($permissions)
		{
			$this->parse_userinfo['permissions'] = $permissions;
		}
	}

	/**
	* Collect parser options and misc data and fully parse the string into an HTML version
	*
	* @param	string	Unparsed text
	* @param	int|str	ID number of the forum whose parsing options should be used or a "special" string
	* @param	bool	Whether to allow smilies in this post (if the option is allowed)
	* @param	bool	Whether to parse the text as an image count check
	* @param	string	Preparsed text ([img] tags should not be parsed)
	* @param	int		Whether the preparsed text has images
	* @param	bool	Whether the parsed post is cachable
	* @param	string	Switch for dealing with nl2br
	*
	* @return	string	Parsed text
	*/
	function parse($text, $forumid = 0, $allowsmilie = true, $isimgcheck = false, $parsedtext = '', $parsedhasimages = 3, $cachable = false, $htmlstate = null)
	{
		global $calendarinfo;

		$this->forumid = $forumid;

		$donl2br = true;

		if (empty($forumid))
		{
			$forumid = 'nonforum';
		}

		switch($forumid)
		{
			// Parse Calendar
			case 'calendar':
				$dohtml = $calendarinfo['allowhtml'];
				$dobbcode = $calendarinfo['allowbbcode'];
				$dobbimagecode = $calendarinfo['allowimgcode'];
				$dosmilies = $calendarinfo['allowsmilies'];
				break;

			// parse private message
			case 'privatemessage':
				$dohtml = false;
				$dobbcode = $this->registry->options['privallowbbcode'];
				$dobbimagecode = true;
				$dosmilies = $this->registry->options['privallowsmilies'];
				break;

			// parse signature
			case 'signature':
				if (!empty($this->parse_userinfo['permissions']))
				{
					$dohtml = ($this->parse_userinfo['permissions']['signaturepermissions'] & $this->registry->bf_ugp_signaturepermissions['allowhtml']);
					$dobbcode = ($this->parse_userinfo['permissions']['signaturepermissions'] & $this->registry->bf_ugp_signaturepermissions['canbbcode']);
					$dobbimagecode = ($this->parse_userinfo['permissions']['signaturepermissions'] & $this->registry->bf_ugp_signaturepermissions['allowimg']);
					$dosmilies = ($this->parse_userinfo['permissions']['signaturepermissions'] & $this->registry->bf_ugp_signaturepermissions['allowsmilies']);
					break;
				}
				// else fall through to nonforum

			// parse non-forum item
			case 'nonforum':
				$dohtml = $this->registry->options['allowhtml'];
				$dobbcode = $this->registry->options['allowbbcode'];
				$dobbimagecode = $this->registry->options['allowbbimagecode'];
				$dosmilies = $this->registry->options['allowsmilies'];
				break;

			// parse announcement
			case 'announcement':
				global $post;
				$dohtml = ($post['announcementoptions'] & $this->registry->bf_misc_announcementoptions['allowhtml']);
				if ($dohtml)
				{
					$donl2br = false;
				}
				$dobbcode = ($post['announcementoptions'] & $this->registry->bf_misc_announcementoptions['allowbbcode']);
				$dobbimagecode = ($post['announcementoptions'] & $this->registry->bf_misc_announcementoptions['allowbbcode']);
				$dosmilies = $allowsmilie;
				break;

			// parse visitor/group/picture message
			case 'visitormessage':
			case 'groupmessage':
			case 'socialmessage':
				$dohtml = $this->registry->options['allowhtml'];
				$dobbcode = $this->registry->options['allowbbcode'];
				$dobbimagecode = true; // this tag can be disabled manually; leaving as true means old usages remain (as documented)
				$dosmilies = $this->registry->options['allowsmilies'];
				break;

			// parse forum item
			default:
				if (intval($forumid))
				{
//					$forum = fetch_foruminfo($forumid);
//					$dohtml = $forum['allowhtml'];
//					$dobbimagecode = $forum['allowimages'];
//					$dosmilies = $forum['allowsmilies'];
//					$dobbcode = $forum['allowbbcode'];
				}
				// else they'll basically just default to false -- saves a query in certain circumstances
				break;
		}

		if (!$allowsmilie)
		{
			$dosmilies = false;
		}

		// Legacy Hook 'bbcode_parse_start' Removed //

		if (!empty($parsedtext) AND !VB_API)
		{
			if ($parsedhasimages)
			{
				return $this->handle_bbcode_img($parsedtext, $dobbimagecode, $parsedhasimages);
			}
			else
			{
				return $parsedtext;
			}
		}
		else
		{
			return $this->do_parse($text, $dohtml, $dosmilies, $dobbcode, $dobbimagecode, $donl2br, $cachable, $htmlstate);
		}
	}

	/**
	* Parse the string with the selected options
	*
	* @param	string	Unparsed text
	* @param	bool	Whether to allow HTML (true) or not (false)
	* @param	bool	Whether to parse smilies or not
	* @param	bool	Whether to parse BB code
	* @param	bool	Whether to parse the [img] BB code (independent of $do_bbcode)
	* @param	bool	Whether to automatically replace new lines with HTML line breaks
	* @param	bool	Whether the post text is cachable
	* @param	string	Switch for dealing with nl2br
	*	@param	boolean	do minimal required actions to parse bbcode
	*
	* @return	string	Parsed text
	*/
	function do_parse($text, $do_html = false, $do_smilies = true, $do_bbcode = true, $do_imgcode = true, $do_nl2br = true, $cachable = false, $htmlstate = null, $minimal = false)
	{
		global $html_allowed;
		if ($htmlstate)
		{
			switch ($htmlstate)
			{
				case 'on':
					$do_nl2br = false;
					break;
				case 'off':
					$do_html = false;
					break;
				case 'on_nl2br':
					$do_nl2br = true;
					break;
			}
		}

		$this->options = array(
			'do_html'    => $do_html,
			'do_smilies' => $do_smilies,
			'do_bbcode'  => $do_bbcode,
			'do_imgcode' => $do_imgcode,
			'do_nl2br'   => $do_nl2br,
			'cachable'   => $cachable
		);
		$this->cached = array('text' => '', 'has_images' => 0);

		$fulltext = $text;

		// ********************* REMOVE HTML CODES ***************************
		if (!$do_html)
		{
			$text = vB_String::htmlSpecialCharsUni($text);
		}
		$html_allowed = $do_html;

		if (!$minimal)
		{
			$text = $this->parse_whitespace_newlines($text, $do_nl2br);
		}
		// ********************* PARSE BBCODE TAGS ***************************
		if ($do_bbcode)
		{
			$text = $this->parse_bbcode($text, $do_smilies, $do_imgcode, $do_html);
		}
		else if ($do_smilies)
		{
			$text = $this->parse_smilies($text, $do_html);
		}

		$has_img_tag = 0;
		if (!$minimal)
		{
			// parse out nasty active scripting codes
			static $global_find = array('/(javascript):/si', '/(about):/si', '/(vbscript):/si', '/&(?![a-z0-9#]+;)/si');
			static $global_replace = array('\\1<b></b>:', '\\1<b></b>:', '\\1<b></b>:', '&amp;');
			$text = preg_replace($global_find, $global_replace, $text);

			// run the censor
			$text = fetch_censored_text($text);
			$has_img_tag = ($do_bbcode ? max(array($this->contains_bbcode_img_tags($fulltext), $this->contains_bbcode_img_tags($text))) : 0);
		}

		// Legacy Hook 'bbcode_parse_complete_precache' Removed //

		// save the cached post
		if ($this->options['cachable'])
		{
			$this->cached['text'] = $text;
			$this->cached['has_images'] = $has_img_tag;
		}
		// do [img] tags if the item contains images
		if(($do_bbcode OR $do_imgcode) AND $has_img_tag)
		{
			$text = $this->handle_bbcode_img($text, $do_imgcode, $has_img_tag, $fulltext);
		}

		// Legacy Hook 'bbcode_parse_complete' Removed //

		return $text;
	}

	/**
	 * This is copied from the blog bbcode parser. We either have a specific
	 * amount of text, or [PRBREAK][/PRBREAK].
	 *
	 * @param	array	Fixed tokens
	 * @param	integer	Length of the text before parsing (optional)
	 *
	 * @return	array	Tokens, chopped to the right length.
	 */
	public function get_preview($pagetext, $initial_length = 0, $do_html = false, $do_nl2br = true, $htmlstate = null)
	{
		if ($htmlstate)
		{
			switch ($htmlstate)
	{
				case 'on':
					$do_nl2br = false;
					break;
				case 'off':
					$do_html = false;
					break;
				case 'on_nl2br':
					$do_nl2br = true;
					break;
			}
		}

		$this->options = array(
			'do_html'    => $do_html,
			'do_smilies' => false,
			'do_bbcode'  => true,
			'do_imgcode' => false,
			'do_nl2br'   => $do_nl2br,
			'cachable'   => true
		);

		global $html_allowed;
		$html_allowed = $do_html;

		if (!$do_html)
		{
			$pagetext = htmlspecialchars_uni($pagetext);
		}
		$pagetext = $this->parse_whitespace_newlines(trim(strip_quotes($pagetext)), $do_nl2br);
		$tokens = $this->fix_tags($this->build_parse_array($pagetext));

		$counter = 0;
		$stack = array();
		$new = array();
		$over_threshold = false;

		if (strpos($pagetext, '[PRBREAK][/PRBREAK]'))
		{
			$this->snippet_length = strlen($pagetext);
		}
		else if (intval($initial_length))
		{
			$this->snippet_length = $initial_length;

		}
		else
		{
			$this->snippet_length = $this->default_previewlen;
		}

		$noparse = false;

		//strip these tags from the preview including anything they might contain
		//we keep track of each seperately, but that might be overkill (we shouldn't
		//see a case where they are nested).
		$strip_tags = array_fill_keys(array('video', 'page', 'attach', 'img2'), 0);

		foreach ($tokens AS $tokenid => $token)
		{
			if (($token['name'] == 'noparse') AND $do_html)
			{
				//can't parse this. We don't know what's inside.
				$new[] = $token;
				$noparse = ! $noparse;
			}

			//if this is a tag we are skipping, flip the "in" state based on if this is an open or close tag
			else if (!empty($token['name']) AND isset($strip_tags[$token['name']]))
			{
				$strip_tags[$token['name']] = !$token['closing'];
				continue;
			}

			//if any of our skip flags are set, skip this tag
			else if(array_sum($strip_tags) > 0)
			{
				continue;
			}

			// only count the length of text entries
			else if ($token['type'] == 'text')
			{

				if (!$noparse)
				{
					//If this has [ATTACH] or [IMG] or VIDEO then we nuke it.
					$pagetext =preg_replace('#\[ATTACH.*?\[/ATTACH\]#si', '', $token['data']);
					$pagetext = preg_replace('#\[IMG.*?\[/IMG\]#si', '', $pagetext);
					$pagetext = preg_replace('#\[video.*?\[/video\]#si', '', $pagetext);
					if ($pagetext == '')
			{
						continue;
					}
					$token['data'] = $pagetext;
				}
				$length = vbstrlen($token['data']);

				// uninterruptable means that we will always show until this tag is closed
				$uninterruptable = (isset($stack[0]) AND isset($this->uninterruptable["$stack[0]"]));

				if ((($counter + $length) < $this->snippet_length )OR $uninterruptable OR $noparse)
				{
					// this entry doesn't push us over the threshold
					$new[] = $token;
					$counter += $length;
				}
				else
				{
					// a text entry that pushes us over the threshold
					$over_threshold = true;
					$last_char_pos = $this->snippet_length - $counter - 1; // this is the threshold char; -1 means look for a space at it
					if ($last_char_pos < 0)
					{
						$last_char_pos = 0;
					}

					if (preg_match('#\s#s', $token['data'], $match, PREG_OFFSET_CAPTURE, $last_char_pos))
					{
						$token['data'] = substr($token['data'], 0, $match[0][1]); // chop to offset of whitespace
						if (substr($token['data'], -3) == '<br')
						{
							// we cut off a <br /> code, so just take this out
							$token['data'] = substr($token['data'], 0, -3);
						}

						$new[] = $token;
					}
					else
					{
						$new[] = $token;
					}

					break;
				}
			}
			else
			{
				// not a text entry
				if ($token['type'] == 'tag')
				{
					//If we have a prbreak we are done.
					if (($token['name'] == 'prbreak') AND isset($tokens[intval($tokenid) + 1])
						AND ($tokens[intval($tokenid) + 1]['name'] == 'prbreak')
						AND ($tokens[intval($tokenid) + 1]['closing']))
					{
						$over_threshold == true;
						break;
					}
					// build a stack of open tags
					if ($token['closing'] == true)
					{
						// by now, we know the stack is sane, so just remove the first entry
						array_shift($stack);
					}
					else
					{
						array_unshift($stack, $token['name']);
					}
				}

				$new[] = $token;
			}
		}
		// since we may have cut the text, close any tags that we left open
		foreach ($stack AS $tag_name)
		{
			$new[] = array('type' => 'tag', 'name' => $tag_name, 'closing' => true);
		}

		$this->createdsnippet = (sizeof($new) != sizeof($tokens) OR $over_threshold); // we did something, so we made a snippet

		$result = $this->parse_array($new, true, true, $do_html);
		return $result;
	}

	/**
	* Word wraps the text if enabled.
	*
	* @param	string	Text to wrap
	*
	* @return	string	Wrapped text
	*/
	function do_word_wrap($text)
	{
		if ($this->registry->options['wordwrap'] != 0)
		{
			$text = fetch_word_wrapped_string($text, false, '  ');
		}
		return $text;
	}

	/**
	* Parses smilie codes into their appropriate HTML image versions
	*
	* @param	string	Text with smilie codes
	* @param	bool	Whether HTML is allowed
	*
	* @return	string	Text with HTML images in place of smilies
	*/
	function parse_smilies($text, $do_html = false)
	{
		static $regex_cache;
		$org_text = $text;
		$this->local_smilies =& $this->cache_smilies($do_html);

		$cache_key = ($do_html ? 'html' : 'nohtml');

		if (!isset($regex_cache["$cache_key"]))
		{
			$regex_cache["$cache_key"] = array();
			$quoted = array();

			foreach ($this->local_smilies AS $find => $replace)
			{
				$quoted[] = preg_quote($find, '/');
				if (sizeof($quoted) > 500)
				{
					$regex_cache["$cache_key"][] = '/(?<!&amp|&quot|&lt|&gt|&copy|&#[0-9]{1}|&#[0-9]{2}|&#[0-9]{3}|&#[0-9]{4}|&#[0-9]{5})(' . implode('|', $quoted) . ')/s';
					$quoted = array();
				}
			}

			if (sizeof($quoted) > 0)
			{
				$regex_cache["$cache_key"][] = '/(?<!&amp|&quot|&lt|&gt|&copy|&#[0-9]{1}|&#[0-9]{2}|&#[0-9]{3}|&#[0-9]{4}|&#[0-9]{5})(' . implode('|', $quoted) . ')/s';
			}
		}
		$replaced_nr = 0;
		foreach ($regex_cache["$cache_key"] AS $regex)
		{
			$text = preg_replace_callback($regex, array(&$this, 'replace_smilies'), $text, -1, $replaced_nr);
			if (isset($this->imgcount) AND $replaced_nr > 0)
			{
				$this->imgcount += $replaced_nr;
			}
		}
		if (!empty($this->imgcount))
		{
			$allowedImgs = vB::getUserContext($this->userid)->getLimit('sigmaximages');
			if (($allowedImgs > 0) AND ($allowedImgs < $this->imgcount))
			{
				$this->errors['img'] = array('toomanyimages' => array($this->imgcount, $allowedImgs));
				return $org_text;
			}
		}
		return $text;
	}

	/**
	* Callback function for replacing smilies.
	*
	* @ignore
	*/
	function replace_smilies($matches)
	{
		return $this->local_smilies["$matches[0]"];
	}

	/**
	* Caches the smilies in a form ready to be executed.
	*
	* @param	bool	Whether HTML parsing is enabled
	*
	* @return	array	Reference to smilie cache (key: find text; value: replace text)
	*/
	function &cache_smilies($do_html)
	{
		$key = $do_html ? 'html' : 'no_html';
		if (isset($this->smilie_cache["$key"]))
		{
			return $this->smilie_cache["$key"];
		}

		$sc =& $this->smilie_cache["$key"];
		$sc = array();
		if ($this->registry->smiliecache !== null)
		{
			// we can get the smilies from the smiliecache datastore
			DEVDEBUG('returning smilies from the datastore');

			foreach ($this->registry->smiliecache AS $smilie)
			{
				if (!$do_html)
				{
					$find = htmlspecialchars_uni(trim($smilie['smilietext']));
				}
				else
				{
					$find = trim($smilie['smilietext']);
				}

				$smiliepath = $smilie['smiliepath'];

				// if you change this HTML tag, make sure you change the smilie remover in code/php/html tag handlers!
				if ($this->is_wysiwyg())
				{
					$replace = "<img src=\"$smiliepath\" border=\"0\" alt=\"\" title=\"" . htmlspecialchars_uni($smilie['title']) . "\" smilieid=\"$smilie[smilieid]\" class=\"inlineimg\" />";
				}
				else
				{
					$replace = "<img src=\"$smiliepath\" border=\"0\" alt=\"\" title=\"" . htmlspecialchars_uni($smilie['title']) . "\" class=\"inlineimg\" />";
				}

				$sc["$find"] = $replace;
			}
		}
		else
		{
			// we have to get the smilies from the database
			DEVDEBUG('querying for smilies');

			$this->registry->smiliecache = array();

			$smilies = vB::getDbAssertor()->getRows('fetchSmilies', array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_STORED));
			foreach ($smilies as $smilie)
			{
				if (!$do_html)
				{
					$find = htmlspecialchars_uni(trim($smilie['smilietext']));
				}
				else
				{
					$find = trim($smilie['smilietext']);
				}

				$smiliepath = $smilie['smiliepath'];

				// if you change this HTML tag, make sure you change the smilie remover in code/php/html tag handlers!
				if ($this->is_wysiwyg())
				{
					$replace = "<img src=\"$smiliepath\" border=\"0\" alt=\"\" title=\"" . htmlspecialchars_uni($smilie['title']) . "\" smilieid=\"$smilie[smilieid]\" class=\"inlineimg\" />";
				}
				else
				{
					$replace = "<img src=\"$smiliepath\" border=\"0\" alt=\"\" title=\"" . htmlspecialchars_uni($smilie['title']) . "\" class=\"inlineimg\" />";
				}

				$sc["$find"] = $replace;

				$this->registry->smiliecache["$smilie[smilieid]"] = $smilie;
			}
		}

		return $sc;
	}

	/**
	* Parses out specific white space before or after cetain tags and does nl2br
	*
	* @param	string	Text to process
	* @param	bool	Whether to translate newlines to <br /> tags
	*
	* @return	string	Processed text
	*/
	function parse_whitespace_newlines($text, $do_nl2br = true)
	{
		// this replacement is equivalent to removing leading whitespace via this regex:
		// '#(? >(\r\n|\n|\r)?( )+)(\[(\*\]|/?list|indent))#si'
		// however, it's performance is much better! (because the tags occur less than the whitespace)
		foreach (array('[*]', '[list', '[/list', '[indent') AS $search_string)
		{
			$start_pos = 0;
			while (($tag_pos = stripos($text, $search_string, $start_pos)) !== false)
			{
				$whitespace_pos = $tag_pos - 1;
				while ($whitespace_pos >= 0 AND $text[$whitespace_pos] == ' ')
				{
					--$whitespace_pos;
				}
				if ($whitespace_pos >= 1 AND substr($text, $whitespace_pos - 1, 2) == "\r\n")
				{
					$whitespace_pos -= 2;
				}
				else if ($whitespace_pos >= 0 AND ($text[$whitespace_pos] == "\r" OR $text[$whitespace_pos] == "\n"))
				{
					--$whitespace_pos;
				}

				$length = $tag_pos - $whitespace_pos - 1;
				if ($length > 0)
				{
					$text = substr_replace($text, '', $whitespace_pos + 1, $length);
				}

				$start_pos = $tag_pos + 1 - $length;
			}
		}
		$text = preg_replace('#(/list\]|/indent\])(?> *)#si', '$1', $text);

		if ($do_nl2br)
		{
			$text = nl2br($text);
		}

		return $text;
	}

	/**
	* Parse an input string with BB code to a final output string of HTML
	*
	* @param	string	Input Text (BB code)
	* @param	bool	Whether to parse smilies
	* @param	bool	Whether to parse img (for the video bbcodes)
	* @param	bool	Whether to allow HTML (for smilies)
	*
	* @return	string	Ouput Text (HTML)
	*/
	function parse_bbcode($input_text, $do_smilies, $do_imgcode, $do_html = false)
	{
		return $this->parse_array($this->fix_tags($this->build_parse_array($input_text)), $do_smilies, $do_imgcode, $do_html);
	}

	/**
	* Takes a raw string and builds an array of tokens for parsing.
	*
	* @param	string	Raw text input
	*
	* @return	array	List of tokens
	*/
	function build_parse_array($text)
	{
		$start_pos = 0;
		$strlen = strlen($text);
		$output = array();
		$state = BB_PARSER_START;

		while ($start_pos < $strlen)
		{
			switch ($state)
			{
				case BB_PARSER_START:
					$tag_open_pos = strpos($text, '[', $start_pos);
					if ($tag_open_pos === false)
					{
						$internal_data = array('start' => $start_pos, 'end' => $strlen);
						$state = BB_PARSER_TEXT;
					}
					else if ($tag_open_pos != $start_pos)
					{
						$internal_data = array('start' => $start_pos, 'end' => $tag_open_pos);
						$state = BB_PARSER_TEXT;
					}
					else
					{
						$start_pos = $tag_open_pos + 1;
						if ($start_pos >= $strlen)
						{
							$internal_data = array('start' => $tag_open_pos, 'end' => $strlen);
							$start_pos = $tag_open_pos;
							$state = BB_PARSER_TEXT;
						}
						else
						{
							$state = BB_PARSER_TAG_OPENED;
						}
					}
					break;

				case BB_PARSER_TEXT:
					$end = end($output);
					if ($end['type'] == 'text')
					{
						// our last element was text too, so let's join them
						$key = key($output);
						$output["$key"]['data'] .= substr($text, $internal_data['start'], $internal_data['end'] - $internal_data['start']);
					}
					else
					{
						$output[] = array('type' => 'text', 'data' => substr($text, $internal_data['start'], $internal_data['end'] - $internal_data['start']));
					}

					$start_pos = $internal_data['end'];
					$state = BB_PARSER_START;
					break;

				case BB_PARSER_TAG_OPENED:
					$tag_close_pos = strpos($text, ']', $start_pos);
					if ($tag_close_pos === false)
					{
						$internal_data = array('start' => $start_pos - 1, 'end' => $start_pos);
						$state = BB_PARSER_TEXT;
						break;
					}

					// check to see if this is a closing tag, since behavior changes
					$closing_tag = ($text[$start_pos] == '/');
					if ($closing_tag)
					{
						// we don't want the / to be saved
						++$start_pos;
					}

					// ok, we have a ], check for an option
					$tag_opt_start_pos = strpos($text, '=', $start_pos);
					if ($closing_tag OR $tag_opt_start_pos === false OR $tag_opt_start_pos > $tag_close_pos)
					{
						// no option, so the ] is the end of the tag
						// check to see if this tag name is valid
						$tag_name_orig = substr($text, $start_pos, $tag_close_pos - $start_pos);
						$tag_name = strtolower($tag_name_orig);

						// if this is a closing tag, we don't know whether we had an option
						$has_option = $closing_tag ? null : false;

						if ($this->is_valid_tag($tag_name, $has_option))
						{
							$output[] = array(
								'type' => 'tag',
								'name' => $tag_name,
								'name_orig' => $tag_name_orig,
								'option' => false,
								'closing' => $closing_tag
							);

							$start_pos = $tag_close_pos + 1;
							$state = BB_PARSER_START;
						}
						else
						{
							// this is an invalid tag, so it's just text
							$internal_data = array('start' => $start_pos - 1 - ($closing_tag ? 1 : 0), 'end' => $start_pos);
							$state = BB_PARSER_TEXT;
						}
					}
					else
					{
						// check to see if this tag name is valid
						$tag_name_orig = substr($text, $start_pos, $tag_opt_start_pos - $start_pos);
						$tag_name = strtolower($tag_name_orig);

						if (!$this->is_valid_tag($tag_name, true))
						{
							// this isn't a valid tag name, so just consider it text
							$internal_data = array('start' => $start_pos - 1, 'end' => $start_pos);
							$state = BB_PARSER_TEXT;
							break;
						}

						// we have a = before a ], so we have an option
						$delimiter = $text[$tag_opt_start_pos + 1];
						if ($delimiter == '&' AND substr($text, $tag_opt_start_pos + 2, 5) == 'quot;')
						{
							$delimiter = '&quot;';
							$delim_len = 7;
						}
						else if ($delimiter != '"' AND $delimiter != "'")
						{
							$delimiter = '';
							$delim_len = 1;
						}
						else
						{
							$delim_len = 2;
						}

						if ($delimiter != '')
						{
							$close_delim = strpos($text, "$delimiter]", $tag_opt_start_pos + $delim_len);
							if ($close_delim === false)
							{
								// assume no delimiter, and the delimiter was actually a character
								$delimiter = '';
								$delim_len = 1;
							}
							else
							{
								$tag_close_pos = $close_delim;
							}
						}

						$tag_option = substr($text, $tag_opt_start_pos + $delim_len, $tag_close_pos - ($tag_opt_start_pos + $delim_len));
						if ($this->is_valid_option($tag_name, $tag_option))
						{
							$output[] = array(
								'type' => 'tag',
								'name' => $tag_name,
								'name_orig' => $tag_name_orig,
								'option' => $tag_option,
								'delimiter' => $delimiter,
								'closing' => false
							);

							$start_pos = $tag_close_pos + $delim_len;
							$state = BB_PARSER_START;
						}
						else
						{
							// this is an invalid option, so consider it just text
							$internal_data = array('start' => $start_pos - 1, 'end' => $start_pos);
							$state = BB_PARSER_TEXT;
						}
					}
					break;
			}
		}
		return $output;
	}

	/**
	* Traverses parse array and fixes nesting and mismatched tags.
	*
	* @param	array	Parsed data array, such as one from build_parse_array
	*
	* @return	array	Parse array with specific data fixed
	*/
	function fix_tags($preparsed)
	{
		$output = array();
		$stack = array();
		$noparse = null;

		foreach ($preparsed AS $node_key => $node)
		{
			if ($node['type'] == 'text')
			{
				$output[] = $node;
			}
			else if ($node['closing'] == false)
			{
				// opening a tag
				if ($noparse !== null)
				{
					$output[] = array('type' => 'text', 'data' => '[' . $node['name_orig'] . ($node['option'] !== false ? "=$node[delimiter]$node[option]$node[delimiter]" : '') . ']');
					continue;
				}

				$output[] = $node;
				end($output);

				$node['added_list'] = array();
				$node['my_key'] = key($output);
				array_unshift($stack, $node);

				if ($node['name'] == 'noparse')
				{
					$noparse = $node_key;
				}
			}
			else
			{
				// closing tag
				if ($noparse !== null AND $node['name'] != 'noparse')
				{
					// closing a tag but we're in a noparse - treat as text
					$output[] = array('type' => 'text', 'data' => '[/' . $node['name_orig'] . ']');
				}
				else if (($key = $this->find_first_tag($node['name'], $stack)) !== false)
				{
					if ($node['name'] == 'noparse')
					{
						// we're closing a noparse tag that we opened
						if ($key != 0)
						{
							for ($i = 0; $i < $key; $i++)
							{
								$output[] = $stack["$i"];
								unset($stack["$i"]);
							}
						}

						$output[] = $node;

						unset($stack["$key"]);
						$stack = array_values($stack); // this is a tricky way to renumber the stack's keys

						$noparse = null;

						continue;
					}

					if ($key != 0)
					{
						end($output);
						$max_key = key($output);

						// we're trying to close a tag which wasn't the last one to be opened
						// this is bad nesting, so fix it by closing tags early
						for ($i = 0; $i < $key; $i++)
						{
							$output[] = array('type' => 'tag', 'name' => $stack["$i"]['name'], 'name_orig' => $stack["$i"]['name_orig'], 'closing' => true);
							$max_key++;
							$stack["$i"]['added_list'][] = $max_key;
						}
					}

					$output[] = $node;

					if ($key != 0)
					{
						$max_key++; // for the node we just added

						// ...and now reopen those tags in the same order
						for ($i = $key - 1; $i >= 0; $i--)
						{
							$output[] = $stack["$i"];
							$max_key++;
							$stack["$i"]['added_list'][] = $max_key;
						}
					}

					unset($stack["$key"]);
					$stack = array_values($stack); // this is a tricky way to renumber the stack's keys
				}
				else
				{
					// we tried to close a tag which wasn't open, to just make this text
					$output[] = array('type' => 'text', 'data' => '[/' . $node['name_orig'] . ']');
				}
			}
		}

		// These tags were never closed, so we want to display the literal BB code.
		// Rremove any nodes we might've added before, thinking this was valid,
		// and make this node become text.
		foreach ($stack AS $open)
		{
			foreach ($open['added_list'] AS $node_key)
			{
				unset($output["$node_key"]);
			}
			$output["$open[my_key]"] = array(
				'type' => 'text',
				'data' => '[' . $open['name_orig'] . (!empty($open['option']) ? '=' . $open['delimiter'] . $open['option'] . $open['delimiter'] : '') . ']'
			);
		}

		/*
		// automatically close any tags that remain open
		foreach (array_reverse($stack) AS $open)
		{
			$output[] = array('type' => 'tag', 'name' => $open['name'], 'name_orig' => $open['name_orig'], 'closing' => true);
		}
		*/

		$output = $this->fixQuoteTags($output);

		return $output;
	}

	/**
	 * @see vB5_Template_BbCode::fixQuoteTags()
	 */
	protected function fixQuoteTags($elements)
	{
		// NOTE: See extensive comments on this function in vB5_Template_BbCode
		// The only differences here are the use of vB_String instead of vB5_String
		// and how vB options are accessed.

		$prevKey = null;

		foreach ($elements AS $key => $el)
		{
			if ($prevKey !== null)
			{
				$prevEl = $elements[$prevKey];

				if ($prevEl['type'] == 'tag' AND $prevEl['name'] == 'quote' AND $el['type'] == 'text')
				{
					if (!preg_match('/^.*;n?\d+$/U', $prevEl['option'], $match))
					{
						$options = vB::getDatastore()->getValue('options');
						$limit = (int) $options['maxuserlength'];
						$limit -= vB_String::vbStrlen($prevEl['option']);
						$limit += 20;

						$text = vB_String::vbChop($el['data'], $limit);

						if (preg_match('/^(.*(?<!&#[0-9]{3}|&#[0-9]{4}|&#[0-9]{5});\s*n\d+\s*)\]/U', $text, $match))
						{
							$len = strlen($match[1]);
							$elements[$prevKey]['option'] .= ']' . substr($el['data'], 0, $len);

							$len = strlen($match[0]);
							$elements[$key]['data'] = substr($el['data'], $len);
						}
					}
				}
			}

			$prevKey = $key;
		}

		return $elements;
	}

	/**
	* Takes a parse array and parses it into the final HTML.
	* Tags are assumed to be matched.
	*
	* @param	array	Parse array
	* @param	bool	Whether to parse smilies
	* @param	bool	Whether to parse img (for the video tags)
	* @param	bool	Whether to allow HTML (for smilies)
	*
	* @return	string	Final HTML
	*/
	function parse_array($preparsed, $do_smilies, $do_imgcode, $do_html = false)
	{
		$this->parse_output = '';
		$output =& $this->parse_output;
		$this->stack = array();
		$stack_size = 0;

		// holds options to disable certain aspects of parsing
		$parse_options = array(
			'no_parse'          => 0,
			'no_wordwrap'       => 0,
			'no_smilies'        => 0,
			'strip_space_after' => 0
		);

		$this->node_max = count($preparsed);
		$this->node_num = 0;

		foreach ($preparsed AS $node)
		{
			$this->node_num++;
			$pending_text = '';
			if ($node['type'] == 'text')
			{
				$pending_text =& $node['data'];

				// remove leading space after a tag
				if ($parse_options['strip_space_after'])
				{
					$pending_text = $this->strip_front_back_whitespace($pending_text, $parse_options['strip_space_after'], true, false);
					$parse_options['strip_space_after'] = 0;
				}

				// parse smilies
				if ($do_smilies AND !$parse_options['no_smilies'])
				{
					$pending_text = $this->parse_smilies($pending_text, $do_html);
				}

				// do word wrap
				if (!$parse_options['no_wordwrap'])
				{
					$pending_text = $this->do_word_wrap($pending_text);
				}

				if ($parse_options['no_parse'])
				{
					$pending_text = str_replace(array('[', ']'), array('&#91;', '&#93;'), $pending_text);
				}
			}
			else if ($node['closing'] == false)
			{
				$parse_options['strip_space_after'] = 0;

				if ($parse_options['no_parse'] == 0)
				{
					// opening a tag
					// initialize data holder and push it onto the stack
					$node['data'] = '';
					array_unshift($this->stack, $node);
					++$stack_size;

					$has_option = $node['option'] !== false ? 'option' : 'no_option';
					$tag_info =& $this->tag_list["$has_option"]["$node[name]"];

					// setup tag options
					if (!empty($tag_info['stop_parse']))
					{
						$parse_options['no_parse'] = 1;
					}
					if (!empty($tag_info['disable_smilies']))
					{
						$parse_options['no_smilies']++;
					}
					if (!empty($tag_info['disable_wordwrap']))
					{
						$parse_options['no_wordwrap']++;
					}
				}
				else
				{
					$pending_text = '&#91;' . $node['name_orig'] . ($node['option'] !== false ? "=$node[delimiter]$node[option]$node[delimiter]" : '') . '&#93;';
				}
			}
			else
			{
				$parse_options['strip_space_after'] = 0;

				// closing a tag
				// look for this tag on the stack
				if (($key = $this->find_first_tag($node['name'], $this->stack)) !== false)
				{
					// found it
					$open =& $this->stack["$key"];
					$this->current_tag =& $open;

					$has_option = $open['option'] !== false ? 'option' : 'no_option';

					// check to see if this version of the tag is valid
					if (isset($this->tag_list["$has_option"]["$open[name]"]))
					{
						$tag_info =& $this->tag_list["$has_option"]["$open[name]"];

						// make sure we have data between the tags
						if ((isset($tag_info['strip_empty']) AND $tag_info['strip_empty'] == false) OR trim($open['data']) != '')
						{
							// make sure our data matches our pattern if there is one
							if (empty($tag_info['data_regex']) OR preg_match($tag_info['data_regex'], $open['data']))
							{
								// see if the option might have a tag, and if it might, run a parser on it
								if (!empty($tag_info['parse_option']) AND strpos($open['option'], '[') !== false)
								{
									$old_stack = $this->stack;
									$open['option'] = $this->parse_bbcode($open['option'], $do_smilies, $do_imgcode);
									$this->stack = $old_stack;
									$this->current_tag =& $open;
									unset($old_stack);
								}

								// now do the actual replacement
								if (isset($tag_info['html']))
								{
									// this is a simple HTML replacement
									// removing bad fix per Freddie.
									//$search = array("'", '=');
									//$replace = array('&#039;', '&#0061;');
									//$open['data'] = str_replace($search, $replace, $open['data']);
									//$open['option'] = str_replace($search, $replace, $open['option']);
									$pending_text = sprintf($tag_info['html'], $open['data'], $open['option']);
								}
								else if (isset($tag_info['callback']))
								{
									// call a callback function
									if ($tag_info['callback'] == 'handle_bbcode_video' AND !$do_imgcode)
									{
										$tag_info['callback'] = 'handle_bbcode_url';
										$open['option'] = '';
									}

									$pending_text = $this->{$tag_info['callback']}($open['data'], $open['option']);
								}
							}
							else
							{
								// oh, we didn't match our regex, just print the tag out raw
								$pending_text =
									'&#91;' . $open['name_orig'] .
									($open['option'] !== false ? "=$open[delimiter]$open[option]$open[delimiter]" : '') .
									'&#93;' . $open['data'] . '&#91;/' . $node['name_orig'] . '&#93;'
								;
							}
						}

						// undo effects of various tag options
						if (!empty($tag_info['strip_space_after']))
						{
							$parse_options['strip_space_after'] = $tag_info['strip_space_after'];
						}
						if (!empty($tag_info['stop_parse']))
						{
							$parse_options['no_parse'] = 0;
						}
						if (!empty($tag_info['disable_smilies']))
						{
							$parse_options['no_smilies']--;
						}
						if (!empty($tag_info['disable_wordwrap']))
						{
							$parse_options['no_wordwrap']--;
						}
					}
					else
					{
						// this tag appears to be invalid, so just print it out as text
						$pending_text = '&#91;' . $open['name_orig'] . ($open['option'] !== false ? "=$open[delimiter]$open[option]$open[delimiter]" : '') . '&#93;';
					}

					// pop the tag off the stack

					unset($this->stack["$key"]);
					--$stack_size;
					$this->stack = array_values($this->stack); // this is a tricky way to renumber the stack's keys
				}
				else
				{
					// wasn't there - we tried to close a tag which wasn't open, so just output the text
					$pending_text = '&#91;/' . $node['name_orig'] . '&#93;';
				}
			}

			if ($stack_size == 0)
			{
				$output .= $pending_text;
			}
			else
			{
				$this->stack[0]['data'] .= $pending_text;
			}
		}

		/*
		// check for tags that are stil open at the end and display them
		foreach (array_reverse($this->stack) AS $open)
		{
			$output .= '[' . $open['name_orig'];
			if ($open['option'])
			{
				$output .= '=' . $open['delimiter'] . $open['option'] . $open['delimiter'];
			}
			$output .= "]$open[data]";
			//$output .= $open['data'];
		}
		*/

		return $output;
	}

	/**
	* Checks if the specified tag exists in the list of parsable tags
	*
	* @param	string		Name of the tag
	* @param	bool/null	true = tag with option, false = tag without option, null = either
	*
	* @return	bool		Whether the tag is valid
	*/
	function is_valid_tag($tag_name, $has_option = null)
	{
		if ($tag_name === '')
		{
			// no tag name, so this definitely isn't a valid tag
			return false;
		}

		if ($tag_name[0] == '/')
		{
			$tag_name = substr($tag_name, 1);
		}

		if ($has_option === null)
		{
			return (isset($this->tag_list['no_option']["$tag_name"]) OR isset($this->tag_list['option']["$tag_name"]));
		}
		else
		{
			$option = $has_option ? 'option' : 'no_option';
			return isset($this->tag_list["$option"]["$tag_name"]);
		}
	}

	/**
	* Checks if the specified tag option is valid (matches the regex if there is one)
	*
	* @param	string		Name of the tag
	* @param	string		Value of the option
	*
	* @return	bool		Whether the option is valid
	*/
	function is_valid_option($tag_name, $tag_option)
	{
		if (empty($this->tag_list['option']["$tag_name"]['option_regex']))
		{
			return true;
		}
		return preg_match($this->tag_list['option']["$tag_name"]['option_regex'], $tag_option);
	}

	/**
	* Find the first instance of a tag in an array
	*
	* @param	string		Name of tag
	* @param	array		Array to search
	*
	* @return	int/false	Array key of first instance; false if it does not exist
	*/
	function find_first_tag($tag_name, &$stack)
	{
		foreach ($stack AS $key => $node)
		{
			if ($node['name'] == $tag_name)
			{
				return $key;
			}
		}
		return false;
	}

	/**
	* Find the last instance of a tag in an array.
	*
	* @param	string		Name of tag
	* @param	array		Array to search
	*
	* @return	int/false	Array key of first instance; false if it does not exist
	*/
	function find_last_tag($tag_name, &$stack)
	{
		foreach (array_reverse($stack, true) AS $key => $node)
		{
			if ($node['name'] == $tag_name)
			{
				return $key;
			}
		}
		return false;
	}

	/**
	 * Handles an [indent] tag.
	 *
	 * @param	string	The text to indent
	 * @param	string	Indentation level
	 *
	 * @return	string	HTML representation of the tag.
	 */
	protected function handle_bbcode_indent($text, $type = '')
	{
		$type = (int) $type;

		if ($type < 1)
		{
			$type = 1;
		}

		$indent = $type * vB_Api_Bbcode::EDITOR_INDENT;
		$user = vB::getCurrentSession()->fetch_userinfo();
		$dir = ($user['lang_options']['direction'] ? 'left' : 'right');

		return '<div style="margin-' . $dir . ':' . $indent . 'px">' . $text . '</div>';
	}

	/**
	* Allows extension of the class functionality at run time by calling an
	* external function. To use this, your tag must have a callback of
	* 'handle_external' and define an additional 'external_callback' entry.
	* Your function will receive 3 parameters:
	*	A reference to this BB code parser
	*	The value for the tag
	*	The option for the tag
	* Ensure that you accept at least the first parameter by reference!
	*
	* @param	string	Value for the tag
	* @param	string	Option for the tag (if it has one)
	*
	* @return	string	HTML representation of the tag
	*/
	function handle_external($value, $option = null)
	{
		$open = $this->current_tag;

		$has_option = $open['option'] !== false ? 'option' : 'no_option';
		$tag_info =& $this->tag_list["$has_option"]["$open[name]"];

		return $tag_info['external_callback']($this, $value, $option);
	}

	/**
	* Handles an [email] tag. Creates a link to email an address.
	*
	* @param	string	If tag has option, the displayable email name. Else, the email address.
	* @param	string	If tag has option, the email address.
	*
	* @return	string	HTML representation of the tag.
	*/
	function handle_bbcode_email($text, $link = '')
	{
		$rightlink = trim($link);
		if (empty($rightlink))
		{
			// no option -- use param
			$rightlink = trim($text);
		}
		$rightlink = str_replace(array('`', '"', "'", '['), array('&#96;', '&quot;', '&#39;', '&#91;'), $this->strip_smilies($rightlink));

		if (!trim($link) OR $text == $rightlink)
		{
			$tmp = unhtmlspecialchars($text);
			if (vbstrlen($tmp) > 55 AND $this->is_wysiwyg() == false)
			{
				$text = htmlspecialchars_uni(vbchop($tmp, 36) . '...' . substr($tmp, -14));
			}
		}

		// remove double spaces -- fixes issues with wordwrap
		$rightlink = str_replace('  ', '', $rightlink);

		// email hyperlink (mailto:)
		if (vB_String::isValidEmail($rightlink))
		{
			return "<a href=\"mailto:$rightlink\">$text</a>";
		}
		else
		{
			return $text;
		}
	}

	/**
	* Handles a [quote] tag. Displays a string in an area indicating it was quoted from someone/somewhere else.
	*
	* @param	string	The body of the quote.
	* @param	string	If tag has option, the original user to post.
	*
	* @return	string	HTML representation of the tag.
	*/
	function handle_bbcode_quote($message, $username = '')
	{
		global $vbulletin, $vbphrase, $show;

		// remove smilies from username
		$username = $this->strip_smilies($username);

		// NOTE: This regex differs from the other bbcode implementations in that
		// it doesn't account for the nXXX nodeid format. It uses (\d+) instead
		// of (n?\d+) I don't want to change it at this time because I haven't
		// researched exactly where and how this class is used.
		if (preg_match('/^(.+)(?<!&#[0-9]{3}|&#[0-9]{4}|&#[0-9]{5});\s*(\d+)\s*$/U', $username, $match))
		{
			$username = $match[1];
			$postid = $match[2];
		}
		else
		{
			$postid = 0;
		}

		$username = $this->do_word_wrap($username);

		$show['username'] = iif($username != '', true, false);
		$message = $this->strip_front_back_whitespace($message, 1);

		if ($this->options['cachable'] == false)
		{
			$show['iewidthfix'] = (is_browser('ie') AND !(is_browser('ie', 6)));
		}
		else
		{
			// this post may be cached, so we can't allow this "fix" to be included in that cache
			$show['iewidthfix'] = false;
		}

		$templater = vB_Template::create($this->printable ? $this->quote_printable_template : $this->quote_template, true);
			$templater->register('message', $message);
			$templater->register('postid', $postid);
			$templater->register('username', $username);
			$templater->register('quote_vars', $this->quote_vars);
		return $templater->render();
	}

	/**
	* Handles a [post] tag. Creates a link to another post.
	*
	* @param	string	If tag has option, the displayable name. Else, the postid.
	* @param	string	If tag has option, the postid.
	*
	* @return	string	HTML representation of the tag.
	*/
	function handle_bbcode_post($text, $postId)
	{
		$postId = intval($postId);

		if (empty($postId))
		{
			// no option -- use param
			$postId = intval($text);
			unset($text);
		}

		$url = vB_Api::instanceInternal('route')->fetchLegacyPostUrl($postId);

		if (!isset($text))
		{
			$text = $url;
		}

		// standard URL hyperlink
		return "<a href=\"$url\" target=\"_blank\">$text</a>";
	}

	/**
	* Handles a [thread] tag. Creates a link to another thread.
	*
	* @param	string	If tag has option, the displayable name. Else, the threadid.
	* @param	string	If tag has option, the threadid.
	*
	* @return	string	HTML representation of the tag.
	*/
	function handle_bbcode_thread($text, $threadId)
	{
		$threadId = intval($threadId);

		if (empty($threadId))
		{
			// no option -- use param
			$threadId = intval($text);
			unset($text);
		}

		$url = vB_Api::instanceInternal('route')->fetchLegacyThreadUrl($threadId);

		if (!isset($text))
		{
			$text = $url;
		}

		// standard URL hyperlink
		return "<a href=\"$url\" target=\"_blank\">$text</a>";
	}

	/**
	* Handles a [php] tag. Syntax highlights a string of PHP.
	*
	* @param	string	The code to highlight.
	*
	* @return	string	HTML representation of the tag.
	*/
	function handle_bbcode_php($code)
	{
		global $vbulletin, $vbphrase, $show;
		static $codefind1, $codereplace1, $codefind2, $codereplace2;

		$code = $this->strip_front_back_whitespace($code, 1);

		if (!is_array($codefind1))
		{
			$codefind1 = array(
				'<br>',		// <br> to nothing
				'<br />'	// <br /> to nothing
			);
			$codereplace1 = array(
				'',
				''
			);

			$codefind2 = array(
				'&gt;',		// &gt; to >
				'&lt;',		// &lt; to <
				'&quot;',	// &quot; to ",
				'&amp;',	// &amp; to &
				'&#91;',    // &#91; to [
				'&#93;',    // &#93; to ]
			);
			$codereplace2 = array(
				'>',
				'<',
				'"',
				'&',
				'[',
				']',
			);
		}

		// remove htmlspecialchars'd bits and excess spacing
		$code = rtrim(str_replace($codefind1, $codereplace1, $code));
		$blockheight = $this->fetch_block_height($code); // fetch height of block element
		$code = str_replace($codefind2, $codereplace2, $code); // finish replacements

		// do we have an opening <? tag?
		if (!preg_match('#<\?#si', $code))
		{
			// if not, replace leading newlines and stuff in a <?php tag and a closing tag at the end
			$code = "<?php BEGIN__VBULLETIN__CODE__SNIPPET $code \r\nEND__VBULLETIN__CODE__SNIPPET ?>";
			$addedtags = true;
		}
		else
		{
			$addedtags = false;
		}

		// highlight the string
		$oldlevel = error_reporting(0);
		$code = highlight_string($code, true);
		error_reporting($oldlevel);

		// if we added tags above, now get rid of them from the resulting string
		if ($addedtags)
		{
			$search = array(
				'#&lt;\?php( |&nbsp;)BEGIN__VBULLETIN__CODE__SNIPPET( |&nbsp;)#siU',
				'#(<(span|font)[^>]*>)&lt;\?(</\\2>(<\\2[^>]*>))php( |&nbsp;)BEGIN__VBULLETIN__CODE__SNIPPET( |&nbsp;)#siU',
				'#END__VBULLETIN__CODE__SNIPPET( |&nbsp;)\?(>|&gt;)#siU'
			);
			$replace = array(
				'',
				'\\4',
				''
			);

			$code = preg_replace($search, $replace, $code);
		}

		$code = preg_replace('/&amp;#([0-9]+);/', '&#$1;', $code); // allow unicode entities back through
		$code = str_replace(array('[', ']'), array('&#91;', '&#93;'), $code);

		$templater = vB_Template::create($this->printable ? 'bbcode_php_printable' : 'bbcode_php', true);
			$templater->register('blockheight', $blockheight);
			$templater->register('code', $code);
		return $templater->render();
	}

	/**
	* Emulates the behavior of a pre tag in HTML. Tabs and multiple spaces
	* are replaced with spaces mixed with non-breaking spaces. Usually combined
	* with code tags. Note: this still allows the browser to wrap lines.
	*
	* @param	string	Text to convert. Should not have <br> tags!
	*
	* @param	string	Converted text
	*/
	function emulate_pre_tag($text)
	{
		$text = str_replace(
			array("\t",       '  '),
			array('        ', '&nbsp; '),
			nl2br($text)
		);

		return preg_replace('#([\r\n]) (\S)#', '$1&nbsp;$2', $text);
	}

	/**
	* Handles a [video] tag. Displays a movie.
	*
	* @param	string	The code to display
	*
	* @return	string	HTML representation of the tag.
	*/
	function handle_bbcode_video($url, $option)
	{
		global $vbulletin, $vbphrase, $show;

		$params = array();
		$options = explode(';', $option);
		$provider = strtolower($options[0]);
		$code = $options[1];

		if (!$code OR !$provider)
		{
			return '[video=' . $option . ']' . $url . '[/video]';
		}

		$templater = vB_Template::create('bbcode_video', true);
			$templater->register('url', $url);
			$templater->register('provider', $provider);
			$templater->register('code', $code);

		return $templater->render();
	}

	/**
	* Handles a [code] tag. Displays a preformatted string.
	*
	* @param	string	The code to display
	*
	* @return	string	HTML representation of the tag.
	*/
	function handle_bbcode_code($code)
	{
		global $vbulletin, $vbphrase, $show;

		// remove unnecessary line breaks and escaped quotes
		$code = str_replace(array('<br>', '<br />'), array('', ''), $code);

		$code = $this->strip_front_back_whitespace($code, 1);

		if ($this->printable)
		{
			$code = $this->emulate_pre_tag($code);
			$template = 'bbcode_code_printable';
		}
		else
		{
			$blockheight = $this->fetch_block_height($code);
			$template = 'bbcode_code';
		}

		$templater = vB_Template::create($template, true);
			$templater->register('blockheight', $blockheight);
			$templater->register('code', $code);
		return $templater->render();
	}

	/**
	 * Handled [h] tags - converts to <b>
	*
	* @param	string	Body of the [H]
	* @param	string	H Size (1 - 6)
	*
	* @return	string	Parsed text
	*/
	function handle_bbcode_h($text, $option)
	{
		if (preg_match('#^[1-6]$#', $option))
		{
			return "<b>{$text}</b><br /><br />";
		}
		else
		{
			return $text;
		}

		return $text;
	}


	/**
	* Handles an [html] tag. Syntax highlights a string of HTML.
	*
	* @param	string	The HTML to highlight.
	*
	* @return	string	HTML representation of the tag.
	*/
	function handle_bbcode_html($code)
	{
		global $vbulletin, $vbphrase, $show, $html_allowed;
		static $regexfind, $regexreplace;

		$code = $this->strip_front_back_whitespace($code, 1);


		if (!is_array($regexfind))
		{
			$regexfind = array(
				'#<br( /)?>#siU',				// strip <br /> codes
				'#(&amp;\w+;)#siU',				// do html entities
				'#&lt;!--(.*)--&gt;#siU',		// italicise comments
			);
			$regexreplace = array(
				'',								// strip <br /> codes
				'<b><i>\1</i></b>',				// do html entities
				'<i>&lt;!--\1--&gt;</i>',		// italicise comments
			);
		}

		// parse the code
		$code = preg_replace($regexfind, $regexreplace, $code);

		$code = preg_replace_callback('#&lt;((?>[^&"\']+?|&quot;.*&quot;|&(?!gt;)|"[^"]*"|\'[^\']*\')+)&gt;#siU', // push code through the tag handler
			array($this, 'handleBBCodeTagPregMatch1'), $code);

		if ($html_allowed)
		{
			$code = preg_replace_callback('#<((?>[^>"\']+?|"[^"]*"|\'[^\']*\')+)>#', // push code through the tag handler
				array($this, 'handleBBCodeTagPregMatch2'), $code);
		}

		if ($this->printable)
		{
			$code = $this->emulate_pre_tag($code);
			$template = 'bbcode_html_printable';
		}
		else
		{
			$blockheight = $this->fetch_block_height($code);
			$template = 'bbcode_html';
		}

		$templater = vB_Template::create($template, true);
			$templater->register('blockheight', $blockheight);
			$templater->register('code', $code);
		return $templater->render();
	}

	/**
	 * Callback for preg_replace_callback used in handle_bbcode_html
	 */
	protected function handleBBCodeTagPregMatch1($matches)
	{
		return $this->handle_bbcode_html_tag($matches[1]);
	}

	/**
	 * Callback for preg_replace_callback used in handle_bbcode_html
	 */
	protected function handleBBCodeTagPregMatch2($matches)
	{
		return $this->handle_bbcode_html_tag(vB_String::htmlSpecialCharsUni($matches[1]));
	}

	/**
	* Handles an individual HTML tag in a [html] tag.
	*
	* @param	string	The body of the tag.
	*
	* @return	string	Syntax highlighted, displayable HTML tag.
	*/
	function handle_bbcode_html_tag($tag)
	{
		static $bbcode_html_colors;

		if (empty($bbcode_html_colors))
		{
			$bbcode_html_colors = $this->fetch_bbcode_html_colors();
		}

		// change any embedded URLs so they don't cause any problems
		$tag = preg_replace('#\[(email|url)=&quot;(.*)&quot;\]#siU', '[$1="$2"]', $tag);

		// find if the tag has attributes
		$spacepos = strpos($tag, ' ');
		if ($spacepos != false)
		{
			// tag has attributes - get the tag name and parse the attributes
			$tagname = substr($tag, 0, $spacepos);
			$tag = preg_replace('# (\w+)=&quot;(.*)&quot;#siU', ' \1=<span style="color:' . $bbcode_html_colors['attribs'] . '">&quot;\2&quot;</span>', $tag);
		}
		else
		{
			// no attributes found
			$tagname = $tag;
		}
		// remove leading slash if there is one
		if ($tag[0] == '/')
		{
			$tagname = substr($tagname, 1);
		}
		// convert tag name to lower case
		$tagname = strtolower($tagname);

		// get highlight colour based on tag type
		switch($tagname)
		{
			// table tags
			case 'table':
			case 'tr':
			case 'td':
			case 'th':
			case 'tbody':
			case 'thead':
				$tagcolor = $bbcode_html_colors['table'];
				break;
			// form tags
			//NOTE: Supposed to be a semi colon here ?
			case 'form';
			case 'input':
			case 'select':
			case 'option':
			case 'textarea':
			case 'label':
			case 'fieldset':
			case 'legend':
				$tagcolor = $bbcode_html_colors['form'];
				break;
			// script tags
			case 'script':
				$tagcolor = $bbcode_html_colors['script'];
				break;
			// style tags
			case 'style':
				$tagcolor = $bbcode_html_colors['style'];
				break;
			// anchor tags
			case 'a':
				$tagcolor = $bbcode_html_colors['a'];
				break;
			// img tags
			case 'img':
				$tagcolor = $bbcode_html_colors['img'];
				break;
			// if (vB Conditional) tags
			case 'if':
			case 'else':
			case 'elseif':
				$tagcolor = $bbcode_html_colors['if'];
				break;
			// all other tags
			default:
				$tagcolor = $bbcode_html_colors['default'];
				break;
		}

		$tag = '<span style="color:' . $tagcolor . '">&lt;' . str_replace('\\"', '"', $tag) . '&gt;</span>';
		return $tag;
	}

	/**
	* Handles a [list] tag. Makes a bulleted or ordered list.
	*
	* @param	string	The body of the list.
	* @param	string	If tag has option, the type of list (ordered, etc).
	*
	* @return	string	HTML representation of the tag.
	*/
	function handle_bbcode_list($text, $type = '')
	{
		if ($type)
		{
			switch ($type)
			{
				case 'A':
					$listtype = 'upper-alpha';
					break;
				case 'a':
					$listtype = 'lower-alpha';
					break;
				case 'I':
					$listtype = 'upper-roman';
					break;
				case 'i':
					$listtype = 'lower-roman';
					break;
				case '1': //break missing intentionally
				default:
					$listtype = 'decimal';
					break;
			}
		}
		else
		{
			$listtype = '';
		}

		// emulates ltrim after nl2br
		$text = preg_replace('#^(\s|<br>|<br />)+#si', '', $text);

		$bullets = preg_split('#\s*\[\*\]#s', $text, -1, PREG_SPLIT_NO_EMPTY);
		if (empty($bullets))
		{
			return "\n\n";
		}

		$output = '';
		foreach ($bullets AS $bullet)
		{
			$output .= $this->handle_bbcode_list_element($bullet);
		}

		if ($listtype)
		{
			return '<ol class="' . $listtype . '">' . $output . '</ol>';
		}
		else
		{
			return "<ul>$output</ul>";
		}
	}

	/**
	* Handles a single bullet of a list
	*
	* @param	string	Text of bullet
	*
	* @return	string	HTML for bullet
	*/
	function handle_bbcode_list_element($text)
	{
		return "<li>$text</li>\n";
	}


	/**
	* Handles a [url] tag. Creates a link to another web page.
	*
	* @param	string	If tag has option, the displayable name. Else, the URL.
	* @param	string	If tag has option, the URL.
	* @param	bool	If this is for an image, just return the link
	*
	* @return	string	HTML representation of the tag.
	*/
	function handle_bbcode_url($text, $link, $image = false)
	{
		$rightlink = trim($link);

		if (empty($rightlink))
		{
			// no option -- use param
			$rightlink = trim($text);
		}
		$rightlink = str_replace(array('`', '"', "'", '['), array('&#96;', '&quot;', '&#39;', '&#91;'), $this->strip_smilies($rightlink));

		// remove double spaces -- fixes issues with wordwrap
		$rightlink = str_replace('  ', '', $rightlink);

		if (!preg_match('#^[a-z0-9]+(?<!about|javascript|vbscript|data):#si', $rightlink))
		{
			$rightlink = "http://$rightlink";
		}

		if (!trim($link) OR str_replace('  ', '', $text) == $rightlink)
		{
			$tmp = unhtmlspecialchars($rightlink);
			if (vbstrlen($tmp) > 55 AND $this->is_wysiwyg() == false)
			{
				$text = htmlspecialchars_uni(vbchop($tmp, 36) . '...' . substr($tmp, -14));
			}
			else
			{
				// under the 55 chars length, don't wordwrap this
				$text = str_replace('  ', '', $text);
			}
		}

		static $current_url, $current_host, $allowed, $friendlyurls = array();

		if (!isset($current_url))
		{
			$current_url = @vB_String::parseUrl($this->registry->options['bburl']);
		}
		$is_external = $this->registry->options['url_nofollow'];

		if ($this->registry->options['url_nofollow'])
		{
			if (!isset($current_host))
			{
				$current_host = preg_replace('#:(\d)+$#', '', VB_HTTP_HOST);

				$allowed = preg_split('#\s+#', $this->registry->options['url_nofollow_whitelist'], -1, PREG_SPLIT_NO_EMPTY);
				$allowed[] = preg_replace('#^www\.#i', '', $current_host);
				$allowed[] = preg_replace('#^www\.#i', '', $current_url['host']);
			}

			$target_url = preg_replace('#^([a-z0-9]+:(//)?)#', '', $rightlink);

			foreach ($allowed AS $host)
			{
				if (stripos($target_url, $host) !== false)
				{
					$is_external = false;
				}
			}
		}

		if ($image)
		{
			return array('link' => $rightlink, 'nofollow' => $is_external);
		}

		// API need to convert link to vb:action/param1=val1/param2=val2...
		if (defined('VB_API') AND VB_API === true)
		{
			$current_link = @vB_String::parseUrl($rightlink);
			if ($current_link !== false)
			{
				$current_link['host'] = strtolower($current_link['host']);
				$current_url['host'] = strtolower($current_url['host']);
				if (
					(
						$current_link['host'] == $current_url['host']
						OR 'www.' . $current_link['host'] == $current_url['host']
						OR $current_link['host'] == 'www.' . $current_url['host']
					)
					AND
					(!$current_url['path'] OR stripos($current_link['path'], $current_url['path']) !== false)
				)
				{
					// This is a vB link.
					if (
						$current_link['path'] == $current_url['path']
						OR $current_link['path'] . '/' == $current_url['path']
						OR $current_link['path'] == $current_url['path'] . '/'
					)
					{
						$rightlink = 'vb:index';
					}
					else
					{
						// Get a list of declared friendlyurl classes
						if (!$friendlyurls)
						{
							require_once(DIR . '/includes/class_friendly_url.php');
							$classes = get_declared_classes();
							foreach ($classes as $classname)
							{
								if (strpos($classname, 'vB_Friendly_Url_') !== false)
								{
									$reflect = new ReflectionClass($classname);
									$props = $reflect->getdefaultProperties();

									if ($classname == 'vB_Friendly_Url_vBCms')
									{
										$props['idvar'] = $props['ignorelist'][] = $this->registry->options['route_requestvar'];
										$props['script'] = 'content.php';
										$props['rewrite_segment'] = 'content';
									}

									if ($props['idvar'])
									{
										$friendlyurls[$classname]['idvar'] = $props['idvar'];
										$friendlyurls[$classname]['idkey'] = $props['idkey'];
										$friendlyurls[$classname]['titlekey'] = $props['titlekey'];
										$friendlyurls[$classname]['ignorelist'] = $props['ignorelist'];
										$friendlyurls[$classname]['script'] = $props['script'];
										$friendlyurls[$classname]['rewrite_segment'] = $props['rewrite_segment'];
									}
								}

								$friendlyurls['vB_Friendly_Url_vBCms']['idvar'] = $this->registry->options['route_requestvar'];
								$friendlyurls['vB_Friendly_Url_vBCms']['ignorelist'][] = $this->registry->options['route_requestvar'];
								$friendlyurls['vB_Friendly_Url_vBCms']['script'] = 'content.php';
								$friendlyurls['vB_Friendly_Url_vBCms']['rewrite_segment'] = 'content';

								$friendlyurls['vB_Friendly_Url_vBCms2']['idvar'] = $this->registry->options['route_requestvar'];
								$friendlyurls['vB_Friendly_Url_vBCms2']['ignorelist'][] = $this->registry->options['route_requestvar'];
								$friendlyurls['vB_Friendly_Url_vBCms2']['script'] = 'list.php';
								$friendlyurls['vB_Friendly_Url_vBCms2']['rewrite_segment'] = 'list';
							}
						}

						/*
						* 	FRIENDLY_URL_OFF
						*	showthread.php?t=1234&p=2
						*
						*	FRIENDLY_URL_BASIC
						*	showthread.php?1234-Thread-Title/page2&pp=2
						*
						*	FRIENDLY_URL_ADVANCED
						*	showthread.php/1234-Thread-Title/page2?pp=2
						*
						*	FRIENDLY_URL_REWRITE
						*	/threads/1234-Thread-Title/page2?pp=2
						*/

						// Try to get the script name
						// FRIENDLY_URL_OFF, FRIENDLY_URL_BASIC or FRIENDLY_URL_ADVANCED
						$scriptname = '';
						if (preg_match('#([^/]+)\.php#si', $current_link['path'], $matches))
						{
							$scriptname = $matches[1];
						}
						else
						{
							// Build a list of rewrite_segments
							foreach ($friendlyurls as $v)
							{
								$rewritesegments .= "|$v[rewrite_segment]";
							}
							$pat = '#/(' . substr($rewritesegments, 1) . ')/#si';
							if (preg_match($pat, $current_link['path'], $matches))
							{
								$uri = $matches[1];
							}
							// Decide the type of the url
							$urltype = null;
							foreach ($friendlyurls as $v)
							{
								if ($v['rewrite_segment'] == $uri)
								{
									$urltype = $v;
									break;
								}
							}

							// Convert $uri back to correct scriptname
							$scriptname = str_replace('.php', '', $urltype['script']);
						}

						if ($scriptname)
						{
							$oldrightlink = $rightlink;

							$rightlink = "vb:$scriptname";

							// Check if it's FRIENDLY_URL_BASIC or FRIENDLY_URL_ADVANCED
							if (preg_match('#(?:\?|/)(\d+).*?(?:/page(\d+)|$)#si', $oldrightlink, $matches))
							{
								// Decide the type of the url
								$urltype = null;
								foreach ($friendlyurls as $v)
								{
									if ($v['script'] == $scriptname . '.php')
									{
										$urltype = $v;
										break;
									}
								}

								if ($urltype)
								{
									$rightlink .= "/$urltype[idvar]=$matches[1]";
								}

								if ($matches[2])
								{
									$rightlink .= "/page=2";
								}
							}
							if (preg_match_all('#([a-z0-9_]+)=([a-z0-9_\+]+)#si', $current_link['query'], $matches))
							{
								foreach ($matches[0] as $match)
								{
									$rightlink .= "/$match";
								}

							}
						}
					}
				}
			}
		}

		// standard URL hyperlink
		return "<a href=\"$rightlink\" target=\"_blank\"" . ($is_external ? ' rel="nofollow"' : '') . ">$text</a>";
	}

	protected function handle_bbcode_attach($text, $option)
	{
		/*
			At the moment, this is here only to hack around the wordwrap from breaking a possibly long attach bbcode (due to a long caption in the json_encode string).
			The json_encode/decode doesn't break, but the generated *search* string for str_replace in handle_bbcode_img() does break, as that comes from the
			full text and not the *current page text* that's been through wordwrap.
		 */
		$option = strtoupper($option);
		switch ($option)
		{
			case 'JSON':
				if (!$this->options['do_html'])
				{
					$unescaped_text = html_entity_decode($text, ENT_QUOTES);
				}
				else
				{
					$unescaped_text = $text;
				}

				$data = json_decode($unescaped_text, true);

				if (empty($data))
				{
					// just let the old attachment code handle this.
					return '[ATTACH=' . $option . ']' . $text . '[/ATTACH]';
				}
				else
				{
					$data['original_text'] = $text;
					$return = $this->processAttachBBCode($data);

					return $return;
				}

				break;
			case 'CONFIG':
				$prefix = '[ATTACH=' . $option . ']';
				break;
			case '':
			default:
				$prefix = '[ATTACH]';
				break;
		}

		return $prefix . $text . '[/ATTACH]';
	}

	protected function handle_bbcode_img2($text, $option)
	{

		/*
			See notes above for handle_bbcode_attach.
			Let's also support custom settings on an external image.
		 */
		$option = strtoupper($option);
		switch ($option)
		{
			case 'JSON':
				if (!$this->options['do_html'])
				{
					$unescaped_text = html_entity_decode($text, ENT_QUOTES);
				}
				else
				{
					$unescaped_text = $text;
				}

				$data = json_decode($unescaped_text, true);

				if (empty($data))
				{
					// We don't know what to do with this
					return '[IMG2=' . $option . ']' . $text . '[/IMG2]';
				}
				else
				{
					$data['original_text'] = $text;
					$return = $this->processImg2BBCode($data);

					return $return;
				}

				break;
			default:
				$prefix = '[IMG2]';
				break;
		}

		return $prefix . $text . '[/IMG2]';
	}

	protected function processImg2BBCode($data)
	{
		$settings = $this->processCustomImgConfig($data);

		/*
			TODO: Do img bbcodes have any "reader" permission checks required to render image??
		 */

		$size = 'full'; // external image, we have no business passing in our own query params here.



		// OUTPUT LOGIC
		$link = $data['src']; // UNCLEAN

		/*
			Mostly used when the user may not have img bbcode perms for signatures.

			Return as a link instead, using as much info as possible.
		*/
		if (empty($this->options['do_imgcode']))
		{
			// Just display a link.
			// alt, title & caption are cleaned TYPE_NOHTML in processCustomImgConfig()

			$link = vB_String::htmlSpecialCharsUni($link);

			$alt = '';
			if (!empty($settings['imgbits']['alt']))
			{
				$alt = ' alt="' . $settings['imgbits']['alt'] . '"';
			}

			$title = '';
			if (!empty($settings['imgbits']['title']))
			{
				$title = ' title="' . $settings['imgbits']['title'] . '"';
			}

			$linktext = $link;
			if (!empty($settings['all']['caption']))
			{
				$linktext = $settings['all']['caption'];
			}
			elseif (!empty($settings['imgbits']['title']))
			{
				$linktext = $settings['imgbits']['title'];
			}

			return	"<a href=\"" . $link . "\" $title $alt >$linktext</a>";
		}

		/*
			Build up the img tag & caption if necessary
		 */
		$fullsize = false; // Set if $settings['all']['size'] is 'full' or 'fullsize'. Used to bypass anchoring for fullsize images.
		$customLink = false; // If $settings['all']['link'] is 1 and $settings['all']['url'] isn't empty, it becomes an array of data-attributes to set in the img bits
		$imgclass = array();


		//$settings = $this->processCustomImgConfig($data);
		$imgbits = $settings['imgbits'];

		$imgbits['border'] = 0;

		// this comes from $data['src'] which is cleaned by the text api, so we don't want to double escape it here.
		$imgbits['src'] = vB_String::htmlSpecialCharsUni($link);
		if (!empty($size) AND $size != 'full')
		{
			$imgbits['src'] .= '&amp;type=' . $size;
		}

		// This is required for img2 plugin to recognize the image as editable
		$imgbits['class'] = "bbcode-attachment";

		// also replicated for the figure element in addCaption
		// Note, we don't want to double up the classes on BOTH figure & img (or else the plugin JS gets messier),
		// so we check to see if this will be added via caption later.
		if (empty($settings['all']['caption']) AND isset($settings['all']['data-align']))
		{
			switch ($settings['all']['data-align'])
			{
				case 'left':
				case 'center':
				case 'right':
					$imgbits['class'] .= ' align_' . $settings['all']['data-align'];
					break;
				default:
					$imgbits['class'] .= ' thumbnail';	// old behavior. Not sure if our css needs this for non-aligned but non-thumbnail images...
					break;
			}
		}

		if (empty($imgbits['alt']))
		{
			$imgbits['alt'] = "";
		}

		if (!empty($settings['all']['data-linktype']) AND $settings['all']['data-linktype'] == 1)
		{
			$insertHtml = $this->addAnchorAndConvertToHtml($imgbits, $settings, $link, $size, array());
		}
		else
		{
			// "default" or "none". Since this is not an attachment, the default/none should be the same, no anchoring whatsoever.
			$insertHtml = $this->convertImgBitsArrayToHtml($imgbits);
		}
		$insertHtml = $this->addCaption($insertHtml, $settings);

		if (isset($settings['all']['data-align']) && $settings['all']['data-align'] == 'center')
		{
			$insertHtml = "<div class=\"img_align_center_wrapper\">$insertHtml</div>";
		}

		return $insertHtml;
	}

	protected function processAttachBBCode($data)
	{
		$currentUserid = vb::getUserContext()->fetchUserId();

		$attachmentid = false;
		$tempid = false;
		$filedataid = false;

		$phraseApi = vB_Api::instanceInternal('phrase');

		if (!empty($data['data-tempid']) AND strpos($data['data-tempid'], 'temp_') === 0)
		{
			// this attachment hasn't been saved yet (ex. going back & forth between source mode & wysiwyg on a new content)
			if (preg_match('#^temp_(\d+)_(\d+)_(\d+)$#', $data['data-tempid'], $matches))
			{
				// if the id is in the form temp_##_###_###, it's a temporary id that links to hidden inputs that contain
				// the stored settings that will be saved when it becomes a new attachment @ post save.
				$tempid = $matches[0];
				$filedataid = intval($matches[1]);

				if (isset($this->filedatas[$filedataid]) AND !$this->filedatas[$filedataid]['isImage'])
				{
					$result = $phraseApi->render(array('attachment' => 'attachment'));
					// non image. Return as <a >
					$insertHtml = "<a class=\"bbcode-attachment\" href=\"" .
						"filedata/fetch?filedataid=$filedataid\" data-tempid=\"" . $tempid . "\" >"
						. $result['phrases']['attachment']
						. "</a>";
					return $insertHtml;
				}
				else
				{
					// image. Return as <img >
					$settings = $this->processCustomImgConfig($data);
					$size = $this->getNearestImageSize($settings);

					// also replicated for the figure element in addCaption
					// Note, we don't want to double up the classes on BOTH figure & img (or else the plugin JS gets messier),
					// so we check to see if this will be added via caption later.
					$alignClass = '';
					if (empty($settings['all']['caption']) AND isset($settings['all']['data-align']))
					{
						switch ($settings['all']['data-align'])
						{
							case 'left':
							case 'center':
							case 'right':
								$alignClass = ' align_' . $settings['all']['data-align'];
								break;
							default:
								$alignClass = ' thumbnail';	// old behavior. Not sure if our css needs this for non-aligned but non-thumbnail images...
								break;
						}
					}

					$imgbits = array();

					$imgbits = $settings['imgbits'];
					$imgbits['class'] = "bbcode-attachment js-need-data-att-update{$alignClass}";
					$imgbits['border'] = 0;
					$link = "filedata/fetch?filedataid=$filedataid&type=$size";
					$imgbits['src'] = vB_String::htmlSpecialCharsUni($link);

					$insertHtml = $this->convertImgBitsArrayToHtml($imgbits);

					$insertHtml = $this->addCaption($insertHtml, $settings);


					if (isset($settings['all']['data-align']) && $settings['all']['data-align'] == 'center')
					{
						$insertHtml = "<div class=\"img_align_center_wrapper\">$insertHtml</div>";
					}
					return $insertHtml;
				}
			}
		}
		else if (!empty($data['data-attachmentid']) AND is_numeric($data['data-attachmentid']))
		{
			// keep 'data-attachmentid' key in sync with text LIB's replaceAttachBbcodeTempids()
			$attachmentid = $data['data-attachmentid'];
			$filedataid = false;

			if (empty($this->attachments["$attachmentid"]))
			{
				return $data['original_text'];
			}

			$attachment =& $this->attachments["$attachmentid"];
			$filedataid = $attachment['filedataid'];

			// flag this for omit from append_noninline_attachments.
			if ($this->unsetattach)
			{
				$this->skipAttachmentList[$attachmentid] = array(
					'attachmentid' => $attachmentid,
					'filedataid' => $filedataid,
				);
			}


			$settings = $this->processCustomImgConfig($data);

			// todo: match nearest size
			$size = $this->getNearestImageSize($settings);

			// <IMG > OR <A > CHECK
			$isImage = vB_Api::instanceInternal('content_attach')->isImage($attachment['extension'], $size);

			/*
				The only reason we do permission checks here is to make the rendered result look nicer, NOT for
				security.
				If they have no permission to see an image, any image tags will just show a broken image,
				so we show a link with the filename instead.
			*/
			$hasPermission = $this->checkImagePermissions($currentUserid, $attachment['parentid']);

			$useImageTag = ($this->options['do_imgcode'] AND
				$isImage AND
				$hasPermission
			);
			// Special override for 'canseethumbnails'
			if ($useImageTag AND
				!$this->userImagePermissions[$currentUserid][$attachment['parentid']]['cangetimageattachment']
			)
			{
				$size = 'thumb';
			}



			// OUTPUT LOGIC
			$link = 'filedata/fetch?';
			if (!empty($attachment['nodeid']))
			{
				$link .= "id=$attachment[nodeid]";
				$id = 'attachment' . $attachment['nodeid'];
			}
			else
			{
				$link .= "filedataid=$attachment[filedataid]";
				$id = 'filedata' . $attachment['filedataid'];
			}
			if (!empty($attachment['resize_dateline']))
			{
				$link .= "&d=$attachment[resize_dateline]";
			}
			else
			{
				$link .= "&d=$attachment[dateline]";
			}


			// TODO: This doesn't look right to me. I feel like htmlSpecialCharsUni should be outside of the
			// fetch_censored_text call, but don't have time to verify this right now...
			$attachment['filename'] = fetch_censored_text(vB_String::htmlSpecialCharsUni($attachment['filename']));
			if (empty($attachment['extension']))
			{
				$attachment['extension'] = strtolower(file_extension($attachment['filename']));
			}
			$attachment['filesize_humanreadable'] = vb_number_format($attachment['filesize'], 1, true);


			if (!$useImageTag)
			{
				$result = $phraseApi->render(array('title' => array(
					'image_x_y_z',
					$attachment['filename'], // html escaped above.
					intval($attachment['counter']),
					$attachment['filesize_humanreadable']
				)));
				$title = $result['phrases']['title'];

				$filename = $attachment['filename']; // html escaped above.
				// Just display a link.
				$link = vB_String::htmlSpecialCharsUni($link);
				return	"<a href=\"" . $link . "\" title=\"" . $title . "\">$filename</a>";
			}

			/*
				Build up the img tag & caption if necessary
			 */
			$fullsize = false; // Set if $settings['all']['size'] is 'full' or 'fullsize'. Used to bypass anchoring for fullsize images.
			$customLink = false; // If $settings['all']['link'] is 1 and $settings['all']['url'] isn't empty, it becomes an array of data-attributes to set in the img bits
			$imgclass = array();


			//$settings = $this->processCustomImgConfig($data);
			$imgbits = $settings['imgbits'];

			$imgbits['border'] = 0;

			$imgbits['src'] = vB_String::htmlSpecialCharsUni($link);
			if (!empty($size) AND $size != 'full')
			{
				$imgbits['src'] .= '&amp;type=' . $size;
			}

			$imgbits['class'] = "bbcode-attachment";
			// also replicated for the figure element in addCaption
			// Note, we don't want to double up the classes on BOTH figure & img (or else the plugin JS gets messier),
			// so we check to see if this will be added via caption later.
			if (empty($settings['all']['caption']) AND isset($settings['all']['data-align']))
			{
				switch ($settings['all']['data-align'])
				{
					case 'left':
					case 'center':
					case 'right':
						$imgbits['class'] .= ' align_' . $settings['all']['data-align'];
						break;
					default:
						$imgbits['class'] .= ' thumbnail';	// old behavior. Not sure if our css needs this for non-aligned but non-thumbnail images...
						break;
				}
			}

			if (empty($imgbits['alt']))
			{
				$result = $phraseApi->render(array('alt' => array(
					'image_larger_version_x_y_z',
					$attachment['filename'],
					intval($attachment['counter']),
					$attachment['filesize_humanreadable'],
					$attachment['nodeid']
				)));
				$imgbits['alt'] = $result['phrases']['alt'];
			}

			$insertHtml = $this->addAnchorAndConvertToHtml($imgbits, $settings, $link, $size, $attachment);
			$insertHtml = $this->addCaption($insertHtml, $settings);

			if (isset($settings['all']['data-align']) && $settings['all']['data-align'] == 'center')
			{
				return "<div class=\"img_align_center_wrapper\">$insertHtml</div>";
			}
			else
			{
				return $insertHtml;
			}
		}
		else
		{
			// TODO: can legacy attachments come through here...???
			/*
			// it's a legacy attachmentid, get the new id
			if (isset($this->oldAttachments[intval($matches[2])]))
			{
				// key should be nodeid, not filedataid.
				$attachmentid =  $this->oldAttachments[intval($matches[2])]['nodeid'];
				//$showOldImage = $this->oldAttachments[intval($matches[2])]['cangetattachment'];
			}
			*/
		}

		// No data match was found for the attachment, so just let attachReplaceCallback or attachReplaceCallbackFinal deal with this later.
		return $data['original_text'];
	}

	protected function addCaption($insertHtml, $settings)
	{
		if (empty($settings['all']['caption']))
		{
			return $insertHtml;
		}
		else
		{
			$alignClass = '';
			if (isset($settings['all']['data-align']))
			{
				switch ($settings['all']['data-align'])
				{
					case 'left':
					case 'center':
					case 'right':
						$alignClass = ' align_' . $settings['all']['data-align'];
						break;
					default:
						break;
				}
			}

			/*
			'<figure class="{captionedClass}">' +
				template +
				'<figcaption>{captionPlaceholder}</figcaption>' +
			'</figure>
			 */
			return
				"<figure class=\"image bbcode-attachment{$alignClass}\">" .
					$insertHtml .
					"<figcaption>" . $settings['all']['caption'] . "</figcaption>" .	// no XSS here as this is put through htmlentities() in processCustomImgConfig()
				"</figure>";
		}
	}


	protected function convertImgBitsArrayToHtml($imgbits)
	{
		$imgtag = '';
		foreach ($imgbits AS $tag => $value)
		{
			$imgtag .= "$tag=\"$value\" ";
		}
		/*
			note: be careful about adding white space before & after this. In particular, image2's plugin code's isLinkedorStandaloneImage() check
			kind of fails due to expecting <img> being the only child of <a>, and the whitespace creates a text sibling node to <img>.
		 */
		$imgtag = "<img $imgtag/>";

		return $imgtag;
	}

	protected function addAnchorAndConvertToHtml($imgbits, $settings, $link, $size, $attachment)
	{
		$hrefbits = array();
		// link: 0 = default, 1 = url, 2 = none
		if (!empty($settings['all']['data-linktype']))
		{
			if ($settings['all']['data-linktype'] == 2)
			{
				// nothing to do here..
				return $this->convertImgBitsArrayToHtml($imgbits);
			}
			else
			{
				// note, settings['all']['linkurl'] is currently cleaned by processCustomImgConfig
				$settings['all']['data-linkurl'] = $settings['all']['data-linkurl'];
				// custom URL
				$linkinfo = $this->handle_bbcode_url('', $settings['all']['data-linkurl'], true);
				if ($linkinfo['link'] AND $linkinfo['link'] != 'http://')
				{
					$hrefbits['href'] = $linkinfo['link']; // todo: check if handle_bbcode_url html escapes this.

					// linktarget: 0 = self, 1 = new window
					if (!empty($settings['all']['data-linktarget']))
					{
						$hrefbits['target'] = '_blank';
					}

					// below will always occur if it's an external link.
					if ($linkinfo['nofollow'])
					{
						$hrefbits["rel"] = "nofollow";
					}
				}
			}
		}
		else
		{
			$fullsize = ($size == 'fullsize' OR $size == 'full');
			if ($fullsize)
			{
				// Do not link for a full sized image. There's no bigger image to view.
				$hrefbits = array();
			}
			else
			{
				$hrefbits['href'] = vB_String::htmlSpecialCharsUni($link);
				// Use lightbox only if it's not fullsize and one of these extensions
				// Not sure why we have the extension list here. Maybe the plugin only supported
				// certain file types in vB4?


				$lightbox_extensions = array('gif', 'jpg', 'jpeg', 'jpe', 'png', 'bmp');
				$lightbox = in_array(strtolower($attachment['extension']), $lightbox_extensions);
				if ($lightbox)
				{
					/* Lightbox doesn't work in vB5 for non-gallery attachments yet.
					*/
					$hrefbits["rel"] = 'Lightbox_' . $this->containerid;
					// todo: get lightbox working for attachments and figure out the best way to set this class...
					$imgbits["class"] .= ' js-lightbox group-by-parent-' . $attachment['parentid'];
					$hrefbits['target'] = '_blank';
				}
				else
				{
					$hrefbits["rel"] = "nofollow";
				}
			}
		}

		// Something above might've modified imgbits, so we have to do it down here.
		$insertHtml = $this->convertImgBitsArrayToHtml($imgbits);


		if (!empty($hrefbits) AND !empty($hrefbits['href']))
		{
			if (isset($hrefbits['class']))
			{
				$hrefbits['class'] .= " bbcode-attachment";
			}
			else
			{
				$hrefbits['class'] = "bbcode-attachment";
			}
			$anchortag = '';
			foreach ($hrefbits AS $tag => $value)
			{
				$anchortag .= "$tag=\"$value\" ";
			}

			$insertHtml = "<a $anchortag >" . $insertHtml . "</a>";

			return $insertHtml;
		}
		else
		{
			return $insertHtml;
		}
	}

	protected function getNearestImageSize($settings)
	{
		static $attachresizes;
		if (is_null($attachresizes))
		{
			$options = vB::getDatastore()->get_value('options');
			$attachresizes = @unserialize($options['attachresizes']);
			asort($attachresizes); // sort low to high, so we find the nearest largest image.
		}

		if (!empty($settings['all']['data-size']) AND $settings['all']['data-size']  != 'custom')
		{
			return $settings['all']['data-size'];
		}

		$copy = $attachresizes;
		if (isset($settings['all']['width']))
		{
			$width = $settings['all']['width'];
		}
		else
		{
			$width = 0;
		}

		if (isset($settings['all']['height']))
		{
			$height = $settings['all']['height'];
		}
		else
		{
			$height = 0;
		}

		// todo: What size should it be if width & height are empty? ATM not sure if they *can* be empty for image2 inserted attachments.

		foreach (array($width, $height) AS $imagelength)
		{
			foreach ($copy AS $type => $maxallowedlength)
			{
				if (empty($maxallowedlength))
				{
					// 0 == fullsize, we default to it at the end so just unset it.
					unset($copy[$type]);
					continue;
				}

				if ($maxallowedlength < $imagelength)
				{
					unset($copy[$type]);
				}
				else
				{
					break;
				}
			}
		}

		$size = 'full';

		if (!empty($copy))
		{
			reset($copy);
			$size = key($copy);
		}

		return $size;
	}

	protected function processCustomImgConfig($config_array)
	{
		if (!is_array($config_array) OR empty($config_array))
		{
			return array('all' => array(), 'imgbits' => array(), 'html' => '');
		}
		/*
			If $align="config{...}", that's a json_encode'd array of custom settings, set as part of image2 plugin handler
		 */
		// todo: make this a common public arr for this & wysiwyghtmlparser
		// KEEP THIS SYNCED, GREP FOR FOLLOWING IN core/vb/wysiwyghtmlparser.php
		// GREP MARK IMAGE2 ACCEPTED CONFIG
		$accepted_config = array(
			'alt'	                  => vB_Cleaner::TYPE_NOHTML,
			'title'                   => vB_Cleaner::TYPE_NOHTML,
			'data-tempid'             => vB_Cleaner::TYPE_NOHTML,
			'data-attachmentid'       => vB_Cleaner::TYPE_INT,
			'width'                   => vB_Cleaner::TYPE_NUM,
			'height'                  => vB_Cleaner::TYPE_NUM,
			'data-align'              => vB_Cleaner::TYPE_NOHTML,
			'caption'                 => vB_Cleaner::TYPE_NOHTML,
			'data-linktype'           => vB_Cleaner::TYPE_INT, // todo
			'data-linkurl'            => vB_Cleaner::TYPE_NOHTML, // todo. todo2: should this be TYPE_STR & cleaned when inserted into HTML??
			'data-linktarget'         => vB_Cleaner::TYPE_INT, // todo
			'style'                   => vB_Cleaner::TYPE_STR, //todo
			'data-size'               => vB_Cleaner::TYPE_NOHTML,
		);

		$settings = array();
		foreach ($accepted_config AS $name => $info) // $info not yet used. May be used for different types of cleaning, etc
		{
			if(isset($config_array[$name]))
			{
				//$settings[$name] = htmlentities($config_array[$name]);	// default of ENT_COMPAT is OK as we use double quotes as delimiters in caller & belo
				//$settings[$name] = vB_String::htmlSpecialCharsUni($config_array[$name]); // todo: use this instead??
				$settings[$name] = $config_array[$name]; // cleaned by cleaner below. STR types must be cleaned separately!
			}
			else
			{
				// Do not set any defaults via the *cleaner*. If we don't do this, cleaner will add this to the cleaned array if it's not set in the unclean array.
				unset($accepted_config[$name]);
			}
		}

		/*
			We have to clean here instead of at save time because wysiwyg to source and back doesn't work properly since that doesn't
			go through the text api/lib.
			style is uncleaned, as it needs to be raw html, but is unset if the poster lacks the canattachmentcss permission
		 */
		$unclean = $settings;
		$settings = vB::getCleaner()->cleanArray($settings, $accepted_config);

		/*
			Let's do some more checks to make things play nicely.
		 */
		if (empty($settings['width']) OR !is_numeric($settings['width']))
		{
			unset($settings['width']);
		}

		if (empty($settings['height']) OR !is_numeric($settings['height']))
		{
			unset($settings['height']);
		}

		if (isset($settings['data-size']) AND $settings['data-size'] == 'custom')
		{
			unset($settings['data-size']);
		}
		else
		{
			if (!isset($settings['data-size']))
			{
				$settings['data-size'] = null;
			}

			$settings['data-size'] = vB_Api::instanceInternal('filedata')->sanitizeFiletype($settings['data-size']);
		}

		//$settings['debug'] = 'godzilla';


		$not_part_of_img_tag = array(
			'caption' => true,
			//'data-linktype' => true, // todo
			//'data-linkurl' => true, // todo
			//'data-linktarget' => true, // todo
		);
		$imgtag = '';
		$imgbits = array();
		foreach ($settings AS $tag => $value)
		{
			if (!isset($not_part_of_img_tag[$tag]))
			{
				$imgtag .= "$tag=\"$value\" ";
				$imgbits[$tag] = $value;
			}
		}

		return array('all' => $settings, 'imgbits' => $imgbits, 'html' => $imgtag);
	}

	/**
	* Handles an [img] tag.
	*
	* @param	string	The text to search for an image in.
	* @param	string	Whether to parse matching images into pictures or just links.
	*
	* @return	string	HTML representation of the tag.
	*/
	function handle_bbcode_img($bbcode, $do_imgcode, $has_img_code = false, $fulltext = '')
	{
		global $vbphrase;
		$sessionurl = vB::getCurrentSession()->get('sessionurl');
		/* Do search on $fulltext, which would be the entire article, not just a page of the article which would be in $page */
		if (!$fulltext)
		{
			$fulltext = $bbcode;
		}

		if (($has_img_code & BBCODE_HAS_ATTACH) AND preg_match_all('#\[attach(?:=(right|left|config))?\](\d+)\[/attach\]#i', $fulltext, $matches))
		{
			// This forumid check needs to be moved out to an extended thread class...
			if ($this->forumid && $this->forumid != "blog_entry")
			{
				$forumperms = fetch_permissions($this->forumid);
				$cangetattachment = ($forumperms & $this->registry->bf_ugp_forumpermissions['cangetattachment']);
				$canseethumbnails = ($forumperms & $this->registry->bf_ugp_forumpermissions['canseethumbnails']);
			}
			else
			{
				$cangetattachment = true;
				$canseethumbnails = true;
			}

			foreach($matches[2] AS $key => $attachmentid)
			{
				$align = $matches[1]["$key"];
				$search[] = '#\[attach' . (!empty($align) ? '=' . $align : '') . '\](' . $attachmentid . ')\[/attach\]#i';

				// attachment specified by [attach] tag belongs to this post
				if (!empty($this->attachments["$attachmentid"]))
				{
					$attachment =& $this->attachments["$attachmentid"];
					if (!empty($attachment['settings']) AND strtolower($align) == 'config')
					{
						$settings = unserialize($attachment['settings']);
					}
					else
					{
						$settings = '';
					}

					if ($attachment['state'] != 'visible' AND $attachment['userid'] != $this->registry->userinfo['userid'])
					{	// Don't show inline unless the poster is viewing the post (post preview)
						continue;
					}

					if ($cangetattachment AND $canseethumbnails AND $attachment['thumbnail_filesize'] == $attachment['filesize'])
					{
						$attachment['hasthumbnail'] = false;
						$forceimage = $this->registry->options['viewattachedimages'];
					}
					else if (!$canseethumbnails)
					{
						$attachment['hasthumbnail'] = false;
					}

					$attachment['filename'] = fetch_censored_text(htmlspecialchars_uni($attachment['filename']));
					$attachment['extension'] = strtolower(file_extension($attachment['filename']));
					$attachment['filesize'] = vb_number_format($attachment['filesize'], 1, true);

					$lightbox_extensions = array('gif', 'jpg', 'jpeg', 'jpe', 'png', 'bmp');

					switch($attachment['extension'])
					{
						case 'gif':
						case 'jpg':
						case 'jpeg':
						case 'jpe':
						case 'png':
						case 'bmp':
						case 'tiff':
						case 'tif':
						case 'psd':
						case 'pdf':
							$imgclass = array();
							$fullsize = false;
							$alt_text = $title_text = $caption_tag = $styles = '';
							if ($settings)
							{
								if ($settings['alignment'])
								{
									switch ($settings['alignment'])
									{
										case 'left':
											$imgclass[] = 'align_left';
											break;
										case 'center':
											$imgclass[] = 'align_center';
											break;
										case 'right':
											$imgclass[] = 'align_right';
											break;
									}
								}
								if ($settings['size'])
								{
									if (isset($settings['size']))
									{
										switch ($settings['size'])
										{
											case 'thumbnail':
												$imgclass[] = 'size_thumbnail';
												break;
											case 'medium':
												$imgclass[] = 'size_medium';
												break;
											case 'large':
												$imgclass[] = 'size_large';
												break;
											case 'fullsize':
												$fullsize = true;
												break;
										}
									}
								}
								if ($settings['caption'])
								{
									$caption_tag = "<p class=\"caption $size_class\">$settings[caption]</p>";
								}
								$alt_text = $settings['title'];
								$description_text = $settings['description'];
								$title_text = $settings['title'];
								$styles = $settings['styles'];
							}

							if (($settings OR ($this->registry->options['viewattachedimages'] == 1 AND $attachment['hasthumbnail'])) AND $this->registry->userinfo['showimages'])
							{
								$lightbox = (!$fullsize AND $cangetattachment AND in_array($attachment['extension'], $lightbox_extensions));
								$hrefbits = array(
									'href'   => "attachment.php?{$sessionurl}attachmentid=\\1&amp;d=$attachment[dateline]",
									'id'     => 'attachment\\1',
								);
								if ($lightbox)
								{
									$hrefbits["rel"] = 'Lightbox_' . $this->containerid;
								}
								else
								{
									$hrefbits["rel"] = "nofollow";
								}
								if ($addnewwindow)
								{
									$hrefbits['target'] = '_blank';
								}
								$atag = '';
								foreach ($hrefbits AS $tag => $value)
								{
									$atag .= "$tag=\"$value\" ";
								}

								$imgbits = array(
									'src'    => "attachment.php?{$sessionurl}attachmentid=\\1&amp;d=$attachment[thumbnail_dateline]",
									'border' => '0',
									'alt'    => $alt_text ? $alt_text : construct_phrase($vbphrase['image_larger_version_x_y_z'], $attachment['filename'], $attachment['counter'], $attachment['filesize'], $attachment['attachmentid'])
								);

								if (!$settings AND !$this->displayimage)
								{
									$imgbits['src'] .= '&amp;thumb=1';
								}

								if (!empty($imgclass))
								{
									$imgbits['class'] = implode(' ', $imgclass);
								}
								else
								{
									$imgbits['class'] = 'thumbnail';
								}
								if ($title_text)
								{
									$imgbits['title'] = $title_text;
								}
								else if ($description_text)
								{
									$imgbits['title'] = $description_text;
								}

								if ($description_text)
								{
									$imgbits['description'] = $description_text;
								}

								if ($styles)
								{
									$imgbits['style'] = $styles;
								}
								else if (!$settings AND $align AND $align != 'config')
								{
									$imgbits['style'] = "float:$align";
								}
								$imgtag = '';
								foreach ($imgbits AS $tag => $value)
								{
									$imgtag .= "$tag=\"$value\" ";
								}

								if ($fullsize)
								{
									$replace[] = "<img $imgtag/>";
								}
								else
								{
									if (isset($settings['alignment']) && $settings['alignment'] == 'center')
									{
										$replace[] = "<div class=\"img_align_center  img_align_center_wrapper\">"
											. "<a $atag><img $imgtag/></a>"
											. "</div>";
									}
									else
									{
										$replace[] = "<a $atag><img $imgtag/></a>";
									}
								}

							}
							else if ($this->registry->userinfo['showimages'] AND ($forceimage OR $this->registry->options['viewattachedimages'] == 3) AND !in_array($attachment['extension'], array('tiff', 'tif', 'psd', 'pdf')))
							{	// Display the attachment with no link to bigger image
								$replace[] = "<img src=\"attachment.php?{$sessionurl}attachmentid=\\1&amp;d=$attachment[dateline]\" border=\"0\" alt=\""
								. construct_phrase($vbphrase['image_x_y_z'], $attachment['filename'], $attachment['counter'], $attachment['filesize'])
								. "\" " . (!empty($align) ? " style=\"float: $align\"" : '') . " />";
							}
							else
							{	// Display a link
								$replace[] = "<a href=\"attachment.php?{$sessionurl}attachmentid=\\1&amp;d=$attachment[dateline]\" $addtarget title=\""
								. construct_phrase($vbphrase['image_x_y_z'], $attachment['filename'], $attachment['counter'], $attachment['filesize'])
									. "\">$attachment[filename]</a>";
							}
							break;
						default:
							$replace[] = "<a href=\"attachment.php?{$sessionurl}attachmentid=\\1&amp;d=$attachment[dateline]\" $addtarget title=\""
							. construct_phrase($vbphrase['image_x_y_z'], $attachment['filename'], $attachment['counter'], $attachment['filesize'])
								. "\">$attachment[filename]</a>";
					}
				}
				else
				{	// Belongs to another post so we know nothing about it ... or we are not displying images so always show a link
					$replace[] = "<a href=\"attachment.php?{$sessionurl}attachmentid=\\1\" \">$vbphrase[attachment] \\1</a>";
				}


				// remove attachment from array
				if ($this->unsetattach)
				{
					unset($this->attachments["$attachmentid"]);
				}
			}

			$bbcode = preg_replace($search, $replace, $bbcode);
		}

		if ($has_img_code & BBCODE_HAS_IMG)
		{
			if ($do_imgcode AND ($this->registry->userinfo['userid'] == 0 OR $this->registry->userinfo['showimages']))
			{
				// do [img]xxx[/img]
				$bbcode = preg_replace_callback('#\[img\]\s*(https?://([^*\r\n]+|[a-z0-9/\\._\- !]+))\[/img\]#iU', array($this, 'handleBbcodeImgMatchCallback'), $bbcode);
			}
			else
			{
				$bbcode = preg_replace_callback('#\[img\]\s*(https?://([^*\r\n]+|[a-z0-9/\\._\- !]+))\[/img\]#iU', array($this, 'handleBbcodeUrlCallback'), $bbcode);
			}
		}

		if ($has_img_code & BBCODE_HAS_SIGPIC)
		{
			$bbcode = preg_replace_callback('#\[sigpic\](.*)\[/sigpic\]#siU',
				array($this, 'handleBBCodeSigPicCallback'), $bbcode);
		}

		if ($has_img_code & BBCODE_HAS_RELPATH)
		{
			$bbcode = str_replace('[relpath][/relpath]', htmlspecialchars_uni($this->registry->input->fetch_relpath()), $bbcode);
		}

		return $bbcode;
	}

	/**
	 * Callback for preg_replace_callback in handle_bbcode_img
	 */
	protected function handleBbcodeImgMatchCallback($matches)
	{
		return $this->handle_bbcode_img_match($matches[1]);
	}

	/**
	 * Callback for preg_replace_callback in handle_bbcode_img
	 */
	protected function handleBbcodeUrlCallback($matches)
	{
		return $this->handle_bbcode_url($matches[1], '');
	}

	/**
	 * Callback for preg_replace_callback in handle_bbcode_img
	 */
	protected function handleBBCodeSigPicCallback($matches)
	{
		return $this->handle_bbcode_sigpic($matches[1]);
	}

	/**
	* Handles a match of the [img] tag that will be displayed as an actual image.
	*
	* @param	string	The URL to the image.
	*
	* @return	string	HTML representation of the tag.
	*/
	function handle_bbcode_img_match($link, $fullsize = false)
	{
		$link = $this->strip_smilies(str_replace('\\"', '"', $link));
		// remove double spaces -- fixes issues with wordwrap
		$link = str_replace(array('  ', '"'), '', $link);

		return  '<img src="' .  $link . '" border="0" alt="" />';
	}

	/**
	* Handles the parsing of a signature picture. Most of this is handled
	* based on the $parse_userinfo member.
	*
	* @param	string	Description for the sig pic
	*
	* @return	string	HTML representation of the sig pic
	*/
	function handle_bbcode_sigpic($description)
	{
		// remove unnecessary line breaks and escaped quotes
		$description = str_replace(array('<br>', '<br />', '\\"'), array('', '', '"'), $description);

		if (empty($this->parse_userinfo['userid']) OR empty($this->parse_userinfo['sigpic']) OR (!vB::getUserContext($this->parse_userinfo['userid'])->hasPermission('signaturepermissions', 'cansigpic')))
		{
			// unknown user or no sigpic
			return '';
		}

		$sigpic_url = 'filedata/fetch?filedataid=' . $this->parse_userinfo['sigpic']['filedataid'] . '&amp;sigpic=1';

		$description = str_replace(array('\\"', '"'), '', trim($description));

		$currentUser = vB::getCurrentSession()->fetch_userinfo();
		if ($currentUser['userid'] == 0 OR $currentUser['showimages'])
		{
			return "<img src=\"$sigpic_url\" alt=\"$description\" border=\"0\" />";
		}
		else
		{
			if (!$description)
			{
				$description = $sigpic_url;
				if (vbstrlen($description) > 55 AND $this->is_wysiwyg() == false)
				{
					$description = substr($description, 0, 36) . '...' . substr($description, -14);
				}
			}
			return "<a href=\"$sigpic_url\">$description</a>";
		}
	}

	/**
	* Handles a [size] tag
	*
	* @param	string	The text to size.
	* @param	string	The size to size to
	*
	* @return	string	HTML representation of the tag.
	*/
	function handle_bbcode_size($text, $size)
	{
		$newsize = 0;
		if (preg_match('#^[1-7]$#si', $size, $matches))
		{
			switch ($size)
			{
				case 1:
					$newsize = '8px';
					break;
				case 2:
					$newsize = '10px';
					break;
				case 3:
					$newsize = '12px';
					break;
				case 4:
					$newsize = '20px';
					break;
				case 5:
					$newsize = '28px';
					break;
				case 6:
					$newsize = '48px';
					break;
				case 7:
					$newsize = '72px';
			}

			return "<span style=\"font-size:$newsize\">$text</span>";
		}
		else if (preg_match('#^([8-9]|([1-6][0-9])|(7[0-2]))px$#si', $size, $matches))
		{
			$newsize = $size;
		}

		if ($newsize)
		{
			return "<span style=\"font-size:$newsize\">$text</span>";
		}
		else
		{
			return $text;
		}
	}

	/**
	* Parses the [table] tag and returns the necessary HTML representation.
	* TRs and TDs are parsed by this function (they are not real BB codes).
	* Classes are pushed down to inner tags (TRs and TDs) and TRs are automatically
	* valigned top.
	*
	* @param	string	Content within the table tag
	* @param	string	Optional set of parameters in an unparsed format. Parses "param: value, param: value" form.
	*
	* @return	string	HTML representation of the table and its contents.
	*/
	function parseTableTag($content, $params = '')
	{
		$helper = new vBForum_BBCodeHelper_Table($this);
		return $helper->parseTableTag($content, $params);
	}


	/**
	* Removes the specified amount of line breaks from the front and/or back
	* of the input string. Includes HTML line braeks.
	*
	* @param	string	Text to remove white space from
	* @param	int		Amount of breaks to remove
	* @param	bool	Whether to strip from the front of the string
	* @param	bool	Whether to strip from the back of the string
	*/
	function strip_front_back_whitespace($text, $max_amount = 1, $strip_front = true, $strip_back = true)
	{
		$max_amount = intval($max_amount);

		if ($strip_front)
		{
			$text = preg_replace('#^(( |\t)*((<br>|<br />)[\r\n]*)|\r\n|\n|\r){0,' . $max_amount . '}#si', '', $text);
		}

		if ($strip_back)
		{
			// The original regex to do this: #(<br>|<br />|\r\n|\n|\r){0,' . $max_amount . '}$#si
			// is slow because the regex engine searches for all breaks and fails except when it's at the end.
			// This uses ^ as an optimization by reversing the string. Note that the strings in the regex
			// have been reversed too! strrev(<br />) == >/ rb<
			$text = strrev(preg_replace('#^(((>rb<|>/ rb<)[\n\r]*)|\n\r|\n|\r){0,' . $max_amount . '}#si', '', strrev(rtrim($text))));
		}

		return $text;
	}

	/**
	* Removes translated smilies from a string.
	*
	* @param	string	Text to search
	*
	* @return	string	Text with smilie HTML returned to smilie codes
	*/
	function strip_smilies($text)
	{
		$cache =& $this->cache_smilies(false);

		// 'replace' refers to the <img> tag, so we want to remove that
		return str_replace($cache, array_keys($cache), $text);
	}

	/**
	* Determines whether a string contains an [img] tag.
	*
	* @param	string	Text to search
	*
	* @return	bool	Whether the text contains an [img] tag
	*/
	function contains_bbcode_img_tags($text)
	{
		// use a bitfield system to look for img, attach, and sigpic tags

		$hasimage = 0;
		if (stripos($text, '[/img]') !== false)
		{
			$hasimage += BBCODE_HAS_IMG;
		}

		if (stripos($text, '[/attach]') !== false)
		{
			$hasimage += BBCODE_HAS_ATTACH;
		}

		if (stripos($text, '[/sigpic]') !== false)
		{
			if (!empty($this->parse_userinfo['userid'])
				AND !empty($this->parse_userinfo['sigpic'])
				AND (vB::getUserContext($this->parse_userinfo['userid'])->hasPermission('signaturepermissions', 'cansigpic'))
			)
			{
				$hasimage += BBCODE_HAS_SIGPIC;
			}
		}

		if (stripos($text, '[/relpath]') !== false)
		{
			$hasimage += BBCODE_HAS_RELPATH;
		}

		return $hasimage;
		//return preg_match('#(\[img\]|\[/attach\])#i', $text);
		//return (stripos($text, '[img]') !== false OR stripos($text, '[/attach]') !== false) ? true : false;
		//return preg_match('#\[img\]#i', $text);
		//return iif(strpos(strtolower($bbcode), '[img') !== false, 1, 0);
	}

	/**
	* Returns the height of a block of text in pixels (assuming 16px per line).
	* Limited by your "codemaxlines" setting (if > 0).
	*
	* @param	string	Block of text to find the height of
	*
	* @return	int		Number of lines
	*/
	function fetch_block_height($code)
	{

		// establish a reasonable number for the line count in the code block
		$numlines = max(substr_count($code, "\n"), substr_count($code, "<br />")) + 1;

		// set a maximum number of lines...
		if ($numlines > $this->registry->options['codemaxlines'] AND $this->registry->options['codemaxlines'] > 0)
		{
			$numlines = $this->registry->options['codemaxlines'];
		}
		else if ($numlines < 1)
		{
			$numlines = 1;
		}

		// return height in pixels
		return ($numlines); // removed multiplier
	}

	/**
	* Fetches the colors used to highlight HTML in an [html] tag.
	*
	* @return	array	array of type (key) to color (value)
	*/
	function fetch_bbcode_html_colors()
	{
		return array(
			'attribs'	=> '#0000FF',
			'table'		=> '#008080',
			'form'		=> '#FF8000',
			'script'	=> '#800000',
			'style'		=> '#800080',
			'a'			=> '#008000',
			'img'		=> '#800080',
			'if'		=> '#FF0000',
			'default'	=> '#000080'
		);
	}

	/**
	* Returns whether this parser is a WYSIWYG parser. Useful to change
	* behavior slightly for a WYSIWYG parser without rewriting code.
	*
	* @return	bool	True if it is; false otherwise
	*/
	function is_wysiwyg()
	{
		return false;
	}

	/**
	 * Chops a set of (fixed) BB code tokens to a specified length or slightly over.
	 * It will search for the first whitespace after the snippet length.
	 *
	 * @param	array	Fixed tokens
	 * @param	integer	Length of the text before parsing (optional)
	 *
	 * @return	array	Tokens, chopped to the right length.
	 */
	function make_snippet($tokens, $initial_length = 0)
	{
		// no snippet to make, or our original text was short enough
		if ($this->snippet_length == 0 OR ($initial_length AND $initial_length < $this->snippet_length))
		{
			$this->createdsnippet = false;
			return $tokens;
}

		$counter = 0;
		$stack = array();
		$new = array();
		$over_threshold = false;

		foreach ($tokens AS $tokenid => $token)
		{
			// only count the length of text entries
			if ($token['type'] == 'text')
			{
				$length = vbstrlen($token['data']);

				// uninterruptable means that we will always show until this tag is closed
				$uninterruptable = (isset($stack[0]) AND isset($this->uninterruptable["$stack[0]"]));

				if ($counter + $length < $this->snippet_length OR $uninterruptable)
				{
					// this entry doesn't push us over the threshold
					$new["$tokenid"] = $token;
					$counter += $length;
				}
				else
				{
					// a text entry that pushes us over the threshold
					$over_threshold = true;
					$last_char_pos = $this->snippet_length - $counter - 1; // this is the threshold char; -1 means look for a space at it
					if ($last_char_pos < 0)
					{
						$last_char_pos = 0;
					}

					if (preg_match('#\s#s', $token['data'], $match, PREG_OFFSET_CAPTURE, $last_char_pos))
					{
						$token['data'] = substr($token['data'], 0, $match[0][1]); // chop to offset of whitespace
						if (substr($token['data'], -3) == '<br')
						{
							// we cut off a <br /> code, so just take this out
							$token['data'] = substr($token['data'], 0, -3);
						}

						$new["$tokenid"] = $token;
					}
					else
					{
						$new["$tokenid"] = $token;
					}

					break;
				}
			}
			else
			{
				// not a text entry
				if ($token['type'] == 'tag')
				{
					// build a stack of open tags
					if ($token['closing'] == true)
					{
						// by now, we know the stack is sane, so just remove the first entry
						array_shift($stack);
					}
					else
					{
						array_unshift($stack, $token['name']);
					}
				}

				$new["$tokenid"] = $token;
			}
		}

		// since we may have cut the text, close any tags that we left open
		foreach ($stack AS $tag_name)
		{
			$new[] = array('type' => 'tag', 'name' => $tag_name, 'closing' => true);
		}

		$this->createdsnippet = (sizeof($new) != sizeof($tokens) OR $over_threshold); // we did something, so we made a snippet

		return $new;
	}

	/** Sets the template to be used for generating quotes
	*
	* @param	string	the template name
	***/
	public function set_quote_template($template_name)
	{
		$this->quote_template = $template_name;
	}

	/** Sets the template to be used for generating quotes
	 *
	 * @param	string	the template name
	 ***/
	public function set_quote_printable_template($template_name)
	{
		$this->quote_printable_template = $template_name;
	}

	/** Sets variables to be passed to the quote template
	 *
	 * @param	string	the template name
	 ***/
	public function set_quote_vars($var_array)
	{
		$this->quote_vars = $var_array;
	}

/**
 * This is copied from the blog bbcode parser. We either have a specific
 * amount of text, or [PRBREAK][/PRBREAK].
 *
 * @param	string	text to parse
 * @param	integer	Length of the text before parsing (optional)
 * @param	boolean Flag to indicate whether do html or not
 * @param	boolean Flag to indicate whether to convert new lines to <br /> or not
 * @param	string	Defines how to handle html while parsing.
 * @param	array	Extra options for parsing.
 * 					'do_smilies' => boolean used to handle the smilies display
 *
 * @return	array	Tokens, chopped to the right length.
 */
	public function getPreview($pagetext, $initial_length = 0, $do_html = false, $do_nl2br = true, $htmlstate = null, $options = array())
	{
		if ($htmlstate)
		{
			switch ($htmlstate)
			{
				case 'on':
					$do_nl2br = false;
					break;
				case 'off':
					$do_html = false;
					break;
				case 'on_nl2br':
					$do_nl2br = true;
					break;
			}
		}

		$do_smilies = isset($options['do_smilies']) ? ((bool) $options['do_smilies']) : true;
		$this->options = array(
			'do_html'    => $do_html,
			'do_smilies' => $do_smilies,
			'do_bbcode'  => true,
			'do_imgcode' => false,
			'do_nl2br'   => $do_nl2br,
			'cachable'   => true
		);

		if (!$do_html)
		{
			$pagetext = vB_String::htmlSpecialCharsUni($pagetext);
		}

		$pagetext = $this->parse_whitespace_newlines(trim(strip_quotes($pagetext)), $do_nl2br);
		$tokens = $this->fix_tags($this->build_parse_array($pagetext));

		$counter = 0;
		$stack = array();
		$new = array();
		$over_threshold = false;

		if (!empty($options['allowPRBREAK']) AND strpos($pagetext, '[PRBREAK][/PRBREAK]'))
		{
			$this->snippet_length = strlen($pagetext);
		}
		else if (intval($initial_length))
		{
			$this->snippet_length = $initial_length;
		}
		else
		{
			if (empty($this->default_previewlen))
			{
				$this->default_previewlen = vB::getDatastore()->getOption('previewLength');

				if (empty($this->default_previewlen))
				{
					$this->default_previewlen = 200;
				}
			}
			$this->snippet_length = $this->default_previewlen;
		}

		$noparse = false;
		$video = false;
		$in_page = false;

		foreach ($tokens AS $tokenid => $token)
		{
			if (!empty($token['name']) AND ($token['name'] == 'noparse') AND $do_html)
			{
				//can't parse this. We don't know what's inside.
				$new[] = $token;
				$noparse = ! $noparse;

			}
			else if (!empty($token['name']) AND $token['name'] == 'video')
			{
				$video = !$token['closing'];
				continue;

			}
			else if (!empty($token['name']) AND $token['name'] == 'page')
			{
				$in_page = !$token['closing'];
				continue;

			}
			else if ($video OR $in_page)
			{
				continue;
			}
			// only count the length of text entries
			else if ($token['type'] == 'text')
			{
				if ($over_threshold)
				{
					continue;
				}
				if (!$noparse)
				{
					//If this has [ATTACH] or [IMG] or VIDEO then we nuke it.
					$pagetext =preg_replace('#\[ATTACH.*?\[/ATTACH\]#si', '', $token['data']);
					$pagetext = preg_replace('#\[IMG.*?\[/IMG\]#si', '', $pagetext);
					$pagetext = preg_replace('#\[video.*?\[/video\]#si', '', $pagetext);
					if ($pagetext == '')
					{
						continue;
					}

					if ($trim = stripos($pagetext, '[PRBREAK][/PRBREAK]'))
					{
						$pagetext = substr($pagetext, 0, $trim);
						$over_threshold = true;
					}
					$token['data'] = $pagetext;
				}
				$length = vB_String::vbStrlen($token['data']);

				// uninterruptable means that we will always show until this tag is closed
				$uninterruptable = (isset($stack[0]) AND isset($this->uninterruptable["$stack[0]"]));

				if ((($counter + $length) < $this->snippet_length ) OR $uninterruptable OR $noparse)
				{
					// this entry doesn't push us over the threshold
					$new[] = $token;
					$counter += $length;
				}
				else
				{
					// a text entry that pushes us over the threshold
					$over_threshold = true;
					$last_char_pos = $this->snippet_length - $counter - 1; // this is the threshold char; -1 means look for a space at it
					if ($last_char_pos < 0)
					{
						$last_char_pos = 0;
					}

					if (preg_match('#\s#s', $token['data'], $match, PREG_OFFSET_CAPTURE, $last_char_pos))
					{
						if ($do_html)
						{
							$token['data'] = strip_tags($token['data']);
						}
						$token['data'] = substr($token['data'], 0, $match[0][1]); // chop to offset of whitespace
						if (substr($token['data'], -3) == '<br')
						{
							// we cut off a <br /> code, so just take this out
							$token['data'] = substr($token['data'], 0, -3);
						}

						$new[] = $token;
					}
					else	// no white space found .. chop in the middle
					{
						if ($do_html)
						{
							$token['data'] = strip_tags($token['data']);
						}
						$token['data'] = substr($token['data'], 0, $last_char_pos);
						if (substr($token['data'], -3) == '<br')
						{
							// we cut off a <br /> code, so just take this out
							$token['data'] = substr($token['data'], 0, -3);
						}
						$new[] = $token;
					}
					break;
				}
			}
			else
			{
				// not a text entry
				if ($token['type'] == 'tag')
				{
					//If we have a prbreak we are done.
					if (($token['name'] == 'prbreak') AND isset($tokens[intval($tokenid) + 1])
						AND ($tokens[intval($tokenid) + 1]['name'] == 'prbreak')
						AND ($tokens[intval($tokenid) + 1]['closing']))
					{
						$over_threshold == true;
						break;
					}
					// build a stack of open tags
					if ($token['closing'] == true)
					{
						// by now, we know the stack is sane, so just remove the first entry
						array_shift($stack);
					}
					else
					{
						array_unshift($stack, $token['name']);
					}
				}

				$new[] = $token;
			}
		}
		// since we may have cut the text, close any tags that we left open
		foreach ($stack AS $tag_name)
		{
			$new[] = array('type' => 'tag', 'name' => $tag_name, 'closing' => true);
		}

		$this->createdsnippet = (sizeof($new) != sizeof($tokens) OR $over_threshold); // we did something, so we made a snippet
		$result = $this->parse_array($new, $do_smilies, true, $do_html);
		return $result;
	}
/**
 * Used for any tag we ignore. At the time of this, writing that means PRBREAK and PAGE. Both are cms-only and handled outside the parser.
 *
 * @param	string	Page title
 *
 * @return	string	Output of the page header in multi page views, nothing in single page views
 */
	protected function parseDiscard($text)
	{
		return '';
	}

	/**
	* Returns true of provided $currentUserid has either cangetimageattachment or
	* canseethumbnails permission for the provided $parentid of the attachment.
	* Also stores the already checked permissions in the userImagePermissions
	* class variable.
	*
	* @param	int	$currentUserid
	* @param	int	$parentid	Parent of attachment, usually the "content" post (starter/reply)
	* @return	bool
	*/
	protected function checkImagePermissions($currentUserid, $parentid)
	{
		/*
			The only reason we do permission checks here is to make the rendered result look nicer, NOT for
			security.
			If they have no permission to see an image, any image tags will just show a broken image,
			so we show a link with the filename instead.
		*/
		if (!isset($this->userImagePermissions[$currentUserid][$parentid]['cangetimageattachment']))
		{
			$canDownloadImages = vB::getUserContext($currentUserid)->getChannelPermission('forumpermissions2', 'cangetimgattachment', $parentid);
			$this->userImagePermissions[$currentUserid][$parentid]['cangetimageattachment'] = $canDownloadImages;
		}
		if (!isset($this->userImagePermissions[$currentUserid][$parentid]['canseethumbnails']))
		{
			// Currently there's something wrong with checking 'canseethumbnails' permission.
			// This permission is only editable via usergroup manager, and thus seems to set
			// the permission at the root level, but seems to check it at the specific channel
			// level in the user/permission context.
			$canSeeThumbs = vB::getUserContext($currentUserid)->getChannelPermission('forumpermissions', 'canseethumbnails', $parentid);
			$this->userImagePermissions[$currentUserid][$parentid]['canseethumbnails'] = $canSeeThumbs;
		}


		$hasPermission = (
			$this->userImagePermissions[$currentUserid][$parentid]['cangetimageattachment'] OR
			$this->userImagePermissions[$currentUserid][$parentid]['canseethumbnails']
		);

		return $hasPermission;
	}
}

// ####################################################################

if (!function_exists('stripos'))
{
	/**
	* Case-insensitive version of strpos(). Defined if it does not exist.
	*
	* @param	string		Text to search for
	* @param	string		Text to search in
	* @param	int			Position to start search at
	*
	* @param	int|false	Position of text if found, false otherwise
	*/
	function stripos($haystack, $needle, $offset = 0)
	{
		$foundstring = stristr(substr($haystack, $offset), $needle);
		return $foundstring === false ? false : strlen($haystack) - strlen($foundstring);
	}
}

/**
* Grabs the list of default BB code tags.
*
* @param	string	Allows an optional path/URL to prepend to thread/post tags
* @param	boolean	Force all BB codes to be returned?
*
* @return	array	Array of BB code tags
*/
function fetch_tag_list($prepend_path = '', $force_all = false)
{
	return vB_Api::instanceInternal('bbcode')->fetchTagList($prepend_path, $force_all);
	// TODO: remove the following code or the whole function and replace with reference to api method

	global $vbulletin, $vbphrase;
	static $tag_list;

	if ($force_all)
	{
		$tag_list_bak = $tag_list;
		$tag_list = array();
	}

	if (empty($tag_list))
	{
		//set up some variable for later on to take into account the optional vbforum_url
		//we don't use the seo urls here because they don't play nice with the bbcode
		//processing.
		//
		//forum_path is the prefix for the forum based urls.  If provided we use it as the base.
		//if it is not an absolute url we also use the prepend_path (which is, itself, used to
		//make the url's absolute where needed).
		//forum_path_full is the same, however its always made absolute using the bburl when
		//it is not an absolute url.  This follows existing usage except for inserting the vbforum_url

		$forum_path = $prepend_path;
		$forum_path_full =  rtrim($vbulletin->options['bburl'], '/') . '/';

		$tag_list = array();

		// [QUOTE]
		$tag_list['no_option']['quote'] = array(
			'callback'          => 'handle_bbcode_quote',
			'strip_empty'       => true,
			'strip_space_after' => 2
		);

		// [QUOTE=XXX]
		$tag_list['option']['quote'] = array(
			'callback'          => 'handle_bbcode_quote',
			'strip_empty'       => true,
			'strip_space_after' => 2,
		);

		// [HIGHLIGHT]
		$tag_list['no_option']['highlight'] = array(
			'html'        => '<span class="highlight">%1$s</span>',
			'strip_empty' => true
		);

		// [NOPARSE]-- doesn't need a callback, just some flags
		$tag_list['no_option']['noparse'] = array(
			'html'            => '%1$s',
			'strip_empty'     => true,
			'stop_parse'      => true,
			'disable_smilies' => true
		);

		// [VIDEO]
		$tag_list['option']['video'] = array(
			'callback' => 'handle_bbcode_video',
			'strip_empty'     => true,
			'disable_smilies' => true,
		);

		$tag_list['no_option']['video'] = array(
			'callback'    => 'handle_bbcode_url',
			'strip_empty' => true
		);

		$tag_list['no_option']['prbreak'] = array(
			'callback'    => 'parseDiscard',
			'strip_empty' => true
		);

		if (($vbulletin->options['allowedbbcodes'] & ALLOW_BBCODE_BASIC) OR $force_all)
		{
			// [B]
			$tag_list['no_option']['b'] = array(
				'html'        => '<b>%1$s</b>',
				'strip_empty' => true
			);

			// [I]
			$tag_list['no_option']['i'] = array(
				'html'        => '<i>%1$s</i>',
				'strip_empty' => true
			);

			// [U]
			$tag_list['no_option']['u'] = array(
				'html'        => '<u>%1$s</u>',
				'strip_empty' => true
			);
		}

		if (($vbulletin->options['allowedbbcodes'] & ALLOW_BBCODE_COLOR) OR $force_all)
		{
			// [COLOR=XXX]
			$tag_list['option']['color'] = array(
				'html'         => '<span style="color:%2$s">%1$s</span>',
				'option_regex' => '#^\#?\w+$#',
				'strip_empty'  => true
			);
		}

		if (($vbulletin->options['allowedbbcodes'] & ALLOW_BBCODE_SIZE) OR $force_all)
		{
			// [SIZE=XXX]
			$tag_list['option']['size'] = array(
				'callback'    => 'handle_bbcode_size',
				'strip_empty'  => true
			);
		}

		if (($vbulletin->options['allowedbbcodes'] & ALLOW_BBCODE_FONT) OR $force_all)
		{
			// [FONT=XXX]
			$tag_list['option']['font'] = array(
				'html'         => '<span style="font-family:%2$s">%1$s</span>',
				'option_regex' => '#^[^["`\':]+$#',
				'strip_empty'  => true
			);
		}

		if (($vbulletin->options['allowedbbcodes'] & ALLOW_BBCODE_ALIGN) OR $force_all)
		{
			// [LEFT]
			$tag_list['no_option']['left'] = array(
				'html'              => '<div align="left">%1$s</div>',
				'strip_empty'       => true,
				'strip_space_after' => 1
			);

			// [CENTER]
			$tag_list['no_option']['center'] = array(
				'html'              => '<div align="center">%1$s</div>',
				'strip_empty'       => true,
				'strip_space_after' => 1
			);

			// [RIGHT]
			$tag_list['no_option']['right'] = array(
				'html'              => '<div align="right">%1$s</div>',
				'strip_empty'       => true,
				'strip_space_after' => 1
			);

			// [INDENT]
			$tag_list['no_option']['indent'] = array(
				'html'              => '<blockquote>%1$s</blockquote>',
				'strip_empty'       => true,
				'strip_space_after' => 1
			);
		}

		if (($vbulletin->options['allowedbbcodes'] & ALLOW_BBCODE_LIST) OR $force_all)
		{
			// [LIST]
			$tag_list['no_option']['list'] = array(
				'callback'    => 'handle_bbcode_list',
				'strip_empty' => true
			);

			// [LIST=XXX]
			$tag_list['option']['list'] = array(
				'callback'    => 'handle_bbcode_list',
				'strip_empty' => true
			);

			// [INDENT]
			$tag_list['no_option']['indent'] = array(
				'html'              => '<blockquote>%1$s</blockquote>',
				'strip_empty'       => true,
				'strip_space_after' => 1
			);
		}

		if (($vbulletin->options['allowedbbcodes'] & ALLOW_BBCODE_URL) OR $force_all)
		{
			// [EMAIL]
			$tag_list['no_option']['email'] = array(
				'callback'    => 'handle_bbcode_email',
				'strip_empty' => true
			);

			// [EMAIL=XXX]
			$tag_list['option']['email'] = array(
				'callback'    => 'handle_bbcode_email',
				'strip_empty' => true
			);

			// [URL]
			$tag_list['no_option']['url'] = array(
				'callback'    => 'handle_bbcode_url',
				'strip_empty' => true
			);

			// [URL=XXX]
			$tag_list['option']['url'] = array(
				'callback'    => 'handle_bbcode_url',
				'strip_empty' => true
			);

			// [THREAD]
			$tag_list['no_option']['thread'] = array(
				'html'        => '<a href="' . $forum_path . 'showthread.php?' . vB::getCurrentSession()->get('sessionurl') . 't=%1$s"' .
					($vbulletin->options['friendlyurl'] ? ' rel="nofollow"' : '') . '>' . $forum_path_full . 'showthread.php?t=%1$s</a>',
				'data_regex'  => '#^\d+$#',
				'strip_empty' => true
			);

			// [THREAD=XXX]
			$tag_list['option']['thread'] = array(
				'html'         => '<a href="' . $forum_path . 'showthread.php?' . vB::getCurrentSession()->get('sessionurl') . 't=%2$s"' .
					($vbulletin->options['friendlyurl'] ? ' rel="nofollow"' : '') .
					' title="' . htmlspecialchars_uni($vbulletin->options['bbtitle']) . ' - ' . $vbphrase['thread'] . ' %2$s">%1$s</a>',
				'option_regex' => '#^\d+$#',
				'strip_empty'  => true
			);

			// [POST]
			$tag_list['no_option']['post'] = array(
				'html'        => '<a href="' . $forum_path . 'showthread.php?' . vB::getCurrentSession()->get('sessionurl') . 'p=%1$s#post%1$s"' .
					($vbulletin->options['friendlyurl'] ? ' rel="nofollow"' : '') . '>' . $forum_path_full . 'showthread.php?p=%1$s</a>',
				'data_regex'  => '#^\d+$#',
				'strip_empty' => true
			);

			// [POST=XXX]
			$tag_list['option']['post'] = array(
				'html'         => '<a href="' . $forum_path . 'showthread.php?' . vB::getCurrentSession()->get('sessionurl') . 'p=%2$s#post%2$s"' .
					($vbulletin->options['friendlyurl'] ? ' rel="nofollow"' : '') .
					' title="' . htmlspecialchars_uni($vbulletin->options['bbtitle']) . ' - ' . $vbphrase['post'] . ' %2$s">%1$s</a>',
				'option_regex' => '#^\d+$#',
				'strip_empty'  => true
			);

			if (defined('VB_API') AND VB_API === true)
			{
				$tag_list['no_option']['thread']['html'] = '<a href="vb:showthread/t=%1$s">' . $vbulletin->options['bburl'] . '/showthread.php?t=%1$s</a>';
				$tag_list['option']['thread']['html'] = '<a href="vb:showthread/t=%2$s">%1$s</a>';
				$tag_list['no_option']['post']['html'] = '<a href="vb:showthread/p=%1$s">' . $vbulletin->options['bburl'] . '/showthread.php?p=%1$s</a>';
				$tag_list['option']['post']['html'] = '<a href="vb:showthread/p=%2$s">%1$s</a>';
			}
		}

		if (($vbulletin->options['allowedbbcodes'] & ALLOW_BBCODE_PHP) OR $force_all)
		{
			// [PHP]
			$tag_list['no_option']['php'] = array(
				'callback'          => 'handle_bbcode_php',
				'strip_empty'       => true,
				'stop_parse'        => true,
				'disable_smilies'   => true,
				'disable_wordwrap'  => true,
				'strip_space_after' => 2
			);
		}

		if (($vbulletin->options['allowedbbcodes'] & ALLOW_BBCODE_CODE) OR $force_all)
		{
			//[CODE]
			$tag_list['no_option']['code'] = array(
				'callback'          => 'handle_bbcode_code',
				'strip_empty'       => true,
				'disable_smilies'   => true,
				'disable_wordwrap'  => true,
				'strip_space_after' => 2
			);
		}

		if (($vbulletin->options['allowedbbcodes'] & ALLOW_BBCODE_HTML) OR $force_all)
		{
			// [HTML]
			$tag_list['no_option']['html'] = array(
				'callback'          => 'handle_bbcode_html',
				'strip_empty'       => true,
				'stop_parse'        => true,
				'disable_smilies'   => true,
				'disable_wordwrap'  => true,
				'strip_space_after' => 2
			);
		}

		// Legacy Hook 'bbcode_fetch_tags' Removed //
	}
	if ($force_all)
	{
		$tag_list_return = $tag_list;
		$tag_list = $tag_list_bak;
		return $tag_list_return;
	}
	else
	{
		return $tag_list;
	}


}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 102574 $
|| #######################################################################
\*=========================================================================*/
