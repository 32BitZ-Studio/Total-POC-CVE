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
* BB code parser for the WYSIWYG editor
*
* @package	vBulletin
*/
class vB5_Template_BbCode_Wysiwyg extends vB5_Template_BbCode
{
	/**
	* List of tags the WYSIWYG BB code parser should not parse.
	*
	* @var	array
	*/
	protected $unparsed_tags = array(
		'thread'    => 'thread',
		'post'      => 'post',
		'quote'     => 'quote',
		'highlight' => 'highlight',
		'noparse'   => 'noparse',
		'video'     => 'video',
		'sigpic'    => 'sigpic',

		// leave these parsed, because <space><space> needs to be replaced to emulate pre tags
		//'php',
		//'code',
		//'html',
	);

	/**
	* Type of WYISWYG parser (IE or Mozilla at this point)
	*
	* @var	string
	*/
	protected $type = '';

	public function __construct($appendCustomTags = true)
	{
		$this->setStripSpace(false);
		parent::__construct($appendCustomTags);

		if (!empty(self::$customTags['no_option']))
		{
			foreach(self::$customTags['no_option'] AS $tagname => $taginfo)
			{
				if (!isset($this->unparsed_tags[$tagname]))
				{
					$this->unparsed_tags[$tagname] = $tagname;
				}
			}
		}
		if (!empty(self::$customTags['option']))
		{
			foreach(self::$customTags['option'] AS $tagname => $taginfo)
			{
				if (!isset($this->unparsed_tags[$tagname]))
				{
					$this->unparsed_tags[$tagname] = $tagname;
				}
			}
		}

		// change all unparsable tags to use the unparsable callback
		foreach ($this->unparsed_tags AS $remove)
		{
			if (isset($this->tag_list['option']["$remove"]))
			{
				$this->tag_list['option']["$remove"]['callback'] = 'handle_wysiwyg_unparsable';
				unset($this->tag_list['option']["$remove"]['html'], $this->tag_list['option']["$remove"]['strip_space_after']);
			}
			if (isset($this->tag_list['no_option']["$remove"]))
			{
				$this->tag_list['no_option']["$remove"]['callback'] = 'handle_wysiwyg_unparsable';
				unset($this->tag_list['no_option']["$remove"]['html'], $this->tag_list['option']["$remove"]['strip_space_after']);
			}
		}

		// make the "pre" tags use the correct handler
		foreach (array('code', 'php', 'html') AS $pre_tag)
		{
			if (isset($this->tag_list['no_option']["$pre_tag"]))
			{
				$this->tag_list['no_option']["$pre_tag"]['callback'] = 'handle_preformatted_tag';
				unset($this->tag_list['no_option']["$pre_tag"]['html'], $this->tag_list['option']["$pre_tag"]['strip_space_after']);
			}
		}

		$this->type = vB5_Template_Runtime::isBrowser('ie') ? 'ie' : 'moz_css';
	}

	/**
	* No-op so that non-inline attchments are not rendered at the end of the
	* text for the WYSIWYG editor, since we're now using the parent implementation
	* of handle_bbcode_img().
	*
	* @param	string	Text to append attachments
	* @param	array	Attachment data
	* @param	bool	Whether to show images
	* @param	array	Array of nodeid => (nodeid, filedataid) attachments that should not be included in the attachment box.
	*/
	function append_noninline_attachments($text, $attachments, $do_imgcode = false, $skiptheseattachments = array())
	{
		return $text;
	}

	/**
	* Handles an [img] tag.
	*
	* NOTE: This calls the parent implementation so that the [ATTACH] and [IMG]
	* bbcodes render (nearly) the same when editing the post as when displaying
	* the post. The main difference is that the surrounding anchor tags are
	* removed for images in the WYSIWYG editor, via turnOffSurroundingAnchor.
	* See comment before parent function call.
	*
	* @param	string	The text to search for an image in.
	* @param	string	Whether to parse matching images into pictures or just links.
	*
	* @return	string	Text representation of the tag.
	*/
	function handle_bbcode_img($bbcode, $do_imgcode, $has_img_code = false, $fulltext = '', $forceShowImages = false)
	{
		// the bbcode parser surrounds images in an anchor if the image is not fullsize.
		// In order to have the images show the ckeditor's Image Dialog instead of the Link dialog,
		// we need the images to show up without the surrounding anchor tag.
		// So this is a dirty hacky workaround.
		$this->turnOffSurroundingAnchor = true;
		return parent::handle_bbcode_img($bbcode, $do_imgcode, $has_img_code, $fulltext, $forceShowImages);
	}

	/**
	* Handles a [code]/[html]/[php] tag. In WYSIYWYG parsing, keeps the tag but replaces
	* <space><space> with a non-breaking space followed by a space.
	*
	* @param	string	The code to display
	*
	* @return	string	Tag with spacing replaced
	*/
	function handle_preformatted_tag($code)
	{
		$current_tag =& $this->currentTag;
		$tag_name = (isset($current_tag['name_orig']) ? $current_tag['name_orig'] : $current_tag['name']);

		return "[$tag_name]" . $this->emulate_pre_tag($code) . "[/$tag_name]";
	}

	/**
	* This does it's best to emulate an HTML pre tag and keep whitespace visible
	* in a standard HTML environment. Useful with code/html/php tags.
	*
	* @param	string	Code to process
	*
	* @return	string	Processed code
	*/
	function emulate_pre_tag($code)
	{
		$code = str_replace('  ', ' &nbsp;', $code);
		$code = preg_replace('#(\r\n|\n|\r|<p>)( )(?!([\r\n]}|<p>))#i', '$1&nbsp;', $code);
		return $code;
	}

	/**
	* Perform word wrapping on the text. WYSIWYG parsers should not
	* perform wrapping, so this function does nothing.
	*
	* @param	string	Text to be used for wrapping
	*
	* @return	string	Input string (unmodified)
	*/
	function do_word_wrap($text)
	{
		return $text;
	}

	/**
	* Parses out specific white space before or after cetain tags, rematches
	* tags where necessary, and processes line breaks.
	*
	* @param	string	Text to process
	* @param	bool	Whether to translate newlines to HTML breaks (unused)
	*
	* @return	string	Processed text
	*/
	function parse_whitespace_newlines($text, $do_nl2br = true)
	{
		$whitespacefind = array(
			'#(\r\n|\n|\r)?( )*(\[\*\]|\[/list|\[list|\[indent)#si',
			'#(/list\]|/indent\])( )*(\r\n|\n|\r)?#si'
		);
		$whitespacereplace = array(
			'\3',
			'\1'
		);
		$text = preg_replace($whitespacefind, $whitespacereplace, $text);

		if ($this->is_wysiwyg('ie'))
		{
			// this fixes an issue caused by odd nesting of tags. This causes IE's
			// WYSIWYG editor to display the output as vB will display it
			$rematch_find = array(
				'#\[((color)=.*)\](.*)\[/\\2\]#siU',
				'#\[((font)=.*)\](.*)\[/\\2\]#siU',
				'#\[((size)=.*)\](.*)\[/\\2\]#siU',
			);
			$text = preg_replace_callback($rematch_find,
				array($this, 'bbcodeRematchTagsWysiwygPregMatch1'), $text);

			$rematch_find = array(
				'#\[(b)\](((?>[^[]+?)|(?R)|\[)*)\[/\\1\]#siU',
				'#\[(i)\](((?>[^[]+?)|(?R)|\[)*)\[/\\1\]#siU',
				'#\[(u)\](((?>[^[]+?)|(?R)|\[)*)\[/\\1\]#siU',
				'#\[(left)\](((?>[^[]+?)|(?R)|\[)*)\[/\\1\]#siU',
				'#\[(center)\](((?>[^[]+?)|(?R)|\[)*)\[/\\1\]#siU',
				'#\[(right)\](((?>[^[]+?)|(?R)|\[)*)\[/\\1\]#siU',
			);
			$text = preg_replace_callback($rematch_find,
				array($this, 'bbcodeRematchTagsWysiwygPregMatch2'), $text);

			$text = '<p>' . preg_replace('#(\r\n|\n|\r)#', "</p>\n<p>", ltrim($text)) . '</p>';

			if (strpos('[/list', strtolower($text))) // workaround bug #22749
			{
				$text = preg_replace_callback('#(\[list(=(&quot;|"|\'|)(.*)\\3)?\])(((?>[^\[]*?|(?R))|(?>.))*)(\[/list(=\\3\\4\\3)?\])#siU',
					array($this, 'removeWysiwygBreaksPregMatch3'), $text
				);
			}
			$text = preg_replace('#<p>\s*</p>(?!\s*\[list|$)#i', '<p>&nbsp;</p>', $text);

			$text = str_replace('<p></p>', '', $text);
		}
		else
		{
			$text = nl2br($text);
		}

		// convert tabs to four &nbsp;
		$text = str_replace("\t", '&nbsp;&nbsp;&nbsp;&nbsp;', $text);

		return $text;
	}

	/**
	 * Callback for preg_replace_callback in parse_whitespace_newline
	 */
	protected function bbcodeRematchTagsWysiwygPregMatch1($matches)
	{
		return $this->bbcode_rematch_tags_wysiwyg($matches[3], $matches[2], $matches[1]);
	}

	/**
	 * Callback for preg_replace_callback in parse_whitespace_newline
	 */
	protected function bbcodeRematchTagsWysiwygPregMatch2($matches)
	{
		return $this->bbcode_rematch_tags_wysiwyg($matches[2], $matches[1]);
	}

	/**
	 * Callback for preg_replace_callback in parse_whitespace_newline
	 */
	protected function removeWysiwygBreaksPregMatch3($matches)
	{
		return $this->remove_wysiwyg_breaks($matches[0]);
	}

	/**
	* Parse an input string with BB code to a final output string of HTML
	*
	* @param	string	Input Text (BB code)
	* @param	bool	Whether to parse smilies
	* @param	bool	Whether to parse img code (for the video bbcodes)
	* @param	bool	Whether to allow HTML (for smilies)
	*
	* @return	string	Ouput Text (HTML)
	*/
	function parseBbcode($input_text, $do_smilies, $do_imgcode, $do_html = false)
	{
		$text = $this->parseArray($this->fixTags($this->buildParseArray($input_text)), $do_smilies, $do_imgcode, $do_html);

		if ($this->is_wysiwyg('ie'))
		{
			$text = preg_replace('#<p>((<[^>]+>)*)<(p|div) align="([a-z]+)">(.*)</\\3>((<[^>]+>)*)</p>#siU', '<p align="\\4">\\1\\5\\6</p>', $text);

			// by now, any empty p tags are things that used to be in the form of <p>[tag][/tag]</p>,
			// so we need to leave them to be equivalent to the nl2br version
			$text = preg_replace('#<p></p>#siU', '<p>&nbsp;</p>', $text);

			// rematch <p> tags around blockquotes (from the indent tag)
			do
			{
				$orig_text = $text;
				$text = preg_replace('#<blockquote>(?!<p>)(.*)</blockquote>(?!<p>)#siU', '</p><blockquote><p>\\1</p></blockquote><p>', $text);
			}
			while ($orig_text != $text);

			// it's possible the blockquote rematch caused some blank p tags, so remove them
			$text = preg_replace('#<p></p>#siU', '', $text);
		}

		// need to display smilies in code/php/html tags as literals
		$text = preg_replace_callback('#\[(code|php|html)\](.*)\[/\\1\]#siU',
			array($this, 'stripSmiliesPregMatch'), $text);

		return $text;
	}

	/**
	 * Callback for preg_replace_callback in parseBbcode
	 */
	protected function stripSmiliesPregMatch($matches)
	{
		return $this->stripSmilies($matches[0], true);
	}

	/**
	* Call back to handle any tag that the WYSIWYG editor can't handle. This
	* parses the tag, but returns an unparsed version of it. The advantage of
	* this method is that any parsing directives (no parsing, no smilies, etc)
	* will still be applied to the text within.
	*
	* @param	string	Text inside the tag
	*
	* @return	string	The unparsed tag and the text within it
	*/
	function handle_wysiwyg_unparsable($text)
	{
		$tag_name = (isset($this->currentTag['name_orig']) ? $this->currentTag['name_orig'] : $this->currentTag['name']);
		return '[' . $tag_name .
			($this->currentTag['option'] !== false ?
				('=' . $this->currentTag['delimiter'] . $this->currentTag['option'] . $this->currentTag['delimiter']) :
				''
			) . ']' . $text . '[/' . $tag_name . ']';
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
		$bad_tag_list = '(br|p|li|ul|ol)';

		$exploded = preg_split("#(\r\n|\n|\r)#", $text);

		$output = '';
		foreach ($exploded AS $value)
		{
			if (!preg_match('#(</' . $bad_tag_list . '>|<' . $bad_tag_list . '\s*/>)$#iU', $value))
			{
				if (trim($value) == '')
				{
					$value = '&nbsp;';
				}
				$output .= $value . "<br />\n";
			}
			else
			{
				$output .= "$value\n";
			}
		}
		$output = preg_replace('#<br />+\s*$#i', '', $output);

		return "<li>$output</li>";
	}

	/**
	* Returns whether this parser is a WYSIWYG parser if no type is specified.
	* If a type is specified, it checks whether our type matches
	*
	* @param	string|null	Type of parser to match; null represents any type
	*
	* @return	bool		True if it is; false otherwise
	*/
	function is_wysiwyg($type = null)
	{
		if ($type == null)
		{
			return true;
		}
		else
		{
			return ($this->type == $type);
		}
	}

	/**
	* Automatically inserts a closing tag before a line break and reopens it after.
	* Also wraps the text in the tag. Workaround for IE WYSIWYG issue.
	*
	* @param	string	Text to search through
	* @param	string	Tag to close and reopen (can't include the option)
	* @param	string	Raw text that opens the tag (this needs to include the option if there is one)
	*
	* @return	string	Processed text
	*/
	function bbcode_rematch_tags_wysiwyg($innertext, $tagname, $tagopen_raw = '')
	{
		// This function replaces line breaks with [/tag]\n[tag].
		// It is intended to be used on text inside [tag] to fix an IE WYSIWYG issue.

		$tagopen_raw = str_replace('\"', '"', $tagopen_raw);
		if (!$tagopen_raw)
		{
			$tagopen_raw = $tagname;
		}

		$innertext = str_replace('\"', '"', $innertext);
		return "[$tagopen_raw]" . preg_replace('#(\r\n|\n|\r)#', "[/$tagname]\n[$tagopen_raw]", $innertext) . "[/$tagname]";
	}

	/**
	* Removes IE's WYSIWYG breaks from within a list.
	*
	* @param	string	Text to remove breaks from. Should start with [list] and end with [/list]
	*
	* @return	string	Text with breaks removed
	*/
	function remove_wysiwyg_breaks($fulltext)
	{
		$fulltext = str_replace('\"', '"', $fulltext);
		preg_match('#^(\[list(=(&quot;|"|\'|)(.*)\\3)?\])(.*?)(\[/list(=\\3\\4\\3)?\])$#siU', $fulltext, $matches);
		$prepend = $matches[1];
		$innertext = $matches[5];

		$find = array("</p>\n<p>", '<br />', '<br>');
		$replace = array("\n", "\n", "\n");
		$innertext = str_replace($find, $replace, $innertext);

		if ($this->is_wysiwyg('ie'))
		{
			return '</p>' . $prepend . $innertext . '[/list]<p>';
		}
		else
		{
			return $prepend . $innertext . '[/list]';
		}
	}

	public function getTableHelper()
	{
		if (!isset($this->tableHelper))
		{
			$this->tableHelper = new vB5_Template_BbCode_Tablewysiwyg($this);
		}

		return $this->tableHelper;
	}

	/**
	 * Displays the [USER] bbcode
	 *
	 * @param	string	Username
	 * @parma	int		User ID
	 *
	 * @return	string	Rendered USER bbcode.
	 */
	public function handle_bbcode_user($username = '', $userid = '')
	{
		$userid = (int) $userid;
		$vboptions = vB::getDatastore()->getValue('options');

		// this implementation is used when rendering a post for the editor (when editing a post)

		// keep this markup in sync with the other 2 implementations of handle_bbcode_user()
		// and with autocompleteSelect() in ckeditor.js
		if ($vboptions['userbbcodeavatar'])
		{
			$avatarInfo = Api_InterfaceAbstract::instance()->callApi('User', 'fetchAvatar', array($userid, true));
			$avatarUrl = $vboptions['bburl'] . '/' . $avatarInfo['avatarpath'];

			return '<a href="#" style="background-image:url(\'' . $avatarUrl . '\');" class="b-bbcode-user b-bbcode-user--has-avatar js-bbcode-user" data-userid="' . $userid . '">' . $username . '</a>';
		}
		else
		{
			return '<a href="#" class="b-bbcode-user js-bbcode-user" data-userid="' . $userid . '">' . $username . '</a>';
		}
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
