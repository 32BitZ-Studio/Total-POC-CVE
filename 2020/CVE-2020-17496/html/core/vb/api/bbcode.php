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
 * vB_Api_Bbcode
 *
 * @package vBApi
 * @access public
 */
class vB_Api_Bbcode extends vB_Api
{
	/**#@+
	 * @var int Bit field values to enable/disable specific types of BB codes
	 */
	const ALLOW_BBCODE_BASIC	= 1;
	const ALLOW_BBCODE_COLOR	= 2;
	const ALLOW_BBCODE_SIZE		= 4;
	const ALLOW_BBCODE_FONT		= 8;
	const ALLOW_BBCODE_ALIGN	= 16;
	const ALLOW_BBCODE_LIST		= 32;
	const ALLOW_BBCODE_URL		= 64;
	const ALLOW_BBCODE_CODE		= 128;
	const ALLOW_BBCODE_PHP		= 256;
	const ALLOW_BBCODE_HTML		= 512;
	const ALLOW_BBCODE_IMG		= 1024;
	const ALLOW_BBCODE_QUOTE	= 2048;
	const ALLOW_BBCODE_CUSTOM	= 4096;
	// video in vb4 holds 4096*2. Skip for now in case we bring it into vb5.
	const ALLOW_BBCODE_USER		= 16384;
	/**#@-*/

	/**
	 * Contains an array of user specified custom BB code tags.
	 *
	 * @var array $customTags
	 * @see vB_Api_Bbcode::fetchCustomTags() For the array format.
	 */
	protected $customTags;

	/**
	 * @var int EDITOR_INDENT Used in parsing the [INDENT] bbcode tag
	 */
	const EDITOR_INDENT = 40;

	/**
	 * {@inheritDoc} Methods include: getSignatureInfo
	 *
	 * @var array $disableFalseReturnOnly
	 */
	protected $disableFalseReturnOnly = array('getSignatureInfo');

	/**
	 * Constructor
	 */
	protected function __construct()
	{
		parent::__construct();
	}

	/**
	 * Returns an array of bbcode parsing information. {@see vB_Api_Bbcode::fetchTagList}
	 *
	 * @see vB_Api_Bbcode::fetchTagList
	 * @see vB_Api_Bbcode::fetchCustomTags()
	 * @return array Bbcode parsing information. Format:
	 * <pre>array(
	 *     defaultTags => array {@see vB_Api_Bbcode::fetchTagList}
	 *     customTags => array @see vB_Api_Bbcode::fetchCustomTags
	 *     defaultOptions => array {@see vB_Api_Bbcode::fetchBbcodeOptions()}
	 * )</pre>
	 */
	public function initInfo()
	{
		$response['defaultTags'] = $this->fetchTagList();
		$response['customTags'] = $this->fetchCustomTags();
		$response['defaultOptions'] = $this->fetchBbcodeOptions();
		$response['smilies'] = $this->fetchSmilies();

		$response['sessionUrl'] = vB::getCurrentSession()->get('sessionurl');
		$response['vBHttpHost'] = vB::getRequest()->getVbHttpHost();

		$options = vB::getDatastore()->getValue('options');
		$response['wordWrap'] = $options['wordwrap'];
		$response['codeMaxLines'] = $options['codemaxlines'];
		$response['bbUrl'] = $options['bburl'];
		$response['viewAttachedImages'] = $options['viewattachedimages'];
		$response['urlNoFollow'] = $options['url_nofollow'];
		$response['urlNoFollowWhiteList'] = $options['url_nofollow_whitelist'];
		$response['useFileAvatar'] = $options['usefileavatar'];
		$response['sigpicUrl'] = $options['sigpicurl'];

		return $response;
	}

	/**
	 * Returns the list of default BB code tags
	 *
	 * @param  string  Allows an optional path/URL to prepend to thread/post tags
	 * @param  boolean Force all BB codes to be returned?
	 *
	 * @return array   Array of BB code tags. Format:
	 *		<code>array(
	 *			defaultTags => array {@see vB_Api_Bbcode::fetchTagList}
	 *			customTags => array @see vB_Api_Bbcode::fetchCustomTags
	 *			defaultOptions => array {@see vB_Api_Bbcode::fetchBbcodeOptions()}
	 *		)</code>
	 */
	public function fetchTagList($prepend_path = '', $force_all = false)
	{
		// TODO: we need to refactor $vbphrase
		global $vbphrase;
		static $tag_list;

		$options = vB::getDatastore()->getValue('options');

		if ($force_all)
		{
			$tag_list_bak = $tag_list;
			$tag_list = array();
		}

		if (empty($tag_list))
		{
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
				'disable_smilies' => true,
			);

			// [VIDEO]
			$tag_list['no_option']['video'] = array(
				'callback'    => 'handle_bbcode_url',
				'strip_empty' => true
			);

			// [VIDEO=XXX]
			$tag_list['option']['video'] = array(
				'callback' => 'handle_bbcode_video',
				'strip_empty'     => true,
				'disable_smilies' => true,
			);

			// [PAGE]
			$tag_list['no_option']['page'] = array(
				'callback' => 'parsePageBbcode',
				'strip_space_after' => 2,
				'stop_parse' => true,
				'disable_smilies' => true,
				'strip_empty' => false
			);

			// [PRBREAK]
			$tag_list['no_option']['prbreak'] = array(
				'callback' => 'parsePrbreakBbcode',
				'strip_space_after' => 0,
				'stop_parse' => true,
				'disable_smilies' => true,
				'strip_empty' => false
			);

			if (($options['allowedbbcodes'] & vB_Api_Bbcode::ALLOW_BBCODE_BASIC) OR $force_all)
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

				// [H=1]
				$tag_list['option']['h'] = array(
					'callback' => 'handle_bbcode_h',
					'strip_space_after' => 2,
					'strip_empty' => true
				);

				// [TABLE]
				$tag_list['no_option']['table'] = array(
					'callback' => 'parseTableTag',
					'ignore_global_strip_space_after' => true,
					'strip_space_after' => 2,
					'strip_empty' => true
				);

				// [TABLE=]
				$tag_list['option']['table'] = array(
					'callback' => 'parseTableTag',
					'ignore_global_strip_space_after' => true,
					'strip_space_after' => 2,
					'strip_empty' => true
				);

				// [HR]
				$tag_list['no_option']['hr'] = array(
					'html' => '<hr />%1$s',
					'strip_empty' => false
				);

				// [SUB]
				$tag_list['no_option']['sub'] = array(
					'html' => '<sub>%1$s</sub>',
					'strip_empty' => true
				);

				// [SUP]
				$tag_list['no_option']['sup'] = array(
					'html' => '<sup>%1$s</sup>',
					'strip_empty' => true
				);
			}

			if (($options['allowedbbcodes'] & vB_Api_Bbcode::ALLOW_BBCODE_COLOR) OR $force_all)
			{
				// [COLOR=XXX]
				$tag_list['option']['color'] = array(
					'html'         => '<span style="color:%2$s">%1$s</span>',
					'option_regex' => '#^\#?\w+$#',
					'strip_empty'  => true
				);
			}

			if (($options['allowedbbcodes'] & vB_Api_Bbcode::ALLOW_BBCODE_SIZE) OR $force_all)
			{
				// [SIZE=XXX]
				$tag_list['option']['size'] = array(
					'callback'    => 'handle_bbcode_size',
					'strip_empty'  => true
				);
			}

			if (($options['allowedbbcodes'] & vB_Api_Bbcode::ALLOW_BBCODE_FONT) OR $force_all)
			{
				// [FONT=XXX]
				$tag_list['option']['font'] = array(
					'html'         => '<span style="font-family:%2$s">%1$s</span>',
					'option_regex' => '#^[^["`\':]+$#',
					'strip_empty'  => true
				);
			}

			if (($options['allowedbbcodes'] & vB_Api_Bbcode::ALLOW_BBCODE_ALIGN) OR $force_all)
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
					'callback'          => 'handle_bbcode_indent',
					'strip_empty'       => true,
					'strip_space_after' => 1
				);

				// [INDENT=]
				$tag_list['option']['indent'] = array(
					'callback'          => 'handle_bbcode_indent',
					'strip_empty'       => true,
					'strip_space_after' => 1
				);
			}

			if (($options['allowedbbcodes'] & vB_Api_Bbcode::ALLOW_BBCODE_LIST) OR $force_all)
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
					'callback'          => 'handle_bbcode_indent',
					'strip_empty'       => true,
					'strip_space_after' => 1
				);

				// [INDENT=]
				$tag_list['option']['indent'] = array(
					'callback'          => 'handle_bbcode_indent',
					'strip_empty'       => true,
					'strip_space_after' => 1
				);
			}

			if (($options['allowedbbcodes'] & vB_Api_Bbcode::ALLOW_BBCODE_URL) OR $force_all)
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
					'callback'    => 'handle_bbcode_thread',
					'strip_empty' => true
				);

				// [THREAD=XXX]
				$tag_list['option']['thread'] = array(
					'callback'    => 'handle_bbcode_thread',
					'strip_empty'  => true
				);

				// [POST]
				$tag_list['no_option']['post'] = array(
					'callback'    => 'handle_bbcode_post',
					'strip_empty' => true
				);

				// [POST=XXX]
				$tag_list['option']['post'] = array(
					'callback'    => 'handle_bbcode_post',
					'strip_empty'  => true
				);

				// [NODE]
				$tag_list['no_option']['node'] = array(
					'callback'    => 'handle_bbcode_node',
					'strip_empty' => true
				);

				// [NODE=XXX]
				$tag_list['option']['node'] = array(
					'callback'    => 'handle_bbcode_node',
					'strip_empty'  => true
				);

				if (defined('VB_API') AND VB_API === true)
				{
					$tag_list['no_option']['thread']['html'] = '<a href="vb:showthread/t=%1$s">' . $options['bburl'] . '/showthread.php?t=%1$s</a>';
					$tag_list['option']['thread']['html'] = '<a href="vb:showthread/t=%2$s">%1$s</a>';
					$tag_list['no_option']['post']['html'] = '<a href="vb:showthread/p=%1$s">' . $options['bburl'] . '/showthread.php?p=%1$s</a>';
					$tag_list['option']['post']['html'] = '<a href="vb:showthread/p=%2$s">%1$s</a>';
				}
			}

			if (($options['allowedbbcodes'] & vB_Api_Bbcode::ALLOW_BBCODE_PHP) OR $force_all)
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

			if (($options['allowedbbcodes'] & vB_Api_Bbcode::ALLOW_BBCODE_CODE) OR $force_all)
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

			if (($options['allowedbbcodes'] & vB_Api_Bbcode::ALLOW_BBCODE_HTML) OR $force_all)
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


			if (($options['allowedbbcodes'] & vB_Api_Bbcode::ALLOW_BBCODE_USER) OR $force_all)
			{
				// [USER]
				$tag_list['no_option']['user'] = array(
					'callback'    => 'handle_bbcode_user',
					'strip_empty' => true
				);

				// [USER=XXX]
				$tag_list['option']['user'] = array(
					'callback'    => 'handle_bbcode_user',
					'strip_empty'  => true
				);
			}

			/*
				TODO: add allowedbbcodes?
			 */
			// [ATTACH]
			$tag_list['no_option']['attach'] = array(
				'callback'    => 'handle_bbcode_attach',
				'disable_wordwrap'  => true,
				'strip_empty' => true,
				'disable_smilies' => true,
			);

			// [ATTACH=XXX]
			$tag_list['option']['attach'] = array(
				'callback'    => 'handle_bbcode_attach',
				'disable_wordwrap'  => true,
				'strip_empty'  => true,
				'disable_smilies' => true,
			);

			// [IMG2=XXX]
			$tag_list['option']['img2'] = array(
				'callback'    => 'handle_bbcode_img2',
				'disable_wordwrap'  => true,
				'strip_empty'  => true,
				'disable_smilies' => true,
			);


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

	/**
	 * Loads any user specified custom BB code tags.
	 *
	 * @return array Array of custom BB code tags. Format:
	 *               <pre>
	 *               array(
	 *                   option => array(
	 *                       bbcode_tag => array(
	 *                           html => replacement string
	 *                           strip_empty => int
	 *                           stop_parse => int
	 *                           disable_smilies => int
	 *                           disable_wordwrap => int
	 *                       )
	 *                       [...]
	 *                   )
	 *                   no_option => array(
	 *                       bbcode_tag => array(
	 *                           html => replacement string
	 *                           strip_empty => int
	 *                           stop_parse => int
	 *                           disable_smilies => int
	 *                           disable_wordwrap => int
	 *                       )
	 *                       [...]
	 *                   )
	 *               )
	 *               </pre>
	 */
	protected function fetchCustomTags()
	{
		if (!isset($this->customTags))
		{
			$this->customTags = array();

			$bbcodeoptions = vB::getDatastore()->getValue('bf_misc_bbcodeoptions');

			$bbcodes = vB_Library::instance('bbcode')->fetchBBCodes();
			foreach($bbcodes as $customtag)
			{
				$has_option = $customtag['twoparams'] ? 'option' : 'no_option';
				$customtag['bbcodetag'] = strtolower($customtag['bbcodetag']);
				$this->customTags["$has_option"]["$customtag[bbcodetag]"] = array(
					'html'             => $customtag['bbcodereplacement'],
					'strip_empty'      => (intval($customtag['options']) & $bbcodeoptions['strip_empty']) ? 1 : 0 ,
					'stop_parse'       => (intval($customtag['options']) & $bbcodeoptions['stop_parse']) ? 1 : 0 ,
					'disable_smilies'  => (intval($customtag['options']) & $bbcodeoptions['disable_smilies']) ? 1 : 0 ,
					'disable_wordwrap' => (intval($customtag['options']) & $bbcodeoptions['disable_wordwrap']) ? 1 : 0
				);
			}
		}

		return $this->customTags;
	}

	/**
	 * Compiles and returns an array of various bbcode-related vboptions.
	 *
	 * @return array Array of various bbcode-related vboptions.
	 *     <pre>
	 *     array(
	 *         privatemessage => array(
	 *             allowhtml
	 *             allowbbcode
	 *             allowimagecode
	 *             allowsmilies
	 *         )
	 *         nonforum => array(
	 *             dohtml
	 *             dobbcode
	 *             doimagecode
	 *             dosmilies
	 *         )
	 *         arrays similar to 'nonforum' for visitormessage, groupmessage, and socialmessage.
	 *     )
	 *     </pre>
	 */
	protected function fetchBbcodeOptions()
	{
		$options = vB::getDatastore()->getValue('options');

		$response = array();

		// parse private message
		$response['privatemessage'] = array(
			'allowhtml'      => false,
			'allowbbcode'    => $options['privallowbbcode'],
			'allowimagecode' => true,
			'allowsmilies'   => $options['privallowsmilies'],
		);

		// parse non-forum item
		$response['nonforum'] = array(
			'dohtml'        => $options['allowhtml'],
			'dobbcode'      => $options['allowbbcode'],
			'dobbimagecode' => $options['allowbbimagecode'],
			'dosmilies'     => $options['allowsmilies']
		);

		// parse visitor/group/picture message
		$response['visitormessage'] =
		$response['groupmessage']   =
		$response['socialmessage']  = array(
			'dohtml'        => $options['allowhtml'],
			'dobbcode'      => $options['allowbbcode'],
			'dobbimagecode' => true, // this tag can be disabled manually; leaving as true means old usages remain (as documented)
			'dosmilies'     => $options['allowsmilies']
		);

		return $response;
	}

	/**
	 * Returns an array of smilie information.
	 *
	 * @return array Smilie information corresponding to the data in the "smilie" field,
	 *               with one extra column "smilielen".
	 */
	public function fetchSmilies()
	{
		if ($smilies = vB::getDatastore()->getValue('smiliecache'))
		{
			// we can get the smilies from the smiliecache datastore
			DEVDEBUG('returning smilies from the datastore');

			return $smilies;
		}
		else
		{
			// we have to get the smilies from the database
			DEVDEBUG('querying for smilies');

			return vB::getDbAssertor()->getRows('fetchSmilies');
		}
	}

	/**
	 * Extracts the video and photo content from text.
	 *
	 * @param  string Rawtext from a post
	 *
	 * @return mixed  Array of 'url', 'provider', 'code'
	 */
	public function extractVideo($rawtext)
	{
		$videos = array();
		$filter = '~\[video.*\[\/video~i';
		$matches = array();
		$count = preg_match_all($filter, $rawtext, $matches);

		if ($count > 0)
		{
			foreach ($matches[0] as $match)
			{
				$pos = strpos($match,']');
				if ($pos)
				{
					$codes = substr($match,7, $pos -7);
					$codes = explode(';', $codes);
					if (count($codes) > 1)
					{
						$url = substr($match,$pos + 1, -7);

						if (!empty($url))
						{
							//we have all the necessary variables.
							$videos[] = array(
								'url' => $url,
								'provider' => $codes[0],
								'code' => $codes[1],
							);
						}
					}
				}
			}

			return $videos;
		}
		else
		{
			return 0;
		}

	}

	/**
	 * Parses HTML produced by a WYSIWYG editor and produces the corresponding BBCode formatted text
	 *
	 * @param  string HTML text
	 *
	 * @return string BBCode text
	 */
	public function parseWysiwygHtmlToBbcode($text)
	{
		$wysiwyg = new vB_WysiwygHtmlParser();

		return $wysiwyg->parseWysiwygHtmlToBbcode($text);
	}

	/**
	 * Converts text from an editor into text ready to be saved with bbcode converted
	 *
	 * @param  string Text to convert
	 * @param  array  Options
	 *                - autoparselinks
	 *
	 * @return string Converted Text
	 */
	public function convertWysiwygTextToBbcode($text, $options)
	{
		$text = $this->parseWysiwygHtmlToBbcode($text);

		if (stripos($text, '[video]') !== false)
		{
			require_once(DIR . '/includes/class_bbcode_alt.php');
			$parser = new vB_BbCodeParser_Video_PreParse(vB::get_registry(), array());
			$text = $parser->parse($text);
		}

		if (!empty($options['autoparselinks']))
		{
			$text = $this->convertUrlToBbcode($text);
		}

		return $text;
	}

	/**
	 * Converts URLs into bbcode with [URL]
	 *
	 * @param  string Text potentially containing a URL
	 *
	 * @return string Converted text
	 */
	public function convertUrlToBbcode($messagetext)
	{
		return vB_Library::instance('bbcode')->convertUrlToBbcode($messagetext);
	}

	/**
	 * Determines if the text contains bbcode.
	 *
	 * @param  string Text to test
	 *
	 * @return bool   True if the text contains valid bbcode, false if not.
	 */
	public function hasBbcode($text)
	{
		$tags_list = $this->fetchTagList();
		$pattern = '#\[(' . implode('|', array_keys($tags_list['option'] + $tags_list['no_option'])) . ')[^\]]*\]#siU';
		if (preg_match($pattern, $text))
		{
			return true;
		}
		else
		{
			return false;
		}
	}

	/**
	 * Fetches and parses to html a user's signature
	 *
	 * @deprecated Please use getSignatureInfo instead
	 *
	 * @param int $userid
	 * @param string $signature optionally pass the signature to avoid fetching it again
	 *
	 * @return string the parsed (html) signature
	 */
	public function parseSignature($userid, $signature = false, $skipdupcheck = false)
	{
		if ($userid > 0)
		{
			$sigInfo = $this->getSignatureInfo($userid, $signature, $skipdupcheck);

			return $sigInfo['signature'];
		}
		else
		{
			return '';
		}
	}

	/**
	 * Used by getSignatureInfo and parseSignatures to parse a signature
	 *
	 * @param  int          User ID
	 * @param  string|false (Optional) Signature text or false if unknown
	 * @param  bool         (Optional) Flag to control skipping the dupe check or not.
	 *
	 * @return array        Array containing the parsed signature:
	 *                      <pre>
	 *                      array(
	 *                          signature => parsed signature
	 *                          allowed => array of bbcode tags the user is allowed to use in their signature
	 *                          disabled => array of bbcode tags the user is NOT allowed to use in their signature
	 *                      )
	 *                      </pre>
	 */
	protected function doParseSignature($userid, $signature = false, $skipdupcheck = false)
	{
		if (empty($signature))
		{
			$sigInfo =  vB_Api::instanceInternal('user')->fetchSignature($userid);
			if (empty($sigInfo))
			{
				$sigInfo = array();
			}

			if(empty ($sigInfo['raw']))
			{
				$sigInfo['raw'] = '';
			}
			$signature = $sigInfo['raw'];
		}

		require_once(DIR . '/includes/class_sigparser.php');
		$sig_parser = new vB_SignatureParser(vB::get_registry(), $this->fetchTagList(), $userid);
		$sig_parser->setSkipdupcheck($skipdupcheck);

		// Parse the signature
		$parsed = $sig_parser->parse($signature);
		$perms = $sig_parser->getPerms();

		//only cache the parsed signature if it came from the DB
		if (isset($sigInfo))
		{
			$cacheKey = "vbSig_$userid";
			$cachePermKey = "vbSigPerm_$userid";
			$cache = vB_Cache::instance(vB_Cache::CACHE_STD);

			$cache->write($cacheKey, $parsed, 1440, "userChg_$userid");
			$cache->write($cachePermKey, $perms, 1440, "userChg_$userid");
		}

		return array('signature' => $parsed, 'allowed' => $perms['can'], 'disabled' => $perms['cant']);
	}

	/**
	 * Fetches and parses to html a user's signature
	 *
	 * @param  int    $userid
	 * @param  string $signature optionally pass the signature to avoid fetching it again
	 *
	 * @return array  Array containing the parsed signature: (same as {@see doParseSignature})
	 *                <pre>
	 *                array(
	 *                    signature => parsed HTML signature
	 *                    allowed => array of bbcode tags the user is allowed to use in their signature
	 *                    disabled => array of bbcode tags the user is NOT allowed to use in their signature
	 *                )
	 *                </pre>
	 */
	public function getSignatureInfo($userid, $signature = false, $skipdupcheck = false)
	{
		$userid = intval($userid);
		$cacheKey = "vbSig_$userid";
		$cachePermKey = "vbSigPerm_$userid";
		$cache = vB_Cache::instance(vB_Cache::CACHE_STD);
		$cached_signature = $cache->read($cacheKey);
		$cached_perms = $cache->read($cachePermKey);
		if ($cached_signature !== false AND $cached_perms !== false)
		{
			return array('signature' => $cached_signature, 'allowed' => $cached_perms['can'], 'disabled' => $cached_perms['cant']);
		}

		return $this->doParseSignature($userid, $signature, $skipdupcheck);
	}

	/**
	 * Fetches and parses to html signatures
	 *
	 * @param array  $userIds
	 * @param array  $rawSignatures (Optional) Raw signatures to avoid fetching them again
	 *
	 * @return array the parsed (html) signatures keyed by the userid.
	 */
	public function parseSignatures($userIds, $rawSignatures = array())
	{
		$cleaner = vB::getCleaner();
		$userIds = $cleaner->clean($userIds, vB_Cleaner::TYPE_ARRAY_INT);
		$rawSignatures = $cleaner->clean($rawSignatures, vB_Cleaner::TYPE_ARRAY_STR);

		if (empty($userIds))
		{
			return array();
		}

		$result = array();

		// if we know the signature is empty, we don't even need to query cache
		if (!empty($rawSignatures))
		{
			foreach ($rawSignatures AS $userId => $rawSignature)
			{
				if (empty($rawSignature))
				{
					$result[$userId] = '';
				}
			}
		}

		$remainingUserIds = array_diff($userIds, array_keys($result));
		if (empty($remainingUserIds))
		{
			return $result;
		}

		// now query cache
		$cacheKeys = array();
		foreach($remainingUserIds AS $userId)
		{
			$cacheKeys["vbSig_$userId"] = $userId;
		}

		$cache = vB_Cache::instance(vB_Cache::CACHE_STD);
		$cachedSignatures = $cache->read(array_keys($cacheKeys));

		if ($cachedSignatures)
		{
			foreach ($cachedSignatures AS $cacheKey => $cache)
			{
				if ($cache !== false)
				{
					//note that the cache value is the sig string and not the siginfo array.
					$result[$cacheKeys[$cacheKey]] = $cache;
				}
			}
		}

		$remainingUserIds = array_diff($remainingUserIds, array_keys($result));
		if (empty($remainingUserIds))
		{
			return $result;
		}

		// if we still need signatures do the parsing
		foreach($remainingUserIds AS $userId)
		{
			if (isset($rawSignatures[$userId]))
			{
				$sigInfo = $this->doParseSignature($userId, $rawSignatures[$userId]);
			}
			else
			{
				$sigInfo = $this->doParseSignature($userId);
			}

			$result[$userId] = $sigInfo['signature'];
		}

		return $result;
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 103189 $
|| #######################################################################
\*=========================================================================*/
