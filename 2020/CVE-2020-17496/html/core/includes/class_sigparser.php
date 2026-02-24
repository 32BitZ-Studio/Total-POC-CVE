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

require_once(DIR . '/includes/class_bbcode.php');

/**
* Stack based BB code parser.
*
* @package 		vBulletin
* @version		$Revision: 99787 $
* @date 		$Date: 2018-10-24 17:13:06 -0700 (Wed, 24 Oct 2018) $
*
*/
class vB_SignatureParser extends vB_BbCodeParser
{
	/**
	* User this signature belongs to
	*
	* @var	integer
	*/
	var $userid = 0;

	/**
	* Groupings for tags
	*
	* @var	array
	*/
	var $tag_groups = array();

	/**
	* Errors found in the signature
	*
	* @var	array
	*/
	var $errors = array();

	protected $imgcount = 0;
	protected $skipdupcheck = false;

	private $sigpic_used = false;
	/**
	* Constructor. Sets up the tag permissions list.
	*
	* @param	vB_Registry	Reference to registry object
	* @param	array		The tag_list array for the parent class parser
	* @param	integer		The user this signature belongs to. Required
	* @param	boolean		Whether to append custom tags (they will not be parsed anyway)
	*/
	function __construct(&$registry, $tag_list, $userid, $append_custom_tags = true)
	{
		parent::__construct($registry, $tag_list, false);

		$this->userid = intval($userid);
		if (!$this->userid)
		{
			//this in a very internal error that shouldn't be hit in normal operation.  Not really worth
			//creating a specific phrase for translation.
			throw new vB_Exception_Api('error_x', array('User ID is 0. A signature cannot be parsed unless it belongs to a user.'));
		}
		$usercontext = vB::getUserContext($this->userid);

		$this->parse_userinfo['userid'] = $this->userid;

		$this->tag_groups = array(
			'b'			=> 'basic',
			'i'			=> 'basic',
			'u'			=> 'basic',
			'sub'		=> 'basic',
			'sup'		=> 'basic',
			'hr'		=> 'basic',
			'table'		=> 'basic',

			'color'  => 'color',
			'size'   => 'size',
			'font'   => 'font',

			'left'   => 'align',
			'center' => 'align',
			'right'  => 'align',
			'indent' => 'align',

			'list'   => 'list',

			'url'    => 'link',
			'email'  => 'link',
			'thread' => 'link',
			'post'   => 'link',

			'code'   => 'code',
			'php'    => 'php',
			'html'   => 'html',
			'quote'  => 'quote',
		);

		foreach ($this->tag_groups AS $tag => $tag_group)
		{
			$this->tag_groups[$tag] = 'canbbcode' . $tag_group;
		}

		// 'Allow Image BB Code' perm name isn't prefixed by 'canbbcode' unlike above.
		$this->tag_groups['img'] = 'allowimg';
		/*
			We don't really use these "tag" info for parsing, but rather pass it along to template & ckeditor JS for disabling features
			in a round-about way. It won't really work if 1 feature (Image in this case) controls multiple tags without some refactor
			in ckeditor.js, so I'm leaving it out.
		 */
		// $this->tag_groups['img2'] = 'allowimg';

		foreach ($this->tag_groups AS $tag => $tag_group)
		{
			if ($usercontext->hasPermission('signaturepermissions', $tag_group))
			{
				continue;
			}
			// General if not allowed
			if (isset($this->tag_list['no_option']["$tag"]))
			{
				$this->tag_list['no_option']["$tag"]['callback'] = 'check_bbcode_general';
				unset($this->tag_list['no_option']["$tag"]['html']);
			}

			if (isset($this->tag_list['option']["$tag"]))
			{
				$this->tag_list['option']["$tag"]['callback'] = 'check_bbcode_general';
				unset($this->tag_list['option']["$tag"]['html']);
			}
		}

 		// Specific functions
		$this->tag_list['option']['size']['callback'] = 'check_bbcode_size';
		$this->tag_list['no_option']['img']['callback'] = 'check_bbcode_img';

		// needs to parse sig pics like any other bb code
		$this->tag_list['no_option']['sigpic'] = array(
			'strip_empty' => false,
			'callback' => 'check_bbcode_sigpic'
		);

		if ($append_custom_tags)
		{
			$this->append_custom_tags();
		}
	}

	/**
	 * Collect parser options and misc data to determine how to parse a signature
	 * and determine if errors have occurred.
	 *
	 * @param  string     Unparsed text
	 * @param  int|string ignored but necessary for consistency with class vB_BbCodeParser
	 * @param  bool	      ignored but necessary for consistency with class vB_BbCodeParser
	 * @param  bool	      ignored but necessary for consistency with class vB_BbCodeParser
	 * @param  string     ignored but necessary for consistency with class vB_BbCodeParser
	 * @param  int        ignored but necessary for consistency with class vB_BbCodeParser
	 * @param  bool       ignored but necessary for consistency with class vB_BbCodeParser
	 * @param  string     ignored but necessary for consistency with class vB_BbCodeParser
	 *
	 * @return string     Parsed text
	 */
	function parse($text, $forumid = 0, $allowsmilie = true, $isimgcheck = false, $parsedtext = '', $parsedhasimages = 3, $cachable = false, $htmlstate = null)
	{
		$usercontext = vB::getUserContext($this->userid);
		$dohtml = $usercontext->hasPermission('signaturepermissions', 'allowhtml');
		$dosmilies = $usercontext->hasPermission('signaturepermissions', 'allowsmilies');
		$dobbcode = $usercontext->hasPermission('signaturepermissions', 'canbbcode');
		$dobbimagecode = $usercontext->hasPermission('signaturepermissions', 'allowimg');

		return $this->do_parse($text, $dohtml, $dosmilies, $dobbcode, $dobbimagecode, true, false);
	}

	/**
	 * Returns signature bbcode permissions.
	 *
	 * @return array Signature bbcode permissions
	 *               <pre>
	 *               array()
	 *                   // array of bbcode tags that the user is allowed to use in a signature
	 *                   can => array()
	 *                   // array of bbcode tags that the user is NOT allowed to use in a signature
	 *                   cant => array()
	 *               )
	 *               <pre>
	 */
	public function getPerms()
	{
		$can = $cant = array();
		$usercontext = vB::getUserContext($this->userid);
		$dobbcode = $usercontext->hasPermission('signaturepermissions', 'canbbcode');
		$taglist = $this->tag_groups;

		foreach ($taglist AS $tag => $tag_group)
		{
			if ($dobbcode AND $usercontext->hasPermission('signaturepermissions', $tag_group))
			{
				$can[] = $tag;
			}
			else
			{
				$cant[] = $tag;
			}
		}
		return array('can' => $can, 'cant' => $cant);
	}


	/**
	* BB code callback allowed check
	*
	*/
	function check_bbcode_general($text)
	{
		$tag = $this->current_tag['name'];

		if ($this->tag_groups["$tag"] AND !vB::getUserContext($this->userid)->hasPermission('signaturepermissions', "{$this->tag_groups[$tag]}"))
		{
			$this->errors["$tag"] = 'tag_not_allowed';
		}

		return '';
	}

	/**
	* BB code callback allowed check with size checking
	*
	*/
	function check_bbcode_size($text, $size)
	{
		$size_mod = array();
		foreach ($this->stack AS $stack)
		{
			if ($stack['type'] == 'tag' AND $stack['name'] == 'size')
			{
				$size_mod[] = trim($stack['option']);
			}
		}

		// need to process as a queue, not a stack of open tags
		$base_size = 3;
		foreach (array_reverse($size_mod) AS $tag_size)
		{
			if ($tag_size[0] == '-' OR $tag_size[0] == '+')
			{
				$base_size += $tag_size;
			}
			else
			{
				$base_size = $tag_size;
			}
		}

		// valid sizes can be either numeric or pixel sizes
		// * a numeric size (1-7) corresponds to set pixel sizes ranging from 8px - 72px
		// * a pixel size 8px - 72px, same range as the numeric sizes

		// if we have a pixel size, convert to numeric for the permissions check

		if (!is_numeric($base_size) AND preg_match('#^([0-9]+)px$#si', $base_size, $matches))
		{
			$base_size = $matches[1];

			// these sizes match what's in the bbcode parser
			// 1 => 8px
			// 2 => 10px
			// 3 => 12px
			// 4 => 20px
			// 5 => 28px
			// 6 => 48px
			// 7 => 72px
			if ($base_size < 8)
			{
				$base_size = 0; // less than 8px is invalid
			}
			else if ($base_size == 8)
			{
				$base_size = 1;
			}
			else if ($base_size <= 10)
			{
				$base_size = 2;
			}
			else if ($base_size <= 12)
			{
				$base_size = 3;
			}
			else if ($base_size <= 20)
			{
				$base_size = 4;
			}
			else if ($base_size <= 28)
			{
				$base_size = 5;
			}
			else if ($base_size <= 48)
			{
				$base_size = 6;
			}
			else if ($base_size <= 72)
			{
				$base_size = 7;
			}
			else
			{
				$base_size = 8; // more than 72px is invalid
			}
		}

		$usercontext = vB::getUserContext($this->userid);
		if ($usercontext->hasPermission('signaturepermissions', 'canbbcodesize'))
		{
			if (($sigmaxsizebbcode = $usercontext->getLimit('sigmaxsizebbcode')) > 0 AND $base_size > $sigmaxsizebbcode)
			{
				$this->errors['size'] = 'sig_bbcode_size_tag_too_big';
				$size = $sigmaxsizebbcode;
			}
		}
		else
		{
			$this->errors['size'] = 'tag_not_allowed';
			return '';
		}

		return $this->handle_bbcode_size($text, $size);
	}

	/**
	* BB code callback allowed check for images. Images fall back to links
	* if the image code is disabled, so allow if either is true.
	*
	*/
	function check_bbcode_img($image_path)
	{
		$userContext = vB::getUserContext($this->userid);
		if (
			!($userContext->hasPermission('signaturepermissions', 'allowimg'))
			AND
			!($userContext->hasPermission('signaturepermissions', 'canbbcodelink'))
		)
		{
			$this->errors['img'] = 'tag_not_allowed';
			return '';
		}
		elseif($userContext->hasPermission('signaturepermissions', 'allowimg'))
		{
			$this->imgcount ++;
			$allowedImgs = $userContext->getLimit('sigmaximages');
			if (($allowedImgs > 0) AND ($allowedImgs < $this->imgcount))
			{
				$this->errors['img'] = array('toomanyimages' => array($this->imgcount, $allowedImgs));
				return '';
			}
			return $this->handle_bbcode_img_match($image_path);
		}
		else
		{
			return $this->handle_bbcode_url($image_path, '');
		}
	}

	/**
	* BB code sigpic, returns the <img link.
	*
	*/
	protected function check_bbcode_sigpic($alt_text)
	{
		if (!$sigpic = vB::getDbAssertor()->getRow('vBForum:sigpicnew', array('userid' => $this->userid)))
		{
			// guests can't have sigs (let alone sig pics) so why are we even here?
			if (!in_array('no_sig_pic_to_use', $this->errors))
			{
				$this->errors[] = 'no_sig_pic_to_use';
			}
			return 'sigpic';
		}
		else
		{
			$this->parse_userinfo['sigpic'] = $sigpic;
		}

		if ($this->sigpic_used AND !$this->skipdupcheck)
		{
			// can only use the sigpic once in a signature
			if (!in_array('sig_pic_already_used', $this->errors))
			{
				$this->errors[] = 'sig_pic_already_used';
			}
			return 'sigpic';
		}

		$this->sigpic_used = true;
		return $this->handle_bbcode_sigpic($alt_text);
	}

	public function setSkipdupcheck($skip)
	{
		$this->skipdupcheck = $skip;
	}

} // End Class

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
