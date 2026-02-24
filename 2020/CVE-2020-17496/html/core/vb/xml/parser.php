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
* vBulletin XML Parsing Object
*
* This class allows the parsing of an XML document to an array
*
* @package 		vBulletin
* @author		Scott MacVicar
* @version		$Revision: 103422 $
* @date 		$Date: 2019-11-12 13:09:19 -0800 (Tue, 12 Nov 2019) $
* @copyright 	http://www.vbulletin.com/license.html
*
*/
class vB_XML_Parser
{
	use vB_Trait_NoSerialize;

	/**
	* Error number (0 for no error)
	*
	* @var	integer
	*/
	protected $error_no = 0;

	/**
	* The actual XML data being processed
	*
	* @var	integer
	*/
	protected $xmldata = '';

	/**
	* The final, outputtable data
	*
	* @var	array
	*/
	protected $parseddata = array();

	/**
	* Intermediate stack value used while parsing.
	*
	* @var	array
	*/
	protected $stack = array();

	/**
	* Current CData being parsed
	*
	* @var	string
	*/
	protected $cdata = '';

	/**
	* Number of tags open currently
	*
	* @var	integer
	*/
	protected $tag_count = 0;

	/**
	* Kludge to include the top level element since this parser was written to not return it and now all of the XML functions assume it to not be there
	*
	* @var	boolean
	*/
	public $include_first_tag = false;

	/**
	* Error code from XML object prior to releases of resources. This needs to be done to avoid a segfault in PHP 4. See Bug#24425
	*
	* @var integer
	*/
	protected $error_code = 0;

	/**
	* Error line number from XML object prior to releases of resources. This needs to be done to avoid a segfault in PHP 4. See Bug#24425
	*
	* @var integer
	*/
	protected $error_line = 0;

	/**
	 * Whether to behave in legacy mode for compatibility.
	 * @TODO: Update dependencies and remove legacy support
	 *
	 * @var bool
	 */
	protected $legacy_mode = true;

	/**
	 * The encoding of the input xml.
	 * This can be overridden by the client code.
	 * @see vB_XML_Parser::set_encoding()
	 *
	 * @var string
	 */
	protected $encoding;

	/**
	 * Specified target encoding.
	 * If this is not set then the target encoding will be resolved from language settings.
	 * @see vB_XML_Parser::set_target_encoding()
	 *
	 * @var string
	 */
	protected $target_encoding;

	/**
	 * Specifies whether to NCR encode multibyte.
	 * By default this is disabled and out of range characters will be displayed incorrectly.
	 *
	 * @var bool
	 */
	protected $ncr_encode;

	/**
	 * Whether to escape html in cdata.
	 *
	 * @var bool
	 */
	protected $escape_html;


	private static $memory_checked = false;

	/**
	 *	Get the list array for a sub element.
	 *
	 *	Consider a standard list:
	 *	<tags>
	 *		<tag>value1</tag>
	 *		<tag>value2</tag>
	 *	<tags>
	 *
	 *	This is interpreted as a list and products array('tag' => array('value2'));
	 *
	 *	However if there is only one item in the list, the xml is ambiguous
	 *	<tags>
	 *		<tag>value1</tag>
	 *	<tags>
	 *
	 *	This is interpreted as a single field of the parent elements
	 *	This is interpreted as a list and products array('tag' => 'value2');
	 *
	 *	There is no way for the parser to know if the latter should be an element with one field, or a
	 *	list with one item.  This function assumes that the value is a list and looks for the
	 *	single element and converts it to a single element list.  If there are multiple elements
	 *	it will automatically force the element into an array.
	 *
	 *	usage is
	 *	vB_XML_Parser::getList($var['tag']);
	 */
	//This is an awkward place to put this function but there isn't a good place for it.
	//It comes up in pretty much any instance of using the arrays produced by this class
	//so we might as well put it here.  This is copied from a function in the xml import
	//code.
	public static function getList($xmlArray)
	{
		if (is_array($xmlArray) AND array_key_exists(0, $xmlArray))
		{
			return $xmlArray;
		}
		else
		{
			return array($xmlArray);
		}
	}

	/**
	* Constructor
	*
	* @param	mixed	XML data or boolean false
	* @param	string	Path to XML file to be parsed
	* @param	bool	Read encoding from XML header
	*/
	public function __construct($xml, $path = '', $readencoding = false, $extend_memory = true)
	{
		//this is a hack, but better than what we had -- we used to extend the memory limit just
		//by including this file, but we now do that on most page loads due to the js rollup
		//feature which reads the rollup xml file to do the mapping.
		//We should only be messing with the memory config when absolutely necesary and
		//only when we know we need to (the xml parser has been traditionally used for largish
		//files that can require consiserably memory to parse and store the resulting DOM).
		//This a least allows us to skip the limit increase when we know we don't need it.
		if ($extend_memory AND !self::$memory_checked)
		{
			vB_Utilities::extendMemoryLimit();
			self::$memory_checked = true;
		}

		if ($xml !== false)
		{
			$this->xmldata = $xml;
		}
		else
		{
			if (empty($path))
			{
				$this->error_no = 1;
			}
			else if (!($this->xmldata = @file_get_contents($path)))
			{
				$this->error_no = 2;
			}
		}

		if (!empty($this->xmldata) AND $readencoding)
		{
			if (preg_match('#(<?xml.*encoding=[\'"])(.*?)([\'"].*?>)#m', $this->xmldata, $match))
			{
				$this->set_encoding(strtoupper($match[2]));
			}
		}
	}

	/**
	* Parses XML document into an array
	*
	* @param	string	Encoding of the input XML
	* @param	bool	Empty the XML data string after parsing
	*
	* @return	mixed	array or false on error
	*/
	function &parse($encoding = 'ISO-8859-1', $emptydata = true)
	{
		// Set our own encoding to that passed
		if (!$this->encoding)
		{
			$this->encoding = $encoding;
		}

		$this->encoding = preg_replace('#^utf(\d+)$#si', 'UTF-\1', $this->encoding);

		// Ensure the target encoding is set
		if (!$this->legacy_mode)
		{
			$this->resolve_target_encoding();
		}

		if (empty($this->xmldata) OR $this->error_no > 0)
		{
			$this->error_code = XML_ERROR_NO_ELEMENTS;
			return false;
		}

		if (!($xml_parser = xml_parser_create($this->encoding)))
		{
			return false;
		}

		xml_parser_set_option($xml_parser, XML_OPTION_SKIP_WHITE, 0);
		xml_parser_set_option($xml_parser, XML_OPTION_CASE_FOLDING, 0);
		xml_set_character_data_handler($xml_parser, array(&$this, 'handle_cdata'));
		xml_set_element_handler($xml_parser, array(&$this, 'handle_element_start'), array(&$this, 'handle_element_end'));

		xml_parse($xml_parser, $this->xmldata, true);
		$err = xml_get_error_code($xml_parser);

		if ($emptydata)
		{
			$this->xmldata = '';
			$this->stack = array();
			$this->cdata = '';
		}

		if ($err)
		{
			$this->error_code = @xml_get_error_code($xml_parser);
			$this->error_line = @xml_get_current_line_number($xml_parser);
			xml_parser_free($xml_parser);
			return false;
		}

		xml_parser_free($xml_parser);
		return $this->parseddata;
	}

	/**
	* Handle encoding issues as well as parsing the XML into an array
	*
	* @return	boolean	Success
	*/
	function parse_xml()
	{
		if ($this->legacy_mode)
		{
			return $this->legacy_parse_xml();
		}

		if (preg_match('#(<?xml.*encoding=[\'"])(.*?)([\'"].*?>)#m', $this->xmldata, $match))
		{
			$encoding = strtoupper($match[2]);

			if ($encoding != 'UTF-8')
			{
				// XML will always be UTF-8 at parse time
				$this->xmldata = str_replace($match[0], "$match[1]UTF-8$match[3]", $this->xmldata);
			}

			if (!$this->encoding)
			{
				$this->encoding = $encoding;
			}
		}
		else
		{
			if (!$this->encoding)
			{
				$this->encoding = 'UTF-8';
			}

			if (strpos($this->xmldata, '<?xml') === false)
			{
				// no xml tag, force one
				$this->xmldata = '<?xml version="1.0" encoding="UTF-8"?>' . "\n" . $this->xmldata;
			}
			else
			{
				// xml tag doesn't have an encoding, which is bad
				$this->xmldata = preg_replace(
					'#(<?xml.*)(\?>)#',
					'\\1 encoding="UTF-8" \\2',
					$this->xmldata
				);
			}
		}

		// Ensure the XML is UTF-8
		if ($this->encoding !== 'UTF-8')
		{
			$this->xmldata = to_utf8($this->xmldata, $this->encoding);
			$this->encoding = 'UTF-8';
		}

		// Parse the XML as UTF-8
		if (!$this->parse())
		{
			return false;
		}

		return $this->parseddata;
	}

	/**
	* Handle encoding issues as well as parsing the XML into an array
	*
	* @return	boolean	Success
	*/
	function legacy_parse_xml()
	{
		// in here we should do conversion from the input to the output.
		if (preg_match('#(<?xml.*encoding=[\'"])(.*?)([\'"].*?>)#m', $this->xmldata, $match))
		{
			$in_encoding = strtoupper($match[2]);
			if ($in_encoding == 'ISO-8859-1')
			{
				// browsers treat the encodings like this, so we need iconv to do so as well
				$in_encoding = 'WINDOWS-1252';
			}

			if (($in_encoding != 'UTF-8' OR strtoupper(vB_Template_Runtime::fetchStyleVar('charset')) != 'UTF-8'))
			{
				// this is necessary in PHP5 when try to output a non-support encoding
				$this->xmldata = str_replace($match[0], "$match[1]ISO-8859-1$match[3]", $this->xmldata);
			}
		}
		else
		{
			$in_encoding = 'UTF-8';

			if (strpos($this->xmldata, '<?xml') === false)
			{
				// this is necessary if there's no XML tag, as PHP5 doesn't know what character set it's in,
				// so special characters die
				$this->xmldata = '<?xml version="1.0" encoding="ISO-8859-1"?>' . "\n" . $this->xmldata;
			}
			else
			{
				// xml tag doesn't have an encoding, which is bad
				$this->xmldata = preg_replace(
					'#(<?xml.*)(\?>)#',
					'\\1 encoding="ISO-8859-1" \\2',
					$this->xmldata
				);
			}

			$in_encoding = 'ISO-8859-1';
		}

		$orig_string = $this->xmldata;

		// this is the current user if its the admincp or the guest session for cron
		// should we stick with this or query the DB for the default language?
		$target_encoding = (strtolower(vB_Template_Runtime::fetchStyleVar('charset')) == 'iso-8859-1' ? 'WINDOWS-1252' : vB_Template_Runtime::fetchStyleVar('charset'));
		$xml_encoding = (($in_encoding != 'UTF-8' OR strtoupper(vB_Template_Runtime::fetchStyleVar('charset')) != 'UTF-8') ? 'ISO-8859-1' : 'UTF-8');
		$iconv_passed = false;

		if (strtoupper($in_encoding) !== strtoupper($target_encoding))
		{
			// now we need to deal with those unknown character sets, meep!
			if (function_exists('iconv') AND $encoded_data = iconv($in_encoding, $target_encoding . '//TRANSLIT', $this->xmldata))
			{
				$iconv_passed = true;
				$this->xmldata =& $encoded_data;
			}

			if (!$iconv_passed AND function_exists('mb_convert_encoding') AND $encoded_data = @mb_convert_encoding($this->xmldata, $target_encoding, $in_encoding))
			{
				$this->xmldata =& $encoded_data;
			}
		}

		if ($this->parse($xml_encoding))
		{
			return true;
		}
		else if ($iconv_passed AND $this->xmldata = iconv($in_encoding, $target_encoding . '//IGNORE', $orig_string))
		{
			// this is probably happening because iconv is chopping off the string for some reason.
			// However, when //TRANSLIT fails, //IGNORE still sometimes works, so try that.
			if ($this->parse($xml_encoding))
			{
				return true;
			}
			else
			{
				return false;
			}
		}
		else
		{
			return false;
		}
	}


	/**
	* XML parser callback. Handles CDATA values.
	*
	* @param	resource	Parser that called this
	* @param	string		The CDATA
	*/
	function handle_cdata(&$parser, $data)
	{
		$this->cdata .= $data;
	}

	/**
	* XML parser callback. Handles tag opens.
	*
	* @param	resource	Parser that called this
	* @param	string		The name of the tag opened
	* @param	array		The tag's attributes
	*/
	function handle_element_start(&$parser, $name, $attribs)
	{
		$this->cdata = '';

		foreach ($attribs AS $key => $val)
		{
			if (preg_match('#&[a-z]+;#i', $val))
			{
				$attribs["$key"] = unhtmlspecialchars($val);
			}
		}

		array_unshift($this->stack, array('name' => $name, 'attribs' => $attribs, 'tag_count' => ++$this->tag_count));
	}

	/**
	* XML parser callback. Handles tag closes.
	*
	* @param	resource	Parser that called this
	* @param	string		The name of the tag closed
	*/
	function handle_element_end(&$parser, $name)
	{
		$tag = array_shift($this->stack);
		if ($tag['name'] != $name)
		{
			// there's no reason this should actually happen -- it'd mean invalid xml
			return;
		}

		$output = $tag['attribs'];

		if (trim($this->cdata) !== '' OR $tag['tag_count'] == $this->tag_count)
		{
			if (sizeof($output) == 0)
			{
				$output = $this->unescape_cdata($this->cdata);
			}
			else
			{
				$this->add_node($output, 'value', $this->unescape_cdata($this->cdata));
			}
		}

		if (isset($this->stack[0]))
		{
			$this->add_node($this->stack[0]['attribs'], $name, $output);
		}
		else
		{
			// popped off the first element
			// this should complete parsing
			if ($this->include_first_tag)
			{
				$this->parseddata = array($name => $output);
			}
			else
			{
				$this->parseddata = $output;
			}
		}


		$this->cdata = '';
	}

	/**
	* Returns parser error string
	*
	* @return	mixed error message
	*/
	function error_string()
	{
		if ($errorstring = @xml_error_string($this->error_code()))
		{
			return $errorstring;
		}
		else
		{
			return 'unknown';
		}
	}

	/**
	* Returns parser error line number
	*
	* @return	int error line number
	*/
	function error_line()
	{
		if ($this->error_line)
		{
				return $this->error_line;
		}
		else
		{
			return 0;
		}
	}

	/**
	* Returns parser error code
	*
	* @return	int error line code
	*/
	function error_code()
	{
		if ($this->error_code)
		{
			return $this->error_code;
		}
		else
		{
			return 0;
		}
	}

	/**
	* Returns parser error number
	*
	* @return	int error number
	*/
	function error_no()
	{
		if ($this->error_no)
		{
			return $this->error_no;
		}
		else
		{
			return 0;
		}
	}

	/**
	* Adds node with appropriate logic, multiple values get added to array where unique are their own entry
	*
	* @param	array	Reference to array node has to be added to
	* @param	string	Name of node
	* @param	string	Value of node
	*
	*/
	function add_node(&$children, $name, $value)
	{
		if (!is_array($children) OR !in_array($name, array_keys($children)))
		{ // not an array or its not currently set
			$children[$name] = $value;
		}
		else if (is_array($children[$name]) AND isset($children[$name][0]))
		{ // its the same tag and is already an array
			$children[$name][] = $value;
		}
		else
		{  // its the same tag but its not been made an array yet
			$children[$name] = array($children[$name]);
			$children[$name][] = $value;
		}
	}

	/**
	* Adds node with appropriate logic, multiple values get added to array where unique are their own entry
	*
	* @param	string	XML to have any of our custom CDATAs to be made into CDATA
	*
	*/
	function unescape_cdata($xml)
	{
		static $find, $replace;

		if (!is_array($find))
		{
			$find = array('�![CDATA[', ']]�', "\r\n", "\n");
			$replace = array('<![CDATA[', ']]>', "\n", "\r\n");
		}

		if (!$this->legacy_mode AND ($this->encoding != $this->target_encoding))
		{
			$xml = $this->encode($xml);
		}

		return str_replace($find, $replace, $xml);
	}


	/**
	 * Overrides the character encoding for the input XML.
	 *
	 * @param	string	charset
	 */
	function set_encoding($encoding)
	{
		$this->encoding = $encoding;
	}


	/**
	 * Sets the target charset encoding for the parsed XML.
	 *
	 * @param	string	Target charset
	 * @param	bool	Whether to ncr encode non ASCII
	 * @param	bool	Whether to escape HTML
	 */
	function set_target_encoding($target_encoding, $ncr_encode = false, $escape_html = false)
	{
		$this->target_encoding = $target_encoding;
		$this->ncr_encode = $ncr_encode;
		$this->escape_html = $escape_html;
	}


	/**
	 * Resolves the target encoding of the output.
	 */
	function resolve_target_encoding()
	{
		if (!$this->target_encoding)
		{
			$this->target_encoding = vB_Template_Runtime::fetchStyleVar('charset');
		}

		$this->target_encoding = strtoupper($this->target_encoding);

		// Prefer WINDOWS-1252 over ISO-8859-1
		if ('ISO-8859-1' == $this->target_encoding)
		{
			$this->target_encoding = 'WINDOWS-1252';
		}
	}

	/**
	 * Encodes data to the target encoding.
	 *
	 * @param	string	UTF-8 string to reencode
	 * @return	string	The reencoded string
	 */
	function encode($data)
	{
		if ($this->encoding == $this->target_encoding)
		{
			return $data;
		}

		// Escape HTML
		if ($this->escape_html)
		{
			$data = @htmlspecialchars($data, ENT_COMPAT, $this->encoding);
		}

		// NCR encode
		if ($this->ncr_encode)
		{
			$data = ncrencode($data, true);
		}

		// for to_charset(). Note, we also require vB_String() downstream.
		require_once(DIR . '/includes/functions.php');

		// Convert to the target charset
		return to_charset($data, $this->encoding, $this->target_encoding);
	}


	/**
	 * Disables legacy mode.
	 * With legacy mode disabled character encoding is handled correctly however
	 * legacy dependencies will break.
	 */
	function disable_legacy_mode($disable = true)
	{
		$this->legacy_mode = !$disable;
	}

	public function get_target_encoding()
	{
		/*
		parse() will only call encode() (which latter does the charset conversion from
		$this->encoding to $this->target_encoding) if it's not in legacy mode.
		So if it's in legacy mode, assume data is in $this->encoding, otherwise
		assume it's in $this->target_encoding
		 */
		if ($this->legacy_mode)
		{
			/*
			Note, without further conversion, the data from parse() will be in
			$this->encoding regardless of the XML's encoding, because we call
			xml_parser_create($this->encoding). Per PHP docs: "
				Starting from PHP 5, the input encoding is automatically detected,
				so that the encoding parameter specifies only the output encoding.
			"
			 */
			return $this->encoding;
		}
		else
		{
			return $this->target_encoding;
		}
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 103422 $
|| #######################################################################
\*=========================================================================*/
