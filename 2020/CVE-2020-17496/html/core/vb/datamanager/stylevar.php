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
* Abstract class to do data save/delete operations for StyleVar.
*
* @package	vBulletin
* @version	$Revision: 103429 $
* @date		$Date: 2019-11-13 15:50:42 -0800 (Wed, 13 Nov 2019) $
*/
class vB_DataManager_StyleVar extends vB_DataManager
{
	/**
	* Array of field names that are bitfields, together with the name of the variable in the registry with the definitions.
	* For example: var $bitfields = array('options' => 'bf_misc_useroptions', 'permissions' => 'bf_misc_moderatorpermissions')
	*
	* @var	array
	*/
	protected $bitfields = array();

	/**
	* The main table this class deals with
	*
	* @var	string
	*/
	public $table = 'stylevar';

	/**
	* The name of the primary ID column that is used to uniquely identify records retrieved.
	* This will be used to build the condition in all update queries!
	*
	* @var string
	*/
	protected $primary_id = 'stylevarid';

	/**
	* Array of recognised and required fields for stylevar, and their types
	*
	* @var	array
	*/
	public $validfields = array(
		'stylevarid' => array(vB_Cleaner::TYPE_STR,       vB_DataManager_Constants::REQ_YES,   vB_DataManager_Constants::VF_METHOD, 'verify_stylevar'),
		'styleid'    => array(vB_Cleaner::TYPE_INT,       vB_DataManager_Constants::REQ_YES,   vB_DataManager_Constants::VF_METHOD),
		'dateline'   => array(vB_Cleaner::TYPE_UNIXTIME,  vB_DataManager_Constants::REQ_AUTO),
		'username'   => array(vB_Cleaner::TYPE_STR,       vB_DataManager_Constants::REQ_NO),
		'value'      => array(vB_Cleaner::TYPE_ARRAY_STR, vB_DataManager_Constants::REQ_NO,    vB_DataManager_Constants::VF_METHOD, 'verify_serialized'),
	);

	/**
	* Local storage, used to house data that we will be serializing into value
	*
	* @var  array
	*/
	protected $local_storage = array();
	protected $childvals = array();

	protected $keyField = array('stylevarid', 'styleid');

	/**
	* Local value telling us what datatype this is; saves the resources of gettype()
	*
	* @var  string
	*/
	public $datatype = '';

	/**
	* Condition template for update query
	*
	* @var	array
	*/
	var $condition_construct = array('stylevarid = "%1$s" AND styleid = %2$d', 'stylevarid', 'styleid');

	/** flag for vb5 transition. A subclass can set this to false and we won't set up $vbulletin **/
	protected $needRegistry = false;

	//cleaner
	protected $cleaner;

	/**
	 * Constructor - Checks for necessity of registry object
	 *
	 * Note that this method will accept only the $errtype parameter (via some magic checking of the parameters)
	 *	and this is the preferred way of calling the datamanager functions.  The registry object is deprecated
	 *	and will be created internally for those managers that still need it.
	 *
	 * @param	vB_Registry	Instance of the vBulletin data registry object - expected to have the database object as one of its $this->db member.
	 * @param	integer		One of the ERRTYPE_x constants
	 */
	public function __construct($registry = NULL, $errtype = NULL)
	{
		parent::__construct($registry, $errtype);
		$this->cleaner = vB::getCleaner();

		// Legacy Hook 'stylevardata_start' Removed //
	}


	//We need to rebuild the
	public function post_save_once($doquery = true)
	{
		parent::post_save_once($doquery);

		require_once DIR . '/includes/adminfunctions_template.php';
		//print_rebuild_style(-1, '', 0, 1, 1, 0, false);
		build_style(-1, '', array(
		'docss' => 0,
		'dostylevars' => 1,
		'doreplacements' => 0,
		'doposteditor' => 0) , '-1,1', '', false, false);
	}


	protected function verify_styleid(&$data)
	{
		if ($data < -1)
		{
			$data = 0;
		}

		return true;
	}

	/**
	* database build method that builds the data into our value field
	*
	* @return	boolean	True on success; false if an error occurred
	*/
	public function build()
	{
		// similar to check required, this verifies actual data for stylevar instead of the datamanager fields
		if (is_array($this->childfields))
		{
			foreach ($this->childfields AS $fieldname => $validfield)
			{
				if ($validfield[vB_DataManager_Constants::VF_REQ] == vB_DataManager_Constants::REQ_YES AND !$this->local_storage["$fieldname"])
				{
					$this->error('required_field_x_missing_or_invalid', $fieldname);
					return false;
				}
			}
			$this->set('value', $this->childvals);
		}
		else
		{
			$this->set('value', array());
		}

		return true;
	}

	/**
	* Sets the supplied data to be part of the data to be build into value.
	*
	* @param	string	The name of the field to which the supplied data should be applied
	* @param	mixed	The data itself
	* @param	boolean	Clean data, or insert it RAW (used for non-arbitrary updates, like posts = posts + 1)
	* @param	boolean	Whether to verify the data with the appropriate function. Still cleans data if previous arg is true.
	* @param	string	Table name to force. Leave as null to use the default table
	*
	* @return	boolean	Returns false if the data is rejected for whatever reason
	*/
	public function set_child($fieldname, $value, $clean = true, $doverify = true, $table = null)
	{
		if ($clean)
		{
			$verify = $this->verify_child($fieldname, $value, $doverify);
			if ($verify === true)
			{
				$errsize = sizeof($this->errors);
				$this->do_set_child($fieldname, $value, $table);
				return true;
			}
			else
			{
				if ($this->childfields["$fieldname"][vB_DataManager_Constants::VF_REQ] AND $errsize == sizeof($this->errors))
				{
					$this->error('required_field_x_missing_or_invalid', $fieldname);
				}
				return $verify;
			}
		}
		else if (isset($this->childfields["$fieldname"]))
		{
			$this->local_storage["$fieldname"] = true;
			$this->do_set_child($fieldname, $value, $table);
			return true;
		}
		else
		{
			return false;
		}
	}

	public function get_child($fieldname)
	{
		return $this->childvals[$fieldname] ?? null;
	}

	/**
	* Verifies that the supplied child data is one of the fields used by this object
	*
	* Also ensures that the data is of the correct type,
	* and attempts to correct errors in the supplied data.
	*
	* @param	string	The name of the field to which the supplied data should be applied
	* @param	mixed	The data itself
	* @param	boolean	Whether to verify the data with the appropriate function. Data is still cleaned though.
	*
	* @return	boolean	Returns true if the data is one of the fields used by this object, and is the correct type (or has been successfully corrected to be so)
	*/
	public function verify_child($fieldname, &$value, $doverify = true)
	{
		if (isset($this->childfields["$fieldname"]))
		{
			$field =& $this->childfields["$fieldname"];

			// clean the value according to its type
			$value = $this->cleaner->clean($value, $field[vB_DataManager_Constants::VF_TYPE]);

			if ($doverify AND isset($field[vB_DataManager_Constants::VF_CODE]))
			{
				if ($field[vB_DataManager_Constants::VF_CODE] === vB_DataManager_Constants::VF_METHOD)
				{
					if (isset($field[vB_DataManager_Constants::VF_METHODNAME]))
					{
						return $this->{$field[vB_DataManager_Constants::VF_METHODNAME]}($value);
					}
					else
					{
						return $this->{'verify_' . $fieldname}($value);
					}
				}
				else
				{
					throw new Exception('Lambda validation functions no longer allowed');
				}
			}
			else
			{
				return true;
			}
		}
		else
		{
			trigger_error("Field <em>'$fieldname'</em> is not defined in <em>\$childfields</em> in class <strong>'" . get_class($this) . "'</strong>", E_USER_ERROR);
			return false;
		}
	}

	/**
	* Takes valid data and sets it as part of the child data to be saved
	*
	* @param	string	The name of the field to which the supplied data should be applied
	* @param	mixed		The data itself
	* @param	string	Table name to force. Leave as null to use the default table
	*/
	public function do_set_child($fieldname, &$value, $table = null)
	{
		$this->local_storage["$fieldname"] = true;
		$this->childvals["$fieldname"] =& $value;
	}

	public function is_child_field($fieldname)
	{
		return (isset($this->childfields[$fieldname]));
	}

	/**
	* Validation functions
	*/


	/**
	 *	Generic function to validate css values
	 *
	 *	This function encodes some basic hueritics to help avoid css injection via stylevars
	 *	It's not necesary if the base function validates more tightly -- for instance if we
	 *	validate against an explicit list then we know unsafe values can't get though.
	 *
	 *	This is not suitable for calling if the value isn't a scalar, but it can be called
	 *	for each scalar value in an array (for instance).
	 *
	 *	If the field doesn't have any other validation, then this function should be called.
	 */
	public function verify_css_scalar($value)
	{
		//this is a vague sort of eyeball requirement.  CSS injection attacks tend to be lengthy
		//(as in kilobytes of rules lengthy) and we don't need to allow any particular field value
		//to be all that long.  This is a nice round number that should be larger than any legitimate
		//purpose but will complicate attempts to get real attacks through even if everything else
		//is bypassed.
		if(strlen($value) > 250)
		{
			return false;
		}

		//these characters allow breaking out of css blocks and adding arbitrary rules
		//This is bad.  If there is some css rule where the braces show up in a legitimate
		//context then a custom rule needs to be written to handle that case.
		if (strpos($value, '{') !== false AND strpos($value, '}') !== false)
		{
			return false;
		}

		return true;
	}

	public function verify_stylevar($stylevarid)
	{
		// check if longer than 25 chars, contains anything other than a-zA-Z1-0
		$return = (bool) preg_match('#^[_a-z][a-z0-9_]*$#i', $stylevarid);
		return $return;
	}

	public function verify_url($url)
	{
		//in theory these should be allowed inside of a quoted string.  But it turns out that
		//it's not that hard to break out of quoted string and there are all kinds of escape
		//sequences that need to be accounted for
		//url('} .test {color: red} .test2 {') won't hurt anything, but
		//url('')} .test {color: red} .test2 {') won't hurt anything, but will inject a rule but
		//url('\')} .test {color: red} .test2 {') won't hurt anything, but won't and
		//url('\\')} .test {color: red} .test2 {') won't hurt anything, but won't and will
		//
		//Trying to accept all valid urls and reject all invalid ones will require a pretty detailed
		//parser to figure out the escapes.  Alternately we could allow quotes and reject any string
		//that contains the delimeter quote even if it might be escaped (and therefore valid) but it's
		//not clear that this is better than rejecting braces.
		//
		//So we'll reject braces and hope for the best.  If braces are needed they can be given via
		//uri escape codes.
		//
		//We don't validate size here because of the possibility of data: uris which can get fairly large
		//legitimately.  I don't know if we officially support them, but they work in the current code.
		if (strpos($url, '{') !== false AND strpos($url, '}') !== false)
		{
			return false;
		}

		return true;
	}

	public function verify_borderstyle($style)
	{
		//not sure if blank is valid but it seems safer to allow it
		//and it was valid before we did the verification.
		$valid = array(
			'',
			'none',
			'hidden',
			'dotted',
			'dashed',
			'solid',
			'double',
			'groove',
			'ridge',
			'inset',
			'outset',
			'initial',
			'inherit',
		);

		return in_array($style, $valid);
	}

	public function verify_color($color)
	{
		//Should probably do a better validation of the color value
		//but the valid values are very complicated and diverse.
		//This should prevent dangerous values even if they aren't
		//necesarily valid colors.
		return $this->verify_css_scalar($color);
	}

	public function verify_image($image)
	{
		//as far as I can tell this is strictly a url type so we might be able to
		//remove this function and set the fields to the verify_url directly.
		//leaving seperate for the time being
		return $this->verify_url($image);
	}

	public function verify_repeat($repeat)
	{
		// return true if it is a valid repeat
		$valid_repeat = array(
			'',
			'repeat',
			'repeat-x',
			'repeat-y',
			'no-repeat'
		);
		return in_array($repeat, $valid_repeat);
	}

	public function verify_gradient_type($type)
	{
		$valid = array(
			'',
			'linear-gradient',
			'radial-gradient',
			'repeating-linear-gradient',
			'repeating-radial-gradient',
		);

		return in_array($type, $valid, true);
	}

	public function verify_gradient_direction($direction)
	{
		$valid = array(
			// options in the select menu (subset of what the spec allows)
			'',
			'to top',
			'to top right',
			'to right',
			'to bottom right',
			'to bottom',
			'to bottom left',
			'to left',
			'to top left',
		);

		return in_array($direction, $valid, true);
	}

	public function verify_fontfamily(&$family)
	{
		//if the whole thing is blank it's okay.
		if(trim($family) == '')
		{
			return true;
		}

		//semi-colons at the end of the font family string are technically not correct.  But they are
		//going to happen a lot.  Let's just remove them (and quietly replace the what we save with
		//the corrected value.  They aren't going to hurt anything.
		$family = rtrim($family, ';');

		$values = explode(',', $family);
		//there isn't a limit in the standard but at some point we're probably
		//looking at something squirrely.
		if(count($values) > 20)
		{
			return false;
		}

		foreach ($values AS $value)
		{
			//No individual entry should be blank. No indiviual entry in the list should be an entire line long.
			$strlen = strlen($value);
			if($strlen == 0 OR $strlen > 100)
			{
				return false;
			}

			$value = trim($value);
			if($value[0] == '"' AND $value[-1] == '"')
			{
				if(strpos($value, '"', 1) != $strlen - 1)
				{
					return false;
				}
			}
			else if($value[0] == "'" AND $value[-1] == "'")
			{
				if(strpos($value, "'", 1) != $strlen - 1)
				{
					return false;
				}
			}
			else
			{
				//don't allow punctuation except dashes and underscores.
				if(!preg_match('#^(?:[^[:punct:]]|[-_])*$#', $value))
				{
					return false;
				}
			}
		}

		return true;
	}

	public function verify_fontweight($weight)
	{
		return true;
	}

	public function verify_fontstyle($style)
	{
		return true;
	}

	public function verify_fontvariant($variant)
	{
		return true;
	}

	public function verify_size($variant)
	{
		return true;
	}

	public function verify_boolean($testValue)
	{
		$valid = array(
			true,
			false,
			1,
			0,
			'1',
			'0',
		);

		return in_array($testValue, $valid, true);
	}

	public function verify_font_size($size)
	{
		$valid_size= array(
			'xx-small',
			'x-small',
			'small',
			'medium',
			'large',
			'x-large',
			'xx-large',
			'smaller',
			'larger',
			'inherit'
		);

		if ($size !== '')
		{
			return (in_array($size, $valid_size) OR is_numeric($size));
		}

		return true;
	}

	public function verify_lineheight($height)
	{
		$valid_keywords = array(
			'normal',
		);

		return (
			// no line-height specified
			$height === ''
			OR
			// keyword based line-height
			in_array($height, $valid_keywords, true)
			OR
			// unitless numeric line-height
			(is_numeric($height) AND $height >= 0)
		);
	}

	public function verify_width($width)
	{
		//this is redundant because the field definition has a cleaner code
		//that will force this.  However if somebody changes that (perhaps to
		//allow things like 100%) this will be a reminder that we need to validate
		//the string to prevent injection
		return is_numeric($width);
	}

	public function verify_height($height)
	{
		//this is redundant because the field definition has a cleaner code
		//that will force this.  However if somebody changes that (perhaps to
		//allow things like 100%) this will be a reminder that we need to validate
		//the string to prevent injection
		return is_numeric($height);
	}

	public function verify_fontlist($fontlist)
	{
		// TODO: validate fontlist is a list of fonts, with "'" wrapped around font names with spaces, and each font separated with a ",".
		return true;
	}

	public function verify_texttransfrom($texttransform)
	{
		$valid = array(
			'none',
			'capitalize',
			'uppercase',
			'lowercase',
			'initial',
			'inherit',
		);

		return in_array($texttransform, $valid, true);
	}

	public function verify_textalign($textalign)
	{
		$valid = array(
			'left'    => true,
			'right'   => true,
			'center'  => true,
			'justify' => true,
			'initial' => true,
			'inherit' => true,
		);

		return isset($valid[$textalign]);
	}

	public function verify_units($unit)
	{
		$valid_units = array(
			'',
			'%',
			'px',
			'pt',
			'em',
			'rem',
			'ch',
			'ex',
			'pc',
			'in',
			'cm',
			'mm',
			'vw',
			'vh',
			'vmin',
			'vmax',
		);

		return in_array($unit, $valid_units);
	}

	public function verify_margin($margin)
	{
		return ($margin === 'auto' OR $margin === strval($margin + 0) OR $margin == '');
	}

	public function verify_background_position($position)
	{
		$valid = array(
			'left',
			'right',
			'bottom',
			'top',
			'center',
			'initial',
			'inherit',
			'', // see note below
		);

		/*
			If background.x or .y is inherited, the value will be an empty string. BUT the key must be set for
			vB_Template_Runtime::outputStyleVar() (used by css.php) to do proper lookups on the inherited
			value for stylevar_x & stylevar_y, so we must allow empty string as a valid value.
		 */
		if (in_array($position, $valid, true))
		{
			// valid string value
			return true;
		}
		else
		{
			// valid int value
			$intPosition = intval($position) + 0;
			return (strval($position) === strval($intPosition));
		}

	}

	public function verify_value_stylevar($stylevar)
	{
		// We will only be letting people change this in debug mode. Therefore, we will assume the user knows
		// what they're doing. Possible issues that may arise that we're explicitly not checking for:
		// * stylevar doesn't exist
		// * stylevar part doesn't exist (my_font_stylevar.image)
		// * infinite loops (potentially across descendant & ancestor styles)


		$stylevar = trim($stylevar);
		//blank is okay.
		if($stylevar == '')
		{
			return true;
		}

		$parts = explode('.', $stylevar);
		if(count($parts) != 2)
		{
			return false;
		}

		//the first part is a stylevar name
		if(!$this->verify_stylevar($parts[0]))
		{
			return false;
		}

		//the second part is a fieldanme
		if(!preg_match('#^[_a-z][a-z0-9_-]*$#i', $parts[1]))
		{
			return false;
		}

		return true;
	}

	public function verify_value_inherit_param_color($value)
	{
		if (is_string($value))
		{
			if (empty($value))
			{
				// allow an empty string
				return true;
			}
			else
			{
				// if it's populated, it needs to be:
				// <color>|<int>, <int>, <int>[, <float>]
				list($color, $params) = explode('|', $value);
				$parts = explode(',', $params);
				$len = count($parts);

				return (
					!empty($color) AND
					preg_match('/^(#|rgba?)/', $color) AND
					($len == 3 OR $len == 4)
				);
			}
		}

		return false;
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 103429 $
|| #######################################################################
\*=========================================================================*/
