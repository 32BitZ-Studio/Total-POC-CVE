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

// ##########################################################################

/**
* Abstract class for handling tags found by vB_TemplateParser.
*/
class vB_TemplateParser_Curly
{
	/**
	* Validate the use of this tag. Can validate any aspects of the tag,
	* including attributes, siblings, parents, and children
	*
	* @param	object	DOM Node of type text
	* @param	object	vB_TemplateParser object
	*
	* @return	array	Array of errors
	*/
	public static function validate(vB_Xml_Node $main_node, vB_TemplateParser $parser)
	{
		return array();
	}

	/**
	* Compile this tag. Note that you must account for children as well.
	*
	* @param	object	DOM Node of type text
	* @param	object	vB_TemplateParser object
	*
	* @return	string	Evalable string
	*/
	public static function compile(vB_Xml_Node $main_node, vB_TemplateParser $parser)
	{
		return $parser->_parse_nodes($main_node->childNodes());
	}

	/**
	* Converts a single attribute to an argument string
	*
	* @param	array	the attribute
	* @param	object	the parser object
	*
	* @return	string	string version of attribute
	*/
	protected static function attributeToString($attribute, $parser)
	{
		if (
			$attribute instanceof vB_CurlyNode AND
			in_array($attribute->value, array('raw', 'var', 'compilesearch', 'phrase', 'rawphrase', 'php', 'math', 'url', 'if', 'urlencode', 'concat', 'stylevar', 'spritepath'))
		)
		{
			//The substr is used to strip the two single quotes and period before and after the variable
			//'' . $block_data['key'] . '')' changed to $block_data['key']
			//This allows for an array in an array to be passed in through the link function
			//{vb:link member, {vb:raw array_variable}, {vb:raw array_variable.array_variable}}
			return substr($parser->_default_node_handler($attribute), 4, -4);
		}
		else
		{
			return '"' . $attribute . '"';

			//TODO: change to the following line when we want to enforce
			//no explicit variables as curly brace parameters
			//	$arguments .= "'" . $attribute . "'";
		}
	}

	/**
	* Compiles an array of attributes into an escaped argument string
	* for use by the template eval engine at runtime
	*
	* @param	array	list of attributes
	* @param	object	the parser object
	*
	* @return	string	argument portion for runtime engine call
	*/
	protected static function getArgumentsFromAttributes($attribute_list, $parser)
	{
		$arguments = '';
		foreach ($attribute_list AS $attribute)
		{
			$arguments .= self::attributeToString($attribute, $parser) . ', ';
		}
		// remove trailing comma and space
		$arguments = substr_replace($arguments ,'',-2);

		return $arguments;
	}
	/**
	 * Handles a node
	* @param	object	the attribute
	* @param	object	the parser object
	* @return	string	the handled argument
	*/
	protected static function handleNode(vB_Xml_Node $attribute, vB_TemplateParser &$parser)
	{
		switch($attribute->value)
		{
			case 'raw':
				// we need to check this: I am deliberately NOT concatenating the raw variable to empty strings, cause this may be an array
				$argument = vB_TemplateParser_CurlyRaw::compile($attribute, $parser);
				break;
			case 'php':
				// we need to check this: I am deliberately NOT concatenating the raw variable to empty strings, cause this may be an array
				$argument = vB_TemplateParser_CurlyPhp::compile($attribute, $parser);
				break;
			case 'var':
				// we need to check this: I am deliberately NOT concatenating the raw variable to empty strings, cause this may be an array
				$argument = vB_TemplateParser_CurlyVar::compile($attribute, $parser);
				break;
			default:
				$argument = "'" . $parser->_default_node_handler($attribute) . "'";
				break;
		}
		return $argument;
	}
}

// ##########################################################################

class vB_TemplateParser_CurlyDate extends vB_TemplateParser_Curly
{
	public static function validate(vB_Xml_Node $main_node, vB_TemplateParser $parser)
	{
		$errors = array();

		if (!array_key_exists(0, $main_node->attributes))
		{
			$errors[] = 'no_timestamp_specified';
		}

		if (sizeof($main_node->attributes) > 4)
		{
			$errors[] = 'too_many_attributes';
		}

		return $errors;
	}

	public static function compile(vB_Xml_Node $main_node, vB_TemplateParser $parser)
	{
		$arguments = self::getArgumentsFromAttributes($main_node->attributes, $parser);

		return 'vB_Template_Runtime::date(' .$arguments . ')';
	}
}
// ##########################################################################

class vB_TemplateParser_CurlyDatetime extends vB_TemplateParser_Curly
{
	public static function validate(vB_Xml_Node $main_node, vB_TemplateParser $parser)
	{
		$errors = array();
		if (!array_key_exists(0, $main_node->attributes))
		{
			$errors[] = 'no_timestamp_specified';
		}

		if (sizeof($main_node->attributes) > 3)
		{
			$errors[] = 'too_many_attributes';
		}

		return $errors;
	}

	public static function compile(vB_Xml_Node $main_node, vB_TemplateParser $parser)
	{
		$arguments = self::getArgumentsFromAttributes($main_node->attributes, $parser);

		return 'vB_Template_Runtime::datetime(' .$arguments . ')';
	}
}

// ##########################################################################

class vB_TemplateParser_CurlyEscapeJS extends vB_TemplateParser_Curly
{
	public static function validate(vB_Xml_Node $main_node, vB_TemplateParser $parser)
	{
		$errors = array();

		if (!array_key_exists(0, $main_node->attributes))
		{
			$errors[] = 'no_variable_specified';
		}

		if (sizeof($main_node->attributes) > 1)
		{
			$errors[] = 'too_many_attributes';
		}
		return $errors;
	}

	public static function compile(vB_Xml_Node $main_node, vB_TemplateParser $parser)
	{
		$arguments = self::getArgumentsFromAttributes($main_node->attributes, $parser);

		return 'vB_Template_Runtime::escapeJS(' .$arguments . ')';
	}
}

// ##########################################################################

class vB_TemplateParser_CurlyIf extends vB_TemplateParser_Curly
{
	public static function validate(vB_Xml_Node $main_node, vB_TemplateParser $parser)
	{
		$errors = array();

		if (!array_key_exists(0, $main_node->attributes))
		{
			$errors[] = 'no_condition_specified';
		}

		if (!array_key_exists(1, $main_node->attributes))
		{
			$errors[] = 'no_true_expression_specified';
		}

		if (sizeof($main_node->attributes) > 3)
		{
			$errors[] = 'too_many_attributes';
		}
		return $errors;
	}

	public static function compile(vB_Xml_Node $main_node, vB_TemplateParser $parser)
	{
		$trueval = self::attributeToString($main_node->attributes[1], $parser);
		$falseval = (isset($main_node->attributes[2]) ? self::attributeToString($main_node->attributes[2], $parser) : '""');
		return '((' . $main_node->attributes[0] . ') ? ' . $trueval . ' : ' . $falseval . ') ';
	}
}

// ##########################################################################

class vB_TemplateParser_CurlyLink extends vB_TemplateParser_Curly
{
	public static function validate(vB_Xml_Node $main_node, vB_TemplateParser $parser)
	{
		$errors = array();

		if (!array_key_exists(0, $main_node->attributes))
		{
			$errors[] = 'no_type_specified';
		}

//we've added a link that doesn't need info
//		if (!array_key_exists(1, $main_node->attributes))
//		{
//			$errors[] = 'no_info_specified';
//		}

		$argument_list = array_slice($main_node->attributes, 1);
		foreach ($argument_list AS $attribute)
		{
			if ($attribute instanceof vB_CurlyNode AND !in_array($attribute->value, array('raw', 'var')))
			{
				$errors[] = 'link_only_accepts_vars';
			}
		}

		if (sizeof($main_node->attributes) > 5)
		{
			$errors[] = 'too_many_attributes';
		}

		return $errors;
	}

	public static function compile(vB_Xml_Node $main_node, vB_TemplateParser $parser)
	{
		$argument_list = array_slice($main_node->attributes, 1);
		$arguments = '';
		foreach ($argument_list AS $attribute)
		{
			if ($attribute instanceof vB_CurlyNode)
			{
				$arguments .= ", " .  self::attributeToString($attribute, $parser);
			}
			else if ($attribute === NULL)
			{
				$arguments .= ', NULL';
			}
			else
			{
				$arguments .= ", '" . $attribute . "'";
			}
		}

		return 'vB_Template_Runtime::linkBuild("' . $main_node->attributes[0] . "\"$arguments" . ')';
	}
}

// ##########################################################################

class vB_TemplateParser_CurlyNumber extends vB_TemplateParser_Curly
{
	public static function validate(vB_Xml_Node $main_node, vB_TemplateParser $parser)
	{
		$errors = array();

		if (!array_key_exists(0, $main_node->attributes))
		{
			$errors[] = 'no_number_specified';
		}

		if (sizeof($main_node->attributes) > 2)
		{
			$errors[] = 'too_many_attributes';
		}

		return $errors;
	}

	public static function compile(vB_Xml_Node $main_node, vB_TemplateParser $parser)
	{
		$arguments = self::getArgumentsFromAttributes($main_node->attributes, $parser);

		return 'vB_Template_Runtime::numberFormat(' .$arguments . ')';
	}
}

// ##########################################################################

class vB_TemplateParser_CurlyPhrase extends vB_TemplateParser_Curly
{
	public static function validate(vB_Xml_Node $main_node, vB_TemplateParser $parser)
	{
		$errors = array();

		if (!array_key_exists(0, $main_node->attributes))
		{
			$errors[] = 'no_phrase_specified';
		}

		return $errors;
	}

	public static function compile(vB_Xml_Node $main_node, vB_TemplateParser $parser)
	{
		$argument_list = array_slice($main_node->attributes, 1);
		$arguments = '';
		foreach ($argument_list AS $attribute)
		{
			if ($attribute instanceof vB_CurlyNode)
			{
				$attribute = $parser->_default_node_handler($attribute);
			}
			$arguments .= ", htmlspecialchars('" . $attribute . "')";
		}

		$string = self::attributeToString($main_node->attributes[0], $parser);
		$value = 'vB_Template_Runtime::parsePhrase(' . $string . $arguments . ')';
		return $value;
	}
}


// ##########################################################################

class vB_TemplateParser_CurlyRawPhrase extends vB_TemplateParser_Curly
{
	public static function validate(vB_Xml_Node $main_node, vB_TemplateParser $parser)
	{
		$errors = array();

		if (!array_key_exists(0, $main_node->attributes))
		{
			$errors[] = 'no_phrase_specified';
		}

		return $errors;
	}

	public static function compile(vB_Xml_Node $main_node, vB_TemplateParser $parser)
	{
		$argument_list = array_slice($main_node->attributes, 1);
		$arguments = '';
		foreach ($argument_list AS $attribute)
		{
			if ($attribute instanceof vB_CurlyNode)
			{
				if ($attribute->value == 'raw')
				{
					// allows to pass an array to phrase
					// we need to check this: I am deliberately NOT concatenating the raw variable to empty strings, cause this may be an array
					$arguments .= ", " . vB_TemplateParser_CurlyRaw::compile($attribute, $parser);
				}
				else
				{
					$arguments .= ", '" . $parser->_default_node_handler($attribute) . "'";
				}
			}
			else
			{
				$arguments .= ", '" . $attribute . "'";
			}
		}

		$string = self::attributeToString($main_node->attributes[0], $parser);

		return 'vB_Template_Runtime::parsePhrase(' . $string . $arguments . ')';
	}
}

// ##########################################################################

class vB_TemplateParser_CurlyTime extends vB_TemplateParser_Curly
{
	public static function validate(vB_Xml_Node $main_node, vB_TemplateParser $parser)
	{
		$errors = array();

		if (!array_key_exists(0, $main_node->attributes))
		{
			$errors[] = 'no_time_specified';
		}

		if (sizeof($main_node->attributes) > 1)
		{
			$errors[] = 'too_many_attributes';
		}

		return $errors;
	}

	public static function compile(vB_Xml_Node $main_node, vB_TemplateParser $parser)
	{
		$arguments = self::getArgumentsFromAttributes($main_node->attributes, $parser);

		return 'vB_Template_Runtime::time(' .$arguments . ')';
	}
}

// ##########################################################################

class vB_TemplateParser_CurlyUrlencode extends vB_TemplateParser_Curly
{
	public static function validate(vB_Xml_Node $main_node, vB_TemplateParser $parser)
	{
		$errors = array();

		if (!array_key_exists(0, $main_node->attributes))
		{
			$errors[] = 'no_variable_specified';
		}

		if (sizeof($main_node->attributes) > 1)
		{
			$errors[] = 'too_many_attributes';
		}

		return $errors;
	}

	public static function compile(vB_Xml_Node $main_node, vB_TemplateParser $parser)
	{
		$arguments = self::getArgumentsFromAttributes($main_node->attributes, $parser);

		return 'vB_Template_Runtime::urlEncode(' . $arguments . ')';
	}
}

// ##########################################################################

class vB_TemplateParser_CurlyStylevar extends vB_TemplateParser_Curly
{
	public static function validate(vB_Xml_Node $main_node, vB_TemplateParser $parser)
	{
		$errors = array();

		if (!array_key_exists(0, $main_node->attributes))
		{
			$errors[] = 'no_variable_specified';
		}

		if (sizeof($main_node->attributes) == 2 AND $main_node->attributes[1] !== 'withUnits')
		{
			$errors[] = 'too_many_attributes';
		}

		if (sizeof($main_node->attributes) > 2)
		{
			$errors[] = 'too_many_attributes';
		}

		return $errors;
	}

	public static function compile(vB_Xml_Node $main_node, vB_TemplateParser $parser)
	{
		$secondParam = '';
		if (!empty($main_node->attributes[1]) AND $main_node->attributes[1] === 'withUnits')
		{
			$secondParam = ', true';
		}

		return 'vB_Template_Runtime::fetchStylevar("' . $main_node->attributes[0] . '"' . $secondParam . ')';
	}
}

// ##########################################################################

class vB_TemplateParser_CurlyCustomStylevar extends vB_TemplateParser_Curly
{
	public static function validate(vB_Xml_Node $main_node, vB_TemplateParser $parser)
	{
		$errors = array();

		if (!array_key_exists(0, $main_node->attributes))
		{
			$errors[] = 'no_variable_specified';
		}

		if (sizeof($main_node->attributes) > 2)
		{
			$errors[] = 'too_many_attributes';
		}

		return $errors;
	}

	public static function compile(vB_Xml_Node $main_node, vB_TemplateParser $parser)
	{
		$user = '';
		if (!empty($main_node->attributes[1]))
		{
			if ($main_node->attributes[1] instanceof vB_CurlyNode)
			{
				// allows to pass an array to phrase
				if (in_array($main_node->attributes[1]->value, array('var', 'raw')))
				{
					$user .= ", " . vB_TemplateParser_CurlyRaw::compile($main_node->attributes[1], $parser);
				}
				else
				{
					$user .= ", '" . $parser->_default_node_handler($main_node->attributes[1]) . "'";
				}
			}
		}
		return 'vB_Template_Runtime::fetchCustomStylevar("' . $main_node->attributes[0] . '"' . $user . ')';
	}
}
// ##########################################################################

class vB_TemplateParser_CurlyHeadlink extends vB_TemplateParser_Curly
{
	public static function validate(vB_Xml_Node $main_node, vB_TemplateParser $parser)
	{
		$errors = array();

		if (!array_key_exists(0, $main_node->attributes))
		{
			$errors[] = 'no_variable_specified';
		}

		return $errors;
	}

	public static function compile(vB_Xml_Node $main_node, vB_TemplateParser $parser)
	{
		$argument_list = $main_node->attributes;
		$arguments = array();
		$separator = '=';
		$i = 0;
		$num_arg = count($argument_list);
		while ($i < $num_arg)
		{
			$argument = $argument_list[$i];
			if($argument instanceof vB_CurlyNode || strpos($argument, $separator) === false) {
				// there is no name for this value

				if ($argument instanceof vB_CurlyNode)
				{
					// we need to check this: I am deliberately NOT concatenating the raw variable to empty strings, cause this may be an array
					$arguments[] = vB_TemplateParser_CurlyRaw::compile($argument, $parser);
				}
				else
				{
					$arguments[] = "'$argument'";
				}
			}
			else
			{
				if ($argument[strlen($argument)-1] === $separator)
				{
					// the value is in the next position
					$str = "'" . substr($argument, 0, -1) . "' => ";
					$i++;
					$attribute = $argument_list[$i];
					if ($attribute instanceof vB_CurlyNode)
					{
						// we need to check this: I am deliberately NOT concatenating the raw variable to empty strings, cause this may be an array
						$str .= self::handleNode($attribute, $parser);
					}
					else
					{
						$str .= "'" . $attribute . "'";
					}
					$arguments[] = $str;
				}
				else
				{
					list($key,$value) = explode($separator, $argument);
					$arguments[] = "'$key' => '$value'";
				}
			}
			$i++;
		}
		$arguments = 'array(' . implode(', ', $arguments) . ')';

		return '\'\' . vB_Template_Runtime::includeHeadLink(' . $arguments . '); $final_rendered .= \'\'';
	}
}

// ##########################################################################

class vB_TemplateParser_CurlyCsspath extends vB_TemplateParser_Curly
{
	public static function validate(vB_Xml_Node $main_node, vB_TemplateParser $parser)
	{
		$errors = array();

		if (!array_key_exists(0, $main_node->attributes))
		{
			$errors[] = 'no_variable_specified';
		}

		return $errors;
	}

	public static function compile(vB_Xml_Node $main_node, vB_TemplateParser $parser)
	{
		$argument_list = $main_node->attributes;
		$arguments = $csslinks = array();
		foreach ($argument_list AS $attribute)
		{
			if ($attribute instanceof vB_CurlyNode)
			{
				$attribute = $parser->_default_node_handler($attribute);
			}
			else
			{
				// We do nothing to $attribute
				//$attribute = $attribute;
			}
			$arguments[] = $attribute;
		}

		return '\'\' . vB_Template_Runtime::includeCssFile(\'' . implode(', ', $arguments) . '\'); $final_rendered .= \'\'';
	}
}

// ##########################################################################

class vB_TemplateParser_CurlySpritepath extends vB_TemplateParser_Curly
{
	public static function validate(vB_Xml_Node $main_node, vB_TemplateParser $parser)
	{
		$errors = array();

		if (!array_key_exists(0, $main_node->attributes))
		{
			$errors[] = 'no_variable_specified';
		}

		return $errors;
	}

	public static function compile(vB_Xml_Node $main_node, vB_TemplateParser $parser)
	{
		$arguments = array();

		$attributes = $main_node->attributes;
		foreach ($attributes AS $attribute)
		{
			if ($attribute instanceof vB_CurlyNode)
			{
				$attribute = $parser->_default_node_handler($attribute);
			}
			$arguments[] = $attribute;
		}

		return '\'\' . vB_Template_Runtime::includeSpriteFile(\'' . implode(', ', $arguments) . '\'); $final_rendered .= \'\'';
	}
}

// ##########################################################################

class vB_TemplateParser_CurlyMath extends vB_TemplateParser_Curly
{
	public static function validate(vB_Xml_Node $main_node, vB_TemplateParser $parser)
	{
		$errors = array();

		if (!array_key_exists(0, $main_node->attributes))
		{
			$errors[] = 'no_variable_specified';
		}

		return $errors;
	}

	public static function compile(vB_Xml_Node $main_node, vB_TemplateParser $parser)
	{

		$argument_list = $main_node->attributes;
		$arguments = array();
		foreach ($argument_list AS $attribute)
		{
			if ($attribute instanceof vB_CurlyNode)
			{
				$attribute = "'" . $parser->_default_node_handler($attribute) . "'";
			}
			else
			{
				$attribute = "'$attribute'";
			}
			$arguments[] =  $attribute;
		}
		$arguments = implode(".", $arguments);
		return 'vB_Template_Runtime::runMaths(' . $arguments . ')';
	}
}

// ##########################################################################

class vB_TemplateParser_CurlyVar extends vB_TemplateParser_Curly
{
	public static function validate(vB_Xml_Node $main_node, vB_TemplateParser $parser)
	{
		return vB_TemplateParser_CurlyRaw::validate($main_node, $parser);
	}

	public static function compile(vB_Xml_Node $main_node, vB_TemplateParser $parser)
	{
		return 'vB_Template_Runtime::vBVar(' . vB_TemplateParser_CurlyRaw::compile($main_node, $parser) . ')';
	}
}

class vB_TemplateParser_CurlyRaw extends vB_TemplateParser_Curly
{
	public static function validate(vB_Xml_Node $main_node, vB_TemplateParser $parser)
	{
		$errors = array();

		if (!array_key_exists(0, $main_node->attributes))
		{
			$errors[] = 'no_variable_specified';
		}

		//"(" isn't a valid php identifier character nor anything that we should be adding
		//for our template markup.  All it can do is cause a php function call which we don't want.
		else if(strpos($main_node->attributes[0], '(') !== false)
		{
			throw new vB_Exception_TemplateFatalError('template_text_not_safe');
		}

		//this doesn't do what we think thought it does.  It looks like it matches against something of the form
		//x.y.z according to php identifier rules.  However, since it isn't anchored it will match anything that
		//has a substring that fits the pattern, which is nearly anything with an alpha character.
		//
		//Unfortunately tightening the match causes existing templates to fail validation -- including some things
		//that actually work.  Leaving this as is doesn't make anything worse so we'll need to handle this another
		//time
		else if (!preg_match('#\$?([a-z_][a-z0-9_]*)(\.([a-z0-9_]+|\$([a-z_][a-z0-9_]*))+)*#i', $main_node->attributes[0]))
		{
			$errors[] = 'invalid_variable_name';
		}

		return $errors;
	}

	public static function compile(vB_Xml_Node $main_node, vB_TemplateParser $parser)
	{
		if($main_node->attributes[0] instanceof vB_CurlyNode)
		{
			$main_node->attributes[0] = vB_TemplateParser_CurlyRaw::compile($main_node->attributes[0], $parser);
		}

		$parts = explode('.', $main_node->attributes[0]);

		$output = $parts[0];

		//this logic is designed to make {vb:raw var.{vb:raw someothervar}} work.
		if (isset($parts[1]))
		{
			//this logic is a serious hack and needs revisiting.
			//1) {vb:raw var.subvar.{vb:raw someothervar}} won't work, we only handle the case of the second .
			//2) We don't actually parse/compile the nested node --  {vb:raw var.{vb:raw someothervar.{vb:raw yetanothervar}}} won't work as expected.
			//there may be other edge cases that do weird things because we aren't being consistant with how we manage this
			if (isset($main_node->attributes[1]) AND $main_node->attributes[1] instanceof vB_CurlyNode AND in_array($main_node->attributes[1]->value, array('raw', 'var')))
			{
				$parts[1] = '$' . $main_node->attributes[1]->attributes[0];
			}
			for ($i = 1; $i < sizeof($parts); $i++)
			{
				if ($parts[$i][0] == '$')
				{
					$output .= '[' . $parts[$i] . ']';
				}
				else if (strpos($parts[$i], '$') !== false)
				{
					$output .= '["' . $parts[$i] . '"]';
				}
				else
				{
					$output .= "['" . $parts[$i] . "']";
				}
			}
		}

		return ($output[0] !== '$' ? '$' : '') . $output;
	}
}

// ##########################################################################

class vB_TemplateParser_CurlyData extends vB_TemplateParser_Curly
{
	public static function validate(vB_Xml_Node $main_node, vB_TemplateParser $parser)
	{
		$errors = array();

		if (!array_key_exists(0, $main_node->attributes))
		{
			$errors[] = 'no_variable_specified';
		}
		else if (!array_key_exists(1, $main_node->attributes) OR !array_key_exists(2, $main_node->attributes))
		{
			// TODO: Add an error phrase for no controller/action specified
		}

		return $errors;
	}

	/**
	 * Internal compile function used by CurlyData and CurlyRawData
	 *
	 * @param	vB_Xml_Node	main node
	 * @param	vB_TemplateParser	Parser
	 * @param	string		The runtime function to use in the compiled output
	 *				This will be 'parseData' or 'parseDataWithErrors', depending
	 *				on if this is called from CurlyData or CurlyRawData.
	 *
	 * @return	Compiled node
	 */
	protected static function compileInternal(vB_Xml_Node $main_node, vB_TemplateParser $parser, $runtimeFunctionName)
	{
		$argument_list = array_slice($main_node->attributes, 1);
		$arguments = array();
		foreach ($argument_list AS $attribute)
		{
			if ($attribute instanceof vB_CurlyNode)
			{
				$arguments[] = self::attributeToString($attribute, $parser);
			}
			else
			{
				$arguments[] .= "'" . $attribute . "'";
			}
		}

		$string = vB_TemplateParser_Tag::compileVar($main_node->attributes[0]);

		// TODO: Is there a better way of doing this?
		// I don't want to stop the concatenation cause here we don't really know the output_var value
		return '\'\'; ' . $string . ' = vB_Template_Runtime::' . $runtimeFunctionName . '(' . implode(', ', $arguments) . '); $final_rendered .= \'\'';
	}

	public static function compile(vB_Xml_Node $main_node, vB_TemplateParser $parser)
	{
		return self::compileInternal($main_node, $parser, 'parseData');
	}

}

// ##########################################################################

class vB_TemplateParser_CurlyRawData extends vB_TemplateParser_CurlyData
{
	public static function compile(vB_Xml_Node $main_node, vB_TemplateParser $parser)
	{
		return self::compileInternal($main_node, $parser, 'parseDataWithErrors');
	}
}

// ##########################################################################

class vB_TemplateParser_CurlyTemplate extends vB_TemplateParser_Curly
{
	public static function validate(vB_Xml_Node $main_node, vB_TemplateParser $parser)
	{
		$errors = array();

		if (!array_key_exists(0, $main_node->attributes))
		{
			// TODO: Add an error phrase for no template specified
			$errors[] = 'no_phrase_specified';
		}

		return $errors;
	}

	public static function compile(vB_Xml_Node $main_node, vB_TemplateParser $parser)
	{
		$argument_list = array_slice($main_node->attributes, 1);
		$arguments = array();
		$separator = '=';
		$i =0;
		$num_arg = count($argument_list);
		while ($i < $num_arg)
		{
			$argument = $argument_list[$i];
			if($argument instanceof vB_CurlyNode || strpos($argument, $separator) === false) {
				// there is no name for this value

				if ($argument instanceof vB_CurlyNode)
				{
					// we need to check this: I am deliberately NOT concatenating the raw variable to empty strings, cause this may be an array
					$arguments[] = vB_TemplateParser_CurlyRaw::compile($argument, $parser);
				}
				else
				{
					$arguments[] = "'$argument'";
				}
			}
			else
			{
				if ($argument[strlen($argument)-1] === $separator)
				{
					// the value is in the next position
					$str = "'" . substr($argument, 0, -1) . "' => ";
					$i++;
					$attribute = $argument_list[$i];
					if ($attribute instanceof vB_CurlyNode)
					{
						// we need to check this: I am deliberately NOT concatenating the raw variable to empty strings, cause this may be an array
						$str .= self::handleNode($attribute, $parser);
					}
					else
					{
						$str .= "'" . $attribute . "'";
					}
					$arguments[] = $str;
				}
				else
				{
					list($key,$value) = explode($separator, $argument);
					$arguments[] = "'$key' => '$value'";
				}
			}
			$i++;
		}
		$arguments = 'array(' . implode(', ', $arguments) . ')';

		if ($main_node->attributes[0] instanceof vB_CurlyNode AND in_array($main_node->attributes[0]->value, array('raw', 'var')))
		{
			//use the compiled version of the node to allow the preferred var/raw syntax to be used.
			//This should not be quoted
			$template_name = vB_TemplateParser_CurlyRaw::compile($main_node->attributes[0], $parser);
			//$string = $main_node->attributes[0]->attributes[0];
			//$string = ($string[0] !== '$' ? '$' : '') . $string;
		}
		else
		{
			$template_name = "'" . $main_node->attributes[0] . "'";
		}

		return 'vB_Template_Runtime::includeTemplate(' . $template_name . ",$arguments" . ')';
	}
}

// ##########################################################################

class vB_TemplateParser_CurlyJs extends vB_TemplateParser_Curly
{
	public static function validate(vB_Xml_Node $main_node, vB_TemplateParser $parser)
	{
		$errors = array();

		if (!array_key_exists(0, $main_node->attributes))
		{
			$errors[] = 'no_variable_specified';
		}

		return $errors;
	}

	public static function compile(vB_Xml_Node $main_node, vB_TemplateParser $parser)
	{
		$argument_list = $main_node->attributes;
		$arguments = array();
		foreach ($argument_list AS $attribute)
		{
			if ($attribute instanceof vB_CurlyNode)
			{
				$attribute = $parser->_default_node_handler($attribute);
			}
			else
			{
				// We do nothing to $attribute
				//$attribute = $attribute;
			}

			$arguments[] = "'" . $attribute . "'";
		}

		if (!empty($arguments) AND ($arguments[0] == "'insert_here'" OR $arguments[0] == "'1'"))
		{
			return 'vB_Template_Runtime::includeJs(' . implode(', ', $arguments) . '); $final_rendered .= \'\'';
		}

		return '\'\'; vB_Template_Runtime::includeJs(' . implode(', ', $arguments) . '); $final_rendered .= \'\'';
	}
}

// ##########################################################################

class vB_TemplateParser_CurlyCssExtra extends vB_TemplateParser_Curly
{
	public static function validate(vB_Xml_Node $main_node, vB_TemplateParser $parser)
	{
		$errors = array();

		if (!array_key_exists(0, $main_node->attributes))
		{
			$errors[] = 'no_variable_specified';
		}

		return $errors;
	}

	public static function compile(vB_Xml_Node $main_node, vB_TemplateParser $parser)
	{
		$argument_list = $main_node->attributes;
		$arguments = $csslinks = array();
		foreach ($argument_list AS $attribute)
		{
			if ($attribute instanceof vB_CurlyNode)
			{
				$attribute = $parser->_default_node_handler($attribute);
			}
			else
			{
				// We do nothing to $attribute
				//$attribute = $attribute;
			}

			$arguments[] = "'" . $attribute . "'";
		}

		return '\'\'; vB_Template_Runtime::includeCss(' . implode(', ', $arguments) . '); $final_rendered .= \'\'';
	}
}

// ##########################################################################

class vB_TemplateParser_CurlyRedirect extends vB_TemplateParser_Curly
{

	public static function validate(vB_Xml_Node $main_node, vB_TemplateParser $parser)
	{
		$errors = array();

		if (!array_key_exists(0, $main_node->attributes))
		{
			$errors[] = 'no_phrase_specified';
		}

		return $errors;
	}

	public static function compile(vB_Xml_Node $main_node, vB_TemplateParser $parser)
	{
		$attribute = $main_node->attributes[0];
		if ($attribute instanceof vB_CurlyNode)
		{
			$url = "'" . $parser->_default_node_handler($attribute) . "'";
		}
		else
		{
			$url = "'" . $attribute . "'";
		}

		// TODO: Is there a better way of doing this?
		// I don't want to stop the concatenation cause here we don't really know the output_var value
		return '\'\'; vB_Template_Runtime::doRedirect(' . $url . '); $final_rendered .= \'\'';
	}

}

// ##########################################################################

class vB_TemplateParser_CurlyUrlAdmincpTemp extends vB_TemplateParser_Curly
{
	public static function validate(vB_Xml_Node $main_node, vB_TemplateParser $parser)
	{
		$errors = array();

		if (!array_key_exists(0, $main_node->attributes))
		{
			$errors[] = 'no_route_specified'; // @todo: needs phrase
		}

		if (sizeof($main_node->attributes) > 1)
		{
			$errors[] = 'too_many_attributes';
		}

		//"(" isn't a valid php identifier character nor anything that we should be adding
		//for our template markup.  All it can do is cause a php function call which we don't want.
		if(is_string($main_node->attributes[0]) AND strpos($main_node->attributes[0], '(') !== false)
		{
			throw new vB_Exception_TemplateFatalError('template_text_not_safe');
		}

		// @todo: enable a second parameter to this tag-- an array of addition parameters for the URL.

		return $errors;
	}

	public static function compile(vB_Xml_Node $main_node, vB_TemplateParser $parser)
	{
		$arguments = self::getArgumentsFromAttributes($main_node->attributes, $parser);

		return 'vB_Template_Runtime::buildUrlAdmincpTemp(' . $arguments . ')';
	}
}

// ##########################################################################

class vB_TemplateParser_CurlySet extends vB_TemplateParser_Curly
{
	public static function validate(vB_Xml_Node $main_node, vB_TemplateParser $parser)
	{
		$errors = array();

		if (!array_key_exists(0, $main_node->attributes))
		{
			$errors[] = 'no_variable_specified';
		}

		if (sizeof($main_node->attributes) > 2)
		{
			$errors[] = 'too_many_attributes';
		}

		return $errors;
	}

	public static function compile(vB_Xml_Node $main_node, vB_TemplateParser $parser)
	{
		$attribute = $main_node->attributes[1];
		if ($attribute instanceof vB_CurlyNode)
		{
			$argument = self::handleNode($attribute, $parser);
		}
		else
		{
			$argument ="'" . $attribute . "'";
		}

		if ($main_node->attributes[0] instanceof vB_CurlyNode AND in_array($main_node->attributes[0]->value, array('raw', 'var')))
		{
			$string = $main_node->attributes[0]->attributes[0];
			$string = ($string[0] !== '$' ? '$' : '') . $string;
		}
		else
		{
			$string = vB_TemplateParser_Tag::compileVar($main_node->attributes[0]);
		}
		return "''; $string = $argument;" . ' $final_rendered .= \'\'';
	}
}

// ##########################################################################

class vB_TemplateParser_CurlyStrCat extends vB_TemplateParser_Curly
{
	public static function validate(vB_Xml_Node $main_node, vB_TemplateParser $parser)
	{
		$errors = array();

		if (!array_key_exists(0, $main_node->attributes))
		{
			$errors[] = 'no_variable_specified';
		}

		if (sizeof($main_node->attributes) < 2)
		{
			$errors[] = 'too_few_attributes';
		}

		return $errors;
	}

	public static function compile(vB_Xml_Node $main_node, vB_TemplateParser $parser)
	{
		$var_name = array_shift($main_node->attributes);
		$argument = "";
		foreach ($main_node->attributes AS $attribute)
		{
			$append = "";
			if ($attribute instanceof vB_CurlyNode)
			{
				$append = self::attributeToString($attribute, $parser);
			}
			else
			{
				$append ="'" . $attribute . "'";
			}
			if(!empty($argument))
			{
				$argument .= '.';
			}
			$argument .= $append;
		}
		if ($var_name instanceof vB_CurlyNode AND in_array($var_name->value, array('raw', 'var')))
		{
			$string = $var_name->attributes[0];
			$string = ($string[0] !== '$' ? '$' : '') . $string;
		}
		else
		{
			$string = vB_TemplateParser_Tag::compileVar($var_name);
		}

		return "''; $string .= $argument;" . ' $final_rendered .= \'\'';
	}
}


class vB_TemplateParser_CurlyConcat extends vB_TemplateParser_Curly
{
	public static function validate(vB_Xml_Node $main_node, vB_TemplateParser $parser)
	{
		$errors = array();

		if (!array_key_exists(0, $main_node->attributes))
		{
			$errors[] = 'no_variable_specified';
		}

		if (sizeof($main_node->attributes) < 2)
		{
			$errors[] = 'too_few_attributes';
		}

		return $errors;
	}

	public static function compile(vB_Xml_Node $main_node, vB_TemplateParser $parser)
	{
		$arguments = array();
		foreach ($main_node->attributes AS $attribute)
		{
			$append = "";
			if ($attribute instanceof vB_CurlyNode)
			{
				$append = self::attributeToString($attribute, $parser);
			}
			else
			{
				$append ="'" . $attribute . "'";
			}
			$arguments[] = $append;
		}
		return implode('.', $arguments);
	}
}

// ##########################################################################

class vB_TemplateParser_CurlyStrRepeat extends vB_TemplateParser_Curly
{
	public static function validate(vB_Xml_Node $main_node, vB_TemplateParser $parser)
	{
		$errors = array();

		if (!array_key_exists(0, $main_node->attributes))
		{
			$errors[] = 'no_variable_specified';
		}

		if (sizeof($main_node->attributes) < 2)
		{
			$errors[] = 'too_few_attributes';
		}

		if (sizeof($main_node->attributes) > 2)
		{
			$errors[] = 'too_many_attributes';
		}

		return $errors;
	}

	public static function compile(vB_Xml_Node $main_node, vB_TemplateParser $parser)
	{
		$var_name = array_shift($main_node->attributes);
		$var_value = array_shift($main_node->attributes);
		$argument = "";

		if ($var_name instanceof vB_CurlyNode AND in_array($var_name->value, array('raw', 'var')))
		{
			$string = vB_TemplateParser_Tag::compileVar($var_name->attributes[0]);
		}
		else
		{
			$string = '$' . $var_name;
		}

		if ($var_value instanceof vB_CurlyNode AND in_array($var_value->value, array('raw', 'var')))
		{
			$value = vB_TemplateParser_Tag::compileVar($var_value->attributes[0]);
		}
		else
		{
			$value = '$' . $var_value;
		}

		return "''; $string = str_repeat($string, intval($value));" . ' $final_rendered .= \'\'';
	}
}

/*
//keep this in our back pocket --
//The curly parser currently requires arguments to be either a string or a curly
//tag.  However in some cases, most notably params to phrases, we'd like to be
//able to pass such a combination.  This fakes it by converting a combination into
//a single curly tag.
class vB_TemplateParser_CurlyCat extends vB_TemplateParser_Curly
{
	public static function compile(vB_Xml_Node $main_node, vB_TemplateParser $parser)
	{
		$string = "";
		foreach ($main_node->attributes AS $attribute)
		{
			if ($attribute instanceof vB_CurlyNode)
			{
				$string .= $parser->_default_node_handler($attribute);
			}
			else
			{
				$string .= $attribute;
			}
		}
		return "'$string'";
	}
}
*/

// ##########################################################################

class vB_TemplateParser_CurlyUrl extends vB_TemplateParser_Curly
{
	public static function validate(vB_Xml_Node $main_node, vB_TemplateParser $parser)
	{
		$errors = array();
		if (!array_key_exists(0, $main_node->attributes))
		{
			$errors[] = 'no_type_specified';
		}

		/*  Second and third params are optionals
		if (!array_key_exists(1, $main_node->attributes))
		{
			$errors[] = 'no_info_specified';
		}*/

		//$argument_list = array_slice($main_node->attributes, 0);
		foreach ($main_node->attributes AS $attribute)
		{
			if ($attribute instanceof vB_CurlyNode AND !in_array($attribute->value, array('raw', 'var')))
			{
				$errors[] = 'url_only_accepts_vars';
			}
		}

		if (sizeof($main_node->attributes) > 4)
		{
			$errors[] = 'too_many_attributes';
		}

		return $errors;
	}

	public static function compile(vB_Xml_Node $main_node, vB_TemplateParser $parser)
	{
	//	$argument_list = array_slice($main_node->attributes, 1);
		$arguments = '';
		foreach ($main_node->attributes AS $attribute)
		{
			if ($attribute instanceof vB_CurlyNode)
			{
				$arguments .= self::attributeToString($attribute, $parser) . ", ";
			}
			else if ($attribute === NULL)
			{
				$arguments .= 'NULL, ';
			}
			else if (is_numeric($attribute))
			{
				$arguments .= $attribute . ", ";
			}
			else
			{
				$arguments .= "'" . $attribute . "', ";
			}
		}
		$arguments = substr($arguments, 0, -2);

		return 'vB_Template_Runtime::vBVar(vB_Template_Runtime::buildUrl(' . $arguments . '))';
	}
}

// ##########################################################################

class vB_TemplateParser_CurlyHook extends vB_TemplateParser_Curly
{
	public static function validate(vB_Xml_Node $main_node, vB_TemplateParser $parser)
	{
		$errors = array();

		if (!array_key_exists(0, $main_node->attributes))
		{
			$errors[] = 'no_hook_specified';
		}

		return $errors;
	}

	public static function compile(vB_Xml_Node $main_node, vB_TemplateParser $parser)
	{
		$attribute = $main_node->attributes[0];
		if ($attribute instanceof vB_CurlyNode)
		{
			$string = self::attributeToString($attribute, $parser);
		}
		else
		{
			$string = "'" . $attribute . "'";
		}

		return 'vB_Template_Runtime::hook(' . $string .', get_defined_vars())';
	}
}

// ##########################################################################

class vB_TemplateParser_CurlyDebugVarDump extends vB_TemplateParser_CurlyRaw
{
	public static function validate(vB_Xml_Node $main_node, vB_TemplateParser $parser)
	{
		return array();
	}

	public static function compile(vB_Xml_Node $main_node, vB_TemplateParser $parser)
	{
		if (isset($main_node->attributes) AND isset($main_node->attributes[0]))
		{
			// output the passed variable, pass true as the second param for less output (uses print_r instead of var_dump)
			$definedVarsCode = '';
			$output = parent::compile($main_node, $parser);
			$printFunc = !empty($main_node->attributes[1]) ? 'print_r' : 'var_dump';
		}
		else
		{
			// output all vars defined in the current scope
			$definedVarsCode = '$VB_DEFINED_VARS = array_keys(get_defined_vars()); ';
			$output = '$VB_DEFINED_VARS';
			$printFunc = 'print_r';
		}

		return '\'\'; ' . $definedVarsCode . 'ob_start(); ' . $printFunc . '(' . $output . '); $final_rendered .= \'<div style="border:3px solid red;padding:10px;margin:10px;max-height:100px;overflow:auto;">' . $printFunc . ': ' . str_replace("'", '\\\'', $output) . '<pre>\' . htmlspecialchars(ob_get_clean()) . \'</pre></div>\'; $final_rendered .= \'\'';

	}
}

// ##########################################################################

class vB_TemplateParser_CurlyDebugTrace extends vB_TemplateParser_CurlyRaw
{
	public static function validate(vB_Xml_Node $main_node, vB_TemplateParser $parser)
	{
		return array();
	}

	public static function compile(vB_Xml_Node $main_node, vB_TemplateParser $parser)
	{
		$output = parent::compile($main_node, $parser);

		return '\'\'; ' . 'ob_start(); debug_print_backtrace(); $final_rendered .= \'<div style="border:3px solid red;padding:10px;margin:10px;max-height:100px;overflow:auto;">Stack trace:<pre>\' . htmlspecialchars(ob_get_clean()) . \'</pre></div>\'; $final_rendered .= \'\'';
	}
}

// ##########################################################################

class vB_TemplateParser_CurlyDebugExit extends vB_TemplateParser_CurlyRaw
{
	public static function validate(vB_Xml_Node $main_node, vB_TemplateParser $parser)
	{
		return array();
	}

	public static function compile(vB_Xml_Node $main_node, vB_TemplateParser $parser)
	{
		return '\'\'; vB_Template_Runtime::debugExit(); $final_rendered .= \'\'';
	}
}

// ##########################################################################

class vB_TemplateParser_CurlyDebugTimer extends vB_TemplateParser_CurlyRaw
{
	public static function validate(vB_Xml_Node $main_node, vB_TemplateParser $parser)
	{
		return array();
	}

	public static function compile(vB_Xml_Node $main_node, vB_TemplateParser $parser)
	{
		// optional timer name (allows having multiple timers)
		if (is_array($main_node->attributes) AND array_key_exists(0, $main_node->attributes))
		{
			$timerName = $main_node->attributes[0];
		}
		else
		{
			$timerName = '';
		}

		return '\'\'; $final_rendered .= vB_Template_Runtime::debugTimer(\'' . str_replace("'", "\\'", $timerName) . '\'); $final_rendered .= \'\'';
	}
}

// ##########################################################################

class vB_TemplateParser_CurlyCompileSearch extends vB_TemplateParser_Curly
{
	public static function validate(vB_Xml_Node $main_node, vB_TemplateParser $parser)
	{
		$errors = array();
		if (!array_key_exists(0, $main_node->attributes))
		{
			$errors[] = 'no_searchstring_specified';
		}

		if (sizeof($main_node->attributes) < 2)
		{
			$errors[] = 'too_few_attributes';
		}

		return $errors;
	}

	public static function compile(vB_Xml_Node $main_node, vB_TemplateParser $parser)
	{
		$arguments = array();
		$searchJSON = array_shift($main_node->attributes);
		foreach ($main_node->attributes AS $attribute)
		{
			if ($attribute instanceof vB_CurlyNode)
			{
				// we need to check this: I am deliberately NOT concatenating the raw variable to empty strings, cause this may be an array
				$arguments[] = vB_TemplateParser_CurlyRaw::compile($attribute, $parser);
			}
			else
			{
				$arguments[] = "'$attribute'";
			}
		}

		if ($searchJSON instanceof vB_CurlyNode AND in_array($searchJSON->value, array('raw', 'var')))
		{
			$string = $searchJSON->attributes[0];
			$string = ($string[0] !== '$' ? '$' : '') . $string;
		}
		else
		{
			$string = $searchJSON;
		}
		$arguments = 'array(' . implode(', ', $arguments) . ')';
		return 'vB_Template_Runtime::parseJSON("' . $string . "\",$arguments" . ')';
	}
}

// ##########################################################################

class vB_TemplateParser_CurlyAction extends vB_TemplateParser_Curly
{

	public static function validate(vB_Xml_Node $main_node, vB_TemplateParser $parser)
	{
		$errors = array();

		if (!array_key_exists(0, $main_node->attributes))
		{
			$errors[] = 'no_variable_specified';
		}
		else if (!array_key_exists(1, $main_node->attributes) OR !array_key_exists(2, $main_node->attributes))
		{
			// TODO: Add an error phrase for no controller/action specified
		}

		return $errors;
	}

	public static function compile(vB_Xml_Node $main_node, vB_TemplateParser $parser)
	{
		$argument_list = array_slice($main_node->attributes, 1);
		$arguments = array();
		foreach ($argument_list AS $attribute)
		{
			if ($attribute instanceof vB_CurlyNode)
			{
				$arguments[] = self::attributeToString($attribute, $parser);
			}
			else
			{
				$arguments[] .= "'" . $attribute . "'";
			}
		}

		$string = $main_node->attributes[0];
		$string = ($string[0] !== '$' ? '$' : '') . $string;

		// TODO: Is there a better way of doing this?
		// I don't want to stop the concatenation cause here we don't really know the output_var value
		return '\'\'; ' . $string . ' = vB_Template_Runtime::parseAction(' . implode(', ', $arguments) . '); $final_rendered .= \'\'';
	}
}

//this is exclusely so that the PHP widget can use it.  It's not to be used generally
class vB_TemplateParser_CurlyPhpeval extends vB_TemplateParser_Curly
{
	public static function validate(vB_Xml_Node $main_node, vB_TemplateParser $parser)
	{
		$errors = array();

		if (!array_key_exists(0, $main_node->attributes))
		{
			$errors[] = 'too_few_attributes';
		}

		return $errors;
	}

	public static function compile(vB_Xml_Node $main_node, vB_TemplateParser $parser)
	{
		$attribute = $main_node->attributes[0];
		if ($attribute instanceof vB_CurlyNode)
		{
			$string = "'" . $parser->_default_node_handler($attribute) . "'";
		}
		else
		{
			$string = "'" . $attribute . "'";
		}

		return 'vB_Template_Runtime::evalPhp(' . $string . ')';
	}
}


class vB_TemplateParser_CurlyPhp extends vB_TemplateParser_Curly
{

	public static function validate(vB_Xml_Node $main_node, vB_TemplateParser $parser)
	{
		$errors = array();
		if (!array_key_exists(0, $main_node->attributes))
		{
			$errors[] = 'no_function_specified';
		}
		$function_name = array_shift($main_node->attributes);
		// TODO we probably want to keep this in sync with other place where
		// we define a list of functions that are safe for use in templates.
		// search for 'get_safe_functions' and 'accepted_functions'
		$accepted_functions = array(
				'array',
				'array_fill_keys',
				'array_intersect',
				'array_intersect_key',
				'array_keys',
				'array_merge',
				'array_pop',
				'array_push',
				'array_shift',
				'array_sum',
				'array_unique',
				'array_unshift',
				'base64_encode',
				'count',
				'current',
				'explode',
				'implode',
				'json_decode',
				'json_encode',
				'range',
				'sprintf',
				'str_pad',
				'str_repeat',
				'strip_tags',
				'strtolower',
				'strtoupper',
				'substr',
				'ltrim',
				'rtrim',
				'trim',
				'vB_String::parseUrl',
				'vB5_String::parseUrl',
				'vB_String::jsonEncodeLocalCharset',
				'vB5_String::jsonEncodeLocalCharset',
				'vbstrtolower',
		);

		if (!in_array($function_name, $accepted_functions))
		{
			$errors[] = 'invalid_function_specified';
		}
		return $errors;
	}

	public static function compile(vB_Xml_Node $main_node, vB_TemplateParser $parser)
	{
		$function_name = array_shift($main_node->attributes);
		$arguments = array();
		foreach ($main_node->attributes AS $attribute)
		{
			if ($attribute instanceof vB_CurlyNode)
			{
				$arguments[] = self::attributeToString($attribute, $parser);
			}
			else
			{
				$arguments[] .= "'" . $attribute . "'";
			}
		}
		return $function_name . '(' . implode(', ', $arguments) . ')';
	}

}

class vB_TemplateParser_CurlySchema extends vB_TemplateParser_Curly
{
	public static function validate(vB_Xml_Node $main_node, vB_TemplateParser $parser)
	{
		$errors = array();

		if (!array_key_exists(0, $main_node->attributes))
		{
			$errors[] = 'no_variable_specified';
		}

		if (sizeof($main_node->attributes) > 1)
		{
			$errors[] = 'too_many_attributes';
		}

		return $errors;
	}

	public static function compile(vB_Xml_Node $main_node, vB_TemplateParser $parser)
	{
		if ($main_node->attributes[0] instanceof vB_CurlyNode AND in_array($main_node->attributes[0]->value, array('raw', 'var')))
		{
			$string = '$' . $main_node->attributes[0]->attributes[0];
		}
		else
		{
			// we should only pass variables
			$string = '';
		}

		return 'vB_Template_Runtime::parseSchema(' . $string . ')';
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 102937 $
|| #######################################################################
\*=========================================================================*/
