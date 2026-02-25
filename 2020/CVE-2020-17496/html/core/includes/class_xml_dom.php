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

// #############################################################################

class vB_DomDocument
{
	var $node_list = array();

	function __construct($node_list)
	{
		$this->node_list = $node_list;
	}

	function _find_first_node(&$node_list, $type = 'tag')
	{
		foreach ($node_list AS $key)
		{
			$node =& $this->node_list["$key"];
			if ($node['type'] == $type)
			{
				return $key;
			}
		}

		return null;
	}

	function _find_children($key)
	{
		if (is_array($this->node_list["$key"]['children']))
		{
			$return = $this->node_list["$key"]['children'];
			foreach ($this->node_list["$key"]['children'] AS $child)
			{
				$children = $this->_find_children($child);
				if (is_array($children))
				{
					$return += $children;
				}
			}

			return $return;
		}
		else
		{
			return null;
		}
	}

	function documentElement()
	{
		$start = reset($this->node_list);
		if (($key = $this->_find_first_node($start['children'], 'tag')) !== null)
		{
			return new vB_DomNode($this->node_list["$key"], $key, $this);
		}
		else
		{
			return null;
		}
	}

	function childNodes()
	{
		$node_list = array();
		$start = reset($this->node_list);
		foreach ($start['children'] AS $child)
		{
			switch ($this->node_list["$child"]['type'])
			{
				case 'curly':
				{
					$node_list[] = new vB_CurlyNode($this->node_list["$child"], $this);
				}
				break;
				case 'tag':
				default:
				{
					$node_list[] = new vB_DomNode($this->node_list["$child"], $child, $this);
				}
				break;
			}
		}

		return $node_list;
	}

	function getElementById($id)
	{
		foreach ($this->node_list AS $key => $node)
		{
			if (is_array($node['attributes']) AND !empty($node['attributes']['id']) AND $node['attributes']['id'] == $id)
			{
				return new vB_DomNode($node, $key, $this);
			}
		}

		return null;
	}

	function getElementsByTagName($tagname)
	{
		$node_list = array();

		if ($tagname == '*')
		{
			foreach ($this->node_list AS $key => $node)
			{
				if ($node['type'] == 'tag')
				{
					$node_list[] = new vB_DomNode($node, $key, $this);
				}
			}
		}
		else
		{
			foreach ($this->node_list AS $key => $node)
			{
				if ($node['type'] == 'tag' AND $node['value'] == $tagname)
				{
					$node_list[] = new vB_DomNode($node, $key, $this);
				}
			}
		}

		return $node_list;
	}
}

class vB_DomNode implements vB_Xml_Node
{
	private $internal_id = null;
	public $type = '';
	public $value = '';
	public $attributes = null;
	private $parent = null;
	private $children = array();

	private $document = null;

	public function __construct($node, $internal_id, vB_DomDocument $document)
	{
		$this->internal_id = $internal_id;

		$this->type = $node['type'];
		if (isset($node['value']))
		{
			$this->value = $node['value'];
		}
		if (isset($node['attributes']))
		{
			$this->attributes = $node['attributes'];
		}
		if (isset($node['parent']))
		{
			$this->parent = $node['parent'];
		}
		if (!empty($node['children']))
		{
			$this->children = $node['children'];
		}

		$this->document = $document;
	}

	function childNodes()
	{
		$node_list = array();

		foreach ($this->children AS $child)
		{
			switch ($this->document->node_list["$child"]['type'])
			{
				case 'curly':
				{
					$node_list[] = new vB_CurlyNode($this->document->node_list["$child"], $this->document);
				}
				break;
				case 'tag':
				default:
				{
					$node_list[] = new vB_DomNode($this->document->node_list["$child"], $child, $this->document);
				}
				break;
			}
		}
		return $node_list;
	}

	function simplifiedChildNodes()
	{
		$simplified = array();

		// look for children in the form of <tag>text</tag>
		foreach ($this->children AS $childid)
		{
			$child_node = $this->document->node_list["$childid"];
			if ($child_node['type'] == 'tag' AND !empty($child_node['children']) AND count($child_node['children']) == 1)
			{
				// find a child of this node which only has one child itself...
				$grandchildid = reset($child_node['children']);
				$grandchild_node = $this->document->node_list["$grandchildid"];
				if ($grandchild_node['type'] == 'text')
				{
					// ... and that child is a text node
					$simplified["$child_node[value]"] = $grandchild_node['value'];
				}
			}
		}

		return $simplified;
	}

	function firstChild()
	{
		if (!empty($this->children))
		{
			$first = reset($this->children);
			return new vB_DomNode($this->document->node_list["$first"], $first, $this->document);
		}
		else
		{
			return null;
		}
	}

	function lastChild()
	{
		if (!empty($this->children))
		{
			$last = end($this->children);
			return new vB_DomNode($this->document->node_list["$last"], $last, $this->document);
		}
		else
		{
			return null;
		}
	}

	function parentNode()
	{
		if ($this->parent !== null)
		{
			return new vB_DomNode($this->document->node_list[$this->parent], $this->parent, $this->document);
		}
		else
		{
			return null;
		}
	}

	function previousSibling()
	{
		if ($this->parent !== null)
		{
			$siblings = $this->document->node_list[$this->parent]['children'];

			$previous = null;
			$found = false;

			foreach ($siblings AS $sibling)
			{
				if ($sibling == $this->internal_id)
				{
					$found = true;
					break;
				}
				$previous = $sibling;
			}

			if ($found AND $previous)
			{
				return new vB_DomNode($this->document->node_list["$previous"], $previous, $this->document);
			}
		}

		return null;
	}

	function nextSibling()
	{
		if ($this->parent !== null)
		{
			$siblings = $this->document->node_list[$this->parent]['children'];

			$previous = null;
			$next = null;
			$found = false;

			foreach ($siblings AS $sibling)
			{
				if ($previous == $this->internal_id)
				{
					$found = true;
					$next = $sibling;
					break;
				}
				$previous = $sibling;
			}

			if ($found AND $next)
			{
				return new vB_DomNode($this->document->node_list["$next"], $next, $this->document);
			}
		}

		return null;
	}

	function getElementsByTagName($tagname)
	{
		$children = $this->document->_find_children($this->internal_id);
		$node_list = array();

		if ($tagname == '*')
		{
			foreach ($children AS $key)
			{
				$node = $this->document->node_list["$key"];
				if ($node['type'] == 'tag')
				{
					$node_list[] = new vB_DomNode($node, $key, $this->document);
				}
			}
		}
		else
		{
			foreach ($children AS $key)
			{
				$node = $this->document->node_list["$key"];
				if ($node['type'] == 'tag' AND $node['value'] == $tagname)
				{
					$node_list[] = new vB_DomNode($node, $key, $this->document);
				}
			}
		}

		return $node_list;
	}
}

interface vB_Xml_Node
{
}

class vB_CurlyNode implements vB_Xml_Node
{
	public $type = '';
	public $value = '';
	public $attributes = null;
	private $parent = null;

	public function __construct($node, vB_DomDocument $document = null)
	{
		$this->type = $node['type'];
		if (isset($node['value']))
		{
			$this->value = $node['value'];
		}

		if (isset($node['attributes']))
		{
			$this->attributes = $node['attributes'];
		}

		if (isset($node['parent']))
		{
			$this->parent = $node['parent'];
		}

		if (!empty($this->attributes))
		{
			$this->attributes = $this->parseAttributes();
		}
	}

	private function parseAttributes()
	{
		$attributes = array();
		foreach ($this->attributes AS $attribute)
		{
			if (is_array($attribute) AND $attribute['type'] == 'curly')
			{
				$attribute['value'] = $attribute['tag_name'];
				$attributes[] = new vB_CurlyNode($attribute);
			}
			else
			{
				$attributes[] = $attribute;
			}
		}
		return $attributes;
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
