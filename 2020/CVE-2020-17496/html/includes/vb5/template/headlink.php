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

class vB5_Template_HeadLink
{

	protected static $instance;
	protected $pending = array();

	//list taken from http://www.w3.org/TR/html4/struct/links.html#h-12.3
	static $validLinkAttributes = array(
		'vb_module', //only used for checking duplicate 'rel=next' and 'rel=prev'
		'charset',
		'href',
		'hreflang',
		'type',
		'rel',
		'rev',
		'media',
		'id',
		'class',
		'lang',
		'dir',
		'title',
		'style',
		'target',
	);

	public static function instance()
	{
		if (!isset(self::$instance))
		{
			$c = __CLASS__;
			self::$instance = new $c;
		}

		return self::$instance;
	}

	public function register(array $link)
	{
		//remove invalid link attributes
		self::filterLink($link);

		if (empty($this->pending) OR !isset($link['rel']))
		{
			$this->pending[] = $link;
		}
		else if (strcasecmp($link['rel'], 'next') == 0 OR strcasecmp($link['rel'], 'prev') == 0)
		{
			//we need vb_module to prevent duplicates
			if (!isset($link['vb_module']))
			{
				return;
			}

			$found = false;
			foreach ($this->pending AS $key => $pendingLink)
			{
				//only the first module that sets the 'rel=prev/next' attibute is allowed, otherwise, we might have mixed of 'rel=next' and 'rel=prev' for different modules on a page
				if (isset($pendingLink['rel']) AND isset($pendingLink['vb_module']) AND $pendingLink['vb_module'] != $link['vb_module'])
				{
					return;
				}

				if (isset($pendingLink['rel']) AND strcasecmp($link['rel'], $pendingLink['rel']) == 0)
				{
					$this->pending[$key] = $link; //overwrite the entire link tag
					$found = true;
					break;
				}
			}
			if (!$found)
			{
				$this->pending[] = $link;
			}
		}
		else
		{
			$this->pending[] = $link;
		}
	}

	public function resetPending()
	{
		$this->existing = array();
		$this->pending = array();
	}

	public function insertLinks(&$content)
	{
		if (empty($this->pending))
		{
			return;
		}

		$replace = '';

		foreach ($this->pending AS $link)
		{
			unset($link['vb_module']);

			//generate the link tag
			$replace .= '<link';
			foreach ($link AS $attribute => $value)
			{
				$replace .= " $attribute=\"";
				if (strcasecmp($attribute, 'href') == 0)
				{
					$replace .= htmlspecialchars($value);
				}
				else
				{
					$replace .= $value;
				}
				$replace .= '"';
			}
			$replace .= " />\n";
		}

		// insert the <link> tags inside the <head>
		$replace .= '</head>';
		$content = str_replace('</head>', $replace, $content);
	}

	protected function filterLink(&$link)
	{
		foreach ($link AS $attrib => $value)
		{
			if (!in_array($attrib, self::$validLinkAttributes))
			{
				unset($link[$attrib]);
			}
		}
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
