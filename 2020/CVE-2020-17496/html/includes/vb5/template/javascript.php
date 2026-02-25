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

class vB5_Template_Javascript
{

	protected static $instance;
	protected $pending = array();

	/**
	 * List of JS files that have already been included on this page load and removed from $this->pending.
	 * @var array
	 */
	protected $previouslyIncluded = array();


	public static function instance()
	{
		if (!isset(self::$instance))
		{
			$c = __CLASS__;
			self::$instance = new $c;
		}

		return self::$instance;
	}

	public function register($files)
	{
		foreach ($files as $file)
		{
			if (!in_array($file, $this->pending))
			{
				$this->pending[] = $file;
			}
		}

		$this->previouslyIncluded = array_unique(array_merge($this->previouslyIncluded, $files));
	}

	public function resetPending()
	{
		// @TODO is $this->existing used anywhere? If not, remove it.
		$this->existing = array();
		$this->pending = array();
	}

	/**
	 * Builds the Javascript links needed to include the passed JS files in the markup.
	 *
	 * @param	array	Array of Javascript files
	 *
	 * @return	string	The complete Javascript links to insert into the markup.
	 */
	public function insertJsInclude($scripts)
	{
		$this->previouslyIncluded = array_unique(array_merge($this->previouslyIncluded, $scripts));

		$config = vB5_Config::instance();
		$vboptions = vB5_Template_Options::instance()->getOptions();
		$vboptions = $vboptions['options'];

		if (!isset($this->jsbundles))
		{
			$this->loadJsBundles();
		}

		if ($config->no_js_bundles)
		{
			foreach ($scripts AS $bundle)
			{
				$removed = false;
				if (strpos($bundle, 'js/') === 0)
				{
					$removed = true;
					$bundle = substr($bundle, 3);
				}
				if (isset($this->jsbundles[$bundle]))
				{
					foreach ($this->jsbundles[$bundle] as $jsfile)
					{
						$expanded[] = $jsfile;
					}
				}
				else
				{
					if ($removed)
					{
						$expanded[] = 'js/' . $bundle;
					}
					else
					{
						$expanded[] = $bundle;
					}
				}
			}
			if (!empty($expanded))
			{
				$scripts = $expanded;
			}
		}

		$baseurl_cdn = $vboptions['cdnurl'];

		if (empty($baseurl_cdn))
		{
			$baseurl_cdn = '';
		}
		else
		{
			$baseurl_cdn .= '/';
		}
		// Ensure that the scheme (http or https) matches the current page request we're on.
		// If the login URL uses https, then the resources on that page, in this case the
		// Javascript, need to use it as well. VBV-12286
		$simpleversion = $vboptions['simpleversion'];
		$prescripts = $scripts;
		$scripts = array();
		foreach ($prescripts AS $js)
		{
			$rollupname = substr($js, 3);
			if (isset($this->jsbundles[$rollupname]))
			{
				$scripts[] = preg_replace("#/([^\.]+).js#", "/$1-$simpleversion.js", $js);
			}
			else
			{
				$joinChar = (strpos($js, '?') === false) ? '?' : '&amp;';
				$scripts[] = $js . $joinChar . 'v=' . $simpleversion;
			}
		}

		$replace = '';
		$loaded = array();
		foreach($scripts AS $js)
		{
			if (!in_array($js, $loaded))
			{
				$replace .= '<script type="text/javascript" src="' . $baseurl_cdn . "$js\"></script>\n";
				$loaded[] = $js;
			}
		}

		return $replace;
	}

	/**
	 * Inserts the JS links into the content
	 *
	 * @param	string	(reference) The page content (markup)
	 */
	public function insertJs(&$content)
	{
		$replace = $this->insertJsInclude($this->pending);

		if (stripos($content, '</body>') !== FALSE)
		{
			$replace .= '</body>';
			$content = str_replace('</body>', $replace, $content);
		}
		else
		{
			$content .= $replace;
		}
	}

	private function loadJsBundles()
	{
		$jsfilelist = Api_InterfaceAbstract::instance()->callApi('product', 'loadProductJsRollups');
		if (empty($jsfilelist['vbulletin']))
		{
			return false;
		}
		else
		{
			$data = $jsfilelist['vbulletin'];
		}

		if (!is_array($data['rollup'][0]))
		{
			$data['rollup'] = array($data['rollup']);
		}

		foreach ($data['rollup'] AS $file)
		{
			if (!is_array($file['template']))
			{
				$file['template'] = array($file['template']);
			}
			foreach ($file['template'] AS $name)
			{
				$vbdefaultjs["$file[name]"] = $file['template'];
			}
		}

		$this->jsbundles = $vbdefaultjs;

		// TODO: Add product xml handling here if we need it.

		return true;
	}

	/**
	 * Returns the JS debugging information displayed in the footer.
	 *
	 * @return	array	Array of debugging information
	 */
	public function getDebugLog()
	{
		$log = array();
		foreach ($this->previouslyIncluded AS $included)
		{
			$bundlekey = strpos($included, 'js/') === 0 ? substr($included, 3) : $included;
			$log[$included] = isset($this->jsbundles[$bundlekey]) ? $this->jsbundles[$bundlekey] : true;
		}

		return array(
			'count' => count($log),
			'files' => $log,
		);
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
