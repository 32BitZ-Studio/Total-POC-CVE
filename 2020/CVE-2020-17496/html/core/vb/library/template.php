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
 * vB_Library_Template
 *
 * @package vBLibrary
 * @access public
 */
class vB_Library_Template extends vB_Library
{
	private static $templatecache = array();
	private static $bbcode_style = array('code' => -1, 'html' => -1, 'php' => -1, 'quote' => -1);

	/**
	 * Fetch one template based on its name and style ID.
	 *
	 * @param string $template_name Template name.
	 * @param integer $styleid Style ID. If empty, this method will fetch template from default style.
	 * @return mixed
	 */
	public function fetch($template_name, $styleid = -1, $nopermissioncheck = false)
	{
		if (!empty(self::$templatecache[$template_name]))
		{
			return self::$templatecache[$template_name];
		}

		$fastDs = vB_FastDS::instance();

		if ($fastDs)
		{
			$cached = $fastDs->getTemplates($template_name, $styleid);

			if ($cached)
			{
				self::$templatecache[$template_name] = $cached;
				return $cached;
			}
		}
		$templates = $this->fetchBulk(array($template_name), $styleid, 'compiled', $nopermissioncheck);

		if ($templates[$template_name])
		{
			return $templates[$template_name];
		}

		return false;
	}

	/**
	 * Fetches a bulk of templates from the database
	 *
	 * @param array $template_names List of template names to be fetched.
	 * @param integer $styleid Style ID. If empty, this method will fetch template from default style.
	 *
	 * @return array Array of information about the imported style
	 */
	public function fetchBulk($template_names, $styleid = -1, $type = 'compiled', $nopermissioncheck = false)
	{
		if ($styleid == -1)
		{
			$vboptions = vB::getDatastore()->getValue('options');
			$styleid = $vboptions['styleid'];
		}
		$style = false;

		$response = array();

		if ($type == 'compiled')
		{
			$fastDs = vB_FastDS::instance();

			if ($fastDs)
			{
				$cached = vB_FastDS::instance()->getTemplates($template_names, $styleid);
			}
		}

		foreach ($template_names AS $template)
		{
			// see if we have it in cache already
			if ($type == 'compiled' AND !empty(self::$templatecache[$template]))
			{
				$response[$template] = self::$templatecache[$template];
				continue;
			}
			else if ($type == 'compiled' AND !empty($cached[$template]))
			{
				self::$templatecache[$template] = $cached[$template];
				$response[$template] = $cached[$template];
				continue;
			}
			// load the cache only(once) when we need it
			if (empty($style))
			{
				$style = vB_Library::instance('Style')->fetchStyleRecord($styleid, $nopermissioncheck);
				$templateassoc = $style['templatelist'];
			}
			//handle bad template names -- they should be blank by default.
			if (isset($templateassoc["$template"]))
			{
				$templateids[] = intval($templateassoc["$template"]);
			}
			else
			{
				// @todo: throw an exception if the template doesn't exist and we are in debug mode?
				$response[$template] = '';
			}
		}

		if (!empty($templateids))
		{
			$result = vB::getDbAssertor()->select('template', array('templateid' => $templateids), false,
				array('title', 'textonly', 'template_un', 'template'));

			foreach ($result AS $template)
			{
				if ($type == 'compiled')
				{
					$response[$template['title']] = $this->getTemplateReturn($template);
					self::$templatecache[$template['title']] = $response[$template['title']];
				}
				else
				{
					$response[$template['title']] = $template['template_un'];
				}
			}
		}

		return $response;
	}

	private function getTemplateReturn($template)
	{
		if (!empty($template['textonly']))
		{
			$response = array('textonly' => true, 'template' => $template['template_un']);
		}
		else
		{
			$response = $template['template'];
		}
		return $response;
	}

	/**
	 * Fetches a number of templates from the database and puts them into the templatecache
	 *
	 * @param	array	List of template names to be fetched
	 * @param	string|array	Serialized array or array of template name => template id pairs
	 * @param	bool	Whether to skip adding the bbcode style refs
	 * @param	bool	Whether to force setting the template
	 */
	public function cacheTemplates($templates, $templateidlist, $skip_bbcode_style = false, $force_set = false)
	{
		$vboptions = vB::getDatastore()->getValue('options');
		// vB_Library_Style::switchCssStyle() may pass us a templateidlist that's already unserialized.
		if (!is_array($templateidlist))
		{
			$templateidlist = vB_Utility_Unserialize::unserialize($templateidlist);
		}

		foreach ($templates AS $template)
		{
			if (isset($templateidlist[$template]))
			{
				$templateids[] = intval($templateidlist[$template]);
			}
		}

		if (!empty($templateids))
		{
			$temps = vB::getDbAssertor()->select('template', array('templateid' => $templateids), false,
				array('title', 'textonly', 'template_un', 'template'));

			// cache templates
			foreach ($temps as $temp)
			{
				if (empty(self::$templatecache["$temp[title]"]) OR $force_set)
				{
					self::$templatecache["$temp[title]"] = $this->getTemplateReturn($temp);
				}
			}
		}

		if (!$skip_bbcode_style)
		{
			self::$bbcode_style = array(
				'code'  => &$templateassoc['bbcode_code_styleid'],
				'html'  => &$templateassoc['bbcode_html_styleid'],
				'php'   => &$templateassoc['bbcode_php_styleid'],
				'quote' => &$templateassoc['bbcode_quote_styleid'],
			);
		}
	}

	/**
	 *	Rewrites the file cache for the templates for all styles.
	 */
	public function saveAllTemplatesToFile()
	{
		$template_path = vB::getDatastore()->getOption('template_cache_path');

		$db = vB::getDBAssertor();
		$result = $db->select('template', array(), false, array('templateid', 'template', 'textonly'));

		foreach ($result AS $template)
		{
			$this->saveTemplateToFileSystem($template['templateid'], $template['template'], $template_path, $template['textonly']);
		}

		$fastDs = vB_FastDS::instance();

		//We want to force a fastDS rebuild, but we can't just call rebuild. There may be dual web servers,
		// and calling rebuild only rebuilds one of them.
		$options = vB::getDatastore()->getValue('miscoptions');
		$options['tmtdate'] = vB::getRequest()->getTimeNow();
		vB::getDatastore()->build('miscoptions', serialize($options), 1);
	}

	public function saveTemplatesToFile($templateids)
	{
		$options = vB::getDatastore()->getValue('options');

		if ($options['cache_templates_as_files'] AND $options['template_cache_path'])
		{
			$db = vB::getDBAssertor();
			$result = $db->select('template', array('templateid' => $templateids), false, array('templateid', 'template', 'textonly'));

			foreach ($result AS $template)
			{
				$this->saveTemplateToFileSystem($template['templateid'], $template['template'], $options['template_cache_path'], $template['textonly']);
			}
		}
	}

	public function deleteAllTemplateFiles()
	{
		$template_path = vB::getDatastore()->getOption('template_cache_path');

		$db = vB::getDBAssertor();
		$result = $db->select('template', array(), false, array('templateid', 'template'));

		foreach ($result AS $template)
		{
			$this->deleteTemplateFromFileSystem($template['templateid'], $template_path);
		}
	}

	private function saveTemplateToFileSystem($templateid, $compiled_template, $template_path, $textonly = false)
	{
		$template_name = "template$templateid.php";

		$path = $template_path;
		if(!$this->isAbsolutePath($path))
		{
			$path = DIR . '/' . $template_path;
		}

		$real_path = realpath($path);
		if ($real_path === false)
		{
			@mkdir($path, 0777, true);
			$real_path = realpath($path);

			if ($real_path === false)
			{
				throw new vB_Exception_Api('could_not_cache_template', array($templateid, $template_path, $template_name));
			}
		}

		$template_file = $real_path . "/$template_name";

		//determine if we can write to the provided location
		$can_write_template = false;

		//file is writable
		if (is_writable($template_file))
		{
			$can_write_template = true;
		}
		else
		{
			//file doesn't exist and directory is writeable
			if (!file_exists($template_file) AND is_writeable($real_path))
			{
				$can_write_template = true;
			}
		}

		//if we can write, try to write
		$file = false;
		if ($can_write_template)
		{
			$file = fopen($template_file, 'w+');
			if ($file)
			{
				//hack to deal with the fact that the presentation layer has a separate runtime class.
				$compiled_template = str_replace('vB_Template_Runtime', 'vB5_Template_Runtime', $compiled_template);

				if (empty($textonly))
				{
					fwrite($file, "<?php \nif (!class_exists('vB5_Template', false)) throw new Exception('direct access error');\n");
				}
				fwrite($file, $compiled_template);
				fclose($file);
			}
		}

		if (!$can_write_template OR !$file)
		{
			throw new vB_Exception_Api('could_not_cache_template', array($templateid, $template_path, $template_name));
		}
	}

	//this is a candidate to move elsewhere, perhaps the string utility class.
	private function isAbsolutePath($path)
	{
		if (!strlen($path))
		{
			return false;
		}

		//This is sufficient, but not necesary.
		if (realpath($path) == $path)
		{
			return true;
		}

		//windows drive lettering
		if (preg_match('#^[a-zA-Z]:\\\\#', $path))
		{
			return true;
		}

		// A path starting with / or \ is absolute; anything else is relative.
		return ($path[0] == '/' || $path[0] == '\\');
	}

	public function deleteTemplateFromFileSystem($templateid, $template_path)
	{
		$template_name = "template$templateid.php";

		$real_path = realpath($template_path);
		if ($real_path === false)
		{
			$real_path = realpath(DIR . '/' . $template_path);
			if ($real_path === false)
			{
				//fail quietly on delete, not much we can do about it.
				return;
			}
		}

		$template_file = $real_path . "/$template_name";

		//is_writable not reliable on windows.
		if (!(strtoupper(substr(PHP_OS, 0, 3)) == 'WIN') AND !is_writable($template_file))
		{
			return;
		}

		if (file_exists($template_file))
		{
			unlink($template_file);
		}
	}

	/**
	 * Process the replacement variables.
	 *
	 * @param string The html to be processed
	 * @param integer The styleid to use.
	 *
	 * @return string The processed output
	 */
	public function processReplacementVars($html, $styleid = -1)
	{
		$style = vB_Library::instance('Style')->fetchStyleByID($styleid, false);

		if (!empty($style['replacements']))
		{
			if (!isset($replacementvars["$style[styleid]"]))
			{
				$replacementvars[$style['styleid']] = @unserialize($style['replacements']);
			}

			if (is_array($replacementvars[$style['styleid']]) AND !empty($replacementvars[$style['styleid']]))
			{
				$html = preg_replace(array_keys($replacementvars[$style['styleid']]), $replacementvars[$style['styleid']], $html);
			}
		}

		return $html;
	}


	/**
	 * Insert a new template
	 *
	 * @param integer $dostyleid Style ID which the new template belongs to.
	 * @param string $title Template name.
	 * @param string $content Template content.
	 * @param string $product The product ID which the template belongs to.
	 * @param boolean $savehistory Whether to save the change in template history.
	 * @param string $histcomment Comment of the change to be saved to template history.
	 * @param array $extra extra parameters for the function.
	 *	 			Actually uses params:
	 * 				forcenotextonly  which bypasses the canadmintemplate permission
	 * 				textonly  which sets template text only setting
	 * @return integer New inserted template ID.
	 */
	public function insert
	(
		$dostyleid,
		$title,
		$content,
		$product = 'vbulletin',
		$savehistory = false,
		$histcomment = '',
		$forcesaveonerror = false,
		$extra = array()
	)
	{
		$dostyleid = intval($dostyleid);
		$title = trim($title);
		$content = trim($content);
		$product = trim($product);
		$histcomment = trim($histcomment);
		$userinfo = vB::getCurrentSession()->fetch_userinfo();
		$timenow = vB::getRequest()->getTimeNow();

		//bad things happen if we don't have a valid product at this point.
		//If its blank (which is itself an error) recover with a default that keeps thee
		//system functional
		if (!$product)
		{
			$product = 'vbulletin';
		}

		if (!$title)
		{
			throw new vB_Exception_Api('please_complete_required_fields');
		}

		require_once(DIR . '/includes/adminfunctions.php');		// Required for fetch_product_list()

		// Compile template
		if (!empty($extra['textonly']))
		{
			$template = $content;
		}
		else
		{
			$template = $this->compile($content, $forcesaveonerror);
		}
		// TODO: Product API
		$full_product_info = fetch_product_list(true);

		$result = vB::getDbAssertor()->assertQuery('template_get_existing', array('title' => $title));

		foreach ($result as $curtemplate)
		{
			$exists["$curtemplate[styleid]"] = $curtemplate;
		}

		// work out what we should be doing with the product field
		if ($exists['-1'] AND $dostyleid != -1)
		{
			// there is already a template with this name in the master set - don't allow a different product id
			$product = $exists['-1']['product'];
		}
		else if ($dostyleid != -1)
		{
			// we are not adding a new template to the master set - only allow the default product id
			$product = 'vbulletin';
		}
		else
		{
			// allow this - we are adding a totally new template to the master set
		}

		$stylelib = vB_Library::instance('Style');

		// check if template already exists
		if (!$exists[$dostyleid])
		{
			$templateid = $this->saveTemplate(
				$title,
				$template,
				$content,
				$timenow,
				$userinfo['username'],
				$full_product_info[$product]['version'],
				$product,
				null,
				null,
				$dostyleid,
				$savehistory,
				$histcomment,
				$extra
			);

			// now to update the template id list for this style and all its dependents...
			$stylelib->buildStyle($dostyleid, $title, array(
				'docss' => 0,
				'dostylevars' => 0,
				'doreplacements' => 0,
				'doposteditor' => 0
			), false);
		}
		else
		{
			throw new vB_Exception_Api('template_x_exists_error', array($title, $curtemplate['templateid']));
		}

		if ($savehistory)
		{
			$result = vB::getDbAssertor()->assertQuery('template_savehistory', array(
				'dostyleid' 	=> $dostyleid,
				'title' 		=> $title,
				'template_un' 	=> $content,
				'dateline'		=> $timenow,
				'username'		=> $userinfo['username'],
				'version'		=> $full_product_info[$product]['version'],
				'comment'		=> $histcomment,
			));
		}

		$stylelib->buildStyleDatastore();
		return $templateid;
	}


	/**
	 *	Insert a replacement var
	 *
	 *	@param	integer	$dostyleid
	 *	@param	string	$findtext
	 *	@param	string	$replacetext
	 * 	@param	string	$product The product ID which the replacement var belongs to.
	 *
	 *	@return integer -- The id of the newly created replacement var
	 *
	 *	@throws vB_Exception_Api
	 *		'replacement_x_exists' -- var with that title & styleid already exists
	 *		'replacmentvar_template_x_exists' -- the title matches the title of a non stylevar template
	 *			which can cause potential conflicts.
	 */
	public function insertReplacementVar($dostyleid, $findtext, $replacetext)
	{
		$userinfo = vB::getCurrentSession()->fetch_userinfo();
		$options = vB::getDatastore()->getValue('options');

		$template = $this->fetchReplacementVar($findtext, $dostyleid);
		if ($template)
		{
			throw new vB_Exception_Api('replacement_x_exists', array($findtext, $dostyleid));
		}

		//do not allow a replacement var with the same name as non replacement var template
		//they will conflict and cause odd behavior on the site.  The reason for this is that
		//each style has a compiled list of 'title' => templateid including inheritance which
		//means that two templates with the same title will cause all manner of problems in that
		//list (especially since the replacement var will get used instead of the template in
		//the template render code...)
		//
		//This can be remove when we fix VBV-14598
		$existing = vB::getDbAssertor()->getRow('template', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
			vB_dB_Query::CONDITIONS_KEY => array(
				'title' => $findtext,
				array('field' => 'templatetype', 'value' => 'replacement', 'operator' =>  vB_dB_Query::OPERATOR_NE)
			),
			vB_dB_Query::COLUMNS_KEY => array('templateid')
		));
		if ($existing)
		{
			throw new vB_Exception_Api('replacmentvar_template_x_exists', array($findtext));
		}

		$id = vB::getDbAssertor()->assertQuery('template', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_INSERT,
			'styleid' => $dostyleid,
			'templatetype' => 'replacement',
			'title' => $findtext,
			'template' => $replacetext,
			'username' => $userinfo['username'],
			'version' => $options['templateversion'],
			'product' => 'vbulletin',
			'dateline' => vB::getRequest()->getTimeNow()
		));

		$stylelib = vB_Library::instance('Style');

		// now to update the template id list for this style and all its dependents...
		$stylelib->buildStyle($dostyleid, $findtext, array(
			'docss' => 0,
			'dostylevars' => 0,
			'doreplacements' => 1,
			'doposteditor' => 0
		), false);

		$stylelib->buildStyleDatastore();
		return $id;
	}


	/**
	 *	Update the replacement text for a replacement var
	 *
	 *	@param integer $replacevarid -- template id for the replace var
	 *	@paramstring $replacetext
	 *
	 * 	@return boolean
	 */
	public function updateReplacementVar($replacevarid, $replacetext)
	{
		$userinfo = vB::getCurrentSession()->fetch_userinfo();
		$options = vB::getDatastore()->getValue('options');

		$count = vB::getDbAssertor()->assertQuery('template', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_UPDATE,
			'template' => $replacetext,
			'username' => $userinfo['username'],
			'version' => $options['templateversion'],
			'product' => 'vbulletin',
			'dateline' => vB::getRequest()->getTimeNow(),
			 vB_dB_Query::CONDITIONS_KEY => array(
				'templateid' => $replacevarid,
				'templatetype' => 'replacement',
			 )
		));

		if ($count)
		{
			$template = $this->fetchReplacementVarById($replacevarid);
			$stylelib = vB_Library::instance('Style');

			// now to update the template id list for this style and all its dependents...
			$stylelib->buildStyle($template['styleid'], $template['title'], array(
				'docss' => 0,
				'dostylevars' => 0,
				'doreplacements' => 1,
				'doposteditor' => 0
			), false);
			$stylelib->buildStyleDatastore();
		}

		return ($count > 0);
	}


	/**
	 *	Find the replacement var by title & styleid
	 *
	 *	@param string $findtext
	 *	@param integer $dostyleid
	 *	@param boolean $inherit -- do we check for variables in parent styles?
	 *
	 *	@return false|array -- template record for the replacement variable
	 *		string title
	 *		integer styleid
	 *		integer dateline
	 *		string username
	 *		string template
	 *		string template_un
	 *		string version
	 */
	public function fetchReplacementVar($findtext, $dostyleid, $inherit=false)
	{
		//masterstyle (-1) doesn't have a style record so this branch won't work.  On the other hand
		//it can't have a parent style either so we can treat the inherit case as if it were not inherited.
		if ($inherit AND $dostyleid != -1)
		{
			$style = vB_Library::instance('Style')->fetchStyleByID($dostyleid, true);

			$templateids = $style['templatelist'];
			if (is_string($templateids))
			{
				$templateids = unserialize($templateids);
			}
			return $this->fetchReplacementVarById($templateids[$findtext]);
		}
		else
		{
			$existing = vB::getDbAssertor()->getRow('template', array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
				'styleid' => $dostyleid,
				'title' => $findtext,
				'templatetype' => 'replacement',
				vB_dB_Query::COLUMNS_KEY => array('title', 'styleid', 'dateline', 'username', 'template', 'template_un', 'version')
			));

			if (is_null($existing))
			{
				return false;
			}

			return $existing;
		}
	}

 /**
	 *	Find the replacement var by templateid
	 *
	 *	@param integer $replacevarid
	 *
	 *	@return false|array -- template record for the replacement variable
	 *		string title
	 *		integer styleid
	 *		integer dateline
	 *		string username
	 *		string template
	 *		string template_un
	 *		string version
	 */
	public function fetchReplacementVarById($replacevarid)
	{
		//use explicit conditions key to work around assertor bug when
		//one of the filters is the primary key
		$existing = vB::getDbAssertor()->getRow('template', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
			 vB_dB_Query::CONDITIONS_KEY => array(
				'templateid' => $replacevarid,
				'templatetype' => 'replacement'
			),
			vB_dB_Query::COLUMNS_KEY => array('title', 'styleid', 'dateline', 'username', 'template', 'template_un', 'version')
		));

		if (is_null($existing))
		{
			return false;
		}

		return $existing;
	}


	/**
	 * Compile a template.
	 *
	 * @param string $template_un The uncompiled content of a template.
	 */
	public function compile($template, $forcesaveonerror)
	{
		// @todo
		// Incorrect hack warning!!!
		// The legacy code in class_template_parser.php needs this to be set
		// but it apparrently does not actually need to be an instance of the
		// legacy db class for purposes of compiling a template.
		if (empty($GLOBALS['vbulletin']->db))
		{
			$GLOBALS['vbulletin']->db = false;
		}

		require_once(DIR . '/includes/class_template_parser.php');
		require_once(DIR . '/includes/adminfunctions_template.php');	// Required for check_template_errors()
		$parser = new vB_TemplateParser($template);

		try
		{
			$parser->validate($errors);
		}
		catch (vB_Exception_TemplateFatalError $e)
		{
			throw new vB_Exception_Api($e->getMessage());
		}

		$template = $parser->compile();
		if (!$forcesaveonerror AND !empty($errors))
		{
			throw new vB_Exception_Api('template_compile_error', array($errors));
		}

		//extra set of error checking.  This can be skipped in many situations.
		if (!$forcesaveonerror)
		{
			$errors = check_template_errors($template);
			if (!empty($errors))
			{
				$vb5_config = &vB::getConfig();
				if (!is_array($errors) AND $vb5_config['Misc']['debug'])
				{
					// show compiled template code with line numbers to debug the problem
					$errors .= '<h4>Compiled Template Code:</h4><div style="height:200px; overflow:auto; border:1px solid silver; font-style:normal; font-family:Courier New;"><ol><li>' . implode('</li><li>', explode("\n", htmlspecialchars($template))) . '</li></ol></div>';
				}

				throw new vB_Exception_Api('template_eval_error', array($errors));
			}
		}

		return $template;
	}

	/**
	 * Update a template
	 *
	 * @param integer $templateid Template ID to be updated
	 * @param string $title Template name.
	 * @param string $content Template content.
	 * @param string $product The product ID which the template belongs to.
	 * @param string $oldcontent The content of the template at the time it was loaded.  This is used to prevent
	 *	cases where the template was changed while editing. Pass false to force an update.
	 * @param boolean $savehistory Whether to save the change in template history.
	 * @param string $histcomment Comment of the change to be saved to template history.
	 * @param boolean $forcesaveonerror save the template even though there are errors.
	 * @param array $aditional extra parameters for the function.
	 * 				Actually uses params:
	 * 				forcenotextonly  which bypasses the canadmintemplate permission
	 * 				textonly  which sets template text only setting
	 */
	public function update
	(
		$templateid,
		$title,
		$content,
		$product,
		$oldcontent,
		$savehistory,
		$histcomment,
		$forcesaveonerror = false,
		$additional = array()
	)
	{
		$templateid = intval($templateid);
		$title = trim($title);
		$content = trim($content);
		$product = trim($product);
		$histcomment = trim($histcomment);
		$userinfo = vB::getCurrentSession()->fetch_userinfo();
		$timenow = vB::getRequest()->getTimeNow();

		require_once(DIR . '/includes/adminfunctions.php');
		require_once(DIR . '/includes/adminfunctions_template.php');	// Required for check_template_conflict_error()

		$style_lib = vB_Library::instance('Style');

		// Compile template
		if (!empty($additional['textonly']))
		{
			$template = $content;
		}
		else
		{
			$template = $this->compile($content, $forcesaveonerror);
		}

		// TODO: Product API
		$full_product_info = fetch_product_list(true);

		if (!$forcesaveonerror)
		{
			$errors = check_template_conflict_error($template);
			if (!empty($errors))
			{
				throw new vB_Exception_Api('template_conflict_errors', array($errors));
			}
		}

		$old_template = $this->fetchByID($templateid);

		// Test whether the template exists if new template title is not the same as old one's
		if (strtolower($title) != strtolower($old_template['title']))
		{
			$result = vB::getDbAssertor()->assertQuery('template_fetchbystyleandtitle', array(
				'styleid' => $old_template['styleid'],
				'title' => $title,
			));

			if ($result->valid())
			{
				throw new vB_Exception_Api('invalidid', array('templateid'));
			}
		}

		if ($oldcontent === false)
		{
			$hash = md5($old_template['template_un']);
		}
		else
		{
			$hash = md5($oldcontent);
		}

		$result = $this->saveTemplate(
			$title,
			$template,
			$content,
			$timenow,
			$userinfo['username'],
			$full_product_info[$product]['version'],
			$product,
			$templateid,
			$hash,
			$old_template['styleid'],
			$savehistory,
			$histcomment,
			$additional
		);

		if ($result == 0)
		{
			// we have an edit conflict
			throw new vB_Exception_Api('edit_conflict');
		}
		else
		{
			unset(self::$templatecache[$title]);

			// Remove templatemerge record
			vB::getDbAssertor()->assertQuery('templatemerge',
				array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_DELETE,	'templateid' => $templateid));

			// update any customized templates to reflect a change of product id
			if ($old_template['styleid'] == -1 AND $product != $old_template['product'])
			{
				$result = vB::getDbAssertor()->assertQuery('template_updatecustom_product', array(
					'product'	=> $product,
					'title' 	=> $title,
				));
			}

			//we need to rebuild the style if a css template is changed, we may need to republish.
			if (preg_match('#\.css$#i', $title))
			{
				$style_lib->buildStyle($old_template['styleid'], $title, array(
					'docss' => 0,
					'dostylevars' => 0,
					'doreplacements' => 0,
					'doposteditor' => 0
				), false);
			}

			return true;
		}
	}

	/**
	 * Fetch template by its ID
	 *
	 * @param integer $templateid Template ID.
	 *
	 * @return array Return template array if $templateid is valid.
	 */
	public function fetchByID($templateid)
	{
		$templateid = intval($templateid);
		//not sure why we limit the columns here, but since this feed out the API it's probably for the best.
		$row = vB::getDbAssertor()->getRow('template', array(
			vB_dB_Query::COLUMNS_KEY => array('title', 'styleid', 'dateline', 'username', 'template', 'template_un', 'version', 'textonly', 'product'),
			'templateid' => $templateid,
		));

		if ($row)
		{
			return $row;
		}
		else
		{
			throw new vB_Exception_Api('invalidid', array('templateid'));
		}
	}

	/**
	 *	Save a template and handle all common operations between an insert and an update
	 *	caller is responsible for determining if a update or an insert is needed (via
	 *	providing the existing templateid for the record to be updated)
	 *
	 *	@param $title string.  The title of the template
	 *	@param $template string.  Compiled template text
	 *	@param $content string. Uncompiled template text
	 *	@param $timenow int.  Current time as a datestamp
	 *	@param $username string. Username of the user saving the template
	 *	@param $version string. The version of the product the template belongs to.
	 *	@param $product string. The product that the template belongs to.
	 *	@param $templateid int. The id of the template being saved, null if this is a new template
	 *	@param $hash string.  The md5 hash of the original text of the template being updated. This is used to
	 *		avoid conflicting edits.  Null if this is a new template.
	 *	@param $styleid int.  The ID of the style the template is being saved to.
	 *	@param $savehistory bool. Whether to save this edit to the template history -- valid for new templates
	 *	@param $hiscomment string.  A comment on the edit to save with the history
	 *	@param $additional array.  Extra paraeters for the function
	 * 				Actually uses params:
	 * 				forcenotextonly  which bypasses the canadmintemplate permission
	 * 				textonly  which sets template text only setting
	 *
	 */
	protected function saveTemplate
	(
		$title,
		$template,
		$content,
		$timenow,
		$username,
		$version,
		$product,
		$templateid,
		$hash,
		$styleid,
		$savehistory,
		$histcomment,
		$additional = array()
	)
	{
		$fields = array(
			'title' => $title,
			'template' => $template,
			'template_un' => $content,
			'dateline' => $timenow,
			'username' => $username,
			'version' => $version,
			'product' => $product,
			'textonly' => 0,
		);

		//if the current user does not have canadmintemplates, we force textonly to 1.  Otherwise leave it alone.
		if (!vB::getUserContext()->hasAdminPermission('canadmintemplates')
			AND !isset($additional['forcenotextonly']))
		{
			$fields['textonly'] = 1;
		}
		else if (isset($additional['textonly']))
		{
			$fields['textonly'] = $additional['textonly'];
		}

		//update
		if ($templateid)
		{
			$fields['templateid'] = $templateid;
			$fields['hash'] = $hash;
			$queryid = 'template_update';

			if (!isset($fields['textonly']))
			{
				//We need to get the current value of textonly so we don't change it.
				$existing = vB::getDbAssertor()->getRow('template', array('templateid' => $templateid));
				if ($existing AND !empty($existing['textonly']))
				{
					$fields['textonly'] = 1;
				}
				else
				{
					$fields['textonly'] = 0;
				}
			}
		}
		//insert
		else
		{
			$fields['styleid'] = $styleid;
			$fields[vB_dB_Query::TYPE_KEY] = vB_dB_Query::QUERY_INSERT;
			$queryid = 'template';
		}

		// Do update
		$result = vB::getDbAssertor()->assertQuery($queryid, $fields);
		//If we just did an insert, the templateid is in $result;
		if (empty($templateid) AND is_numeric($result))
		{
			$templateid = $result;
		}
		$this->setTextonlyDS($templateid, $fields['textonly']);

		//a non positive result indicates failure
		if ($result)
		{
			// now update the file system if we setup to do so and we are in the master style
			if (defined('DEV_AUTOEXPORT') AND DEV_AUTOEXPORT AND $styleid == -1)
			{
				$__extra = $additional;
				// We grab it from $fields instead of $additional, as code indicates it may not always be set
				// by caller but should be set in insert anyways (e.g. user doesn't have canadmintemplates)
				$__extra['textonly'] = $fields['textonly'];
				require_once(DIR . '/includes/functions_filesystemxml.php');
				autoexport_write_template($title, $content, $product, $version, $username, $timenow, "", $__extra);
				unset($__extra);
			}

			if ($savehistory)
			{
				vB::getDbAssertor()->assertQuery('template_savehistory', array(
					'dostyleid' => $styleid,
					'title' => $title,
					'template_un' => $content,
					'dateline' => $timenow,
					'username' => $username,
					'version' => $version,
					'comment' => $histcomment,
				));
			}

			//if this is a new template the return from the insert query is the templateid
			if (!$templateid)
			{
				$templateid = $result;
			}
			//if we are storing the templates on the file systems
			$options = vB::getDatastore()->getValue('options');

			if ($options['cache_templates_as_files'] AND $options['template_cache_path'])
			{
				$this->saveTemplateToFileSystem($templateid, $template, $options['template_cache_path'], $fields['textonly']);
			}
			vB_Library::instance('Style')->setCssDate();

			// we need to reset the template fastDS cache.
			$options = vB::getDatastore()->getValue('miscoptions');
			$options['tmtdate']  = vB::getRequest()->getTimeNow();
			vB::getDatastore()->build('miscoptions', serialize($options), 1);
		}

		return $result;
	}

	/**
	 * Get template ID by its template name and style id
	 *
	 * @param $template_name the name of the template
	 * @param $styleid
	 */
	public function getTemplateID($template_name, $styleid = -1)
	{
		$result = $this->getTemplateIds(array($template_name), $styleid);
		return $result['ids'][$template_name];
	}

	/**
	 * Get a list of template IDs by thier template names and style id
	 *
	 * @param array $template_names -- a list of template names
	 * @param array $styleid -- must be a style the user has access to.  If not specified, the default style is used.
	 * @return array array('ids' => $ids) where $ids is a map of names to the template id for that name.  If the name is not
	 * 	found, the entry for that name in the map will be false.
	 */
	public function getTemplateIds($template_names, $styleid = -1)
	{
		$cleaner = vB::getCleaner();
		$template_names = $cleaner->clean($template_names, vB_Cleaner::TYPE_ARRAY);
		$styleid = $cleaner->clean($styleid, vB_Cleaner::TYPE_INT);
		$stylelib = vB_Library::instance('style');

		$style = $stylelib->fetchStyleRecord($styleid, true);
		$ids = array();
		foreach($template_names AS $name)
		{
			if (isset($style['templatelist'][$name]))
			{
				$ids[$name] =  $style['templatelist'][$name];
			}
			else
			{
				$ids[$name] = false;
			}
		}

		return array('ids' => $ids);
	}

	/**
	 *	Clear the template cache
	 *
	 *	Should only be called from unit test code.
	 */
	public function clearTemplateCache()
	{
		self::$templatecache = array();
	}

	/**
	 * This updates the datastore list of templates that have textonly and therefore are not rendered.
	 * @param 	int		$styleid
	 * @param 	string	$title
	 * @param 	bool	$textonly
	 */
	public function setTextonlyDS($templateid, $textonly)
	{
		$ds =vB::getDatastore();
		$textOnly = json_decode($ds->getValue('textonlyTemplates'), true);

		if ($textonly)
		{
			$textOnly[$templateid] = 1;
		}
		else
		{
			unset($textOnly[$templateid]);
		}
		$ds->build('textonlyTemplates', json_encode($textOnly), 0);
	}

	/**
	 * Rebuilds the textonly array();
	 */
	public function rebuildTextonlyDS()
	{
		$toQry = vB::getDbAssertor()->assertQuery('template', array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT, 'textonly' => 1));
		$textOnly = array();

		if ($toQry->valid())
		{
			foreach($toQry AS $template)
			{
				$textOnly[$template['templateid']] = 1;
			}
		}

		vB::getDatastore()->build('textonlyTemplates', json_encode($textOnly), 0);
	}

	public function getTemplateGroupPhrases()
	{
		//this should really be in the database
		//
		//If you change this you need to also update the list in class_filesystem_template.xml
		//we need to run that logic outside of vB and we can't call this function
		//without bootstrapping the system
		$groups = array
		(
			'admin'          => 'group_admin',
			'article'        => 'group_article',
			'bbcode'         => 'group_bbcode',
			'blog'           => 'group_blog',
			'blogadmin'      => 'group_blogadmin',
			'color'          => 'group_color',
			'content'        => 'group_content_templates',
			'conversation'   => 'group_conversation',
			'css'            => 'group_css',
			'dialog'         => 'group_dialog',
			'display'        => 'group_display',
			'editor'         => 'group_editor',
			'error'          => 'group_error',
			'group'          => 'group_sgroup',
			'humanverify'    => 'group_human_verification',
			'inlinemod'      => 'group_inlinemod',
			'link'           => 'group_link',
			'login'          => 'group_login',
			'media'          => 'group_media',
			'memberlist'     => 'group_memberlist',
			'modify'         => 'group_modify',
			'pagenav'        => 'group_pagenav',
			'photo'          => 'group_photo',
			'picture'        => 'group_picture_templates',
			'pmchat'         => 'group_pmchat',
			'privatemessage' => 'group_private_message',
			'profile'        => 'group_profile',
			'screenlayout'   => 'group_screen',
			'search'         => 'group_search',
			'sgadmin'        => 'group_sgadmin',
			'site'           => 'group_site',
			'subscription'   => 'group_paidsubscription',
			'subscriptions'  => 'group_subscription',
			'sprite'         => 'group_sprite',
			'tag'            => 'group_tag',
			'top_menu'       => 'group_top_menu',
			'userfield'      => 'group_user_profile_field',
			'usersettings'   => 'group_usersetting',
			'video'          => 'group_video',
			'widget'         => 'group_widget',
		);

		vB::getHooks()->invoke('hookTemplateGroupPhrase', array(
			'groups' => &$groups,
		));

		return $groups;
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 103351 $
|| #######################################################################
\*=========================================================================*/
