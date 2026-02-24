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
 * vB_Api_Template
 *
 * @package vBApi
 * @access public
 */
class vB_Api_Template extends vB_Api
{
	protected $disableWhiteList = array('fetch', 'fetchBulk', 'fetchTemplateHooks','processReplacementVars', 'getTemplateIds');

	protected $library;

	protected static $special_templates = array(
	/* None currently exist.
	The dummy stops some crashes */
		'dummy entry',
	);

	protected static $common_templates = array(
		'header',
		'footer',
	);

	protected function __construct()
	{
		parent::__construct();
		$this->library = vB_Library::instance('Template');
	}

	/**
	 * Fetch one template based on its name and style ID.
	 *
	 * @param string $template_name Template name.
	 * @param integer $styleid Style ID. If empty, this method will fetch template from default style.
	 * @return mixed
	 */
	public function fetch($template_name, $styleid = -1)
	{
		return $this->library->fetch($template_name, $styleid);
	}

	/**
	 * Fetches a bulk of templates from the database
	 *
	 * @param array $template_names List of template names to be fetched.
	 * @param integer $styleid Style ID. If empty, this method will fetch template from default style.
	 *
	 * @return array Array of information about the imported style
	 */
	public function fetchBulk($template_names, $styleid = -1, $type = 'compiled')
	{
		return $this->library->fetchBulk($template_names, $styleid, $type);
	}

	/**
	 * Get template ID by its template name and style id
	 *
	 * @param $template_name the name of the template
	 * @param $styleid
	 */
	public function getTemplateID($template_name, $styleid = -1)
	{
		$result = $this->library->getTemplateIds(array($template_name), $styleid);
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
		return $this->library->getTemplateIds($template_names, $styleid);
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
		return $this->library->fetchByID($templateid);
	}

	/**
	 * Fetch one uncompiled template based on its name and style ID.
	 *
	 * @param string $template_name Template name.
	 * @param integer $styleid Style ID.
	 */
	public function fetchUncompiled($template_name, $styleid = -1)
	{
		$this->checkHasAdminPermission('canadmintemplates');

		$templates = $this->fetchBulk(array($template_name), $styleid, 'uncompiled');

		if ($templates[$template_name])
		{
			return $templates[$template_name];
		}

		return false;
	}

	/**
	 * Fetches a number of templates from the database and puts them into the templatecache
	 *
	 * @param	array	List of template names to be fetched
	 * @param	string	Serialized array of template name => template id pairs
	 * @param	bool	Whether to skip adding the bbcode style refs
	 * @param	bool	Whether to force setting the template
	 *
	 * @return none
	 */
	public function cacheTemplates($templates, $templateidlist, $skip_bbcode_style = false, $force_set = false)
	{
		return vB_Library::instance('template')->cacheTemplates($templates, $templateidlist, $skip_bbcode_style,  $force_set);
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
	 *
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
		$this->checkCanSaveTemplate(false, array(), $extra);

		return $this->library->insert($dostyleid, $title, $content, $product, $savehistory, $histcomment, $forcesaveonerror, $extra);
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
		$this->checkCanSaveTemplate($templateid, array(),$additional);

		return $this->library->update(
			$templateid,
			$title,
			$content,
			$product,
			$oldcontent,
			$savehistory,
			$histcomment,
			$forcesaveonerror,
			$additional
		);
	}


	/**
	 *	Insert a replacement var
	 *
	 *	@param	integer	$dostyleid
	 *	@param	string	$findtext
	 *	@param	string	$replacetext
	 *
	 *	@return array
	 *		integer id -- The id of the newly created replacement var
	 *
	 *	@throws vB_Exception_Api
	 *		'no_permission' -- user does not have canadminstyles
	 */
	public function insertReplacementVar($dostyleid, $findtext, $replacetext)
	{
		if(!vB::getUserContext()->hasAdminPermission('canadminstyles'))
		{
			throw new vB_Exception_Api('no_permission');
		}

		$id = $this->library->insertReplacementVar($dostyleid, $findtext, $replacetext);
		return array('id' => $id);
	}


	/**
	 *	Update the replacement text for a replacement var
	 *
	 *	@param integer $replacevarid -- templateid for the replacement variable
	 *	@paramstring $replacetext
	 *
	 * 	@return array ('success' => true)
	 *
	 * 	@throws vB_Exception_Api
	 * 		'no_permission' -- user does not have canadminstyles
	 * 		'invalid_data_w_x_y_z' -- if the template does not exist or is not a replacement var
	 */
	public function updateReplacementVar($replacevarid, $replacetext)
	{
		if(!vB::getUserContext()->hasAdminPermission('canadminstyles'))
		{
			throw new vB_Exception_Api('no_permission');
		}

		$result = $this->library->updateReplacementVar($replacevarid, $replacetext);
		if (!$result)
		{
			throw new vB_Exception_Api('invalid_data_w_x_y_z', array($replacevarid, 'replacevarid', __CLASS__, __FUNCTION__));
		}

		return array('success' => true);
	}


	/**
	 * 	Delete a replacement variable
	 *
	 * 	@param integer $replacevarid -- templateid for the replacement variable
	 * 	@return array ('success' => true)
	 *
	 * 	@throws vB_Exception_Api
	 *		'no_permission' -- user does not have canadminstyles
	 * 		'invalid_data_w_x_y_z' -- if the template does not exist or is not a replacement var
	 */
	public function deleteReplacementVar($replacevarid)
	{
		if(!vB::getUserContext()->hasAdminPermission('canadminstyles'))
		{
			throw new vB_Exception_Api('no_permission');
		}

		//if this is a text-only template the customer only needs canadminstyles
		$templateid = intval($replacevarid);
		$template = $this->library->fetchReplacementVarById($replacevarid);

		if (!$template)
		{
			throw new vB_Exception_Api('invalid_data_w_x_y_z', array($replacevarid, 'replacevarid', __CLASS__, __FUNCTION__));
		}

		$this->deleteTemplateInternal($templateid, $template['styleid'], 1);
		return array('success' => true);
	}

	/**
	 *	Find the replacement var by title and styleid
	 *
	 *	@param string $findtext
	 *	@param integer $dostyleid
	 *	@param boolean $inherit -- do we check for variables in parent styles?
	 *
	 *	@return array 'replacevar' => false|array -- template record for the replacement variable
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
		//we may not need to restrict this, but its easier to be restrictive now and
		//open up later than the reverse.  Right now this is only needed by the admincp.
		if(!vB::getUserContext()->hasAdminPermission('canadminstyles'))
		{
			throw new vB_Exception_Api('no_permission');
		}

		$record = $this->library->fetchReplacementVar($findtext, $dostyleid, $inherit);
		return array('replacevar' => $record);
	}

 	/**
	 *	Find the replacement var by templateid
	 *
	 *	@param integer $replacevarid
	 *
	 *	@return array 'replacevar' => false|array -- template record for the replacement variable
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
		//we may not need to restrict this, but its easier to be restrictive now and
		//open up later than the reverse.  Right now this is only needed by the admincp.
		if(!vB::getUserContext()->hasAdminPermission('canadminstyles'))
		{
			throw new vB_Exception_Api('no_permission');
		}

		$record = $this->library->fetchReplacementVarById($replacevarid);
		return array('replacevar' => $record);
	}

	/**
	 * This is the counterpart to saveCssTemplateSbEditor(). Returns the template record,
	 * including template text and the textonly value.
	 *
	 * @param  int    Style ID
	 * @param  string Template Name
	 *
	 * @return array  Array containing the template info
	 */
	public function getCssTemplateSbEditor($styleid, $templateName)
	{
		if (!vB::getUserContext()->hasAdminPermission('canadmintemplates') AND !vB::getUserContext()->hasAdminPermission('canadminstyles'))
		{
			throw new vB_Exception_Api('no_permission');
		}

		// only allow CSS template editing (at least for now)
		if (substr($templateName, -4) != '.css')
		{
			throw new vB_Exception_Api('invalid_request');
		}

		// get template id to fetch, since this template may not exist
		// in this style and will be inherited instead
		$templateid = $this->getTemplateID($templateName, $styleid);

		$conditions = array(
			'templateid' => $templateid,
		);
		$template = vB::getDbAssertor()->getRow('template', $conditions);

		return array(
			'success' => true,
			'template' => $template,
		);
	}

	/**
	 * This is just a wrapper for delete, save, and update.  The presentation layer
	 * doesn't actually know which is correct.  This forces textonly = 1 if the
	 * user doesn't have 'canadmintemplates'.
	 *
	 * @param  string the content of the template
	 * @param  int    the styleid
	 * @param  string the styleid
	 * @param  bool   textonly value
	 *
	 * @return bool
	 */
	public function saveCssTemplateSbEditor($text, $styleid, $templateName, $textonly = 1)
	{
		//If text is empty and there is not currently a template for this style we do nothing.
		//If text is not empty or there is already a template for this style we do an update.
		//If text is not empty, we do an update or insert.

		if (vB::getUserContext()->hasAdminPermission('canadmintemplates'))
		{
			$additional = array('textonly' => ($textonly ? 1 : 0));
		}
		else
		{
			$additional = array('textonly' => 1);
		}

		// permissions checked in checkCanSaveTemplate
		$this->checkCanSaveTemplate(false, array(), $additional);

		// only allow CSS template editing (at least for now)
		if (substr($templateName, -4) != '.css')
		{
			throw new vB_Exception_Api('invalid_request');
		}

		$template = vB::getDbAssertor()->getRow('template', array(
			'styleid' => $styleid,
			'title' => $templateName,
		));

		if (intval($styleid) < 1)
		{
			throw new vB_Exception_Api('invalid_request');
		}

		if ($template)
		{
			//We do have an existing record.
			return $this->library->update(
				$template['templateid'],
				$templateName,
				$text,
				$template['product'],
				$template['template_un'],
				false,
				'',
				false,
				$additional
			);
		}
		else
		{
			return $this->library->insert(
				$styleid,
				$templateName,
				$text,
				'vBulletin',
				false,
				'',
				false,
				$additional
			);
		}
	}

	/**
	 *	Delete a template based on style and name
	 *
	 *	This will delete the template for the given style if it exists
	 *	If the template doesn't exist we will quietly do nothing.
	 */
	public function revertCssTemplateSbEditor($styleid, $templateName)
	{
		$current = vB::getDbAssertor()->getRow('template', array(
			vB_dB_Query::COLUMNS_KEY => array('templateid'),
			'styleid' => $styleid,
			'title' => $templateName,
		));

		if($current)
		{
			//delete doesn't return anything useful, but it also doesn't follow
			//API standards so we don't want to just pass it through
			$this->delete($current['templateid']);
		}

		return array('success' => true);
	}

	/**
	 * Delete a template
	 *
	 * @param integer $templateid Template ID to be deleted.
	 */
	public function delete($templateid)
	{
		//if this is a text-only template the customer only needs canadminstyles
		$templateid = intval($templateid);
		$template = $this->fetchByID($templateid);
		$extra = array();
		$this->checkCanSaveTemplate($templateid, $template, $extra);

		if ($template)
		{
			$this->deleteTemplateInternal($templateid, $template['styleid']);
		}

		if (defined('DEV_AUTOEXPORT') AND DEV_AUTOEXPORT AND $template['styleid'] == -1)
		{
			require_once(DIR . '/includes/functions_filesystemxml.php');
			autoexport_delete_template($template['title']);
		}

		return true;
	}

	/**
	 * This checks permissions for saving a template.
	 *
	 * If textonly is set then the action requires only canadminstyles. Otherwise it requires canadmintemplates.
	 *
	 * @param 	int		templateid
	 * @param 	array 	existing record if available
	 * @param 	array 	data being saved
	 * @param 	array 	extra flags, which may include textonly.
	 *
	 */
	protected function checkCanSaveTemplate($templateid, $existing, &$extra)
	{
		$userContext = vB::getUserContext();
		if ($userContext->hasAdminPermission('canadmintemplates'))
		{
			return true;
		}
		else if ($userContext->hasAdminPermission('canadminstyles'))
		{
			if (!empty($extra['textonly']))
			{
				return true;
			}

			if (empty($existing) AND !empty($templateid))
			{
				$existing = vB::getDbAssertor()->getRow('template', array('templateid' => $templateid) );
			}

			if (!empty($existing['textonly']))
			{
				// user can save, but let's make sure they didn't get clever and pass textonly = false in extra
				$extra['textonly'] = true;
				return true;
			}
		}

		//if we got here, the user does not have the necessary permissions.
		throw new vB_Exception_Api('no_permission');
	}


	/**
	 * Fetch original (not customized) template content
	 *
	 * @param string $title Template name.
	 *
	 * @return array Original template information
	 */
	public function fetchOriginal($title)
	{
		$this->checkHasAdminPermission('canadmintemplates');

		$title = trim($title);

		$result = vB::getDbAssertor()->assertQuery('template_fetchoriginal', array('title' => $title));

		if ($result->valid())
		{
			return $result->current();
		}
		else
		{
			throw new vB_Exception_Api('invalidid', array('templateid'));
		}
	}

	/**
	 * Find custom templates that need updating
	 *
	 * @return array Templates that need updating.
	 */
	public function findUpdates()
	{
		$this->checkHasAdminPermission('canadmintemplates');

		require_once(DIR . '/includes/adminfunctions.php');
		require_once(DIR . '/includes/adminfunctions_template.php');

		$customcache = fetch_changed_templates();
		// TODO: Product API
		$full_product_info = fetch_product_list(true);

		$stylecache = vB_Library::instance('Style')->fetchStyles(false, false);

		$return = array();
		foreach ($stylecache AS $styleid => $style)
		{
			if (is_array($customcache["$styleid"]))
			{
				$return[] = $customcache["$styleid"];
			}
		}

		return $return;
	}

	/**
	 * Dismiss automatical merge
	 *
	 * @param array Template IDs which merge needs to be dismissed.
	 * @return array Number of affected templates.
	 */
	public function dismissMerge($templateids)
	{
		$this->checkHasAdminPermission('canadmintemplates');

		if (empty($templateids))
		{
			throw new vB_Exception_Api('please_complete_required_fields');
		}

		foreach ($templateids as &$templateid)
		{
			$templateid = intval($templateid);
		}

		$result = vB::getDbAssertor()->assertQuery('template_update_mergestatus', array('templateids' => $templateids));

		vB::getDbAssertor()->assertQuery('templatemerge',
			array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_DELETE,	'templateid' => $templateids));

		return $result;
	}

	/**
	 * Search and fetch a list of templates
	 *
	 * @param integer $dostyleid Style ID to be searched in. -1 means search in all styles.
	 * @param mixed $expandset
	 * @param string $searchstring Search for text.
	 * @param boolean $titlesonly Wether to search template titles (names) only.
	 *
	 * @return mixed false if no templates are found. Otherwise an array will be returned with styleids as its keys.
	 */
	public function search($dostyleid, $expandset = null, $searchstring = '', $titlesonly = true)
	{
		$this->checkHasAdminPermission('canadmintemplates');

		$groups = vB_Library::instance('template')->getTemplateGroupPhrases();
		$template_groups = vB_Api::instanceInternal('phrase')->renderPhrases($groups);
		$template_groups = $template_groups['phrases'];

		if ($searchstring)
		{
			$group = 'all';
		}

		if (!empty($expandset))
		{
			$result = vB::getDbAssertor()->assertQuery('template_getmasters');
			foreach ($result as $master)
			{
				$masterset["$master[title]"] = $master['templateid'];
			}
		}
		else
		{
			$masterset = array();
		}

		$style_lib = vB_Library::instance('Style');
		$stylecache = $style_lib->fetchStyles(false, false);

		$return = array();
		foreach($stylecache AS $styleid => $style)
		{
			if ($styleid == -1)
			{
				$vbphrase = vB_Api::instanceInternal('phrase')->fetch(array('master_style'));
				$style['title'] = $vbphrase['master_style'];
				$style['templatelist'] = $masterset;
			}

			if ($expandset == 'all' OR $expandset == $styleid)
			{
				$showstyle = 1;
			}
			else
			{
				$showstyle = 0;
			}

			//this isn't the most efficient way to do this, but it's not something that gets
			//called alot and it's not *that* bad.
			$full_style = $style_lib->fetchStyleByID($styleid);

			$result = vB::getDbAssertor()->assertQuery('searchTemplates', array(
				'searchstring' => $searchstring,
				'titlesonly' => $titlesonly,
				'templateids' => implode(',', $full_style['templatelist']),
			));

			if (!$result->valid())
			{
				return false;
			}

			foreach ($result as $template)
			{
				if ($template['templatetype'] == 'replacement')
				{
					$replacements["$template[templateid]"] = $template;
				}
				else
				{
					// don't show any special templates
					if (in_array($template['title'], vB_Api::instanceInternal('template')->fetchSpecialTemplates()))
					{
						continue;
					}
					else
					{
						$m = substr(strtolower($template['title']), 0, iif($n = strpos($template['title'], '_'), $n, strlen($template['title'])));
						if ($template['styleid'] != -1 AND !isset($masterset["$template[title]"]) AND !isset($template_groups["$m"]))
						{
							$customtemplates["$template[templateid]"] = $template;
						}
						else
						{
							$maintemplates["$template[templateid]"] = $template;
						}
					}
				}

				$return[$styleid]['customtemplates'] = $customtemplates;
				$return[$styleid]['maintemplates'] = $maintemplates;
			}
		}

		return $return;
	}

	/**
	 * Search and Replace templates.
	 *
	 * @param integer $dostyleid Style ID to be searched in. -1 means search in all styles.
	 * @param string $searchstring Search for text.
	 * @param string $replacestring Replace with text.
	 * @param boolean $case_insensitive Case-Insensitive or not.
	 * @param boolean $regex Whether to use regular expressions.
	 * @param boolean $test Test only.
	 * @param integer $startat_style Replacement startat style ID.
	 * @param integer $startat_template Replacement startat template ID.
	 *
	 * @return mixed False if no templates found. Otherwise an array will be returned.
	 */
	public function searchAndReplace(
		$dostyleid,
		$searchstring,
		$replacestring,
		$case_insensitive,
		$regex,
		$test,
		$startat_style,
		$startat_template
	)
	{
		$this->checkHasAdminPermission('canadmintemplates');

		require_once(DIR . '/includes/adminfunctions.php');
		require_once(DIR . '/includes/adminfunctions_template.php');

		// TODO: Product API
		$full_product_info = fetch_product_list(true);

		$vb5_config = &vB::getConfig();
		$userinfo = vB::getCurrentSession()->fetch_userinfo();

		$perpage = 50;
		$searchstring = str_replace(chr(0), '', $searchstring);

		if (empty($searchstring))
		{
			throw new vB_Exception_Api('please_complete_required_fields');
		}

		$limit_style = $startat_style;
		$conditions = array();
		if ($dostyleid == -1)
		{
			if ($vb5_config['Misc']['debug'])
			{
				$conditions[] = array('field' => 'styleid', 'value' => -2, 'operator' => vB_dB_Query::OPERATOR_NE);
				if ($startat_style == 0)
				{
					$editmaster = true;
				}
				else
				{
					$limit_style--; // since 0 means the master style, we have to renormalize
				}
			}
			else
			{
				$conditions[] = array('field' => 'styleid', 'value' => 0, 'operator' => vB_dB_Query::OPERATOR_GT);
			}
		}
		else
		{
			$conditions['styleid'] = $dostyleid;
		}

		if ($editmaster != true)
		{
			$result = vB::getDbAssertor()->assertQuery('getStyleByConds', array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_METHOD,
				'conds' => $conditions,
				'limit_style' => $limit_style
			));

			if (!$result->valid())
			{
				// couldn't grab a style, so we're done
				return false;
			}
			$styleinfo = $result->current();
			$templatelist = unserialize($styleinfo['templatelist']);
		}
		else
		{
			$styleinfo = array(
				'styleid' => -1,
				'title' => 'MASTER STYLE'
			);
			$templatelist = array();

			$result = vB::getDbAssertor()->assertQuery('template_getmasters2');
			foreach ($result as $tid)
			{
				$templatelist["$tid[title]"] = $tid['templateid'];
			}
			$styleinfo['templatelist'] = serialize($templatelist); // for sanity
		}

		$loopend = $startat_template + $perpage;
		$process_templates = array(0);
		$i = 0;

		foreach ($templatelist AS $title => $tid)
		{
			if ($i >= $startat_template AND $i < $loopend)
			{
				$process_templates[] = $tid;
			}
			if ($i >= $loopend)
			{
				break;
			}
			$i++;
		}
		if ($i != $loopend)
		{
			// didn't get the $perpage templates, so we're done with this style
			$styledone = true;
		}
		else
		{
			$styledone = false;
		}

		$templates = vB::getDbAssertor()->assertQuery('template', array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
				'templateid' => $process_templates
			)
		);
		$stats['page'] = $startat_template / $perpage + 1;
		$stats['first'] = $startat_template + 1;
		$count = 0;
		$processed_templates = array();
		foreach ($templates AS $temp)
		{
			$count ++;
			$insensitive_mod = ($case_insensitive ? 'i' : '');

			if ($test)
			{
				if ($regex)
				{
					$encodedsearchstr = str_replace('(?&lt;', '(?<', htmlspecialchars_uni($searchstring));
				}
				else
				{
					$encodedsearchstr = preg_quote(htmlspecialchars_uni($searchstring), '#');
				}

				$newtemplate = preg_replace("#$encodedsearchstr#sU$insensitive_mod",
					'<span class="col-i" style="text-decoration:underline;">' .
					htmlspecialchars_uni($replacestring) . '</span>', htmlspecialchars_uni($temp['template_un']));

				if ($newtemplate != htmlspecialchars_uni($temp['template_un']))
				{
					$temp['newtemplate'] = $newtemplate;
					$processed_templates[] = $temp;
				}
				else
				{
					continue;
				}
			}
			else
			{
				if ($regex)
				{
					$newtemplate = preg_replace("#" . $searchstring . "#sU$insensitive_mod", $replacestring, $temp['template_un']);
				}
				else
				{
					$usedstr = preg_quote($searchstring, '#');
					$newtemplate = preg_replace("#$usedstr#sU$insensitive_mod", $replacestring, $temp['template_un']);
				}

				if ($newtemplate != $temp['template_un'])
				{
					if (!empty($temp['textonly']))
					{
						$newTemplateCompiled = $newtemplate;
					}
					else
					{
						$newTemplateCompiled = $this->library->compile($newtemplate, true);
					}
					if ($temp['styleid'] == $styleinfo['styleid'])
					{
						vB::getDbAssertor()->assertQuery('template', array(
							vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_UPDATE,
							'template'            => $newTemplateCompiled,
							'template_un'         => $newtemplate,
							'dateline'            => TIMENOW,
							'username'            => $userinfo['username'],
							'version'             => $full_product_info["$temp[product]"]['version'],
							'templateid'          => $temp['templateid'],
							'mergestatus'         => 'none',
						));

						// now update the file system if we setup to do so and we are in the master style
						if (defined('DEV_AUTOEXPORT') AND DEV_AUTOEXPORT AND $temp['styleid'] == -1)
						{
							$__extra = array();
							if (!empty($temp['textonly']))
							{
								$__extra['textonly'] = 1;
							}
							require_once(DIR . '/includes/functions_filesystemxml.php');
							autoexport_write_template(
								$temp['title'],
								$newtemplate,
								$temp['product'],
								$full_product_info["$temp[product]"]['version'],
								$userinfo['username'],
								TIMENOW,
								"",
								$__extra
							);
						}

						vB::getDbAssertor()->assertQuery('templatemerge',
							array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_DELETE,	'templateid' => $temp['templateid']));
					}
					else
					{
						/*insert query*/
						$result = vB::getDbAssertor()->assertQuery('template', array(
							vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_UPDATE,
							'dostyleid'           => $styleinfo['styleid'],
							'title'               => $temp['title'],
							'template'            => $newTemplateCompiled,
							'template_un'         => $newtemplate,
							'dateline'            => TIMENOW,
							'username'            => $userinfo['username'],
							'version'             => $full_product_info["$temp[product]"]['version'],
							'product'             => $temp['product'],
						));

						$requirerebuild = true;
					}
					$temp['newtemplate'] = $newtemplate;
					$processed_templates[] = $temp;
					vB_Library::instance('Style')->setCssDate();
				}
				else
				{
					continue;
				}
			}
		} // End foreach
		$stats['last'] = $startat_template + $count;

		if ($styledone == true)
		{
			// Go to the next style. If we're only doing replacements in one style,
			// this will trigger the finished message.
			$startat_style++;
			$loopend = 0;
		}

		return array(
			'processed_templates' => $processed_templates,
			'startat_style'       => $startat_style,
			'startat_template'    => $loopend,
			'requirerebuild'      => $requirerebuild,
			'styleinfo'           => $styleinfo,
			'stats'               => $stats,
		);
	}

	/**
	 * Revert all templates in a style
	 *
	 * @param integer $dostyleid Style ID where the custom templates in it will be reverted
	 *
	 * @return boolean False if nothing to do.
	 */
	public function revertAllInStyle($dostyleid)
	{
		$this->checkHasAdminPermission('canadmintemplates');

		if ($dostyleid == -1)
		{
			throw new vB_Exception_Api('invalid_style_specified');
		}

		$style = vB_Library::instance('Style')->fetchStyleByID($dostyleid);

		if (!$style)
		{
			throw new vB_Exception_Api('invalid_style_specified');
		}

		if (!$style['parentlist'])
		{
			$style['parentlist'] = '-1';
		}
		else if (is_string($style['parentlist']))
		{
			$style['parentlist'] = explode(',', $style['parentlist']);
		}

		$result = vB::getDbAssertor()->assertQuery('template_getrevertingtemplates', array(
			'styleparentlist' => $style['parentlist'],
			'styleid'	=> $style['styleid'],
		));

		if ($result->valid())
		{
			$deletetemplates = array();
			foreach ($result AS $template)
			{
				$deletetemplates["$template[title]"] = $template['templateid'];
			}

			if (!empty($deletetemplates))
			{
				$this->deleteTemplateInternal($deletetemplates, $style['styleid']);
				return true;
			}
		}

		return false;
	}

	/**
	 * Massive merge templates
	 *
	 * @param string $product Product string ID.
	 * @param integer $startat Start offset of the merge.
	 *
	 * @return integer New startat value. -1 if no more to do.
	 */
	public function massMerge($product = 'vbulletin', $startat = 0)
	{
		$this->checkHasAdminPermission('canadmintemplates');

		require_once(DIR . '/includes/adminfunctions.php');

		// TODO: Product API
		$full_product_info = fetch_product_list(true);
		$vbulletin = &vB::get_registry();
		require_once(DIR . '/includes/class_template_merge.php');
		require_once(DIR . '/includes/adminfunctions_template.php');

		$merge = new vB_Template_Merge($vbulletin);
		$merge->time_limit = 5;

		$merge_data = new vB_Template_Merge_Data($vbulletin);
		$merge_data->start_offset = $startat;

		if ($product == 'vbulletin' OR !$product)
		{
			$merge_data->add_condition("tnewmaster.product IN ('', 'vbulletin')");
		}
		else
		{
			$merge_data->add_condition("tnewmaster.product = '" . mysql_escape_string($product) . "'");

			$merge->merge_version = $full_product_info[$product]['version'];
		}

		$completed = $merge->merge_templates($merge_data, $output);

		if ($completed)
		{
			// completed
			build_all_styles();

			vB_Library::instance('Style')->setCssDate();

			return -1;
		}
		else
		{
			return $merge_data->start_offset + $merge->fetch_processed_count();
		}
	}

	/**
	 * Return editing history of a template, including old versions and diffs between versions
	 *
	 * @param string $title Template name.
	 * @param integer $dostyleid Style ID of the template.
	 *
	 * @return array Array of template history revisions.
	 */
	public function history($title, $dostyleid)
	{
		$this->checkHasAdminPermission('canadmintemplates');

		$revisions = array();
		$have_cur_def = false;
		$cur_temp_time = 0;

		$current_temps = vB::getDbAssertor()->assertQuery('template_fetchbystyleandtitle2', array(
			'title' => $title,
			'styleid' => $dostyleid
		));
		foreach ($current_temps as $template)
		{
			$template['type'] = 'current';

			// the point of the second part of this key is to prevent dateline
			// collisions, as rare as that may be
			$revisions["$template[dateline]|b$template[templateid]"] = $template;

			if ($template['styleid'] == -1)
			{
				$have_cur_def = true;
			}
			else
			{
				$cur_temp_time = $template['dateline'];
			}
		}

		$historical_temps = vB::getDbAssertor()->getRows('templatehistory',
			array('title' => $title, 'styleid' => array(-1, $dostyleid)));
		$history_count = count($historical_temps);
		foreach ($historical_temps as $template)
		{
			$template['type'] = 'historical';

			// the point of the second part of this key is to prevent dateline
			// collisions, as rare as that may be
			$revisions["$template[dateline]|a$template[templatehistoryid]"] = $template;
		}

		// I used a/b above, so current versions sort above historical versions
		usort($revisions, "history_compare");

		return $revisions;
	}

	/**
	 * Return editing history of a template by its ID, including old versions and diffs between versions
	 *
	 * @param integer $templateid Template ID.
	 *
	 * @return array Array of template history revisions.
	 */
	public function historyByTemplateID($templateid)
	{
		$this->checkHasAdminPermission('canadmintemplates');

		$template = $this->fetchByID($templateid);
		return $this->history($template['title'], $template['styleid']);
	}

	/**
	 * Fetch current or historical uncompiled version of a template
	 *
	 * @param integer The ID (in the appropriate table) of the record you want to fetch.
	 * @param string Type of template you want to fetch; should be "current" or "historical"
	 */
	public function fetchVersion($historyid, $type)
	{
		$this->checkHasAdminPermission('canadmintemplates');

		require_once(DIR . '/includes/adminfunctions_template.php');

		$template = fetch_template_current_historical($historyid, $type);

		return $template;
	}

	/**
	 * Delete template history versions
	 *
	 * @param array $historyids History IDs to be deleted
	 */
	public function deleteHistoryVersion($historyids)
	{
		$this->checkHasAdminPermission('canadmintemplates');

		if (!is_array($historyids))
		{
			throw new vB_Exception_Api('please_complete_required_fields');
		}

		vB::getDbAssertor()->assertQuery('templatehistory', array(
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_DELETE,
			'templatehistoryid' => $historyids
		));
	}

	public function fetchSpecialTemplates()
	{
		return self::$special_templates;
	}

	public function fetchCommonTemplates()
	{
		return self::$common_templates;
	}

	public function fetchTemplateHooks($hookName)
	{
		static $hooklist, $hooks_set;

		$vboptions = vB::getDatastore()->getValue('options');

		if (!$vboptions['enablehooks'] OR defined('DISABLE_HOOKS'))
		{
			return false;
		}

		if (!$hooks_set)
		{
			$hooks_set = true;
			$hooklist = $this->buildHooklist();
		}

		if (isset($hooklist[$hookName]))
		{
			return $hooklist[$hookName];
		}
		else
		{
			return false;
		}
	}

	public function saveAllTemplatesToFile()
	{
		//This is used primarily to switch between templates in filesystem and in database
		$this->checkHasAdminPermission('cansetserverconfig');
		vB_Library::instance('template')->saveAllTemplatesToFile();
	}

	public function deleteAllTemplateFiles()
	{
		//This is used primarily to switch between templates in filesystem and in database
		$this->checkHasAdminPermission('cansetserverconfig');
		vB_Library::instance('template')->deleteAllTemplateFiles();
	}


	/**
	 * Preload basic language information we're going to need.
	 */
	public function loadLanguage()
	{
		vB::getCurrentSession()->loadLanguage();
	}


	//make sure that we handle all of the associated operations when we delete a template
	protected function deleteTemplateInternal($templateids, $styleid, $dobuildreplacements=0)
	{
		//delete some stuff.
		vB::getDbAssertor()->assertQuery('template',
			array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_DELETE,	'templateid' => $templateids));

		vB::getDbAssertor()->assertQuery('templatemerge',
			array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_DELETE,	'templateid' => $templateids));

		//if we are storing the templates on the file systems
		//handle array or single item
		if (!is_array($templateids))
		{
			$templateids = array($templateids);
		}

		$options = vB::getDatastore()->getValue('options');
		//delete cached template files.
		foreach($templateids AS $templateid)
		{
			if ($options['cache_templates_as_files'] AND $options['template_cache_path'])
			{
				$this->library->deleteTemplateFromFileSystem($templateid, $options['template_cache_path']);
			}
		}

		//rebuild cached information
		$stylelib = vB_Library::instance('Style');
		$stylelib->buildStyle($styleid, '', array('docss' => 0, 'dostylevars' => 0, 'doreplacements' => $dobuildreplacements, 'doposteditor' => 0), false);
		$stylelib->buildStyleDatastore();
	}

	private function buildHooklist()
	{
		$hooks = array();
		$templateHooks = vB::getDatastore()->get_value('hooks');

		if ($templateHooks)
		{
			foreach ($templateHooks as $hook)
			{
				$hooks[$hook['hookname']][][$hook['template']] = $hook['arguments'] ? unserialize($hook['arguments']) : array();
			}
		}

		return $hooks;
	}

	/**
	 * Process the replacement variables.
	 *
	 * @param string The html to be processed
	 * @param integer The styleid to use.
	 *
	 * @return string The processed output
	 */
	public function processReplacementVars($html, $syleid = -1)
	{
		return $this->library->processReplacementVars($html, $syleid);
	}

	/** gets the current textonly array
	 *
	 * @return	mixed	array of styleid => array of template title => 1;
	 *
	 */
	public function getTextonlyDS()
	{
		return json_decode(vB::getDatastore()->getValue('textonlyTemplates'), true);
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 102667 $
|| #######################################################################
\*=========================================================================*/
