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

error_reporting(E_ALL & ~E_NOTICE);

// note #1: arrays used by functions in this code are declared at the bottom of the page

/**
* Expand and collapse button labels
*/
define('EXPANDCODE', '&laquo; &raquo;');
define('COLLAPSECODE', '&raquo; &laquo;');

/**
* Size in rows of template editor <select>
*/
define('TEMPLATE_EDITOR_ROWS', 25);

/**
* List of special purpose templates used by css.php and build_style()
*/
global $vbphrase;

/**
* Initialize the IDs for colour preview boxes
*/
$numcolors = 0;

// #############################################################################
/**
* Trims the string passed to it
*
* @param	string	(ref) String to be trimmed
*/
function array_trim(&$val)
{
	$val = trim($val);
}

// #############################################################################
/**
* Refactor for fetch_template_update_sql() to fit the assertor syntax.
* Returns the sql query name to be executed with the params
*
* @param	string	Title of template
* @param	string	Un-parsed template HTML
* @param	integer	Style ID for template
* @param	array	(ref) array('template' => array($title => true))
* @param	string	The name of the product this template is associated with
*
* @return	array	Containing the queryname and the params needed for the query.
* 					It will return a 'name' key in the params array used if we are using a stored query or query method.
*/
function fetchTemplateUpdateSql($title, $template, $dostyleid, &$delete, $product = 'vbulletin')
{
	global $template_cache;

	$oldtemplate = $template_cache['template']["$title"];

	if (is_array($template))
	{
		array_walk($template, 'array_trim');
		$template = "background: $template[background]; color: $template[color]; padding: $template[padding]; border: $template[border];";
	}

	// check if template should be deleted
	if ($delete['template']["$title"])
	{
		return array('queryname' => 'vBForum:template', 'params' => array(	// todo this should probably be 'template' not 'vBForum:template'
			vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_DELETE,
			'templateid' => $oldtemplate['templateid']
		));
	}

	if ($template == $oldtemplate['template_un'])
	{
		return false;
	}
	else
	{
		// check for copyright removal
		if ($title == 'footer' // only check footer template
			AND strpos($template, '$vbphrase[powered_by_vbulletin]') === false // template to be saved has no copyright
			AND strpos($oldtemplate['template_un'], '$vbphrase[powered_by_vbulletin]') !== false // pre-saved template includes copyright - therefore a removal attempt is being made
		)
		{
			print_stop_message2('you_can_not_remove_vbulletin_copyright');
		}

		// parse template conditionals, bypass special templates
		if (!in_array($title, vB_Api::instanceInternal('template')->fetchSpecialTemplates()))
		{
			/*
				This function is only used by admincp/css.php ATM, and requires canadmintemplates permission.
				I don't think we want to change any template's textonly field for this function.
				Note that replaceTemplates query already handles ignoring missing fields (e.g. not specifying textonly).
			 */
			$parsedtemplate = compile_template($template);

			$errors = check_template_errors($parsedtemplate);

			// halt if errors in conditionals
			if (!empty($errors))
			{
				print_stop_message('error_in_template_x_y', $title, "<i>$errors</i>");
			}
		}
		else
		{
			$parsedtemplate =& $template;
		}

		$full_product_info = fetch_product_list(true);
		$userInfo = vB::getCurrentSession()->fetch_userinfo();
		$queryBits = array(
			'styleid' => intval($dostyleid),
			'title' => $title,
			'template' => $parsedtemplate,
			'template_un' => $template,
			'templatetype' => 'template',
			'dateline' => vB::getRequest()->getTimeNow(),
			'username' => $userInfo['username'],
			'version' => $full_product_info["$product"]['version'],
			'product' => $product,
			// ignoring textonly, see note above at the compile_template() call
		);

		return array('queryname' => 'replaceTemplates', 'params' => array('name' => 'querybits', 'value' => array($queryBits)));
	}

}

// #############################################################################
/**
* Checks the style id of a template item and works out if it is inherited or not
*
* @param	integer	Style ID from template record
*
* @return	string	CSS class name to use to display item
*/
function fetch_inherited_color($itemstyleid, $styleid)
{
	switch ($itemstyleid)
	{
		case $styleid: // customized in current style, or is master set
			if ($styleid == -1)
			{
				return 'col-g';
			}
			else
			{
				return 'col-c';
			}
		case -1: // inherited from master set
		case 0:
			return 'col-g';
		default: // inhertited from parent set
			return 'col-i';
	}

}

// #############################################################################
/**
* Saves the correct style parentlist to each style in the database
*/
function build_template_parentlists()
{
	$styles = vB::getDbAssertor()->assertQuery('vBForum:fetchstyles2');
	foreach ($styles as $style)
	{
		$parentlist = vB_Library::instance('Style')->fetchTemplateParentlist($style['styleid']);
		if ($parentlist != $style['parentlist'])
		{
			vB::getDbAssertor()->assertQuery('vBForum:updatestyleparent', array(
				'parentlist' => $parentlist,
				'styleid' => $style['styleid']
			));
		}
	}

}

// #############################################################################
/**
* Builds all data from the template table into the fields in the style table
*
* @param	boolean $renumber -- no longer used.  Feature removed.
* @param	boolean	If true, will fix styles with no parent style specified
* @param	string	If set, will redirect to specified URL on completion
* @param	boolean	If true, reset the master cache
* @param	boolean	Whether to print status/edit information
*/
function build_all_styles($renumber = 0, $install = 0, $goto = '', $resetcache = false, $printInfo = true)
{
	// -----------------------------------------------------------------------------
	// -----------------------------------------------------------------------------
	// this bit of text is used for upgrade scripts where the phrase system
	// is not available it should NOT be converted into phrases!!!
	$phrases = array(
		'master_style' => 'MASTER STYLE',
		'done' => 'Done',
		'style' => 'Style',
		'styles' => 'Styles',
		'templates' => 'Templates',
		'css' => 'CSS',
		'stylevars' => 'Stylevars',
		'replacement_variables' => 'Replacement Variables',
		'controls' => 'Controls',
		'rebuild_style_information' => 'Rebuild Style Information',
		'updating_style_information_for_each_style' => 'Updating style information for each style',
		'updating_styles_with_no_parents' => 'Updating style sets with no parent information',
		'updated_x_styles' => 'Updated %1$s Styles',
		'no_styles_needed_updating' => 'No Styles Needed Updating',
	);
	$vbphrase = vB_Api::instanceInternal('phrase')->fetch($phrases);
	foreach ($phrases AS $key => $val)
	{
		if (!isset($vbphrase["$key"]))
		{
			$vbphrase["$key"] = $val;
		}
	}
	// -----------------------------------------------------------------------------
	// -----------------------------------------------------------------------------

	if (!empty($goto))
	{
		$form_tags = true;
	}

	if ($printInfo AND (VB_AREA != 'Upgrade' AND VB_AREA != 'Install'))
	{
		echo "<!--<p>&nbsp;</p>-->
		<blockquote>" . iif($form_tags, "<form>") . "<div class=\"tborder\">
		<div class=\"tcat\" style=\"padding:4px\" align=\"center\"><b>" . $vbphrase['rebuild_style_information'] . "</b></div>
		<div class=\"alt1\" style=\"padding:4px\">\n<blockquote>
		";
		vbflush();
	}

	// useful for restoring utterly broken (or pre vb3) styles
	if ($install)
	{
		if ($printInfo AND (VB_AREA != 'Upgrade' AND VB_AREA != 'Install'))
		{
			echo "<p><b>" . $vbphrase['updating_styles_with_no_parents'] . "</b></p>\n<ul class=\"smallfont\">\n";
			vbflush();
		}

		vB::getDbAssertor()->assertQuery('updt_style_parentlist');
	}

	if ($printInfo AND (VB_AREA != 'Upgrade' AND VB_AREA != 'Install'))
	{
		// the main bit.
		echo "<p><b>" . $vbphrase['updating_style_information_for_each_style'] . "</b></p>\n";
		vbflush();
	}

	build_template_parentlists();

	$styleactions = array('dostylevars' => 1, 'doreplacements' => 1, 'doposteditor' => 1);
	if (defined('NO_POST_EDITOR_BUILD'))
	{
		$styleactions['doposteditor'] = 0;
	}

	if ($error = build_style(-1, $vbphrase['master_style'], $styleactions, '', '', $resetcache, $printInfo))
	{
		return $error;
	}

	if ($printInfo AND (VB_AREA != 'Upgrade' AND VB_AREA != 'Install'))
	{
		echo "</blockquote></div>";
		if ($form_tags)
		{
			echo "
			<div class=\"tfoot\" style=\"padding:4px\" align=\"center\">
			<input type=\"button\" class=\"button\" value=\" " . $vbphrase['done'] . " \" onclick=\"window.location='$goto';\" />
			</div>";
		}
		echo "</div>" . iif($form_tags, "</form>") . "</blockquote>
		";
		vbflush();
	}

	vB_Library::instance('Style')->buildStyleDatastore();
}

// #############################################################################
/**
* Displays a style rebuild (build_style) in a nice user-friendly info page
*
* @param	integer	Style ID to rebuild
* @param	string	Title of style
* @param	boolean	Build CSS? (no longer used)
* @param	boolean	Build Stylevars?
* @param	boolean	Build Replacements?
* @param	boolean	Build Post Editor?
*/
function print_rebuild_style($styleid, $title = '', $docss = 1, $dostylevars = 1, $doreplacements = 1, $doposteditor = 1, $printInfo = true)
{
	$vbphrase = vB_Api::instanceInternal('phrase')->fetch(array('master_style', 'rebuild_style_information', 'updating_style_information_for_x', 'done'));
	$styleid = intval($styleid);

	if (empty($title))
	{
		if ($styleid == -1)
		{
			$title = $vbphrase['master_style'];
		}
		else
		{
			DEVDEBUG('Querying first style name');
			$getstyle = vB_Library::instance('Style')->fetchStyleByID($styleid);

			if (!$getstyle)
			{
				return;
			}

			$title = $getstyle['title'];
		}
	}

	if ($printInfo AND (VB_AREA != 'Upgrade') AND (VB_AREA != 'Install'))
	{
		echo "<p>&nbsp;</p>
		<blockquote><form><div class=\"tborder\">
		<div class=\"tcat\" style=\"padding:4px\" align=\"center\"><b>" . $vbphrase['rebuild_style_information'] . "</b></div>
		<div class=\"alt1\" style=\"padding:4px\">\n<blockquote>
		<p><b>" . construct_phrase($vbphrase['updating_style_information_for_x'], $title) . "</b></p>
		<ul class=\"lci\">\n";
		vbflush();
	}

	$actions = array(
		'dostylevars' => $dostylevars,
		'doreplacements' => $doreplacements,
		'doposteditor' => $doposteditor
	);
	build_style($styleid, $title, $actions, false, '', 1, $printInfo);

	if ($printInfo AND (VB_AREA != 'Upgrade') AND (VB_AREA != 'Install'))
	{
		echo "</ul>\n<p><b>" . $vbphrase['done'] . "</b></p>\n</blockquote></div>
		</div></form></blockquote>
		";
		vbflush();
	}

	vB_Library::instance('Style')->buildStyleDatastore();

}

// #############################################################################

/**
 *	Deletes the old style css directory on disk
 *
 *	@param int $styleid
 *	@param string $dir -- the "direction" of the css to delete.  Either 'ltr' or 'rtl' (there are actually two directories per style)
 *	@param bool $contentsonly	-- whether to delete the newly empty directory (if we are deleting the contents to rewrite there is no need)
 */
function delete_style_css_directory($styleid, $dir = 'ltr', $contentsonly = false)
{
	$styledir = vB_Api::instanceInternal('style')->getCssStyleDirectory($styleid, $dir);
	$styledir = $styledir['directory'];

	if (is_dir($styledir))
	{
		$dirhandle = opendir($styledir);

		if ($dirhandle)
		{
			// loop through the files in the style folder
			while (($fname = readdir($dirhandle)) !== false)
			{
				$filepath = $styledir . '/' . $fname;

				// remove just the files inside the directory
				// and this also takes care of the '.' and '..' folders
				if (!is_dir($filepath))
				{
					@unlink($filepath);
				}
			}
			// Close the handle
			closedir($dirhandle);
		}

		// Remove the style directory
		if(!$contentsonly)
		{
			@rmdir($styledir);
		}
	}
}

// #############################################################################
/**
* Attempts to create a new css file for this style
*
* @param	string	CSS filename
* @param	string	CSS contents
*
* @return	boolean	Success
*/
function write_css_file($filename, $contents)
{
	// attempt to write new css file - store in database if unable to write file
	if ($fp = @fopen($filename, 'wb') AND !is_demo_mode())
	{
		fwrite($fp, $contents);
		@fclose($fp);
		return true;
	}
	else
	{
		@fclose($fp);
		return false;
	}
}

/**
 *	Writes style css directory to disk, this includes SVG templates
 *
 *	@param int $styleid
 *	@param string $parentlist -- csv list of ancestors for this style
 *	@param string $dir -- the "direction" of the css to write.  Either 'ltr' or 'rtl' (there are actually two directories per style)
 */
function write_style_css_directory($styleid, $parentlist, $dir = 'ltr')
{
	//verify that we have or can create a style directory
	$styledir = vB_Api::instanceInternal('style')->getCssStyleDirectory($styleid, $dir);
	$styledir = $styledir['directory'];

	//if we have a file that's not a directory or not writable something is wrong.
	if (file_exists($styledir) AND (!is_dir($styledir) OR !is_writable($styledir)))
	{
		return false;
	}

	//clear any old files.
	if (file_exists($styledir))
	{
		delete_style_css_directory($styleid, $dir, true);
	}

	//create the directory -- if it still exists try to continue with the existing dir
	if (!file_exists($styledir))
	{
		if (!mkdir($styledir, 0777, true))
		{
			return false;
		}
	}

	//check for success.
	if (!is_dir($styledir) OR !is_writable($styledir))
	{
		return false;
	}

	// NOTE: SVG templates are processed along with CSS templates.
	// I observed no unwanted behavior by doing this, and if in the
	// future, CSS and SVG templates need to be processed separately
	// we can refactor this at that point.

	//write out the files for this style.
	$parentlistarr = explode(',', $parentlist);
	$set = vB::getDbAssertor()->assertQuery('template_fetch_css_svg_templates', array('styleidlist' => $parentlistarr));

	//collapse the list.
	$css_svg_templates = array();
	foreach ($set as $row)
	{
		$css_svg_templates[] = $row['title'];
	}

	$stylelib = vB_Library::instance('Style');
	$stylelib->switchCssStyle($styleid, $css_svg_templates);

	// Get new css cache bust
	$stylelib->setCssFileDate($styleid);
	$cssfiledate = $stylelib->getCssFileDate($styleid);

	// Keep pseudo stylevars in sync with the css.php and sprite.php handling
	set_stylevar_ltr(($dir == 'ltr'));
	set_stylevar_meta($styleid);

	$base = get_base_url_for_css();
 	if ($base === false)
	{
		return false;
	}

	$templates = array();
	$templates_not_in_rollups = array();
	foreach ($css_svg_templates AS $title)
	{
		//I'd call this a hack but there probably isn't a cleaner way to do this.
		//The css is published to a different directory than the css.php file
		//which means that relative urls that works for css.php won't work for the
		//published directory.  Unfortunately urls from the webroot don't work
		//because the forum often isn't located at the webroot and we can only
		//specify urls from the forum root.  And css doens't provide any way
		//of setting a base url like html does.  So we are left to "fixing"
		//any relative urls in the published css.
		//
		//We leave alone any urls starting with '/', 'http', 'https:', 'data:', and '#'
		// URLs starting with # are for SVG sprite filter elements
		//there are other valid urls, but nothing that people should be
		//using in our css files.
		$text = vB_Template::create($title)->render(true);

		//update image urls to be fully qualified.
		$re = '#url\(\s*["\']?(?!/|http:|https:|data:|\#|"/|\'/)#';
		$text = preg_replace ($re, "$0$base", $text);
		$text = vB_String::getCssMinifiedText($text);

		$templates[$title] = $text;
		$templates_not_in_rollups[$title] = true;
	}

	static $vbdefaultcss = array(), $cssfiles = array();

	if (empty($vbdefaultcss))
	{
		$cssfilelist = vB_Api::instanceInternal('product')->loadProductCssRollups();

		if (empty($cssfilelist['vbulletin']))
		{
			$vbphrase = vB_Api::instanceInternal('phrase')->fetch(array('could_not_open_x'));
			echo construct_phrase($vbphrase['could_not_open_x'], DIR . '/includes/xml/cssrollup_vbulletin.xml');
			exit;
		}

		$data = $cssfilelist['vbulletin'];
		unset($cssfilelist['vbulletin']);

		if (!is_array($data['rollup'][0]))
		{
			$data['rollup'] = array($data['rollup']);
		}

		foreach ($data['rollup'] AS $file)
		{
			foreach ($file['template'] AS $name)
			{
				$vbdefaultcss["$file[name]"] = $file['template'];
			}
		}

		foreach ($cssfilelist AS $css_file => $data)
		{
			$products = vB::getDatastore()->getValue('products');
			if ($data['product'] AND empty($products["$data[product]"]))
			{
				// attached to a specific product and that product isn't enabled
				continue;
			}

			if (!is_array($data['rollup'][0]))
			{
				$data['rollup'] = array($data['rollup']);
			}

			$cssfiles[$css_file]['css'] = $data['rollup'];
		}
	}


	foreach ($cssfiles AS $css_file => $files)
	{
		if (is_array($files['css']))
		{
			foreach ($files['css'] AS $file)
			{
				$result = process_css_rollup_file($file['name'], $file['template'], $templates,
					$styleid, $styledir, $templates_not_in_rollups, $vbdefaultcss);
				if ($result === false)
				{
					return false;
				}
			}
		}
	}

	foreach ($vbdefaultcss AS $xmlfile => $files)
	{
		$result = process_css_rollup_file($xmlfile, $files, $templates, $styleid, $styledir, $templates_not_in_rollups);
		if ($result === false)
		{
			return false;
		}
	}

	foreach($templates_not_in_rollups AS $title => $dummy)
	{
		if (!write_css_file("$styledir/$cssfiledate-$title", $templates[$title]))
		{
			return false;
		}
	}

	return true;
}

/**
 *	Gets the base url for images in the css files
 *
 *	This will be the site root unless there is a CDN configured
 *	the image will all be specified in the css to the url the css.php file is located.
 *	When writing the css to disk we make the urls absolute because the paths are different
 *	from the static css files.
 */
function get_base_url_for_css()
{
	/*
	 *	Most of this is probably an artifact of how we did it before there
	 *	was a frontendurl option, but there might be something in the installer
	 *	that depends on this behavior
	 */

	/*	We need the frontend base url, but this isnt always available.
	If it is available, we simply use it - otherwise we attempt to
	read the frontend config file. In 99.9% of sites this will work.
	If that fails, we attempt to get it from the backend config file.
	This requires that the backend config has this set (Misc, baseurl),
	By default this isnt set, but the site administrator can set it.
	If all this fails, we give up and return false */

	$config = array();


	if ($frontendurl = vB::getDatastore()->getOption('frontendurl'))
	{
		$config['baseurl'] = $frontendurl;
	}
	else if (file_exists($cfile))
	{
		/* Sometimes realpath fails .. PHP documentation states:
		The running script must have executable permissions on all
		directories in the hierarchy, otherwise realpath() will return false */
		if (!($cfile = realpath(DIR . './../config.php')))
		{
			$cfile = '../config.php';
		}

		include($cfile);
	}
	else
	{
		$config =& vB::getConfig();
		$config['baseurl'] = $config['Misc']['baseurl'];
	}

	if (!isset($config['baseurl']))
	{
		return false;
	}
	else
	{
		$base = vB::getDatastore()->getOption('cdnurl');
		if (!$base)
		{
			$base = $config['baseurl'];
		}

		if (substr($base, -1, 1) != '/')
		{
			$base .= '/';
		}
	}

	return $base;
}


function process_css_rollup_file(
	$file,
	$templatelist,
	$templates,
	$styleid,
	$styledir,
	&$templates_not_in_rollups,
	&$vbdefaultcss = array()
)
{
	if (!is_array($templatelist))
	{
		$templatelist = array($templatelist);
	}

	if ($vbdefaultcss AND $vbdefaultcss["$file"])
	{
		// Add these templates to the main file rollup
		$vbdefaultcss["$file"] = array_unique(array_merge($vbdefaultcss["$file"], $templatelist));
		return true;
	}

	$count = 0;
	$text = "";
	foreach ($templatelist AS $name)
	{
		unset($templates_not_in_rollups[$name]);
		$template = $templates[$name];
		if ($count > 0)
		{
			$text .= "\r\n\r\n";
			$template = preg_replace("#@charset [^;]*;#i", "", $template);
		}
		$text .= $template;
		$count++;
	}

	$stylelib = vB_Library::instance('Style');
	$cssfiledate = $stylelib->getCssFileDate($styleid);

	if (!write_css_file("$styledir/$cssfiledate-$file", $text))
	{
		return false;
	}

	return true;
}

// #############################################################################
/**
* Converts all data from the template table for a style into the style table
*
* @param	integer	Style ID
* @param	string	Title of style
* @param	array	Array of actions set to true/false: dostylevars/doreplacements/doposteditor
* @param	string	List of parent styles
* @param	string	Indent for HTML printing
* @param	boolean	Reset the master cache
* @param	boolean	Whether to print status/edit information
*/
function build_style($styleid, $title = '', $actions = array(), $parentlist = '', $indent = '', $resetcache = false, $printInfo = true)
{
	//not sure if this is required.
	require_once(DIR . '/includes/adminfunctions.php');

	$db = vB::getDbAssertor();
	$datastore = vB::getDatastore();
	$styleLib = vB_Library::instance('Style');

	$doOutput = ($printInfo AND VB_AREA != 'Upgrade' AND VB_AREA != 'Install');

	//we only use the phrases if we are doing some output.  No need to load them if we aren't going to use them.
	//note that they are cached so we aren't querying the DB for each style
	if($doOutput)
	{
		$vbphrase = vB_Api::instanceInternal('phrase')->fetch(array('templates', 'stylevars', 'replacement_variables', 'controls', 'done'));
	}

	//don't propagate any local changes to actions to child rebuilds.
	$originalactions = $actions;
	if ($styleid != -1)
	{
		$usecssfiles = $styleLib->useCssFiles($styleid);

		//this is some *old* code.  I think it's due to some fields that writing css files
		//relies on not getting set, but it's been copied, tweaked, and mangled since cssasfiles
		//referred to the vB3 css and not the css template sheets so it's not 100% if it's needed
		//any longer.
		if (($actions['doreplacements'] OR $actions['dostylevars']) AND $usecssfiles)
		{
			$actions['doreplacements'] = true;
		}

		// VBV-16291 certain actions, like write_css_file(), relies on in-memory cached items that would normally be cleared
		// if going through the styleLIB's buildStyle(). To avoid stale data issues in upgrade, we manually clear it here.
		$styleLib->internalCacheClear($styleid);
		if ($doOutput)
		{
			// echo the title and start the listings
			echo "$indent<li><b>$title</b> ... <span class=\"smallfont\">";
			vbflush();
		}

		// build the templateid cache
		if (!$parentlist)
		{
			$parentlist = $styleLib->fetchTemplateParentlist($styleid);
		}

		$templatelist = $styleLib->buildTemplateIdCache($styleid, 1, $parentlist);

		$styleupdate = array();
		$styleupdate['templatelist'] = $templatelist;

		if ($printInfo AND (VB_AREA != 'Upgrade' AND VB_AREA != 'Install'))
		{
			echo "($vbphrase[templates]) ";
			vbflush();
		}

		// cache special templates
		if ($actions['doreplacements'] OR $actions['doposteditor'])
		{
			// get special templates for this style
			$template_cache = array();
			$templateids = unserialize($templatelist);
			$specials = vB_Api::instanceInternal('template')->fetchSpecialTemplates();

			if ($templateids)
			{
				$templates = $db->assertQuery('vBForum:fetchtemplatewithspecial', array(
					'templateids' => $templateids,
					'specialtemplates' => $specials
				));

				foreach ($templates as $template)
				{
					$template_cache["$template[templatetype]"]["$template[title]"] = $template;
				}
			}
		}

		// style vars
		if ($actions['dostylevars'])
		{
			// new stylevars
			static $master_stylevar_cache = null;
			static $resetcachedone = false;
			if ($resetcache AND !$resetcachedone)
			{
				$resetcachedone = true;
				$master_stylevar_cache = null;
			}

			if ($master_stylevar_cache === null)
			{
				$master_stylevar_cache = array();
				$master_stylevars = $db->assertQuery('vBForum:getDefaultStyleVars');

				foreach ($master_stylevars AS $master_stylevar)
				{
					$tmp = unserialize($master_stylevar['value']);
					if (!is_array($tmp))
					{
						$tmp = array('value' => $tmp);
					}
					$master_stylevar_cache[$master_stylevar['stylevarid']] = $tmp;
					$master_stylevar_cache[$master_stylevar['stylevarid']]['datatype'] = $master_stylevar['datatype'];
				}
			}

			$newstylevars = $master_stylevar_cache;

			if (substr(trim($parentlist), 0, -3) != '')
			{
				$data = array(
					'stylelist' => explode(',', substr(trim($parentlist), 0, -3)),
					'parentlist' => $parentlist,
				);
				$new_stylevars = $db->getRows('vBForum:getStylesFromList', $data);

				foreach ($new_stylevars as $new_stylevar)
				{
					ob_start();
					$newstylevars[$new_stylevar['stylevarid']] = unserialize($new_stylevar['value']);
					if (ob_get_clean() OR !is_array($newstylevars[$new_stylevar['stylevarid']]))
					{
						continue;
					}

					$newstylevars[$new_stylevar['stylevarid']]['datatype'] = $master_stylevar_cache[$new_stylevar['stylevarid']]['datatype'];
				}
			}

			$styleupdate['newstylevars'] = serialize($newstylevars);

			if ($doOutput)
			{
				echo "($vbphrase[stylevars]) ";
				vbflush();
			}
		}

		// replacements
		if ($actions['doreplacements'])
		{
			// rebuild the replacements field for this style
			$replacements = array();
			if (is_array($template_cache['replacement']))
			{
				foreach($template_cache['replacement'] AS $template)
				{
					// set the key to be a case-insentitive preg find string
					$replacementkey = '#' . preg_quote($template['title'], '#') . '#si';

					$replacements["$replacementkey"] = $template['template'];
				}
				$styleupdate['replacements'] = serialize($replacements) ;
			}
			else
			{
				$styleupdate['replacements'] = "''";
			}

			if ($doOutput)
			{
				echo "($vbphrase[replacement_variables]) ";
				vbflush();
			}
		}

		// post editor styles
		if ($actions['doposteditor'] AND $template_cache['template'])
		{
			$editorstyles = array();
			if (!empty($template_cache['template']))
			{
				foreach ($template_cache['template'] AS $template)
				{
					if (substr($template['title'], 0, 13) == 'editor_styles')
					{
						$title = 'pi' . substr($template['title'], 13);
						$item = fetch_posteditor_styles($template['template']);
						$editorstyles["$title"] = array($item['background'], $item['color'], $item['padding'], $item['border']);
					}
				}
			}
			if  ($doOutput)
			{
				echo "($vbphrase[controls]) ";
				vbflush();
			}
		}

		// do the style update query
		if (!empty($styleupdate))
		{
			$styleupdate['styleid'] = $styleid;
			$styleupdate[vB_dB_Query::TYPE_KEY] = vB_dB_Query::QUERY_UPDATE;
			$db->assertQuery('vBForum:style', $styleupdate);
		}

		//write out the new css -- do this *after* we update the style record
		if ($usecssfiles)
		{
			foreach(array('ltr', 'rtl') AS $direction)
			{
				if (!write_style_css_directory($styleid, $parentlist, $direction))
				{
					$error = fetch_error("rebuild_failed_to_write_css");
					if ($doOutput)
					{
						echo $error;
					}
					else
					{
						return $error;
					}
				}
			}
		}

		// finish off the listings
		if ($doOutput)
		{
			echo "</span><b>" . $vbphrase['done'] . "</b>.<br />&nbsp;</li>\n";
			vbflush();
		}
	}

	$childsets = $db->getRows('style', array('parentid' => $styleid));
	if (count($childsets))
	{
		if ($doOutput)
		{
			echo "$indent<ul class=\"ldi\">\n";
		}

		foreach ($childsets as $childset)
		{
			if ($error = build_style($childset['styleid'], $childset['title'], $originalactions, $childset['parentlist'], $indent . "\t", $resetcache, $printInfo))
			{
				return $error;
			}
		}

		if ($doOutput)
		{
			echo "$indent</ul>\n";
		}
	}

	//We want to force a fastDS rebuild, but we can't just call rebuild. There may be dual web servers,
	// and calling rebuild only rebuilds one of them.
	$options = $datastore->getValue('miscoptions');
	$options['tmtdate'] = vB::getRequest()->getTimeNow();
	$datastore->build('miscoptions', serialize($options), 1);
}

// #############################################################################
/**
* Prints out a style editor block, as seen in template.php?do=modify
*
* @param	integer	Style ID
* @param	array	Style info array
*/
function print_style($styleid, $style = array())
{
	global $vbulletin, $masterset;

	//we really shouldn't be looking up query string/post info inside of functions
	//but at least we can pull it out to the top of the first function instead of
	//embedding it
	$titlesonly = $vbulletin->GPC['titlesonly'];
	$expandset = $vbulletin->GPC['expandset'];
	$group = $vbulletin->GPC['group'];
	$searchstring = $vbulletin->GPC['searchstring'];

	//this is *probably* always set, based on where the function gets called,
	//but the original code had a guard on it and so we'll make sure.
 	$templateid = (!empty($vbulletin->GPC['templateid']) ? $vbulletin->GPC['templateid'] : null);

	$vb5_config = vB::getConfig();

	$vbphrase = vB_Api::instanceInternal('phrase')->fetch(array(
		'add_child_style', 'add_new_template', 'all_template_groups', 'allow_user_selection',
		'collapse_all_template_groups', 'collapse_template_group', 'collapse_templates',
		'collapse_x', 'common_templates', 'controls', 'custom_templates', 'customize_gstyle',
		'delete_style', 'display_order', 'download', 'edit', 'edit_fonts_colors_etc', 'edit_settings_gstyle',
		'edit_style_options', 'edit_templates', 'expand_all_template_groups', 'expand_template_group',
		'expand_templates', 'expand_x', 'go', 'master_style', 'replacement_variables', 'revert_all_stylevars',
		'revert_all_templates', 'revert_gcpglobal', 'stylevareditor', 'template_is_customized_in_this_style',
		'template_is_inherited_from_a_parent_style', 'template_is_unchanged_from_the_default_style',
		'template_options', 'view_original', 'view_your_forum_using_this_style', 'x_templates', 'choose_action'
	));

	if ($styleid == -1)
	{
		$style['styleid'] = $styleid;
		$style['title'] = $vbphrase['master_style'];
		$style['templatelist'] = $masterset;
		$style['depth'] = 0;
	}
	else
	{
		//in debug mode we show the MASTER style as a the root so we need an extra depth level
		if($vb5_config['Misc']['debug'])
		{
			$style['depth']++;
		}
	}

	//canadminstyles no and canadmintemplates yes isn't really a sensible combination
	//as a result some of the behavior in this instance is inconsistant.  It's not
	//clear if we should even be displaying any of this if the user doesn't have
	//"canadminstyles" (I'm not sure if you can even get to this function without it).
	//Cleaning all of that up is beyond the current scope, but
	//we need to make sure the only canadminstyles and both are well handled.
	$userContext = vB::getUserContext();
	$canadminstyles = $userContext->hasAdminPermission('canadminstyles');
	$canadmintemplates = $userContext->hasAdminPermission('canadmintemplates');

	if ($expandset == 'all' OR $expandset == $styleid)
	{
		$showstyle = 1;
	}
	else
	{
		$showstyle = 0;
	}

	// show the header row
	print_style_header_row($vbphrase, $style, $canadminstyles, $canadmintemplates, $group, $showstyle);
	if ($showstyle)
	{
		//Need to figure out how to ensure that the templatelist is properly passed so
		//we don't need this silliness.  But for now pulling it to the top level function
		//for visibility.
		//master style doesn't really exist and therefore can't be loaded.
		if (empty($style['templatelist']))
		{
	 		$style = vB_Library::instance('Style')->fetchStyleById($styleid);
		}

		/*
			If $style was passed into this function, templatelist might still be a serialized string.
			Note, I only ever ran into this once, and it never happened again, so it might've been
			some old cached data somewhere (cached before the removal of templatelist from the stylecache,
			maybe?)
		 */
		if (is_string($style['templatelist']))
		{
			$style['templatelist'] = unserialize($style['templatelist']);
		}

		$groups = vB_Library::instance('template')->getTemplateGroupPhrases();
		$template_groups = vB_Api::instanceInternal('phrase')->renderPhrases($groups);
		$template_groups = $template_groups['phrases'];

		$templates = print_style_get_templates($vbulletin->db, $style, $masterset, $template_groups, $searchstring, $titlesonly);
	 	if($templates)
		{
			print_style_body($vbphrase, $templates, $template_groups, $style, $canadmintemplates, $group, $templateid, $expandset);
		}
	}
}


// Function to break up print_style into something readable.  Should be considered "private" to this file
function print_style_header_row($vbphrase, $style, $canadminstyles, $canadmintemplates, $group, $showstyle)
{
	$styleid = $style['styleid'];

	$styleLib = vB_Library::instance('style');
	$styleIsReadonly = !$styleLib->checkStyleReadProtection($styleid, $style);

	$showReadonlyMarking = !$styleLib->checkStyleReadProtection($styleid, $style, true);

	$onclickoptions = array('do' => 'modify', 'group' => $group);
	if (empty($showstyle))
	{
		$onclickoptions['expandset'] = $styleid;
	}

	$altRowClass = fetch_row_bgclass();

	$title = $style['title'];
	if ($showReadonlyMarking)
	{
		$title = $style['title'] . " <span class=\"acp-style-readonly-mark\"></span>";
	}

	$printstyleid = 'm';
	$userselect = '';
	$displayorder = '';

	if($styleid != -1)
	{
		$printstyleid = $styleid;

		$userselect = '<input type="checkbox" name="userselect[' . $styleid . ']" value="1" tabindex="1" ';
		if($style['userselect'])
		{
			$userselect .= 'checked="checked" ';
		}
		$userselect .= 'id="userselect_' . $styleid . '" onclick="check_children(' . $styleid . ', this.checked)" />';

		$displayorder = '<input type="text" class="bginput" name="displayorder[' . $styleid . ']" value="' . $style['displayorder'] .
			'" tabindex="1" size="2" title="' . $vbphrase['display_order'] . '" />';
	}

	$label = '&nbsp; ' . construct_depth_mark($style['depth'],	'- - ') . $userselect;

	$forumhome_url = vB5_Route::buildUrl('home|fullurl', array(), array('styleid' => $styleid));

	//this should be all possible option groups.  We'll control via permissions later on.
	//Only groups with options will be displayed.  Order in this array controls display order.
	//We assume that everything except the default "choose" option is in an option group
	//Note that if display_order is not unique then order is undefined (and can vary based on inconsequential changes)
	//We do it this way so that we don't have to consider whether to display an option in the order that we
	//intend to display it -- thus allowing us to avoid massive duplication of logic.
	$optgroups = array(
		'template_options' => array(),
		'edit_fonts_colors_etc' => array(),
		'edit_style_options' => array(),
	);

	//these options for for the more detailed template edit options.
	if ($canadmintemplates)
	{
		if(!$styleIsReadonly)
		{
			//these do not apply to the master style
			if($styleid != -1)
			{
				$optgroups['template_options'][30] = array('phrase' => 'revert_all_templates', 'action' => 'template_revertall');
			}

			$optgroups['edit_fonts_colors_etc'][10] = array('phrase' => 'common_templates', 'action' => 'css_templates');
		}

		$optgroups['edit_style_options'][30] = array('phrase' => 'download', 'action' => 'template_download');
	}

	//we now allow this regardless of which permission the admin has
	if(!$styleIsReadonly)
	{
		$optgroups['template_options'][10] = array('phrase' => 'edit_templates', 'action' => 'template_templates');
		$optgroups['template_options'][20] = array('phrase' => 'add_new_template', 'action' => 'template_addtemplate');
	}

	if ($canadminstyles)
	{
		if(!$styleIsReadonly)
		{
			$optgroups['edit_fonts_colors_etc'][20] = array('phrase' => 'stylevareditor', 'action' => 'stylevar');

			if($styleid != -1)
			{
				$optgroups['edit_fonts_colors_etc'][30] = array('phrase' => 'revert_all_stylevars', 'action' => 'stylevar_revertall');
			}

			$optgroups['edit_fonts_colors_etc'][40] = array('phrase' => 'replacement_variables', 'action' => 'css_replacements');
		}

		if($styleid != -1)
		{
			$optgroups['edit_style_options'][10] = array('phrase' => 'edit_settings_gstyle', 'action' => 'template_editstyle');
			$optgroups['edit_style_options'][40] = array('phrase' => 'delete_style', 'action' => 'template_delete', 'class' => 'col-c');
		}

		$optgroups['edit_style_options'][20] = array('phrase' => 'add_child_style', 'action' => 'template_addstyle');
	}


	$optgrouptext = '';
	foreach($optgroups AS $groupphrase => $options)
	{
		if($options)
		{
			ksort($options);
			$optgrouptext .= '<optgroup label="' . $vbphrase[$groupphrase] . '">' . "\n";
			foreach($options AS $option)
			{
				$class = '';
				if(isset($option['class']))
				{
					$class = ' class="' . $option['class'] . '"';
				}

				$optgrouptext .= '<option value="' . $option['action'] . '"' . $class . '>' . $vbphrase[$option['phrase']] . "</option>\n";
			}
			$optgrouptext .= "</optgroup>\n";
		}
	}

	echo "
	<!-- start header row for style '$styleid' -->
	<table id='styleheader" . $styleid . "' cellpadding=\"2\" cellspacing=\"0\" border=\"0\" width=\"100%\" class=\"stylerow $altRowClass\">
	<tr>
		<td>
			<label for=\"userselect_$styleid\" title=\"$vbphrase[allow_user_selection]\">$label</label>" . //whitespace in the html here alters display
			"<a href=\"$forumhome_url\" target=\"_blank\" title=\"$vbphrase[view_your_forum_using_this_style]\">$title</a>
		</td>
		<td align=\"" . vB_Template_Runtime::fetchStyleVar('right') . "\" nowrap=\"nowrap\">
			$displayorder
			&nbsp;
			<select name=\"styleEdit_$printstyleid\" id=\"menu_$styleid\" onchange=\"Sdo(this.options[this.selectedIndex].value, $styleid);\" class=\"bginput\">
			<option selected=\"selected\">" . $vbphrase['choose_action'] . "</option>
			$optgrouptext
			</select>"; //a newline here causes a display change.

	if($showstyle)
	{
		$code = COLLAPSECODE;
		$title = $vbphrase['collapse_templates'];
	}
	else
	{
		$code = EXPANDCODE;
		$title = $vbphrase['expand_templates'];
	}

	$onclick = "Texpand('" . $group . "', " . ($showstyle ? "''" : $styleid) . ")";
	$expandCollapse = construct_event_button_code($code, $onclick, '', '', $title) . '&nbsp;';

	$goButton = construct_event_button_code($vbphrase['go'],
		"Sdo(this.form.styleEdit_$printstyleid.options[this.form.styleEdit_$printstyleid.selectedIndex].value, $styleid);");

	echo "$goButton
			&nbsp;
			$expandCollapse
		</td>
	</tr>
	</table>
	<!-- end header row for style '$style[styleid]' -->
	";
}

// Function to break up print_style into something readable.  Should be considered "private" to this file
function print_style_get_templates($db, $style, $masterset, $template_groups, $searchstring, $titlesonly)
{
	$searchconds = array();

	if (!empty($searchstring))
	{
		$containsSearch = "LIKE('%" . $db->escape_string_like($searchstring) . "%')";
		if ($titlesonly)
		{
			$searchconds[] = "t1.title $containsSearch";
		}
		else
		{
			$searchconds[] = "( t1.title $containsSearch OR template_un $containsSearch ) ";
		}
	}

	// not sure if this if is necesary any more.  The template list should always be set
	// at this point and if it isn't things don't work properly.  However I need to stop
	// fixing things at some point and wrap this up.
	if (!empty($style['templatelist']) AND is_array($style['templatelist']))
	{
		$templateids = implode(',' , $style['templatelist']);
		if (!empty($templateids))
		{
			$searchconds[] = "templateid IN($templateids)";
		}
	}

	$specials = vB_Api::instanceInternal('template')->fetchSpecialTemplates();

	$templates = $db->query_read("
		SELECT templateid, IF(((t1.title LIKE '%.css') AND (t1.title NOT like 'css_%')),
			CONCAT('csslegacy_', t1.title), title) AS title, styleid, templatetype, dateline, username
		FROM " . TABLE_PREFIX . "template AS t1
		WHERE
			templatetype IN('template', 'replacement') AND " . implode(' AND ', $searchconds) . "
		AND title NOT IN('" . implode("', '", $specials) . "')
		ORDER BY title
	");

	// just exit if no templates found
	$numtemplates = $db->num_rows($templates);
	if ($numtemplates == 0)
	{
		return false;
	}

	$result = array(
		'replacements' => array(),
		'customtemplates' => array(),
		'maintemplates' => array(),
	);

	while ($template = $db->fetch_array($templates))
	{
		$templateid = $template['templateid'];
		if ($template['templatetype'] == 'replacement')
		{
			$result['replacements'][$templateid] = $template;
		}
		else
		{
			// don't show special templates
			if (in_array($template['title'], $specials))
			{
				continue;
			}

			$title = $template['title'];

			$groupname = explode('_', $title, 2);
			$groupname = $groupname[0];

			if ($template['styleid'] != -1 AND !isset($masterset[$title]) AND !isset($template_groups[$groupname]))
			{
				$result['customtemplates'][$templateid] = $template;
			}
			else
			{
				$result['maintemplates'][$templateid] = $template;
			}
		}
	}

	return $result;
}

// Function to break up print_style into something readable.  Should be considered "private" to this file
function print_style_body($vbphrase, $templates, $template_groups, $style, $canadmintemplates, $group, $selectedtemplateid, $expandset)
{
	$directionLeft = vB_Template_Runtime::fetchStyleVar('left');
	$styleid = $style['styleid'];

	//it's really not clear *why* we need to do this.  But in some instances we need an id of 0
	//instead of -1 for the master style.  Need to figure that out, but for now we'll keep the
	//previous behavior.
	$THISstyleid = $styleid;
	if($styleid == -1)
	{
		$THISstyleid = 0;
	}

	echo '
		<!-- start template list for style "' . $style['styleid'] . '" -->
		<table cellpadding="0" cellspacing="10" border="0" align="center">
			<tr valign="top">
				<td>
					<select name="tl' . $THISstyleid. '" id="templatelist' . $THISstyleid . '" class="darkbg" size="' . TEMPLATE_EDITOR_ROWS . '" style="width:450px"
						onchange="Tprep(this.options[this.selectedIndex], ' . $THISstyleid . ', 1);"
						ondblclick="Tdo(Tprep(this.options[this.selectedIndex], ' . $THISstyleid . ', 0), \'\');">
					<option class="templategroup" value="">- - ' . construct_phrase($vbphrase['x_templates'], $style['title']) . ' - -</option>
	';

	// custom templates
	if (!empty($templates['customtemplates']))
	{
		echo "<optgroup label=\"\">\n";
		echo "\t<option class=\"templategroup\" value=\"\">" . $vbphrase['custom_templates'] . "</option>\n";

		foreach($templates['customtemplates'] AS $template)
		{
			echo construct_template_option($template, $selectedtemplateid, $styleid);
			vbflush();
		}

		echo '</optgroup>';
	}

	// main templates
	if ($canadmintemplates AND !empty($templates['maintemplates']))
	{
		$lastgroup = '';
		$echo_ul = 0;

		foreach($templates['maintemplates'] AS $template)
		{
			$showtemplate = 1;
			if (!empty($lastgroup) AND isTemplateInGroup($template['title'], $lastgroup))
			{
				if ($group == 'all' OR $group == $lastgroup)
				{
					echo construct_template_option($template, $selectedtemplateid, $styleid);
					vbflush();
				}
			}
			else
			{
				foreach($template_groups AS $thisgroup => $display)
				{
					if ($lastgroup != $thisgroup AND $echo_ul == 1)
					{
						echo "</optgroup>";
						$echo_ul = 0;
					}

					if (isTemplateInGroup($template['title'], $thisgroup))
					{
						$lastgroup = $thisgroup;
						if ($group == 'all' OR $group == $lastgroup)
						{
							//don't select a group if we are selecting a template
							$selected = '';
							if($group == $thisgroup AND !$selectedtemplateid)
							{
								$selected = ' selected="selected"';
							}

							echo "<optgroup label=\"\">\n";
							echo "\t<option class=\"templategroup\" value=\"[]\"" . $selected . ">" .
								construct_phrase($vbphrase['x_templates'], $display) . " &laquo;</option>\n";
							$echo_ul = 1;
						}
						else
						{
							echo "\t<option class=\"templategroup\" value=\"[$thisgroup]\">" . construct_phrase($vbphrase['x_templates'], $display) . " &raquo;</option>\n";
							$showtemplate = 0;
						}
						break;
					}
				} // end foreach($template_groups

				if ($showtemplate)
				{
					echo construct_template_option($template, $selectedtemplateid, $styleid);
					vbflush();
				}
			} // end if template string same AS last
		}
	}


	echo '
		</select>
	</td>';

	echo "
	<td width=\"100%\" align=\"center\" valign=\"top\">
	<table cellpadding=\"4\" cellspacing=\"1\" border=\"0\" class=\"tborder\" width=\"300\">
	<tr align=\"center\">
		<td class=\"tcat\"><b>$vbphrase[controls]</b></td>
	</tr>
	<tr>
		<td class=\"alt2\" align=\"center\" style=\"font: 11px tahoma, verdana, arial, helvetica, sans-serif\"><div style=\"margin-bottom: 4px;\">\n" .
			construct_event_button_code($vbphrase['customize_gstyle'], "buttonclick(this, {$THISstyleid}, '');", "cust$THISstyleid") . "\n" .
			construct_event_button_code(trim(construct_phrase($vbphrase['expand_x'], '')) . '/' . trim(construct_phrase($vbphrase['collapse_x'], '')), "buttonclick(this, {$THISstyleid}, '');", "expa$THISstyleid") . "</div>\n" .
			construct_event_button_code($vbphrase['edit'], "buttonclick(this, {$THISstyleid}, '');", "edit$THISstyleid") . "\n" .
			construct_event_button_code($vbphrase['view_original'], "buttonclick(this, {$THISstyleid}, 'vieworiginal');", "orig$THISstyleid") . "\n" .
			construct_event_button_code($vbphrase['revert_gcpglobal'], "buttonclick(this, {$THISstyleid}, 'killtemplate');", "kill$THISstyleid") . "\n" .
			"<div class=\"darkbg\" style=\"margin: 4px; padding: 4px; border: 2px inset; text-align: " . $directionLeft . "\" id=\"helparea$THISstyleid\">
				" . construct_phrase($vbphrase['x_templates'], '<b>' . $style['title'] . '</b>') . "
			</div>\n" .
			construct_event_button_code(EXPANDCODE, "Texpand('all', '$expandset');", '', '', $vbphrase['expand_all_template_groups']) . "\n" .
			'<b>' . $vbphrase['all_template_groups'] . "</b>\n" .
			construct_event_button_code(COLLAPSECODE, "Texpand('', '$expandset');", '', '', $vbphrase['collapse_all_template_groups']) . "\n" .
		"</td>
	</tr>
	</table>
	<br />
	<table cellpadding=\"4\" cellspacing=\"1\" border=\"0\" class=\"tborder\" width=\"300\">
	<tr align=\"center\">
		<td class=\"tcat\"><b>$vbphrase[color_key]</b></td>
	</tr>
	<tr>
		<td class=\"alt2\">
		<div class=\"darkbg\" style=\"margin: 4px; padding: 4px; border: 2px inset; text-align: " . $directionLeft . "\">
		<span class=\"col-g\">" . $vbphrase['template_is_unchanged_from_the_default_style'] . "</span><br />
		<span class=\"col-i\">" . $vbphrase['template_is_inherited_from_a_parent_style'] . "</span><br />
		<span class=\"col-c\">" . $vbphrase['template_is_customized_in_this_style'] . "</span>
		</div>
		</td>
	</tr>
	</table>
	";

	echo "\n</td>\n</tr>\n</table>\n
	<script type=\"text/javascript\">
	<!--
	if (document.forms.tform.tl$THISstyleid.selectedIndex > 0)
	{
		Tprep(document.forms.tform.tl$THISstyleid.options[document.forms.tform.tl$THISstyleid.selectedIndex], $THISstyleid, 1);
	}
	//-->
	</script>";

	echo "<!-- end template list for style '$style[styleid]' -->\n\n";
}

/**
 * Tests if the given template is part of the template "group"
 *
 * @param	string	Template name
 * @param	string	Template "group" name
 *
 * @return	bool	True if the given template is part of the group, false otherwise
 */
function isTemplateInGroup($templatename, $groupname)
{
	return (strpos(strtolower(" $templatename"), $groupname) == 1);
}

// #############################################################################
/**
* Constructs a single template item for the style editor form
*
* @param	array	Template info array
* @param	integer	Style ID of style being shown
* @param	boolean	No longer used
* @param	boolean	HTMLise template titles?
*
* @return	string	Template <option>
*/
function construct_template_option($template, $selectedtemplateid, $styleid, $htmlise = true)
{
	$selected = '';
	if ($selectedtemplateid == $template['templateid'])
	{
		$selected = ' selected="selected"';
	}

	//deal with the title.  The csslegacy thing is a hack we can probably remove -- but that will
	//require a bit of work to make sure we don't break anything.
	$title = $template['title'];
	$title = preg_replace('#^csslegacy_(.*)#i', '\\1', $title);
	if ($htmlise)
	{
		$title = htmlspecialchars_uni($title);
	}

	$i = $template['username'] . ';' . $template['dateline'];

	$tsid = '';

	if ($styleid == -1)
	{
		$class = '';
		$value = $template['templateid'];
	}
	else
	{
		switch ($template['styleid'])
		{
			// template is inherited from the master set
			case 0:
			case -1:
			{
				$class = 'col-g';
				$value = '~';
				break;
			}

			// template is customized for this specific style
			case $styleid:
			{
				$class = 'col-c';
				$value = $template['templateid'];
				break;
			}

			// template is customized in a parent style - (inherited)
			default:
			{
				$class = 'col-i';
				$value = '[' . $template['templateid'] . ']';
				$tsid = $template['styleid'];
				break;
			}
		}
	}

	$option = "\t" . '<option class="template-option ' . $class . '" value="' . $value . '" ';
	if($tsid)
	{
		$option .= 'tsid="' . $tsid . '" ';
	}
	$option .= 'i="' . $i . '"' . $selected . '>' . $title . "</option>\n";

	return $option;
}

// #############################################################################
/**
* Processes a raw template for conditionals, phrases etc into PHP code for eval()
*
* @param	string	Template
*	@deprecated -- this functionality has been moved to the template API.
* @return	string
*/
function compile_template($template, &$errors = array())
{
	require_once(DIR . '/includes/class_template_parser.php');
	$parser = new vB_TemplateParser($template);

	try
	{
		$parser->validate($errors);
	}
	catch (vB_Exception_TemplateFatalError $e)
	{
		global $vbphrase;
		echo "<p>&nbsp;</p><p>&nbsp;</p>";
		print_form_header('admincp/', '', 0, 1, '', '65%');
		print_table_header($vbphrase['vbulletin_message']);
		print_description_row($vbphrase[$e->getMessage()]);
		print_table_footer(2, construct_button_code($vbphrase['go_back'], 'javascript:history.back(1)'));
		print_cp_footer();
		exit;
	}

	$template = $parser->compile();
	return $template;
}

// #############################################################################
/**
* Prints a row containing a <select> showing the available styles
*
* @param	string	Name for <select>
* @param	integer	Selected style ID
* @param	string	Name of top item in <select>
* @param	string	Title of row
* @param	boolean	Display top item?
*/
function print_style_chooser_row($name = 'parentid', $selectedid = -1, $topname = NULL, $title = NULL, $displaytop = true)
{
	global $vbphrase;

	if ($topname === NULL)
	{
		$topname = $vbphrase['no_parent_style'];
	}
	if ($title === NULL)
	{
		$title = $vbphrase['parent_style'];
	}

	$stylecache = vB_Library::instance('Style')->fetchStyles(false, false);

	$styles = array();

	if ($displaytop)
	{
		$styles['-1'] = $topname;
	}

	foreach($stylecache AS $style)
	{
		$styles["$style[styleid]"] = construct_depth_mark($style['depth'], '--', iif($displaytop, '--')) . " $style[title]";
	}

	print_select_row($title, $name, $styles, $selectedid);
}

// #############################################################################
/**
* If a template item is customized, returns HTML to allow revertion
*
* @param	integer	Style ID of template item
* @param	string	Template type (replacement / stylevar etc.)
* @param	string	Name of template record
*
* @return	array	array('info' => x, 'revertcode' => 'y')
*/
function construct_revert_code($itemstyleid, $templatetype, $varname)
{
	global $vbphrase, $vbulletin;

	if ($templatetype == 'replacement')
	{
		$revertword = 'delete';
	}
	else
	{
		$revertword = 'revert';
	}

	switch ($itemstyleid)
	{
		case -1:
			return array('info' => '', 'revertcode' => '&nbsp;');
		case $vbulletin->GPC['dostyleid']:
			return array(
				'info' => "($vbphrase[customized_in_this_style])",
				'revertcode' => "<label for=\"del_{$templatetype}_{$varname}\">" . $vbphrase["$revertword"] .
					"<input type=\"checkbox\" name=\"delete[$templatetype][$varname]\" id=\"del_{$templatetype}_{$varname}\" value=\"1\" tabindex=\"1\" title=\"" .
					$vbphrase["$revertword"] . "\" /></label>",
			);
		default:
			return array('info' => '(' . construct_phrase($vbphrase['customized_in_a_parent_style_x'], $itemstyleid) . ')', 'revertcode' => '&nbsp;');
	}
}

// #############################################################################
/**
* Prints a row containing a textarea for editing one of the 'common templates'
*
* @param	string	Template variable name
*/
function print_common_template_row($varname)
{
	global $template_cache, $vbphrase, $vbulletin;

	$template = $template_cache['template']["$varname"];
	$description = $vbphrase["{$varname}_desc"];

	$color = fetch_inherited_color($template['styleid'], $vbulletin->GPC['dostyleid']);
	$revertcode = construct_revert_code($template['styleid'], 'template', $varname);

	print_textarea_row(
		"<b>$varname</b> <dfn>$description</dfn><span class=\"smallfont\"><br /><br />$revertcode[info]<br /><br />$revertcode[revertcode]</span>",
		"commontemplate[$varname]",
		$template['template_un'],
		8, 70, 1, 0, 'ltr',
		"$color\" style=\"font: 9pt courier new"
	);
}

// #############################################################################
/**
* Prints a row containing a textarea for editing a replacement variable
*
* @param	string	Find text
* @param	string	Replace text
* @param	integer	Number of rows for textarea
* @param	integer	Number of columns for textarea
*/
function print_replacement_row($find, $replace, $rows = 2, $cols = 50, $replacement_info = array())
{
	global $vbulletin;
	static $rcount = 0;

	$rcount++;

	$color = fetch_inherited_color($replacement_info["$find"], $vbulletin->GPC['dostyleid']);
	$revertcode = construct_revert_code($replacement_info["$find"], 'replacement', $rcount);

	construct_hidden_code("replacement[$rcount][find]", $find);
	print_cells_row(array(
		'<pre>' . htmlspecialchars_uni($find) . '</pre>',
		"\n\t<span class=\"smallfont\"><textarea name=\"replacement[$rcount][replace]\" class=\"$color\" rows=\"$rows\" cols=\"$cols\" tabindex=\"1\">" . htmlspecialchars_uni($replace) . "</textarea><br />$revertcode[info]</span>\n\t",
		"<span class=\"smallfont\">$revertcode[revertcode]</span>"
	));

}

// #############################################################################
/**
* Returns styles for post editor interface from template
*
* @param	string	Template contents
*
* @return	array
*/
function fetch_posteditor_styles($template)
{
	$item = array();

	preg_match_all('#([a-z0-9-]+):\s*([^\s].*);#siU', $template, $regs);

	foreach ($regs[1] AS $key => $cssname)
	{
		$item[strtolower($cssname)] = trim($regs[2]["$key"]);
	}

	return $item;
}

// #############################################################################
/**
* Prints a row containing an <input type="text" />
*
* @param	string	Title for row
* @param	string	Name for input field
* @param	string	Value for input field
* @param	boolean	Whether or not to htmlspecialchars the input field value
* @param	integer	Size for input field
* @param	integer	Max length for input field
* @param	string	Text direction for input field
* @param	mixed	If specified, overrides the default CSS class for the input field
*/
function print_color_input_row($title, $name, $value = '', $htmlise = true, $size = 35, $maxlength = 0, $direction = '', $inputclass = false)
{
	global $vbulletin, $numcolors;
	$vb5_config = vB::getConfig();

	$direction = verify_text_direction($direction);
	print_label_row(
		$title,
		"<div id=\"ctrl_$name\">
			<input style=\"float:" . vB_Template_Runtime::fetchStyleVar('left') . "; margin-" . vB_Template_Runtime::fetchStyleVar('right') . ": 4px\" type=\"text\" class=\"" . iif($inputclass, $inputclass, 'bginput') . "\" name=\"$name\" id=\"color_$numcolors\" value=\"" . iif($htmlise, htmlspecialchars_uni($value), $value) . "\" size=\"$size\"" . iif($maxlength, " maxlength=\"$maxlength\"") . " dir=\"$direction\" tabindex=\"1\"" . iif($vb5_config['Misc']['debug'], " title=\"name=&quot;$name&quot;\"") . " onchange=\"preview_color($numcolors)\" />
			<div style=\"float:" . vB_Template_Runtime::fetchStyleVar('left') . "\" id=\"preview_$numcolors\" class=\"colorpreview\" onclick=\"open_color_picker($numcolors, event)\"></div>
		</div>",
		'', 'top', $name
	);

	$numcolors++;
}

// #############################################################################
/**
* Builds the color picker popup item for the style editor
*
* @param	integer	Width of each color swatch (pixels)
* @param	string	CSS 'display' parameter (default: 'none')
*
* @return	string
*/
function construct_color_picker($size = 12, $display = 'none')
{
	global $vbulletin, $colorPickerWidth, $colorPickerType;

	$previewsize = 3 * $size;
	$surroundsize = $previewsize * 2;
	$colorPickerWidth = 21 * $size + 22;

	$html = "
	<style type=\"text/css\">
	#colorPicker
	{
		background: black;
		position: absolute;
		left: 0px;
		top: 0px;
		width: {$colorPickerWidth}px;
	}
	#colorFeedback
	{
		border: solid 1px black;
		border-bottom: none;
		width: {$colorPickerWidth}px;
		padding-left: 0;
		padding-right: 0;
	}
	#colorFeedback input
	{
		font: 11px verdana, arial, helvetica, sans-serif;
	}
	#colorFeedback button
	{
		width: 19px;
		height: 19px;
	}
	#txtColor
	{
		border: inset 1px;
		width: 70px;
	}
	#colorSurround
	{
		border: inset 1px;
		white-space: nowrap;
		width: {$surroundsize}px;
		height: 15px;
	}
	#colorSurround td
	{
		background-color: none;
		border: none;
		width: {$previewsize}px;
		height: 15px;
	}
	#swatches
	{
		background-color: black;
		width: {$colorPickerWidth}px;
	}
	#swatches td
	{
		background: black;
		border: none;
		width: {$size}px;
		height: {$size}px;
	}
	</style>
	<div id=\"colorPicker\" style=\"display:$display\" oncontextmenu=\"switch_color_picker(1); return false\" onmousewheel=\"switch_color_picker(event.wheelDelta * -1); return false;\">
	<table id=\"colorFeedback\" class=\"tcat\" cellpadding=\"0\" cellspacing=\"4\" border=\"0\" width=\"100%\">
	<tr>
		<td><button type=\"button\" onclick=\"col_click('transparent'); return false\"><img src=\"" . get_cpstyle_href('colorpicker_transparent.gif') . "\" title=\"'transparent'\" alt=\"\" /></button></td>
		<td>
			<table id=\"colorSurround\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\">
			<tr>
				<td id=\"oldColor\" onclick=\"close_color_picker()\"></td>
				<td id=\"newColor\"></td>
			</tr>
			</table>
		</td>
		<td width=\"100%\"><input id=\"txtColor\" type=\"text\" value=\"\" size=\"8\" /></td>
		<td style=\"white-space:nowrap\">
			<input type=\"hidden\" name=\"colorPickerType\" id=\"colorPickerType\" value=\"$colorPickerType\" />
			<button type=\"button\" onclick=\"switch_color_picker(1); return false\"><img src=\"" . get_cpstyle_href('colorpicker_toggle.gif') . "\" alt=\"\" /></button>
			<button type=\"button\" onclick=\"close_color_picker(); return false\"><img src=\"" . get_cpstyle_href('colorpicker_close.gif') . "\" alt=\"\" /></button>
		</td>
	</tr>
	</table>
	<table id=\"swatches\" cellpadding=\"0\" cellspacing=\"1\" border=\"0\">\n";

	$colors = array(
		'00', '33', '66',
		'99', 'CC', 'FF'
	);

	$specials = array(
		'#000000', '#333333', '#666666',
		'#999999', '#CCCCCC', '#FFFFFF',
		'#FF0000', '#00FF00', '#0000FF',
		'#FFFF00', '#00FFFF', '#FF00FF'
	);

	$green = array(5, 4, 3, 2, 1, 0, 0, 1, 2, 3, 4, 5);
	$blue = array(0, 0, 0, 5, 4, 3, 2, 1, 0, 0, 1, 2, 3, 4, 5, 5, 4, 3, 2, 1, 0);

	for ($y = 0; $y < 12; $y++)
	{
		$html .= "\t<tr>\n";

		$html .= construct_color_picker_element(0, $y, '#000000');
		$html .= construct_color_picker_element(1, $y, $specials["$y"]);
		$html .= construct_color_picker_element(2, $y, '#000000');

		for ($x = 3; $x < 21; $x++)
		{
			$r = floor((20 - $x) / 6) * 2 + floor($y / 6);
			$g = $green["$y"];
			$b = $blue["$x"];

			$html .= construct_color_picker_element($x, $y, '#' . $colors["$r"] . $colors["$g"] . $colors["$b"]);
		}

		$html .= "\t</tr>\n";
	}

	$html .= "\t</table>
	</div>
	<script type=\"text/javascript\">
	<!--
	var tds = fetch_tags(fetch_object(\"swatches\"), \"td\");
	for (var i = 0; i < tds.length; i++)
	{
		tds[i].onclick = swatch_click;
		tds[i].onmouseover = swatch_over;
	}
	//-->
	</script>\n";

	return $html;
}

// #############################################################################
/**
* Builds a single color swatch for the color picker gadget
*
* @param	integer	Current X coordinate
* @param	integer	Current Y coordinate
* @param	string	Color
*
* @return	string
*/
function construct_color_picker_element($x, $y, $color)
{
	return "\t\t<td style=\"background:$color\" id=\"sw$x-$y\"><img src=\"images/clear.gif\" alt=\"\" style=\"width:11px; height:11px\" /></td>\r\n";
}

// #############################################################################
/**
* Prints a row containing template search javascript controls
*/
function print_template_javascript($textarea_id)
{
	$vbphrase = vB_Api::instanceInternal('phrase')->fetch(array('not_found'));

	print_phrase_ref_popup_javascript();

	echo '<script type="text/javascript" src="core/clientscript/vbulletin_templatemgr.js?v=' . SIMPLE_VERSION . '"></script>';
	echo '<script type="text/javascript">
<!--
	var vbphrase = { \'not_found\' : "' . fetch_js_safe_string($vbphrase['not_found']) . '" };
// -->
</script>
';
	activateCodeMirror(array($textarea_id));
}

function activateCodeMirror($ids)
{
	$vbphrase = vB_Api::instanceInternal('phrase')->fetch(array('fullscreen'));
	?>
				<script src="core/clientscript/codemirror/lib/codemirror.js?v=<?php echo SIMPLE_VERSION ?>"></script>

				<script src="core/clientscript/codemirror/mode/xml/xml.js?v=<?php echo SIMPLE_VERSION ?>"></script>
				<script src="core/clientscript/codemirror/mode/javascript/javascript.js?v=<?php echo SIMPLE_VERSION ?>"></script>
				<script src="core/clientscript/codemirror/mode/css/css.js?v=<?php echo SIMPLE_VERSION ?>"></script>
				<!-- <script src="core/clientscript/codemirror/mode/clike/clike.js?v=<?php echo SIMPLE_VERSION ?>"></script> -->
				<script src="core/clientscript/codemirror/mode/htmlmixed/htmlmixed.js?v=<?php echo SIMPLE_VERSION ?>"></script>
				<script src="core/clientscript/codemirror/mode/vbulletin/vbulletin.js?v=<?php echo SIMPLE_VERSION ?>"></script>

				<script src="core/clientscript/codemirror/addon/mode/overlay.js?v=<?php echo SIMPLE_VERSION ?>"></script>
				<script src="core/clientscript/codemirror/addon/selection/active-line.js?v=<?php echo SIMPLE_VERSION ?>"></script>
				<script src="core/clientscript/codemirror/addon/edit/matchbrackets.js?v=<?php echo SIMPLE_VERSION ?>"></script>
				<script src="core/clientscript/codemirror/addon/fold/foldcode.js?v=<?php echo SIMPLE_VERSION ?>"></script>
				<script src="core/clientscript/codemirror/addon/search/search.js?v=<?php echo SIMPLE_VERSION ?>"></script>
				<script src="core/clientscript/codemirror/addon/search/searchcursor.js?v=<?php echo SIMPLE_VERSION ?>"></script>
				<script src="core/clientscript/codemirror/addon/search/match-highlighter.js?v=<?php echo SIMPLE_VERSION ?>"></script>
				<script src="core/clientscript/codemirror/addon/edit/closetag.js?v=<?php echo SIMPLE_VERSION ?>"></script>
				<script src="core/clientscript/codemirror/addon/hint/show-hint.js?v=<?php echo SIMPLE_VERSION ?>"></script>
				<script src="core/clientscript/codemirror/addon/hint/vbulletin-hint.js?v=<?php echo SIMPLE_VERSION ?>"></script>
			<script type="text/javascript">
			<!--
			window.onload = function() {
				$(["<?php echo implode('","', $ids)?>"]).each(function(){
					setUpCodeMirror({
						textarea_id : this,
						phrase_fullscreen : "<?php echo $vbphrase['fullscreen']; ?>",
						mode:'vbulletin'
					})
				});
			};
			//-->
			</script><?php
}

function activateCodeMirrorPHP($ids)
{
	$vbphrase = vB_Api::instanceInternal('phrase')->fetch(array('fullscreen'));
	?>
				<script src="core/clientscript/codemirror/lib/codemirror.js?v=<?php echo SIMPLE_VERSION ?>"></script>
				<script src="core/clientscript/codemirror/mode/clike/clike.js?v=<?php echo SIMPLE_VERSION ?>"></script>
				<script src="core/clientscript/codemirror/mode/php/php.js?v=<?php echo SIMPLE_VERSION ?>"></script>

				<script src="core/clientscript/codemirror/addon/selection/active-line.js?v=<?php echo SIMPLE_VERSION ?>"></script>
				<script src="core/clientscript/codemirror/addon/edit/matchbrackets.js?v=<?php echo SIMPLE_VERSION ?>"></script>
				<script src="core/clientscript/codemirror/addon/fold/foldcode.js?v=<?php echo SIMPLE_VERSION ?>"></script>
				<script src="core/clientscript/codemirror/addon/search/match-highlighter.js?v=<?php echo SIMPLE_VERSION ?>"></script>
				<script src="core/clientscript/codemirror/addon/edit/closetag.js?v=<?php echo SIMPLE_VERSION ?>"></script>
				<script src="core/clientscript/codemirror/addon/hint/show-hint.js?v=<?php echo SIMPLE_VERSION ?>"></script>
			<script type="text/javascript">
			<!--
			window.onload = function() {
				$(["<?php echo implode('","', $ids)?>"]).each(function(){
					setUpCodeMirror({
						textarea_id : this,
						phrase_fullscreen : "<?php echo $vbphrase['fullscreen']; ?>",
						mode: "application/x-httpd-php-open"
					})
				});
			};
			//-->
			</script><?php
}

// ###########################################################################################
// START XML STYLE FILE FUNCTIONS

function get_style_export_xml
(
	$styleid,
	$product,
	$product_version,
	$title,
	$mode,
	$remove_guid = false,
	$stylevars_only = false,
	$stylevar_groups = array()
)
{
	global $vbulletin;

	/* Load the master 'style' phrases and then
	build a local $template_groups array using them. */
	$vbphrase = vB_Api::instanceInternal('phrase')->fetchByGroup('style', -1);

	$groups = vB_Library::instance('template')->getTemplateGroupPhrases();
	$template_groups = vB_Api::instanceInternal('phrase')->renderPhrases($groups);
	$template_groups = $template_groups['phrases'];

	$vb5_config = vB::getConfig();
	if (!$vb5_config)
	{
		$vb5_config =& vB::getConfig();
	}

	if ($styleid == -1)
	{
		// set the style title as 'master style'
		$style = array('title' => $vbphrase['master_style']);
		$sqlcondition = "styleid = -1";
		$parentlist = "-1";
		$is_master = true;
	}
	else
	{
		// query everything from the specified style
		$style = $vbulletin->db->query_first("
			SELECT *
			FROM " . TABLE_PREFIX . "style
			WHERE styleid = " . $styleid
		);

		//export as master -- export a style with all changes as a new master style.
		if ($mode == 2)
		{
			//only allowed in debug mode.
			if (!$vb5_config['Misc']['debug'])
			{
				print_cp_no_permission();
			}

			// get all items from this style and all parent styles
			$sqlcondition = "templateid IN(" . implode(',', unserialize($style['templatelist'])) . ")";
			$sqlcondition .= " AND title NOT LIKE 'vbcms_grid_%'";
			$parentlist = $style['parentlist'];
			$is_master = true;
			$title = $vbphrase['master_style'];
		}

		//export with parent styles
		else if ($mode == 1)
		{
			// get all items from this style and all parent styles (except master)
			$sqlcondition = "styleid <> -1 AND templateid IN(" . implode(',', unserialize($style['templatelist'])) . ")";
			//remove the master style id off the end of the list
			$parentlist = substr(trim($style['parentlist']), 0, -3);
			$is_master = false;
		}

		//this style only
		else
		{
			// get only items customized in THIS style
			$sqlcondition = "styleid = " . $styleid;
			$parentlist = $styleid;
			$is_master = false;
		}
	}

	if ($product == 'vbulletin')
	{
		$sqlcondition .= " AND (product = '" . vB::getDbAssertor()->escape_string($product) . "' OR product = '')";
	}
	else
	{
		$sqlcondition .= " AND product = '" . vB::getDbAssertor()->escape_string($product) . "'";
	}

	// set a default title
	if ($title == '' OR $styleid == -1)
	{
		$title = $style['title'];
	}

	if (!empty($style['dateline']))
	{
		$dateline = $style['dateline'];
	}
	else
	{
		$dateline = vB::getRequest()->getTimeNow();
	}

	// --------------------------------------------
	// query the templates and put them in an array

	$templates = array();

	if (!$stylevars_only)
	{
		$gettemplates = $vbulletin->db->query_read("
			SELECT title, templatetype, username, dateline, version,
			IF(templatetype = 'template', template_un, template) AS template,
			textonly
			FROM " . TABLE_PREFIX . "template
			WHERE $sqlcondition
			ORDER BY title
		");

		$ugcount = $ugtemplates = 0;
		while ($gettemplate = $vbulletin->db->fetch_array($gettemplates))
		{
			switch($gettemplate['templatetype'])
			{
				case 'template': // regular template

					// if we have ad template, and we are exporting as master, make sure we do not export the ad data
					if (substr($gettemplate['title'], 0, 3) == 'ad_' AND $mode == 2)
					{
						$gettemplate['template'] = '';
					}

					$isgrouped = false;
					foreach(array_keys($template_groups) AS $group)
					{
						if (strpos(strtolower(" $gettemplate[title]"), $group) == 1)
						{
							$templates["$group"][] = $gettemplate;
							$isgrouped = true;
						}
					}
					if (!$isgrouped)
					{
						if ($ugtemplates % 10 == 0)
						{
							$ugcount++;
						}
						$ugtemplates++;
						//sort ungrouped templates last.
						$ugcount_key = 'zzz' . str_pad($ugcount, 5, '0', STR_PAD_LEFT);
						$templates[$ugcount_key][] = $gettemplate;
						$template_groups[$ugcount_key] = construct_phrase($vbphrase['ungrouped_templates_x'], $ugcount);
					}
				break;

				case 'stylevar': // stylevar
					$templates[$vbphrase['stylevar_special_templates']][] = $gettemplate;
				break;

				case 'css': // css
					$templates[$vbphrase['css_special_templates']][] = $gettemplate;
				break;

				case 'replacement': // replacement
					$templates[$vbphrase['replacement_var_special_templates']][] = $gettemplate;
				break;
			}
		}
		unset($gettemplate);
		$vbulletin->db->free_result($gettemplates);
		if (!empty($templates))
		{
			ksort($templates);
		}

	}

	// --------------------------------------------
	// fetch stylevar-dfns

	$stylevarinfo = get_stylevars_for_export($product, $parentlist, $stylevar_groups);
	$stylevar_cache = $stylevarinfo['stylevars'];
	$stylevar_dfn_cache = $stylevarinfo['stylevardfns'];

	if (empty($templates) AND empty($stylevar_cache) AND empty($stylevar_dfn_cache))
	{
		throw new vB_Exception_AdminStopMessage('download_contains_no_customizations');
	}

	// --------------------------------------------
	// now output the XML

	$xml = new vB_XML_Builder();
	$rootAttributes =
		array(
			'name' => $title,
			'vbversion' => $product_version,
			'product' => $product,
			'type' => $is_master ? 'master' : 'custom',
			'dateline' => $dateline,
		);
	if (isset($style['styleattributes']) AND $style['styleattributes'] != vB_Library_Style::ATTR_DEFAULT)
	{
		$rootAttributes['styleattributes'] = $style['styleattributes'];
	}
	$xml->add_group('style',
		$rootAttributes
	);


	/*
	 * Check if it's a THEME, and add extra guid, icon & previewimage tags.
	 */
	if (!empty($style['guid']))
	{
		// we allow removing the GUID
		if (!$remove_guid)
		{
			$xml->add_tag('guid', $style['guid']);
		}

		// optional, image data
		$optionalImages = array(
			// DB column name => XML tag name
			'filedataid' => 'icon',
			'previewfiledataid' => 'previewimage',
		);
		foreach ($optionalImages AS $dbColumn => $tagname)
		{
			if (!empty($style[$dbColumn]))
			{
				$filedata = vB_Api::instanceInternal('filedata')->fetchImageByFiledataid($style[$dbColumn]);
				if (!empty($filedata['filedata']))
				{
					$xml->add_tag($tagname, base64_encode($filedata['filedata']));
				}
			}
		}
	}

	foreach($templates AS $group => $grouptemplates)
	{
		$xml->add_group('templategroup', array('name' => iif(isset($template_groups["$group"]), $template_groups["$group"], $group)));
		foreach($grouptemplates AS $template)
		{
			$attributes = array(
				'name' => htmlspecialchars($template['title']),
				'templatetype' => $template['templatetype'],
				'date' => $template['dateline'],
				'username' => $template['username'],
				'version' => htmlspecialchars_uni($template['version']),
			);
			$textonly = !empty($template['textonly']);
			if ($textonly)
			{
				$attributes['textonly'] = 1;
			}

			$xml->add_tag('template', $template['template'], $attributes, true);
		}
		$xml->close_group();
	}

	$xml->add_group('stylevardfns');
	foreach ($stylevar_dfn_cache AS $stylevargroupname => $stylevargroup)
	{
		$xml->add_group('stylevargroup', array('name' => $stylevargroupname));
		foreach($stylevargroup AS $stylevar)
		{
			$xml->add_tag('stylevar', '',
				array(
					'name' => htmlspecialchars($stylevar['stylevarid']),
					'datatype' => $stylevar['datatype'],
					'validation' => base64_encode($stylevar['validation']),
					'failsafe' => base64_encode($stylevar['failsafe'])
				)
			);
		}
		$xml->close_group();
	}
	$xml->close_group();

	$xml->add_group('stylevars');
	foreach ($stylevar_cache AS $stylevarid => $stylevar)
	{
		$xml->add_tag('stylevar', '',
			array(
				'name' => htmlspecialchars($stylevar['stylevarid']),
				'value' => base64_encode($stylevar['value'])
			)
		);
	}
	$xml->close_group();

	$xml->close_group();

	$doc = "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>\r\n\r\n";
	$doc .= $xml->output();
	$xml = null;
	return $doc;
}

/// #############################################################################
/**
* Reads XML style file and imports data from it into the database
*
* @param	string	$xml		XML data
* @param	integer	$styleid	Style ID
* @param	integer	$parentid	Parent style ID
* @param	string	$title		New style title
* @param	boolean	$anyversion	Allow vBulletin version mismatch
* @param	integer	$displayorder	Display order for new style
* @param	boolean	$userselct	Allow user selection of new style
* @param  	int|null	$startat	Starting template group index for this run of importing templates (0 based). Null means all templates (single run)
* @param  	int|null	$perpage	Number of templates to import at a time
* @param	boolean	$scilent		Run silently (do not echo)
* @param	array|boolean	$parsed_xml	Parsed array of XML data. If provided the function will ignore $xml and use the provided, already parsed data.
*
* @return	array	Array of information about the imported style
*/
function xml_import_style(
	$xml = false,
	$styleid = -1,
	$parentid = -1,
	$title = '',
	$anyversion = false,
	$displayorder = 1,
	$userselect = true,
	$startat = null,
	$perpage = null,
	$scilent = false,
	$parsed_xml = false,
	$requireUniqueTitle = true
)
{
	// $GLOBALS['path'] needs to be passed into this function or reference $vbulletin->GPC['path']

	//checking the root node name
	if (!empty($xml))
	{
		$r = new XMLReader();
		if ($r->xml($xml))
		{
			if ($r->read())
			{
				$node_name = $r->name;
				if ($node_name != 'style')
				{
					print_stop_message2('file_uploaded_not_in_right_format_error');
				}
			}
			else
			{
				//can not read the document
				print_stop_message2('file_uploaded_unreadable');
			}
		}
		else
		{
			//can not open the xml
			print_stop_message2('file_uploaded_unreadable');
		}
	}

	global $vbulletin;
	if (!$scilent)
	{
		$vbphrase = vB_Api::instanceInternal('phrase')->fetch(array('importing_style', 'please_wait', 'creating_a_new_style_called_x'));
		print_dots_start('<b>' . $vbphrase['importing_style'] . "</b>, $vbphrase[please_wait]", ':', 'dspan');
	}

	if (empty($parsed_xml))
	{
		//where is this used?  I hate having this random global value in the middle of this function
		$xmlobj = new vB_XML_Parser($xml, $vbulletin->GPC['path']);
		if ($xmlobj->error_no() == 1)
		{
			if ($scilent)
			{
				throw new vB_Exception_AdminStopMessage('no_xml_and_no_path');
			}
			print_dots_stop();
			print_stop_message2('no_xml_and_no_path');
		}
		else if ($xmlobj->error_no() == 2)
		{
			if ($scilent)
			{
				throw new vB_Exception_AdminStopMessage(array('please_ensure_x_file_is_located_at_y', 'vbulletin-style.xml', $vbulletin->GPC['path']));
			}
			print_dots_stop();
			print_stop_message2(array('please_ensure_x_file_is_located_at_y', 'vbulletin-style.xml', $vbulletin->GPC['path']));
		}

		if(!$parsed_xml = $xmlobj->parse())
		{
			if ($scilent)
			{
				throw new vB_Exception_AdminStopMessage(array('xml_error_x_at_line_y', $xmlobj->error_string(), $xmlobj->error_line()));
			}
			print_dots_stop();
			print_stop_message2(array('xml_error_x_at_line_y', $xmlobj->error_string(), $xmlobj->error_line()));
		}
	}

	$version = $parsed_xml['vbversion'];
	$master = ($parsed_xml['type'] == 'master' ? 1 : 0);
	$title = (empty($title) ? $parsed_xml['name'] : $title);
	$product = (empty($parsed_xml['product']) ? 'vbulletin' : $parsed_xml['product']);
	$styleattributes = (isset($parsed_xml['styleattributes']) ? intval($parsed_xml['styleattributes']) : vB_Library_Style::ATTR_DEFAULT);
	$dateline = (isset($parsed_xml['dateline']) ? intval($parsed_xml['dateline']) : vB::getRequest()->getTimeNow());
	$assertor = vB::getDbAssertor(); // cache assertor to avoid repeated, unnecessary function call.


	$one_pass = (is_null($startat) AND is_null($perpage));
	if (!$one_pass AND (!is_numeric($startat) OR !is_numeric($perpage) OR $perpage <= 0 OR $startat < 0))
	{
			if ($scilent)
			{
				throw new vB_Exception_AdminStopMessage('');
			}
			print_dots_stop();
			print_stop_message2('');
	}

	$outputtext = '';
	if ($one_pass OR ($startat == 0))
	{
		require_once(DIR . '/includes/adminfunctions.php');
		// version check
		$full_product_info = fetch_product_list(true);
		$product_info = $full_product_info["$product"];

		if ($version != $product_info['version'] AND !$anyversion AND !$master)
		{
			if ($scilent)
			{
				throw new vB_Exception_AdminStopMessage(array('upload_file_created_with_different_version', $product_info['version'], $version));
			}
			print_dots_stop();
			print_stop_message2(array('upload_file_created_with_different_version', $product_info['version'], $version));
		}

		//Initialize the style -- either init the master, create a new style, or verify the style to overwrite.
		if ($master)
		{
			$import_data = @unserialize(fetch_adminutil_text('master_style_import'));
			if (!empty($import_data) AND (TIMENOW - $import_data['last_import']) <= 30)
			{
				if ($scilent)
				{
					throw new vB_Exception_AdminStopMessage(array('must_wait_x_seconds_master_style_import', vb_number_format($import_data['last_import'] + 30 - TIMENOW)));
				}
				print_dots_stop();
				print_stop_message2(array('must_wait_x_seconds_master_style_import',  vb_number_format($import_data['last_import'] + 30 - TIMENOW)));
			}

			// overwrite master style
//			if  ($printInfo AND (VB_AREA != 'Upgrade' AND VB_AREA != 'Install'))
//			{
//				echo "<h3>$vbphrase[master_style]</h3>\n<p>$vbphrase[please_wait]</p>";
//				vbflush();
//			}
			$products = array($product);
			if ($product == 'vbulletin')
			{
				$products[] = '';
			}
			$assertor->assertQuery('vBForum:deleteProductTemplates', array('products' =>$products));
			$assertor->assertQuery('vBForum:updateProductTemplates', array('products' =>$products));
			$styleid = -1;
		}
		else
		{
			if ($styleid == -1)
			{
				// creating a new style
				if ($requireUniqueTitle AND $assertor->getRow('style', array('title' => $title)))
				{
					if ($scilent)
					{
						throw new vB_Exception_AdminStopMessage(array('style_already_exists', $title));
					}
					print_dots_stop();
					print_stop_message2(array('style_already_exists',  $title));
				}
				else
				{
					if (!$scilent)
					{
						if ((VB_AREA != 'Upgrade') OR (VB_AREA != 'Install'))
						{
							$outputtext = construct_phrase($vbphrase['creating_a_new_style_called_x'], $title) . "<br>\n";
						}
						else
						{
							// this isn't compatible with the ajax installer
							echo "<h3><b>" . construct_phrase($vbphrase['creating_a_new_style_called_x'], $title) . "</b></h3>\n<p>$vbphrase[please_wait]</p>";
							vbflush();
						}
					}
					/*insert query*/
					$styleid = $assertor->insert('style', array(
							'title' => $title,
							'parentid' => $parentid,
							'displayorder' => $displayorder,
							'userselect' => $userselect ? 1 : 0,
							'styleattributes' => $styleattributes,
							'dateline' => $dateline,
						)
					);


					if (is_array($styleid))
					{
						$styleid = array_pop($styleid);
					}
				}
			}
			else
			{
				// overwriting an existing style
				if ($oldStyleData = $assertor->getRow('style', array('styleid' => $styleid)))
				{
					/*
						Do an update if needed.
						Especially required for forcing theme XML changes to stick during upgrade
						(ex adding/changing styleattributes)
					*/
					$changed = (
						$oldStyleData['title'] != $title ||
						$oldStyleData['parentid'] != $parentid ||
						$oldStyleData['displayorder'] != $displayorder ||
						$oldStyleData['userselect'] != $userselect ||
						$oldStyleData['styleattributes'] != $styleattributes ||
						$oldStyleData['dateline'] != $dateline
					);
					if ($changed)
					{
						$styleid = $assertor->update('style',
							array(
								'title' => $title,
								'parentid' => $parentid,
								'displayorder' => $displayorder,
								'userselect' => $userselect ? 1 : 0,
								'styleattributes' => $styleattributes,
								'dateline' => $dateline,
							),
							array('styleid' => $styleid)
						);
					}


//					if  ($printInfo AND (VB_AREA != 'Upgrade' AND VB_AREA != 'Install'))
//					{
//						echo "<h3><b>" . construct_phrase($vbphrase['overwriting_style_x'], $getstyle['title']) . "</b></h3>\n<p>$vbphrase[please_wait]</p>";
//						vbflush();
//					}
				}
				else
				{
					if ($scilent)
					{
						throw new vB_Exception_AdminStopMessage('cant_overwrite_non_existent_style');
					}
					print_dots_stop();
					print_stop_message2('cant_overwrite_non_existent_style');
				}
			}
		}
	}
	else
	{
		//We should never get styleid = -1 unless $master is true;
		if (($styleid == -1) AND !$master)
		{
			// According to this code, a style's title is a unique identifier (why not use guid?). This might be problematic.
			$stylerec = $assertor->getRow('style', array('title' => $title));

			if ($stylerec AND intval($stylerec['styleid']))
			{
				$styleid = $stylerec['styleid'];
			}
			else
			{
				if ($scilent)
				{
					throw new vB_Exception_AdminStopMessage(array('incorrect_style_setting', $title));
				}
				print_dots_stop();
				print_stop_message2(array('incorrect_style_setting',  $title));
			}
		}
	}

	//load the templates
	if ($arr = $parsed_xml['templategroup'])
	{
		if (empty($arr[0]))
		{
			$arr = array($arr);
		}

		$templates_done = (is_numeric($startat) AND (count($arr) <= $startat));
		if ($one_pass OR !$templates_done)
		{
			if (!$one_pass)
			{
				$arr = array_slice($arr, $startat, $perpage);
			}
			$outputtext .= xml_import_template_groups($styleid, $product, $arr, !$one_pass);
		}
	}
	else
	{
		$templates_done = true;
	}

	//note that templates may actually be done at this point, but templates_done is
	//only true if templates were completed in a prior step. If we are doing a multi-pass
	//process, we don't want to install stylevars in the same pass.  We aren't really done
	//until we hit a pass where the templates are done before processing.
	$done = ($one_pass OR $templates_done);
	if ($done)
	{
		//load stylevars and definitions
		// re-import any stylevar definitions
		if ($master AND !empty($parsed_xml['stylevardfns']['stylevargroup']))
		{
			xml_import_stylevar_definitions($parsed_xml['stylevardfns'], 'vbulletin');
		}

		//if the tag is present but empty we'll end up with a string with whitespace which
		//is a non "empty" value.
		if (!empty($parsed_xml['stylevars']) AND is_array($parsed_xml['stylevars']))
		{
			xml_import_stylevars($parsed_xml['stylevars'], $styleid);
		}

		if ($master)
		{
			xml_import_restore_ad_templates();
			build_adminutil_text('master_style_import', serialize(array('last_import' => TIMENOW)));
		}
		if (!$scilent)
		{
			print_dots_stop();
		}
	}
	$fastDs = vB_FastDS::instance();

	//We want to force a fastDS rebuild, but we can't just call rebuild. There may be dual web servers,
	// and calling rebuild only rebuilds one of them.
	$options = vB::getDatastore()->getValue('miscoptions');
	$options['tmtdate'] = vB::getRequest()->getTimeNow();
	vB::getDatastore()->build('miscoptions', serialize($options), 1);

	return array(
		'version' => $version,
		'master'  => $master,
		'title'   => $title,
		'product' => $product,
		'done'    => $done,
		'overwritestyleid' => $styleid,
		'output'  => $outputtext,
	);
}

function xml_import_template_groups($styleid, $product, $templategroup_array, $output_group_name, $printInfo = true)
{
	global $vbulletin, $vbphrase;

	$safe_product =  vB::getDbAssertor()->escape_string($product);

	$querytemplates = 0;
	$outputtext = '';
	if  ($printInfo AND (VB_AREA != 'Upgrade' AND VB_AREA != 'Install'))
	{
		echo defined('NO_IMPORT_DOTS') ? "\n" : '<br />';
		vbflush();
	}
	foreach ($templategroup_array AS $templategroup)
	{
		if (empty($templategroup['template'][0]))
		{
			$tg = array($templategroup['template']);
		}
		else
		{
			$tg = &$templategroup['template'];
		}

		if ($output_group_name)
		{
			$text = construct_phrase($vbphrase['template_group_x'], $templategroup['name']);
			$outputtext .= $text;
			if  ($printInfo AND (VB_AREA != 'Upgrade' AND VB_AREA != 'Install'))
			{
				echo $text;
				vbflush();
			}
		}

		foreach($tg AS $template)
		{
			$textonly = !empty($template['textonly']);
			// Skip compile for textonly templates or non-template templatetypes.
			if ($textonly OR $template['templatetype'] != 'template')
			{
				$parsedTemplate = $template['value'];
			}
			else
			{
				$parsedTemplate = compile_template($template['value']);
			}

			$querybit = array(
				'styleid'     => $styleid,
				'title'       => $template['name'],
				'template'    => $template['templatetype'] == 'template' ? $parsedTemplate : $template['value'],
				'template_un' => $template['templatetype'] == 'template' ? $template['value'] : '',
				'dateline'    => $template['date'],
				'username'    => $template['username'],
				'version'     => $template['version'],
				'product'     => $product,
				'textonly'    => $textonly,
			);
			$querybit['templatetype'] = $template['templatetype'];

			$querybits[] = $querybit;

			if (++$querytemplates % 10 == 0 OR $templategroup['name'] == 'Css')
			{
				/*insert query*/
				vB::getDbAssertor()->assertQuery('replaceTemplates', array('querybits' => $querybits));
				$querybits = array();
			}

			// Send some output to the browser inside this loop so certain hosts
			// don't artificially kill the script. See bug #34585
			if (!defined('SUPPRESS_KEEPALIVE_ECHO'))
			{
				if (VB_AREA == 'Upgrade' OR VB_AREA == 'Install')
				{
					echo ' ';
				}
				else
				{
					echo '-';
				}
				vbflush();
			}
		}

		if  ($printInfo AND (VB_AREA != 'Upgrade' AND VB_AREA != 'Install'))
		{
			echo defined('NO_IMPORT_DOTS') ? "\n" : '<br />';
			vbflush();
		}
	}

	// insert any remaining templates
	if (!empty($querybits))
	{
		vB::getDbAssertor()->assertQuery('replaceTemplates', array('querybits' => $querybits));
		$querybits = array();
	}

	return $outputtext;
}

function xml_import_restore_ad_templates()
{
	global $vbulletin;

	// Get the template titles
	$save = array();
	$save_tables = vB::getDbAssertor()->assertQuery('template', array(vB_dB_Query::CONDITIONS_KEY=> array(
			array('field'=>'templatetype', 'value' => 'template', vB_dB_Query::OPERATOR_KEY => vB_dB_Query::OPERATOR_EQ),
			array('field'=>'styleid', 'value' => -10, vB_dB_Query::OPERATOR_KEY => vB_dB_Query::OPERATOR_EQ),
			array('field'=>'product', 'value' => array('vbulletin', ''), vB_dB_Query::OPERATOR_KEY => vB_dB_Query::OPERATOR_EQ),
			array('field'=>'title', 'value' => 'ad_', vB_dB_Query::OPERATOR_KEY => vB_dB_Query::OPERATOR_BEGINS),
	)));


	foreach ($save_tables as $table)
	{
		$save[] = $table['title'];
	}

	// Are there any
	if (count($save))
	{
		// Delete any style id -1 ad templates that may of just been imported.
		vB::getDbAssertor()->delete('template', array(
			array('field'=>'templatetype', 'value' => 'template', vB_dB_Query::OPERATOR_KEY => vB_dB_Query::OPERATOR_EQ),
			array('field'=>'styleid', 'value' => -1, vB_dB_Query::OPERATOR_KEY => vB_dB_Query::OPERATOR_EQ),
			array('field'=>'product', 'value' => array('vbulletin', ''), vB_dB_Query::OPERATOR_KEY => vB_dB_Query::OPERATOR_EQ),
			array('field'=>'title', 'value' => $save, vB_dB_Query::OPERATOR_KEY => vB_dB_Query::OPERATOR_EQ),
		));


		// Replace the -1 templates with the -10 before they are deleted
		vB::getDbAssertor()->assertQuery('template',
			array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_UPDATE,
				vB_dB_Query::CONDITIONS_KEY => array(
					array('field'=>'templatetype', 'value' => 'template', vB_dB_Query::OPERATOR_KEY => vB_dB_Query::OPERATOR_EQ),
					array('field'=>'styleid', 'value' => -10, vB_dB_Query::OPERATOR_KEY => vB_dB_Query::OPERATOR_EQ),
					array('field'=>'product', 'value' => array('vbulletin', ''), vB_dB_Query::OPERATOR_KEY => vB_dB_Query::OPERATOR_EQ),
					array('field'=>'title', 'value' => $save, vB_dB_Query::OPERATOR_KEY => vB_dB_Query::OPERATOR_EQ),
				),
				'styleid' => -1,
			)
		);

	}
}

function xml_import_stylevar_definitions($stylevardfns, $product)
{
	global $vbulletin;

	$querybits = array();
	$stylevardfns = get_xml_list($stylevardfns['stylevargroup']);

	/*
		Delete the existing stylevars
		parentid will = 0 for imported stylevars,
		but is set to -1 for custom added sytlevars.
		We only really care about this for default
		vbulletin as any other products will clear up
		their own stylevars when they are uninstalled.
	*/

	if ($product == 'vbulletin')
	{
		$where = array('product' => 'vbulletin', 'parentid' => 0);
	}
	else
	{
		$where = array('product' => $product);
	}

	vB::getDbAssertor()->delete('vBForum:stylevardfn', $where);

	foreach ($stylevardfns AS $stylevardfn_group)
	{
		$sg = get_xml_list($stylevardfn_group['stylevar']);
		foreach ($sg AS $stylevardfn)
		{
			$querybits[] = "('" . $vbulletin->db->escape_string($stylevardfn['name']) . "', -1, '" .
				$vbulletin->db->escape_string($stylevardfn_group['name']) . "', '" .
				$vbulletin->db->escape_string($product) . "', '" .
				$vbulletin->db->escape_string($stylevardfn['datatype']) . "', '" .
				$vbulletin->db->escape_string(base64_decode($stylevardfn['validation'])) . "', '" .
				$vbulletin->db->escape_string(base64_decode($stylevardfn['failsafe'])) . "', 0, 0
			)";
		}

		if (!empty($querybits))
		{
			$vbulletin->db->query_write("
				REPLACE INTO " . TABLE_PREFIX . "stylevardfn
				(stylevarid, styleid, stylevargroup, product, datatype, validation, failsafe, parentid, parentlist)
				VALUES
				" . implode(',', $querybits) . "
			");
		}
		$querybits = array();
	}
}

function xml_import_stylevars($stylevars, $styleid)
{
	$values = array();
	$sv = get_xml_list($stylevars['stylevar']);

	foreach ($sv AS $stylevar)
	{
		//the parser merges attributes and child nodes into a single array.  The unnamed text
		//children get placed into a key called "value" automagically.  Since we don't have any
		//text children we just take the first one.
		$values[] = array(
			'stylevarid' => $stylevar['name'],
			'styleid' => $styleid,
			'value' => base64_decode($stylevar['value'][0]),
			'dateline' => time(),
			'username' => 'Style-Importer',
		);
	}

	if (!empty($values))
	{
		vB::getDbAssertor()->assertQuery('replaceValues', array('table' => 'stylevar', 'values' => $values));
	}
}


/**
*	Get the stylevar list processed to export
*
*	Seperated into its own function for reuse by products
*
*	@param string product -- The name of the product to
*	@param string stylelist -- The styles to export as a comma seperated string
*		(in descending order of precedence).  THE CALLER IS RESPONSIBLE FOR SANITIZING THE
*		INPUT.
*/
function get_stylevars_for_export($product, $stylelist, $stylevar_groups = array())
{
	$assertor = vB::getDbAssertor();
	$queryParams = array(
		'product'   => ($product == 'vbulletin') ? array('vbulletin', '') : array((string)$product),
		'stylelist' => explode(',', $stylelist),
		'stylevar_groups' => $stylevar_groups,
	);

	$stylevar_cache = array();
	$stylevars = $assertor->getRows('vBForum:getStylevarsForExport', $queryParams);
	foreach ($stylevars AS $stylevar)
	{
		$stylevar_cache[$stylevar['stylevarid']] = $stylevar;
		ksort($stylevar_cache);
	}

	$stylevar_dfn_cache = array();
	$stylevar_dfns = $assertor->getRows('vBForum:getStylevarsDfnForExport', $queryParams);
	foreach ($stylevar_dfns AS $stylevar_dfn)
	{
		$stylevar_dfn_cache[$stylevar_dfn['stylevargroup']][] = $stylevar_dfn;
	}

	return array("stylevars" => $stylevar_cache, "stylevardfns" => $stylevar_dfn_cache);
}


// #############################################################################
/**
* Converts a version number string into an array that can be parsed
* to determine if which of several version strings is the newest.
*
* @param	string	Version string to parse
*
* @return	array	Array of 6 bits, in decreasing order of influence; a higher bit value is newer
*/
function fetch_version_array($version)
{
	// parse for a main and subversion
	if (preg_match('#^([a-z]+ )?([0-9\.]+)[\s-]*([a-z].*)$#i', trim($version), $match))
	{
		$main_version = $match[2];
		$sub_version = $match[3];
	}
	else
	{
		$main_version = $version;
		$sub_version = '';
	}

	$version_bits = explode('.', $main_version);

	// pad the main version to 4 parts (1.1.1.1)
	if (sizeof($version_bits) < 4)
	{
		for ($i = sizeof($version_bits); $i < 4; $i++)
		{
			$version_bits["$i"] = 0;
		}
	}

	// default sub-versions
	$version_bits[4] = 0; // for alpha, beta, rc, pl, etc
	$version_bits[5] = 0; // alpha, beta, etc number

	if (!empty($sub_version))
	{
		// match the sub-version
		if (preg_match('#^(A|ALPHA|B|BETA|G|GAMMA|RC|RELEASE CANDIDATE|GOLD|STABLE|FINAL|PL|PATCH LEVEL)\s*(\d*)\D*$#i', $sub_version, $match))
		{
			switch (strtoupper($match[1]))
			{
				case 'A':
				case 'ALPHA';
					$version_bits[4] = -4;
					break;

				case 'B':
				case 'BETA':
					$version_bits[4] = -3;
					break;

				case 'G':
				case 'GAMMA':
					$version_bits[4] = -2;
					break;

				case 'RC':
				case 'RELEASE CANDIDATE':
					$version_bits[4] = -1;
					break;

				case 'PL':
				case 'PATCH LEVEL';
					$version_bits[4] = 1;
					break;

				case 'GOLD':
				case 'STABLE':
				case 'FINAL':
				default:
					$version_bits[4] = 0;
					break;
			}

			$version_bits[5] = $match[2];
		}
	}

	// sanity check -- make sure each bit is an int
	for ($i = 0; $i <= 5; $i++)
	{
		$version_bits["$i"] = intval($version_bits["$i"]);
	}

	return $version_bits;
}

/**
* Compares two version strings. Returns true if the first parameter is
* newer than the second.
*
* @param	string	Version string; usually the latest version
* @param	string	Version string; usually the current version
* @param	bool	Flag to allow check if the versions are the same
*
* @return	bool	True if the first argument is newer than the second, or if 'check_same' is true and the versions are the equal
*/
function is_newer_version($new_version_str, $cur_version_str, $check_same = false)
{
	// if they're the same, don't even bother
	if ($cur_version_str != $new_version_str)
	{
		$cur_version = fetch_version_array($cur_version_str);
		$new_version = fetch_version_array($new_version_str);

		// iterate parts
		for ($i = 0; $i <= 5; $i++)
		{
			if ($new_version["$i"] != $cur_version["$i"])
			{
				// true if newer is greater
				return ($new_version["$i"] > $cur_version["$i"]);
			}
		}
	}
	else if ($check_same)
	{
		return true;
	}

	return false;
}

/**
* Function used for usort'ing a collection of templates.
* This function will return newer versions first.
*
* @param	array	First version
* @param	array	Second version
*
* @return	integer	-1, 0, 1
*/
function history_compare($a, $b)
{
	// if either of them does not have a version, make it look really old to the
	// comparison tool so it doesn't get bumped all the way up when its not supposed to
	if (!$a['version'])
	{
		$a['version'] = "0.0.0";
	}

	if (!$b['version'])
	{
		$b['version'] = "0.0.0";
	}

	// these return values are backwards to sort in descending order
	if (is_newer_version($a['version'], $b['version']))
	{
		return -1;
	}
	else if (is_newer_version($b['version'], $a['version']))
	{
		return 1;
	}
	else
	{
		if($a['type'] == $b['type'])
		{
			return ($a['dateline'] > $b['dateline']) ? -1 : 1;
		}
		else if($a['type'] == "historical")
		{
			return 1;
		}
		else
		{
			return -1;
		}
	}
}

// #############################################################################
/**
*	Checks for problems with conflict resolution
*
*	This was not put into check_template_errors because the reported for that
* assumes a certain kind of error and is confusing with the conflict error
* message.
*
* @param	string Template PHP code
* @return string Error message detected or empty string if no error
*/
function check_template_conflict_error($template)
{
	if (preg_match(get_conflict_text_re(), $template))
	{
		$error = fetch_error('template_conflict_exists');
		if (!$error)
		{
			//if the error lookup fails return *something* so the calling code doesn't think
			//we succeeded.
			return "Conflict Error";
		}
		else
		{
			return $error;
		}
	}

	return '';
}

/**
* Collects errors encountered while parsing a template and returns them
*
* @param	string	Template PHP code
*
* @return	string
*/
function check_template_errors($template)
{
	// Attempt to enable display_errors so that this eval actually returns something in the event of an error
	@ini_set('display_errors', true);

	if (preg_match('#^(.*)<if condition=(\\\\"|\')(.*)\\2>#siU', $template, $match))
	{
		// remnants of a conditional -- that means something is malformed, probably missing a </if>
		return fetch_error('template_conditional_end_missing_x', (substr_count($match[1], "\n") + 1));
	}

	if (preg_match('#^(.*)</if>#siU', $template, $match))
	{
		// remnants of a conditional -- missing beginning
		return fetch_error('template_conditional_beginning_missing_x', (substr_count($match[1], "\n") + 1));
	}

	if (strpos(@ini_get('disable_functions'), 'ob_start') !== false)
	{
		// alternate method in case OB is disabled; probably not as fool proof
		@ini_set('track_errors', true);
		$oldlevel = error_reporting(0);
		eval('$devnull = "' . $template . '";');
		error_reporting($oldlevel);

		if (strpos(strtolower($php_errormsg), 'parse') !== false)
		{
			// only return error if we think there's a parse error
			// best workaround to ignore "undefined variable" type errors
			return $php_errormsg;
		}
		else
		{
			return '';
		}
	}
	else
	{
		$olderrors = @ini_set('display_errors', true);
		$oldlevel = error_reporting(E_ERROR | E_PARSE | E_CORE_ERROR | E_COMPILE_ERROR | E_USER_ERROR);

		// VBV-12511 -- show template code and line numbers even if eval hits a fatal error
		$vb5_config = &vB::getConfig();
		if ($vb5_config['Misc']['debug'])
		{
			register_shutdown_function(function($template)
			{
				if (!empty($GLOBALS['vb_check_template_errors_passed']))
				{
					return;
				}

				echo '<h4>Compiled Template Code:</h4><div style="height:200px; overflow:auto; border:1px solid silver; font-style:normal; font-family:Courier New;"><ol><li>' . implode('</li><li>', explode("\n", htmlspecialchars($template))) . '</li></ol></div>';

			}, $template);
		}
		// end VBV-12511

		ob_start();

		//add the try/catch for PHP7.  Won't do anything for earlier versions (and messing around with the
		//output buffering shouldn't be needed for PHP7 but that should be vetted before we remove it.
		try
		{
			if (strpos($template, '$final_rendered') !== false)
			{
				eval($template);
			}
			else
			{
				eval('$devnull = "' . $template . '";');
			}
		}
		catch(Error $e)
		{
			$errors = $e->getMessage();
		}

		// VBV-12511 -- show template code and line numbers even if eval hits a fatal error
		if ($vb5_config['Misc']['debug'])
		{
			$GLOBALS['vb_check_template_errors_passed'] = true;
		}
		// end VBV-12511

		if(!isset($errors))
		{
			$errors = ob_get_contents();
		}
		ob_end_clean();

		error_reporting($oldlevel);
		if ($olderrors !== false)
		{
			@ini_set('display_errors', $olderrors);
		}

		return $errors;
	}
}

/**
* Fetches a current or historical template.
*
* @param	integer	The ID (in the appropriate table) of the record you want to fetch
* @param	string	Type of template you want to fetch; should be "current" or "historical"
*
* @return	array	The data for the matching record
*/
function fetch_template_current_historical(&$id, $type)
{
	global $vbulletin;

	$id = intval($id);

	if ($type == 'current')
	{
		return $vbulletin->db->query_first("
			SELECT *, template_un AS templatetext
			FROM " . TABLE_PREFIX . "template
			WHERE templateid = $id
		");
	}
	else
	{
		return $vbulletin->db->query_first("
			SELECT *, template AS templatetext
			FROM " . TABLE_PREFIX . "templatehistory
			WHERE templatehistoryid = $id
		");
	}
}


/**
* Fetches the list of templates that have a changed status in the database
*
* List is hierarchical by style.
*
* @return array Associative array of styleid => template list with each template
* list being an array of templateid => template record.
*/
function fetch_changed_templates()
{
	$set = vB::getDbAssertor()->getRows('vBForum:fetchchangedtemplates', array(
		vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_STORED
	));
	foreach ($set as $template)
	{
		$templates["$template[styleid]"]["$template[templateid]"] = $template;
	}
	return $templates;
}

/**
* Fetches the count templates that have a changed status in the database
*
* @return int Number of changed templates
*/
function fetch_changed_templates_count()
{
	$result = vB::getDbAssertor()->getRow('vBForum:getChangedTemplatesCount');
	return $result["count"];
}

/**
*	Get the template from the template id
*
*	@param id template id
* @return array template table record
*/
function fetch_template_by_id($id)
{
	$filter = array('templateid' => intval($id));
	return fetch_template_internal($filter);
}

/**
*	Get the template from the template using the style and title
*
*	@param 	int 	styleid
* 	@param  string	title
* 	@return array 	template table record
*/
function fetch_template_by_title($styleid, $title)
{
	$filter = array('styleid' => intval($styleid), 'title' => (string) $title, 'templatetype' => 'template');
	return fetch_template_internal($filter);
}


/**
*	Get the template from the templatemerge (saved origin templates in the merge process)
* using the id
*
* The record is returned with the addition of an extra template_un field.
* This is set to the same value as the template field and is intended to match up the
* fields in the merge table with the fields in the main template table.
*
*	@param 	int 	id - Note that this is the same value as the main template table id
* 	@return array 	template record with extra template_un field
*/
function fetch_origin_template_by_id($id)
{
	$result = vB::getDbAssertor()->getRow('templatemerge', array('templateid' => intval($id)));

	if ($result)
	{
		$result['template_un'] = $result['template'];
	}
	return $result;
}

/**
*	Get the template from the template using the id
*
* The record is returned with the addition of an extra template_un field.
* This is set to the same value as the template field and is intended to match up the
* fields in the merge table with the fields in the main template table.
*
*	@param int id - Note that this is the not same value as the main template table id,
*		there can be multiple saved history versions for a given template
* @return array template record with extra template_un field
*/
function fetch_historical_template_by_id($id)
{
	$result = vB::getDbAssertor()->getRow('templatehistory', array('templatehistoryid' => intval($id)));

	//adjust to look like the main template result
	if ($result)
	{
		$result['template_un'] = $result['template'];
	}
	return $result;
}

/**
*	Get the template record
*
* This should only be called by cover functions in the file
* caller is responsible for sql security on $filter;
*
*	@filter Array	Filters to be used in the where clause. Field should be the key:
*					e.g: array('templateid' => $someValue)
* @private
*/
function fetch_template_internal($filter)
{
	$assertor = vB::getDbAssertor();
	$structure = $assertor->fetchTableStructure('template');
	$structure = $structure['structure'];

	$queryParams = array();
	foreach ($filter AS $field => $val)
	{
		if (in_array($field, $structure))
		{
			$queryParams[$field] = $val;
		}
	}

	return $assertor->getRow('template', $queryParams);
}


/**
* Get the requested templates for a merge operation
*
*	This gets the templates needed to show the merge display for a given custom
* template.  These are the custom template, the current default template, and the
* origin template saved when the template was initially merged.
*
* We can only display merges for templates that were actually merged during upgrade
*	as we only save the necesary information at that point.  If we don't have the
* available inforamtion to support the merge display, then an exception will be thrown
* with an explanatory message. Updating a template after upgrade
*
*	If the custom template was successfully merged we return the historical template
* save at upgrade time instead of the current (automatically updated at merge time)
* template.  Otherwise the differences merged into the current template will not be
* correctly displayed.
*
*	@param int templateid - The id of the custom user template to start this off
*	@throws Exception thrown if state does not support a merge display for
* 	the requested template
*	@return array array('custom' => $custom, 'new' => $new, 'origin' => $origin)
*/
function fetch_templates_for_merge($templateid)
{
	global $vbphrase;
	if (!$templateid)
	{
		throw new Exception($vbphrase['merge_error_invalid_template']);
	}

	$custom = fetch_template_by_id($templateid);
	if (!$custom)
	{
		throw new Exception(construct_phrase($vbphrase['merge_error_notemplate'], $templateid));
	}

	if ($custom['mergestatus'] == 'none')
	{
		throw new Exception($vbphrase['merge_error_nomerge']);
	}

	$new = fetch_template_by_title(-1, $custom['title']);
	if (!$new)
	{
		throw new Exception(construct_phrase($vbphrase['merge_error_nodefault'],  $custom['title']));
	}

	$origin = fetch_origin_template_by_id($custom['templateid']);
	if (!$origin)
	{
		throw new Exception(construct_phrase($vbphrase['merge_error_noorigin'],  $custom['title']));
	}

	if ($custom['mergestatus'] == 'merged')
	{
		$custom = fetch_historical_template_by_id($origin['savedtemplateid']);
		if (!$custom)
		{
			throw new Exception(construct_phrase($vbphrase['merge_error_nohistory'],  $custom['title']));
		}
	}

	return array('custom' => $custom, 'new' => $new, 'origin' => $origin);
}


/**
* Format the text for a merge conflict
*
* Take the three conflict text strings and format them into a human readable
* text block for display.
*
* @param string	Text from custom template
* @param string	Text from origin template
* @param string	Text from current VBulletin template
* @param string	Version string for origin template
* @param string	Version string for currnet VBulletin template
* @param bool	Whether to output the wrapping text with html markup for richer display
*
* @return string -- combined text
*/
function format_conflict_text($custom, $origin, $new, $origin_version, $new_version, $html_markup = false, $wrap = true)
{
	global $vbphrase;

	$new_title = $vbphrase['new_default_value'];
	$origin_title = $vbphrase['old_default_value'];
	$custom_title = $vbphrase['your_customized_value'];

	if ($html_markup)
	{
		$text =
			"<div class=\"merge-conflict-row\"><b>$custom_title</b><div>" . format_diff_text($custom, $wrap) . "</div></div>"
			. "<div class=\"merge-conflict-row\"><b>$origin_title</b><div>" . format_diff_text($origin, $wrap) . "</div></div>"
			. "<div class=\"merge-conflict-final-row\"><b>$new_title</b><div>" . format_diff_text($new, $wrap) . "</div></div>";
	}
	else
	{
		$origin_bar = "======== $origin_title ========";

		$text  = "<<<<<<<< $custom_title <<<<<<<<\n";
		$text .= $custom;
		$text .= $origin_bar . "\n";
		$text .= $origin;
		$text .= str_repeat("=", strlen($origin_bar)) . "\n";
		$text .= $new;
		$text .= ">>>>>>>> $new_title >>>>>>>>\n";
	}

	return $text;
}

function format_diff_text($string, $wrap = true)
{
	if (trim($string) === '')
	{
		return '&nbsp;';
	}
	else
	{
		if ($wrap)
		{
			$string = nl2br(htmlspecialchars_uni($string));
			$string = preg_replace('#( ){2}#', '&nbsp; ', $string);
			$string = str_replace("\t", '&nbsp; &nbsp; ', $string);
			return "<code>$string</code>";
		}
		else
		{
			return '<pre style="display:inline">' . "\n" . htmlspecialchars_uni($string) . '</pre>';
		}
	}
}

/**
* Return regular expression to detect the blocks returned by format_conflict_text
*
* @return string -- value suitable for passing to preg_match as an re
*/
function get_conflict_text_re()
{
	//we'll start by grabbing the formatting from format_conflict_text directly
	//this should reduce cases were we change the formatting and forget to change the re
	$re = format_conflict_text(".*\n", ".*\n", ".*\n", ".*", '.*');

	//we don't have a set number of delimeter characters since we try to even up the lines
	//in some cases (which can vary based on the version strings).  Since we don't have the
	//exact version available, we don't know how many got inserted.  We'll match any number
	//(we use two because we should always have at least that many and it dramatically improves
	//performance -- probably because we get an early failure on all of the html tags)
	$re = preg_replace('#<+#', '<<+', $re);
	$re = preg_replace('#=+#', '==+', $re);
	$re = preg_replace('#>+#', '>>+', $re);

	//handle variations on newlines.
	$re = str_replace("\n", "(?:\r|\n|\r\n)", $re);

	//convert the preg format
	$re = "#$re#isU";
	return $re;
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 103332 $
|| #######################################################################
\*=========================================================================*/
