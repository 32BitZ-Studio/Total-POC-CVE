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

// ######################## SET PHP ENVIRONMENT ###########################
error_reporting(E_ALL & ~E_NOTICE);

// ##################### DEFINE IMPORTANT CONSTANTS #######################
define('CVS_REVISION', '$RCSfile$ - $Revision: 99787 $');

// #################### PRE-CACHE TEMPLATES AND DATA ######################
global $phrasegroups, $specialtemplates, $vbphrase, $groupcache, $tableadded;
$phrasegroups = array('cpcms');
$specialtemplates = array();

// ########################## REQUIRE BACK-END ############################
require_once(dirname(__FILE__) . '/global.php');

// ######################## CHECK ADMIN PERMISSIONS #######################
if (!can_administer('canadmincms'))
{
	print_cp_no_permission();
}

// ############################# LOG ACTION ###############################

// TODO: WHAT SHOULD WE LOG?
/*$vbulletin->input->clean_array_gpc('r', array(
	'userid' => vB_Cleaner::TYPE_INT
));*/
//log_admin_action(iif($vbulletin->GPC['userid'] != 0, 'user id = ' . $vbulletin->GPC['userid']));


// ########################################################################
// ######################### START MAIN SCRIPT ############################
// ########################################################################

$vb5_config =& vB::getConfig();


// ###################### setting cookies #######################
// This has to happen before header is sent to browser

// clean the required request & cookie values so we can use them here
$vbulletin->input->clean_array_gpc('c', array(COOKIE_PREFIX . 'contentlist_perpage' => vB_Cleaner::TYPE_UINT));
$vbulletin->input->clean_array_gpc('r', array('perpage'		=> vB_Cleaner::TYPE_UINT,));

// if cookie was set, set the perpage value to the value found in cookie only if not set in the request.
// If request perpage is not empty, the user probably set it and we need to update the cookie.
if (!empty($vbulletin->GPC[COOKIE_PREFIX . 'contentlist_perpage']))
{
	if (empty($vbulletin->GPC['perpage']))
	{
		$vbulletin->GPC['perpage'] = $vbulletin->GPC[COOKIE_PREFIX . 'contentlist_perpage'];
	}
}

if (!empty($vbulletin->GPC['perpage']))
{
	$perpage = $vbulletin->GPC['perpage'];
}
else
{
	$perpage = 25;
}
// save to cookie if the request value is different than the one saved in cookie.
if (($perpage != $vbulletin->GPC[COOKIE_PREFIX . 'contentlist_perpage']) AND !@headers_sent())
{
	vbsetcookie('contentlist_perpage', $perpage, true, true, true);
}
// ###################### end setting cookies #######################

// Include css_b_icon.css on the page
// This links directly to css.php instead of using CSS as files if enabled
// This works around some issues with using frontend CSS in the Admin CP, and should not
// cause problems. 1) We already force some CSS to load via css.php in other places,
// 2) the file should be cached by the browser, 3) this is the Admin CP not the public
// facing frontend.
// Using the default styleid could prove problematic, and if so, we can figure out a way
// to always get the vB Default style (master style) for the Admin CP use if we need to.
$vboptions = vB::getDatastore()->getValue('options');
$style = vB_Library::instance('style')->fetchStyleByID($vboptions['styleid'], false);
$csslinkquery = http_build_query(array(
	'styleid' => $vboptions['styleid'],
	'langid' => LANGUAGEID,
	'd' => $style['dateline'],
	'td' => vB_Template_Runtime::fetchStyleVar('textdirection'),
	'sheet' => 'css_b_icon.css',
	'v' => $vboptions['simpleversion']
), '', '&amp;');
$csslink = '<link rel="stylesheet" type="text/css" href="css.php?' . $csslinkquery . '" />';

// print header
print_cp_header($vbphrase['content_management'], '', $csslink);
unset($csslink, $csslinkquery, $style);


if (empty($_REQUEST['do']))
{
	$_REQUEST['do'] = 'contentlist';
}


// articles root channelid
$articleChannelId = vB_Api::instanceInternal('node')->fetchArticleChannel();

// just a wrapper for generateCategoryList because I'm having to call the same3 lines over and over again.
function getFullCategoryList(&$channelInfoArray = array(), $tabsize=1, $tabchar="--", $tabspace=" ")
{
	$cache = vB_Cache::instance(vB_Cache::CACHE_STD);
	$cacheKey = "vBAdminCP_CMS_Categories";
	$categories = $cache->read($cacheKey);
	$writeCache = false;
	$cacheEvents = array();

	if (empty($categories))
	{
		$categories = vB::getDbAssertor()->getRows('vBAdminCP:getCMSChannels',
			array(	'articleChannelId' => vB_Api::instanceInternal('node')->fetchArticleChannel(),
					'channelcontenttype' =>  vB_Api::instanceInternal('ContentType')->fetchContentTypeIdFromClass('Channel')
			)
		);
		$writeCache = true;
	}
	$categoriesList = array();

	// The query result is sorted by depth first. We have to group/sort into a hierarchical order, such that
	// children come immediately after a parent.
	$parent_position = array(); // parentid => position
	$nodeid_index = array();	// nodeid => search result index
	foreach($categories AS $index => $category)
	{
		$cacheEvents[] = 'nodeChg_' . $category['nodeid'];
		$parentid = $category['parentid'];
		$nodeid_index[$category['nodeid']] = $index;
		if (empty($parent_position)) // the top-most depth=0 item. I.e. the root channel
		{
			$parent_position[$category['nodeid']] = 0;
		}
		else
		{
			$position = $parent_position[$parentid] + 1;
			// increment positions of parents whose positions are after $position
			foreach($parent_position AS $pid => $pos)
			{
				if ($pos >= $position)
				{
					$parent_position[$pid]++;
				}
			}
			// node will be positioned after its parent, but above any siblings. This is why all but the depth is sort order DESC in the query.
			$parent_position[$category['nodeid']] = $position;
		}
	}
	// sort parent_position by position
	asort($parent_position);
	foreach ($parent_position AS $nodeid => $position)
	{
		$category = $categories[$nodeid_index[$nodeid]];
		$channelInfoArray[$category['nodeid']] = array(
			"title" => $category['htmltitle'],
			"parentid" => $category['parentid'],
			"showpublished" => $category['showpublished'],
			"textcount" => $category['textcount'],
			"displayorder" => $category['displayorder'],
			"description" => $category['description'],
		);
		$tab = str_repeat($tabchar, ($category['depth'] * $tabsize)) . $tabspace;
		$categoriesList[$category['nodeid']] = $tab . $category['htmltitle'];
	}

	if ($writeCache)
	{
		$cache->write($cacheKey, $categories, 1440, $cacheEvents);
	}

	return $categoriesList;
}

// some commonly used icons...
$icon['x'] = 'style="cursor: pointer; display: inline-block;" class="b-icon b-icon__x-circle"';

// Using Sitebuilder icons, per sprint review 2013-10-10
$cssimgurl2 = "" .$vbulletin->options['frontendurl'] . '/images/css/sprite_icons_' . vB_Template_Runtime::fetchStyleVar('textdirection') . ".png";
$icon['edit'] = "style=\"cursor: pointer; padding-right: 5px; display: inline-block; background-position: -32px -64px; width: 24px; height: 24px; background-image: url(" . $cssimgurl2 . ");\"";
$icon['delete'] = "style=\"cursor: pointer; display: inline-block; background-position: -0px -64px; width: 24px; height: 24px; background-image: url(" . $cssimgurl2 . ");\"";

// some commonly used javascript...
?>
	<script type="text/javascript">
	// handles checking/unchecking all nodes when top checkbox is clicked
	function js_cms_select_node(nodeid)
	{
		nodeid = "select_" + nodeid;
		var checkBox = document.getElementById(nodeid),
			checked = checkBox.checked,
			inputs = document.getElementsByTagName("input"),
			length = inputs.length;
		if (nodeid == 'select_all')
		{
			// check all checkboxes
			for (var i = 0; i < length; i++)
			{
				// deal only with the checkboxes with select_<nodeid> id's
				if (inputs[i].id != 'select_all' && inputs[i].type == "checkbox" && inputs[i].id.substring(0,7) == "select_" )
				{
					inputs[i].checked = checked;
				}
			}
		}
		else	// indeterminate check.
		{
			checkallBox = document.getElementById("select_all"),
			checkallBoxChecked = checkallBox.checked,
			// see if all checkboxes are checked.
			allchecked = checked;
			anychecked = false;	// if select_all was checked, then at least 1 was checked, EXCEPT when there's only one result.
			for (var i = 0; i < length; i++)
			{
				// deal only with the checkboxes with select_<nodeid> id's
				if (inputs[i].id != 'select_all' && inputs[i].type == "checkbox" && inputs[i].id.substring(0,7) == "select_" )
				{
					// check if any of the boxes are checked.
					if (inputs[i].checked)
					{
						if (!anychecked)
						{
							anychecked = true;
						}
					}
					else
					{
						allchecked = false;
					}
				}
			}
			if (allchecked)	// if all nodes are selected, let's check the select_all for them.
			{
				checkallBox.checked = true;
			}
			else if (anychecked && checkallBoxChecked)	// only set indeterminate if select_all was previously checked
			{
				checkallBox.indeterminate = true;
			}
			else // nothing is selected, uncheck select_all
			{
				checkallBox.indeterminate = false;
				checkallBox.checked = false;
			}

		}
	}
	// save display order. bit of a hack, but easiest to just get the displayorders through a form submit
	function js_cms_savedisplayorder()
	{
		var form = document.getElementById('cpform'),
			override = document.createElement("input");
		override.type = "hidden";
		override.name = "action_override";
		override.value = "savedisplayorder";
		form.appendChild(override);
		document.getElementById('cpform').submit();
	}
	</script>
	<?php
// ###################### Start content list #######################
if ($_REQUEST['do'] == 'contentlist')
{
	// Avoid using GET requests to perform none-idempotent actions..
	?>
	<script type="text/javascript">
	// update filter value list
	function js_cms_update_filter()
	{
		var filterKey = document.getElementById('filterkey').value,
			filterValueSelectId = "filtervalue_" + filterKey,
			allFilterValueSelects = document.getElementsByName("filtervalue"),
			length = allFilterValueSelects.length;
		for (var i=0; i < length; i++)
		{
			if (allFilterValueSelects[i].id != filterValueSelectId)
			{
				$(allFilterValueSelects[i]).addClass("hide");
			}
			else
			{
					$(allFilterValueSelects[i]).removeClass("hide");
			}
		}
		var filterOpSelectId = "filterop_" + filterKey,
			allFilterOpSelects = document.getElementsByName("filterop"),
			length = allFilterOpSelects.length;
		for (var i=0; i < length; i++)
		{
			if (allFilterOpSelects[i].id != filterOpSelectId)
			{
				$(allFilterOpSelects[i]).addClass("hide");
			}
			else
			{
				$(allFilterOpSelects[i]).removeClass("hide");
			}
		}
	}

	// handle apply filter action when filtergo button is pressed
	function js_cms_go_filter()
	{
		var filterKey = document.getElementById('filterkey').value,
			filterOpEl = document.getElementById('filterop_' + filterKey),
			filterOp = false;
		if (filterOpEl)
		{
			filterOp = filterOpEl.value;
		}
		if (filterKey != "default")
		{
			js_cms_apply_filter(filterKey, filterOp, 1);
		}
	}

	// apply a filter
	function js_cms_apply_filter(filterKey,filterOp,direction)
	{
		var	addKey = filterKey,
			addString = "&" + filterKey;
		if (filterOp)
		{
			addString += "[" + filterOp + "]";
		}
		if (direction > 0)
		{
			var filterValue = document.getElementById('filtervalue_' + filterKey).value;
			addString += "=" + filterValue;
		}
		else	// if direction is nonpostive, we're removing the filter instead.
		{
			addString = '';
		}

		if (filters != "default")	// default is no action
		{
			// go to first page when a filter is applied/removed.
			// Since the result can be different, it does not make sense to maintain the current page.
			document.getElementById('removefilter_page_').setAttribute('data-value', 1);

			var filters = document.getElementsByName('filter'),
				length = filters.length;
			filterString = "";
			for (var i = 0; i < length; i++)
			{
				if (filters[i].getAttribute('data-key') != addKey)
				{
					filterString += "&" + filters[i].getAttribute('data-key');
					if (filters[i].getAttribute('data-useopkey') > 0)
					{
						filterString += "[" + filters[i].getAttribute('data-opkey') + "]";
					}
					filterString += "=" + filters[i].getAttribute('data-value');
				}
				else
				{
					filterString += addString;
					addString = '';
				}
			}

			filterString += addString;
			vBRedirect("admincp/cms.php?do=contentlist" + filterString);
		}
	}

	// handles single-content action (edit, delete)
	function js_cms_contentaction(nodeid, action)
	{
		switch (action)
		{
			case 'editcontent':
				url = document.getElementById("edit_content_" + nodeid).getAttribute('data-url');
				// check for edit=1 query & append it if missing
				separator = url.indexOf('?') !== -1 ? "&" : "?";
				if (url.indexOf('edit=1') == -1)
				{
					url = url + separator + 'edit=1';	// query string to initialize editor
				}
				window.open(url); // open article in new window
				break;
			case 'deletecontent':
				gobackto = window.location.href;
				gobackto = gobackto.replace(/^.*?do=/i, '');
				gobackto = encodeURIComponent(gobackto);
				vBRedirect("admincp/cms.php?do=delete&nodeid=" + nodeid + "&type=article&uriencoded=1&gobackto=" + gobackto);
				break;
			default:
				break;
		}
	}

	// used to populate tag or author list
	function js_cms_generate_xlist(name)
	{
		var subjects = document.getElementsByName(name + 'list'),
			length = subjects.length
			subjectSelect = document.getElementById('filtervalue_' + name);
		subjectSelect.remove(0);
		for (i=0; i < length; i++)
		{
			subjectItem = document.createElement( 'option' );
			subjectItem.text = subjects[i].value;
			subjectItem.value = subjects[i].getAttribute('data-id');
			subjectSelect.add(subjectItem);
		}
	}

	// show tags, or filter by selected tag. direction = 0 means filter, -1 or +1 means hide or show tags
	// id can be nodeid for showing tags, or tagid for filtering.
	function js_cms_showtags(id, direction)
	{
		if (direction == 0)
		{
			// need to refactor. this bit of code is duplicated from js_cms_apply_filter
			var filters = document.getElementsByName('filter'),
				length = filters.length,
				filterString = "",
				addString = "&tag=" + id;

			for (var i = 0; i < length; i++)
			{
				if (filters[i].id != "removefilter_tag_")
				{
					filterString += "&" + filters[i].getAttribute('data-key');
					if (filters[i].getAttribute('data-useopkey') > 0)
					{
						filterString += "[" + filters[i].getAttribute('data-opkey') + "]";
					}
					filterString += "=" + filters[i].getAttribute('data-value');
				}
				else
				{
					filterString += addString;
					addString = '';
				}
			}

			filterString += addString;
			vBRedirect("admincp/cms.php?do=contentlist" + filterString);
		}

		var tagCountAnchor = document.getElementById("tagcount_" + id);
		var tagStringsDiv = document.getElementById("tag_" + id);
		if (direction > 0)
		{
			$(tagCountAnchor).addClass("hide");
			$(tagStringsDiv).removeClass("hide");
		}
		if (direction < 0)
		{
			$(tagCountAnchor).removeClass("hide");
			$(tagStringsDiv).addClass("hide");
		}

		return false;
	}
	</script>
	<?php
	$vbulletin->input->clean_array_gpc('r', array(
		'channel'		=> vB_Cleaner::TYPE_INT,
		'page'			=> vB_Cleaner::TYPE_UINT,
		//'perpage'		=> vB_Cleaner::TYPE_UINT,
		'contenttype'	=> vB_Cleaner::TYPE_STR,
		'author'	 	=> vB_Cleaner::TYPE_STR,
		'published' 	=> vB_Cleaner::TYPE_NOCLEAN,
		'preview'	 	=> vB_Cleaner::TYPE_NOCLEAN,
		'tag'	 		=> vB_Cleaner::TYPE_NOCLEAN,
		'date' 			=> vB_Cleaner::TYPE_NOCLEAN,
		'views' 		=> vB_Cleaner::TYPE_NOCLEAN,
		'comments'		=> vB_Cleaner::TYPE_NOCLEAN,
	));

	// get all categories
	$channelInfoArray = array();
	$categoriesList = getFullCategoryList($channelInfoArray);

	// This is the query string used to specify the filters.
	// this is appended to the gobackto hidden input to allow redirection back to this filtered page.
	$filterQueryString = "";

	// all possible filter options
	// Selected filters are unset as we buildup the filter
	$options_filter_key = array('default' => $vbphrase['select_a_filter'],
		'channel' => $vbphrase['cms_category'],
		'contenttype' => $vbphrase['contenttype'],
		'author' => $vbphrase['author'],
		'tag' => $vbphrase['tag'],
		'published' => $vbphrase['cms_published'],
		'preview' => $vbphrase['publicpreview'],
		'date' => $vbphrase['date'],
		'views' => $vbphrase['views'],
		'comments' => $vbphrase['comments'],
	);

	/**  pretty-fy output stuff
	 */
	// filter remove list, ex: views > 5 X, published = yes X ...
	$filterListHTML = "";

	// convert the op to a human-readable operand =, <, >
	$opToHTML = array(
		"eq" => "=",
		"lt" => "&lt;",
		"gt" => "&gt;",
	);

	// text-like content types, back and forth from contenttypeid to contenttypeclass
	$contentTypeApi = vB_Api::instanceInternal('ContentType');
	$contentTypes_id_class = array();
	$contentTypes_class_id = array();
	$contentTypes_class_class = array();
	foreach (array("Text", "Poll", "Gallery", "Link", "Video", "Event") AS $class)
	{
		$id = $contentTypeApi->fetchContentTypeIdFromClass($class);
		$contentTypes_id_class[$id] = $class;
		$contentTypes_class_id[$class] = $id;
		$contentTypes_class_class[$class] = $class;
	}
	// contenttype output formatter
	function formatContentTypeId($id, $idToClass)
	{
		return $idToClass[$id];
	}

	// tagid to text. need to grab the text from the tag table
	function formatTag($id)
	{
		$tagQry = vB::getDbAssertor()->getRow('vBForum:tag', array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT, 'tagid' => $id));
		if (isset($tagQry['tagtext']))
		{
			return $tagQry['tagtext'];
		}
		else
		{
			return "";
		}
	}

	$dateFormat = $vbulletin->options["dateformat"];

	// specify functions to use to format certain values here. Ex. publishdate formated by vbdate
	// array( nodefieldname/$filter_name => array(functionname, array(functionargs))),
	$outputFormatter = array(
		"viewcount" 		=> array("vb_number_format", array("#filter_value#")),
		"textcount" 		=> array("vb_number_format", array("#filter_value#")),
		"contenttypeid" 	=> array("formatContentTypeId", array("#filter_value#", $contentTypes_id_class)),
		"tag" 				=> array("formatTag", array("#filter_value#")),
	);

	// phrases used for the filter remove list
	// TODO, we can just copy $options_filter_key & update whatever uses $filterKeyToPhraseMap to understand that the value is the phrase already
	$filterKeyToPhraseMap = $options_filter_key;

	/*array(
		"channel" 		=> "cms_category",
		"contenttype"	=> "contenttype",
		"author" 		=> "author",
		"tag" 			=> "tag",
		"published"		=> "cms_published",
		"preview" 		=> "publicpreview",
		"date"			=> "date",
		"views"			=> "views",
		"comments"		=> "comments",
	);*/



	// PAGINATION
	if (!empty($vbulletin->GPC['page']))
	{
		$page = $vbulletin->GPC['page'];
	}
	else
	{
		$page = 1;
	}

	$searchParams['page'] = $page;
	$searchParams['perpage'] = $perpage;
	$filterQueryString .= "&page=$page&perpage=$perpage";
	// pagination filterlist html comes before the channel simply for cosmetic reasons. It's easier to remove trailing comma after the channel filter this way.
	$filterListHTML .= "<input type=\"hidden\" name=\"filter\" id=\"removefilter_page_\" data-key=\"page\" data-opkey=\"\" data-useopkey=\"0\" data-value=\"". $page ."\" />" .
			"<input type=\"hidden\" name=\"filter\" id=\"removefilter_perpage_\" data-key=\"perpage\" data-opkey=\"\" data-useopkey=\"0\" data-value=\"". $perpage ."\" />";

	// selected filter operation / value for applied filters
	$selectedFilterOp = array();
	$selectedFilterValue = array();
	$filterWordLimit = 20;

	// CHANNEL FILTER, handled specially than the additional filters.
	// Can't be integer 0. If it is ('default', for ex), default to root channel, and set no depth
	if (!empty($vbulletin->GPC['channel']) )
	{
		$gpc_key = 'channel';
		$channelid = $vbulletin->GPC['channel'];
		$searchParams['channelids'] = array($channelid); // single parent.
		$selectedFilterValue[$gpc_key] = $channelid;
		$filterWord = $channelInfoArray[$channelid]['title'];
		$filtertext = $filterKeyToPhraseMap[$gpc_key]  . " = " .  ((strlen($filterWord) > $filterWordLimit)?substr($filterWord, 0, $filterWordLimit-3) . "...":$filterWord);	// prettify
		$id = "removefilter_".$gpc_key."_";
		$filterListHTML .= "<input type=\"hidden\" name=\"filter\" id=\"" . $id . "\" data-key=\"" . $gpc_key . "\" data-opkey=\"\" data-useopkey=\"0\" data-value=\"". $channelid ."\" />";
		$filterListHTML .= "<wbr /><span title=\"$filterWord\">" .
			$filtertext .
			"&nbsp;<div onclick=\"js_cms_apply_filter('$gpc_key','', -1)\"" . $icon['x'] . "></div></span>, \t";
		//unset($options_filter_key[$gpc_key]); // uncomment to remove applied filter from filter list.
		$filterQueryString .= "&" . $gpc_key . "=" . $channelid;
	}
	else
	{
		$channelid = $articleChannelId;
		$searchParams['channelids'] = array_keys($channelInfoArray); // all CMS channels
		//$depth = 0;	// list articles from ALL categories
	}


	/**
	 * Additional Filtering
	*/
	// maps external (querystring / column header) => internal (search result array keys) fieldname
	// Ex. query string specifies &preview=no, the fieldname it should check is "public_preview"
	// When adding a new potential filter, be sure to add it to the cleaning list above
	// ($vbulletin->input->clean_array_gpc()) or it will be discarded before reaching this point.
	$queryToFieldname = array(
		//"channel"
		"published"		=> "showpublished",
		"preview" 		=> "public_preview",
		"author" 		=> "authorname",
		"contenttype" 	=> "contenttypeid",
		"tag"			=> "tag",
		"date"			=> "publishdate",
		"views"			=> "viewcount",
		"comments"		=> "textcount",
	);
	$dateMaps = array();
	if (isset($vbulletin->GPC['date']))
	{
		foreach ($vbulletin->GPC['date'] AS $op => $date)
		{
			$dateMaps[$date] = strtotime($date);	// yy-mm-dd to unix
		}
	}
	/*
	 * 	A bit more complex map. Given a field name, if appropriate it has maps from "readable" querystring values to their equivalent used in the nodes array.
	 *	Also specifies what comparison operations are possible, with default being the first one.
	 *		ex. &published=yes, that maps to a check of showpublished == 1.
	 *  For operations with only one allowed operations, the op key is not required.
	 *		ie. published[eq]=yes will not work.
	 *	if no values are specified, then it's usually variable & dependent on content, ex authorname
	 *	usage ex. admincp/cms.php?do=contentlist&preview=no&published=yes&date[lt]=1379949480
	 */
	$filterMap = array(
		"showpublished" 	=> array("values" => array("yes" => 1, "no" => 0),	"op" => array("eq")),
		"public_preview"	=> array("values" => array("yes" => 1, "no" => 0), 	"op" => array("eq")),
		"authorname" 		=> array("values" => array(), 		"op" => array("eq")),	// moved to json filter list
		"contenttypeid" 	=> array("values" => $contentTypes_class_id, 		"op" => array("eq")),
		"tag" 				=> array("values" => array(), 		"op" => array("eq")),
		"publishdate" 			=> array("values" => $dateMaps, 		"op" => array("lt", "gt")),
		"viewcount" 		=> array("values" => array(), 		"op" => array("eq", "lt", "gt")),
		"textcount" 		=> array("values" => array(), 		"op" => array("eq", "lt", "gt")),
	);
	foreach ($queryToFieldname AS $gpc_key => $filter_name)
	{
		if (!empty($vbulletin->GPC[$gpc_key]))
		{
			/* FORMAT INPUT INTO STANDARD ARRAY */
			$map = $filterMap[$filter_name];
			$useOpKey = count($map["op"]) - 1; // used to indicate which filters only has 1 op & should not require an op key
			if (!is_array($vbulletin->GPC[$gpc_key]))
			{
				$default_op = $map["op"][0];
				$filterSet[$default_op] = $vbulletin->GPC[$gpc_key];
			}
			else
			{
				$filterSet = $vbulletin->GPC[$gpc_key];
			}

			// filter_value is the value given in the query string, not the value used internally
			foreach ($filterSet AS $filter_op => $filter_value)
			{
				// make sure this operation is allowed. key can be int 0, so explicit boolean check
				if (array_search($filter_op, $map["op"]) === false)
				{
					continue;
				}

				/* APPEND FILTER TO FILTER QUERY STRING*/
				$filterQueryString .= "&" . $gpc_key . ($useOpKey?"[".$filter_op."]":"") . "=" . $filter_value;
				$selectedFilterValue[$gpc_key] = $filter_value;

				/* ADD FILTER TO SEARCH PARAMS */
				// if necessary, convert the input value something meaningful for the tables.
				// Ex., "Yes" to 1 for showpublished & public_preview
				if (isset($map["values"][$filter_value]))
				{
					$mappedValue = $map["values"][$filter_value];
				}
				else
				{
					$mappedValue = $filter_value;
				}
				if ($useOpKey)
				{
					$searchParams[$filter_name] = array("op" => $filter_op, "value" => $mappedValue);
					$selectedFilterOp[$gpc_key] = $filter_op;
				}
				else
				{
					$searchParams[$filter_name] = $mappedValue;
				}


				/* GENERATE FILTER LIST HTML */
				// format the value to something readable, if a function is specified
				$prettyValue = $filter_value;
				if (isset($outputFormatter[$filter_name]))
				{
					$index = array_search('#filter_value#', $outputFormatter[$filter_name][1]);
					$outputFormatter[$filter_name][1][$index] = $filter_value;
					$prettyValue = call_user_func_array($outputFormatter[$filter_name][0], $outputFormatter[$filter_name][1]);
				}
				$filterWord = $prettyValue;
				$filtertext = $filterKeyToPhraseMap[$gpc_key]  . " = " .  ((strlen($filterWord) > $filterWordLimit)?substr($filterWord, 0, $filterWordLimit-3) . "...":$filterWord);	// prettify
				//$filtertext = $filterKeyToPhraseMap[$gpc_key] . " " . $opToHTML[$filter_op] . " " . $prettyValue;
				$id = "removefilter_" . $gpc_key . "_" . ($useOpKey?$filter_op:"");
				$filterListHTML .=
					"<input type=\"hidden\" name=\"filter\" id=\"" . $id . "\" data-key=\"" . $gpc_key . "\" data-opkey=\"" . $filter_op . "\" data-useopkey=\"$useOpKey\" data-value=\"". $filter_value ."\" />" .
					"<wbr /><span title=\"$filterWord\">" . $filtertext . "&nbsp;" .
					"<div onclick=\"js_cms_apply_filter('$gpc_key','".($useOpKey?$filter_op:"")."', -1)\"" . $icon['x'] . "></div></span>, \t";


				/* REMOVE USED FILTER FROM FILTER SELECT DROPDOWN */
				//unset($options_filter_key[$gpc_key]);  // uncomment to remove applied filter from filter list.
			}
		}
	}
	$filterListHTML = trim($filterListHTML, ", \t"); // remove last comma


	/**
	 *	Begin building buttons & header
	 */

	$options_actionlist = array(
		'default' => $vbphrase['select_an_action'],
		'publish' => $vbphrase['publish'],
		'unpublish' => $vbphrase['unpublish'],
		'move' => $vbphrase['move'],
		'delete' => $vbphrase['delete'],
	);

	// Possible filter-values that can be selected for each filter. Some of them are infinite, and should be handled by
	// something other than a select dropdown (ex, an input box for views, comments)
	// for a list of all available filters, see $options_filter_key further above
	$options_filter_value = array(
		'default' => array("default" => $vbphrase['please_choose_a_filter']),
		'channel' => $categoriesList,
		'contenttype' => $contentTypes_id_class,
		'author' => array("default" => $vbphrase['no_authors_found']),
		'tag' => array("default" => $vbphrase['no_tags_found']),
		'published' => array("yes" => $vbphrase['yes'], "no" => $vbphrase['no']),
		'preview' => array("yes" => $vbphrase['yes'], "no" => $vbphrase['no']),
		'date' => array("default" => "inputbox"),
		'views' => array("default" => "inputbox"),
		'comments' => array("default" => "inputbox"),
	);

	// construct the filter value select or input-box based on options...
	$filter_value_selects = "";
	foreach ($options_filter_value AS $key => $options)
	{
		$fieldname = isset($queryToFieldname[$key])?$queryToFieldname[$key]:false;
		$useOpKey = isset($filterMap[$fieldname])?(count($filterMap[$fieldname]['op']) - 1):0;
		if ($useOpKey)
		{
			foreach ($filterMap[$fieldname]['op'] AS $opkey)
			{
				$opOptions[$opkey] = $opToHTML[$opkey];
			}
			$selectOp = "<select class=\"bginput hide\" name=\"filterop\" id=\"filterop_" .$key. "\">\n" .
				construct_select_options($opOptions, (isset($selectedFilterOp[$key])?$selectedFilterOp[$key]:'')) . "\t</select>\n";
			// if multiple operations are possible, a textbox will likely be more useful than a select dropdown...
			$filter_value_selects .= $selectOp .
				"<input " . (($key != 'default')?"class=\"bginput hide\" ":"class=\"bginput\"") . " type=\"text\" name=\"filtervalue\" id=\"filtervalue_" .$key. "\"" .
				" onkeydown=\"if (event.keyCode == 13) {js_cms_go_filter(); return false;}\" " .
				(isset($selectedFilterValue[$key])?"value=\"" . $selectedFilterValue[$key] . "\"":'') . ">\n\t";
		}
		else
		{
			$filter_value_selects .= "<select " . (($key != 'default')?"class=\"bginput hide\" ":"class=\"bginput\"") . " name=\"filtervalue\" id=\"filtervalue_" .$key. "\"" .
				"onchange=\"js_cms_go_filter();\">\n" .
				construct_select_options($options, (isset($selectedFilterValue[$key])?$selectedFilterValue[$key]:'')) . "\t</select>";
		}
	}

	// build up the 'action' cells that will go above the column titles
	// what to do about certain fields that can't be built up until all the node data is available? Ex, authors, tags
	$actioncell1 = "<input type=\"checkbox\" id=\"select_all\" onchange=\"js_cms_select_node('all');\">";
	$actioncell2 =
		"<select name=\"action\" id=\"action\" class=\"bginput\">\n" . construct_select_options($options_actionlist) . "\t</select>" .
			construct_button_code($vbphrase['apply'], "submit", false, '', false);
	$actioncell3 =
		"<select id=\"filterkey\" class=\"bginput\" onchange=\"js_cms_update_filter();\">\n" . construct_select_options($options_filter_key) . "\t</select>" .
		$filter_value_selects .
		"<input type=\"button\" id=\"filtergo\" class=\"button\" value=\"".$vbphrase['filter']."\" onclick=\"js_cms_go_filter();\">";
	$actioncell4 = $filterListHTML; // additional filter indicators
	$actioncellLast = construct_button_code($vbphrase['savedisplayorder'], "js_cms_savedisplayorder()", false, '', true);
	$header = array(
		'checkbox' 		=> '',
		'title' 		=> $vbphrase['title'],
		'contenttype' 	=> $vbphrase['content_break_type'],
		'category' 		=> $vbphrase['cms_category'],	// should this read "Category" singular? Since they can only have a linear category hierarchy, not a net...
		'tags' 			=> $vbphrase['tags'],
		'published'		=> $vbphrase['cms_published'],
		'publicpreview' => $vbphrase['public_break_preview'],
		'views' 		=> $vbphrase['views'],
		'comments' 		=> $vbphrase['comments'],
		'control' 		=> $vbphrase['control'],
		'displayorder' 	=> $vbphrase['display_break_order'],
	);
	$colspan = count($header);	// # of columns

	// START FORM & TABLE PRINTING
	print_form_header('admincp/cms', 'nodeaction', false, true, 'cpform', '100%', '', true, 'post', 0, false, '', true);

	// set widths
	$headerCssHelpers = array(
		'checkbox' 		=> "h-width-s",
		'title' 		=> "h-width-l",
		'contenttype' 	=> false,
		'category' 		=> "h-width-m",/*
		'tags' 			=> "h-width-m",
		'published'		=> "h-width-m",
		'publicpreview' => "h-width-m",
		'views' 		=> "h-width-m",
		'comments' 		=> "h-width-m",
		'control' 		=> "h-width-m",
		'displayorder' 	=> "h-width-m",*/
	);
	// to make fixed layout work, the first row MUST have the width info. So we have to insert
	// an empty row with just the width info before print_table_header()
	echo "<tr>";
	foreach ($headerCssHelpers AS $class)
	{
		echo "<td class=\"" . $class . "\"></td>";
	}
	echo "</tr>";
	print_table_header($vbphrase['contentlist'], $colspan, false, '', 'center', true);

	// Not sure how to add like this a row using the functions in adminfunctions.php
	echo "<tr class=\"tfoot\" >\n\t" .
		"<td align=\"center\">$actioncell1</td>\n\t" .
		"<td colspan=\"" . ($colspan - 1) . "\">" .
		"<div class=\"cms actionbar\" style=\"display: inline-block; float: left; text-align: left;\">$actioncell2\t$actioncell3</div>\n\t" .
		"<div style=\"display: inline-block; float: right; text-align: right;\">$actioncellLast</div>\n\t" .
		"<div class=\"cms filterlist\" style=\"text-align: left;\">$actioncell4</div>\n\t" .
		"</td></tr>";
	// print column header/titles
	print_cells_row($header, false, "cms thead", 1, 'top', false, false, true);

	// grab all CMS content
	$searchResults = vB::getDbAssertor()->getRows('vBAdminCP:getFullFilteredCMSContentNodeids',
		$searchParams
	);

	// authors & taglist must be built after we know which content has went through the filter.
	$nodesOnPage = array();
	$nodetags = array();
	$tags = array();
	$authors = array();
	$total = 0;
	$start = $perpage*($page - 1);
	$stop = $perpage*$page;
	foreach ($searchResults AS $node)
	{
		$nodeid = $node['nodeid'];
		if (($start <= $total) AND ($total < $stop))
		{
			$nodesOnPage[$nodeid] = $node;
		}
		if (isset($node['taglist']) AND !empty($node['taglist']))
		{
			foreach(explode(',', $node['taglist']) AS $tagtext)
			{
				if (!isset($tags[$tagtext]))
				{
					$tags[$tagtext] = $tagtext;
				}
			}
		}
		if (!isset($authors[$node['authorname']]))
		{
			$authors[$node['authorname']] = $node['userid']; // we're gonna sort by key later to make them alphabetical, so use the tag text as key.
		}
		$total++;
	}

	// Query tag table to grab tag ids for each tagtext found in node.taglist.
	$tagidToTagtext = array();
	$tagQry = vB::getDbAssertor()->getRows('vBForum:tag', array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT, 'tagtext' => $tags));
	foreach($tagQry AS $taginfo)
	{
		$tagtext = $taginfo['tagtext'];
		$tagid = $taginfo['tagid'];
		$tagidToTagtext[$tagid] = $tagtext;
		$tags[$tagtext] = $tagid;	// we're gonna sort by key later to make them alphabetical, so use the tag text as key.
	}

	// now if no errors were encountered, let's build & print the list of content
	if (!empty($nodesOnPage))
	{
		$alti = 0;
		// OUTPUT
		foreach ($nodesOnPage AS $node)
		{
			$nodeid = $node['nodeid'];
			if (isset($nodetags[$nodeid]))
			{
				$node['tag'] = explode(',', $nodetags[$nodeid]);
			}

			// prevent dupes now, so we don't have to check later in JS
			$authorname = $node['authorname'];
			if (!isset($authors[$authorname]))
			{
				$authors[$authorname] = $authorname;
			}

			// build up the tag links
			$taglinks = "<div class=\"taglist hide\" id=\"tag_" . $nodeid . "\">\n";
			$tagCount = 0;
			if (!empty($node['taglist']))
			{
				$node['taglist'] = explode(',', $node['taglist'] );
				$tagCount = count($node['taglist']);
				foreach($node['taglist'] AS $tagtext)
				{
					$tagid = $tags[$tagtext];
					$taglinks .= "<div class=\"h-margin-top-s\"><a href=\"#\" onclick=\"return js_cms_showtags('" . $tagid . "', 0);\">$tagtext</a></div> ";
				}
			}
			$taglinks .= "<div class=\"h-margin-top-s h-margin-bottom-s\"><a href=\"#\" onclick=\"return js_cms_showtags($nodeid, -1)\"" . $icon['x'] . "></a></div> ";
			$taglinks .= "</div>";
			if ($tagCount > 0)
			{
				$taglinks =
					"<a id=\"tagcount_" . $nodeid . "\" href=\"#\" onclick=\"return js_cms_showtags($nodeid, 1);\" data-tags=\"" . $node['taglist'] . "\">" .
						$tagCount .
					"</a>" . $taglinks;
			}
			else
			{
				$taglinks = '0';
			}

			$url = vB5_Route::buildURL($node['routeid'] . '|fullurl', $node, array());
			$cell = array();
			//		checkbox, title, contenttype, categories, ...
			$cell[] = "<input type=\"checkbox\" name=\"select_node[" . $nodeid . "]\" id=\"select_" . $nodeid . "\" onchange=\"js_cms_select_node(" .$nodeid.");\"/>";
			// the phrase content_link_date_by doesn't have a space before the "by", so we insert it if a valid date is
			// to be inserted. If it's unpublished (publishdate = 0), we skip the date.
			$publishdate = (($node['publishdate'] > 0) ? vbdate($dateFormat, $node['publishdate']) . ' ' : '');
			$cell[] = construct_phrase(
						$vbphrase['content_link_date_by'], $url,
						$node['htmltitle'], $publishdate,
						$node['authorname']);
			$cell[] = $contentTypes_id_class[$node['contenttypeid']]; // articles and static pages do not have distinct contenttypes.
			$cell[] = $channelInfoArray[$node['parentid']]['title'];
			//		tags, status, permissionpreview, ...
			$cell[] = $taglinks;
			$cell[] = ($node['showpublished']) ? $vbphrase['yes'] : $vbphrase['no'];
			$cell[] = ($node['public_preview']) ? $vbphrase['yes'] : $vbphrase['no'];	// todo make it an icon
			//		view, comments, control, displayorder
			$cell[] = vb_number_format(isset($node['viewcount'])?$node['viewcount']:0);
			$cell[] = vb_number_format($node['textcount']);
			$cell[] = "<span title=\"" . $vbphrase['editcontent'] . "\" id=\"edit_content_" . $nodeid . "\" data-url=\"$url\" onclick=\"js_cms_contentaction(" . $nodeid . ", 'editcontent')\"" . $icon['edit'] . "></span>" .
						"<span title=\"" . $vbphrase['deletecontent'] . "\" onclick=\"js_cms_contentaction(" . $nodeid . ", 'deletecontent')\"" . $icon['delete'] . "></span>";
			$cell[] = "<input type=\"text\" name=\"displayorder[" . $nodeid . "]\" value=\"" . $node['displayorder'] . "\" size=3 onkeydown=\"if (event.keyCode == 13) js_cms_savedisplayorder();\"/>";


			//		checkbox, title, contenttype, categories, ...
			//		tags, status, permissionpreview, ...
			//		view, comments, control, displayorder
			$nowrap = array(
				0, 0, 1, 0,
				0, 1, 1,
				1, 1, 1, 0
			);
			$alignArray = array(
				"center", "left", false, false,
				false, false, false,
				false, false, false, "center"
			);
			print_cells_row($cell, false, "cms alt" . ($alti++ % 2 + 1), 0, 'center', false, false, $nowrap, $alignArray);
		}
	}
	// todo: else block to display something for errors/no content?


	echo "<input type=\"hidden\" name=\"gobackto\" value=\"contentlist" . $filterQueryString . "\" />\n"; // used for redirecting back to this page
	echo "<input type=\"hidden\" name=\"type\" value=\"article\" />\n"; // used to selected the correct phrase in do=kill later

	// call JS to populate authorlist. Skip if they already applied the author filter.
	if (!empty($authors))
	{
		uksort($authors, 'strnatcasecmp');
		foreach ($authors AS $authorname => $userid)
		{
			echo "<input type=\"hidden\" name=\"authorlist\" value=\"" . $authorname . "\" data-id =\"" . $authorname . "\" />\n";
		}
		echo "<script type=\"text/javascript\">\n\tjs_cms_generate_xlist('author');\n</script>";
	}
	// same, but for tags this time
	if (!empty($tags))
	{
		uksort($tags, 'strnatcasecmp');
		foreach ($tags AS $tagtext => $tagid)
		{
			echo "<input type=\"hidden\" name=\"taglist\" value=\"" . $tagtext . "\" data-id =\"" . $tagid . "\" />\n";
		}
		echo "<script type=\"text/javascript\">\n\tjs_cms_generate_xlist('tag');\n</script>";
	}

	// PAGINATION
	$numResults = count($searchResults);
	$maxPage = max(ceil($total / $perpage), 1);
	$contentPerPageDropdown = array();
	foreach ( array(5, 10, 15, 20, 25, 50, 75, 100, 200) AS $key )
	{
		$contentPerPageDropdown[$key] = $key;
	}
	$actioncellPagination = $vbphrase['articles_per_page'] . "&nbsp;" .
		"<select id=\"contentperpage\" onChange=\"" .	// calculate what page the top article on the current page would be with the new perpage setting. Reload to that page with the new perpage setting
			"perpage = parseInt(document.getElementById('contentperpage').value, 10); newpage = Math.ceil((" .
				$perpage * ($page - 1). "+1)/perpage); goto = ('admincp/cms.php?do=' + '" . $filterQueryString . "').replace('&page=" .
				$page. "&perpage=" .$perpage. "', '&page=' + newpage + '&perpage=' + perpage); vBRedirect(goto);\">\n" .
			construct_select_options($contentPerPageDropdown, $perpage) . "\t</select>&nbsp;&nbsp;\n";
	$actioncellPagination .= "<div class=\"b-pagination\">";
	// FIRST PAGE
	$actioncellPagination .= construct_phrase($vbphrase['page_x_of_y'], $page, $maxPage) . "\t";
	$firstFilter = "cms.php?do=contentlist" . str_replace("&page=" . $page,"&page=1", $filterQueryString);
	$actioncellPagination .= "&nbsp;<a " .(($page == 1)?"class=\"selected\" ":"") ."href=\"admincp/$firstFilter\">" . $vbphrase['first'] . "</a>\n";
	//$actioncellPagination .= construct_button_code($vbphrase['first'], $firstFilter);

	$pagesInBetween = array();
	if ($maxPage > 2)
	{
		$padby = 4;	// 4 digits on either side.
		$start = max(2, min($page - $padby, $maxPage - (2*$padby + 1))); // cannot be less than 2. Normally start at $padby before current page up to a full range before maxpage.
		$stop = min(max($page + $padby, 9), $maxPage - 1); // cannot be more than 1 before maxpage. Normally stop at $padby after current page, unless current page is in the 1-9 range.
		$pagesInBetween = range($start, $stop);
	}
	foreach ($pagesInBetween AS $jumptopage)
	{
		$pageFilter = "cms.php?do=contentlist" . str_replace("&page=" . $page,"&page=" . $jumptopage, $filterQueryString);
		$actioncellPagination .= "<a " . (($jumptopage == $page)?"class=\"selected\" ":""). "href=\"admincp/$pageFilter\">$jumptopage</a>$spaceAfter\n";
		//$actioncellPagination .= construct_button_code($jumptopage, $pageFilter);
	}

	if ($maxPage > 1)
	{
		// LAST PAGE
		$lastFilter = "cms.php?do=contentlist" . str_replace("&page=" . $page,"&page=" . $maxPage, $filterQueryString);
		$actioncellPagination .= "&nbsp;<a " .(($page == $maxPage)?"class=\"selected\" ":"") ."href=\"admincp/$lastFilter\">" . $vbphrase['last'] . "</a>\n";
		//$actioncellPagination .= construct_button_code($vbphrase['last'], $lastFilter);
	}
	$actioncellPagination .= "</div>";


	// print save display order button again @ footer
	print_table_footer($colspan,
		$actioncellPagination . $actioncellLast,
		'',
		true,
		'',
		'cms tfoot');
	echo "<script type=\"text/javascript\" src=\"js/jquery/jquery-ui-1.11.4.custom.min.js?v=" . SIMPLE_VERSION . "\"></script>";
?>
	<script type="text/javascript">
		$('#filtervalue_date').addClass('js-datepicker');
		$('.js-datepicker').datepicker({ dateFormat: 'yy-mm-dd' });
	</script>
<?php
}

// ###################### Start Content Action #######################
if ($_REQUEST['do'] == 'nodeaction')
{
	$vbulletin->input->clean_array_gpc('r', array(
		'action' 		=>  vB_Cleaner::TYPE_STR,
		'select_node'	=> vB_Cleaner::TYPE_ARRAY_INT,
		'action_override' => vB_Cleaner::TYPE_STR,
		'displayorder'	=> vB_Cleaner::TYPE_ARRAY_INT,
		'gobackto' 		=>  vB_Cleaner::TYPE_STR,
		)
	);

	if (!empty($vbulletin->GPC['action_override']))
	{
		$action = $vbulletin->GPC['action_override'];
	}
	else
	{
		$action = $vbulletin->GPC['action'];
	}

	// for certain nodeactions, the user could've come from either contentlist or categorylist
	//nod that this was intended orginally for the "do" parameter, but quashed multiple params
	//into a string depending on the fact that print_cp_redirect2 didn't properly escape its
	//params and thus the url would end up correct even though we weren't passing the params
	//correctly (passed as array('do' => 'something&page=1&perpage=25') which is a single parameter.
	//We fixed the escaping for another issue to ensure that params containing url chars were
	//handled correctly, which broke this.  Parse the param passed to us and pass the params through
	//as a correct array.
	$gobackto = array();
	parse_str('do=' . $vbulletin->GPC['gobackto'], $gobackto);


	// is it save displayorder?
	if ($action == 'savedisplayorder')
	{
		$displayorders = array();
		foreach ($vbulletin->GPC['displayorder'] AS $nodeid => $displayorder)
		{
			// this only supports setting a positive displayorder.
			// What about unsetting, or negative displayorders?
			$displayorder = intval($displayorder);
			if ($displayorder >= 0)
			{
				$displayorders[$nodeid] = $displayorder;
			}
		}

		// get rid of any unchanged ones
		$nodes = vB::getDbAssertor()->getRows('vBForum:node',
			array(
				vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
				'nodeid' => array_keys($displayorders),
				vB_dB_Query::COLUMNS_KEY => array('nodeid', 'displayorder')
			)
		);
		if (!empty($nodes))
		{
			$sql = "UPDATE " . TABLE_PREFIX . "node \nSET displayorder = CASE \n";
			$events = array();
			foreach($nodes AS $node)
			{
				$nodeid = $node['nodeid'];
				$displayorder = $node['displayorder'];
				if ($displayorders[$nodeid] === $displayorder)
				{
					unset($displayorders[$nodeid]);
				}
				else
				{
					$sql .= "\tWHEN nodeid = ". $nodeid . " THEN " . $displayorders[$nodeid] . "\n";
					$events[] = 'nodeChg_' . $nodeid;
				}
			}
			$sql .= "ELSE displayorder \nEND  \nWHERE nodeid IN (" . implode(',', array_keys($displayorders)) . ")";
			if (!empty($displayorders))
			{
				$vbulletin->db->query_write($sql);
				vB_Cache::allCacheEvent($events);
			}
		}
		print_cp_redirect2('cms', $gobackto, 1, 'admincp');
	}

	// for everything else, there has to be selected nodes...

	if (!is_array($vbulletin->GPC['select_node']) OR empty($vbulletin->GPC['select_node']))
	{
		print_stop_message2('nothing_to_do');
	}

	// grab nodeids, make sure they're int
	$nodeids = array();
	foreach ($vbulletin->GPC['select_node'] AS $nodeid => $nothing)
	{
		$nodeid = intval($nodeid);
		if ($nodeid > 0)
		{
			$nodeids[$nodeid] = $nodeid;
		}
	}
	if (empty($nodeids))
	{
		print_stop_message2('nothing_to_do');
	}

	switch ($action)
	{
		case 'publish':
			$nodes = vB::getDbAssertor()->getRows('vBForum:node',
				array(
					vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
					'nodeid' => $nodeids,
					vB_dB_Query::COLUMNS_KEY => array('nodeid', 'publishdate')
				)
			);
			if (!empty($nodes))
			{
				foreach($nodes AS $node)
				{
					$nodeid = $node['nodeid'];
					$publishdate = $node['publishdate'];
					// only set publishdate if the article is not yet published
					// also immediately publish future-published articles
					if ($publishdate > 0 AND $publishdate <=  vB::getRequest()->getTimeNow() AND ($node['showpublished'] > 0 ))
					{
						unset($nodeids[$nodeid]);
					}
				}
			}
			vB_Api::instanceInternal('node')->publish($nodeids);
			print_cp_redirect2('cms', $gobackto, 1, 'admincp');
			break;
		case 'unpublish':
			foreach ($nodeids AS $nodeid)
			{
				// TODO: Should we check if node was never published (empty publishdate) and only unpublish those?
				vB_Api::instanceInternal('node')->setUnPublished($nodeid);
			}
			print_cp_redirect2('cms', $gobackto, 1, 'admincp');
			break;
		case 'move':
			$_REQUEST['do'] = 'move1';
			break;
		case 'delete':
			$_REQUEST['do'] = 'delete';
			break;
		default:
			print_stop_message2('nothing_to_do');
			break;
	}
}


// ###################### Start Move (Step 1) #######################
if ($_REQUEST['do'] == 'move1')
{
	// nodeids should've been constructed above in nodeaction.
	if (!isset($nodeids) OR empty($nodeids))
	{
		print_stop_message2('nothing_to_do');
	}

	$categoriesList =  getFullCategoryList();

	print_form_header('admincp/cms', 'move2');
	print_table_header($vbphrase['please_choose_a_category_for_move']);
	print_cells_row(
		array( "<select name=\"channelid\" id=\"channellist\" size=\"20\" class=\"bginput\" style=\"width:350px\">\n" .
			construct_select_options($categoriesList) . "\t</select>" ),
		false, false, 1
	);

	foreach($nodeids AS $nodeid)
	{
		construct_hidden_code("nodeids[" . $nodeid . "]", $nodeid);
	}
	construct_hidden_code("gobackto", $vbulletin->GPC['gobackto']);

	print_submit_row($vbphrase['continue'], 0, 2, $vbphrase['go_back']);
}

// ###################### Start Move (Step 2) #######################
if ($_REQUEST['do'] == 'move2')
{
	$vbulletin->input->clean_array_gpc('r', array(
		'nodeids'	=> vB_Cleaner::TYPE_ARRAY_INT,
		'channelid' 		=> vB_Cleaner::TYPE_INT,
		'gobackto' 		=>  vB_Cleaner::TYPE_STR,
		)
	);
	// nodeids should've been constructed above in nodeaction.
	if (!is_array($vbulletin->GPC['nodeids']) OR empty($vbulletin->GPC['nodeids']))
	{
		print_stop_message2('nothing_to_do');
	}
	if (empty($vbulletin->GPC['channelid']))
	{
		print_stop_message2('no_category_selected');
	}

	vB_Api::instanceInternal('node')->moveNodes($vbulletin->GPC['nodeids'], $vbulletin->GPC['channelid']);
	print_cp_redirect2('cms', array('do' => $vbulletin->GPC['gobackto']), 1, 'admincp');
}

// ###################### Start Delete (Confirmation) #######################
if ($_REQUEST['do'] == 'delete')
{
	$vbulletin->input->clean_array_gpc('r', array(
		'select_node'	=> vB_Cleaner::TYPE_ARRAY_INT,
		'nodeid' 		=> vB_Cleaner::TYPE_INT,
		'type' 			=> vB_Cleaner::TYPE_STR,	// article or category
		'gobackto' 		=>  vB_Cleaner::TYPE_STR,
		'uriencoded'	=>  vB_Cleaner::TYPE_BOOL,
		)
	);

	if ((empty($vbulletin->GPC['select_node']) OR !is_array($vbulletin->GPC['select_node']) ) AND empty($vbulletin->GPC['nodeid']))
	{
		print_stop_message2('nothing_to_do');
	}

	// grab nodeids from the array keys & make sure they're int
	// Also, exclude the root channel (can be included from categorylist)
	$nodeids = array();
	foreach ($vbulletin->GPC['select_node'] AS $nodeid => $nothing)
	{
		$nodeid = intval($nodeid);
		if ($nodeid > 0 AND $nodeid != $articleChannelId)
		{
			$nodeids['delete[' . $nodeid . ']'] = $nodeid;
		}
	}
	if (!empty($vbulletin->GPC['nodeid']) AND $vbulletin->GPC['nodeid'] != $articleChannelId)
	{
		$nodeids['delete[' .$vbulletin->GPC['nodeid'] . ']'] = $vbulletin->GPC['nodeid'];
	}

	if (empty($nodeids))
	{
		print_stop_message2('nothing_to_do');
	}

	$phrasename = 'delete_' . $vbulletin->GPC['type'] . '_confirm_' . ((count($nodeids) > 1)?'multiple':'single');
	// if the gobackto was passed in as a query param from javascript, we need to undo the javascript's encodeURIComponent()
	if (!empty($vbulletin->GPC['uriencoded']))
	{
		$vbulletin->GPC['gobackto'] = rawurldecode($vbulletin->GPC['gobackto']);
	}
	construct_hidden_code("gobackto", $vbulletin->GPC['gobackto']);

	print_confirmation($vbphrase[$phrasename], 'cms', 'kill', $nodeids);
}

// ###################### Start Delete #######################
if ($_REQUEST['do'] == 'kill')
{
	$vbulletin->input->clean_array_gpc('r', array(
		'delete'	=> vB_Cleaner::TYPE_ARRAY_INT,
		'gobackto' 		=>  vB_Cleaner::TYPE_STR,
		)
	);

	if (empty($vbulletin->GPC['delete']) OR !is_array($vbulletin->GPC['delete']))
	{
		print_stop_message2('nothing_to_do');
	}

	// grab nodeids from the array keys & make sure they're int
	$nodeids = array();
	foreach ($vbulletin->GPC['delete'] AS $nodeid)
	{
		$nodeid = intval($nodeid);
		if ($nodeid > 0)
		{
			$nodeids['delete[' . $nodeid . ']'] = $nodeid;
		}
	}
	if (!empty($vbulletin->GPC['nodeid']))
	{
		$nodeids['delete[' .$vbulletin->GPC['nodeid'] . ']'] = $vbulletin->GPC['nodeid'];
	}

	vB_Api::instanceInternal('node')->deleteNodes($nodeids);
	if (empty($vbulletin->GPC['gobackto']))
	{
		$vbulletin->GPC['gobackto'] = 'contentlist'; // by default, go to the content listing page if this isn't set.
	}
	print_cp_redirect2('cms', array('do' => $vbulletin->GPC['gobackto']), 1, 'admincp');
}




// ###################### Start category list #######################
if ($_REQUEST['do'] == 'categorylist')
{
	?>
	<script type="text/javascript">
	// handles single-category action (edit, add, delete)
	function js_cms_categoryaction(nodeid)
	{
		if (nodeid == 'addcategory')
		{
			var action = 'addcategory';
		}
		else
		{
			var selectElement = document.getElementById("singlecategory_" + nodeid);	// select element
			var action = selectElement.options[selectElement.selectedIndex].value;	// selected action to perform
		}

		var page = "admincp/cms.php?";
		switch (action)
		{
			case 'editcategory':
				page += "do=editcategory&nodeid=" + nodeid + "&type=category&gobackto=categorylist";
				break;
			case 'addchildcategory':
				page += "do=addcategory&parentid=" + nodeid;
				break;
			case 'addcategory':
				page += "do=addcategory";
				break;
			case 'deletecategory':
				page += "do=delete&nodeid=" + nodeid + "&type=category&gobackto=categorylist";
				break;
			default:
				return;
				break;
		}

		vBRedirect(page);
	}
	</script>
	<?php

	$options_actionlist = array(
		'default' => $vbphrase['select_an_action'],
		'publish' => $vbphrase['publish'],
		'unpublish' => $vbphrase['unpublish'],
		'delete' => $vbphrase['delete'],
	);

	// build up the 'action' cells that will go above the column titles
	$actioncell1 = "<input type=\"checkbox\" id=\"select_all\" onchange=\"js_cms_select_node('all');\">";
	$actioncell2 =
		"<select name=\"action\" id=\"action\" class=\"bginput\">\n" . construct_select_options($options_actionlist) . "\t</select>" .
			construct_button_code($vbphrase['apply'], "submit", false, '', false);

	$actioncellLast = construct_button_code($vbphrase['savedisplayorder'], "js_cms_savedisplayorder()", false, '', true);
	$actioncellLast .= construct_button_code($vbphrase['plus_category'], "js_cms_categoryaction('addcategory')", false, '', true);
	$header = array(
		'',
		$vbphrase['cms_category_name'],
		$vbphrase['cms_published'],
		//$vbphrase['contentcolumns'],
		//$vbphrase['defaultdisplayorder'],
		$vbphrase['articles'],
		//$vbphrase['views'],
		$vbphrase['control'],
		$vbphrase['displayorder'],
	);
	$colspan = count($header);	// # of columns

	// start form & table printing
	print_form_header('admincp/cms', 'nodeaction');
	print_table_header($vbphrase['categorylist'], $colspan);
	// action buttons before table header/column titles
	echo "<tr class=\"tfoot\" style=\"white-space:nowrap\">\n\t" .
		"<td align=\"center\">$actioncell1</td>\n\t" .
		"<td colspan=\"" . ($colspan - 1) . "\" align=\"left\">" .
		"$actioncell2<div style=\"float: right;\">$actioncellLast</div>" .
		"</td></tr>\n";

	// print column titles
	print_cells_row($header, true, false, -1, 'top', false, false, true);

	// fetch all categories
	$channelInfoArray = array();
	$categoriesList = getFullCategoryList($channelInfoArray, 1, "- - ", "");

	/* REMOVING VIEW COUNTS FROM CATEGORY LIST FOR PERFORMANCE, PER SPRINT REVIEW 2013-10-10
	// grabbing nodeviews is going to be a bit tricky. We don't track channel views, so we have to find all children's views & sum them.
	// grab all cms content nodes
	$searchJSON = array(
		'channel' => $articleChannelId,
		'starter_only' => 1,
		'view' => 'topic',
		'sort' => array('displayorder' => 'asc'),
		'ignore_cache' => 1,	// maybe we should rely on potentially cached search from content list, but what if nodes were deleted?
	);
	$searchResults = vB_Api::instanceInternal('search')->getInitialResults($searchJSON, $perpage, $pagenumber, false);
	if (!isset($searchResults['errors']) AND !empty($searchResults['results']))
	{
		$nodeids = array_keys($searchResults['results']);

		// insert nodeviews for immediate parent.
		$nodeviewsQry = vB::getDbAssertor()->getRows('vBForum:nodeview', array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT, 'nodeid' => $nodeids));
		foreach($nodeviewsQry AS $nodeview)
		{
			$nodeid = $nodeview['nodeid'];
			$channelid = $searchResults['results'][$nodeid]['parentid'];
			$channelInfoArray[$channelid]['viewcount'] = (isset($channelInfoArray[$channelid]['viewcount'])?$channelInfoArray[$channelid]['viewcount'] +  $nodeview['count']:$nodeview['count']);
		}
	}
	*/

	$options_singlenode_actionlist = array(
		'editcategory' => $vbphrase['edit_cms_category'],
		'addchildcategory' => $vbphrase['add_cms_child_category'],
		'deletecategory' => $vbphrase['delete_cms_category'],
	);
	$alt_i = 1;
	foreach ($categoriesList AS $channelid => $tabbedtitle)
	{
		$channel = $channelInfoArray[$channelid];
		$cell = array();
		$class = ($alt_i++%2)?'alt1':'alt2';
		echo "<tr class=$class>";
		//		checkbox, category name, status,
		echo "<td align=\"center\"><input type=\"checkbox\" name=\"select_node[" . $channelid . "]\" id=\"select_" . $channelid . "\" onchange=\"js_cms_select_node(".$channelid.");\"/></td>";
		echo "<td align=\"left\">$tabbedtitle</td>";
		echo "<td align=\"center\">" . ($channel['showpublished'] ? $vbphrase['yes'] : $vbphrase['no']) . "</td>";
		//  contentcolumns, defaultdisplayorder (SKIPPED - not yet implemented)
		// 		posts, view, control
		echo "<td align=\"center\">" . vb_number_format($channel['textcount']) . "</td>"; // or should it be total count to include children from all depths?
		//echo "<td align=\"center\">" . vb_number_format((isset($channel['viewcount'])?$channel['viewcount']:0)) . "</td>";
		echo "<td align=\"center\" style=\"white-space:nowrap\">" .
			"<select id=\"singlecategory_" . $channelid . "\" class=\"bginput\" onchange=\"js_cms_categoryaction(" . $channelid . ");\">\n" .
				construct_select_options($options_singlenode_actionlist) .
				"\t</select>" .
				construct_button_code(
					$vbphrase['go'],
					"js_cms_categoryaction(" . $channelid . ")",
					false, '', true
				) .
			"</td>";
		// 		displayorder
		echo "<td align=\"center\" style=\"white-space:nowrap\">" .
			"<input type=\"text\" name=\"displayorder[" . $channelid . "]\" value=\"" . $channel['displayorder'] . "\" size=4 onkeydown=\"if (event.keyCode == 13) js_cms_savedisplayorder();\"/>" .
			"</td>";
	}

	echo "<input type=\"hidden\" name=\"gobackto\" value=\"categorylist\" />\n"; // used for redirecting back to this page
	echo "<input type=\"hidden\" name=\"type\" value=\"category\" />\n"; // used to selected the correct phrase in do=kill later

	// print save display order button again @ footer
	// hack to make the top & bottom buttons aligned
	echo "<tr class=\"tfoot\" style=\"white-space:nowrap\">\n\t" .
		"<td colspan=\"" . ($colspan) . "\"><div style=\"float: right;\">$actioncellLast</div></td></tr>\n";

	print_table_footer();
}


// ###################### Start add category (add category page) #######################
if ($_REQUEST['do'] == 'addcategory')
{
	$vbulletin->input->clean_array_gpc('r', array(
		'parentid'			=> vB_Cleaner::TYPE_UINT,
	));

	if (empty($vbulletin->GPC['parentid']))
	{
		$parentid= vB_Api::instanceInternal('node')->fetchArticleChannel();
	}
	else
	{
		$parentid = $vbulletin->GPC['parentid'];
	}

	// fetch all categories
	$categoriesList =  getFullCategoryList();

	// start form & table printing
	print_form_header('admincp/cms', 'addcategory2');
	print_table_header($vbphrase['add_new_cms_category']);
	print_input_row($vbphrase['cms_category_title'], 'channel[title]', '');
	print_textarea_row($vbphrase['cms_category_description'], 'channel[description]', '');
	print_select_row($vbphrase['cms_published'], 'channel[publish]', array(1 => $vbphrase['cms_published'], 0 => $vbphrase['unpublished']), 0);
	print_select_row($vbphrase['cms_parent_category'], 'channel[parentid]', $categoriesList, $parentid);
	print_input_row($vbphrase['displayorder'], 'channel[displayorder]', 1);

	$actioncell1 = construct_button_code($vbphrase['save'], "submit", false, '', false);
	$actioncellLast = construct_button_code($vbphrase['reset'], "reset", false, '', false);
	// print footer buttons
	print_table_footer(2,
		$actioncell1 . "\t" . $actioncellLast,
		'',
		true);
}

// ###################### Start add category 2 (create channel node & return to categorylist) #######################
if ($_REQUEST['do'] == 'addcategory2')
{
	$vbulletin->input->clean_array_gpc('r', array(
		'channel'	=> vB_Cleaner::TYPE_NOCLEAN,
		)
	);

	if ( !is_array($vbulletin->GPC['channel'])
		OR empty($vbulletin->GPC['channel']['title']) OR empty($vbulletin->GPC['channel']['parentid']) OR !isset($vbulletin->GPC['channel']['publish'])
	)
	{
		print_stop_message2('nothing_to_do');
	}

	$string = vB::getString();
	$data['title'] = $string->htmlentities($vbulletin->GPC['channel']['title']);	// convert html entities in the title to preserve them.
	$data['description'] = $vbulletin->GPC['channel']['description'];
	$data['parentid'] = intval($vbulletin->GPC['channel']['parentid']);
	$data['publishdate'] = (empty($vbulletin->GPC['channel']['publish'])? 0 : (vB::getRequest()->getTimeNow() - 1));
	$data['displayorder'] = intval($vbulletin->GPC['channel']['displayorder']);

	vB_Library::instance('article')->createArticleCategory($data);
	print_cp_redirect2('cms', array('do' => "categorylist"), 1, 'admincp');
}

// ###################### Start edit category #######################
if ($_REQUEST['do'] == 'editcategory')
{
	$vbulletin->input->clean_array_gpc('r', array(
		'nodeid'			=> vB_Cleaner::TYPE_UINT,
	));

	$channelid = $vbulletin->GPC['nodeid'];
	// fetch all categories
	$channelInfoArray = array();
	$categoriesList =  getFullCategoryList($channelInfoArray);
	$channel = $channelInfoArray[$channelid];

	// start form & table printing
	print_form_header('admincp/cms', 'savecategory');
	print_table_header($vbphrase['edit_cms_category']);
	print_input_row($vbphrase['cms_category_title'], 'channel[title]', html_entity_decode($channel['title']));
	print_textarea_row($vbphrase['cms_category_description'], 'channel[description]', $channel['description']);
	print_select_row($vbphrase['cms_published'], 'channel[publish]', array(1 => $vbphrase['cms_published'], 0 => $vbphrase['unpublished']), $channel['showpublished']);
	if ($channelid != $articleChannelId)
	{
		print_select_row($vbphrase['cms_parent_category'], 'channel[parentid]', $categoriesList, $channel['parentid']);
	}
	else
	{
		print_select_row($vbphrase['cms_parent_category'], 'channel[parentid]', array($vbphrase['none']));
	}
	print_input_row($vbphrase['displayorder'], 'channel[displayorder]', intval($channel['displayorder']));

	construct_hidden_code('channelid', $channelid);
	construct_hidden_code('previous[parentid]', $channel['parentid']);
	construct_hidden_code('previous[title]', $channel['title']);
	construct_hidden_code('previous[description]', $channel['description']);
	construct_hidden_code('previous[showpublished]', $channel['showpublished']);
	construct_hidden_code('previous[displayorder]', $channel['displayorder']);

	$actioncell1 = construct_button_code($vbphrase['save'], "submit", false, '', false);
	$actioncellLast = construct_button_code($vbphrase['reset'], "reset", false, '', false);
	// print footer buttons
	print_table_footer(2,
		$actioncell1 . "\t" . $actioncellLast,
		'',
		true);
}

// ###################### Start save category #######################
if ($_REQUEST['do'] == 'savecategory')
{
	$vbulletin->input->clean_array_gpc('r', array(
		'channel'	=> vB_Cleaner::TYPE_NOCLEAN,
		'channelid'	=> vB_Cleaner::TYPE_INT,
		'previous'	=> vB_Cleaner::TYPE_NOCLEAN,
		)
	);

	$string = vB::getString();

	$channelid = $vbulletin->GPC['channelid'];
	// convert html entities in the title to preserve them.
	$data['title'] = $string->htmlentities($vbulletin->GPC['channel']['title']);
	$data['description'] = $vbulletin->GPC['channel']['description'];	// should there be any html entities?
	$data['parentid'] = intval($vbulletin->GPC['channel']['parentid']);
	$data['showpublished'] = intval($vbulletin->GPC['channel']['publish']);
	$data['displayorder'] = intval($vbulletin->GPC['channel']['displayorder']);
	$previousData['title'] = $vbulletin->GPC['previous']['title'];
	$previousData['description'] = $vbulletin->GPC['previous']['description'];
	$previousData['parentid'] = intval($vbulletin->GPC['previous']['parentid']);
	$previousData['showpublished'] = intval($vbulletin->GPC['previous']['showpublished']);
	$previousData['displayorder'] = $vbulletin->GPC['previous']['displayorder'];


	// check if title update is necessary
	if ($data['title'] == $previousData['title'])
	{
		unset($data['title']);	// no change required
	}

	// check if description update is necessary
	if ($data['description'] == $previousData['description'])
	{
		unset($data['description']);	// no change required
	}

	// translate showpublished into publishdate
	if ($data['showpublished'])
	{
		$data['publishdate'] = vB::getRequest()->getTimeNow() - 1;
		$data['unpublishdate'] = 0;
	}
	else
	{
		$data['publishdate'] = 0;
	}
	if ($data['showpublished'] == $previousData['showpublished'])
	{
		unset($data['publishdate']);	// no change required
	}
	unset($data['showpublished']);

	// check if displayorder update is necessary
	if ($data['displayorder'] === $previousData['displayorder'])
	{
		unset($data['displayorder']);	// no change required
	}

	// if the desired parent is a child, show an error / go back page
	$closureQry = vB::getDbAssertor()->getRow('vBForum:closure', array(
		vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT,
		'parent' =>$channelid,
		'child' => $data['parentid']
	));

	// if any records exist, that means the parent is either the channel itself or its child.
	if (!empty($closureQry))
	{
		print_stop_message2('invalid_parent_category');
	}

	// if the parentid is the same, OR the current channel is the top level channel, just unset the parentid.
	if (($data['parentid'] == $previousData['parentid']) OR ($channelid == $articleChannelId))
	{
		unset($data['parentid']);
	}

	// update the channel
	if (!empty($data))
	{
		vB_Api::instanceInternal('content_channel')->update($channelid, $data);
	}

	print_cp_redirect2('cms', array('do' => 'categorylist'), 1, 'admincp');
}

// ###################### Start tag list #######################
if ($_REQUEST['do'] == 'taglist')
{
	$channelInfoArray = array();
	$categoriesList = getFullCategoryList($channelInfoArray);
	// grab all CMS content
	$searchResults = vB::getDbAssertor()->getRows('vBAdminCP:getFullFilteredCMSContentNodeids',
		array('channelids' => array_keys($channelInfoArray))
	);

	// the posts count must be populated
	$tags = array();
	foreach ($searchResults AS $node)
	{
		if (isset($node['taglist']) AND !empty($node['taglist']))
		{
			foreach(explode(',', $node['taglist']) AS $tagtext)
			{
				if (!isset($tags[$tagtext]['posts']))
				{
					$tags[$tagtext]['posts'] = 1;
				}
				else
				{
					$tags[$tagtext]['posts']++;
				}
			}
		}
	}
	uksort($tags, 'strnatcasecmp'); // sort alphabetically by tagtext

	// Query tag table to grab tag ids for each tagtext found in node.taglist
	$tagQry = vB::getDbAssertor()->getRows('vBForum:tag', array(vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_SELECT, 'tagtext' =>array_keys($tags)));
	foreach($tagQry AS $taginfo)
	{
		$tagtext = $taginfo['tagtext'];
		$tagid = $taginfo['tagid'];
		$tags[$tagtext]['tagid'] = $tagid;	// we're gonna sort by key later to make them alphabetical, so use the tag text as key.
	}

	$header = array(
		$vbphrase['tagname'],
		$vbphrase['articles'],
	);
	$colspan = count($header);	// # of columns

	// START FORM & TABLE PRINTING
	print_form_header('admincp/cms');
	print_table_header($vbphrase['taglist'], $colspan);
	print_cells_row($header, true, false, 1, 'top', false, false, true);

	foreach ($tags AS $tagtext => $tag)
	{
		$cell = array();
		$cell[] = $tagtext;
		$cell[] = "<a id=\"tagcount_" . $nodeid . "\" href=\"admincp/cms.php?do=contentlist&tag=".$tag['tagid']."\">" .
					$tag['posts'] .
				"</a>";

		print_cells_row($cell);
	}

	print_table_footer();
}

print_cp_footer();

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
