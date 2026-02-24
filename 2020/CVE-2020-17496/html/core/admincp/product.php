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
define('CVS_REVISION', '$RCSfile$ - $Revision: 102599 $');

// #################### PRE-CACHE TEMPLATES AND DATA ######################
global $phrasegroups, $specialtemplates, $vbphrase, $vbulletin;
$phrasegroups = array('hooks');
$specialtemplates = array();

// ########################## REQUIRE BACK-END ############################
require_once(dirname(__FILE__) . '/global.php');
require_once(DIR . '/includes/adminfunctions_product.php');
require_once(DIR . '/includes/adminfunctions_template.php');

$assertor = vB::getDbAssertor();
$prod_lib = vB_Library::instance('product');

// ######################## CHECK ADMIN PERMISSIONS #######################
// don't allow demo version or admin with no permission to administer products
if (is_demo_mode() OR !can_administer('canadminproducts'))
{
	print_cp_no_permission();
}

$vbulletin->input->clean_array_gpc('r', array(
	'productid' => vB_Cleaner::TYPE_STR
));

// ############################# LOG ACTION ###############################
log_admin_action(iif($vbulletin->GPC['productid'] != 0, 'Product id = ' . $vbulletin->GPC['productid']));

// #############################################################################
// ########################### START MAIN SCRIPT ###############################
// #############################################################################

if ($_REQUEST['do'] != 'download' AND $_REQUEST['do'] != 'productexport')
{
	$extraheaders = '';
	if (in_array($_REQUEST['do'], array('productadd', 'productedit')))
	{
		$extraheaders = '
			<link rel="stylesheet" href="core/clientscript/codemirror/lib/codemirror.css?v=' . SIMPLE_VERSION . '">
			<link rel="stylesheet" href="core/clientscript/codemirror/addon/hint/show-hint.css?v=' . SIMPLE_VERSION . '">';
	}

	print_cp_header($vbphrase['hook_products_system'], '', $extraheaders);
}

if (empty($_REQUEST['do']))
{
	$_REQUEST['do'] = 'product';
}

if (in_array($_REQUEST['do'], array('product', 'productadd', 'productedit', 'extensions')))
{
	if (!$vbulletin->options['enablehooks'] OR defined('DISABLE_HOOKS'))
	{
		$hooksEnabled = false;

		if (!$vbulletin->options['enablehooks'])
		{
			print_warning_table($vbphrase['hooks_disabled_options']);
		}
		else
		{
			print_warning_table($vbphrase['hooks_disable_config']);
		}
	}
	else
	{
		$hooksEnabled = true;
	}
}

// #############################################################################
// ####################          Products                   ####################
// #############################################################################

if ($_REQUEST['do'] == 'product')
{
	?>
	<script type="text/javascript">
	function js_page_jump(i, sid)
	{
		var sel = fetch_object("prodsel" + i);
		var act = sel.options[sel.selectedIndex].value;
		if (act != '')
		{
			switch (act)
			{
				case 'productdisable': page = "admincp/product.php?do=productdisable&productid="; break;
				case 'productenable': page = "admincp/product.php?do=productenable&productid="; break;
				case 'productedit': page = "admincp/product.php?do=productedit&productid="; break;
				case 'productversioncheck': page = "admincp/product.php?do=productversioncheck&productid="; break;
				case 'productexport':
					document.cpform.productid.value = sid;
					document.cpform.submit();
					return;
				case 'productdelete': page = "admincp/product.php?do=productdelete&productid="; break;
				default: return;
			}
			document.cpform.reset();
			jumptopage = page + sid + "&s=<?php echo vB::getCurrentSession()->get('sessionhash'); ?>";
			vBRedirect(jumptopage);
		}
		else
		{
			alert('<?php echo addslashes_js($vbphrase['invalid_action_specified_gcpglobal']); ?>');
		}
	}
	</script>
	<?php

	print_form_header('admincp/product', 'productexport', false, true, 'cpform', '90%', 'download');
	construct_hidden_code('productid', '');

	print_table_header($vbphrase['installed_products'], 4);
	print_cells_row(
		array(
			$vbphrase['title'],
			$vbphrase['version_products'],
			$vbphrase['description_gcpglobal'],
			'<div style="margin-right: 10px" align="' . vB_Template_Runtime::fetchStyleVar('right') . '">' . $vbphrase['controls'] . '</div>',
		),
		true,
		'',
		-2
	);

	print_cells_row(array('<strong>vBulletin</strong>', $vbulletin->options['templateversion'], '', ''), false, '', -2);

	// used for <select> id attribute
	$i = 0;

	$products = $assertor->getRows('product', array(), 'title');
	// Also grab options associated with each product
	$productIds = array();
	foreach ($products AS $product)
	{
		$productIds[$product['productid']] = $product['productid'];
	}
	// 'vbulletin' is not stored in the product table ATM, but just in case the product model changes in the future,
	// pre-emptively unset the default product as that'll return too many options and not be useful.
	unset($productIds['vbulletin']);
	$productOptions = array();
	$productOptionsRows = $assertor->getRows('setting', array('product' => $productIds), 'product');
	foreach ($productOptionsRows AS $__row)
	{
		$__product = $__row['product'];
		$__varname = $__row['varname'];
		if (!isset($productOptions[$__product]))
		{
			$productOptions[$__product] = array();
		}
		$productOptions[$__product][$__varname] = $__row;
	}

	foreach ($products AS $product)
	{
		$__pid = $product['productid'];
		$title = htmlspecialchars_uni($product['title']);
		if (!$product['active'])
		{
			$title = "<strike>$title</strike>";
		}

		if ($product['url'])
		{
			$title = '<a href="' . htmlspecialchars_uni($product['url']) . "\" target=\"_blank\">$title</a>";
		}

		$options = array('productedit' => $vbphrase['edit']);
		if ($product['versioncheckurl'])
		{
			$options['productversioncheck'] = $vbphrase['check_version'];
		}
		if ($product['active'])
		{
			$options['productdisable'] = $vbphrase['disable'];
		}
		else
		{
			$options['productenable'] = $vbphrase['enable'];
		}
		$options['productexport'] = $vbphrase['export'];
		$options['productdelete'] = $vbphrase['uninstall'];

		$safeid = preg_replace('#[^a-z0-9_]#', '', $__pid);
		if (file_exists(DIR . '/includes/version_' . $safeid . '.php'))
		{
			include_once(DIR . '/includes/version_' . $safeid . '.php');
		}
		$define_name = 'FILE_VERSION_' . strtoupper($safeid);
		if (defined($define_name) AND constant($define_name) !== '')
		{
			$product['version'] = constant($define_name);
		}

		$showOptMax = 2;
		$__productOptionsText = "";
		$__productOptionsShowMoreArray = array();
		if (!empty($productOptions[$__pid]))
		{
			$__optCount = 0;
			foreach ($productOptions[$__pid] AS $__opt)
			{
				$__optCount++;
				if ($showOptMax >= $__optCount)
				{
					$__productOptionsText .= '<li class="product-options__list-item">' . get_setting_link($__opt) . '</li>';
				}
				else
				{
					$__productOptionsShowMoreArray[] = '<li class="product-options__list-item">' . get_setting_link($__opt) . '</li>';
				}
			}
		}
		if (!empty($__productOptionsShowMoreArray))
		{
			$__moreOptCount = count($__productOptionsShowMoreArray);
			if ($__moreOptCount > 1)
			{
				$__productOptionsText .= get_collapser(
					implode('', $__productOptionsShowMoreArray),
					sprintf($vbphrase['show_x_more_options'], $__moreOptCount),
					$vbphrase['hide_additional_options']
				);
			}
			else
			{
				$__productOptionsText .= $__productOptionsShowMoreArray[0];
			}
		}
		if (!empty($__productOptionsText))
		{
			$__productOptionsText = "
				<style>
				.product-options {
					border: 1px solid #53575E;
					margin-top: 5px;
				}
				.product-options__label {
					margin: 5px 15px;
					font-weight: bold;
				}
				.product-options__list {
					list-style: none;
					margin: 0;
					padding: 0;
				}
				.product-options__list-item {
					margin-" . vB_Template_Runtime::fetchStyleVar('left') . ": 15px;
				}
				.product-options__list-item:last-child {
					margin-bottom: 8px;
				}
				.product-options__list .collapse {
					margin: 5px 0 0;
				}
				.product-options__list .collapse-label {
					/* stylevar not needed since left and right values are equal */
					padding-left: 15px;
					padding-right: 15px;
				}
				.product-options__list .collapse-content .product-options__list-item:last-child {
					margin-bottom: 3px;
				}
				</style>
				<div class=\"product-options\">
					<div class=\"product-options__label\">{$vbphrase['related_options']}:</div>
					<ul class=\"product-options__list\">
						{$__productOptionsText}
					</ul>
				</div>
			";
		}

		$i++;
		print_cells_row(array(
			$title,
			htmlspecialchars_uni($product['version']),
			htmlspecialchars_uni($product['description']) . $__productOptionsText,
			"<div align=\"" . vB_Template_Runtime::fetchStyleVar('right') . "\" style=\"white-space:nowrap\">
				<select name=\"s$product[productid]\" id=\"prodsel$i\" onchange=\"js_page_jump($i, '$product[productid]')\" class=\"bginput\">
					" . construct_select_options($options) . "
				</select>&nbsp;<input type=\"button\" class=\"button\" value=\"" . $vbphrase['go'] . "\" onclick=\"js_page_jump($i, '$product[productid]');\" />
			</div>"
		), false, '', -2);
	}

	print_table_footer();
	echo '<p align="center">' . construct_link_code($vbphrase['add_import_product'], "product.php?" . vB::getCurrentSession()->get('sessionurl') . "do=productadd") . '</p>';
}

// #############################################################################

if ($_REQUEST['do'] == 'productversioncheck')
{
	$product = $assertor->getRow('product', array('productid' => $vbulletin->GPC['productid']));

	if (!$product OR empty($product['versioncheckurl']))
	{
		print_stop_message2('invalid_product_specified');
	}

	$version_url = @vB_String::parseUrl($product['versioncheckurl']);
	if (!$version_url)
	{
		print_stop_message2('invalid_version_check_url_specified');
	}

	if (!$version_url['port'])
	{
		$version_url['port'] = 80;
	}
	if (!$version_url['path'])
	{
		$version_url['path'] = '/';
	}

	$fp = @fsockopen($version_url['host'], ($version_url['port'] ? $version_url['port'] : 80), $errno, $errstr, 10);
	if (!$fp)
	{
		print_stop_message2(array(
			'version_check_connect_failed_host_x_error_y',
			htmlspecialchars_uni($version_url['host']),
			htmlspecialchars_uni($errstr)
		));
	}

	$send_headers = "POST $version_url[path] HTTP/1.0\r\n";
	$send_headers .= "Host: $version_url[host]\r\n";
	$send_headers .= "User-Agent: vBulletin Product Version Check\r\n";
	if ($version_url['query'])
	{
		$send_headers .= "Content-Type: application/x-www-form-urlencoded\r\n";
	}
	$send_headers .= "Content-Length: " . strlen($version_url['query']) . "\r\n";
	$send_headers .= "\r\n";

	fwrite($fp, $send_headers . $version_url['query']);

	$full_result = '';
	while (!feof($fp))
	{
		$result = fgets($fp, 1024);
		$full_result .= $result;
	}

	fclose($fp);

	preg_match('#^(.*)\r\n\r\n(.*)$#sU', $full_result, $matches);
	$headers = trim($matches[1]);
	$body = trim($matches[2]);

	if (preg_match('#<version productid="' . preg_quote($product['productid'], '#') . '">(.+)</version>#iU', $body, $matches))
	{
		$latest_version = $matches[1];
	}
	else if (preg_match('#<version>(.+)</version>#iU', $body, $matches))
	{
		$latest_version = $matches[1];
	}
	else
	{
		print_stop_message2('version_check_failed_not_found');
	}

	// see if we have a patch or something
	$safeid = preg_replace('#[^a-z0-9_]#', '', $product['productid']);
	if (file_exists(DIR . '/includes/version_' . $safeid . '.php'))
	{
		include_once(DIR . '/includes/version_' . $safeid . '.php');
	}
	$define_name = 'FILE_VERSION_' . strtoupper($safeid);
	if (defined($define_name) AND constant($define_name) !== '')
	{
		$product['version'] = constant($define_name);
	}

	print_form_header('admincp/', '');

	if (is_newer_version($latest_version, $product['version']))
	{
		print_table_header(construct_phrase($vbphrase['product_x_out_of_date'], htmlspecialchars_uni($product['title'])));
		print_label_row($vbphrase['installed_version'], htmlspecialchars_uni($product['version']));
		print_label_row($vbphrase['latest_version'], htmlspecialchars_uni($latest_version));
		if ($product['url'])
		{
			print_description_row(
				'<a href="admincp/' . htmlspecialchars_uni($product['url']) . '" target="_blank">' . $vbphrase['click_here_for_more_info'] . '</a>',
				false,
				2,
				'',
				'center'
			);
		}
	}
	else
	{
		print_table_header(construct_phrase($vbphrase['product_x_up_to_date'], htmlspecialchars_uni($product['title'])));
		print_label_row($vbphrase['installed_version'], htmlspecialchars_uni($product['version']));
		print_label_row($vbphrase['latest_version'], htmlspecialchars_uni($latest_version));
	}

	print_table_footer();
}

// #############################################################################

if ($_REQUEST['do'] == 'productdisable' OR $_REQUEST['do'] == 'productenable')
{
	$vbulletin->input->clean_array_gpc('r', array(
		'confirmswitch' => vB_Cleaner::TYPE_BOOL
	));

	$product = $assertor->getRow('product', array('productid' => $vbulletin->GPC['productid']));

	if (!$product)
	{
		print_stop_message2('invalid_product_specified');
	}

	$product_list = fetch_product_list(true);

	$dependency_result = $assertor->getRows('productdependency', array(
		vB_dB_Query::CONDITIONS_KEY => array(
			array('field' => 'dependencytype', 'value' => 'product', vB_dB_Query::OPERATOR_KEY => vB_dB_Query::OPERATOR_EQ),
			array('field' => 'parentproductid', 'value' => '', vB_dB_Query::OPERATOR_KEY => vB_dB_Query::OPERATOR_NE)
		)
	));

	if ($_REQUEST['do'] == 'productdisable')
	{
		$newstate = 0;

		// disabling a product -- disable all children

		// list with parents as keys, good for traversing downward
		$dependency_list = array();
		foreach ($dependency_result AS $dependency)
		{
			$dependency_list["$dependency[parentproductid]"][] = $dependency['productid'];
		}

		$children = fetch_product_dependencies($vbulletin->GPC['productid'], $dependency_list);

		$need_switch = array();
		foreach ($children AS $childproductid)
		{
			$childproduct = $product_list["$childproductid"];
			if ($childproduct AND $childproduct['active'] == 1)
			{
				// product exists and is enabled -- needs to be disabled
				$need_switch["$childproductid"] = $childproduct['title'];
			}
		}

		$phrase_name = 'additional_products_disable_x_y';
	}
	else
	{
		$newstate = 1;

		// enabling a product -- enable all parents

		// list with children as keys, good for traversing upward
		$dependency_list = array();
		foreach ($dependency_result AS $dependency)
		{
			$dependency_list["$dependency[productid]"][] = $dependency['parentproductid'];
		}

		$parents = fetch_product_dependencies($vbulletin->GPC['productid'], $dependency_list);

		$need_switch = array();
		foreach ($parents AS $parentproductid)
		{
			$parentproduct = $product_list["$parentproductid"];
			if ($parentproduct AND $childproduct['active'] == 0)
			{
				// product exists and is disabled -- needs to be enabled
				$need_switch["$parentproductid"] = $parentproduct['title'];
			}
		}

		$phrase_name = 'additional_products_enable_x_y';
	}

	if (!$vbulletin->GPC['confirmswitch'] AND count($need_switch) > 0)
	{
		// to do this, we need to update the status of some additional products,
		// so make sure the user knows what's going on
		$need_switch_str = '<li>' . implode('</li><li>', $need_switch) . '</li>';
		print_stop_message2(array(
			$phrase_name,
			htmlspecialchars_uni($product['title']),
			$need_switch_str,
			'product.php?' . vB::getCurrentSession()->get('sessionurl') .
				'do=' . urlencode($_REQUEST['do']) .
				'&amp;productid=' . urlencode($vbulletin->GPC['productid']) .
				'&amp;confirmswitch=1'
		));
	}

	// $need_switch is already escaped
	$product_update = array_keys($need_switch);
	$product_update[] = $vbulletin->GPC['productid'];

	// Do the product table
	$assertor->assertQuery('product', array(
		vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_UPDATE,
		vB_dB_Query::CONDITIONS_KEY => array(
			array('field' => 'productid', 'value' => $product_update, 'operator' =>  vB_dB_Query::OPERATOR_EQ),
		),
	   'active' => $newstate
	));

	// build bitfields to remove/add this products bitfields
	require_once(DIR . '/includes/class_bitfield_builder.php');
	vB_Bitfield_Builder::save();

	vB_Cache::instance()->purge('vb_types.types');

	// this could enable a cron entry, so we need to rebuild that as well
	require_once(DIR . '/includes/functions_cron.php');
	build_cron_next_run();

	$prod_lib->buildProductDatastore();

	// reload blocks and block types
	if ($_REQUEST['do'] == 'productdisable')
	{
		print_stop_message2('product_disabled_successfully', 'product', array('do' => 'product'));
	}
	else
	{
		build_all_styles();
		print_stop_message2('product_enabled_successfully', 'product', array('do' => 'product'));
	}
}

// #############################################################################

if ($_REQUEST['do'] == 'productadd' OR $_REQUEST['do'] == 'productedit')
{
	if ($vbulletin->GPC['productid'])
	{
		$product = $assertor->getRow('product', array('productid' => $vbulletin->GPC['productid']));
	}
	else
	{
		$product = array();
	}

	if (!$product)
	{
		?>
		<script type="text/javascript">
		<!--
		function js_confirm_upload(tform, filefield)
		{
			if (filefield.value == "")
			{
				return confirm("<?php echo construct_phrase($vbphrase['you_did_not_specify_a_file_to_upload'], '" + tform.serverfile.value + "'); ?>");
			}
			return true;
		}
		//-->
		</script>
		<?php

		print_form_header('admincp/product', 'productimport', 1, 1, 'uploadform" onsubmit="return js_confirm_upload(this, this.productfile);');
		print_table_header($vbphrase['import_product']);
		print_upload_row($vbphrase['upload_xml_file'], 'productfile', 999999999);
		print_input_row($vbphrase['import_xml_file'], 'serverfile', './includes/xml/product.xml');
		print_yes_no_row($vbphrase['allow_overwrite_upgrade_product'], 'allowoverwrite', 0);
		print_submit_row($vbphrase['import']);
	}

	print_form_header('admincp/product', 'productsave');

	if ($product)
	{
		print_table_header(construct_phrase($vbphrase['edit_product_x'], $product['productid']));
		print_label_row($vbphrase['product_id'], $product['productid']);

		construct_hidden_code('productid', $product['productid']);
		construct_hidden_code('editing', 1);
	}
	else
	{
		print_table_header($vbphrase['add_new_product']);
		print_input_row($vbphrase['product_id'], 'productid', '', true, 50, 25); // max length = 25
	}

	print_input_row($vbphrase['title'], 'title', $product['title'], true, 50, 50);
	print_input_row($vbphrase['version_products'], 'version', $product['version'], true, 50, 25);
	print_input_row($vbphrase['description_gcpglobal'], 'description', $product['description'], true, 50, 250);
	print_input_row($vbphrase['product_url'], 'url', $product['url'], true, 50, 250);
	print_input_row($vbphrase['version_check_url'], 'versioncheckurl', $product['versioncheckurl'], true, 50, 250);

	print_submit_row();

	// if we're editing a product, show the install/uninstall code options
	if ($product)
	{
		echo '<hr />';

		print_form_header('admincp/product', 'productdependency');
		construct_hidden_code('productid', $vbulletin->GPC['productid']);

		// the <label> tags in the product type are for 3.6 bug 349
		$dependency_types = array(
			'php'       => $vbphrase['php_version'],
			'mysql'     => $vbphrase['mysql_version_products'],
			'vbulletin' => $vbphrase['vbulletin_version_products'],
			'product'   => $vbphrase['product_id'] . '</label>&nbsp;<input type="text" class="bginput" name="parentproductid" id="it_parentproductid" value="" size="15" maxlength="25" tabindex="1" /><label>',
		);

		$product_dependencies = $assertor->getRows('productdependency', array('productid' => $vbulletin->GPC['productid']), array('dependencytype', 'parentproductid', 'minversion'));

		if (count($product_dependencies))
		{
			print_table_header($vbphrase['existing_product_dependencies'], 4);
			print_cells_row(array(
				$vbphrase['dependency_type'],
				$vbphrase['compatibility_starts'],
				$vbphrase['incompatible_with'],
				$vbphrase['delete']
			), 1);

			foreach ($product_dependencies AS $product_dependency)
			{
				if ($product_dependency['dependencytype'] != 'product')
				{
					$dep_type = $dependency_types["$product_dependency[dependencytype]"];
				}
				else
				{
					$dep_type = $vbphrase['product'] . ' - ' . htmlspecialchars_uni($product_dependency['parentproductid']);
				}

				$depid = $product_dependency['productdependencyid'];

				print_cells_row(array(
					$dep_type,
					"<input type=\"text\" name=\"productdependency[$depid][minversion]\" value=\"" . htmlspecialchars_uni($product_dependency['minversion']) . "\" size=\"25\" maxlength=\"50\" tabindex=\"1\" />",
					"<input type=\"text\" name=\"productdependency[$depid][maxversion]\" value=\"" . htmlspecialchars_uni($product_dependency['maxversion']) . "\" size=\"25\" maxlength=\"50\" tabindex=\"1\" />",
					"<input type=\"checkbox\" name=\"productdependency[$depid][delete]\" value=\"1\" />"
				));
			}

			print_table_break();
		}

		print_table_header($vbphrase['add_new_product_dependency']);
		print_radio_row($vbphrase['dependency_type'], 'dependencytype', $dependency_types);
		print_input_row($vbphrase['compatibility_starts_with_version'], 'minversion', '', true, 25, 50);
		print_input_row($vbphrase['incompatible_with_version_and_newer'], 'maxversion', '', true, 25, 50);

		print_submit_row();

		// #############################################
		echo '<hr />';

		print_form_header('admincp/product', 'productcode');
		construct_hidden_code('productid', $vbulletin->GPC['productid']);

		$productcodes = $assertor->getRows('productcode', array('productid' => $vbulletin->GPC['productid']), 'version');

		if (count($productcodes))
		{
			print_table_header($vbphrase['existing_install_uninstall_code'], 4);
			print_cells_row(array(
				$vbphrase['version_products'],
				$vbphrase['install_code'],
				$vbphrase['uninstall_code'],
				$vbphrase['delete']
			), 1);

			$productcodes_grouped = array();
			$productcodes_versions = array();

			foreach ($productcodes AS $productcode)
			{
				// have to be careful here, as version numbers are not necessarily unique
				$productcodes_versions["$productcode[version]"] = 1;
				$productcodes_grouped["$productcode[version]"][] = $productcode;
			}

			$productcodes_versions = array_keys($productcodes_versions);
			usort($productcodes_versions, 'version_sort');

			foreach ($productcodes_versions AS $version)
			{
				foreach ($productcodes_grouped["$version"] AS $productcode)
				{
					print_cells_row(array(
						"<input type=\"text\" name=\"productcode[$productcode[productcodeid]][version]\" value=\"" . htmlspecialchars_uni($productcode['version']) . "\" style=\"width:100%\" size=\"10\" />",
						"<textarea name=\"productcode[$productcode[productcodeid]][installcode]\" rows=\"5\" cols=\"40\" style=\"width:100%\" wrap=\"virtual\" tabindex=\"1\">" . htmlspecialchars($productcode['installcode']) . "</textarea>",
						"<textarea name=\"productcode[$productcode[productcodeid]][uninstallcode]\" rows=\"5\" cols=\"40\" style=\"width:100%\" wrap=\"virtual\" tabindex=\"1\">" . htmlspecialchars($productcode['uninstallcode']) . "</textarea>",
						"<input type=\"checkbox\" name=\"productcode[$productcode[productcodeid]][delete]\" value=\"1\" />"
					));
				}
			}

			print_table_break();
		}

		print_table_header($vbphrase['add_new_install_uninstall_code']);

		print_input_row($vbphrase['version_products'], 'version');
		print_textarea_row($vbphrase['install_code'], 'installcode', '', 5, '70" style="width:100%', true, false);
		$installId = $vbulletin->textarea_id;
		print_textarea_row($vbphrase['uninstall_code'], 'uninstallcode', '', 5, '70" style="width:100%', true, false);
		$uninstallId = $vbulletin->textarea_id;
		activateCodeMirrorPHP(array($installId, $uninstallId));
		print_submit_row();
	}
}

// #############################################################################

if ($_POST['do'] == 'productsave')
{
	// Check to see if it is a duplicate.
	$vbulletin->input->clean_array_gpc('p', array(
		'editing'         => vB_Cleaner::TYPE_BOOL,
		'title'           => vB_Cleaner::TYPE_STR,
		'version'         => vB_Cleaner::TYPE_STR,
		'description'     => vB_Cleaner::TYPE_STR,
		'url'             => vB_Cleaner::TYPE_STR,
		'versioncheckurl' => vB_Cleaner::TYPE_STR,
		'confirm'         => vB_Cleaner::TYPE_BOOL,
	));

	if ($vbulletin->GPC['url'] AND !preg_match('#^[a-z0-9]+:#i', $vbulletin->GPC['url']))
	{
		$vbulletin->GPC['url'] = 'http://' . $vbulletin->GPC['url'];
	}
	if ($vbulletin->GPC['versioncheckurl'] AND !preg_match('#^[a-z0-9]+:#i', $vbulletin->GPC['versioncheckurl']))
	{
		$vbulletin->GPC['versioncheckurl'] = 'http://' . $vbulletin->GPC['versioncheckurl'];
	}

	if (!$vbulletin->GPC['productid'] OR !$vbulletin->GPC['title'] OR !$vbulletin->GPC['version'])
	{
		print_stop_message2('please_complete_required_fields');
	}

	if (strtolower($vbulletin->GPC['productid']) == 'vbulletin')
	{
		print_stop_message2(array('product_x_installed_version_y_z', 'vBulletin', $vbulletin->options['templateversion'], $vbulletin->GPC['version']));
	}

	if (!$vbulletin->GPC['editing'] AND $existingprod = $assertor->getRow('product', array('productid' => $vbulletin->GPC['productid'])))
	{
		print_stop_message2(array('product_x_installed_version_y_z', $vbulletin->GPC['title'], $existingprod['version'], $vbulletin->GPC['version']));
	}

	require_once(DIR . '/includes/adminfunctions_template.php');

	$invalid_version_structure = array(0, 0, 0, 0, 0, 0);
	if (fetch_version_array($vbulletin->GPC['version']) == $invalid_version_structure)
	{
		print_stop_message2('invalid_product_version');
	}

	if ($vbulletin->GPC['editing'])
	{
		$assertor->update('product', array(
				'title' => $vbulletin->GPC['title'],
				'description' => $vbulletin->GPC['description'],
				'version' => $vbulletin->GPC['version'],
				'url' => $vbulletin->GPC['url'],
				'versioncheckurl' => $vbulletin->GPC['versioncheckurl']
			),
			array('productid' => $vbulletin->GPC['productid'])
		);
	}
	else
	{
		// product IDs must match #^[a-z0-9_]+$# and must be max 25 chars
		if (!preg_match('#^[a-z0-9_]+$#s', $vbulletin->GPC['productid']) OR strlen($vbulletin->GPC['productid']) > 25)
		{
			$sugg = preg_replace('#\s+#s', '_', strtolower($vbulletin->GPC['productid']));
			$sugg = preg_replace('#[^\w]#s', '', $sugg);
			$sugg = str_replace('__', '_', $sugg);
			$sugg = substr($sugg, 0, 25);
			print_stop_message2(array('product_id_invalid', htmlspecialchars_uni($vbulletin->GPC['productid']), $sugg));
		}

		// reserve 'vb' prefix for official vBulletin products
		if (!$vbulletin->GPC['confirm'] AND strtolower(substr($vbulletin->GPC['productid'], 0, 2)) == 'vb')
		{
			print_form_header('admincp/product', 'productsave');
			print_table_header($vbphrase['vbulletin_message']);
			print_description_row(
				htmlspecialchars_uni($vbulletin->GPC['title']) . ' ' . htmlspecialchars_uni($vbulletin->GPC['version']) .
				'<dfn>' . htmlspecialchars_uni($vbulletin->GPC['description']) . '</dfn>'
			);
			print_input_row($vbphrase['vb_prefix_reserved'], 'productid', $vbulletin->GPC['productid'], true, 35, 25);
			construct_hidden_code('title', $vbulletin->GPC['title']);
			construct_hidden_code('description', $vbulletin->GPC['description']);
			construct_hidden_code('version', $vbulletin->GPC['version']);
			construct_hidden_code('confirm', 1);
			construct_hidden_code('url', $vbulletin->GPC['url']);
			construct_hidden_code('versioncheckurl', $vbulletin->GPC['versioncheckurl']);
			print_submit_row();
			print_cp_footer();

			// execution terminates here
		}

		/* insert query */
		$assertor->insert('product', array(
			'productid' => $vbulletin->GPC['productid'],
			'title' => $vbulletin->GPC['title'],
			'description' => $vbulletin->GPC['description'],
			'version' => $vbulletin->GPC['version'],
			'active' => 1,
			'url' => $vbulletin->GPC['url'],
			'versioncheckurl' => $vbulletin->GPC['versioncheckurl']
		));
	}

	// update the products datastore
	$prod_lib->buildProductDatastore();

	if (defined('DEV_AUTOEXPORT') AND DEV_AUTOEXPORT)
	{
		require_once(DIR . '/includes/functions_filesystemxml.php');
		autoexport_write_product($vbulletin->GPC['productid']);
	}

	print_stop_message2(array('product_x_updated',  $vbulletin->GPC['productid']), 'product', array('do' => 'product'));
}

// #############################################################################

if ($_POST['do'] == 'productdependency')
{
	$vbulletin->input->clean_array_gpc('p', array(
		'dependencytype'	=> vB_Cleaner::TYPE_STR,
		'parentproductid'	=> vB_Cleaner::TYPE_STR,
		'minversion'		=> vB_Cleaner::TYPE_STR,
		'maxversion'		=> vB_Cleaner::TYPE_STR,
		'productdependency'	=> vB_Cleaner::TYPE_ARRAY
	));

	$product = $assertor->getRow('product', array('productid' => $vbulletin->GPC['productid']));

	if (!$product)
	{
		print_stop_message2('invalid_product_specified');
	}

	if ($vbulletin->GPC['dependencytype'] != 'product')
	{
		$vbulletin->GPC['parentproductid'] = '';
	}

	if ($vbulletin->GPC['dependencytype'] OR $vbulletin->GPC['parentproductid'])
	{
		if ($vbulletin->GPC['minversion'] OR $vbulletin->GPC['maxversion'])
		{
			/* insert query */
			$assertor->insert('productdependency', array(
				'productid' => $vbulletin->GPC['productid'],
				'dependencytype' => $vbulletin->GPC['dependencytype'],
				'parentproductid' => $vbulletin->GPC['parentproductid'],
				'minversion' => $vbulletin->GPC['minversion'],
				'maxversion' => $vbulletin->GPC['maxversion']
			));
		}
		else
		{
			print_stop_message2('please_complete_required_fields');
		}
	}

	foreach ($vbulletin->GPC['productdependency'] AS $productdependencyid => $product_dependency)
	{
		$productdependencyid = intval($productdependencyid);

		if ($product_dependency['delete'])
		{
			$assertor->delete('productdependency', array('productdependencyid' => $productdependencyid));
		}
		else
		{
			$assertor->update('productdependency',
				array('minversion' => $product_dependency['minversion'], 'maxversion' => $product_dependency['maxversion']),
				array('productdependencyid' => $productdependencyid)
			);
		}
	}

	if (defined('DEV_AUTOEXPORT') AND DEV_AUTOEXPORT)
	{
		require_once(DIR . '/includes/functions_filesystemxml.php');
		autoexport_write_product($vbulletin->GPC['productid']);
	}

	print_stop_message2(array('product_x_updated',  $vbulletin->GPC['productid']), 'product', array('do' => 'productedit','productid'=>$vbulletin->GPC['productid']));
}

// #############################################################################

if ($_POST['do'] == 'productcode')
{
	$vbulletin->input->clean_array_gpc('p', array(
		'version'		=> vB_Cleaner::TYPE_STR,
		'installcode'	=> vB_Cleaner::TYPE_STR,
		'uninstallcode'	=> vB_Cleaner::TYPE_STR,
		'productcode'	=> vB_Cleaner::TYPE_ARRAY
	));
	$product = $assertor->getRow('product', array('productid' => $vbulletin->GPC['productid']));
	if (!$product)
	{
		print_stop_message2('invalid_product_specified');
	}

	if ($vbulletin->GPC['version'] AND ($vbulletin->GPC['installcode'] OR $vbulletin->GPC['uninstallcode']))
	{
		$assertor->insert('productcode', array(
			'productid' => $vbulletin->GPC['productid'],
			'version' => $vbulletin->GPC['version'],
			'installcode' => $vbulletin->GPC['installcode'],
			'uninstallcode' => $vbulletin->GPC['uninstallcode']
		));
	}

	foreach ($vbulletin->GPC['productcode'] AS $productcodeid => $productcode)
	{
		$productcodeid = intval($productcodeid);

		if ($productcode['delete'])
		{
			$assertor->delete('productcode', array('productcodeid' => $productcodeid));
		}
		else
		{
			$assertor->update('productcode',
				array('version' => $productcode['version'], 'installcode' => $productcode['installcode'], 'uninstallcode' => $productcode['uninstallcode']),
				array('productcodeid' => $productcodeid)
			);
		}
	}

	if (defined('DEV_AUTOEXPORT') AND DEV_AUTOEXPORT)
	{
		require_once(DIR . '/includes/functions_filesystemxml.php');
		autoexport_write_product($vbulletin->GPC['productid']);
	}

	print_stop_message2(array('product_x_updated',  $vbulletin->GPC['productid']), 'product', array('do' => 'productedit','productid'=>$vbulletin->GPC['productid']));
}

// #############################################################################

if ($_POST['do'] == 'productkill')
{
	if (strtolower($vbulletin->GPC['productid']) == 'vbulletin')
	{
		print_cp_redirect2('product', array('do' => 'product'), 1, 'admincp');
	}

	$safe_productid = $vbulletin->db->escape_string($vbulletin->GPC['productid']);
	// run uninstall code first; try to undo things in the opposite order they were done
	$productcodes = $assertor->getRows('productcode', array(
		vB_dB_Query::CONDITIONS_KEY => array(
			array('field' => 'productid', 'value' => $safe_productid, vB_dB_Query::OPERATOR_KEY => vB_dB_Query::OPERATOR_EQ),
			array('field' => 'uninstallcode', 'value' => '', vB_dB_Query::OPERATOR_KEY => vB_dB_Query::OPERATOR_NE)
		)
	));

	$productcodes_grouped = array();
	$productcodes_versions = array();

	foreach ($productcodes AS $productcode)
	{
		// have to be careful here, as version numbers are not necessarily unique
		$productcodes_versions["$productcode[version]"] = 1;
		$productcodes_grouped["$productcode[version]"][] = $productcode;
	}

	unset($productcodes_versions['*']);
	$productcodes_versions = array_keys($productcodes_versions);
	usort($productcodes_versions, 'version_sort');
	$productcodes_versions = array_reverse($productcodes_versions);

	if (!empty($productcodes_grouped['*']))
	{
		// run * entries first
		foreach ($productcodes_grouped['*'] AS $productcode)
		{
			eval($productcode['uninstallcode']);
		}
	}

	foreach ($productcodes_versions AS $version)
	{
		foreach ($productcodes_grouped["$version"] AS $productcode)
		{
			eval($productcode['uninstallcode']);
		}
	}

	//clear the type cache.
	vB_Cache::instance()->purge('vb_types.types');

	// need to remove the language columns for this product as well
	$assertor->assertQuery('removeLanguageFromPackage', array('productid' => $vbulletin->GPC['productid']));

	delete_product($vbulletin->GPC['productid']);

	build_all_styles();

	require_once(DIR . '/includes/adminfunctions_language.php');
	build_language();

	vB::getDatastore()->build_options();

	require_once(DIR . '/includes/functions_cron.php');
	build_cron_next_run();

	$prod_lib->buildProductDatastore();

	// build bitfields to remove/add this products bitfields
	require_once(DIR . '/includes/class_bitfield_builder.php');
	vB_Bitfield_Builder::save($db);

	// reload block types
	$file = false;
	$args = array();
	if (!defined('DISABLE_PRODUCT_REDIRECT'))
	{
		$file = 'product';
		$args = array('do' => 'product');
	}
	print_stop_message2(array('product_x_uninstalled',  $vbulletin->GPC['productid']), $file, $args);
}

// #############################################################################

if ($_REQUEST['do'] == 'productdelete')
{
	if (strtolower($vbulletin->GPC['productid']) == 'vbulletin')
	{
		print_cp_redirect2('product', array('do' => 'product'), 1, 'admincp');
	}

	$dependency_result = $assertor->getRows('productdependency', array(
		vB_dB_Query::CONDITIONS_KEY => array(
			array('field' => 'dependencytype', 'value' => 'product', vB_dB_Query::OPERATOR_KEY => vB_dB_Query::OPERATOR_EQ),
			array('field' => 'parentproductid', 'value' => '', vB_dB_Query::OPERATOR_KEY => vB_dB_Query::OPERATOR_NE)
		)
	));

	// find child products -- these may break if we uninstall this
	$dependency_list = array();
	foreach ($dependency_result AS $dependency)
	{
		$dependency_list["$dependency[parentproductid]"][] = $dependency['productid'];
	}

	$children = fetch_product_dependencies($vbulletin->GPC['productid'], $dependency_list);

	$product_list = fetch_product_list(true);

	$children_text = array();
	foreach ($children AS $childproductid)
	{
		$childproduct = $product_list["$childproductid"];
		if ($childproduct)
		{
			$children_text[] = $childproduct['title'];
		}
	}

	if ($children_text)
	{
		$affected_children = construct_phrase(
			$vbphrase['uninstall_product_break_products_x'],
			'<li>' . implode('</li><li>', $children_text) . '</li>'
		);
	}
	else
	{
		$affected_children = '';
	}

	// find widgetinstances that will be deleted
	$widgetids = $assertor->getColumn('widget', 'widgetid', array('product' => $vbulletin->GPC['productid']));
	$widget_info = "";
	if (!empty($widgetids))
	{
		/*
			Just a list of integer widgetinstanceids aren't gonna be very helpful to a non-developer.
			Per Wayne, the page name (Page Name field when you save a page in site builder) of the pages
			that contain the widgetinstances would be most helpful, so let's get those page names.
			Since pagetemplates hold the widgetinstances, and multiple pages might use the same pagetemplate,
			the list might get a bit long... hopefully not long enough to require pagination though.
		 */
		$pagetemplateids = $assertor->getColumn('widgetinstance', 'pagetemplateid', array('widgetid' => $widgetids));

		$pages = $assertor->getRows('page', array('pagetemplateid' => $pagetemplateids));
		if (!empty($pages))
		{
			$pageids = array();
			$pagenames = array();
			foreach ($pages AS $__page)
			{
				$pageids[] = $__page['pageid'];
				$pagenames[] = $__page['title'];
			}
			$params = array(
				'doabsoluteurl' => true,
				'pageid' => $pageids,
			);
			$urlData = vB_Library::instance("page")->getUrls($params);
			/*
				getUrls() returns the following blocks:
					'all',
					'custom_pages',
					'orphans'
				'all' should include 'custom_pages' as well. Ignoring 'orphans' for now since if we want them
				we have to fetch them as a separate query.
			 */
			$string = vB::getString();
			$urls = array();
			foreach ($urlData['all']['paginated'] AS $__pageno => $__list)
			{
				foreach ($__list AS $__key => $__urldata)
				{

					$__urldata['url_htmlsafe'] = $string->htmlentities($__urldata['url']);
					$__urldata['label_htmlsafe'] = $string->htmlentities($__urldata['label']);
					/*
					From admin_sbpanel_pagelist_content template:
					<a href="{vb:var page.url}" title="{vb:var page.label}">{vb:var page.label}</a>{vb:var page.label_after_anchor}
					 */
					$urls[] = "<a href=\"{$__urldata['url_htmlsafe']}\" title=\"{$__urldata['label_htmlsafe']}\">"
						. $string->htmlentities($__urldata['label'])
						. "</a>"
						. $string->htmlentities($__urldata['label_after_anchor']);
				}
			}
			/*
				todo: There might be rare cases where we have pages but no URLs
				($excludedChannelGUIDs in vB_Api_Pages::getUrls(), and "content"
				pages like specific topic URLs, as there would be way too many)
				The warning phrase below notes that not all pages have URLs, but
				we may want to explicitly handle the case where there are NO URLs
				with a second phrase.
			 */

			$widget_info = construct_phrase(
				$vbphrase['uninstall_product_widgets_removed_on_pages_x'],
				'<li>' . implode('</li><li>', $pagenames) . '</li>',
				'<li>' . implode('</li><li>', $urls) . '</li>'
			);
		}
	}

	if (!empty($affected_children) AND !empty($widget_info))
	{
		$extra = $affected_children . "<br />" . $widget_info;
	}
	else
	{
		// If there's only one or no extra phrases, don't add an unnecessary break
		$extra = $affected_children . $widget_info;
	}


	print_delete_confirmation(
		'product',
		$vbulletin->GPC['productid'],
		'product',
		'productkill',
		'',
		0,
		$extra
	);
}

// #############################################################################

if ($_POST['do'] == 'productimport')
{
	$vbulletin->input->clean_array_gpc('p', array(
		'serverfile'   => vB_Cleaner::TYPE_STR,
		'allowoverwrite' => vB_Cleaner::TYPE_BOOL
	));

	$vbulletin->input->clean_array_gpc('f', array(
		'productfile' => vB_Cleaner::TYPE_FILE
	));
	scanVbulletinGPCFile('productfile');

	// Get realpaths.
	$serverfile = realpath($vbulletin->GPC['serverfile']);
	$tempfile = realpath($vbulletin->GPC['productfile']['tmp_name']);

	if (!$serverfile)
	{
		// If above fails, try relative path instead.
		$serverfile = realpath(DIR . DIRECTORY_SEPARATOR . $vbulletin->GPC['serverfile']);
	}

	// do not use file_exists here, under IIS it will return false in some cases
	if ($tempfile AND is_uploaded_file($tempfile))
	{
		// got an uploaded file?
		$xml = file_read($tempfile);
	}
	else if ($serverfile AND file_exists($serverfile))
	{
		// no uploaded file - got a local file?
		$xml = file_read($serverfile);
	}
	else
	{
		print_stop_message2('no_file_uploaded_and_no_local_file_found_gerror');
	}

	try
	{
		$info = install_product($xml, $vbulletin->GPC['allowoverwrite']);
		//install translations if this xml file corresponds to a proper package
		//and we have an official translation.
	 	vB_Library_Functions::installProductTranslations($info['productid'], VB_PKG_PATH . '/' .  $info['productid'] . '/xml');
	}
	catch (vB_Exception_AdminStopMessage $e)
	{
		//move print_stop_message calls from install_product so we
		//can use it places where said calls aren't appropriate.
		call_user_func_array('print_stop_message', $e->getParams());
	}

	/*
		Figure out what we want to do in the end.
		What we'd like to do is
			1. If don't need a merge, print the stop message which redirects to either the defined redirect
				for the product or the default redirect (aka the products admin page)
			2. If we do, then redirect to the merge page which will redirect to the proper redirect page
				when finished.

		As always users complicate things.  Some products want to display errors which get unreadable when
		the page automatically redirects.  We have a DISABLE_PRODUCT_REDIRECT flag which is supposed to
		simply display the stop message and not redirect.
	*/

	$file = false;
	$args = array();
	if (!defined('DISABLE_PRODUCT_REDIRECT'))
	{
		$file = 'product';
		$args = array('do' => 'product');
	}

	$redirect = defined('CP_REDIRECT') ? CP_REDIRECT : 'product.php?do=product';

	if ($info['need_merge'])
	{
		$file = 'template';
		$args = array(
			'do' => 'massmerge',
			'product' => $product,
			'hash' => CP_SESSIONHASH,
			'redirect' => $redirect
		);

		if (!defined('DISABLE_PRODUCT_REDIRECT'))
		{
			print_cp_redirect2('template', $args, 2, 'admincp');
		}
		else
		{
			//if we just don't define the back url we'll get a javascript "back" as default.
			//an empty string (instead of null) triggers no back button, which is what we want.
			//ugly, but it avoids rewriting a lot of the logic in print_stop_message here.
			$backurl = '';
			print_stop_message2(array('product_x_imported_need_merge', $info['productid']), $file, $args, $backurl, true);
		}
	}
	else
	{
		print_stop_message2(array('product_x_imported',  $info['productid']), $file, $args);
	}
}

// #############################################################################

if ($_REQUEST['do'] == 'productexport')
{
	try
	{
		$doc = get_product_export_xml($vbulletin->GPC['productid']);
	}
	catch (vB_Exception_AdminStopMessage $e)
	{
		//move print_stop_message calls from install_product so we
		//can use it places where said calls aren't appropriate.
		call_user_func_array('print_stop_message', $e->getParams());
	}

	require_once(DIR . '/includes/functions_file.php');
	file_download($doc, "product_" . $vbulletin->GPC['productid'] . '.xml', 'text/xml');
}

// #############################################################################

if ($_REQUEST['do'] == 'extensions')
{
	print_table_start();
	print_table_header(construct_phrase($vbphrase['list_extensions_version'], $vbulletin->options['templateversion']), 7);

	print_cells_row(
		array(
			$vbphrase['title'] . ' (' .
			$vbphrase['version_products'] . ')',
			$vbphrase['class'],
			$vbphrase['active'],
			$vbphrase['minver'],
			$vbphrase['maxver'],
			$vbphrase['compatible'],
			$vbphrase['order'],
		),
		true,
		false,
		0.5 // Stops the final column being right aligned
	);

	$options = vB::getDatastore()->getValue('options');

	$failed = array();
	$extensions = vB_Api_Extensions::loadAllExtensions();

	if ($extensions)
	{
		$product = '';
		foreach($extensions AS $extn)
		{
			if (isset($extn['__failed']))
			{
				//__failed can only have one item in it, which makes having it
				//as an array of key => value pairs dubious.

				$value = reset($extn['__failed']);
				$dir = key($extn['__failed']);
				$failed[] = array(
					'dir'  => $dir,
					'file' => $value[0]
				);

				continue;
			}

			if ($product != $extn['product'])
			{
				print_description_row(
					$vbphrase['product'] . ': ' . $extn['package'],
					false,
					7,
					'boldrow'
				);

				$product = $extn['product'];
			}

			if (!$options['enablehooks'] OR defined('DISABLE_HOOKS'))
			{
				$extn['enabled'] = false;
			}

			$title = htmlspecialchars_uni($extn['title']);
			$title = $extn['enabled'] ? $title : "<strike>$title</strike>";

			$enabled = $extn['enabled'] ? $vbphrase['yes'] : ($extn['dependancy'] ? $vbphrase['no_dep'] : $vbphrase['no']);

			print_cells_row(
				array(
					vB_Library_Admin::buildElementCell('', $title, 0, false, '', '', '', $extn['version'], $extn['developer']),
					vB_Library_Admin::buildDisplayCell($extn['class']),
					vB_Library_Admin::buildDisplayCell($enabled, ($extn['enabled'] AND $extn['compatible'])),
					vB_Library_Admin::buildDisplayCell($extn['minver']),
					vB_Library_Admin::buildDisplayCell($extn['maxver']),
					vB_Library_Admin::buildDisplayCell($extn['compatible'] ? $vbphrase['yes'] : $vbphrase['no'], $extn['compatible']),
					vB_Library_Admin::buildDisplayCell($extn['order']),
				),
				false,
				false,
				0.5
			);
		}

		if (!empty($failed))
		{
			print_table_footer();
			print_table_start();
			print_table_header($vbphrase['failed_extensions'], 2);

			print_cells_row(
				array(
					$vbphrase['directory'],
					$vbphrase['filename_gcpglobal'],
				),
				true,
				false,
				0.5
			);

			foreach ($failed AS $info)
			{
				print_cells_row(
					array(
						$info['dir'],
						$info['file'],
					),
					false,
					false,
					0.5
				);
			}
		}

		print_table_footer();
	}
	else
	{
		print_description_row(
			$vbphrase['no_extensions'],
			false,
			7,
			'boldrow'
		);

		print_table_footer();
	}

	//display product particulars

	print_table_start();
	print_table_header($vbphrase['product_list'], 5);

	print_cells_row(
		array(
			$vbphrase['title'].' ('.$vbphrase['version_products'].')',
			$vbphrase['product_class'],
			$vbphrase['minver'],
			$vbphrase['maxver'],
			$vbphrase['api_classes'],
		),
		true,
		false,
		0.5
	);


	$product_meta = $assertor->getRows('product', array(), false, 'productid');

	$products = vB::getProducts();
	$api_classes = $products->getApiClassesByProduct();

	$productlist = $products->getProductObjects();
	$disabledproductslist = $products->getDisabledProductObjects();

	$api_classes = $products->getApiClassesByProduct();

	function display_product_row($object, $meta, $api_classes, $enabled)
	{
		$packagetitle = $meta['title'];
		$version = $meta['version'];
		if(!$enabled)
		{
			$packagetitle = '<s>' . $packagetitle . '</s>';
			$version = '<s>' . $version . '</s>';
		}

		$classes = array();
		foreach($api_classes AS $api_class)
		{
			$classes[] = $api_class['classname'];
		}

		$classes = implode('<br/>', array_unique($classes));
		$minVersion = (empty($object->vbMinVersion) ? vB_Phrase::fetchSinglePhrase('none') : $object->vbMinVersion);
		$maxVersion = (empty($object->vbMaxVersion) ? vB_Phrase::fetchSinglePhrase('none') : $object->vbMaxVersion);

		print_cells_row(
			array(
				vB_Library_Admin::buildElementCell('', $packagetitle, 0, false, '', '', '', $version, $meta['description']),
				vB_Library_Admin::buildDisplayCell(get_class($object)),
				vB_Library_Admin::buildDisplayCell($minVersion),
				vB_Library_Admin::buildDisplayCell($maxVersion),
				vB_Library_Admin::buildDisplayCell($classes)
			),
			false,
			false,
			0.5
		);
	}

	if ($productlist OR $disabledproductslist)
	{
		foreach($productlist AS $packagename => $hookproduct)
		{
			$classes = (isset($api_classes[$packagename]) ? $api_classes[$packagename] : array());
			display_product_row($hookproduct, $product_meta[$packagename], $classes, $hooksEnabled);
		}

		foreach($disabledproductslist AS $packagename => $hookproduct)
		{
			$classes = (isset($api_classes[$packagename]) ? $api_classes[$packagename] : array());
			display_product_row($hookproduct, $product_meta[$packagename], $classes, false);
		}
	}
	else
	{
		print_description_row(
			$vbphrase['no_products'],
			false,
			5,
			'boldrow'
		);
	}

	print_table_footer();
	//end products

	print_table_start();
	print_table_header($vbphrase['product_hook_list'], 3);

	print_cells_row(
		array(
			$vbphrase['hook_class'],
			$vbphrase['order'],
			$vbphrase['hook_list'],
		),
		true,
		false,
		0.5
	);

	function display_product_hooks($object, $meta, $enabled, $phrases)
	{
		if(empty($object->hookClasses))
		{
			return;
		}

		$title = htmlspecialchars_uni($meta['title']);
		$title = $enabled ? $title : "<strike>$title</strike>";

		print_description_row(
			$phrases['product'] . ': ' . $title,
			false,
			4,
			'boldrow'
		);

		foreach($object->hookClasses AS $hook_class)
		{
			$methodslist = array();
			if (class_exists($hook_class))
			{
				$methods = get_class_methods($hook_class);
				$methods = (empty($methods) ? array() : $methods);

				foreach($methods AS $method)
				{
					$methodslist[] = $method;
				}

				$classmethods = implode('<br/>', array_unique($methodslist));

				$classname= $enabled ? $hook_class : "<strike>$hook_class</strike>";
				$order = isset($hook_class::$order) ? $hook_class::$order : 10;
			}
			else
			{
				$classname = '<s>' . $hook_class . '</s>';
				$order = '';
				$classmethods = '';
			}

			print_cells_row(
				array(
					vB_Library_Admin::buildDisplayCell($classname),
					vB_Library_Admin::buildDisplayCell($order),
					vB_Library_Admin::buildDisplayCell($classmethods, false, true),
				),
				false,
				false,
				0.5
			);
		}
	}

	if ($productlist OR $disabledproductslist)
	{
		foreach($productlist AS $packagename => $hookproduct)
		{
			display_product_hooks($hookproduct, $product_meta[$packagename], $hooksEnabled, $vbphrase);
		}

		foreach($disabledproductslist AS $packagename => $hookproduct)
		{
			display_product_hooks($hookproduct, $product_meta[$packagename], false, $vbphrase);
		}
	}
	else
	{
		print_description_row(
			$vbphrase['no_hook_products'],
			false,
			3,
			'boldrow'
		);
	}

	print_table_footer();
}

print_cp_footer();

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 102599 $
|| #######################################################################
\*=========================================================================*/
