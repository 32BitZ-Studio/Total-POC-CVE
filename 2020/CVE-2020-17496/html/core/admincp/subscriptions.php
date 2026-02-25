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
define('CVS_REVISION', '$RCSfile$ - $Revision: 101129 $');

// #################### PRE-CACHE TEMPLATES AND DATA ######################
global $phrasegroups, $specialtemplates, $vbphrase, $vbulletin, $tableadded;
$phrasegroups = array('subscription', 'cpuser', 'stats');
$specialtemplates = array();

// ########################## REQUIRE BACK-END ############################
require_once(dirname(__FILE__) . '/global.php');
require_once(DIR . '/includes/class_paid_subscription.php');
$assertor = vB::getDbAssertor();

// ######################## CHECK ADMIN PERMISSIONS #######################
if (!can_administer('canadminusers'))
{
	print_cp_no_permission();
}

$vbulletin->input->clean_array_gpc('r', array(
	'userid'         => vB_Cleaner::TYPE_INT,
	'subscriptionid' => vB_Cleaner::TYPE_INT,
));

// ############################# LOG ACTION ###############################
log_admin_action(!empty($vbulletin->GPC['userid']) ? "user id = " . $vbulletin->GPC['userid'] : !empty($vbulletin->GPC['subscriptionid']) ? "subscriptionid id = " . $vbulletin->GPC['subscriptionid'] : '');

// ########################################################################
// ######################### START MAIN SCRIPT ############################
// ########################################################################

$vb5_config =& vB::getConfig();

print_cp_header($vbphrase['subscription_manager_gsubscription']);
$subobj = new vB_PaidSubscription($vbulletin);

if (empty($_REQUEST['do']))
{
	$_REQUEST['do'] = 'modify';
}

// ###################### Start Add #######################
if ($_REQUEST['do'] == 'add' OR $_REQUEST['do'] == 'edit')
{
	$options = vB::getDatastore()->getValue('options');
	$filebase = $options['bburl'];

	?>
	<script type="text/javascript">
		$(document).ready(function()
		{
			// Reset the Pricing index and delete link
			var resetPricing = function()
			{
				$('tbody.pricing').each(function(index)
				{
					var $pricing = $(this);

					// Go through input boxes and update the name of them
					$(':input', $pricing).each(function()
					{
						var $input = $(this),
							name = $input.attr('name'),
							id = $input.attr('id');
						if (typeof id !== "undefined")
						{
							$input.attr('id', id.replace(/\d+/, index));
						}

						if (typeof name !== "undefined")
						{
							$input.attr('name', name.replace(/\d+/, index));
						}

					});

					$('div', $pricing).each(function()
					{
						var id = $(this).attr('id');
						if (typeof id !== "undefined")
						{
							$(this).attr('id', id.replace(/\d+/, index));
						};
					});

					//note this won't actually update the html/data-index attribute.  It will however,
					//update the results from subsequent calls to data
					$('.currency', $pricing).data('index', index);
					$('.pricingindex', $pricing).text(index+1);
				});


				// Process delete link visiblity
				if ($('tbody.pricing').length == 1)
				{
					$('a.delete_pricing').addClass('hide');
				}
				else
				{
					$('a.delete_pricing').removeClass('hide');
				}
			}

			// New Pricing link
			$(document).on('click', 'a.new_pricing', function()
			{
				// Clone current pricing and append new one to it
				var currentpricing = $(this).closest('tbody'), newpricing = currentpricing.clone();
				newpricing.find(':input').val('');

				newpricing.insertAfter(currentpricing);

				resetPricing();

				return false;
			});

			// Delete Pricing link
			$(document).on('click', 'a.delete_pricing', function()
			{
				$(this).closest('tbody').remove();
				resetPricing();

				return false;
			});

			// Remove currencies that have been choosen before
			var defaultoptions;
			var resetCurrencySelect = function(container)
			{
				if (!defaultoptions) defaultoptions = $('select.currency', container).eq(0).find('option');

				// Reset all options
				var selectedcurrencies = [];
				$('select.currency', container).each(function()
				{
					var selectbox = $(this), selectval = selectbox.val();
					$(this).empty();
					defaultoptions.each(function()
					{
						selectbox.append($(this).clone());
					});
					selectbox.val(selectval);

					// Update input name
					selectbox.closest('div.pricerow').find('input.cost').attr('name', 'sub[time][' + selectbox.data('index') + '][cost][' + selectval + ']');

					selectedcurrencies.push(selectval);
				});

				$('select.currency', container).each(function()
				{
					var selectval = $(this).val();

					$("option", $(this)).each(function()
					{
						if ($.inArray($(this).val(), selectedcurrencies) != -1 && $(this).val() != selectval)
						{
							$(this).remove();
						}
					});
				});
			}

			var resetCurrencyRemoveLinks = function(currency) {
				// If there's only one pricerow, hide remove links
				if ($('.pricerow', currency).length == 1) {
					$('a.removeprice', currency).addClass('hide');
				}
				else {
					$('a.removeprice', currency).removeClass('hide');
				}
			}

			$('tbody.pricing').each(function() {
				resetCurrencySelect($(this));
			});

			// Currency select box
			$(document).on('change', 'select.currency', function()
			{
				$(this).closest('div.pricerow').find('input.cost').attr('name', 'sub[time][' + $(this).data('index') + '][cost][' + $(this).val() + ']');
				resetCurrencySelect($(this).closest('td'));
			});

			// Add more prices
			$(document).on('click', 'a.addmoreprices', function()
			{
				var container = $(this).closest('td');

				// Find a pricerow and clone it
				var lastpricerow = container.find('div.pricerow').last(),
					lastcurrencyselect = $("select.currency", lastpricerow),
					lastcurrencyselectval = lastcurrencyselect.val(),
					newpricerow = lastpricerow.clone(),
					newcurrencyselect = $("select.currency", newpricerow);

				// Empty the price input
				$('input', newpricerow).val('');

				// Make the current select to select the next val of lastpricerow
				$("option", lastcurrencyselect).each(function()
				{
					if ($(this).val() != lastcurrencyselectval)
					{
						newcurrencyselect.val($(this).val());
						return false;
					}
				});

				newpricerow.insertBefore($(this).closest('div'));
				resetCurrencySelect(container);
				resetCurrencyRemoveLinks(container);

				// If the currency select has only one option, we are out of currencies and stop user to add more
				if ($("option", lastcurrencyselect).length == 1) {
					$(this).addClass('hide');
				}

				return false;
			});

			// Remove price link
			$(document).on('click', 'a.removeprice', function()
			{
				var container = $(this).closest('td');

				$(this).closest('div.pricerow').remove();

				resetCurrencySelect(container);

				// Show "Add more prices" link
				$('a.addmoreprices', container).removeClass('hide');

				resetCurrencyRemoveLinks(container);
				return false;
			});

			$('a.new_pricing').last().click();
		});
	</script>
	<?php
	print_form_header('admincp/subscriptions', 'update');

	if ($_REQUEST['do'] == 'add')
	{
		print_table_header($vbphrase['add_new_subscription_gsubscription']);
		$sub['active'] = true;
		$sub['displayorder'] = 1;
		$sub['newoptions'] = false;
	}
	else
	{
		$sub = $assertor->getRow('vBForum:subscription', array('subscriptionid' => $vbulletin->GPC['subscriptionid']));

		$sub['cost'] = unserialize($sub['cost']);
		$sub['newoptions'] = @unserialize($sub['newoptions']);
		$sub = array_merge($sub, convert_bits_to_array($sub['options'], $subobj->_SUBSCRIPTIONOPTIONS));
		$sub = array_merge($sub, convert_bits_to_array($sub['adminoptions'], $vbulletin->bf_misc_adminoptions));
		$title = 'sub' . $sub['subscriptionid'] . '_title';
		$desc = 'sub' . $sub['subscriptionid'] . '_desc';

		$phrases = $assertor->getRows('vBForum:phrase', array(
			'fieldname' => 'subscription', 'varname' => array($title, $desc)
		));

		foreach ($phrases AS $phrase)
		{
			if ($phrase['varname'] == $title)
			{
				$sub['title'] = $phrase['text'];
				$sub['titlevarname'] = 'sub' . $sub['subscriptionid'] . '_title';
			}
			else if ($phrase['varname'] == $desc)
			{
				$sub['description'] = $phrase['text'];
				$sub['descvarname'] = 'sub' . $sub['subscriptionid'] . '_desc';
			}
		}

		print_table_header(construct_phrase($vbphrase['x_y_id_z'], $vbphrase['subscription'], htmlspecialchars_uni($sub['title']), $sub['subscriptionid']));
		construct_hidden_code('subscriptionid', $sub['subscriptionid']);
	}

	if ($sub['title'])
	{
		$phraseurl = "phrase.php?do=edit&fieldname=subscription&varname=$sub[titlevarname]&t=1";
		print_input_row($vbphrase['title'] . '<dfn>' . construct_link_code($vbphrase['translations'], $phraseurl, 1)  . '</dfn>', 'title', $sub['title']);
	}
	else
	{
		print_input_row($vbphrase['title'], 'title');
	}

	if ($sub['description'])
	{
		$phraseurl = "phrase.php?do=edit&fieldname=subscription&varname=$sub[descvarname]&t=1";
		print_textarea_row($vbphrase['description_gcpglobal'] . '<dfn>' . construct_link_code($vbphrase['translations'], $phraseurl, 1)  . '</dfn>', 'description', $sub['description']);
	}
	else
	{
		print_textarea_row($vbphrase['description_gcpglobal'], 'description');
	}

	print_yes_no_row($vbphrase['active_gsubscription'], 'sub[active]', $sub['active']);
	print_input_row($vbphrase['display_order'], 'sub[displayorder]', $sub['displayorder'], true, 5);
	print_yes_no_row($vbphrase['display_subscription_during_registration'], 'newoptions[regshow]', (isset($sub['newoptions']['regshow']) ? $sub['newoptions']['regshow'] : 0));

	// Prices
	print_table_break();
	print_table_header($vbphrase['cost'], 2);

	$direction = verify_text_direction('');

	// Get a list of supported currencies.
	$paymentapis = $assertor->getRows('vBForum:paymentapi');

	$currencystring = '';
	foreach ($paymentapis as $api)
	{
		$currencystring .= $api['currency'] . ',';
	}
	$currencystring = trim($currencystring, ',');
	$currencies = explode(',', $currencystring);
	$currencyoptions = array();
	foreach($currencies as $currency)
	{
		$currencyoptions[strtolower($currency)] = strtoupper($currency);
	}

	if (empty($sub['cost']))
	{
		$sub['cost'][] = array();
	}
	$hide_class = '';
	if (count($sub['cost']) <= 1)
	{
		$hide_class = 'hide';
	}


	echo '</tbody>';
	foreach ($sub['cost'] AS $i => $sub_occurence)
	{
		echo '<tbody class="pricing">';

		print_cells_row(array(
			$vbphrase['pricing'] . ' #<span class="pricingindex">' . ($i + 1) . '</span>',
			'<a href="#" class="new_pricing">' . $vbphrase['new_pricing'] . '</a> <a href="#" class="delete_pricing ' . $hide_class . '">' . $vbphrase['delete'] . '</a>'
		), 1);

		print_label_row($vbphrase['subscription_length'], '<div id="ctrl_sub[time][' . $i . '][length]">
			<input type="text" class="bginput" name="sub[time][' . $i . '][length]" dir="' . $direction . '" tabindex="1" size="35" value="' . $sub_occurence['length'] . '" />
			<select name="sub[time][' . $i . '][units]" tabindex="1" class="bginput">' .
				construct_select_options(array('D' => $vbphrase['days'], 'W' => $vbphrase['weeks'], 'M' => $vbphrase['months'], 'Y' => $vbphrase['years']), $sub_occurence['units']) .
			'</select>
			<input type="checkbox" name="sub[time][' . $i . '][recurring]" value="1" tabindex="1"' . ($sub_occurence['recurring'] ? ' checked="checked"' : '') . ' />' . $vbphrase['recurring'] . '
		</div>');

		print_input_row($vbphrase['ccbill_subid'], 'sub[time][' . $i . '][ccbillsubid]', $sub_occurence['ccbillsubid']);
		print_input_row($vbphrase['twocheckout_prodid'], 'sub[time][' . $i . '][twocheckout_prodid]', $sub_occurence['twocheckout_prodid']);

		$pricerow = '';
		if (!empty($sub_occurence['cost']))
		{
			$currency_hide_class = '';
			if (count($sub_occurence['cost']) <= 1)
			{
				$currency_hide_class = 'hide';
			}

			foreach ($sub_occurence['cost'] as $currency => $cost)
			{
				if (empty($cost)) continue;

				$pricerow .= '<div class="pricerow"><input type="text" class="bginput cost" name="sub[time][' . $i . '][cost][' . $currency . ']" dir="' . $direction . '" tabindex="1" size="35" value="' . number_format($cost, 2, '.', '') . '" />'
					. '<select tabindex="1" class="bginput currency currency_' . $i . '" data-index="' . $i . '">' .
						construct_select_options($currencyoptions, $currency) .
					'</select>
					<a href="#" class="removeprice ' . $currency_hide_class . '">' . $vbphrase['remove'] . '</a></div>';
			}
		}
		else
		{
			$pricerow .= '<div class="pricerow"><input type="text" class="bginput cost" name="sub[time][' . $i . '][cost][usd]" dir="' . $direction . '" tabindex="1" size="35" value="" /> '
				. '<select tabindex="1" class="bginput currency currency_' . $i . '" data-index="' . $i . '">' .
					construct_select_options($currencyoptions, 'usd') .
				'</select>
				<a href="#" class="removeprice hide">' . $vbphrase['remove'] . '</a></div>';
		}

		$pricerow .= '<div><a href="#" class="addmoreprices">' . $vbphrase['add_more_prices'] . '</a></div>';

		print_label_row($vbphrase['price'], $pricerow);

	}

	echo '</tbody><tbody>';

	$apis = $assertor->getRows('vBForum:paymentapi', array('active' => 1));

	foreach ($apis as $api)
	{
		$settings = @unserialize($api['subsettings']);
		if ($settings)
		{
			print_table_break();
			print_table_header($api['title']);
			if (is_array($settings))
			{
				// $info is an array
				foreach ($settings AS $key => $info)
				{
					$name = "newoptions[api][{$api['classname']}][$key]";
					$value = (isset($sub['newoptions']['api'][$api['classname']][$key]))?$sub['newoptions']['api'][$api['classname']][$key]:$info['value'];
					$title = $vbphrase["subsetting_{$api['classname']}_{$key}_title"];
					switch ($info['type'])
					{
						case 'yesno':
							if (empty($value))
							{
								$value = 0;
							}
							print_yes_no_row($title, $name, $value);
							break;

						case 'select':
							$options = array();
							if ($info['options'] AND is_array($info['options']))
							{
								foreach ($info['options'] as $option)
								{
									$options[$option] = $vbphrase['subsetting_' . $api['classname'] . '_' . $key . '_' . $option . '_selectoption'];
								}
							}
							print_select_row($title, $name, $options, $value);
							break;

						default:
							print_input_row($title, $name, $value, 1, 40);
							break;
					}
				}
			}
		}
	}

	// Admin override
	print_table_break();
	print_table_header($vbphrase['admin_override_options']);
	foreach ($vbulletin->bf_misc_adminoptions AS $field => $value)
	{
		print_yes_no_row($vbphrase['keep_' . $field], 'adminoptions[' . $field . ']', $sub["$field"]);
	}
	print_table_break();

	// USERGROUP SECTION
	print_table_header($vbphrase['usergroup_options_gcpuser']);
	print_chooser_row($vbphrase['primary_usergroup'], 'sub[nusergroupid]', 'usergroup', $sub['nusergroupid'], $vbphrase['no_change']);
	print_membergroup_row($vbphrase['additional_usergroups'], 'membergroup', 0, $sub);

	$tableadded = 1;
	print_submit_row(iif($_REQUEST['do'] == 'add', $vbphrase['save'], $vbphrase['update']), '_default_', 10);

}

// ###################### Start Update #######################
if ($_POST['do'] == 'update')
{
	$vbulletin->input->clean_array_gpc('p', array(
		'sub'          => vB_Cleaner::TYPE_ARRAY,
		'forums'       => vB_Cleaner::TYPE_ARRAY_BOOL,
		'membergroup'  => vB_Cleaner::TYPE_ARRAY_UINT,
		'adminoptions' => vB_Cleaner::TYPE_ARRAY_UINT,
		'newoptions'   => vB_Cleaner::TYPE_ARRAY,
		'shipping'     => vB_Cleaner::TYPE_UINT,
		'title'        => vB_Cleaner::TYPE_STR,
		'description'  => vB_Cleaner::TYPE_STR,
	));

	if ($vbulletin->GPC['shipping'] == 2)
	{
		$vbulletin->GPC['options']['shipping1'] = 1;
	}
	else if ($vbulletin->GPC['shipping'] == 4)
	{
		$vbulletin->GPC['options']['shipping2'] = 1;
	}

	require_once(DIR . '/includes/functions_misc.php');
	$vbulletin->GPC['sub']['adminoptions'] = convert_array_to_bits($vbulletin->GPC['adminoptions'], $vbulletin->bf_misc_adminoptions);
	$vbulletin->GPC['sub']['newoptions'] = serialize($vbulletin->GPC['newoptions']);

	$sub =& $vbulletin->GPC['sub'];

	$sub['active'] = intval($sub['active']);
	$sub['displayorder'] = intval($sub['displayorder']);

	$clean_times = array();
	$lengths = array('D' => 'days', 'W' => 'weeks', 'M' => 'months', 'Y' => 'years');

	$haspayment = false;
	foreach($vbulletin->GPC['newoptions']['api'] AS $apioption)
	{
		//show isn't guarenteed to be a "newoption" for any given payment API but
		//by convention it is.  And you can't actually allow to be used if it isn't
		if(!empty($apioption['show']))
		{
			$haspayment = true;
			break;
		}
	}

	if(!$haspayment)
	{
		print_stop_message2('invalid_subscription_no_payment');
	}

	$counter = 0;
	if (is_array($vbulletin->GPC['sub']['time']))
	{
		foreach ($vbulletin->GPC['sub']['time'] AS $key => $moo)
		{
			$havecurrency = false;
			$counter++;
			$moo['length'] = intval($moo['length']);

			foreach ($moo['cost'] AS $currency => $value)
			{
				if ($value != 0)
				{
					$havecurrency = true;
					$moo['cost']["$currency"] = number_format($value, 2, '.', '');
				}
			}
			if ($moo['length'] == 0)
			{
				if ($havecurrency)
				{
					print_stop_message2(array('enter_subscription_length_for_subscription_x',  $counter));
				}
				continue;
			}
			else if (!$havecurrency)
			{
				print_stop_message2(array('enter_cost_information_for_subscription_x',  $counter));
			}

			if (strtotime("now + $moo[length] " . $lengths["$moo[units]"]) <= 0 OR $moo['length'] <= 0)
			{
				print_stop_message2('invalid_subscription_length');
			}
			$moo['recurring'] = intval($moo['recurring']);
			$moo['ccbillsubid'] = intval($moo['ccbillsubid']) ? intval($moo['ccbillsubid']) : '';
			$clean_times[$key] = $moo;
		}
		unset($vbulletin->GPC['sub']['time']);
	}
	else
	{
		print_stop_message2('variables_missing_suhosin');
	}
	$sub['cost'] = serialize($clean_times);

	$aforums = array();
	if (is_array($vbulletin->GPC['forums']))
	{
		foreach ($vbulletin->GPC['forums'] AS $key => $value)
		{
			if ($value == 1)
			{
				$aforums[] = intval($key);
			}
		}
	}
	else
	{
		print_stop_message2('variables_missing_suhosin');
	}

	$sub['membergroupids'] = '';
	if (!empty($vbulletin->GPC['membergroup']))
	{
		$sub['membergroupids'] = implode(',', $vbulletin->GPC['membergroup']);
	}
	$sub['forums'] = implode(',', $aforums);

	if (empty($clean_times))
	{
		$sub['active'] = 0;
	}

	if (empty($vbulletin->GPC['title']))
	{
		print_stop_message2('please_complete_required_fields');
	}
	if (in_array($sub['nusergroupid'], $vbulletin->GPC['membergroup']))
	{
		print_stop_message2('primary_equals_secondary');
	}

	if (empty($vbulletin->GPC['subscriptionid']))
	{
		$conditions = fetchQuerySql($sub, 'subscription');
		$vbulletin->GPC['subscriptionid'] = $assertor->insert('vBForum:subscription', $conditions['insert']);
		$insert_default_deny_perms = true;
	}
	else
	{
		$result = fetchQuerySql($sub, 'subscription', array('subscriptionid' => $vbulletin->GPC['subscriptionid']));
		$assertor->update('vBForum:subscription', $result['set'], $result['conditions']);
		$insert_default_deny_perms = false;
	}

	if ($insert_default_deny_perms)
	{
		// by default, deny buy permission to selected usergroups
		$subPerms = array();
		// # Users awaiting email confirmation
		// # Users Awaiting Moderation
		foreach (array(3, 4) AS $groupid)
		{
			$subPerms[] = array(
				'usergroupid' => $groupid,
				'subscriptionid' => $vbulletin->GPC['subscriptionid']
			);
		}

		$assertor->assertQuery('replaceValues', array('values' => $subPerms, 'table' => 'subscriptionpermission'));
		unset($subPerms);
	}

	$phraseVals = array();
	foreach (array('_title' => 'title', '_desc' => 'description') AS $phrasekey => $field)
	{
		$phraseVals[] = array(
			'languageid' => 0,
			'fieldname' => 'subscription',
			'varname' => 'sub' . $vbulletin->GPC['subscriptionid'] . $phrasekey,
			'text' => $vbulletin->GPC["$field"],
			'product' => 'vbulletin',
			'dateline' => vB::getRequest()->getTimeNow(),
			'version' => $vbulletin->options['templateversion']
		);
		// the global vbphrase is not being updated during build_language()
		$vbphrase['sub' . $vbulletin->GPC['subscriptionid'] . $phrasekey] = $vbulletin->GPC["$field"];
	}
	$assertor->assertQuery('replaceValues', array('values' => $phraseVals, 'table' => 'phrase'));
	unset($phraseVals);

	require_once(DIR . '/includes/adminfunctions_language.php');
	build_language(-1, 0, false);

	toggle_subs();

	print_stop_message2(array('saved_subscription_x_successfully',  htmlspecialchars_uni($vbulletin->GPC['title'])), 'subscriptions', array('do' => 'modify'));

}

// ###################### Start Remove #######################
if ($_REQUEST['do'] == 'remove')
{
	print_delete_confirmation(
		'vBForum:subscription',
		$vbulletin->GPC['subscriptionid'],
		'subscriptions',
		'kill',
		'subscription',
		0,
		'',
		$vbphrase['doing_this_will_remove_additional_access_subscription'],
		'subscriptionid'
	);
}

// ###################### Start Kill #######################
if ($_POST['do'] == 'kill')
{
	$assertor->assertQuery('vBForum:phrase', array(
		vB_dB_Query::TYPE_KEY => vB_dB_Query::QUERY_DELETE,
		vB_dB_Query::CONDITIONS_KEY => array(
			array('field'=> 'fieldname', 'value' => 'subscription', vB_dB_Query::OPERATOR_KEY => vB_dB_Query::OPERATOR_EQ),
			array('field'=> 'varname', 'value' => array('sub' . $vbulletin->GPC['subscriptionid'] . '_title', 'sub' . $vbulletin->GPC['subscriptionid'] . '_desc'), vB_dB_Query::OPERATOR_KEY => vB_dB_Query::OPERATOR_EQ)
		)
	));

	require_once(DIR . '/includes/adminfunctions_language.php');
	build_language();

	$users = $assertor->getRows('vBForum:subscriptionlog', array(
		'subscriptionid' => $vbulletin->GPC['subscriptionid'], 'status' => 1
	));
	foreach ($users AS $user)
	{
		$subobj->delete_user_subscription($vbulletin->GPC['subscriptionid'], $user['userid']);
	}

	$assertor->delete('vBForum:subscription', array('subscriptionid' => $vbulletin->GPC['subscriptionid']));
	$assertor->delete('vBForum:subscriptionlog', array('subscriptionid' => $vbulletin->GPC['subscriptionid']));

	toggle_subs();

	print_stop_message2('deleted_subscription_successfully', 'subscriptions', array('do'=>'modify'));

}

// ###################### Start find #######################
if ($_REQUEST['do'] == 'find')
{
	$vbulletin->input->clean_array_gpc('r', array(
		'status'      => vB_Cleaner::TYPE_INT,
		'orderby'     => vB_Cleaner::TYPE_NOHTML,
		'limitstart'  => vB_Cleaner::TYPE_INT,
		'limitnumber' => vB_Cleaner::TYPE_INT,
	));

	$condition = array();
	if ($vbulletin->GPC['subscriptionid'])
	{
		$condition = array_merge($condition, array('subscriptionid' => $vbulletin->GPC['subscriptionid']));
	}
	if ($vbulletin->GPC['status'] > -1)
	{
		$condition = array_merge($condition, array('subscriptionlog.status' => $vbulletin->GPC['status']));
	}
	//$condition = '1=1';
	//$condition .= iif($vbulletin->GPC['subscriptionid'], " AND subscriptionid=" . $vbulletin->GPC['subscriptionid']);
	//$condition .= ($vbulletin->GPC['status'] > -1) ? ' AND subscriptionlog.status = ' . $vbulletin->GPC['status'] : '';

	switch($vbulletin->GPC['orderby'])
	{
		case 'subscriptionid':
			//$orderby = 'subscriptionid, username';
			$orderby = array(
				'field' => array('subscriptionlog.subscriptionid', 'user.username'),
				'direction' => array(vB_dB_Query::SORT_ASC, vB_dB_Query::SORT_ASC)
			);
			break;
		case 'startdate':
			//$orderby = 'regdate';
			$orderby = array(
				'field' => array('subscriptionlog.regdate'),
				'direction' => array(vB_dB_Query::SORT_ASC)
			);
			break;
		case 'enddate':
			//$orderby = 'expirydate';
			$orderby = array(
				'field' => array('subscriptionlog.expirydate'),
				'direction' => array(vB_dB_Query::SORT_ASC)
			);
			break;
		case 'status':
			//$orderby = 'subscriptionlog.status, username';
			$orderby = array(
				'field' => array('subscriptionlog.status', 'user.username'),
				'direction' => array(vB_dB_Query::SORT_ASC, vB_dB_Query::SORT_ASC)
			);
			break;
		case 'username':
		default:
			$vbulletin->GPC['orderby'] = 'username';
			//$orderby = 'username';
			$orderby = array(
				'field' => array('user.username'),
				'direction' => array(vB_dB_Query::SORT_ASC)
			);
	}

	if (empty($vbulletin->GPC['limitstart']))
	{
		$vbulletin->GPC['limitstart'] = 0;
	}
	else
	{
		$vbulletin->GPC['limitstart']--;
	}

	if (empty($vbulletin->GPC['limitnumber']) OR $vbulletin->GPC['limitnumber'] == 0)
	{
		$vbulletin->GPC['limitnumber'] = 25;
	}

	$users = $assertor->assertQuery('vBForum:getSubscriptionUsersLog', array(
		'conditions' => $condition,
		vB_dB_Query::PARAM_LIMITSTART => $vbulletin->GPC['limitstart'],
		vB_dB_Query::PARAM_LIMIT => $vbulletin->GPC['limitnumber'],
		'sortby' => array($orderby)
	));

	$countusers = $assertor->getRow('vBForum:getSubscriptionUsersLog', array(
		'conditions' => $condition,
		'count' => true
	));

	if (!$countusers['users'])
	{
		print_stop_message2('no_matches_found_gerror');
	}
	else
	{
		$limitfinish = $vbulletin->GPC['limitstart'] + $vbulletin->GPC['limitnumber'];

		$subs = $assertor->getRows('vBForum:subscription', array(), 'subscriptionid');
		foreach ($subs AS $sub)
		{
			$subcache["{$sub['subscriptionid']}"] = htmlspecialchars_uni($vbphrase['sub' . $sub['subscriptionid'] . '_title']);
		}

		print_form_header('admincp/subscriptions', 'find');
		print_table_header(
			construct_phrase(
				$vbphrase['showing_subscriptions_x_to_y_of_z'],
				($vbulletin->GPC['limitstart'] + 1),
				iif($limitfinish > $countusers['users'], $countusers['users'], $limitfinish),
				$countusers[users]
				), 6);

		$addon  = "&amp;subscriptionid=" . $vbulletin->GPC['subscriptionid'];
		$addon .= "&amp;status=" . $vbulletin->GPC['status'];
		$addon .= "&amp;limitnumber=" . $vbulletin->GPC['limitnumber'];
		$addon .= "&amp;limitstart=" . $vbulletin->GPC['limitstart'];

		$headings = array();

		if ($vbulletin->GPC['orderby'] == 'subscriptionid')
		{
			$headings[] = $vbphrase['title'];
		}
		else
		{
			$headings[] = "<a href=\"admincp/subscriptions.php?" . vB::getCurrentSession()->get('sessionurl') . "do=find&amp;orderby=subscriptionid" . $addon . "\" title=\"" . $vbphrase['order_by_title'] . "\">" . $vbphrase['title'] . "</a>";
		}
		if ($vbulletin->GPC['orderby'] == 'username')
		{
			$headings[] = $vbphrase['username'];
		}
		else
		{
			$headings[] = "<a href=\"admincp/subscriptions.php?" . vB::getCurrentSession()->get('sessionurl') . "do=find&amp;orderby=username" . $addon . "\" title=\"" . $vbphrase['order_by_username'] . "\">" . $vbphrase['username'] . "</a>";
		}
		if ($vbulletin->GPC['orderby'] == 'startdate')
		{
			$headings[] = $vbphrase['start_date'];
		}
		else
		{
			$headings[] = "<a href=\"admincp/subscriptions.php?" . vB::getCurrentSession()->get('sessionurl') . "do=find&amp;orderby=startdate" . $addon . "\" title=\"" . $vbphrase['order_by_start_date'] . "\">" . $vbphrase['start_date'] . "</a>";
		}
		if ($vbulletin->GPC['orderby'] == 'enddate')
		{
			$headings[] = $vbphrase['end_date'];
		}
		else
		{
			$headings[] = "<a href=\"admincp/subscriptions.php?" . vB::getCurrentSession()->get('sessionurl') . "do=find&amp;orderby=enddate" . $addon . "\" title=\"" . $vbphrase['order_by_end_date'] . "\">" . $vbphrase['end_date'] . "</a>";
		}
		if ($vbulletin->GPC['orderby'] == 'status')
		{
			$headings[] = $vbphrase['status'];
		}
		else
		{
			$headings[] = "<a href=\"admincp/subscriptions.php?" . vB::getCurrentSession()->get('sessionurl') . "do=find&amp;orderby=status" . $addon . "\" title=\"" . $vbphrase['order_by_status'] . "\">" . $vbphrase['status'] . "</a>";
		}
		$headings[] = $vbphrase['controls'];

		print_cells_row($headings, 1);
		// now display the results
		foreach ($users AS $user)
		{
			$cell = array();
			$cell[] = $subcache["{$user['subscriptionid']}"];
			$cell[] = "<a href=\"admincp/user.php?" . vB::getCurrentSession()->get('sessionurl') . "do=edit&u=$user[userid]\"><b>$user[username]</b></a>&nbsp;";
			$cell[] = vbdate($vbulletin->options['dateformat'], $user['regdate']);
			$cell[] = vbdate($vbulletin->options['dateformat'], $user['expirydate']);
			$cell[] = iif($user['status'], $vbphrase['active_gsubscription'], $vbphrase['disabled']);
			$cell[] = construct_button_code($vbphrase['edit'], "admincp/subscriptions.php?" . vB::getCurrentSession()->get('sessionurl') . "do=adjust&subscriptionlogid=$user[subscriptionlogid]");
			print_cells_row($cell);
		}

		construct_hidden_code('subscriptionid', $vbulletin->GPC['subscriptionid']);
		construct_hidden_code('status', $vbulletin->GPC['status']);
		construct_hidden_code('limitnumber', $vbulletin->GPC['limitnumber']);
		construct_hidden_code('orderby', $vbulletin->GPC['orderby']);

		if ($vbulletin->GPC['limitstart'] == 0 AND $countusers['users'] > $vbulletin->GPC['limitnumber'])
		{
			construct_hidden_code('limitstart', $vbulletin->GPC['limitstart'] + $vbulletin->GPC['limitnumber'] + 1);
			print_submit_row($vbphrase['next_page'], 0, 6);
		}
		else if ($limitfinish < $countusers['users'])
		{
			construct_hidden_code('limitstart', $vbulletin->GPC['limitstart'] + $vbulletin->GPC['limitnumber'] + 1);
			print_submit_row($vbphrase['next_page'], 0, 6, $vbphrase['prev_page'], '', true);
		}
		else if ($vbulletin->GPC['limitstart'] > 0 AND $limitfinish >= $countusers['users'])
		{
			print_submit_row($vbphrase['first_page'], 0, 6, $vbphrase['prev_page'], '', true);
		}
		else
		{
			print_table_footer();
		}

	}
}

// ###################### Start status #######################
if ($_POST['do'] == 'status')
{
	$vbulletin->input->clean_array_gpc('p', array(
		'subscriptionlogid' => vB_Cleaner::TYPE_INT,
		'status'            => vB_Cleaner::TYPE_INT,
		'regdate'           => vB_Cleaner::TYPE_ARRAY_INT,
		'expirydate'        => vB_Cleaner::TYPE_ARRAY_INT,
		'username'          => vB_Cleaner::TYPE_NOHTML,
	));

	require_once(DIR . '/includes/functions_misc.php');
	$regdate = vbmktime($vbulletin->GPC['regdate']['hour'], $vbulletin->GPC['regdate']['minute'], 0, $vbulletin->GPC['regdate']['month'], $vbulletin->GPC['regdate']['day'], $vbulletin->GPC['regdate']['year']);
	$expirydate = vbmktime($vbulletin->GPC['expirydate']['hour'], $vbulletin->GPC['expirydate']['minute'], 0, $vbulletin->GPC['expirydate']['month'], $vbulletin->GPC['expirydate']['day'], $vbulletin->GPC['expirydate']['year']);

	if ($expirydate < 0 OR $expirydate <= $regdate)
	{
		print_stop_message2('invalid_subscription_length');
	}
	if ($vbulletin->GPC['userid'])
	{ // already existing entry
		if (!$vbulletin->GPC['status'])
		{
			$assertor->update('vBForum:subscriptionlog',
				array('regdate' => $regdate, 'expirydate' => $expirydate),
				array('userid' => $vbulletin->GPC['userid'], 'subscriptionid' => $vbulletin->GPC['subscriptionid'])
			);
			$subobj->delete_user_subscription($vbulletin->GPC['subscriptionid'], $vbulletin->GPC['userid']);
		}
		else
		{
			$subobj->build_user_subscription($vbulletin->GPC['subscriptionid'], -1, $vbulletin->GPC['userid'], $regdate, $expirydate, false);
		}
	}
	else
	{
		try
		{
			$userinfo = vB_Api::instanceInternal('user')->fetchByUsername($vbulletin->GPC['username']);
		}
		catch (vB_Exception_Api $ex)
		{
			$userinfo = false;
		}

		if (!$userinfo['userid'])
		{
			print_stop_message2('no_users_matched_your_query');
		}

		$subobj->build_user_subscription($vbulletin->GPC['subscriptionid'], -1, $userinfo['userid'], $regdate, $expirydate, false);

	}

	print_stop_message2(
		array(
			'saved_subscription_x_successfully',
			htmlspecialchars_uni($vbphrase['sub' . $vbulletin->GPC['subscriptionid'] . '_title'])
		),
		'subscriptions',
		array(
			'do' => 'find',
			'status' => -1,
			'subscriptionid' => $vbulletin->GPC['subscriptionid']
		)
	);
}

// ###################### Start status #######################
if ($_REQUEST['do'] == 'adjust')
{
	$vbulletin->input->clean_array_gpc('r', array(
		'subscriptionlogid' => vB_Cleaner::TYPE_INT
	));

	print_form_header('admincp/subscriptions', 'status');

	$subobj->cache_user_subscriptions();
	if (empty($subobj->subscriptioncache))
	{
		print_stop_message2(array('nosubscriptions',  $vbulletin->options['bbtitle']));
	}

	$sublist = array();
	$subPhraseVarnames = array();

	foreach ($subobj->subscriptioncache AS $key => $subscription)
	{
		if (empty($vbulletin->GPC['subscriptionid']) AND empty($sublist))
		{
			$vbulletin->GPC['subscriptionid'] = $subscription['subscriptionid'];
		}
		$subPhraseVarnames[] = 'sub' . $subscription['subscriptionid'] . '_title';
	}

	$subphrases = vB_Api::instanceInternal('phrase')->fetch($subPhraseVarnames);
	$vbphrase = array_merge($vbphrase, $subphrases);
	unset($subPhraseVarnames, $subphrases);

	foreach ($subobj->subscriptioncache AS $key => $subscription)
	{
		$sublist["$subscription[subscriptionid]"] = htmlspecialchars_uni($vbphrase['sub' . $subscription['subscriptionid'] . '_title']);
	}

	if ($vbulletin->GPC['subscriptionlogid'])
	{ // already exists
		$sub = $assertor->getRow('vBForum:getSubscriptionUsersLog', array('conditions' => array('subscriptionlogid' => $vbulletin->GPC['subscriptionlogid'])));
		print_table_header(construct_phrase($vbphrase['edit_subscription_for_x'], $sub['username']));
		construct_hidden_code('userid', $sub['userid']);
		$vbulletin->GPC['subscriptionid'] = $sub['subscriptionid'];
		print_select_row($vbphrase['subscription'], 'subscriptionid', $sublist, $vbulletin->GPC['subscriptionid']);
	}
	else
	{
		print_table_header($vbphrase['add_user']);
		$subinfo = $assertor->getRow('vBForum:subscription', array('subscriptionid' => $vbulletin->GPC['subscriptionid']));

		$cost_length = unserialize($subinfo['cost']);

		reset($cost_length);
		$first_sub = current($cost_length);
		if (!empty($first_sub['units']))
		{
			$expiry = $subobj->fetch_proper_expirydate(vB::getRequest()->getTimeNow(), $first_sub['length'], $first_sub['units']);
		}
		else
		{
			$expiry = vB::getRequest()->getTimeNow() + 60;
		}

		$sub = array(
			'regdate'    => vB::getRequest()->getTimeNow(),
			'status'     => 1,
			'expirydate' => $expiry
		);
		print_select_row($vbphrase['subscription'], 'subscriptionid', $sublist, $vbulletin->GPC['subscriptionid']);
		if ($vbulletin->GPC['userid'])
		{
			$userinfo = fetch_userinfo($vbulletin->GPC['userid']);
			if (!$userinfo)
			{
				print_stop_message2('invalid_user_specified');
			}
		}
		else
		{
			$userinfo = array('username' => '');
		}
		print_input_row($vbphrase['username'], 'username', $userinfo['username'], false);
	}

	print_time_row($vbphrase['start_date'], 'regdate', $sub['regdate']);
	print_time_row($vbphrase['expiry_date'], 'expirydate', $sub['expirydate']);
	if ($vbulletin->GPC['subscriptionlogid'])
	{
		print_radio_row($vbphrase['active_gsubscription'], 'status', array(
			0 => $vbphrase['no'],
			1 => $vbphrase['yes']
		), $sub['status'], 'smallfont');
	}
	print_submit_row();
}

// ###################### Start modify #######################
if ($_REQUEST['do'] == 'modify')
{

	$options = array(
		'edit' => $vbphrase['edit'],
		'remove' => $vbphrase['delete'],
		'view' => $vbphrase['view_users'],
		'addu' => $vbphrase['add_user']
	);

	?>
	<script type="text/javascript">
	function js_forum_jump(sid)
	{
		var action = eval("document.cpform.s" + sid + ".options[document.cpform.s" + sid + ".selectedIndex].value");
		if (action != '')
		{
			switch (action)
			{
				case 'edit': page = "admincp/subscriptions.php?do=edit&subscriptionid="; break;
				case 'remove': page = "admincp/subscriptions.php?do=remove&subscriptionid="; break;
				case 'view': page = "admincp/subscriptions.php?do=find&status=-1&subscriptionid="; break;
				case 'addu': page = "admincp/subscriptions.php?do=adjust&subscriptionid="; break;
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

	print_form_header('admincp/subscriptions', 'doorder');
	print_table_header($vbphrase['subscription_manager_gsubscription'], 6);
	print_cells_row(array($vbphrase['title'], $vbphrase['active_gsubscription'], $vbphrase['completed'], $vbphrase['total'], $vbphrase['display_order'], $vbphrase['controls']), 1, 'tcat', 1);
	$totals = $assertor->getRows('vBForum:getSubscriptionLogCount');
	foreach ($totals AS $total)
	{
		$t_cache["{$total['subscriptionid']}"] = $total['total'];
	}

	$totals = $assertor->getRows('vBForum:getActiveSubscriptionLogCount');
	foreach ($totals AS $total)
	{
		$ta_cache["{$total['subscriptionid']}"] = $total['total'];
	}

	$subobj->cache_user_subscriptions();
	if (is_array($subobj->subscriptioncache))
	{
		//fetching the title phrases separately because the new subscription titles don't get added immediately into the global $vbphrase array
		$titlePhrases = array();
		foreach ($subobj->subscriptioncache AS $key => $subscription)
		{
			$titlePhrases['sub' . $subscription['subscriptionid'] . '_title'] = 'sub' . $subscription['subscriptionid'] . '_title';
		}

		try
		{
			$titlePhrases = vB_Api::instanceInternal('phrase')->fetch($titlePhrases);
		}
		catch (Exception $e)
		{}

		foreach ($subobj->subscriptioncache AS $key => $subscription)
		{
			$cells = array();

			$subscription['title'] = htmlspecialchars_uni($titlePhrases['sub' . $subscription['subscriptionid'] . '_title']);
			if (!$subscription['active'])
			{
				$cells[] = "<em>$subscription[title]</em>";
			}
			else
			{
				$cells[] = "<strong>$subscription[title]</strong>";
			}

			// active
			$cells[] = iif(!$ta_cache["{$subscription['subscriptionid']}"], 0, "<a href=\"admincp/subscriptions.php?do=find&amp;subscriptionid=$subscription[subscriptionid]&amp;status=1\"><span style=\"color: green;\">" . $ta_cache["{$subscription['subscriptionid']}"] . "</span></a>");
			// completed
			$completed = intval($t_cache["{$subscription['subscriptionid']}"] - $ta_cache["{$subscription['subscriptionid']}"]);
			$cells[] = iif(!$completed, 0, "<a href=\"admincp/subscriptions.php?do=find&amp;subscriptionid=$subscription[subscriptionid]&amp;status=0\"><span style=\"color: red;\">" . $completed . "</span></a>");
			// total
			$cells[] = iif(!$t_cache["{$subscription['subscriptionid']}"], 0, "<a href=\"admincp/subscriptions.php?do=find&amp;subscriptionid=$subscription[subscriptionid]&amp;status=-1\">" . $t_cache["{$subscription['subscriptionid']}"] . "</a>");
			// display order
			$cells[] = "<input type=\"text\" class=\"bginput\" name=\"order[$subscription[subscriptionid]]\" value=\"$subscription[displayorder]\" tabindex=\"1\" size=\"3\" title=\"" . $vbphrase['edit_display_order'] . "\" />";
			// controls
			$cells[] = "\n\t<select name=\"s$subscription[subscriptionid]\" onchange=\"js_forum_jump($subscription[subscriptionid]);\" class=\"bginput\">\n" . construct_select_options($options) . "\t</select>\n\t<input type=\"button\" class=\"button\" value=\"" . $vbphrase['go'] . "\" onclick=\"js_forum_jump($subscription[subscriptionid]);\" />\n\t";
			print_cells_row($cells, 0, '', 1);
		}
	}
	print_table_footer(6, "<input type=\"submit\" class=\"button\" tabindex=\"1\" value=\"" . $vbphrase['save_subscription_manager'] . "\" accesskey=\"s\" />" . construct_button_code($vbphrase['add_new_subscription_gsubscription'], "admincp/subscriptions.php?" . vB::getCurrentSession()->get('sessionurl') . "do=add"));

}

// ###################### Start do order #######################
if ($_POST['do'] == 'doorder')
{
	$vbulletin->input->clean_array_gpc('p', array('order' => vB_Cleaner::TYPE_ARRAY));

	if (is_array($vbulletin->GPC['order']))
	{
		$subobj->cache_user_subscriptions();
		if (is_array($subobj->subscriptioncache) AND (!empty($vbulletin->GPC['order']) AND !empty($subobj->subscriptioncache)))
		{
			$assertor->assertQuery('vBForum:doSubscriptionLogOrder', array(
				'subscriptions' => $subobj->subscriptioncache,
				'displayorder' => $vbulletin->GPC['order']
			));
		}
	}

	print_stop_message2('saved_display_order_successfully', 'subscriptions', array('do'=>'modify'));
}

// ###################### Start Remove #######################
if ($_REQUEST['do'] == 'apirem')
{
	if (!vB::getUserContext()->hasAdminPermission('cansetserverconfig'))
	{
		print_cp_no_permission();
	}
	$vbulletin->input->clean_array_gpc('r', array(
		'paymentapiid' => vB_Cleaner::TYPE_INT
	));
	print_delete_confirmation('vBForum:paymentapi', $vbulletin->GPC['paymentapiid'], 'subscriptions', 'apikill', 'paymentapi', 0, '',  'title', 'paymentapiid');
}

// ###################### Start Kill #######################
if ($_POST['do'] == 'apikill')
{
	if (!vB::getUserContext()->hasAdminPermission('cansetserverconfig'))
	{
		print_cp_no_permission();
	}
	$vbulletin->input->clean_array_gpc('r', array(
		'paymentapiid' => vB_Cleaner::TYPE_INT
	));

	$assertor->delete('vBForum:paymentapi', array('paymentapiid' => $vbulletin->GPC['paymentapiid']));

	toggle_subs();

	print_stop_message2('deleted_paymentapi_successfully', 'subscriptions', array('do'=>'api'));

}

// ###################### Start Api Edit #######################
if ($_REQUEST['do'] == 'apiedit' OR $_REQUEST['do'] == 'apiadd')
{
	$vbulletin->input->clean_array_gpc('r', array(
		'paymentapiid' => vB_Cleaner::TYPE_INT
	));

	print_form_header('admincp/subscriptions', 'apiupdate');
	if ($_REQUEST['do'] == 'apiadd')
	{
		if (!vB::getUserContext()->hasAdminPermission('cansetserverconfig'))
		{
			print_cp_no_permission();
		}
		print_table_header($vbphrase['add_new_paymentapi']);
	}
	else
	{
		$api = $assertor->getRow('vBForum:paymentapi', array('paymentapiid' => $vbulletin->GPC['paymentapiid']));
		print_table_header(construct_phrase($vbphrase['x_y_id_z'], $vbphrase['paymentapi'], $api['title'], $api['paymentapiid']));
		construct_hidden_code('paymentapiid', $api['paymentapiid']);
	}

	print_input_row($vbphrase['title'], 'api[title]', $api['title']);
	print_radio_row($vbphrase['active_gsubscription'], 'api[active]', array(
		0 => $vbphrase['no'],
		1 => $vbphrase['yes']
	), $api['active'], 'smallfont');
	if ($vb5_config['Misc']['debug'])
	{
		print_input_row($vbphrase['classname'], 'api[classname]', $api['classname']);
		print_input_row($vbphrase['supported_currency'], 'api[currency]', $api['currency']);
		print_radio_row($vbphrase['supports_recurring'], 'api[recurring]', array(
			0 => $vbphrase['no'],
			1 => $vbphrase['yes']
		), $api['recurring'], 'smallfont');
	}
	else
	{
		print_label_row($vbphrase['classname'], $api['classname']);
		print_label_row($vbphrase['supported_currency'], $api['currency']);
		print_label_row($vbphrase['supports_recurring'], ($api['recurring'] ? $vbphrase['yes'] : $vbphrase['no']));
	}

	if ($_REQUEST['do'] == 'apiedit')
	{
		$settings = unserialize($api['settings']);
		if (is_array($settings))
		{
			// $info is an array
			foreach ($settings AS $key => $info)
			{
				print_description_row(
					'<div>' . $vbphrase["setting_{$api['classname']}_{$key}_title"] . '</div>',
					0, 2, 'optiontitle'
				);
				$name = "settings[$key]";
				$description = "<div class=\"smallfont\">" . $vbphrase["setting_{$api['classname']}_{$key}_desc"] . '</div>';
				switch ($info['type'])
				{
					case 'yesno':
					print_yes_no_row($description, $name, $info['value']);
					break;

					default:
					print_input_row($description, $name, $info['value'], 1, 40);
					break;
				}
			}
		}
	}

	print_submit_row(iif($_REQUEST['do'] == 'apiadd', $vbphrase['save'], $vbphrase['update']));
}

// ###################### Start Update #######################
if ($_POST['do'] == 'apiupdate')
{
	$vbulletin->input->clean_array_gpc('p', array(
		'api'			=> vB_Cleaner::TYPE_ARRAY,
		'settings'		=> vB_Cleaner::TYPE_ARRAY,
		'paymentapiid'	=> vB_Cleaner::TYPE_UINT,
	));

	$api =& $vbulletin->GPC['api'];

	if (!empty($vbulletin->GPC['paymentapiid']) AND !empty($vbulletin->GPC['settings']))
	{
		$currentinfo = $assertor->getRow('vBForum:paymentapi', array('paymentapiid' => $vbulletin->GPC['paymentapiid']));
		$settings = unserialize($currentinfo['settings']);
		$updatesettings = false;

		if (!vB::getUserContext()->hasAdminPermission('cansetserverconfig'))
		{
			//These should not be changed by the user. The api does not set these, but they could force through a manually created submit
			unset($vbulletin->GPC['settings']['classname']);
			unset($vbulletin->GPC['settings']['supported_currency']);
			unset($vbulletin->GPC['settings']['supports_recurring']);
		}

		foreach ($vbulletin->GPC['settings'] AS $key => $value)
		{

			if (isset($settings["$key"]) AND $settings["$key"]['value'] != $value)
			{
				switch ($settings["$key"]['validate'])
				{
					case 'number':
						$value += 0;
						break;
					case 'boolean':
						$value = $value ? 1 : 0;
						break;
					case 'string':
						$value = trim($value);
						break;
				}
				$settings["$key"]['value'] = $value;
				$updatesettings = true;
			}
		}
		if ($updatesettings)
		{
			$api['settings'] = serialize($settings);
		}
	}
	else
	{
		//This is an add
		if (!vB::getUserContext()->hasAdminPermission('cansetserverconfig'))
		{
			print_cp_no_permission();
		}
	}

	$api['title'] = htmlspecialchars_uni($api['title']);
	$api['active'] = intval($api['active']);

	if (isset($api['classname']))
	{
		$api['classname'] = preg_replace('#[^a-z0-9_]#i', '', $api['classname']);
		if (empty($api['classname']))
		{
			print_stop_message2('please_complete_required_fields');
		}
	}

	if (isset($api['currency']))
	{
		if (empty($api['currency']))
		{
			print_stop_message2('please_complete_required_fields');
		}
	}

	if (isset($api['recurring']))
	{
		$api['recurring'] = intval($api['recurring']);
	}

	if (empty($api['title']))
	{
		print_stop_message2('please_complete_required_fields');
	}

	if (empty($vbulletin->GPC['paymentapiid']))
	{
		/*insert query*/
		$queryParams = fetchQuerySql($api, 'paymentapi');
		$assertor->insert('vBForum:paymentapi', $queryParams['insert']);
	}
	else
	{
		$queryParams = fetchQuerySql($api, 'paymentapi', array('paymentapiid' => $vbulletin->GPC['paymentapiid']));
		$assertor->update('vBForum:paymentapi', $queryParams['set'], $queryParams['conditions']);
	}

	toggle_subs();

	print_stop_message2(array('saved_paymentapi_x_successfully',  $api['title']),'subscriptions', array('do'=>'api'));

}

// ###################### Start api #######################
if ($_REQUEST['do'] == 'api')
{

	$options = array(
		'edit' => $vbphrase['edit']
	);

	if ($vb5_config['Misc']['debug'] AND vB::getUserContext()->hasAdminPermission('cansetserverconfig'))
	{
		$options['remove'] = $vbphrase['delete'];
	}

	?>
	<script type="text/javascript">
	function js_forum_jump(pid)
	{
		var action = eval("document.cpform.p" + pid + ".options[document.cpform.p" + pid + ".selectedIndex].value");
		if (action != '')
		{
			switch (action)
			{
				case 'edit': page = "admincp/subscriptions.php?do=apiedit&paymentapiid="; break;
	<?php  	if ($vb5_config['Misc']['debug'] AND vB::getUserContext()->hasAdminPermission('cansetserverconfig'))
	{
		echo "case 'remove': page = \"admincp/subscriptions.php?do=apirem&paymentapiid=\"; break;";
	}
	?>

			}
			document.cpform.reset();
			jumptopage = page + pid + "&s=<?php echo vB::getCurrentSession()->get('sessionhash'); ?>";
			vBRedirect(jumptopage);
		}
		else
		{
			alert('<?php echo addslashes_js($vbphrase['invalid_action_specified_gcpglobal']); ?>');
		}
	}
	</script>
	<?php
	print_form_header('admincp/subscriptions');
	// PHRASE ME
	print_table_header($vbphrase['payment_api_manager'], 3);
	print_cells_row(array($vbphrase['title'], $vbphrase['active_gsubscription'], $vbphrase['controls']), 1, 'tcat', 1);
	$apis = $assertor->getRows('vBForum:paymentapi');

	$yesImage = get_cpstyle_href('cp_tick_yes.gif');
	$noImage = get_cpstyle_href('cp_tick_no.gif');
	foreach ($apis AS $api)
	{
		$cells = array();
		$cells[] = $api['title'];
		if ($api['active'])
		{
			$cells[] = "<img src=\"$yesImage\" alt=\"\" />";
		}
		else
		{
			$cells[] = "<img src=\"$noImage\" alt=\"\" />";
		}

		$cells[] = "\n\t<select name=\"p$api[paymentapiid]\" onchange=\"js_forum_jump($api[paymentapiid]);\" class=\"bginput\">\n" . construct_select_options($options) . "\t</select>\n\t<input type=\"button\" class=\"button\" value=\"" . $vbphrase['go'] . "\" onclick=\"js_forum_jump($api[paymentapiid]);\" />\n\t";
		print_cells_row($cells, 0, '', 1);
	}

	print_table_footer(3);
}

// ###################### Start find #######################
if ($_REQUEST['do'] == 'transdetails')
{
	$vbulletin->input->clean_array_gpc('r', array(
		'paymenttransactionid' => vB_Cleaner::TYPE_UINT,
	));

	if (!$payment = $assertor->getRow('vBForum:paymenttransaction', array('paymenttransactionid' => $vbulletin->GPC['paymenttransactionid'])))
	{
		print_stop_message2('no_matches_found_gerror');
	}

	$request = unserialize($payment['request']);
	if (empty($request['GET']) AND empty($request['POST']))
	{
		print_stop_message2('no_matches_found_gerror');
	}
	else
	{
		print_form_header('admincp/', '');

		print_table_header($vbphrase['transaction_details']);
		print_table_break();
		if (!empty($request['vb_error_code']))
		{
			print_table_header('API');
			print_label_row('vb_error_code', htmlspecialchars_uni($request['vb_error_code']));
		}
		if ($get = unserialize($request['GET']))
		{
			print_table_header('GET');
			foreach($get AS $key => $value)
			{
				print_label_row(htmlspecialchars_uni($key), htmlspecialchars_uni($value));
			}
		}
		if ($post = unserialize($request['POST']))
		{
			print_table_header('POST');
			foreach($post AS $key => $value)
			{
				print_label_row(htmlspecialchars_uni($key), htmlspecialchars_uni($value));
			}
		}
		print_table_footer();
	}
}

// ###################### Start find #######################
if ($_REQUEST['do'] == 'transactions')
{
	$vbulletin->input->clean_array_gpc('r', array(
		'state'          => vB_Cleaner::TYPE_INT,
		'orderby'        => vB_Cleaner::TYPE_NOHTML,
		'limitstart'     => vB_Cleaner::TYPE_INT,
		'limitnumber'    => vB_Cleaner::TYPE_INT,
		'paymentapiid'   => vB_Cleaner::TYPE_UINT,
		'transactionid'  => vB_Cleaner::TYPE_STR,
		'currency'       => vB_Cleaner::TYPE_NOHTML,
		'exact'          => vB_Cleaner::TYPE_BOOL,
		'start'          => vB_Cleaner::TYPE_ARRAY_UINT,
		'end'            => vB_Cleaner::TYPE_ARRAY_UINT,
		'type'           => vB_Cleaner::TYPE_NOHTML,
		'scope'          => vB_Cleaner::TYPE_NOHTML,
		'subscriptionid' => vB_Cleaner::TYPE_UINT,
		'userid'         => vB_Cleaner::TYPE_UINT,
		'username'       => vB_Cleaner::TYPE_NOHTML
	));

	$userinfo = array();
	if ($vbulletin->GPC['username'])
	{
		try
		{
			$userinfo = vB_Api::instanceInternal('user')->fetchByUsername($vbulletin->GPC['username']);
		}
		catch (vB_Exception_Api $ex)
		{
			print_stop_message2($ex->getMessage());
		}

		if (!$userinfo)
		{
			print_stop_message2('invalid_user_specified');
		}
	}
	else if ($vbulletin->GPC['userid'])
	{
		try
		{
			$userinfo = vB_Api::instanceInternal('user')->fetchUserinfo($vbulletin->GPC['userid']);
		}
		catch (vB_Exception_Api $ex)
		{
			print_stop_message2($ex->getMessage());
		}

		if (!$userinfo)
		{
			print_stop_message2('invalid_user_specified');
		}
	}

	if (empty($vbulletin->GPC['start']) AND !$vbulletin->GPC['transactionid'])
	{
		$vbulletin->GPC['start'] = vB::getRequest()->getTimeNow() - 3600 * 24 * 365;
	}

	if (empty($vbulletin->GPC['end']))
	{
		$vbulletin->GPC['end'] = vB::getRequest()->getTimeNow();
	}

	if (empty($vbulletin->GPC['limitstart']))
	{
		$vbulletin->GPC['limitstart'] = 0;
	}
	else
	{
		$vbulletin->GPC['limitstart']--;
	}

	if (empty($vbulletin->GPC['limitnumber']) OR $vbulletin->GPC['limitnumber'] == 0)
	{
		$vbulletin->GPC['limitnumber'] = 25;
	}

	$subobj->cache_user_subscriptions();
	$sublist = array('' => $vbphrase['all_subscriptions']);
	foreach ($subobj->subscriptioncache AS $key => $subscription)
	{
		if (empty($vbulletin->GPC['subscriptionid']) AND empty($sublist))
		{
			$vbulletin->GPC['subscriptionid'] = $subscription['subscriptionid'];
		}
		$sublist["$subscription[subscriptionid]"] = htmlspecialchars_uni($vbphrase['sub' . $subscription['subscriptionid'] . '_title']);
	}

	$apicache = array(0 => $vbphrase['all_processors']);
	// get the settings for all the API stuff
	$paymentapis = $assertor->getRows('vBForum:paymentapi', array(), 'title');
	foreach ($paymentapis AS $paymentapi)
	{
		$apicache["$paymentapi[paymentapiid]"] = $paymentapi['title'];
	}

	if (!$vbulletin->GPC['scope'])
	{
		$vbulletin->GPC['state'] = -1;
	}

	if ($vbulletin->GPC['type'] == 'stats')
	{
		switch ($vbulletin->GPC['orderby'])
		{
			case 'date_asc':
				$orderby = array(
					'field' => array('paymenttransaction.dateline'),
					'direction' => array(vB_dB_Query::SORT_ASC)
				);
				break;
			case 'total_asc':
				$orderby = array(
					'field' => array('aliasField.total'),
					'direction' => array(vB_dB_Query::SORT_ASC)
				);
				break;
			case 'total_desc':
				$orderby = array(
					'field' => array('aliasField.total'),
					'direction' => array(vB_dB_Query::SORT_DESC)
				);
				break;
			default:
				$orderby = array(
					'field' => array('paymenttransaction.dateline'),
					'direction' => array(vB_dB_Query::SORT_DESC)
				);
				$vbulletin->GPC['orderby'] = 'date_desc';
		}

		print_form_header('admincp/subscriptions', 'transactions');

		print_table_header($vbphrase['transaction_stats_gsubscription']);
		construct_hidden_code('type', 'stats');
		print_time_row($vbphrase['start_date'], 'start', $vbulletin->GPC['start'], false);
		print_time_row($vbphrase['end_date'], 'end', $vbulletin->GPC['end'], false);
		if (!empty($subobj->subscriptioncache))
		{
			print_select_row($vbphrase['subscription'], 'subscriptionid', $sublist, $vbulletin->GPC['subscriptionid']);
		}
		print_select_row($vbphrase['processor'], 'paymentapiid', $apicache, $vbulletin->GPC['paymentapiid']);
		print_select_row($vbphrase['currency'], 'currency', array(
			''    => $vbphrase['all_currency'],
			'usd' => $vbphrase['us_dollars'],
			'gbp' => $vbphrase['pounds_sterling'],
			'eur' => $vbphrase['euros'],
			'aud' => $vbphrase['aus_dollars'],
			'cad' => $vbphrase['cad_dollars'],
		), $vbulletin->GPC['currency']);
		print_select_row($vbphrase['type_gsubscription'], 'state', array(
			'-1'   => $vbphrase['all_types_gsubscription'],
			'0' => $vbphrase['failure'],
			'1'  => $vbphrase['charge'],
			'2'  => $vbphrase['reversal'],
		), $vbulletin->GPC['state']);
		print_select_row($vbphrase['scope'], 'scope', array('daily' => $vbphrase['daily'], 'weekly' => $vbphrase['weekly_gstats'], 'monthly' => $vbphrase['monthly']), $vbulletin->GPC['scope']);
		print_select_row($vbphrase['order_by_gcpglobal'], 'orderby', array(
			'date_asc'   => $vbphrase['date_ascending'],
			'date_desc'  => $vbphrase['date_descending'],
			'total_asc'  => $vbphrase['total_ascending'],
			'total_desc' => $vbphrase['total_descending'],
		), $vbulletin->GPC['orderby']);
		print_submit_row($vbphrase['go']);
	}

	if ($vbulletin->GPC['type'] == 'log')
	{
		switch($vbulletin->GPC['orderby'])
		{
			case 'amount':
				$orderby = array(
					'field' => array('paymenttransaction.amount'),
					'direction' => array(vB_dB_Query::SORT_ASC)
				);
				break;
			case 'transactionid':
				$orderby = array(
					'field' => array('paymenttransaction.transactionid'),
					'direction' => array(vB_dB_Query::SORT_ASC)
				);
				break;
			case 'username':
				$orderby = array(
					'field' => array('user.username'),
					'direction' => array(vB_dB_Query::SORT_ASC)
				);
				break;
			case 'paymentapiid':
				$orderby = array(
					'field' => array('paymenttransaction.paymentapiid'),
					'direction' => array(vB_dB_Query::SORT_ASC)
				);
				break;
			case 'dateline':
			default:
				$vbulletin->GPC['orderby'] = 'dateline';
				$orderby = array(
					'field' => array('paymenttransaction.dateline'),
					'direction' => array(vB_dB_Query::SORT_ASC)
				);
		}

		if (!$vbulletin->GPC['transactionid'])
		{
			print_form_header('admincp/subscriptions', 'transactions');
			print_table_header($vbphrase['transaction_log_gsubscription']);

			construct_hidden_code('type', 'log');
			construct_hidden_code('scope', 1);
			print_time_row($vbphrase['start_date'], 'start', $vbulletin->GPC['start'], false);
			print_time_row($vbphrase['end_date'], 'end', $vbulletin->GPC['end'], false);
			if (!empty($subobj->subscriptioncache))
			{
				print_select_row($vbphrase['subscription'], 'subscriptionid', $sublist, $vbulletin->GPC['subscriptionid']);
			}
			print_select_row($vbphrase['processor'], 'paymentapiid', $apicache, $vbulletin->GPC['paymentapiid']);
			print_select_row($vbphrase['currency'], 'currency', array(
				''    => $vbphrase['all_currency'],
				'usd' => $vbphrase['us_dollars'],
				'gbp' => $vbphrase['pounds_sterling'],
				'eur' => $vbphrase['euros'],
				'aud' => $vbphrase['aus_dollars'],
				'cad' => $vbphrase['cad_dollars'],
			), $vbulletin->GPC['currency']);
			print_select_row($vbphrase['type_gsubscription'], 'state', array(
				'-1'   => $vbphrase['all_types_gsubscription'],
				'0' => $vbphrase['failure'],
				'1'  => $vbphrase['charge'],
				'2'  => $vbphrase['reversal'],
			), $vbulletin->GPC['state']);
			print_input_row($vbphrase['username'], 'username', $userinfo['username'], false);
			print_select_row($vbphrase['order_by_gcpglobal'], 'orderby', array(
				'dateline'       => $vbphrase['date'],
				'amount'         => $vbphrase['amount_gsubscription'],
				'transactionid'  => $vbphrase['transactionid'],
				'username'       => $vbphrase['username'],
				'paymentapiid'   => $vbphrase['processor'],
			), $vbulletin->GPC['orderby']);
			print_submit_row($vbphrase['go']);
		}

		if ($vbulletin->GPC['transactionid'] OR !$vbulletin->GPC['scope'])
		{
  			print_form_header('admincp/subscriptions', 'transactions');
  			construct_hidden_code('type', 'log');
  			construct_hidden_code('scope', 1);
  			print_table_header($vbphrase['transaction_lookup']);
  			print_input_row($vbphrase['transactionid'], 'transactionid', $vbulletin->GPC['transactionid']);
  			print_yes_no_row($vbphrase['exact_match'], 'exact', empty($vbulletin->GPC['transactionid']) ? true : $vbulletin->GPC['exact']);
  			print_submit_row($vbphrase['go']);
  		}
	}

	$condition = array();
	$params = array();
	if (!$vbulletin->GPC['transactionid'])
	{
		$start_time = mktime(0, 0, 0, $vbulletin->GPC['start']['month'], $vbulletin->GPC['start']['day'], $vbulletin->GPC['start']['year']);
		$end_time = mktime(23, 59, 59, $vbulletin->GPC['end']['month'], $vbulletin->GPC['end']['day'], $vbulletin->GPC['end']['year']);
		if ($start_time > 0)
		{
			$params[vB_dB_Query::CONDITIONS_KEY][] = array('field' => 'paymenttransaction.dateline', 'value' => $start_time, vB_dB_Query::OPERATOR_KEY => vB_dB_Query::OPERATOR_GTE);
		}
		if ($end_time > 0)
		{
			$params[vB_dB_Query::CONDITIONS_KEY][] = array('field' => 'paymenttransaction.dateline', 'value' => $end_time, vB_dB_Query::OPERATOR_KEY => vB_dB_Query::OPERATOR_LTE);
		}
		if ($vbulletin->GPC['paymentapiid'])
		{
			$params[vB_dB_Query::CONDITIONS_KEY][] = array('field' => 'paymenttransaction.paymentapiid', 'value' => $vbulletin->GPC['paymentapiid'], vB_dB_Query::OPERATOR_KEY => vB_dB_Query::OPERATOR_EQ);
		}
		if ($vbulletin->GPC['currency'])
		{
			$params[vB_dB_Query::CONDITIONS_KEY][] = array('field' => 'paymenttransaction.currency', 'value' => $vbulletin->GPC['currency'], vB_dB_Query::OPERATOR_KEY => vB_dB_Query::OPERATOR_EQ);
		}
		if ($vbulletin->GPC['subscriptionid'])
		{
			$params[vB_dB_Query::CONDITIONS_KEY][] = array('field' => 'paymentinfo.subscriptionid', 'value' => $vbulletin->GPC['subscriptionid'], vB_dB_Query::OPERATOR_KEY => vB_dB_Query::OPERATOR_EQ);
		}
		if ($userinfo['userid'])
		{
			$params[vB_dB_Query::CONDITIONS_KEY][] = array('field' => 'paymentinfo.userid', 'value' => $userinfo['userid'], vB_dB_Query::OPERATOR_KEY => vB_dB_Query::OPERATOR_EQ);
		}

		if ($vbulletin->GPC['state'] >= 0)
		{
			$params[vB_dB_Query::CONDITIONS_KEY][] = array('field' => 'paymenttransaction.state', 'value' => $vbulletin->GPC['state'], vB_dB_Query::OPERATOR_KEY => vB_dB_Query::OPERATOR_EQ);
		}
	}
	else
	{
		if ($vbulletin->GPC['exact'])
		{
			$params[vB_dB_Query::CONDITIONS_KEY][] = array('field' => 'paymenttransaction.transactionid', 'value' => $vbulletin->GPC['transactionid'], vB_dB_Query::OPERATOR_KEY => vB_dB_Query::OPERATOR_EQ);
		}
		else
		{
			$params[vB_dB_Query::CONDITIONS_KEY][] = array('field' => 'paymenttransaction.transactionid', 'value' => $vbulletin->GPC['transactionid'], vB_dB_Query::OPERATOR_KEY => vB_dB_Query::OPERATOR_INCLUDES);
		}
	}

	$params['sortby'] = array($orderby);
	if ($vbulletin->GPC['type'] == 'stats')
	{
		if ($vbulletin->GPC['scope'])
		{
			switch ($vbulletin->GPC['scope'])
			{
				case 'weekly':
					$sqlformat = '%U %Y';
					$phpformat = '# (! Y)';
					break;
				case 'monthly':
					$sqlformat = '%m %Y';
					$phpformat = '! Y';
					break;
				case 'daily':
					$sqlformat = '%w %U %m %Y';
					$phpformat = '! d, Y';
					break;
				default:
			}
			$params['sqlformat'] = $sqlformat;
			$statistics = $assertor->getRows('vBForum:getTransactionStats', $params);

			$results = array();
			foreach ($statistics AS $stats)
			{
				$month = strtolower(date('F', $stats['dateline']));
				$dates[] = str_replace(' ', '&nbsp;', str_replace('#', $vbphrase['week'] . '&nbsp;' . strftime('%U', $stats['dateline']), str_replace('!', $vbphrase["$month"], date($phpformat, $stats['dateline']))));
				$results[] = $stats['total'];
			}

			if (!sizeof($results))
			{
				print_stop_message2('no_matches_found_gerror');
			}

			// we'll need a poll image
			$style = $assertor->getRow('vBForum:style', array('styleid' => $vbulletin->options['styleid']));
			$vbulletin->stylevars = unserialize($style['newstylevars']);
			fetch_stylevars($style, $vbulletin->userinfo);

			print_form_header('admincp/');
			print_table_header($vbphrase['results'], 3);
			print_cells_row(array($vbphrase['date'], '&nbsp;', $vbphrase['total']), 1);
			$maxvalue = max($results);
			foreach ($results as $key => $value)
			{
				$i++;
				$bar = ($i % 6) + 1;
				if ($maxvalue == 0)
				{
					$percentage = 100;
				}
				else
				{
					$percentage = ceil(($value/$maxvalue) * 100);
				}
				print_statistic_result($dates["$key"], $bar, $value, $percentage);
			}
			print_table_footer(3);
		}
	}
	else
	{
		if ($vbulletin->GPC['scope'])
		{
			$counttrans = $assertor->getRow('vBForum:getTransactionLogCount', $params);

			$params[vB_dB_Query::PARAM_LIMIT] = $vbulletin->GPC['limitstart'];
			$params[vB_dB_Query::PARAM_LIMITSTART] = $vbulletin->GPC['limitnumber'];

			$trans = $assertor->getRows('vBForum:getTransactionLog', $params);

			if (!$counttrans['trans'])
			{
				print_stop_message2('no_matches_found_gerror');
			}
			else
			{
				$limitfinish = $vbulletin->GPC['limitstart'] + $vbulletin->GPC['limitnumber'];

				print_form_header('admincp/subscriptions', 'transactions');
				print_table_header(
					construct_phrase(
						$vbphrase['showing_transactions_x_to_y_of_z'],
						($vbulletin->GPC['limitstart'] + 1),
						iif($limitfinish > $counttrans['trans'], $counttrans['trans'], $limitfinish),
						$counttrans[trans]
					),
					7
				);
				$addon = '&amp;limitnumber=' . $vbulletin->GPC['limitnumber'];
				$addon .= $vbulletin->GPC['limitstart'] ? '&amp;limitstart=' . $vbulletin->GPC['limitstart'] : '';
				$addon .= '&amp;start[month]=' .  $vbulletin->GPC['start']['month'];
				$addon .= '&amp;start[day]=' . $vbulletin->GPC['start']['day'];
				$addon .= '&amp;start[year]=' . $vbulletin->GPC['start']['year'];
				$addon .= '&amp;end[month]=' . $vbulletin->GPC['end']['month'];
				$addon .= '&amp;end[day]=' . $vbulletin->GPC['end']['day'];
				$addon .= '&amp;end[year]=' . $vbulletin->GPC['end']['year'];
				$addon .= '&amp;scope=1';
				$addon .= $vbulletin->GPC['transactionid'] ? '&amp;transactionid=' . urlencode($vbulletin->GPC['transactionid']) : '';
				$addon .= $vbulletin->GPC['paymentapiid'] ? '&amp;paymentapiid=' . $vbulletin->GPC['paymentapiid'] : '';
				$addon .= $vbulletin->GPC['type'] ? '&amp;type=' . $vbulletin->GPC['type'] : '';
				$addon .= $vbulletin->GPC['currency'] ? '&amp;currency=' . $vbulletin->GPC['currency'] : '';
				$addon .= $vbulletin->GPC['subscriptionid'] ? '&amp;subscriptionid=' . $vbulletin->GPC['subscriptionid'] : '';
				$addon .= '&amp;state=' . $vbulletin->GPC['state'];
				$addon .= $userinfo['userid'] ? '&amp;userid=' . $userinfo['userid'] : '';

				$headings = array();
				#API
				if ($vbulletin->GPC['orderby'] == 'paymentapiid')
				{
					$headings[] = $vbphrase['processor'];
				}
				else
				{
					$headings[] = "<a href=\"admincp/subscriptions.php?" . vB::getCurrentSession()->get('sessionurl') . "do=transactions&amp;orderby=paymentapiid" . $addon . "\" title=\"" . $vbphrase['order_by_api'] . "\">" . $vbphrase['processor'] . "</a>";
				}
				#Date
				if ($vbulletin->GPC['orderby'] == 'dateline')
				{
					$headings[] = $vbphrase['date'];
				}
				else
				{
					$headings[] = "<a href=\"admincp/subscriptions.php?" . vB::getCurrentSession()->get('sessionurl') . "do=transactions&amp;orderby=dateline" . $addon . "\" title=\"" . $vbphrase['order_by_date'] . "\">" . $vbphrase['date'] . "</a>";
				}
				#Transactionid
				if ($vbulletin->GPC['orderby'] == 'transactionid')
				{
					$headings[] = $vbphrase['transactionid'];
				}
				else
				{
					$headings[] = "<a href=\"admincp/subscriptions.php?" . vB::getCurrentSession()->get('sessionurl') . "do=transactions&amp;orderby=transactionid" . $addon . "\" title=\"" . $vbphrase['order_by_transactionid'] . "\">" . $vbphrase['transactionid'] . "</a>";
				}
				#Amount
				if ($vbulletin->GPC['orderby'] == 'amount')
				{
					$headings[] = $vbphrase['amount_gsubscription'];
				}
				else
				{
					$headings[] = "<a href=\"admincp/subscriptions.php?" . vB::getCurrentSession()->get('sessionurl') . "do=transactions&amp;orderby=amount" . $addon . "\" title=\"" . $vbphrase['order_by_amount'] . "\">" . $vbphrase['amount_gsubscription'] . "</a>";
				}
				#Username
				if ($vbulletin->GPC['orderby'] == 'username')
				{
					$headings[] = $vbphrase['username'];
				}
				else
				{
					$headings[] = "<a href=\"admincp/subscriptions.php?" . vB::getCurrentSession()->get('sessionurl') . "do=transactions&amp;orderby=username" . $addon . "\" title=\"" . $vbphrase['order_by_username'] . "\">" . $vbphrase['username'] . "</a>";
				}
				$headings[] = $vbphrase['subscription'];
				$headings[] = $vbphrase['type_gsubscription'];

				print_cells_row($headings, 1);
				// now display the results
				foreach ($trans AS $tran)
				{
					$cell = array();
					$cell[] = $tran['title'] ? $tran['title'] : '-';
					$cell[] = vbdate($vbulletin->options['logdateformat'], $tran['dateline']);
					$cell[] = $tran['transactionid'] ? htmlspecialchars_uni($tran['transactionid']) : '-';
					$cell[] = $tran['state'] ? htmlspecialchars_uni(vb_number_format($tran['amount'], 2) . ' ' . strtoupper($tran['currency'])) : '-';
					$cell[] = $tran['username'] ? "<a href=\"admincp/user.php?" . vB::getCurrentSession()->get('sessionurl') . "do=edit&u=$tran[userid]\"><b>$tran[username]</b></a>&nbsp;" : '-';
					$cell[] = $tran['subscriptionid'] ? $vbphrase['sub' . $tran['subscriptionid'] . '_title'] : '-';
					if ($tran['state'] == 0)
					{
						$cell[] = construct_link_code($vbphrase['failure'], "subscriptions.php?do=transdetails&amp;paymenttransactionid=$tran[paymenttransactionid]" . vB::getCurrentSession()->get('sessionurl'));
					}
					else if ($tran['state'] == 1)
					{
						$cell[] = $vbphrase['charge'];
					}
					else if ($tran['state'] == 2)
					{
						$cell[] = $vbphrase['reversal'];
					}
					else
					{
						$cell[] = $vbphrase['n_a'];
					}
					print_cells_row($cell);
				}

				construct_hidden_code('paymentapiid', $vbulletin->GPC['paymentapiid']);
				construct_hidden_code('transactionid', $vbulletin->GPC['transactionid']);
				construct_hidden_code('limitnumber', $vbulletin->GPC['limitnumber']);
				construct_hidden_code('orderby', $vbulletin->GPC['orderby']);
				construct_hidden_code('start[month]', $vbulletin->GPC['start']['month']);
				construct_hidden_code('start[day]', $vbulletin->GPC['start']['day']);
				construct_hidden_code('start[year]', $vbulletin->GPC['start']['year']);
				construct_hidden_code('end[month]', $vbulletin->GPC['end']['month']);
				construct_hidden_code('end[day]', $vbulletin->GPC['end']['day']);
				construct_hidden_code('end[year]', $vbulletin->GPC['end']['year']);
				construct_hidden_code('currency', $vbulletin->GPC['currency']);
				construct_hidden_code('type', $vbulletin->GPC['type']);
				construct_hidden_code('subscriptionid', $vbulletin->GPC['subscriptionid']);
				construct_hidden_code('state', $vbulletin->GPC['state']);
				construct_hidden_code('userid', $userinfo['userid']);
				construct_hidden_code('scope', 1);

				if ($vbulletin->GPC['limitstart'] == 0 AND $counttrans['trans'] > $vbulletin->GPC['limitnumber'])
				{
					construct_hidden_code('limitstart', $vbulletin->GPC['limitstart'] + $vbulletin->GPC['limitnumber'] + 1);
					print_submit_row($vbphrase['next_page'], 0, 7);
				}
				else if ($limitfinish < $counttrans['trans'])
				{
					construct_hidden_code('limitstart', $vbulletin->GPC['limitstart'] + $vbulletin->GPC['limitnumber'] + 1);
					print_submit_row($vbphrase['next_page'], 0, 7, $vbphrase['prev_page'], '', true);
				}
				else if ($vbulletin->GPC['limitstart'] > 0 AND $limitfinish >= $counttrans['trans'])
				{
					print_submit_row($vbphrase['first_page'], 0, 7, $vbphrase['prev_page'], '', true);
				}
				else
				{
					print_table_footer();
				}
			}
		}
	}
}

print_cp_footer();

// ###################### Start toggle_subs #######################
// Function disables subs if there isn't an active API or active SUB (and vice versa)
function toggle_subs()
{
	$assertor = vB::getDbAssertor();

	// bit of a hack, will most likely change this to a datastore item in the future
	$setting = 0;
	if ($check = $assertor->getRow('vBForum:paymentapi', array('active' => 1)))
	{
		if ($check = $assertor->getRow('vBForum:subscription', array('active' => 1)))
		{
			$setting = 1;
		}
	}

	if ($setting != vB::getDatastore()->getOption('subscriptionmethods'))
	{
		// update $vboptions
		$assertor->update('setting', array('value' => $setting), array('varname' => 'subscriptionmethods'));
		vB::getDatastore()->build_options();
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 101129 $
|| #######################################################################
\*=========================================================================*/
