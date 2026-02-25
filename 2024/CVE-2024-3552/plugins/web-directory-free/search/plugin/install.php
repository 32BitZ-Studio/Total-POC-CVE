<?php 

function wcsearch_install_search() {
	global $wpdb;
	
	if (!get_option('wcsearch_installed_search')) {
		
		$wpdb->query("
				CREATE TABLE {$wpdb->wcsearch_cache} (
					`hash` varchar(64) NOT NULL,
					`val` text NOT NULL,
					KEY `hash` (`hash`)
				) ENGINE=InnoDB  DEFAULT CHARSET=utf8 ;");
	
		add_option('wcsearch_installed_search', true);
		add_option('wcsearch_installed_search_version', WCSEARCH_VERSION);
		add_option('wcsearch_force_include_js_css', false);
		
	} elseif (get_option('wcsearch_installed_search_version') != WCSEARCH_VERSION) {
		$upgrades_list = array(
				'1.0.1',
				'1.0.6',
				'1.2.3',
				'1.2.5',
		);

		$old_version = get_option('wcsearch_installed_search_version');
		foreach ($upgrades_list AS $upgrade_version) {
			if (!$old_version || version_compare($old_version, $upgrade_version, '<')) {
				$upgrade_function_name = 'wcsearch_upgrade_to_' . str_replace('.', '_', $upgrade_version);
				if (function_exists($upgrade_function_name))
					$upgrade_function_name();
				do_action('wcsearch_version_upgrade', $upgrade_version);
			}
		}

		update_option('wcsearch_installed_search_version', WCSEARCH_VERSION);
		
		echo '<script>location.reload();</script>';
		exit;
	}
	
	global $wcsearch_instance;
	$wcsearch_instance->loadClasses();
}

function wcsearch_upgrade_to_1_0_1() {
	global $wpdb;
	
	$wpdb->query("CREATE TABLE {$wpdb->wcsearch_cache} (
			`hash` varchar(64) NOT NULL,
			`val` text NOT NULL,
			KEY `hash` (`hash`)
			) ENGINE=InnoDB  DEFAULT CHARSET=utf8 ;");
}

function wcsearch_upgrade_to_1_0_6() {
	add_option('wcsearch_force_include_js_css', false);
}

function wcsearch_upgrade_to_1_2_3() {
	global $wpdb;
	
	$models = $wpdb->get_results("
			SELECT meta_id, meta_value FROM {$wpdb->postmeta}
			WHERE
			meta_key = '_model'
			", ARRAY_A);
	
	foreach ($models AS $model) {
		$meta_value = json_decode($model['meta_value']);
	
		if (!empty($meta_value->placeholders)) {
			foreach ($meta_value->placeholders AS $key=>$placeholder) {
				if (!empty($meta_value->placeholders[$key]->input->suggestions)) {
					if (!empty($meta_value->placeholders[$key]->input->type) && (($meta_value->placeholders[$key]->input->type == 'tax' && $placeholder->input->mode == 'dropdown_address') || ($meta_value->placeholders[$key]->input->type == 'address'))) {
						$meta_value->placeholders[$key]->input->address_suggestions = $meta_value->placeholders[$key]->input->suggestions;
						unset($meta_value->placeholders[$key]->input->suggestions);
					}
					if (!empty($meta_value->placeholders[$key]->input->type) && (($meta_value->placeholders[$key]->input->type == 'tax' && $placeholder->input->mode == 'dropdown_keywords') || ($meta_value->placeholders[$key]->input->type == 'keywords'))) {
						$meta_value->placeholders[$key]->input->keywords_suggestions = $meta_value->placeholders[$key]->input->suggestions;
						unset($meta_value->placeholders[$key]->input->suggestions);
					}
				}
			}
			$meta_value = json_encode($meta_value);
		}
		
		$wpdb->update($wpdb->postmeta, array('meta_value' => $meta_value), array('meta_id' => $model['meta_id']));
	}
}

function wcsearch_upgrade_to_1_2_5() {
	update_option('wcsearch_force_include_js_css', false);
}

?>