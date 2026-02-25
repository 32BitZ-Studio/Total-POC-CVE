<?php

add_filter("wcsearch_get_count_num_args", "wc_get_count_num_args");
function wc_get_count_num_args($args) {

	if ($count_params_post = wcsearch_getValue($_POST, "count_params")) {
		$count_params_array = array();
		foreach ($count_params_post AS $param) {
			if (strpos($param['name'], '[]') !== false) {
				$name = str_replace("[]", "", $param['name']);
				$count_params_array[$name][] = $param['value'];
			} else {
				$name = $param['name'];
				$count_params_array[$name] = $param['value'];
			}
		}

		if ($count_params_array) {
			$args = array_merge($args, array_filter($count_params_array));
				
			$taxonomies = wc_get_taxonomies();
			foreach ($taxonomies AS $tax_name=>$tax_slug) {
				if (empty($args['taxonomies'][$tax_name]) && !empty($count_params_array[$tax_slug])) {
					$args['taxonomies'][$tax_name] = wcsearch_get_tax_terms_from_args($tax_slug, $count_params_array);
				}
			}
		}
	}

	return $args;
}

add_filter("wcsearch_get_taxonomies", "wc_get_taxonomies");
function wc_get_taxonomies($taxonomies = array()) {
	
	if (wcsearch_is_woo_active()) {
		$taxonomies['product_cat'] = 'product_cat';
		$taxonomies['product_tag'] = 'product_tag';
	
		$wc_attribute_taxonomies = wc_get_attribute_taxonomies();
		foreach ($wc_attribute_taxonomies AS $taxonomy) {
			$tax_name = wc_attribute_taxonomy_name($taxonomy->attribute_name);
	
			$taxonomies[$tax_name] = $tax_name;
		}
	}
	
	return $taxonomies;
}

add_filter("wcsearch_get_taxonomies_names", "wc_get_taxonomies_names");
function wc_get_taxonomies_names($taxonomies_names = array()) {
	
	if (wcsearch_is_woo_active()) {
		$taxonomies_names['product_cat'] = esc_html__("Product categories", "WCSEARCH");
		$taxonomies_names['product_tag'] = esc_html__("Product tags", "WCSEARCH");
	
		$wc_attribute_taxonomies = wc_get_attribute_taxonomies();
		foreach ($wc_attribute_taxonomies AS $taxonomy) {
			$tax_name = wc_attribute_taxonomy_name($taxonomy->attribute_name);
	
			$taxonomies_names[$tax_name] = $taxonomy->attribute_label;
		}
	}
	
	return $taxonomies_names;
}

add_filter("wcsearch_query_class_name", "wc_query_class_name", 10, 2);
function wc_query_class_name($class_name, $used_by) {

	if ($used_by == 'wc') {
		$class_name = "wcsearch_query";
	}

	return $class_name;
}

add_filter("wcsearch_adapter_options", "wc_adapter_options");
function wc_adapter_options($options) {
	
	$options['wc'] = array(
			'loop_selector_name' => 'wcsearch-woo-loop',
			'submit_callback' => 'wcsearch_submit_request',
			'keywords_search_action' => 'wcsearch_keywords_search',
	);
	
	return $options;
}

add_filter("wcsearch_get_used_by_by_tax", "wc_get_used_by_by_tax", 10, 2);
function wc_get_used_by_by_tax($used_by, $tax) {
	
	$taxes = wc_get_taxonomies();
	
	if (isset($taxes[$tax])) {
		$used_by = 'wc';
	}

	return $used_by;
}

add_filter("wcsearch_allowed_params", "wc_allowed_params");
function wc_allowed_params($allowed_params) {
	
	$allowed_params = array(
			'keywords',
			'orderby',
			'page',
			'ratings',
			'more_filters',
			'address',
			'place_id',
			'radius',
	);
	
	if (wcsearch_is_woo_active()) {
		$allowed_params[] = 'price';
		$allowed_params[] = 'product_cat';
		$allowed_params[] = 'product_cat_relation';
		$allowed_params[] = 'product_tag';
		$allowed_params[] = 'product_tag_relation';
		$allowed_params[] = 'featured';
		$allowed_params[] = 'onsale';
		$allowed_params[] = 'instock';
		
		$wc_attribute_taxonomies = wc_get_attribute_taxonomies();
		foreach ($wc_attribute_taxonomies AS $taxonomy) {
			$tax_name = wc_attribute_taxonomy_name($taxonomy->attribute_name);
		
			$allowed_params[] = $tax_name;
			$allowed_params[] = $tax_name . '_relation';
		}
	}
	
	return $allowed_params;
}

add_filter("wcsearch_get_model_fields", "wc_get_model_fields", 10, 2);
function wc_get_model_fields($model_fields, $used_by) {
	
	if ($used_by != 'wc') {
		return $model_fields;
	}
	
	if (wcsearch_is_woo_active()) {
		$model_fields = array(
				array(
						'name' => 'Keywords',
						'type' => 'keywords',
						'slug' => 'keywords',
						'icon' => 'wcsearch-fa-search',
				),
				array(
						'name' => 'Price',
						'type' => 'price',
						'slug' => 'price',
						'icon' => 'wcsearch-fa-usd',
						'values' => '',
				),
				array(
						'name' => 'Product categories',
						'type' => 'tax',
						'tax' => 'product_cat',
						'slug' => 'product_cat',
						'icon' => 'wcsearch-fa-bars',
						'values' => '',
				),
				array(
						'name' => 'Product tags',
						'type' => 'tax',
						'tax' => 'product_tag',
						'slug' => 'product_tag',
						'icon' => 'wcsearch-fa-bars',
						'values' => '',
				),
				array(
						'name' => 'Search button',
						'type' => 'button',
						'slug' => 'submit',
						'icon' => 'wcsearch-fa-sign-in',
				),
				array(
						'name' => 'Reset button',
						'type' => 'reset',
						'slug' => 'reset',
						'icon' => 'wcsearch-fa-eraser',
				),
				array(
						'name' => 'More filters',
						'type' => 'more_filters',
						'slug' => 'more_filters',
						'icon' => 'wcsearch-fa-chevron-down',
				),
				array(
						'name' => 'Featured checkbox',
						'type' => 'featured',
						'slug' => 'featured',
						'icon' => 'wcsearch-fa-check-square-o ',
						'values' => '',
				),
				array(
						'name' => 'InStock checkbox',
						'type' => 'instock',
						'slug' => 'instock',
						'icon' => 'wcsearch-fa-check-square-o ',
						'values' => '',
				),
				array(
						'name' => 'OnSale checkbox',
						'type' => 'onsale',
						'slug' => 'onsale',
						'icon' => 'wcsearch-fa-check-square-o ',
						'values' => '',
				),
				array(
						'name' => 'Ratings checkboxes',
						'type' => 'ratings',
						'slug' => 'ratings',
						'icon' => 'wcsearch-fa-check-square-o ',
						'values' => '',
				),
		);
	}
	
	return $model_fields;
}

add_filter("wcsearch_get_model_fields", "wc_filter_model_fields", 11, 2);
function wc_filter_model_fields($model_fields, $used_by) {
	
	if ($used_by != 'wc') {
		return $model_fields;
	}
	
	if (wcsearch_is_woo_active()) {
		foreach ($model_fields AS $key=>$field) {
			if ($field['type'] == 'tax') {
				if (!taxonomy_exists($field['tax'])) {
					unset($model_fields[$key]);
				}
			}
		}
		
		if (function_exists('wc_get_attribute_taxonomies')) {
			$wc_attribute_taxonomies = wc_get_attribute_taxonomies();
			foreach ($wc_attribute_taxonomies AS $taxonomy) {
				$model_fields[] = array(
						'name' => $taxonomy->attribute_label,
						'type' => 'tax',
						'tax' => wc_attribute_taxonomy_name($taxonomy->attribute_name),
						'slug' => wc_attribute_taxonomy_name($taxonomy->attribute_name),
						'icon' => 'wcsearch-fa-search',
						'values' => '',
				);
			}
		}
		
		// add address and radius fields
		if (wcsearch_geocode_functions()) {
			$model_fields[] = array(
					'name' => 'Address',
					'type' => 'address',
					'slug' => 'address',
					'icon' => 'wcsearch-fa-map-marker ',
					'values' => '',
			);
				
			$model_fields[] = array(
					'name' => 'Radius',
					'type' => 'radius',
					'slug' => 'radius',
					'icon' => 'wcsearch-fa-location-arrow ',
					'values' => '',
			);
		}
	}
	
	return $model_fields;
}

add_filter("wcsearch_get_min_max_numbers", "wc_get_min_max_numbers", 10, 3);
function wc_get_min_max_numbers($vals, $used_by, $slug) {
	
	if ($used_by == 'wc') {
		global $wpdb;
		
		$vals = $wpdb->get_row("SELECT MIN(CONVERT(pm.meta_value, UNSIGNED INTEGER)) AS min, MAX(CONVERT(pm.meta_value, UNSIGNED INTEGER)) AS max FROM {$wpdb->postmeta} AS pm WHERE pm.meta_key = '_price' ");
	}
	
	return $vals;
}

add_filter("wcsearch_price_format", "wc_price_format", 10, 3);
function wc_price_format($value, $used_by, $slug) {
	
	if (wcsearch_is_woo_active() && $used_by == 'wc') {
		$value = wc_price($value, array('decimals' => 0));
	}
	
	return $value;
}

?>