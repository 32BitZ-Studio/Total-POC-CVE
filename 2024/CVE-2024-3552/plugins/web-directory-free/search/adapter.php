<?php 

include_once W2DC_PATH . 'search/plugin/search.php';
include_once W2DC_PATH . 'search/query.php';
include_once W2DC_PATH . 'search/filters/directory.php';
include_once W2DC_PATH . 'search/filters/number.php';
include_once W2DC_PATH . 'search/filters/tax.php';
include_once W2DC_PATH . 'search/filters/ratings.php';
include_once W2DC_PATH . 'search/filters/perpage.php';
include_once W2DC_PATH . 'search/filters/author.php';
include_once W2DC_PATH . 'search/filters/post_in.php';
include_once W2DC_PATH . 'search/filters/post_not_in.php';
include_once W2DC_PATH . 'search/filters/address.php';
include_once W2DC_PATH . 'search/filters/date.php';
include_once W2DC_PATH . 'search/filters/string.php';
include_once W2DC_PATH . 'search/filters/keywords.php';
include_once W2DC_PATH . 'search/filters/hours.php';


function w2dc_get_search_fields() {
	global $w2dc_instance, $w2dc_search_fields;
	
	// cache search fields
	if ($w2dc_search_fields) {
		return $w2dc_search_fields;
	}
	
	$search_fields = array();
	
	foreach ($w2dc_instance->content_fields->content_fields_array AS $content_field) {
		if ($content_field->canBeSearched()) {
			$search_field = new stdClass();
			$search_field->content_field = $content_field;
			$search_fields[$content_field->slug] = $search_field;
		}
	}
	
	$w2dc_search_fields = $search_fields;
	
	return $search_fields;
}

add_filter("wcsearch_get_taxonomies", "w2dc_get_taxonomies");
function w2dc_get_taxonomies($taxonomies = array()) {
	
	$taxonomies['w2dc-category'] = 'categories';
	$taxonomies['w2dc-location'] = 'locations';
	$taxonomies['w2dc-tag']      = 'tags';
	
	$search_fields = w2dc_get_search_fields();
	
	foreach ($search_fields AS $search_field) {
		if (in_array($search_field->content_field->type, array("select", "checkbox", "radio"))) {
			$taxonomies[$search_field->content_field->slug] = $search_field->content_field->slug;
		} else {
			
		}
	}
	
	return $taxonomies;
}

add_filter("wcsearch_get_taxonomies_names", "w2dc_get_taxonomies_names");
function w2dc_get_taxonomies_names($taxonomies_names = array()) {
	
	$taxonomies_names['w2dc-category'] = esc_html__("Directory categories", "W2DC");
	$taxonomies_names['w2dc-location'] = esc_html__("Directory locations", "W2DC");
	$taxonomies_names['w2dc-tag'] = esc_html__("Directory tags", "W2DC");
	
	$search_fields = w2dc_get_search_fields();
	
	foreach ($search_fields AS $search_field) {
		if (in_array($search_field->content_field->type, array("select", "checkbox", "radio"))) {
			$taxonomies_names[$search_field->content_field->slug] = $search_field->content_field->name;
		}
	}
	
	return $taxonomies_names;
}

add_filter("wcsearch_default_query", "w2dc_get_default_query");
function w2dc_get_default_query($default_query = array()) {
	
	if ($category = w2dc_isCategory()) {
		$default_query['categories'] = $category->term_id;
		$default_query['include_categories_children'] = true;
	}
	if ($location = w2dc_isLocation()) {
		$default_query['locations'] = $location->term_id;
		$default_query['include_locations_children'] = true;
	}
	if ($tag = w2dc_isTag()) {
		$default_query['tags'] = $tag->term_id;
	}
	
	return $default_query;
}

add_filter("wcsearch_set_args_from_old_form", "w2dc_set_args_from_old_form", 10, 3);
function w2dc_set_args_from_old_form($form_args, $args, $search_form) {

	if (!isset($args['show_categories_search'])) {
		$args['show_categories_search'] = 1;
	}
	if (!isset($args['show_keywords_search'])) {
		$args['show_keywords_search'] = 1;
	}
	if (!isset($args['show_locations_search'])) {
		$args['show_locations_search'] = 1;
	}
	if (!isset($args['show_address_search'])) {
		$args['show_address_search'] = 1;
	}
	if (!isset($args['show_radius_search'])) {
		$args['show_radius_search'] = 1;
	}

	$form_args = array_merge($form_args, array(
			'columns_num' => 2,
			'model' => array(
					"placeholders" => array(),
			),
			'used_by' => 'w2dc',
			'use_border' => 0,
			'use_ajax' => 1,
			'auto_submit' => 1,
			'bg_color' => get_option("w2dc_search_bg_color"),
			'bg_transparency' => get_option("w2dc_search_bg_opacity"),
			'text_color' => get_option("w2dc_search_text_color"),
			'use_overlay' => get_option("w2dc_search_overlay"),
			'scroll_to' => (get_option("w2dc_auto_scroll_on_search") ? 'products' : ''),
	));

	if (!empty($args['show_categories_search']) && !empty($args['show_keywords_search'])) {
		$input = array(
				"type" => "tax",
				"slug" => "categories",
				"tax" => "w2dc-category",
				"title" => "",
				"visible_status" => "always_opened",
				"mode" => "dropdown_keywords",
				'placeholder' => esc_html__("Enter keywords or select category", "W2DC"),
		);
		if (!empty($args['keywords_ajax_search'])) {
			$input['autocomplete'] = 1;
		}
		if (!empty($args['keywords_search_examples'])) {
			$input['keywords_suggestions'] = esc_attr($args['keywords_search_examples']);
		}
		if (!empty($args['keywords_placeholder'])) {
			$input['placeholder'] = esc_attr($args['keywords_placeholder']);
		}
		if (!empty($args['what_search'])) {
			$input['values'] = esc_attr($args['what_search']);
		}
		if (!empty($args['categories_search_level'])) {
			$input['depth'] = (int) $args['categories_search_level'];
		}

		$form_args['model']["placeholders"][] = array(
				"columns" => 1,
				"rows" => 1,
				"input" => $input
		);
	} elseif (!empty($args['show_categories_search'])) {
		$input = array(
				"type" => "tax",
				"slug" => "categories",
				"tax" => "w2dc-category",
				"title" => "",
				"visible_status" => "always_opened",
				"mode" => "dropdown",
				"values" => "",
				"placeholder" => esc_html__("Select category", "W2DC"),
		);
		if (!empty($args['categories_search_level'])) {
			$input['depth'] = (int) $args['categories_search_level'];
		}

		$form_args['model']["placeholders"][] = array(
				"columns" => 1,
				"rows" => 1,
				"input" => $input,
		);
	} elseif (!empty($args['show_keywords_search'])) {
		$input = array(
				"type" => "keywords",
				"slug" => "keywords",
				"title" => "",
				"visible_status" => "always_opened",
				"placeholder" => esc_html__("Enter keywords", "W2DC"),
		);
		if (!empty($args['keywords_ajax_search'])) {
			$input['autocomplete'] = 1;
		}
		if (!empty($args['keywords_search_examples'])) {
			$input['keywords_suggestions'] = esc_attr($args['keywords_search_examples']);
		}
		if (!empty($args['keywords_placeholder'])) {
			$input['placeholder'] = esc_attr($args['keywords_placeholder']);
		}
		if (!empty($args['what_search'])) {
			$input['values'] = esc_attr($args['what_search']);
		}

		$form_args['model']["placeholders"][] = array(
				"columns" => 1,
				"rows" => 1,
				"input" => $input
		);
	}

	if (!empty($args['show_locations_search']) && !empty($args['show_address_search'])) {
		$input = array(
				"type" => "tax",
				"slug" => "locations",
				"tax" => "w2dc-location",
				"title" => "",
				"visible_status" => "always_opened",
				"mode" => "dropdown_address",
				"values" => "",
				"placeholder" => esc_html__("Enter address or select location", "W2DC"),
		);
		if (!empty($args['locations_search_level'])) {
			$input['depth'] = (int) $args['locations_search_level'];
		}
		if (!empty($args['address_placeholder'])) {
			$input['placeholder'] = esc_attr($args['address_placeholder']);
		}

		$form_args['model']["placeholders"][] = array(
				"columns" => 1,
				"rows" => 1,
				"input" => $input,
		);
	} elseif (!empty($args['show_locations_search'])) {
		$input = array(
				"type" => "tax",
				"slug" => "locations",
				"tax" => "w2dc-location",
				"title" => "",
				"visible_status" => "always_opened",
				"mode" => "dropdown",
				"values" => "",
				"placeholder" => esc_html__("Select location", "W2DC"),
		);
		if (!empty($args['locations_search_level'])) {
			$input['depth'] = (int) $args['locations_search_level'];
		}

		$form_args['model']["placeholders"][] = array(
				"columns" => 1,
				"rows" => 1,
				"input" => $input,
		);
	} elseif (!empty($args['show_address_search'])) {
		$input = array(
				"type" => "address",
				"slug" => "address",
				"title" => "",
				"visible_status" => "always_opened",
				"address_suggestions" => "",
				"values" => "",
				"placeholder" => esc_html__("Enter address", "W2DC"),
		);
		if (!empty($args['address_placeholder'])) {
			$input['placeholder'] = esc_attr($args['address_placeholder']);
		}

		$form_args['model']["placeholders"][] = array(
				"columns" => 1,
				"rows" => 1,
				"input" => $input,
		);
	}
	if (!empty($args['show_radius_search'])) {
		$input = array(
				"type" => "radius",
				"slug" => "radius",
				"title" => "",
				"visible_status" => "always_opened",
		);
		if (!empty($args['radius'])) {
			$input['values'] = (int) $args['radius'];
		} else {
			$input['values'] = get_option("w2dc_radius_search_default");
		}

		$form_args['model']["placeholders"][] = array(
				"columns" => 2,
				"rows" => 1,
				"input" => $input,
		);
	}
	
	if (!get_option("w2dc_hide_search_button")) {
		$input = array(
				"type" => "button",
				"slug" => "button",
				"title" => "",
				"visible_status" => "always_opened",
		);
		
		$form_args['model']["placeholders"][] = array(
				"columns" => 1,
				"rows" => 1,
				"input" => $input,
		);
	}

	if (!empty($args['search_fields']) || !empty($args['search_fields_advanced'])) {

		if (!empty($args['search_fields'])) {
			$search_fields = explode(",", $args['search_fields']);
		} else {
			$search_fields = array();
		}

		if (!empty($args['search_fields_advanced'])) {
			$search_fields_advanced = explode(",", $args['search_fields_advanced']);

			$input = array(
					"type" => "more_filters",
					"slug" => "more_filters",
			);
			if (!empty($args['advanced_open'])) {
				$input["open_by_default"] = 1;
			}
			$form_args['model']["placeholders"][] = array(
					"columns" => 1,
					"rows" => 1,
					"input" => $input,
			);

		} else {
			$search_fields_advanced = array();
		}

		if ($all_search_fields = w2dc_get_search_fields()) {
			foreach ($all_search_fields AS $slug=>$search_field) {

				//if (in_array($search_field->content_field->id, $search_fields) || in_array($search_field->content_field->id, $search_fields_advanced)) {

				if (in_array($search_field->content_field->type, array("select", "checkbox", "radio"))) {
					$type= "select";
				}
				if (in_array($search_field->content_field->type, array("price"))) {
					$type= "price";
				}
				if (in_array($search_field->content_field->type, array("number"))) {
					$type= "number";
				}
				if (in_array($search_field->content_field->type, array("string", "textarea", "phone"))) {
					$type= "string";
				}
				if (in_array($search_field->content_field->type, array("datetime"))) {
					$type= "date";
				}

				$visible_status = "always_opened";
				if (in_array($search_field->content_field->id, $search_fields_advanced)) {
					$visible_status = "more_filters";
				}

				$input = array(
						"type" => $type,
						"slug" => $search_field->content_field->slug,
						"title" => $search_field->content_field->name,
						"visible_status" => $visible_status,
				);
				$form_args['model']["placeholders"][] = array(
						"columns" => 1,
						"rows" => 1,
						"input" => $input,
				);
				//}

				if (!empty($args[$slug])) {

				}
			}
		}
	}

	if (count($form_args['model']['placeholders']) == 1) {
		$form_args['columns_num'] = 1;
	}
	
	if (isset($args['columns'])) {
		$form_args['columns_num'] = $args['columns'];
	}

	return $form_args;
}

add_filter("wcsearch_query_class_name", "w2dc_query_class_name", 10, 2);
function w2dc_query_class_name($class_name, $used_by) {
	
	if ($used_by == 'w2dc') {
		$class_name = "w2dc_search_query";
	}
	
	return $class_name;
}

add_filter("wcsearch_adapter_options", "w2dc_adapter_options");
function w2dc_adapter_options($options) {

	$options['w2dc'] = array(
			'loop_selector_name' => array('w2dc-controller', 'w2dc-map-wrapper'),
			'submit_callback' => 'w2dc_callAJAXSearch',
			'keywords_search_action' => 'w2dc_keywords_search',
			'enable_my_location_button' => (int) get_option('w2dc_address_geocode'),
	);

	return $options;
}

add_filter("wcsearch_get_used_by_by_tax", "w2dc_get_used_by_by_tax", 10, 2);
function w2dc_get_used_by_by_tax($used_by, $tax) {

	$taxes = w2dc_get_taxonomies();

	if (isset($taxes[$tax])) {
		$used_by = 'w2dc';
	}

	return $used_by;
}

add_filter("wcsearch_get_term_icon_url", "w2dc_get_term_icon_url", 10, 3);
function w2dc_get_term_icon_url($url, $term_id, $tax_name) {
	
	switch ($tax_name) {
		case W2DC_CATEGORIES_TAX:
			if ($file = w2dc_getCategoryIconFile($term_id)) {
				$url = W2DC_CATEGORIES_ICONS_URL . $file;
			} elseif (w2dc_getDefaultTermIconUrl($tax_name)) {
				$url = w2dc_getDefaultTermIconUrl($tax_name);
			}
			break;
		case W2DC_LOCATIONS_TAX:
			if ($file = w2dc_getLocationIconFile($term_id)) {
				$url = W2DC_LOCATIONS_ICONS_URL . $file;
			} elseif (w2dc_getDefaultTermIconUrl($tax_name)) {
				$url = w2dc_getDefaultTermIconUrl($tax_name);
			}
			break;
	}
	
	return $url;
}

add_filter("wcsearch_allowed_params", "w2dc_allowed_params");
function w2dc_allowed_params($allowed_params) {
	
	$allowed_params[] = "order_by";
	$allowed_params[] = "order";
	
	$allowed_params[] = "categories";
	$allowed_params[] = "categories_relation";
	$allowed_params[] = "locations";
	$allowed_params[] = "locations_relation";
	$allowed_params[] = "tags";
	$allowed_params[] = "tags_relation";
	
	$search_fields = w2dc_get_search_fields();
	
	foreach ($search_fields AS $search_field) {
		if (in_array($search_field->content_field->type, array("select", "checkbox", "radio"))) {
			$allowed_params[] = $search_field->content_field->slug;
			$allowed_params[] = 'field_' . $search_field->content_field->slug;
			$allowed_params[] = $search_field->content_field->slug . "_relation";
		} else {
			$allowed_params[] = $search_field->content_field->slug;
		}
	}
	
	return $allowed_params;
}

add_filter("wcsearch_select_fields", "w2dc_select_fields_filter");
function w2dc_select_fields_filter($select_fields) {
	
	$search_fields = w2dc_get_search_fields();
	
	foreach ($search_fields AS $search_field) {
		if (in_array($search_field->content_field->type, array("select", "checkbox", "radio"))) {
			$select_fields[] = $search_field->content_field->slug;
		}
	}
	
	return $select_fields;
}

add_filter("wcsearch_get_select_field", "w2dc_get_select_field_filter", 10, 2);
function w2dc_get_select_field_filter($content_field, $tax_name) {
	
	$search_fields = w2dc_get_search_fields();
	
	if (isset($search_fields[$tax_name])) {
		$content_field = $search_fields[$tax_name]->content_field;
	}
	
	return $content_field;
}

add_filter("w2dc_query_input_args", "w2dc_query_input_args");
function w2dc_query_input_args($args) {
	
	$taxonomies = w2dc_get_taxonomies();
	
	if (w2dc_do_follow_get_params($args)) {
		$_args = array_merge(array(
				'orderby' => '',
				'order' => '',
				'page' => 1,
				'taxonomies' => array(),
		), w2dc_get_default_query(), $args, wcsearch_get_query_string());
	
		$_args['page'] = (get_query_var('paged')) ? absint(get_query_var('paged')) : $_args['page'];
		$_args['posts_per_page'] = w2dc_getValue($args, 'perpage', (int)get_option('w2dc_listings_number_excerpt'));
		
		foreach ($taxonomies AS $tax_name=>$tax_slug) {
			if (wcsearch_get_tax_terms_from_query_string($tax_slug, $_args)) {
				$_args['taxonomies'][$tax_name] = wcsearch_get_tax_terms_from_query_string($tax_slug, $_args);
			} elseif (!empty($_args[$tax_slug])) {
				$_args['taxonomies'][$tax_name] = wcsearch_get_tax_terms_from_args($tax_slug, $_args);
			}
		}
	} else {
		// do not take params from GET and search query
		$_args = array_merge(array(
				'orderby' => '',
				'order' => '',
				'page' => 1,
				'taxonomies' => array(),
		), w2dc_get_default_query(), $args, array('paged' => 1));
		
		$_args['posts_per_page'] = w2dc_getValue($args, 'perpage', (int)get_option('w2dc_listings_number_excerpt'));
		
		foreach ($taxonomies AS $tax_name=>$tax_slug) {
			if (!empty($_args[$tax_slug])) {
				$_args['taxonomies'][$tax_name] = wcsearch_get_tax_terms_from_args($tax_slug, $_args);
			}
		}
	}
	
	return $_args;
}


function w2dc_do_follow_get_params($args) {
	
	if (!empty($args['include_get_params'])) {
		return true;
	} elseif (isset($args['include_get_params']) && $args['include_get_params'] == 1) {
		return true;
	} elseif (!isset($args['include_get_params'])) {
		return true;
	} elseif (isset($args['include_get_params']) && $args['include_get_params'] == 0) {
		return false;
	}
}


add_filter('wcsearch_get_model_fields', 'w2dc_filter_model_fields', 11, 2);
function w2dc_filter_model_fields($model_fields, $used_by) {
	
	if ($used_by != 'w2dc') {
		return $model_fields;
	}
	
	$model_fields = array(
			array(
					'name' => 'Keywords',
					'type' => 'keywords',
					'slug' => 'keywords',
					'icon' => 'wcsearch-fa-search',
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
					'name' => esc_html__('Categories', "W2DC"),
					'type' => 'tax',
					'tax' => 'w2dc-category',
					'slug' => 'categories',
					'icon' => 'wcsearch-fa-bars',
					'values' => '',
			),
			array(
					'name' => esc_html__('Locations', "W2DC"),
					'type' => 'tax',
					'tax' => 'w2dc-location',
					'slug' => 'locations',
					'icon' => 'wcsearch-fa-bars',
					'values' => '',
			),
			array(
					'name' => esc_html__('Tags', "W2DC"),
					'type' => 'tax',
					'tax' => 'w2dc-tag',
					'slug' => 'tags',
					'icon' => 'wcsearch-fa-bars',
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
	
	$search_fields = w2dc_get_search_fields();
	
	foreach ($search_fields AS $search_field) {
		if (in_array($search_field->content_field->type, array("select", "checkbox", "radio"))) {
			$model_fields[] = array(
					'name' => $search_field->content_field->name,
					'type' => 'select',
					'slug' => $search_field->content_field->slug,
					'tax' => $search_field->content_field->slug,
					'icon' => 'wcsearch-fa-bars',
					'values' => '',
			);
		} elseif ($search_field->content_field->type == "price") {
			$model_fields[] = array(
					'name' => $search_field->content_field->name,
					'type' => 'price',
					'slug' => $search_field->content_field->slug,
					'icon' => 'wcsearch-fa-usd',
					'values' => '',
			);
		} elseif ($search_field->content_field->type == "number") {
			$model_fields[] = array(
					'name' => $search_field->content_field->name,
					'type' => 'number',
					'slug' => $search_field->content_field->slug,
					'icon' => 'wcsearch-fa-sliders',
					'values' => '',
			);
		} elseif (in_array($search_field->content_field->type, array("string", "textarea", "phone"))) {
			$model_fields[] = array(
					'name' => $search_field->content_field->name,
					'type' => 'string',
					'slug' => $search_field->content_field->slug,
					'icon' => 'wcsearch-fa-sliders',
					'values' => '',
			);
		} elseif ($search_field->content_field->type == "datetime") {
			$model_fields[] = array(
					'name' => $search_field->content_field->name,
					'type' => 'date',
					'slug' => $search_field->content_field->slug,
					'icon' => 'wcsearch-fa-calendar',
					'values' => '',
			);
		} elseif ($search_field->content_field->type == "hours") {
			$model_fields[] = array(
					'name' => $search_field->content_field->name,
					'type' => 'hours',
					'slug' => $search_field->content_field->slug,
					'icon' => 'wcsearch-fa-clock-o',
					'values' => '',
			);
		}
	}
	
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
	
	return $model_fields;
}

add_action("admin_menu", "w2dc_remove_native_demo_forms_menu_link", 11);
function w2dc_remove_native_demo_forms_menu_link() {
	remove_submenu_page('edit.php?post_type=wcsearch_form', 'wcsearch_demo_data');
}

add_action("admin_menu", "w2dc_remove_search_settings_menu_link", 11);
function w2dc_remove_search_settings_menu_link() {
	remove_submenu_page('edit.php?post_type=wcsearch_form', 'wcsearch_settings');
}

// remove [wcsearch id=XX] shortcode column, add custom [webdirectory-search form_id=XX]
add_action("admin_init", "w2dc_remove_posts_custom_column", 1100);
function w2dc_remove_posts_custom_column() {
	global $wcsearch_instance;

	remove_filter('manage_'.WCSEARCH_FORM_TYPE.'_posts_custom_column', array($wcsearch_instance->search_forms, 'manage_wcsearch_table_rows'));

	add_filter('manage_'.WCSEARCH_FORM_TYPE.'_posts_custom_column', 'w2dc_manage_wcsearch_table_rows', 10, 2);
}
function w2dc_manage_wcsearch_table_rows($column, $post_id) {
	switch ($column) {
		case "wcsearch_shortcode":
			echo '[webdirectory-search form_id="' . esc_attr($post_id) . '"]';
			break;
	}
}

// add directory parameter into query in wcsearch_get_count_num()
add_filter("wcsearch_get_count_num_args", "w2dc_get_count_num_args_filter");
function w2dc_get_count_num_args_filter($args) {
	global $w2dc_instance;
	
	if ($w2dc_instance->directories->isMultiDirectory()) {
		$args['directories'] = $w2dc_instance->current_directory->id;
	}
	
	return $args;
}

// search/filters/ratings.php file
function w2dc_avg_rating_key() {
	if (defined('W2RR_VERSION')) {
		return '_avg_rating';
	} elseif (defined('W2DC_AVG_RATING_KEY')) {
		return W2DC_AVG_RATING_KEY;
	}
}

add_filter("wcsearch_get_min_max_numbers", "w2dc_get_min_max_numbers", 10, 3);
function w2dc_get_min_max_numbers($vals, $used_by, $slug) {
	
	if ($used_by == 'w2dc') {
		global $wpdb;
		
		$search_fields = w2dc_get_search_fields();
		
		foreach ($search_fields AS $search_field) {
			if (in_array($search_field->content_field->type, array('price', 'number')) && $search_field->content_field->slug == $slug) {

				$id = $search_field->content_field->id;

				$vals = $wpdb->get_row("SELECT MIN(CONVERT(pm.meta_value, UNSIGNED INTEGER)) AS min, MAX(CONVERT(pm.meta_value, UNSIGNED INTEGER)) AS max FROM {$wpdb->postmeta} AS pm WHERE pm.meta_key = '_content_field_{$id}'");
			}
		}
	}
	
	return $vals;
}

add_filter("wcsearch_price_format", "w2dc_number_format", 10, 3);
add_filter("wcsearch_number_format", "w2dc_number_format", 10, 3);
function w2dc_number_format($value, $used_by, $slug) {

	if ($used_by == 'w2dc') {
		$search_fields = w2dc_get_search_fields();
		
		foreach ($search_fields AS $search_field) {
			if (in_array($search_field->content_field->type, array('price', 'number')) && $search_field->content_field->slug == $slug) {
				$value = $search_field->content_field->formatValue($value);
			}
		}
	}

	return $value;
}

add_filter("wcsearch_get_datepicker_lang_code", "w2dc_get_datepicker_lang_code");
function w2dc_get_datepicker_lang_code($locale) {

	return w2dc_getDatePickerLangCode($locale);
}

add_action('save_post_' . W2DC_POST_TYPE, 'w2dc_clear_count_cache');
add_action('w2dc_save_content_field_config', 'w2dc_clear_count_cache');
function w2dc_clear_count_cache() {
	global $wcsearch_instance;
	
	$wcsearch_instance->clear_count_cache();
}

add_filter("update_term_meta", "w2dc_update_term_meta", 10, 3);
function w2dc_update_term_meta($meta_id, $object_id, $meta_key) {
	global $wcsearch_instance;
	
	if ($meta_key == 'directories_count') {
		$wcsearch_instance->clear_count_cache();
	}
}

add_action('wp_ajax_w2dc_save_rating', 'w2dc_clear_count_cache', 0);
add_action('wp_ajax_nopriv_w2dc_save_rating', 'w2dc_clear_count_cache', 0);
add_action('wp_ajax_w2dc_reset_ratings', 'w2dc_clear_count_cache', 0);
add_action('wp_ajax_nopriv_w2dc_reset_ratings', 'w2dc_clear_count_cache', 0);

add_action('wp_ajax_w2rr_save_rating', 'w2dc_clear_count_cache', 0);
add_action('wp_ajax_nopriv_w2rr_save_rating', 'w2dc_clear_count_cache', 0);
add_action('wp_ajax_w2rr_delete_single_rating', 'w2dc_clear_count_cache', 0);
add_action('wp_ajax_nopriv_w2rr_delete_single_rating', 'w2dc_clear_count_cache', 0);
add_action('w2rr_save_review', 'w2dc_clear_count_cache', 0);

add_action("wcsearch_output_hidden_fields", "w2dc_output_hidden_fields_directory");
function w2dc_output_hidden_fields_directory($search_form) {
	global $w2dc_instance;
	
	$directory_id = $w2dc_instance->current_directory->id;
	
	$search_form->setCommonField('directories', $directory_id);
}

add_filter("wcsearch_get_edit_form_link", "w2dc_get_edit_form_link", 10, 2);
function w2dc_get_edit_form_link($link, $id) {
	
	if (function_exists('w2dc_dashboardUrl')) {
		$link = w2dc_dashboardUrl(array('redirect_to' => urlencode(admin_url('post.php?post=' . $id . '&action=edit'))));
	}
	
	return $link;
}

?>