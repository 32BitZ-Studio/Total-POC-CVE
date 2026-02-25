<?php

add_action('vc_before_init', 'w2dc_vc_init');

function w2dc_vc_init() {
	
	global $w2dc_instance;
	global $w2dc_fsubmit_instance;
	
	if (!isset($w2dc_instance->content_fields)) { // some "unique" themes/plugins call vc_before_init more than ones - this is such protection
		return ;
	}

	if (!function_exists('w2dc_ordering_param')) { // some "unique" themes/plugins call vc_before_init more than ones - this is such protection
		vc_add_shortcode_param('ordering', 'w2dc_ordering_param');
		function w2dc_ordering_param($settings, $value) {
			$ordering = w2dc_orderingItems();

			$out = '<select id="' . $settings['param_name'] . '" name="' . $settings['param_name'] . '" class="wpb_vc_param_value">';
			foreach ($ordering AS $ordering_item) {
				$out .= '<option value="' . $ordering_item['value'] . '" ' . selected($value, $ordering_item['value'], false) . '>' . $ordering_item['label'] . '</option>';
			}
			$out .= '</select>';
	
			return $out;
		}
	}

	if (!function_exists('w2dc_mapstyle_param')) { // some "unique" themes/plugins call vc_before_init more than ones - this is such protection
		vc_add_shortcode_param('mapstyle', 'w2dc_mapstyle_param');
		function w2dc_mapstyle_param($settings, $value) {
			if (w2dc_getMapEngine()) {
				$out = '<select id="' . $settings['param_name'] . '" name="' . $settings['param_name'] . '" class="wpb_vc_param_value">';
				$out .= '<option value="0" ' . ((!$value) ? 'selected' : 0) . '>' . __('Default', 'W2DC') . '</option>';
				$map_styles = array('default' => '');
				foreach (w2dc_getAllMapStyles() AS $name=>$style) {
					$out .= '<option value="' . $name . '" ' . selected($value, $name, false) . '>' . $name . '</option>';
				}
				$out .= '</select>';
		
				return $out;
			} else {
				return esc_html("Map engine was not selected", "W2DC");
			}
		}
	}

	if (!function_exists('w2dc_directories_param')) { // some "unique" themes/plugins call vc_before_init more than ones - this is such protection
		vc_add_shortcode_param('directories', 'w2dc_directories_param');
		function w2dc_directories_param($settings, $value) {
			global $w2dc_instance;

			$out = "<script>
				function updateTagChecked_directories() { jQuery('#" . $settings['param_name'] . "').val(jQuery('#" . $settings['param_name'] . "_select').val()); }
			
				jQuery(function() {
					jQuery('body').on('click', '#" . $settings['param_name'] . "_select option', updateTagChecked_directories);
					updateTagChecked_directories();
				});
			</script>";

			$out .= '<select id="' . $settings['param_name'] . '_select" name="' . $settings['param_name'] . '_select" multiple="multiple">';
			$out .= '<option value="" ' . ((!$value) ? 'selected' : 0) . '>' . __('- Auto -', 'W2DC') . '</option>';
			foreach ($w2dc_instance->directories->directories_array AS $directory) {
				$out .= '<option value="' . $directory->id . '" ' . selected(in_array($directory->id, explode(',', $value)), true, false) . '>' . $directory->name . '</option>';
			}
			$out .= '</select>';
			$out .= '<input type="hidden" id="' . $settings['param_name'] . '" name="' . $settings['param_name'] . '" class="wpb_vc_param_value" value="' . $value . '" />';
			return $out;
		}
	}
	
	if (!function_exists('w2dc_directory_param')) { // some "unique" themes/plugins call vc_before_init more than ones - this is such protection
		vc_add_shortcode_param('directory', 'w2dc_directory_param');
		function w2dc_directory_param($settings, $value) {
			global $w2dc_instance;

			$out = '<select id="' . $settings['param_name'] . '" name="' . $settings['param_name'] . '" class="wpb_vc_param_value">';
			$out .= '<option value="" ' . ((!$value) ? 'selected' : 0) . '>' . __('- Auto -', 'W2DC') . '</option>';
			foreach ($w2dc_instance->directories->directories_array AS $directory) {
				$out .= '<option value="' . $directory->id . '" ' . selected($value, $directory->id, false) . '>' . $directory->name . '</option>';
			}
			$out .= '</select>';
	
			return $out;
		}
	}
	
	if (!function_exists('w2dc_levels_param')) { // some "unique" themes/plugins call vc_before_init more than ones - this is such protection
		vc_add_shortcode_param('levels', 'w2dc_levels_param');
		function w2dc_levels_param($settings, $value) {
			global $w2dc_instance;
	
			$out = "<script>
				function updateTagChecked_levels() { jQuery('#" . $settings['param_name'] . "').val(jQuery('#" . $settings['param_name'] . "_select').val()); }
		
				jQuery(function() {
					jQuery('body').on('click', '#" . $settings['param_name'] . "_select option', updateTagChecked_levels);
					updateTagChecked_levels();
				});
			</script>";
	
			$out .= '<select id="' . $settings['param_name'] . '_select" name="' . $settings['param_name'] . '_select" multiple="multiple">';
			$out .= '<option value="" ' . ((!$value) ? 'selected' : '') . '>' . __('- Auto -', 'W2DC') . '</option>';
			foreach ($w2dc_instance->levels->levels_array AS $level) {
				$out .= '<option value="' . $level->id . '" ' . selected($value, $level->id, false) . '>' . $level->name . '</option>';
			}
			$out .= '</select>';
			$out .= '<input type="hidden" id="' . $settings['param_name'] . '" name="' . $settings['param_name'] . '" class="wpb_vc_param_value" value="' . $value . '" />';
			return $out;
		}
	}

	if (!function_exists('w2dc_level_param')) { // some "unique" themes/plugins call vc_before_init more than ones - this is such protection
		vc_add_shortcode_param('level', 'w2dc_level_param');
		function w2dc_level_param($settings, $value) {
			global $w2dc_instance;

			$out = '<select id="' . $settings['param_name'] . '" name="' . $settings['param_name'] . '" class="wpb_vc_param_value">';
			$out .= '<option value="" ' . ((!$value) ? 'selected' : 0) . '>' . __('- Auto -', 'W2DC') . '</option>';
			foreach ($w2dc_instance->levels->levels_array AS $level) {
				$out .= '<option value="' . $level->id . '" ' . selected($value, $level->id, false) . '>' . $level->name . '</option>';
			}
			$out .= '</select>';
	
			return $out;
		}
	}

	if (!function_exists('w2dc_categories_param')) { // some "unique" themes/plugins call vc_before_init more than ones - this is such protection
		vc_add_shortcode_param('categoriesfield', 'w2dc_categories_param');
		function w2dc_categories_param($settings, $value) {
			$out = "<script>
				function updateTagChecked_categories() { jQuery('#" . $settings['param_name'] . "').val(jQuery('#" . $settings['param_name'] . "_select').val()); }
		
				jQuery(function() {
					jQuery('body').on('click', '#" . $settings['param_name'] . "_select option', updateTagChecked_categories);
					updateTagChecked_categories();
				});
			</script>";
		
			$out .= '<select multiple="multiple" id="' . $settings['param_name'] . '_select" name="' . $settings['param_name'] . '_select" style="height: 300px">';
			$out .= '<option value="" ' . ((!$value) ? 'selected' : '') . '>' . __('- Select All -', 'W2DC') . '</option>';
			ob_start();
			w2dc_renderOptionsTerms(W2DC_CATEGORIES_TAX, 0, explode(',', $value));
			$out .= ob_get_clean();
			$out .= '</select>';
			$out .= '<input type="hidden" id="' . $settings['param_name'] . '" name="' . $settings['param_name'] . '" class="wpb_vc_param_value" value="' . $value . '" />';
		
			return $out;
		}
	}

	if (!function_exists('w2dc_category_param')) { // some "unique" themes/plugins call vc_before_init more than ones - this is such protection
		vc_add_shortcode_param('categoryfield', 'w2dc_category_param');
		function w2dc_category_param($settings, $value) {
			$out = '<select id="' . $settings['param_name'] . '" name="' . $settings['param_name'] . '" class="wpb_vc_param_value">';
			$out .= '<option value="" ' . ((!$value) ? 'selected' : '') . '>' . __('- No category selected -', 'W2DC') . '</option>';
			ob_start();
			w2dc_renderOptionsTerms(W2DC_CATEGORIES_TAX, 0, array($value));
			$out .= ob_get_clean();
			$out .= '</select>';
		
			return $out;
		}
	}

	if (!function_exists('w2dc_locations_param')) { // some "unique" themes/plugins call vc_before_init more than ones - this is such protection
		vc_add_shortcode_param('locationsfield', 'w2dc_locations_param');
		function w2dc_locations_param($settings, $value) {
			$out = "<script>
				function updateTagChecked_locations() { jQuery('#" . $settings['param_name'] . "').val( jQuery('#" . $settings['param_name'] . "_select').val()); }
		
				jQuery(function() {
					jQuery('body').on('click', '#" . $settings['param_name'] . "_select option', updateTagChecked_locations);
					updateTagChecked_locations();
				});
			</script>";
		
			$out .= '<select multiple="multiple" id="' . $settings['param_name'] . '_select" name="' . $settings['param_name'] . '_select" style="height: 300px">';
			$out .= '<option value="" ' . ((!$value) ? 'selected' : '') . '>' . __('- Select All -', 'W2DC') . '</option>';
			ob_start();
			w2dc_renderOptionsTerms(W2DC_LOCATIONS_TAX, 0, explode(',', $value));
			$out .= ob_get_clean();
			$out .= '</select>';
			$out .= '<input type="hidden" id="' . $settings['param_name'] . '" name="' . $settings['param_name'] . '" class="wpb_vc_param_value" value="' . $value . '" />';
		
			return $out;
		}
	}

	if (!function_exists('w2dc_location_param')) { // some "unique" themes/plugins call vc_before_init more than ones - this is such protection
		vc_add_shortcode_param('locationfield', 'w2dc_location_param');
		function w2dc_location_param($settings, $value) {
			$out = '<select id="' . $settings['param_name'] . '" name="' . $settings['param_name'] . '" class="wpb_vc_param_value">';
			$out .= '<option value="" ' . ((!$value) ? 'selected' : '') . '>' . __('- No location selected -', 'W2DC') . '</option>';
			ob_start();
			w2dc_renderOptionsTerms(W2DC_LOCATIONS_TAX, 0, array($value));
			$out .= ob_get_clean();
			$out .= '</select>';
		
			return $out;
		}
	}

	if (!function_exists('w2dc_content_fields_param')) { // some "unique" themes/plugins call vc_before_init more than ones - this is such protection
		vc_add_shortcode_param('contentfields', 'w2dc_content_fields_param');
		function w2dc_content_fields_param($settings, $value) {
			global $w2dc_instance;
			$out = "<script>
				function updateTagChecked_content_fields() { jQuery('#" . $settings['param_name'] . "').val(jQuery('#" . $settings['param_name'] . "_select').val()); }
		
				jQuery(function() {
					jQuery('body').on('click', '#" . $settings['param_name'] . "_select option', updateTagChecked_content_fields);
					updateTagChecked_content_fields();
				});
			</script>";

			$content_fields_ids = explode(',', $value);
			$out .= '<select multiple="multiple" id="' . $settings['param_name'] . '_select" name="' . $settings['param_name'] . '_select" style="height: 300px">';
			$out .= '<option value="" ' . ((!$value) ? 'selected' : '') . '>' . __('- All content fields -', 'W2DC') . '</option>';
			$out .= '<option value="" ' . (($value == -1) ? 'selected' : '') . '>' . __('- No content fields -', 'W2DC') . '</option>';
			foreach ($w2dc_instance->search_fields->search_fields_array AS $search_field)
				$out .= '<option value="' . $search_field->content_field->id . '" ' . (in_array($search_field->content_field->id, $content_fields_ids) ? 'selected' : '') . '>' . $search_field->content_field->name . '</option>';
			$out .= '</select>';
			$out .= '<input type="hidden" id="' . $settings['param_name'] . '" name="' . $settings['param_name'] . '" class="wpb_vc_param_value" value="' . $value . '" />';
		
			return $out;
		}
	}
	
	if (!function_exists('w2dc_form_id_param')) { // some "unique" themes/plugins call vc_before_init more than ones - this is such protection
		vc_add_shortcode_param('formid', 'w2dc_form_id_param');
		function w2dc_form_id_param($settings, $value) {
			$out .= '<select id="' . $settings['param_name'] . '_select" name="' . $settings['param_name'] . '" class="wpb_vc_param_value">';
			$out .= '<option value="" ' . (($value == -1) ? 'selected' : '') . '>' . __('- No form selected -', 'W2DC') . '</option>';
			foreach (wcsearch_get_search_forms_posts() AS $id=>$title)
				$out .= '<option value="' . $id . '" ' . ($value == $id ? 'selected' : '') . '>' . $title . '</option>';
			$out .= '</select>';
		
			return $out;
		}
	}
	
	$vc_directory_args = array(
		'name'                    => __('Web 2.0 Directory', 'W2DC'),
		'description'             => __('Main shortcode', 'W2DC'),
		'base'                    => 'webdirectory',
		'icon'                    => W2DC_RESOURCES_URL . 'images/webdirectory.png',
		'show_settings_on_create' => true,
		'category'                => __('Directory Content', 'W2DC'),
		'params'                  => array(
			array(
					'type' => 'dropdown',
					'param_name' => 'custom_home',
					'value' => array(__('No', 'W2DC') => '0', __('Yes', 'W2DC') => '1'),
					'heading' => __('Is it on custom home page?', 'W2DC'),
					'description' => __('Only listings will be displayed. Other Visual Composer elements (categories, search, map) you can add separately.', 'W2DC'),
			),
			array(
					'type' => 'directory',
					'param_name' => 'id',
					'heading' => __('Select Directory', 'W2DC'),
			)
		),
	);
	vc_map($vc_directory_args);
	
	global $w2dc_levels_table_widget_params;
	if ($w2dc_fsubmit_instance) {
		$vc_submit_args = array(
			'name'                    => __('Listings submit', 'W2DC'),
			'description'             => __('Listings submission pages', 'W2DC'),
			'base'                    => 'webdirectory-submit',
			'icon'                    => W2DC_RESOURCES_URL . 'images/webdirectory.png',
			'show_settings_on_create' => false,
			'category'                => __('Directory Content', 'W2DC'),
			'params'                  => $w2dc_levels_table_widget_params
		);
		vc_map($vc_submit_args);

		$vc_pricing_table_args = array(
			'name'                    => __('Pricing table', 'W2DC'),
			'description'             => __('Listings levels table. Works in the same way as 1st step on Listings submit, displays only pricing table. Note, that page with Listings submit element required.', 'W2DC'),
			'base'                    => 'webdirectory-levels-table',
			'icon'                    => W2DC_RESOURCES_URL . 'images/webdirectory.png',
			'show_settings_on_create' => false,
			'category'                => __('Directory Content', 'W2DC'),
			'params'                  => $w2dc_levels_table_widget_params
		);
		vc_map($vc_pricing_table_args);

		vc_map( array(
			'name'                    => __('Users Dashboard', 'W2DC'),
			'description'             => __('Directory frontend dashboard', 'W2DC'),
			'base'                    => 'webdirectory-dashboard',
			'icon'                    => W2DC_RESOURCES_URL . 'images/webdirectory.png',
			'show_settings_on_create' => false,
			'category'                => __('Directory Content', 'W2DC'),
			'params'                  => array(
					array(
							'type' => 'dropdown',
							'param_name' => 'listing_info',
							'value' => array(__('Yes', 'W2DC') => '1', __('No', 'W2DC') => '0'),
							'heading' => __('Display info metabox on listing edition page', 'W2DC'),
					),
			),
		));
	}
	
	global $w2dc_listings_widget_params;
	$vc_listings_args = array(
		'name'                    => __('Directory Listings', 'W2DC'),
		'description'             => __('Directory listings filtered by params', 'W2DC'),
		'base'                    => 'webdirectory-listings',
		'icon'                    => W2DC_RESOURCES_URL . 'images/webdirectory.png',
		'show_settings_on_create' => true,
		'category'                => __('Directory Content', 'W2DC'),
		'params'                  => $w2dc_listings_widget_params
	);
	vc_map($vc_listings_args);

	global $w2dc_map_widget_params;
	$vc_maps_args = array(
			'name'                    => __('Directory Map', 'W2DC'),
			'description'             => __('Directory map and markers', 'W2DC'),
			'base'                    => 'webdirectory-map',
			'icon'                    => W2DC_RESOURCES_URL . 'images/webdirectory.png',
			'show_settings_on_create' => true,
			'category'                => __('Directory Content', 'W2DC'),
			'params'                  => $w2dc_map_widget_params
	);
	vc_map($vc_maps_args);

	global $w2dc_categories_widget_params;
	vc_map( array(
		'name'                    => __('Categories List', 'W2DC'),
		'description'             => __('Directory categories list', 'W2DC'),
		'base'                    => 'webdirectory-categories',
		'icon'                    => W2DC_RESOURCES_URL . 'images/webdirectory.png',
		'show_settings_on_create' => true,
		'category'                => __('Directory Content', 'W2DC'),
		'params'                  => $w2dc_categories_widget_params,
	));

	global $w2dc_locations_widget_params;
	vc_map( array(
		'name'                    => __('Locations List', 'W2DC'),
		'description'             => __('Directory locations list', 'W2DC'),
		'base'                    => 'webdirectory-locations',
		'icon'                    => W2DC_RESOURCES_URL . 'images/webdirectory.png',
		'show_settings_on_create' => true,
		'category'                => __('Directory Content', 'W2DC'),
		'params'                  => $w2dc_locations_widget_params
	));

	global $w2dc_search_widget_params;
	$vc_search_args = array(
		'name'                    => __('Search form', 'W2DC'),
		'description'             => __('Directory listings search form', 'W2DC'),
		'base'                    => 'webdirectory-search',
		'icon'                    => W2DC_RESOURCES_URL . 'images/webdirectory.png',
		'show_settings_on_create' => false,
		'category'                => __('Directory Content', 'W2DC'),
		'params'                  => $w2dc_search_widget_params
	);
	vc_map($vc_search_args);

	global $w2dc_slider_widget_params;
	$vc_slider_args = array(
			'name'                    => __('Listings slider', 'W2DC'),
			'description'             => __('Directory listings in slider view', 'W2DC'),
			'base'                    => 'webdirectory-slider',
			'icon'                    => W2DC_RESOURCES_URL . 'images/webdirectory.png',
			'show_settings_on_create' => true,
			'category'                => __('Directory Content', 'W2DC'),
			'params'                  => $w2dc_slider_widget_params
	);
	vc_map($vc_slider_args);
	
	global $w2dc_buttons_widget_params;
	$vc_front_buttons_args = array(
			'name'                    => __('Front buttons', 'W2DC'),
			'description'             => __('Submit listing, my bookmarks, edit listing, print listing, ....', 'W2DC'),
			'base'                    => 'webdirectory-buttons',
			'icon'                    => W2DC_RESOURCES_URL . 'images/webdirectory.png',
			'show_settings_on_create' => false,
			'category'                => __('Directory Content', 'W2DC'),
			'params'                  => $w2dc_buttons_widget_params
	);
	vc_map($vc_front_buttons_args);
	
	vc_map(array(
			'name'                    => __('Listing page', 'W2DC'),
			'description'             => __('Single listing "template" page', 'W2DC'),
			'base'                    => 'webdirectory-listing-page',
			'icon'                    => W2DC_RESOURCES_URL . 'images/webdirectory.png',
			'show_settings_on_create' => false,
			'category'                => __('Directory Content', 'W2DC'),
			'params'                  => array(
					array(
							'type' => 'directory',
							'param_name' => 'directory',
							'heading' => __('Select Directory', 'W2DC'),
					)
			),
		)
	);
	
	global $w2dc_page_header_widget_params;
	vc_map(array(
			'name'                    => __('Page header', 'W2DC'),
			'description'             => __('Header with title, breadcrumbs and featured image for listings, categories, locations pages', 'W2DC'),
			'base'                    => 'webdirectory-page-header',
			'icon'                    => W2DC_RESOURCES_URL . 'images/webdirectory.png',
			'show_settings_on_create' => false,
			'category'                => __('Directory Content', 'W2DC'),
		)
	);

}

?>