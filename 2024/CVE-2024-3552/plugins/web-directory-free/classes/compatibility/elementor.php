<?php

add_action('wp_footer', 'w2dc_elementor_support_wp_footer');
function w2dc_elementor_support_wp_footer() {
	if (!defined('ELEMENTOR_VERSION')) {
		return;
	}
	?>
	<script>
		jQuery(function($) {
			var interval = setInterval(function() {
				if (typeof elementorFrontend != 'undefined' && typeof elementorFrontend.hooks != 'undefined') {
					elementorFrontend.hooks.addAction('frontend/element_ready/global', function(el) {
						if (el.data("widget_type") == 'map.default' && typeof w2dc_load_maps != 'undefined') {
							for (var i=0; i<w2dc_map_markers_attrs_array.length; i++) {
								w2dc_load_map(i);
							}
						}
					});

					clearInterval(interval);
				}
			}, 100);
		});
	</script>
	<?php
}

/**
 * return content of the listing page built by Elementor
 * 
 */
add_action('w2dc_the_content_listing_page', 'w2dc_elementor_listing_page_the_content');
function w2dc_elementor_listing_page_the_content($page_content) {
	if (!defined('ELEMENTOR_VERSION')) {
		return $page_content;
	}
	
	global $w2dc_instance;
	
	$elementor_content = \Elementor\Plugin::$instance->frontend->get_builder_content_for_display($w2dc_instance->listing_page_id);
	
	if (empty($elementor_content) && $page_content) {
		return $page_content;
	} else {
		return $elementor_content;
	}
}

global $w2dc_directory_elements_list;
$w2dc_directory_elements_list = array(
		'directory',
);

global $w2dc_listing_elements_list;
$w2dc_listing_elements_list = array(
		'listing_page',
		'listing_header',
		'listing_gallery',
		'listing_map',
		'listing_videos',
		'listing_contact',
		'listing_report',
		'listing_comments',
		'listing_fields',
);

add_filter('w2dc_get_directory_of_page', 'w2dc_elementor_get_directory_of_page', 10, 2);
function w2dc_elementor_get_directory_of_page($current_directory, $page_id) {
	global $wpdb, $w2dc_instance;
	
	if (!defined('ELEMENTOR_VERSION')) {
		return $current_directory;
	}
	
	$elementor_data = get_post_meta($page_id, '_elementor_data' ,true);

	if (is_string($elementor_data) && !empty($elementor_data)) {
		$elementor_data = json_decode($elementor_data, true);
		
		if ($elementor_data) {
				
			$widget = w2dc_elementor_find_directory_elem($elementor_data);
			
			if ($widget) {
				if (!empty($widget['settings']['directories'])) {
					$directory_id = $widget['settings']['directories'];
				} else {
					$directory_id = $w2dc_instance->directories->getDefaultDirectory()->id;
				}
				
				$current_directory = $w2dc_instance->directories->getDirectoryById($directory_id);
			}
		}
	}

	return $current_directory;
}

/**
 * add pages built by Elementor
 * 
 */
add_filter('w2dc_get_all_directory_pages', 'w2dc_elementor_directory_pages');
function w2dc_elementor_directory_pages($directory_pages) {
	global $wpdb, $w2dc_instance, $w2dc_directory_elements_list;
	
	if (!defined('ELEMENTOR_VERSION')) {
		return $directory_pages;
	}
	
	foreach ($w2dc_directory_elements_list AS $el) {
		$sql_or[] = "pm.meta_value LIKE '%\"widgetType\":\"" . $el . "\"%'";
	}
	
	$elem_directory_pages = $wpdb->get_results("
		SELECT p.ID, pm.meta_value FROM {$wpdb->posts} AS p
		LEFT JOIN {$wpdb->postmeta} AS pm ON p.ID = pm.post_id
		WHERE (pm.meta_key = '_elementor_data' AND " . implode(" OR ", $sql_or) . ") AND p.post_status = 'publish' AND p.post_type = 'page'", ARRAY_A);
	
	foreach ($elem_directory_pages AS $row) {
		$post_id = $row['ID'];
		
		$directory_pages[] = array(
				'id' => $post_id,
				'slug' => get_post($post_id)->post_name,
		);
	}
	
	return $directory_pages;
}

/**
 * add pages built by Elementor
 * 
 */
add_filter('w2dc_get_all_listing_pages', 'w2dc_elementor_listing_pages');
function w2dc_elementor_listing_pages($listing_pages) {
	global $wpdb, $w2dc_instance, $w2dc_listing_elements_list;
	
	if (!defined('ELEMENTOR_VERSION')) {
		return $listing_pages;
	}
	
	foreach ($w2dc_listing_elements_list AS $el) {
		$sql_or[] = "pm.meta_value LIKE '%\"widgetType\":\"" . $el . "\"%'";
	}
	
	$elem_listing_pages = $wpdb->get_results("
		SELECT p.ID, pm.meta_value FROM {$wpdb->posts} AS p
		LEFT JOIN {$wpdb->postmeta} AS pm ON p.ID = pm.post_id
		WHERE (pm.meta_key = '_elementor_data' AND " . implode(" OR ", $sql_or) . ") AND p.post_status = 'publish' AND p.post_type = 'page'", ARRAY_A);
	
	foreach ($elem_listing_pages AS $row) {
		$post_id = $row['ID'];
		$elementor_data = json_decode($row['meta_value'], true);
		
		if ($elementor_data) {
			
			$widget = w2dc_elementor_find_listing_elem($elementor_data);
			
			if (!empty($widget['settings']['directory'])) {
				$directory_id = $widget['settings']['directory'];
				
				if (isset($listing_pages[$directory_id])) {
					return $listing_pages;
				} else {
					$listing_pages[$directory_id] = $post_id;
				}
			} else {
				$listing_pages[$w2dc_instance->directories->getDefaultDirectory()->id] = $post_id;
			}
		}
	}
	
	return $listing_pages;
}

function w2dc_elementor_find_listing_page_elem($item) {
	global $w2dc_elementor_listing_page_widget;

	if (is_array($item)) {
		if (!isset($item['widgetType']) || $item['widgetType'] != 'listing_page') {
			array_map('w2dc_elementor_find_listing_page_elem', $item);
		} else {
			$w2dc_elementor_listing_page_widget = $item;
		}
	}
}

/**
 * detect is page contains listing header Elementor widget
 */
add_filter('w2dc_is_listing_elements_on_page', 'w2dc_is_listing_elements_on_page');
function w2dc_is_listing_elements_on_page($is_on_page) {

	if (!defined('ELEMENTOR_VERSION')) {
		return $is_on_page;
	}
	
	global $w2dc_instance;
	
	$elementor_data = get_post_meta($w2dc_instance->listing_page_id, '_elementor_data' ,true);

	if (is_string($elementor_data) && !empty($elementor_data)) {
		$elementor_data = json_decode($elementor_data, true);
	}

	if ($elementor_data) {
		$is_on_page = w2dc_elementor_find_listing_elem($elementor_data);
	}

	return $is_on_page;
}

function w2dc_elementor_find_directory_elem($elementor_data) {
	
	global $w2dc_elementor_directory_element_widget, $w2dc_directory_elements_list;
	
	$w2dc_elementor_directory_element_widget = false;
	
	array_map(
			function($item) use ($w2dc_directory_elements_list) { return _w2dc_elementor_find_directory_elem($item, $w2dc_directory_elements_list); },
			$elementor_data
	);
	
	return $w2dc_elementor_directory_element_widget;
}

function _w2dc_elementor_find_directory_elem($item, $elements_list) {
	global $w2dc_elementor_directory_element_widget;

	if (is_array($item)) {
		if (!isset($item['widgetType']) || !in_array($item['widgetType'], $elements_list)) {
			array_map(
			function($item) use ($elements_list) { return _w2dc_elementor_find_directory_elem($item, $elements_list); },
			$item
			);
		} else {
			$w2dc_elementor_directory_element_widget = $item;
		}
	}
}

function w2dc_elementor_find_listing_elem($elementor_data) {
	
	global $w2dc_elementor_listing_element_widget, $w2dc_listing_elements_list;
	
	$w2dc_elementor_listing_element_widget = false;
	
	array_map(
			function($item) use ($w2dc_listing_elements_list) { return _w2dc_elementor_find_listing_elem($item, $w2dc_listing_elements_list); },
			$elementor_data
	);
	
	return $w2dc_elementor_listing_element_widget;
}

function _w2dc_elementor_find_listing_elem($item, $elements_list) {
	global $w2dc_elementor_listing_element_widget;

	if (is_array($item)) {
		if (!isset($item['widgetType']) || !in_array($item['widgetType'], $elements_list)) {
			array_map(
					function($item) use ($elements_list) { return _w2dc_elementor_find_listing_elem($item, $elements_list); },
					$item
			);
		} else {
			$w2dc_elementor_listing_element_widget = $item;
		}
	}
}

/**
 * load listing controller if the page contains listing page or listing header Elementor widget
 */
add_action('w2dc_load_frontend_controllers', 'w2dc_elementor_load_directory_post_controllers');
function w2dc_elementor_load_directory_post_controllers($post) {
	global $w2dc_instance;
	
	if (!empty($post->ID)) {
		$post_id = $post->ID;
		$post_meta = get_post_meta($post_id, '_elementor_data', true);
		
		if (is_string($post_meta) && !empty($post_meta)) {
			
			$elementor_data = json_decode($post_meta, true);
	
			if ($elementor_data) {
				
				$widget = w2dc_elementor_find_listing_elem($elementor_data);
				
				if ($widget) {
	
					if (!empty($widget['settings']['directory'])) {
						$directory_id = $widget['settings']['directory'];
					} else {
						$directory_id = $w2dc_instance->directories->getDefaultDirectory()->id;
					}
					
					$settings = array_merge(array(
							'directory' => $directory_id,
					), $widget['settings']);
	
					$controller = new w2dc_directory_controller();
					$controller->init($settings, W2DC_LISTING_SHORTCODE);
	
					$w2dc_instance->frontend_controllers[W2DC_LISTING_SHORTCODE][] = $controller;
				}
			}
		}
	}
}

/**
 * load directory controller if the page contains directory widget
 */
add_action('w2dc_load_frontend_controllers', 'w2dc_elementor_load_directory_controllers');
function w2dc_elementor_load_directory_controllers($post) {
	global $w2dc_instance;
	
	if (!empty($post->ID)) {
		$post_id = $post->ID;
		$post_meta = get_post_meta($post_id, '_elementor_data', true);
		
		if (is_string($post_meta) && !empty($post_meta)) {
			
			$elementor_data = json_decode($post_meta, true);
	
			if ($elementor_data) {
				
				$widget = w2dc_elementor_find_directory_elem($elementor_data);
				
				if ($widget) {
	
					if (!empty($widget['settings']['directories'])) {
						$directory_id = $widget['settings']['directories'];
					} else {
						$directory_id = $w2dc_instance->directories->getDefaultDirectory()->id;
					}
					
					$settings = array_merge(array(
							'directories' => $directory_id,
					), $widget['settings']);
	
					$controller = new w2dc_directory_controller();
					$controller->init($settings, W2DC_MAIN_SHORTCODE);
	
					$w2dc_instance->frontend_controllers[W2DC_MAIN_SHORTCODE][] = $controller;
				}
			}
		}
	}
}

?>