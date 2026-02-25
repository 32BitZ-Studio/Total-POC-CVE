<?php

global $w2dc_map_widget_params;
$w2dc_map_widget_params = array(
		array(
				'type' => 'dropdown',
				'param_name' => 'custom_home',
				'value' => array(__('No', 'W2DC') => '0', __('Yes', 'W2DC') => '1'),
				'heading' => __('Is it on custom home page?', 'W2DC'),
		),
		array(
				'type' => 'directories',
				'param_name' => 'directories',
				'heading' => __("Listings of these directories", "W2DC"),
				'dependency' => array('element' => 'custom_home', 'value' => '0'),
		),
		array(
				'type' => 'dropdown',
				'param_name' => 'map_markers_is_limit',
				'value' => array(__('The only map markers of visible listings will be displayed (when listings shortcode is connected with map by unique string)', 'W2DC') => '1', __('Display all map markers', 'W2DC') => '0'),
				'heading' => __('How many map markers to display on the map', 'W2DC'),
				//'dependency' => array('element' => 'custom_home', 'value' => '0'),
		),
		array(
				'type' => 'textfield',
				'param_name' => 'uid',
				'value' => '',
				'heading' => __('uID. Enter unique string to connect this shortcode with another shortcodes', 'W2DC'),
				'dependency' => array('element' => 'custom_home', 'value' => '0'),
		),
		array(
				'type' => 'dropdown',
				'param_name' => 'draw_panel',
				'value' => array(__('No', 'W2DC') => '0', __('Yes', 'W2DC') => '1'),
				'heading' => __('Enable Draw Panel', 'W2DC'),
				'description' => __('Very important: MySQL version must be 5.6.1 and higher or MySQL server variable "thread stack" must be 256K and higher. Ask your hoster about it if "Draw Area" does not work.', 'W2DC'),
		),
		array(
				'type' => 'textfield',
				'param_name' => 'num',
				'value' => 10,
				'heading' => __('Number of markers', 'W2DC'),
				'description' => __('Number of markers to display on map (-1 gives all markers)', 'W2DC'),
		),
		array(
				'type' => 'textfield',
				'param_name' => 'width',
				'heading' => __('Width', 'W2DC'),
				'description' => __('Set map width in pixels. With empty field the map will take all possible width.', 'W2DC'),
		),
		array(
				'type' => 'textfield',
				'param_name' => 'height',
				'value' => 400,
				'heading' => __('Height', 'W2DC'),
				'description' => __('Set map height in pixels, also possible to set 100% value', 'W2DC'),
		),
		array(
				'type' => 'mapstyle',
				'param_name' => 'map_style',
				'heading' => __('Maps style', 'W2DC'),
		),
		array(
				'type' => 'dropdown',
				'param_name' => 'sticky_scroll',
				'value' => array(__('No', 'W2DC') => '0', __('Yes', 'W2DC') => '1'),
				'heading' => __('Make map to be sticky on scroll', 'W2DC'),
		),
		array(
				'type' => 'textfield',
				'param_name' => 'sticky_scroll_toppadding',
				'value' => 0,
				'heading' => __('Sticky scroll top padding', 'W2DC'),
				'description' => __('Top padding in pixels', 'W2DC'),
				'dependency' => array('element' => 'sticky_scroll', 'value' => '1'),
		),
		array(
				'type' => 'dropdown',
				'param_name' => 'show_summary_button',
				'value' => array(__('No', 'W2DC') => '0', __('Yes', 'W2DC') => '1'),
				'heading' => __('Show summary button', 'W2DC'),
				'description' => __('Show summary button in InfoWindow', 'W2DC'),
		),
		array(
				'type' => 'dropdown',
				'param_name' => 'show_readmore_button',
				'value' => array(__('Yes', 'W2DC') => '1', __('No', 'W2DC') => '0'),
				'heading' => __('Show readmore button', 'W2DC'),
				'description' => __('Show read more button in InfoWindow', 'W2DC'),
		),
		array(
				'type' => 'dropdown',
				'param_name' => 'geolocation',
				'value' => array(__('No', 'W2DC') => '0', __('Yes', 'W2DC') => '1'),
				'heading' => __('GeoLocation', 'W2DC'),
				'description' => __('Geolocate user and center map', 'W2DC'),
		),
		array(
				'type' => 'dropdown',
				'param_name' => 'ajax_map_loading',
				'value' => array(__('No', 'W2DC') => '0', __('Yes', 'W2DC') => '1'),
				'heading' => __('AJAX loading', 'W2DC'),
				'description' => __('When map contains lots of markers - this may slow down map markers loading. Select AJAX to speed up loading. Requires Starting Address or Starting Point coordinates Latitude and Longitude.', 'W2DC'),
		),
		array(
				'type' => 'dropdown',
				'param_name' => 'ajax_markers_loading',
				'value' => array(__('No', 'W2DC') => '0', __('Yes', 'W2DC') => '1'),
				'heading' => __('Maps info window AJAX loading', 'W2DC'),
				'description' => __('This may additionaly speed up loading', 'W2DC'),
		),
		array(
				'type' => 'textfield',
				'param_name' => 'start_address',
				'heading' => __('Starting Address', 'W2DC'),
				'description' => __('When map markers load by AJAX - it should have starting point and starting zoom. Enter start address or select latitude and longitude (recommended). Example: 1600 Amphitheatre Pkwy, Mountain View, CA 94043, USA', 'W2DC'),
		),
		array(
				'type' => 'textfield',
				'param_name' => 'start_latitude',
				'heading' => __('Starting Point Latitude', 'W2DC'),
		),
		array(
				'type' => 'textfield',
				'param_name' => 'start_longitude',
				'heading' => __('Starting Point Longitude', 'W2DC'),
		),
		array(
				'type' => 'dropdown',
				'param_name' => 'start_zoom',
				'heading' => __('Default zoom', 'W2DC'),
				'value' => array(__("Auto", "W2DC") => '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19'),
				'std' => '0',
		),
		array(
				'type' => 'dropdown',
				'param_name' => 'min_zoom',
				'heading' => __('Min zoom', 'W2DC'),
				'value' => array(__("Auto", "W2DC") => '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19'),
				'std' => '0',
		),
		array(
				'type' => 'dropdown',
				'param_name' => 'max_zoom',
				'heading' => __('Max zoom', 'W2DC'),
				'value' => array(__("Auto", "W2DC") => '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19'),
				'std' => '0',
		),
		array(
				'type' => 'dropdown',
				'param_name' => 'sticky_featured',
				'value' => array(__('No', 'W2DC') => '0', __('Yes', 'W2DC') => '1'),
				'heading' => __('Show markers only of sticky or/and featured listings', 'W2DC'),
				'description' => __('Whether to show markers only of sticky or/and featured listings', 'W2DC'),
				'dependency' => array('element' => 'custom_home', 'value' => '0'),
		),
		array(
				'type' => 'dropdown',
				'param_name' => 'search_on_map',
				'value' => array(__('No', 'W2DC') => '0', __('Yes', 'W2DC') => '1'),
				'heading' => __('Show search form and listings sidebar on the map', 'W2DC'),
		),
		array(
				'type' => 'formid',
				'param_name' => 'search_on_map_id',
				'heading' => __('Select search form', 'W2DC'),
		),
		array(
				'type' => 'dropdown',
				'param_name' => 'search_on_map_open',
				'value' => array(__('No', 'W2DC') => '0', __('Yes', 'W2DC') => '1'),
				'heading' => __('Search form open by default', 'W2DC'),
				'dependency' => array('element' => 'search_on_map', 'value' => '1'),
		),
		array(
				'type' => 'dropdown',
				'param_name' => 'search_on_map_right',
				'value' => array(__('Left', 'W2DC') => '0', __('Right', 'W2DC') => '1'),
				'heading' => __('Show search form at the sidebar', 'W2DC'),
				'dependency' => array('element' => 'search_on_map', 'value' => '0'),
		),
		array(
				'type' => 'dropdown',
				'param_name' => 'search_on_map_listings',
				'value' => array(
						__('In sidebar', 'W2DC') => 'sidebar',
						__('At the bottom', 'W2DC') => 'bottom',
				),
				'heading' => __('Show listings', 'W2DC'),
				'dependency' => array('element' => 'search_on_map', 'value' => '1'),
		),
		array(
				'type' => 'dropdown',
				'param_name' => 'radius_circle',
				'value' => array(__('Yes', 'W2DC') => '1', __('No', 'W2DC') => '0'),
				'heading' => __('Show radius circle', 'W2DC'),
				'description' => __('Display radius circle on map when radius filter provided', 'W2DC'),
		),
		array(
				'type' => 'dropdown',
				'param_name' => 'clusters',
				'value' => array(__('No', 'W2DC') => '0', __('Yes', 'W2DC') => '1'),
				'heading' => __('Group map markers in clusters', 'W2DC'),
		),
		array(
				'type' => 'dropdown',
				'param_name' => 'enable_full_screen',
				'value' => array(__('Yes', 'W2DC') => '1', __('No', 'W2DC') => '0'),
				'heading' => __('Enable full screen button', 'W2DC'),
		),
		array(
				'type' => 'dropdown',
				'param_name' => 'enable_wheel_zoom',
				'value' => array(__('Yes', 'W2DC') => '1', __('No', 'W2DC') => '0'),
				'heading' => __('Enable zoom by mouse wheel', 'W2DC'),
		),
		array(
				'type' => 'dropdown',
				'param_name' => 'enable_dragging_touchscreens',
				'value' => array(__('Yes', 'W2DC') => '1', __('No', 'W2DC') => '0'),
				'heading' => __('Enable map dragging on touch screen devices', 'W2DC'),
		),
		array(
				'type' => 'dropdown',
				'param_name' => 'center_map_onclick',
				'value' => array(__('No', 'W2DC') => '0', __('Yes', 'W2DC') => '1'),
				'heading' => __('Center map on marker click', 'W2DC'),
		),
		array(
				'type' => 'textfield',
				'param_name' => 'author',
				'heading' => __('Author', 'W2DC'),
				'description' => __('Enter exact ID of author or word "related" to get assigned listings of current author (works only on listing page or author page)', 'W2DC'),
				'dependency' => array('element' => 'custom_home', 'value' => '0'),
		),
		array(
				'type' => 'dropdown',
				'param_name' => 'related_categories',
				'value' => array(__('No', 'W2DC') => '0', __('Yes', 'W2DC') => '1'),
				'heading' => __('Use related categories', 'W2DC'),
				'description' => __('Parameter works only on listings and categories pages', 'W2DC'),
				'dependency' => array('element' => 'custom_home', 'value' => '0'),
		),
		array(
				'type' => 'categoriesfield',
				'param_name' => 'categories',
				'heading' => __('Select listings categories to display on map', 'W2DC'),
				'dependency' => array('element' => 'custom_home', 'value' => '0'),
		),
		array(
				'type' => 'dropdown',
				'param_name' => 'related_locations',
				'value' => array(__('No', 'W2DC') => '0', __('Yes', 'W2DC') => '1'),
				'heading' => __('Use related locations.', 'W2DC'),
				'description' => __('Parameter works only on listings and locations pages', 'W2DC'),
				'dependency' => array('element' => 'custom_home', 'value' => '0'),
		),
		array(
				'type' => 'locationsfield',
				'param_name' => 'locations',
				'heading' => __('Select listings locations to display on map', 'W2DC'),
				'dependency' => array('element' => 'custom_home', 'value' => '0'),
		),
		array(
				'type' => 'dropdown',
				'param_name' => 'related_tags',
				'value' => array(__('No', 'W2DC') => '0', __('Yes', 'W2DC') => '1'),
				'heading' => __('Use related tags', 'W2DC'),
				'description' => __('Parameter works only on listings and tags pages', 'W2DC'),
				'dependency' => array('element' => 'custom_home', 'value' => '0'),
		),
		array(
				'type' => 'dropdown',
				'param_name' => 'include_categories_children',
				'value' => array(__('No', 'W2DC') => '0', __('Yes', 'W2DC') => '1'),
				'heading' => __('Include children of selected categories and locations', 'W2DC'),
				'description' => __('When enabled - any subcategories or sublocations will be included as well. Related categories and locations also affected.', 'W2DC'),
				'dependency' => array('element' => 'custom_home', 'value' => '0'),
		),
		array(
				'type' => 'levels',
				'param_name' => 'levels',
				'heading' => __('Listings levels', 'W2DC'),
				'description' => __('Categories may be dependent from listings levels', 'W2DC'),
				'dependency' => array('element' => 'custom_home', 'value' => '0'),
		),
		array(
				'type' => 'textfield',
				'param_name' => 'post__in',
				'heading' => __('Exact listings', 'W2DC'),
				'description' => __('Comma separated string of listings IDs. Possible to display exact listings.', 'W2DC'),
				'dependency' => array('element' => 'custom_home', 'value' => '0'),
		),
		array(
				'type' => 'textfield',
				'param_name' => 'start_listings',
				'heading' => __('Start listings', 'W2DC'),
				'description' => __('Comma separated string of listings IDs. Display these listings by default, then directory searches as usual.', 'W2DC'),
		),
		array(
				'type' => 'checkbox',
				'param_name' => 'visibility',
				'heading' => __("Show only on directory pages", "W2DC"),
				'value' => 0,
				'description' => __("Otherwise it will load plugin's files on all pages", "W2DC"),
		),
);

class w2dc_map_widget extends w2dc_widget {

	public function __construct() {
		global $w2dc_instance, $w2dc_map_widget_params;

		parent::__construct(
				'w2dc_map_widget',
				__('Directory - Map', 'W2DC')
		);

		foreach ($w2dc_instance->content_fields->content_fields_array AS $filter_field) {
			if (method_exists($filter_field, 'getWidgetParams') && ($field_params = $filter_field->getWidgetParams())) {
				$w2dc_map_widget_params = array_merge($w2dc_map_widget_params, $field_params);
			}
		}

		$this->convertParams($w2dc_map_widget_params);
	}
	
	public function render_widget($instance, $args) {
		global $w2dc_instance;
		
		// when visibility enabled - show only on directory pages
		if (empty($instance['visibility']) || !empty($w2dc_instance->frontend_controllers)) {
	
			$title = apply_filters('widget_title', $instance['title']);
	
			echo $args['before_widget'];
			if (!empty($title)) {
				echo $args['before_title'] . $title . $args['after_title'];
			}
			echo '<div class="w2dc-content w2dc-widget w2dc-map-widget">';
			$controller = new w2dc_map_controller();
			$controller->init($instance);
			echo $controller->display();
			echo '</div>';
			echo $args['after_widget'];
		}
	}
}
?>