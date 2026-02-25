<?php

global $w2dc_listings_widget_params;
$w2dc_listings_widget_params = array(
		array(
				'type' => 'directories',
				'param_name' => 'directories',
				'heading' => __("Listings of these directories", "W2DC"),
		),
		array(
				'type' => 'textfield',
				'param_name' => 'uid',
				'value' => '',
				'heading' => __('uID. Enter unique string to connect this shortcode with another shortcodes', 'W2DC'),
		),
		array(
				'type' => 'dropdown',
				'param_name' => 'onepage',
				'value' => array(__('No', 'W2DC') => '0', __('Yes', 'W2DC') => '1'),
				'heading' => __('Show all possible listings on one page', 'W2DC'),
		),
		array(
				'type' => 'textfield',
				'param_name' => 'perpage',
				'value' => 10,
				'heading' => __('Number of listing per page', 'W2DC'),
				'description' => __('Number of listings to display per page. Set -1 to display all listings without paginator', 'W2DC'),
				'dependency' => array('element' => 'onepage', 'value' => '0'),
		),
		array(
				'type' => 'dropdown',
				'param_name' => 'hide_listings',
				'value' => array(__('No', 'W2DC') => '0', __('Yes', 'W2DC') => '1'),
				'heading' => __('Hide listings', 'W2DC'),
				'description' => __('Hide listings by default, they will appear after search.', 'W2DC'),
		),
		array(
				'type' => 'dropdown',
				'param_name' => 'hide_paginator',
				'value' => array(__('No', 'W2DC') => '0', __('Yes', 'W2DC') => '1'),
				'heading' => __('Hide paginator', 'W2DC'),
				'description' => __('When paginator is hidden - it will display only exact number of listings', 'W2DC'),
				'dependency' => array('element' => 'onepage', 'value' => '0'),
		),
		array(
				'type' => 'dropdown',
				'param_name' => 'scrolling_paginator',
				'value' => array(__('No', 'W2DC') => '0', __('Yes', 'W2DC') => '1'),
				'heading' => __('Load next set of listing on scroll', 'W2DC'),
				'dependency' => array('element' => 'onepage', 'value' => '0'),
				'description' => esc_html__('Works when "Show More Listings" button enabled', 'W2DC')
		),
		array(
				'type' => 'dropdown',
				'param_name' => 'sticky_featured',
				'value' => array(__('No', 'W2DC') => '0', __('Yes', 'W2DC') => '1'),
				'heading' => __('Show only sticky or/and featured listings', 'W2DC'),
				'description' => __('Whether to show only sticky or/and featured listings', 'W2DC'),
		),
		array(
				'type' => 'ordering',
				'param_name' => 'order_by',
				'heading' => __('Order by', 'W2DC'),
				'description' => __('Order listings by any of these parameter', 'W2DC'),
		),
		array(
				'type' => 'dropdown',
				'param_name' => 'order',
				'value' => array(__('Ascending', 'W2DC') => 'ASC', __('Descending', 'W2DC') => 'DESC'),
				'description' => __('Direction of sorting.', 'W2DC'),
		),
		array(
				'type' => 'dropdown',
				'param_name' => 'hide_order',
				'value' => array(__('No', 'W2DC') => '0', __('Yes', 'W2DC') => '1'),
				'heading' => __('Hide ordering links', 'W2DC'),
				'description' => __('Whether to hide ordering navigation links', 'W2DC'),
		),
		array(
				'type' => 'dropdown',
				'param_name' => 'hide_count',
				'value' => array(__('No', 'W2DC') => '0', __('Yes', 'W2DC') => '1'),
				'heading' => __('Hide number of listings', 'W2DC'),
				'description' => __('Whether to hide number of found listings', 'W2DC'),
		),
		array(
				'type' => 'dropdown',
				'param_name' => 'show_views_switcher',
				'value' => array(__('Yes', 'W2DC') => '1', __('No', 'W2DC') => '0'),
				'heading' => __('Show listings views switcher', 'W2DC'),
				'description' => __('Whether to show listings views switcher', 'W2DC'),
		),
		array(
				'type' => 'dropdown',
				'param_name' => 'listings_view_type',
				'value' => array(__('List', 'W2DC') => 'list', __('Grid', 'W2DC') => 'grid'),
				'heading' => __('Listings view by default', 'W2DC'),
				'description' => __('Do not forget that selected view will be stored in cookies', 'W2DC'),
		),
		array(
				'type' => 'dropdown',
				'param_name' => 'listings_view_grid_columns',
				'value' => array('1' => '1', '2' => '2', '3' => '3', '4' => '4'),
				'heading' => __('Number of columns for listings Grid View', 'W2DC'),
				'std' => '2',
				'dependency' => array('element' => 'listings_view_type', 'value' => 'grid'),
		),
		array(
				'type' => 'textfield',
				'param_name' => 'listing_thumb_width',
				'heading' => __('Listing thumbnail logo width in List View', 'W2DC'),
				'value' => 300,
				'description' => __('in pixels', 'W2DC'),
				'dependency' => array('element' => 'listings_view_type', 'value' => 'list'),
		),
		array(
				'type' => 'dropdown',
				'param_name' => 'wrap_logo_list_view',
				'value' => array(__('No', 'W2DC') => '0', __('Yes', 'W2DC') => '1'),
				'heading' => __('Wrap logo image by text content in List View', 'W2DC'),
				'dependency' => array('element' => 'listings_view_type', 'value' => 'list'),
		),
		array(
				'type' => 'dropdown',
				'param_name' => 'grid_view_logo_ratio',
				'value' => array(
						__('1:1 (square)', 'W2DC') => '100',
						__('4:3', 'W2DC') => '75',
						__('16:9', 'W2DC') => '56.25',
						__('2:1', 'W2DC') => '50'
				),
				'heading' => __('Aspect ratio of logo in Grid View', 'W2DC'),
				'std' => '75',
				'dependency' => array('element' => 'listings_view_type', 'value' => 'grid'),
		),
		array(
				'type' => 'dropdown',
				'param_name' => 'logo_animation_effect',
				'value' => array(
						__('Disabled', 'W2DC') => 0,
						__('Enabled', 'W2DC') => 1
				),
				'std' => 1,
				'heading' => __('Thumbnail animation hover effect', 'W2DC'),
		),
		array(
				'type' => 'dropdown',
				'param_name' => 'hide_content',
				'value' => array(__('No', 'W2DC') => '0', __('Yes', 'W2DC') => '1'),
				'heading' => __('Hide content fields data', 'W2DC'),
		),
		array(
				'type' => 'dropdown',
				'param_name' => 'rating_stars',
				'value' => array(__('Yes', 'W2DC') => '1', __('No', 'W2DC') => '0'),
				'heading' => __('Show rating stars', 'W2DC'),
				'description' => __('When ratings addon enabled', 'W2DC'),
		),
		array(
				'type' => 'dropdown',
				'param_name' => 'summary_on_logo_hover',
				'value' => array(__('No', 'W2DC') => '0', __('Yes', 'W2DC') => '1'),
				'heading' => __('Summary text on logo hover', 'W2DC'),
				'dependency' => array('element' => 'hide_content', 'value' => '0'),
		),
		array(
				'type' => 'dropdown',
				'param_name' => 'carousel',
				'value' => array(__('No', 'W2DC') => '0', __('Yes', 'W2DC') => '1'),
				'heading' => __('Carousel slider', 'W2DC'),
		),
		array(
				'type' => 'textfield',
				'param_name' => 'carousel_show_slides',
				'value' => 4,
				'heading' => __('Slides to show', 'W2DC'),
				'dependency' => array('element' => 'carousel', 'value' => '1'),
		),
		array(
				'type' => 'textfield',
				'param_name' => 'carousel_slide_width',
				'value' => 250,
				'heading' => __('Slide width, in pixels', 'W2DC'),
				'dependency' => array('element' => 'carousel', 'value' => '1'),
		),
		array(
				'type' => 'textfield',
				'param_name' => 'carousel_slide_height',
				'value' => 300,
				'heading' => __('Slide height, in pixels', 'W2DC'),
				'dependency' => array('element' => 'carousel', 'value' => '1'),
		),
		array(
				'type' => 'textfield',
				'param_name' => 'carousel_full_width',
				'heading' => __('Carousel width, in pixels. With empty field carousel will take all possible width.', 'W2DC'),
				'dependency' => array('element' => 'carousel', 'value' => '1'),
		),
		array(
				'type' => 'textfield',
				'param_name' => 'address',
				'heading' => __('Address', 'W2DC'),
				'description' => __('Display listings near this address, recommended to set default radius', 'W2DC'),
		),
		array(
				'type' => 'textfield',
				'param_name' => 'radius',
				'heading' => __('Radius', 'W2DC'),
				'description' => __('Display listings near provided address within this radius in miles or kilometers', 'W2DC'),
		),
		array(
				'type' => 'textfield',
				'param_name' => 'author',
				'heading' => __('Author', 'W2DC'),
				'description' => __('Enter exact ID of author or word "related" to get assigned listings of current author (works only on listing page or author page)', 'W2DC'),
		),
		array(
				'type' => 'dropdown',
				'param_name' => 'related_categories',
				'value' => array(__('No', 'W2DC') => '0', __('Yes', 'W2DC') => '1'),
				'heading' => __('Use related categories', 'W2DC'),
				'description' => __('Parameter works only on listings and categories pages', 'W2DC'),
		),
		array(
				'type' => 'categoriesfield',
				'param_name' => 'categories',
				'heading' => __('Select certain categories', 'W2DC'),
		),
		array(
				'type' => 'dropdown',
				'param_name' => 'related_locations',
				'value' => array(__('No', 'W2DC') => '0', __('Yes', 'W2DC') => '1'),
				'heading' => __('Use related locations', 'W2DC'),
				'description' => __('Parameter works only on listings and locations pages', 'W2DC'),
		),
		array(
				'type' => 'locationsfield',
				'param_name' => 'locations',
				'heading' => __('Select certain locations', 'W2DC'),
		),
		array(
				'type' => 'dropdown',
				'param_name' => 'related_tags',
				'value' => array(__('No', 'W2DC') => '0', __('Yes', 'W2DC') => '1'),
				'heading' => __('Use related tags', 'W2DC'),
				'description' => __('Parameter works only on listings and tags pages', 'W2DC'),
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
		),
		array(
				'type' => 'textfield',
				'param_name' => 'post__in',
				'heading' => __('Exact listings', 'W2DC'),
				'description' => __('Comma separated string of listings IDs. Possible to display exact listings.', 'W2DC'),
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

class w2dc_listings_widget extends w2dc_widget {

	public function __construct() {
		global $w2dc_instance, $w2dc_listings_widget_params;

		parent::__construct(
				'w2dc_listings_shortcode_widget',
				__('Directory - Listings', 'W2DC')
		);

		foreach ($w2dc_instance->content_fields->content_fields_array AS $filter_field) {
			if (method_exists($filter_field, 'getWidgetParams') && ($field_params = $filter_field->getWidgetParams())) {
				$w2dc_listings_widget_params = array_merge($w2dc_listings_widget_params, $field_params);
			}
		}

		$this->convertParams($w2dc_listings_widget_params);
	}
	
	public function render_widget($instance, $args) {
		global $w2dc_instance;
		
		// when visibility enabled - show only on directory pages
		if (empty($instance['visibility']) || !empty($w2dc_instance->frontend_controllers)) {
			if (isset($instance['title'])) {
				$title = apply_filters('widget_title', $instance['title']);
			}
			
			echo $args['before_widget'];
			if (!empty($title)) {
				echo $args['before_title'] . $title . $args['after_title'];
			}
			echo '<div class="w2dc-content w2dc-widget w2dc-listings-widget">';
			$controller = new w2dc_listings_controller();
			$controller->init($instance);
			
			// add frontend controller to get compatibility by uID parameter with maps controller
			$w2dc_instance->frontend_controllers['webdirectory-listings'][] = $controller;
			
			echo $controller->display();
			echo '</div>';
			echo $args['after_widget'];
		}
	}
}
?>