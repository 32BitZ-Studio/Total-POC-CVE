<?php

global $w2dc_locations_widget_params;
$w2dc_locations_widget_params = array(
		array(
				'type' => 'dropdown',
				'param_name' => 'custom_home',
				'value' => array(__('No', 'W2DC') => '0', __('Yes', 'W2DC') => '1'),
				'heading' => __('Is it on custom home page?', 'W2DC'),
		),
		array(
				'type' => 'directory',
				'param_name' => 'directory',
				'heading' => __("Locations links will redirect to selected directory", "W2DC"),
		),
		array(
				'type' => 'textfield',
				'param_name' => 'parent',
				'heading' => __('Parent location', 'W2DC'),
				'description' => __('ID of parent location (default 0 – this will build locations tree starting from the parent as root)', 'W2DC'),
				'dependency' => array('element' => 'custom_home', 'value' => '0'),
		),
		array(
				'type' => 'dropdown',
				'param_name' => 'depth',
				'value' => array('1' => '1', '2' => '2'),
				'heading' => __('locations nesting level', 'W2DC'),
				'description' => __('The max depth of locations tree. When set to 1 – only root locations will be listed', 'W2DC'),
			),
		array(
				'type' => 'textfield',
				'param_name' => 'sublocations',
				'heading' => __('Show sublocations items number', 'W2DC'),
				'description' => __('This is the number of sublocations those will be displayed in the table, when location item includes more than this number "View all sublocations ->" link appears at the bottom', 'W2DC'),
				'dependency' => array('element' => 'depth', 'value' => '2'),
		),
		array(
				'type' => 'dropdown',
				'param_name' => 'columns',
				'value' => array('1' => '1', '2' => '2', '3' => '3', '4' => '4'),
				'std' => '2',
				'heading' => __('locations columns number', 'W2DC'),
				'description' => __('locations list is divided by columns', 'W2DC'),
		),
		array(
				'type' => 'dropdown',
				'param_name' => 'count',
				'value' => array(__('Yes', 'W2DC') => '1', __('No', 'W2DC') => '0'),
				'heading' => __('Show location listings count', 'W2DC'),
				'description' => __('Whether to show number of listings assigned with current location', 'W2DC'),
		),
		array(
				'type' => 'dropdown',
				'param_name' => 'hide_empty',
				'value' => array(__('No', 'W2DC') => '0', __('Yes', 'W2DC') => '1'),
				'heading' => __('Hide empty locations', 'W2DC'),
		),
		array(
				'type' => 'dropdown',
				'param_name' => 'grid',
				'value' => array(__('No', 'W2DC') => '0', __('Yes', 'W2DC') => '1'),
				'heading' => __('Enable grid view', 'W2DC'),
		),
		array(
				'type' => 'dropdown',
				'param_name' => 'grid_view',
				'value' => array(
						__('Standard', 'W2DC') => '0',
						__('Left Side Grid', 'W2DC') => '1',
						__('Right Side Grid', 'W2DC') => '2',
						__('Center Grid', 'W2DC') => '3',
				),
				'heading' => __('Grid view', 'W2DC'),
		),
		array(
				'type' => 'dropdown',
				'param_name' => 'icons',
				'value' => array(__('Yes', 'W2DC') => '1', __('No', 'W2DC') => '0'),
				'heading' => __('Show locations icons', 'W2DC'),
		),
		array(
				'type' => 'locationsfield',
				'param_name' => 'locations',
				'heading' => __('locations', 'W2DC'),
				'dependency' => array('element' => 'custom_home', 'value' => '0'),
		),
		array(
				'type' => 'checkbox',
				'param_name' => 'visibility',
				'heading' => __("Show only on directory pages", "W2DC"),
				'value' => 0,
				'description' => __("Otherwise it will load plugin's files on all pages", "W2DC"),
		),
);

class w2dc_locations_widget extends w2dc_widget {

	public function __construct() {
		global $w2dc_instance, $w2dc_locations_widget_params;

		parent::__construct(
				'w2dc_locations_shortcode_widget',
				__('Directory - Locations', 'W2DC')
		);

		$this->convertParams($w2dc_locations_widget_params);
	}
	
	public function render_widget($instance, $args) {
		global $w2dc_instance;
		
		// when visibility enabled - show only on directory pages
		if (empty($instance['visibility']) || !empty($w2dc_instance->frontend_controllers)) {
			$instance['menu'] = 0;
			
			$title = apply_filters('widget_title', $instance['title']);
	
			echo $args['before_widget'];
			if (!empty($title)) {
				echo $args['before_title'] . $title . $args['after_title'];
			}
			echo '<div class="w2dc-content w2dc-widget w2dc-locations-widget">';
			$controller = new w2dc_locations_controller();
			$controller->init($instance);
			echo $controller->display();
			echo '</div>';
			echo $args['after_widget'];
		}
	}
}
?>