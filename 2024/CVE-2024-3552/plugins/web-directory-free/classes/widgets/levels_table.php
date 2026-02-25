<?php

global $w2dc_levels_table_widget_params;
$w2dc_levels_table_widget_params = array(
		array(
				'type' => 'levels',
				'param_name' => 'levels',
				'heading' => __('Listings levels', 'W2DC'),
				'description' => __('Choose exact levels to display', 'W2DC'),
				'value' => '',
		),
		array(
				'type' => 'directory',
				'param_name' => 'directory',
				'heading' => __("Specific directory", "W2DC"),
		),
		array(
				'type' => 'dropdown',
				'param_name' => 'columns',
				'value' => array('1' => '1', '2' => '2', '3' => '3', '4' => '4'),
				'std' => '3',
				'heading' => __('Columns', 'W2DC'),
		),
		array(
				'type' => 'dropdown',
				'param_name' => 'columns_same_height',
				'value' => array(__('No', 'W2DC') => '0', __('Yes', 'W2DC') => '1'),
				'heading' => __('Show negative parameters', 'W2DC'),
				'description' => __('Show parameters those have negation. For example, such row in the table will be shown: Featured Listings - No. In other case this row will be hidden.', 'W2DC'),
		),
		array(
				'type' => 'dropdown',
				'param_name' => 'show_period',
				'value' => array(__('Yes', 'W2DC') => '1', __('No', 'W2DC') => '0'),
				'heading' => __('Show level active period on choose level page', 'W2DC'),
		),
		array(
				'type' => 'dropdown',
				'param_name' => 'show_sticky',
				'value' => array(__('Yes', 'W2DC') => '1', __('No', 'W2DC') => '0'),
				'heading' => __('Show is level sticky on choose level page', 'W2DC'),
		),
		array(
				'type' => 'dropdown',
				'param_name' => 'show_featured',
				'value' => array(__('Yes', 'W2DC') => '1', __('No', 'W2DC') => '0'),
				'heading' => __('Show is level featured on choose level page', 'W2DC'),
		),
		array(
				'type' => 'dropdown',
				'param_name' => 'show_categories',
				'value' => array(__('Yes', 'W2DC') => '1', __('No', 'W2DC') => '0'),
				'heading' => esc_attr__("Show level's categories number on choose level page", 'W2DC'),
		),
		array(
				'type' => 'dropdown',
				'param_name' => 'show_locations',
				'value' => array(__('Yes', 'W2DC') => '1', __('No', 'W2DC') => '0'),
				'heading' => esc_attr__("Show level's locations number on choose level page", 'W2DC'),
		),
		array(
				'type' => 'dropdown',
				'param_name' => 'show_maps',
				'value' => array(__('Yes', 'W2DC') => '1', __('No', 'W2DC') => '0'),
				'heading' => __('Show is level supports maps on choose level page', 'W2DC'),
		),
		array(
				'type' => 'dropdown',
				'param_name' => 'show_images',
				'value' => array(__('Yes', 'W2DC') => '1', __('No', 'W2DC') => '0'),
				'heading' => esc_attr__("Show level's images number on choose level page", 'W2DC'),
		),
		array(
				'type' => 'dropdown',
				'param_name' => 'show_videos',
				'value' => array(__('Yes', 'W2DC') => '1', __('No', 'W2DC') => '0'),
				'heading' => esc_attr__("Show level's videos number on choose level page", 'W2DC'),
		),
		array(
				'type' => 'textarea',
				'param_name' => 'options',
				'heading' => __("Options", "W2DC"),
				'description' => __("Example: 1=option=no;2=option=yes;", "W2DC"),
		),
);

class w2dc_levels_table_widget extends w2dc_widget {

	public function __construct() {
		global $w2dc_instance, $w2dc_levels_table_widget_params;

		parent::__construct(
				'w2dc_levels_table_widget',
				__('Directory - Listings levels', 'W2DC')
		);

		$this->convertParams($w2dc_levels_table_widget_params);
	}
	
	public function render_widget($instance, $args) {
		global $w2dc_instance;
		
		$title = apply_filters('widget_title', $instance['title']);
	
		echo $args['before_widget'];
		if (!empty($title)) {
			echo $args['before_title'] . $title . $args['after_title'];
		}
		echo '<div class="w2dc-content w2dc-widget w2dc-levels-table-widget">';
		$controller = new w2dc_levels_table_controller();
		$controller->init($instance);
		echo $controller->display();
		echo '</div>';
		echo $args['after_widget'];
	}
}
?>