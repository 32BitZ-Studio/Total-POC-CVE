<?php

global $w2dc_content_field_widget_params;
$w2dc_content_field_widget_params = array(
		array(
				'type' => 'contentfield',
				'param_name' => 'id',
				'heading' => __('Content field', 'W2DC'),
		),
		array(
				'type' => 'textfield',
				'param_name' => 'listing',
				'heading' => __('Listing ID', 'W2DC'),
				'description' => __('Leave empty if you place it on single listing page', 'W2DC'),
		),
		array(
				'type' => 'textfield',
				'param_name' => 'classes',
				'heading' => __('CSS classes', 'W2DC'),
				'description' => __('CSS classes to add to content field wrapper', 'W2DC'),
		),
		array(
				'type' => 'checkbox',
				'param_name' => 'visibility',
				'heading' => __("Show only on directory pages", "W2DC"),
				'value' => 0,
				'description' => __("Otherwise it will load plugin's files on all pages", "W2DC"),
		),
);

class w2dc_content_field_widget extends w2dc_widget {

	public function __construct() {
		global $w2dc_instance, $w2dc_content_field_widget_params;

		parent::__construct(
				'w2dc_content_field_shortcode_widget',
				__('Directory - Content field', 'W2DC')
		);

		$this->convertParams($w2dc_content_field_widget_params);
	}
	
	public function render_widget($instance, $args) {
		global $w2dc_instance;
		
		if (empty($instance['listing']) && !w2dc_isListing()) {
			return false;
		}
		
		// when visibility enabled - show only on directory pages
		if (empty($instance['visibility']) || !empty($w2dc_instance->frontend_controllers)) {
			if (isset($instance['title'])) {
				$title = apply_filters('widget_title', $instance['title']);
			}
			
			echo $args['before_widget'];
			if (!empty($title)) {
				echo $args['before_title'] . $title . $args['after_title'];
			}
			echo '<div class="w2dc-content w2dc-widget w2dc-breadcrumbs-widget">';
			$controller = new w2dc_content_field_controller();
			$controller->init($instance);
			echo $controller->display();
			echo '</div>';
			echo $args['after_widget'];
		}
	}
}

?>