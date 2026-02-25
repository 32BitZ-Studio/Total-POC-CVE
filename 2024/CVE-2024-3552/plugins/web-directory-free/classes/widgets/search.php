<?php

global $w2dc_search_widget_params;
$w2dc_search_widget_params = array(
		array(
				'type' => 'dropdown',
				'param_name' => 'custom_home',
				'value' => array(__('No', 'W2DC') => '0', __('Yes', 'W2DC') => '1'),
				'heading' => __('Is it on custom home page?', 'W2DC'),
		),
		array(
				'type' => 'directory',
				'param_name' => 'directory',
				'heading' => __("Search by directory", "W2DC"),
				'dependency' => array('element' => 'custom_home', 'value' => '0'),
		),
		array(
				'type' => 'textfield',
				'param_name' => 'uid',
				'heading' => __("uID", "W2DC"),
				'description' => __("Enter unique string to connect search form with another elements on the page", "W2DC"),
				'dependency' => array('element' => 'custom_home', 'value' => '0'),
		),
		array(
				'type' => 'formid',
				'param_name' => 'form_id',
				'heading' => esc_html__("Select search form", "W2DC"),
		),
);

class w2dc_search_widget extends w2dc_widget {

	public function __construct() {
		global $w2dc_search_widget_params;

		parent::__construct(
				'w2dc_search_widget',
				__('Directory - Search', 'W2DC')
		);

		$this->convertParams($w2dc_search_widget_params);
	}
	
	public function render_widget($instance, $args) {
		global $w2dc_instance;
		
		// when visibility enabled - show only on directory pages
		if (empty($instance['visibility']) || !empty($w2dc_instance->frontend_controllers)) {
			// when search_visibility enabled - show only when main search form wasn't displayed
			if (!empty($instance['search_visibility']) && !empty($w2dc_instance->frontend_controllers)) {
				foreach ($w2dc_instance->frontend_controllers AS $shortcode_controllers) {
					foreach ($shortcode_controllers AS $controller) {
						if (is_object($controller) && !empty($controller->search_form)) {
							return false;
						}
					}
				}
			}
				
			$title = apply_filters('widget_title', $instance['title']);
				
			// it is auto selection - take current directory
			if ($instance['directory'] == 0) {
				// probably we are on single listing page - it could be found only after frontend controllers were loaded, so we have to repeat setting
				$w2dc_instance->setCurrentDirectory();
		
				$instance['directory'] = $w2dc_instance->current_directory->id;
			}
			
			if (empty($instance['form_id'])) {
				$instance['columns'] = 1;
			}

			echo $args['before_widget'];
			if (!empty($title)) {
				echo $args['before_title'] . $title . $args['after_title'];
			}
			echo '<div class="w2dc-content w2dc-widget w2dc-search-widget">';
			$controller = new w2dc_search_controller();
			$controller->init($instance);
			echo $controller->display();
			echo '</div>';
			echo $args['after_widget'];
		}
	}
}
?>