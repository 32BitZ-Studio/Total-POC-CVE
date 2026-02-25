<?php

global $w2dc_buttons_widget_params;
$w2dc_buttons_widget_params = array(
		array(
				'type' => 'directories',
				'param_name' => 'directories',
				'heading' => __("Set specific directory for submit button", "W2DC"),
				'description' => __("Select some items to dispay submit buttons for each directory", "W2DC"),
		),
		array(
				'type' => 'dropdown',
				'param_name' => 'hide_button_text',
				'value' => array(__('No', 'W2DC') => '0', __('Yes', 'W2DC') => '1'),
				'heading' => __('Hide button names, display only popups', 'W2DC'),
		),
		array(
				'type' => 'checkbox',
				'param_name' => 'buttons',
				'value' => array(
						__('Submit button', 'W2DC') => 'submit',
						__('My bookmarks page link', 'W2DC') => 'favourites',
						__('Claim button (only on single listing page)', 'W2DC') => 'claim',
						__('Edit listing button (only on single listing page)', 'W2DC') => 'edit',
						__('Print listing button (only on single listing page)', 'W2DC') => 'print',
						__('Bookmark listing button (only on single listing page)', 'W2DC') => 'bookmark',
						__('Save PDF listing button (only on single listing page)', 'W2DC') => 'pdf',
						__('Logout button', 'W2DC') => 'logout',
				),
				'std' => array('submit', 'favourites', 'claim', 'edit', 'print', 'bookmark', 'pdf', 'logout'),
				'heading' => __('Select buttons to display', 'W2DC'),
				'description' => __('Most of buttons can be displayed only on single listings pages', 'W2DC'),
		),
		array(
				'type' => 'checkbox',
				'param_name' => 'visibility',
				'heading' => __("Show only on directory pages", "W2DC"),
				'value' => 0,
				'description' => __("Otherwise it will load plugin's files on all pages", "W2DC"),
		),
);

class w2dc_buttons_widget extends w2dc_widget {

	public function __construct() {
		global $w2dc_instance, $w2dc_buttons_widget_params;

		parent::__construct(
				'w2dc_buttons_widget',
				__('Directory - Buttons', 'W2DC')
		);

		$this->convertParams($w2dc_buttons_widget_params);
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
			echo '<div class="w2dc-content w2dc-widget w2dc-buttons-widget">';
			$controller = new w2dc_buttons_controller();
			$controller->init($instance);
			echo $controller->display();
			echo '</div>';
			echo $args['after_widget'];
		}
	}
}
?>