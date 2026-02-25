<?php

global $w2dc_listing_report_widget_params;
$w2dc_listing_report_widget_params = array(
		array(
				'type' => 'textfield',
				'param_name' => 'listing',
				'heading' => __('Listing ID', 'W2DC'),
				'description' => __('Leave empty if you place it on single listing page', 'W2DC'),
		),
);

class w2dc_listing_report_widget extends w2dc_widget {

	public function __construct() {
		global $w2dc_instance, $w2dc_listing_report_widget_params;

		parent::__construct(
				'w2dc_listing_report_shortcode_widget',
				__('Directory - Listing report', 'W2DC')
		);

		$this->convertParams($w2dc_listing_report_widget_params);
	}
	
	public function render_widget($instance, $args) {
		global $w2dc_instance;
		
		if (empty($instance['listing']) && !w2dc_isListing()) {
			return false;
		}

		if (isset($instance['title'])) {
			$title = apply_filters('widget_title', $instance['title']);
		}
			
		echo $args['before_widget'];
		if (!empty($title)) {
			echo $args['before_title'] . $title . $args['after_title'];
		}
		echo '<div class="w2dc-content w2dc-widget w2dc-listing-report-widget">';
		$controller = new w2dc_listing_report_controller();
		$controller->init($instance);
		echo $controller->display();
		echo '</div>';
		echo $args['after_widget'];
	}
}

?>