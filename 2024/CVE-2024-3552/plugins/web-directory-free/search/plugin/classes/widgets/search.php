<?php

global $wcsearch_search_widget_params;
$wcsearch_search_widget_params = array(
		array(
				'type' => 'formid',
				'param_name' => 'form_id',
				'heading' => esc_html__("Select search form", "WCSEARCH"),
		),
);

class wcsearch_search_widget extends wcsearch_widget {

	public function __construct() {
		global $wcsearch_instance, $wcsearch_search_widget_params;

		parent::__construct(
				'wcsearch_search_widget',
				esc_html__('WC Search Form', 'WCSEARCH')
		);

		$this->convertParams($wcsearch_search_widget_params);
	}
	
	public function render_widget($instance, $args) {
		global $wcsearch_instance;
		
		$search_form_id = $instance['form_id'];
		if ($search_form_id) {
			$title = apply_filters('widget_title', $instance['title']);
	
			echo $args['before_widget'];
			if (!empty($title)) {
				echo esc_attr($args['before_title'] . $title . $args['after_title']);
			}
			echo '<div class="wcsearch-content wcsearch-widget wcsearch-search-widget">';
			echo $wcsearch_instance->renderShortcode(array('id' => $search_form_id), '', WCSEARCH_MAIN_SHORTCODE);
			echo '</div>';
			echo $args['after_widget'];
		}
	}
}

?>