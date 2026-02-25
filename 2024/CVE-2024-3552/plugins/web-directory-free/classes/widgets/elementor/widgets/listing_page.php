<?php

class w2dc_listing_page_elementor_widget extends w2dc_elementor_widget {

	public function get_name() {
		return 'listing_page';
	}

	public function get_title() {
		return __('Listing Page', 'W2DC');
	}

	public function get_icon() {
		return 'eicon-single-page';
	}
	
	public function get_categories() {
		return array('directory-single-category');
	}
	
	protected function register_controls() {
	
		$this->start_controls_section(
				'content_section',
				array(
						'label' => esc_html__('Listing page', 'W2DC'),
						'tab' => \Elementor\Controls_Manager::TAB_CONTENT,
				)
		);
		
		global $w2dc_listing_page_widget_params;
		
		$controls = w2dc_elementor_convert_params($w2dc_listing_page_widget_params);
		
		foreach ($controls AS $param_name=>$control) {
			$this->add_control($param_name, $control);
		}
	
		$this->end_controls_section();
	}
	
	protected function render() {
		
		global $w2dc_instance;
		
		$settings = $this->get_settings_for_display();
		
		$controller = new w2dc_directory_controller();
		$controller->init($settings, W2DC_LISTING_SHORTCODE);
		
		echo $controller->display();
	}
}

?>