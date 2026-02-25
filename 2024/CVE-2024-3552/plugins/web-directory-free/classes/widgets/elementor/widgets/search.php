<?php

class w2dc_search_elementor_widget extends w2dc_elementor_widget {

	public function get_name() {
		return 'search';
	}

	public function get_title() {
		return __('Search', 'W2DC');
	}

	public function get_icon() {
		return 'eicon-code';
	}
	
	public function get_categories() {
		return array('directory-category');
	}
	
	protected function register_controls() {
	
		$this->start_controls_section(
				'content_section',
				array(
						'label' => esc_html__('Search', 'W2DC'),
						'tab' => \Elementor\Controls_Manager::TAB_CONTENT,
				)
		);
		
		global $w2dc_search_widget_params;
		
		$controls = w2dc_elementor_convert_params($w2dc_search_widget_params);
		
		foreach ($controls AS $param_name=>$control) {
			$this->add_control($param_name, $control);
		}
	
		$this->end_controls_section();
	}
	
	protected function render() {
		
		$settings = $this->get_settings_for_display();
		
		// it is auto selection - take current directory
		if (!isset($settings['directory']) || $settings['directory'] == 0) {
			global $w2dc_instance;
			
			// probably we are on single listing page - it could be found only after frontend controllers were loaded, so we have to repeat setting
			$w2dc_instance->setCurrentDirectory();
		
			$settings['directory'] = $w2dc_instance->current_directory->id;
		}
		
		$controller = new w2dc_search_controller();
		$controller->init($settings);
		echo $controller->display();
	}
}

?>