<?php

class w2dc_listings_elementor_widget extends w2dc_elementor_widget {

	public function get_name() {
		return 'listings';
	}

	public function get_title() {
		return __('Listings', 'W2DC');
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
						'label' => esc_html__('Listings', 'W2DC'),
						'tab' => \Elementor\Controls_Manager::TAB_CONTENT,
				)
		);
		
		global $w2dc_listings_widget_params;
		
		global $w2dc_instance;
		foreach ($w2dc_instance->content_fields->content_fields_array AS $filter_field) {
			if (method_exists($filter_field, 'getWidgetParams') && ($field_params = $filter_field->getWidgetParams())) {
				$w2dc_listings_widget_params = array_merge($w2dc_listings_widget_params, $field_params);
			}
		}
		
		$controls = w2dc_elementor_convert_params($w2dc_listings_widget_params);
		
		foreach ($controls AS $param_name=>$control) {
			$this->add_control($param_name, $control);
		}
	
		$this->end_controls_section();
	}
	
	protected function render() {
		
		global $w2dc_instance;
		
		$settings = $this->get_settings_for_display();
		
		$controller = new w2dc_listings_controller();
		$controller->init($settings);
			
		// add frontend controller to get compatibility by uID parameter with maps controller
		$w2dc_instance->frontend_controllers['webdirectory-listings'][] = $controller;
		
		echo $controller->display();
	}
}

?>