<?php

class w2dc_content_fields_group_elementor_widget extends w2dc_elementor_widget {

	public function get_name() {
		return 'content_fields_group';
	}

	public function get_title() {
		return __('Content fields Group', 'W2DC');
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
						'label' => esc_html__('Content fields Group', 'W2DC'),
						'tab' => \Elementor\Controls_Manager::TAB_CONTENT,
				)
		);
		
		global $w2dc_content_fields_group_widget_params;
		
		$controls = w2dc_elementor_convert_params($w2dc_content_fields_group_widget_params);
		
		foreach ($controls AS $param_name=>$control) {
			$this->add_control($param_name, $control);
		}
	
		$this->end_controls_section();
	}
	
	protected function render() {
		
		$settings = $this->get_settings_for_display();
		
		$controller = new w2dc_content_fields_group_controller();
		$controller->init($settings);
		echo $controller->display();
	}
}

?>