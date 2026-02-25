<?php

class w2dc_levels_table_elementor_widget extends w2dc_elementor_widget {

	public function get_name() {
		return 'levels_table';
	}

	public function get_title() {
		return __('Levels table', 'W2DC');
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
						'label' => esc_html__('Levels table', 'W2DC'),
						'tab' => \Elementor\Controls_Manager::TAB_CONTENT,
				)
		);
		
		global $w2dc_levels_table_widget_params;
		
		$controls = w2dc_elementor_convert_params($w2dc_levels_table_widget_params);
		
		foreach ($controls AS $param_name=>$control) {
			$this->add_control($param_name, $control);
		}
	
		$this->end_controls_section();
	}
	
	protected function render() {
		
		global $w2dc_fsubmit_instance;
		
		if (!$w2dc_fsubmit_instance) {
			printf(__('Please enable <a href="%s">"Frontend submission & dashboard addon" to display this widget', 'W2DC'), admin_url('admin.php?page=w2dc_settings'));
			return ;
		}
		
		$settings = $this->get_settings_for_display();
		
		$controller = new w2dc_levels_table_controller();
		$controller->init($settings);
		echo $controller->display();
	}
}

?>