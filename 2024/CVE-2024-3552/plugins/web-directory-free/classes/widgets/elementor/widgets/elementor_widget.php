<?php

abstract class w2dc_elementor_widget extends \Elementor\Widget_Base {
	
	public function __construct($data = array(), $args = null) {
		parent::__construct($data, $args);
		
		global $w2dc_instance;
		
		$w2dc_instance->enqueue_scripts_styles(true);
		$w2dc_instance->enqueue_scripts_styles_custom(true);
		$w2dc_instance->enqueue_dynamic_css(true);
	}
	
	protected function content_template() {
		echo '<div class="w2dc-elementor-widget-content-template">' . $this->get_title() . '</div>';
	}
	
	public function get_settings_for_display($setting_key = null) {
		
		$settings = parent::get_settings_for_display($setting_key);
		
		foreach ($settings AS $key=>$setting) {
			if (is_null($setting)) {
				unset($settings[$key]);
			}
		}
		
		return $settings;
	}
}