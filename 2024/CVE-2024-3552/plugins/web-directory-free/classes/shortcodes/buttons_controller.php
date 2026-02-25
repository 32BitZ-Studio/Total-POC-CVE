<?php 

/**
 *  [webdirectory-buttons] shortcode
 *
 *
 */
class w2dc_buttons_controller extends w2dc_frontend_controller {
	public $frontpanel_buttons;

	public function init($args = array()) {
		parent::init($args);
		
		global $w2dc_instance;

		$shortcode_atts = array_merge(array(
				'hide_button_text' => false,
				'buttons' => 'submit,claim,favourites,edit,print,bookmark,pdf', // also 'logout' possible
		), $args);

		$this->args = $shortcode_atts;
		
		$this->frontpanel_buttons = new w2dc_frontpanel_buttons($this->args);

		apply_filters('w2dc_buttons_controller_construct', $this);
	}

	public function display() {
		$output =  $this->frontpanel_buttons->display(true);
		wp_reset_postdata();

		return $output;
	}
}

?>