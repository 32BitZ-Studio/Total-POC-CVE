<?php 

/**
 *  [webdirectory-search] shortcode
 *
 *
 */
class w2dc_search_controller extends w2dc_frontend_controller {

	public function init($args = array()) {
		global $w2dc_instance;

		parent::init($args);

		$this->args = array_merge(array(
				'form_id' => "",
				'custom_home' => 0,
				'directory' => 0,
				'uid' => null,
		), $args);

		// $w2dc_instance->getShortcodeProperty(W2DC_MAIN_SHORTCODE) gives recursion in frontend_controller.php 
		if (!$this->args['custom_home'] && $this->args['uid']) {
			$this->hash = md5($this->args['uid']);
		} elseif ($this->args['custom_home'] && ($shortcode_controller = $w2dc_instance->getShortcodeProperty(W2DC_MAIN_SHORTCODE))) {
			$this->hash = $shortcode_controller->hash;
			
			// set form ID from the settings
			if (!$this->args['form_id'] && get_option('w2dc_search_form_id')) {
				$this->args['form_id'] = get_option('w2dc_search_form_id');
			}
		}

		$this->search_form = new w2dc_search_form($this->hash, $this->args);
		
		apply_filters('w2dc_search_controller_construct', $this);
	}

	public function display() {
		ob_start();
		$this->search_form->display();
		$output = ob_get_clean();

		return $output;
	}
}

?>