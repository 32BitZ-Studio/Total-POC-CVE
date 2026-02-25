<?php 

/**
 *  [webdirectory-breadcrumbs] shortcode
 *
 *
 */
class w2dc_breadcrumbs_controller extends w2dc_frontend_controller {

	public function init($args = array()) {
		parent::init($args);

		$shortcode_atts = array_merge(array(
				
		), $args);

		$this->args = $shortcode_atts;

		apply_filters('w2dc_breadcrumbs_controller_construct', $this);
	}

	public function display() {
		global $w2dc_instance;

		if ($shortcode_controller = w2dc_getShortcodeController()) {
			ob_start();

			$shortcode_controller->printBreadCrumbs();
				
			$output = ob_get_clean();
				
			return $output;
		}
	}
}

?>