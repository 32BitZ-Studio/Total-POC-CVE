<?php 

/**
 *  [webdirectory-page-title] shortcode
 *  
 *  
 */

class w2dc_page_title_controller extends w2dc_frontend_controller {
	public $page_title = '';

	public function init($args = array()) {
		
		if ($controllers = w2dc_getFrontendControllers(W2DC_MAIN_SHORTCODE)) {
			$this->page_title = $controllers[0]->page_title;
		} elseif ($controllers = w2dc_getFrontendControllers(W2DC_LISTING_SHORTCODE)) {
			$this->page_title = $controllers[0]->page_title;
		}

		apply_filters('w2dc_page_title_controller_construct', $this);
	}

	public function display() {
		
		return $this->page_title;
	}
}

?>