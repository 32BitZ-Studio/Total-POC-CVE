<?php 

/**
 *  [webdirectory-listing-header] shortcode
 *
 *
 */
class w2dc_listing_header_controller extends w2dc_frontend_controller {
	public $listing;

	public function init($args = array()) {
		global $w2dc_instance;
		
		parent::init($args);
		
		$shortcode_atts = array_merge(array(
				'listing' => '',
		), $args);

		$this->args = $shortcode_atts;
		
		if (empty($this->args['listing'])) {
			if ($shortcode_controller = w2dc_getShortcodeController()) {
				if ($shortcode_controller->is_single) {
					if ($shortcode_controller->is_listing) {
						$this->listing = $shortcode_controller->listing;
					}
				}
			}
		} else {
			$this->listing = w2dc_getListing($this->args['listing']);
		}
		
		apply_filters('w2dc_listing_header_controller_construct', $this);
	}
	
	public function display() {
		
		if ($this->listing) {
			
			$listing = $this->listing;
			
			return w2dc_renderTemplate("frontend/single_parts/header.tpl.php", array('listing' => $listing, 'title' => $listing->title()), true);
		}
	}
}

?>