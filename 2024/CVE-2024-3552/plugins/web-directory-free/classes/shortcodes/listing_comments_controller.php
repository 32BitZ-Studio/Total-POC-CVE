<?php 

/**
 *  [webdirectory-listing-comments] shortcode
 *
 *
 */
class w2dc_listing_comments_controller extends w2dc_frontend_controller {
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
		
		apply_filters('w2dc_listing_comments_controller_construct', $this);
	}
	
	public function display() {
		
		if ($this->listing) {
			ob_start();
			
			$listing = $this->listing;
			
			if (get_option('w2dc_listings_comments_mode') == 'enabled' || (get_option('w2dc_listings_comments_mode') == 'wp_settings' && $listing->post->comment_status == 'open')) {
				echo '<div id="comments-tab">';
				w2dc_comments_system($listing);
				echo '</div>';
			}
			
			return ob_get_clean();
		}
	}
}

?>