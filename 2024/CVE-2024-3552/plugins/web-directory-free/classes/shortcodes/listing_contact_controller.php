<?php 

/**
 *  [webdirectory-listing-contact] shortcode
 *
 *
 */
class w2dc_listing_contact_controller extends w2dc_frontend_controller {
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
		
		apply_filters('w2dc_listing_contact_controller_construct', $this);
	}
	
	public function display() {
		
		if ($this->listing) {
			ob_start();
			
			$listing = $this->listing;
			
			if (!get_option('w2dc_hide_anonymous_contact_form') || is_user_logged_in()) {
				if (defined('WPCF7_VERSION') && w2dc_get_wpml_dependent_option('w2dc_listing_contact_form_7')) {
					echo do_shortcode(w2dc_get_wpml_dependent_option('w2dc_listing_contact_form_7'));
				} else {
					w2dc_renderTemplate('frontend/single_parts/contact_form.tpl.php', array('listing' => $listing));
				}
			} else {
				printf(__('You must be <a href="%s">logged in</a> to submit contact form', 'W2DC'), wp_login_url(get_permalink($listing->post->ID)));
			}
			
			return ob_get_clean();
		}
	}
}

?>