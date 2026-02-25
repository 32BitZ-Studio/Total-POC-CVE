<?php 

/**
 *  [webdirectory-content-field] shortcode
 *
 *
 */
class w2dc_content_field_controller extends w2dc_frontend_controller {
	public $listing;

	public function init($args = array()) {
		global $w2dc_instance;
		
		parent::init($args);
		
		$shortcode_atts = array_merge(array(
				'listing' => '',
				'id' => '',
				'classes' => '',
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
		
		apply_filters('w2dc_content_fields_controller_construct', $this);
	}
	
	public function display() {
		$field_id = $this->args['id'];
		
		if ($this->listing && $field_id) {
			ob_start();
			
			$content_field = $this->listing->getContentField($field_id);
			if ($content_field && $content_field->isNotEmpty($this->listing)) {
				echo '<div class="w2dc-content">';
				$this->listing->renderContentField($this->args['id'], $this->args['classes']);
				echo '</div>';
			}
			
			return ob_get_clean();
		}
	}
}

?>