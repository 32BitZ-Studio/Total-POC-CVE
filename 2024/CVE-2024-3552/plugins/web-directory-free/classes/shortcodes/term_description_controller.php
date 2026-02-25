<?php 

/**
 *  [webdirectory-term-description] shortcode
 *
 *
 */
class w2dc_term_description_controller extends w2dc_frontend_controller {

	public function init($args = array()) {
		parent::init($args);

		$shortcode_atts = array_merge(array(
				
		), $args);

		$this->args = $shortcode_atts;

		apply_filters('w2dc_term_description_controller_construct', $this);
	}

	public function display() {
		global $w2dc_instance;

		$term_description = null;
		if ($shortcode_controller = $w2dc_instance->getShortcodeProperty(W2DC_MAIN_SHORTCODE)) {
			if ($shortcode_controller->is_category && $shortcode_controller->category->term_id)
				$term_description = term_description($shortcode_controller->category->term_id, W2DC_CATEGORIES_TAX);
			if ($shortcode_controller->is_location && $shortcode_controller->location->term_id)
				$term_description = term_description($shortcode_controller->location->term_id, W2DC_LOCATIONS_TAX);
			if ($shortcode_controller->is_tag && $shortcode_controller->tag->term_id)
				$term_description = term_description($shortcode_controller->tag->term_id, W2DC_TAGS_TAX);

			if ($term_description) {
				
				ob_start();

				echo '<div class="w2dc-content">';
					echo '<div class="archive-meta">';
						echo $term_description;
					echo '</div>';
				echo '</div>';
				
				$output = ob_get_clean();
				
				return $output;
			}
		}
	}
}

?>