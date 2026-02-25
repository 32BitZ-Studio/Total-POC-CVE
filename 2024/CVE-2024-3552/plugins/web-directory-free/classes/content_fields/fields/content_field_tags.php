<?php 

class w2dc_content_field_tags extends w2dc_content_field {
	protected $can_be_required = false;
	protected $can_be_ordered = false;
	protected $is_categories = false;
	protected $is_slug = false;
	
	public function isNotEmpty($listing) {
		if (has_term('', W2DC_TAGS_TAX, $listing->post->ID))
			return true;
		else
			return false;
	}

	public function renderOutput($listing, $group = null, $css_classes = '') {
		if (!($template = w2dc_isTemplate('content_fields/fields/tags_output_'.$this->id.'.tpl.php'))) {
			$template = 'content_fields/fields/tags_output.tpl.php';
		}
		
		$template = apply_filters('w2dc_content_field_output_template', $template, $this, $listing, $group);
			
		w2dc_renderTemplate($template, array('content_field' => $this, 'listing' => $listing, 'group' => $group, 'css_classes' => $css_classes));
	}
	
	public function renderOutputForMap($location, $listing) {
		return w2dc_renderTemplate('content_fields/fields/tags_output_map.tpl.php', array('content_field' => $this, 'listing' => $listing), true);
	}
}
?>