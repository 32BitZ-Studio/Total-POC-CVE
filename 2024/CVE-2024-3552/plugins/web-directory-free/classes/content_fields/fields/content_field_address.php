<?php 

class w2dc_content_field_address extends w2dc_content_field {
	protected $can_be_required = true;
	protected $can_be_ordered = false;
	protected $is_categories = false;
	protected $is_slug = false;
	
	public function isNotEmpty($listing) {
		foreach ($listing->locations AS $location)
			if ($location->getWholeAddress())
				return true;

		return false;
	}

	public function renderOutput($listing, $group = null, $css_classes = '') {
		if ($listing->level->locations_number) {
			if (!($template = w2dc_isTemplate('content_fields/fields/address_output_'.$this->id.'.tpl.php'))) {
				$template = 'content_fields/fields/address_output.tpl.php';
			}
			
			$template = apply_filters('w2dc_content_field_output_template', $template, $this, $listing, $group);
			
			w2dc_renderTemplate($template, array('content_field' => $this, 'listing' => $listing, 'group' => $group, 'css_classes' => $css_classes));
		}
	}
	
	public function renderOutputForMap($location, $listing) {
		if ($listing->level->locations_number)
			return $location->getWholeAddress() . w2dc_get_distance($location);
	}
}
?>