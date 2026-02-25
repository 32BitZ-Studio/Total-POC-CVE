<?php 

/**
 *  [webdirectory-locations] shortcode
 *
 *
 */
class w2dc_locations_controller extends w2dc_frontend_controller {

	public function init($args = array()) {
		global $w2dc_instance;
		
		parent::init($args);

		$shortcode_atts = array_merge(array(
				'custom_home' => 0,
				'directory' => 0,
				'parent' => 0,
				'depth' => 1,
				'columns' => 2,
				'count' => 1,
				'hide_empty' => 0,
				'sublocations' => 0,
				'locations' => array(),
				'grid' => 0,
				'grid_view' => 0, // 3 types of view
				'icons' => 1,
				'menu' => 0,
				'order' => 'default', // 'default', 'name', 'count'
		), $args);
		$this->args = $shortcode_atts;

		if ($this->args['custom_home']) {
			if ($w2dc_instance->getShortcodeProperty(W2DC_MAIN_SHORTCODE, 'is_location')) {
				$location = $w2dc_instance->getShortcodeProperty(W2DC_MAIN_SHORTCODE, 'location');
				$this->args['parent'] = $location->term_id;
			}

			$this->args['depth'] = w2dc_getValue($args, 'depth', get_option('w2dc_locations_nesting_level'));
			$this->args['columns'] = w2dc_getValue($args, 'columns', get_option('w2dc_locations_columns'));
			$this->args['count'] = w2dc_getValue($args, 'count', get_option('w2dc_show_location_count'));
			$this->args['hide_empty'] = w2dc_getValue($args, 'hide_empty', get_option('w2dc_hide_empty_categories'));
			$this->args['sublocations'] = w2dc_getValue($args, 'subcats', get_option('w2dc_sublocations_items'));
			if ($w2dc_instance->current_directory->locations) {
				$this->args['locations'] = implode(',', $w2dc_instance->current_directory->locations);
			}
		}
		
		if (isset($this->args['locations']) && !is_array($this->args['locations'])) {
			if ($locations = array_filter(explode(',', $this->args['locations']), 'trim')) {
				$this->args['locations'] = $locations;
			}
		}

		apply_filters('w2dc_locations_controller_construct', $this);
	}

	public function display() {
		global $w2dc_instance;
		
		$this->args['max_subterms'] = $this->args['sublocations'];
		$this->args['exact_terms'] = $this->args['locations'];
		
		ob_start();

		if ($this->args['custom_home'] && $w2dc_instance->getShortcodeProperty(W2DC_MAIN_SHORTCODE, 'is_location') && !get_option('w2dc_show_locations_index')) {
			$this->args['depth'] = 1;
		}
		$locations_view = new w2dc_locations_view($this->args);
		$locations_view->display();

		$output = ob_get_clean();

		return $output;
	}
}

?>