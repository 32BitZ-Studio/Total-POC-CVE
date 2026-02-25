<?php 

class w2dc_levels {
	public $levels_array = array();

	public function __construct() {
		$this->getLevelsFromDB();
	}
	
	public function saveOrder($order_input) {
		global $wpdb;

		if ($order_ids = explode(',', trim($order_input))) {
			$i = 1;
			foreach ($order_ids AS $id) {
				$wpdb->update($wpdb->w2dc_levels, array('order_num' => $i), array('id' => $id));
				$i++;
			}
		}
		$this->getLevelsFromDB();
		return true;
	}
	
	public function getLevelsFromDB() {
		global $wpdb;
		$this->levels_array = array();

		$array = $wpdb->get_results("SELECT * FROM {$wpdb->w2dc_levels} ORDER BY order_num", ARRAY_A);
		foreach ($array AS $row) {
			$level = new w2dc_level;
			$level->buildLevelFromArray($row);
			$this->levels_array[$row['id']] = $level;
		}
	}
	
	public function getLevelById($level_id) {
		if (isset($this->levels_array[$level_id]))
			return $this->levels_array[$level_id];
	}
	
	public function getDefaultLevel() {
		$array_keys = array_keys($this->levels_array);
		$first_id = array_shift($array_keys);
		return $this->getLevelById($first_id);
	}

	public function createLevelFromArray($array) {
		global $wpdb, $w2dc_instance;
		
		$insert_update_args = array(
				'name' => w2dc_getValue($array, 'name'),
				'description' => w2dc_getValue($array, 'description'),
				'who_can_view' => serialize(w2dc_getValue($array, 'who_can_view', array())),
				'who_can_submit' => serialize(w2dc_getValue($array, 'who_can_submit', array())),
				'active_interval' => w2dc_getValue($array, 'active_interval', 1),
				'active_period' => w2dc_getValue($array, 'active_period', 'day'),
				'eternal_active_period' => w2dc_getValue($array, 'eternal_active_period', 0),
				'change_level_id' => w2dc_getValue($array, 'change_level_id', 1),
				'listings_in_package' => w2dc_getValue($array, 'listings_in_package', 1),
				'raiseup_enabled' => w2dc_getValue($array, 'raiseup_enabled'),
				'sticky' => w2dc_getValue($array, 'sticky'),
				'listings_own_page' => w2dc_getValue($array, 'listings_own_page'),
				'nofollow' => w2dc_getValue($array, 'nofollow'),
				'featured' => w2dc_getValue($array, 'featured'),
				'categories_number' => w2dc_getValue($array, 'categories_number', 0),
				'tags_number' => w2dc_getValue($array, 'tags_number', 0),
				'locations_number' => w2dc_getValue($array, 'locations_number', 1),
				'unlimited_categories' => w2dc_getValue($array, 'unlimited_categories'),
				'unlimited_tags' => w2dc_getValue($array, 'unlimited_tags'),
				'map' => w2dc_getValue($array, 'map'),
				'logo_enabled' => w2dc_getValue($array, 'logo_enabled'),
				'images_number' => w2dc_getValue($array, 'images_number'),
				'videos_number' => w2dc_getValue($array, 'videos_number'),
				'categories' => serialize(w2dc_getValue($array, 'categories', array())),
				'content_fields' => serialize(w2dc_getValue($array, 'content_fields', array())),
				'locations_number' => w2dc_getValue($array, 'locations_number', 1),
				'map_markers' => w2dc_getValue($array, 'map_markers', 1),
		);
		$insert_update_args = apply_filters('w2dc_level_create_edit_args', $insert_update_args, $array);

		if ($wpdb->insert($wpdb->w2dc_levels, $insert_update_args)) {
			$new_level_id = $wpdb->insert_id;
			
			do_action('w2dc_update_level', $new_level_id, $array);
			
			$this->getLevelsFromDB();
			$levels = $w2dc_instance->levels;
			$results = array();
			foreach ($levels->levels_array AS $level) {
				$results[$level->id]['disabled'] = false;
				$results[$level->id]['raiseup'] = false;
			}
			$level = $this->getLevelById($new_level_id);
			$level->saveUpgradeMeta($results);
			return true;
		}
	}
	
	public function saveLevelFromArray($level_id, $array) {
		global $wpdb;

		$insert_update_args = array(
				'name' => w2dc_getValue($array, 'name'),
				'description' => w2dc_getValue($array, 'description'),
				'who_can_view' => serialize(w2dc_getValue($array, 'who_can_view', array())),
				'who_can_submit' => serialize(w2dc_getValue($array, 'who_can_submit', array())),
				'active_interval' => w2dc_getValue($array, 'active_interval'),
				'active_period' => w2dc_getValue($array, 'active_period'),
				'eternal_active_period' => w2dc_getValue($array, 'eternal_active_period'),
				'change_level_id' => w2dc_getValue($array, 'change_level_id'),
				'listings_in_package' => w2dc_getValue($array, 'listings_in_package'),
				'sticky' => w2dc_getValue($array, 'sticky'),
				'listings_own_page' => w2dc_getValue($array, 'listings_own_page'),
				'nofollow' => w2dc_getValue($array, 'nofollow'),
				'raiseup_enabled' => w2dc_getValue($array, 'raiseup_enabled'),
				'featured' => w2dc_getValue($array, 'featured'),
				'categories_number' => w2dc_getValue($array, 'categories_number'),
				'tags_number' => w2dc_getValue($array, 'tags_number', 0),
				'locations_number' => w2dc_getValue($array, 'locations_number', 1),
				'unlimited_categories' => w2dc_getValue($array, 'unlimited_categories'),
				'unlimited_tags' => w2dc_getValue($array, 'unlimited_tags'),
				'map' => w2dc_getValue($array, 'map'),
				'logo_enabled' => w2dc_getValue($array, 'logo_enabled'),
				'images_number' => w2dc_getValue($array, 'images_number'),
				'videos_number' => w2dc_getValue($array, 'videos_number'),
				'categories' => serialize(w2dc_getValue($array, 'categories', array())),
				'locations' => serialize(w2dc_getValue($array, 'locations', array())),
				'content_fields' => serialize(w2dc_getValue($array, 'content_fields', array())),
				'locations_number' => w2dc_getValue($array, 'locations_number', 1),
				'map_markers' => w2dc_getValue($array, 'map_markers', 1),
		);
		$insert_update_args = apply_filters('w2dc_level_create_edit_args', $insert_update_args, $array);
	
		if ($wpdb->update($wpdb->w2dc_levels, $insert_update_args, array('id' => $level_id), null, array('%d')) !== false) {
			do_action('w2dc_update_level', $level_id, $array);
			
			$old_level = $this->getLevelById($level_id);
			$this->getLevelsFromDB();
			$new_level = $this->getLevelById($level_id);
			
			// update listings from eternal active period to numeric
			if ($old_level->eternal_active_period && !$new_level->eternal_active_period) {
				$expiration_date = w2dc_calcExpirationDate(current_time('timestamp'), $new_level);
				$postids = $this->getPostIdsByLevelId($level_id);
				foreach ($postids AS $post_id) {
					delete_post_meta($post_id, '_expiration_date');
					update_post_meta($post_id, '_expiration_date', $expiration_date);
				}
			} elseif (!$old_level->eternal_active_period && $new_level->eternal_active_period) {
				$postids = $this->getPostIdsByLevelId($level_id);
				foreach ($postids AS $post_id)
					delete_post_meta($post_id, '_expiration_date');
			}
			
			return true;
		}
	}
	
	public function deleteLevel($level_id) {
		global $wpdb;
		
		$postids = $this->getPostIdsByLevelId($level_id);
		foreach ($postids AS $post_id)
			wp_delete_post($post_id, true);
	
		$wpdb->delete($wpdb->w2dc_levels, array('id' => $level_id));

		// Renew levels' upgrade meta
		/* $this->getLevelsFromDB();
		$results = array();
		foreach ($this->levels_array AS $level1) {
			foreach ($this->levels_array AS $level2) {
				$results[$level1->id][$level2->id]['disabled'] = $level1->upgrade_meta[$level2->id]['disabled'];
				$results[$level1->id][$level2->id]['raiseup'] = $level1->upgrade_meta[$level2->id]['raiseup'];
			}
			$level1->saveUpgradeMeta($results[$level1->id]);
		} */

		$this->getLevelsFromDB();
		return true;
	}
	
	public function getPostIdsByLevelId($level_id) {
		global $wpdb;

		return $postids = $wpdb->get_col($wpdb->prepare("SELECT post_id FROM {$wpdb->w2dc_levels_relationships} WHERE level_id=%d", $level_id));
	}
}

class w2dc_level {
	public $id;
	public $order_num;
	public $name = '';
	public $description = '';
	public $who_can_view = array();
	public $who_can_submit = array();
	public $active_interval;
	public $active_period;
	public $eternal_active_period = 1;
	public $change_level_id = 0;
	public $listings_in_package = 1;
	public $featured = 0;
	public $listings_own_page = 1;
	public $nofollow = 0;
	public $raiseup_enabled = 0;
	public $sticky = 0;
	public $categories_number = 0;
	public $unlimited_categories = 1;
	public $tags_number = 0;
	public $unlimited_tags = 1;
	public $locations_number = 1;
	public $map = 1;
	public $map_markers = 1;
	public $logo_enabled;
	public $images_number = 1;
	public $videos_number = 1;
	public $categories = array();
	public $locations = array();
	public $content_fields = array();
	public $upgrade_meta = array();
	public $price;
	public $raiseup_price;
	public $ratings_enabled;

	public function buildLevelFromArray($array) {
		$this->id = w2dc_getValue($array, 'id');
		$this->order_num = w2dc_getValue($array, 'order_num');
		$this->name = w2dc_getValue($array, 'name');
		$this->description = w2dc_getValue($array, 'description');
		$this->who_can_view = w2dc_getValue($array, 'who_can_view');
		$this->who_can_submit = w2dc_getValue($array, 'who_can_submit');
		$this->active_interval = w2dc_getValue($array, 'active_interval');
		$this->active_period = w2dc_getValue($array, 'active_period');
		$this->eternal_active_period = w2dc_getValue($array, 'eternal_active_period');
		$this->change_level_id = w2dc_getValue($array, 'change_level_id');
		$this->listings_in_package = w2dc_getValue($array, 'listings_in_package');
		$this->featured = w2dc_getValue($array, 'featured');
		$this->sticky = w2dc_getValue($array, 'sticky');
		$this->listings_own_page = w2dc_getValue($array, 'listings_own_page');
		$this->nofollow = w2dc_getValue($array, 'nofollow');
		$this->raiseup_enabled = w2dc_getValue($array, 'raiseup_enabled');
		$this->categories_number = w2dc_getValue($array, 'categories_number');
		$this->unlimited_categories = w2dc_getValue($array, 'unlimited_categories');
		$this->tags_number = w2dc_getValue($array, 'tags_number');
		$this->unlimited_tags = w2dc_getValue($array, 'unlimited_tags');
		$this->locations_number = w2dc_getValue($array, 'locations_number');
		$this->map = w2dc_getValue($array, 'map');
		$this->map_markers = w2dc_getValue($array, 'map_markers');
		$this->logo_enabled = w2dc_getValue($array, 'logo_enabled');
		$this->images_number = w2dc_getValue($array, 'images_number');
		$this->videos_number = w2dc_getValue($array, 'videos_number');
		$this->categories = w2dc_getValue($array, 'categories');
		$this->locations = w2dc_getValue($array, 'locations');
		$this->content_fields = w2dc_getValue($array, 'content_fields');
		$this->upgrade_meta = (w2dc_getValue($array, 'upgrade_meta')) ? unserialize(w2dc_getValue($array, 'upgrade_meta')) : array();
		
		$this->convertUserRoles();
		$this->convertCategories();
		$this->convertLocations();
		$this->convertContentFields();
		
		apply_filters('w2dc_levels_loading', $this, $array);
	}
	
	public function convertUserRoles() {
		if ($this->who_can_view) {
			$unserialized_who_can_view = maybe_unserialize($this->who_can_view);
			if (count($unserialized_who_can_view) > 1 || $unserialized_who_can_view != array('')) {
				$this->who_can_view = $unserialized_who_can_view;
			} else {
				$this->who_can_view = array();
			}
		} else {
			$this->who_can_view = array();
		}
		
		if ($this->who_can_submit) {
			$unserialized_who_can_submit = maybe_unserialize($this->who_can_submit);
			if (count($unserialized_who_can_submit) > 1 || $unserialized_who_can_submit != array('')) {
				$this->who_can_submit = $unserialized_who_can_submit;
			} else {
				$this->who_can_submit = array();
			}
		} else {
			$this->who_can_submit = array();
		}
	}
	
	public function convertCategories() {
		if ($this->categories) {
			$unserialized_categories = maybe_unserialize($this->categories);
			if (count($unserialized_categories) > 1 || $unserialized_categories != array('')) {
				$this->categories = $unserialized_categories;
			} else {
				$this->categories = array();
			}
		} else {
			$this->categories = array();
		}
		
		return $this->categories;
	}

	public function convertLocations() {
		if ($this->locations) {
			$unserialized_locations = maybe_unserialize($this->locations);
			if (count($unserialized_locations) > 1 || $unserialized_locations != array('')) {
				$this->locations = $unserialized_locations;
			} else {
				$this->locations = array();
			}
		} else {
			$this->locations = array();
		}
		
		return $this->locations;
	}

	public function convertContentFields() {
		if ($this->content_fields) {
			$unserialized_content_fields = maybe_unserialize($this->content_fields);
			if (count($unserialized_content_fields) > 1 || $unserialized_content_fields != array('')) {
				$this->content_fields = $unserialized_content_fields;
			} else {
				$this->content_fields = array();
			}
		} else {
			$this->content_fields = array();
		}
		
		return $this->content_fields;
	}
	
	public function getActivePeriodString() {
		if ($this->eternal_active_period) {
			return __('Never expire', 'W2DC');
		} else {
			if ($this->active_period == 'day')
				return $this->active_interval . ' ' . _n('day', 'days', $this->active_interval, 'W2DC');
			elseif ($this->active_period == 'week')
				return $this->active_interval . ' ' . _n('week', 'weeks', $this->active_interval, 'W2DC');
			elseif ($this->active_period == 'month')
				return $this->active_interval . ' ' . _n('month', 'months', $this->active_interval, 'W2DC');
			elseif ($this->active_period == 'year')
				return $this->active_interval . ' ' . _n('year', 'years', $this->active_interval, 'W2DC');
		}
	}
	
	public function saveUpgradeMeta($meta) {
		global $wpdb;
		
		$this->upgrade_meta = $meta;
		
		$this->upgrade_meta = apply_filters('w2dc_level_upgrade_meta', $this->upgrade_meta, $this);

		return $wpdb->update($wpdb->w2dc_levels, array('upgrade_meta' => serialize($this->upgrade_meta)), array('id' => $this->id));
	}
	
	public function isUpgradable() {
		global $w2dc_instance;

		if (count($w2dc_instance->levels->levels_array) > 1) {
			if (empty($this->upgrade_meta)) {
				return true;
			}
			
			foreach ($this->upgrade_meta AS $id=>$meta) {
				if (($id != $this->id) && (!isset($meta['disabled']) || !$meta['disabled'] || (current_user_can('editor') || current_user_can('manage_options'))))
					return true;
			}
		}
		return false;
	}
	
	public function addContentField($content_field) {
		global $wpdb, $w2dc_instance;
		
		if (!empty($this->content_fields) && !in_array($content_field->id, $this->content_fields)) {
			if ($this->content_fields == array(0)) {
				$this->content_fields = array();
			}
			
			$this->content_fields[] = $content_field->id;
			
			if (count($this->content_fields) == count($w2dc_instance->content_fields->content_fields_array)) {
				$this->content_fields = array();
			}
			
			return $wpdb->update($wpdb->w2dc_levels, array('content_fields' => serialize($this->content_fields)), array('id' => $this->id), null, array('%d'));
		}
	}
	
	public function removeContentField($content_field) {
		global $wpdb, $w2dc_instance;
		
		if ($this->content_fields != array(0)) {
			if (empty($this->content_fields)) {
				foreach ($w2dc_instance->content_fields->content_fields_array AS $field_id=>$field) {
					if ($content_field->id != $field_id) {
						$this->content_fields[] = $field_id;
					}
				}
			} elseif (($field_id = array_search($content_field->id, $this->content_fields)) !== false) {
				unset($this->content_fields[$field_id]);
				
				if (empty($this->content_fields)) {
					$this->content_fields = array(0);
				}
			}
			
			return $wpdb->update($wpdb->w2dc_levels, array('content_fields' => serialize($this->content_fields)), array('id' => $this->id), null, array('%d'));
		} else {
			return true;
		}
	}
}

// adapted for WPML
add_action('init', 'w2dc_levels_names_into_strings');
function w2dc_levels_names_into_strings() {
	global $w2dc_instance, $sitepress;

	if (function_exists('wpml_object_id_filter') && $sitepress) {
		foreach ($w2dc_instance->levels->levels_array AS &$level) {
			$level->name = apply_filters('wpml_translate_single_string', $level->name, 'Web 2.0 Directory', 'The name of level #' . $level->id);
			$level->description = apply_filters('wpml_translate_single_string', $level->description, 'Web 2.0 Directory', 'The description of level #' . $level->id);
		}
	}
}

add_filter('w2dc_level_create_edit_args', 'w2dc_filter_level_settings', 10, 2);
function w2dc_filter_level_settings($insert_update_args, $array) {
	global $sitepress;

	if (function_exists('wpml_object_id_filter') && $sitepress) {
		if ($sitepress->get_default_language() != ICL_LANGUAGE_CODE) {
			if (isset($_GET['action']) && $_GET['action'] == 'edit' && isset($_GET['level_id'])) {
				$level_id = $_GET['level_id'];
				if ($name_string_id = icl_st_is_registered_string('Web 2.0 Directory', 'The name of level #' . $level_id))
					icl_add_string_translation($name_string_id, ICL_LANGUAGE_CODE, $insert_update_args['name'], ICL_TM_COMPLETE);
				if ($description_string_id = icl_st_is_registered_string('Web 2.0 Directory', 'The description of level #' . $level_id))
					icl_add_string_translation($description_string_id, ICL_LANGUAGE_CODE, $insert_update_args['description'], ICL_TM_COMPLETE);
				unset($insert_update_args['name']);
				unset($insert_update_args['description']);
				
				unset($insert_update_args['categories']);
				unset($insert_update_args['locations']);
			} else { 
				$insert_update_args['categories'] = '';
				$insert_update_args['locations'] = '';
			}
		}
	}
	return $insert_update_args;
}

add_action('w2dc_update_level', 'w2dc_save_level_categories_locations', 10, 2);
function w2dc_save_level_categories_locations($level_id, $array) {
	global $sitepress;

	if (function_exists('wpml_object_id_filter') && $sitepress) {
		if ($sitepress->get_default_language() != ICL_LANGUAGE_CODE) {
			update_option('w2dc_wpml_level_categories_'.$level_id.'_'.ICL_LANGUAGE_CODE, w2dc_getValue($array, 'categories'));
			update_option('w2dc_wpml_level_locations_'.$level_id.'_'.ICL_LANGUAGE_CODE, w2dc_getValue($array, 'locations'));
		}
		
		if ($sitepress->get_default_language() == ICL_LANGUAGE_CODE) {
			do_action('wpml_register_single_string', 'Web 2.0 Directory', 'The name of level #' . $level_id, w2dc_getValue($array, 'name'));
			do_action('wpml_register_single_string', 'Web 2.0 Directory', 'The description of level #' . $level_id, w2dc_getValue($array, 'description'));
		}
	}
}
	
add_action('init', 'w2dc_load_levels_categories_locations');
function w2dc_load_levels_categories_locations() {
	global $w2dc_instance, $sitepress;

	if (function_exists('wpml_object_id_filter') && $sitepress) {
		if ($sitepress->get_default_language() != ICL_LANGUAGE_CODE) {
			foreach ($w2dc_instance->levels->levels_array AS &$level) {
				$_categories = get_option('w2dc_wpml_level_categories_'.$level->id.'_'.ICL_LANGUAGE_CODE);
				if ($_categories && (count($_categories) > 1 || $_categories != array('')))
					$level->categories = $_categories;
				else
					$level->categories = array();
				$_locations = get_option('w2dc_wpml_level_locations_'.$level->id.'_'.ICL_LANGUAGE_CODE);
				if ($_locations && (count($_locations) > 1 || $_locations != array('')))
					$level->locations = $_locations;
				else
					$level->locations = array();
			}
		}
	}
}

?>