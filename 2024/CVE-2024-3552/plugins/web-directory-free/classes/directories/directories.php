<?php 

class w2dc_directories {
	public $directories_array = array();

	public function __construct() {
		$this->getDirectoriesFromDB();

		add_action('init', array($this, 'setAdvanceDirectoriesURLs'));
		add_action('w2dc_load_pages_directories', array($this, 'setDirectoriesURLs'));
	}

	public function getDirectoriesFromDB() {
		global $wpdb;
		$this->directories_array = array();

		$array = $wpdb->get_results("SELECT * FROM {$wpdb->w2dc_directories}", ARRAY_A);
		foreach ($array AS $row) {
			$directory = new w2dc_directory;
			$directory->buildDirectoryFromArray($row);
			$this->directories_array[$row['id']] = $directory;
		}
		
		if (!$this->directories_array || defined('W2DCF_VERSION')) {
			
			$default_directory = new w2dc_directory;
			$default_directory->buildDirectoryFromArray(array(
					'id'		=> 1,
					'name' 		=> __('Listings', 'W2DC'),
					'single' 	=> __('listing', 'W2DC'),
					'plural' 	=> __('listings', 'W2DC')
			));
					
			$this->directories_array[1] = $default_directory;
		}
	}
	
	public function setAdvanceDirectoriesURLs() {
		foreach ($this->directories_array AS &$directory) {
			$directory->setAdvanceURL();
		}
	}

	public function setDirectoriesURLs() {
		foreach ($this->directories_array AS &$directory) {
			$directory->setDirectoryURL();
		}
	}
	
	public function isMultiDirectory() {
		return (count($this->directories_array) > 1) ? true : false;
	}

	public function getDirectoryById($directory_id) {
		if (isset($this->directories_array[$directory_id]))
			return $this->directories_array[$directory_id];
	}
	
	public function getDefaultDirectory() {
		$array_keys = array_keys($this->directories_array);
		$first_id = array_shift($array_keys);
		return $this->getDirectoryById($first_id);
	}

	public function createDirectoryFromArray($array) {
		global $wpdb, $w2dc_instance;
		
		$insert_update_args = array(
				'name' => w2dc_getValue($array, 'name'),
				'single' => w2dc_getValue($array, 'single'),
				'plural' => w2dc_getValue($array, 'plural'),
				'listing_slug' => w2dc_getValue($array, 'listing_slug'),
				'category_slug' => w2dc_getValue($array, 'category_slug'),
				'location_slug' => w2dc_getValue($array, 'location_slug'),
				'tag_slug' => w2dc_getValue($array, 'tag_slug'),
				'categories' => serialize(w2dc_getValue($array, 'categories', array())),
				'locations' => serialize(w2dc_getValue($array, 'locations', array())),
				'levels' => serialize(w2dc_getValue($array, 'levels', array())),
		);
		$insert_update_args = apply_filters('w2dc_directory_create_edit_args', $insert_update_args, $array);

		if ($wpdb->insert($wpdb->w2dc_directories, $insert_update_args)) {
			$new_directory_id = $wpdb->insert_id;
			
			do_action('w2dc_update_directory', $new_directory_id, $array);
			
			$this->getDirectoriesFromDB();
			return true;
		}
	}
	
	public function saveDirectoryFromArray($directory_id, $array) {
		global $wpdb;

		$insert_update_args = array(
				'name' => w2dc_getValue($array, 'name'),
				'single' => w2dc_getValue($array, 'single'),
				'plural' => w2dc_getValue($array, 'plural'),
				'listing_slug' => w2dc_getValue($array, 'listing_slug'),
				'category_slug' => w2dc_getValue($array, 'category_slug'),
				'location_slug' => w2dc_getValue($array, 'location_slug'),
				'tag_slug' => w2dc_getValue($array, 'tag_slug'),
				'categories' => serialize(w2dc_getValue($array, 'categories', array())),
				'locations' => serialize(w2dc_getValue($array, 'locations', array())),
				'levels' => serialize(w2dc_getValue($array, 'levels', array())),
		);
		$insert_update_args = apply_filters('w2dc_directory_create_edit_args', $insert_update_args, $array);
	
		if ($wpdb->update($wpdb->w2dc_directories, $insert_update_args, array('id' => $directory_id), null, array('%d')) !== false) {
			do_action('w2dc_update_directory', $directory_id, $array);
			
			$this->getDirectoriesFromDB();
			return true;
		}
	}
	
	public function deleteDirectory($directory_id, $new_directory_id) {
		global $w2dc_instance, $wpdb;

		// We can not delete default directory
		if ($directory_id != $this->getDefaultDirectory()->id) {
			$wpdb->delete($wpdb->w2dc_directories, array('id' => $directory_id));
			
			if (!$w2dc_instance->directories->getDirectoryById($new_directory_id)) {
				$new_directory_id = $w2dc_instance->directories->getDefaultDirectory()->id;
			}
			$wpdb->update($wpdb->postmeta, array('meta_value' => $new_directory_id), array('meta_key' => '_directory_id', 'meta_value' => $directory_id));
	
			$this->getDirectoriesFromDB();
			return true;
		}
	}
	
	public function getDirectoryOfPage($page_id = 0) {
		$current_directory = null;

		$pattern = get_shortcode_regex(array(W2DC_MAIN_SHORTCODE));
		if ($page_id && ($page = get_post($page_id))) {
			if (preg_match_all('/'.$pattern.'/s', $page->post_content, $matches) && array_key_exists(2, $matches)) {
				foreach ($matches[2] AS $key=>$shortcode) {
					if ($shortcode == W2DC_MAIN_SHORTCODE) {
						if (($attrs = shortcode_parse_atts($matches[3][$key]))) {
							if (isset($attrs['id']) && is_numeric($attrs['id']) && ($directory = $this->getDirectoryById($attrs['id']))) {
								$current_directory = $directory;
								break;
							} elseif (!isset($attrs['id'])) {
								$current_directory = $this->getDefaultDirectory();
								break;
							}
						} else {
							$current_directory = $this->getDefaultDirectory();
							break;
						}
					}
				}
			}
		} else {
			$current_directory = $this->getDefaultDirectory();
		}
		
		$current_directory = apply_filters("w2dc_get_directory_of_page", $current_directory, $page_id);
		
		return $current_directory;
	}
}

class w2dc_directory {
	public $id;
	public $url;
	public $name;
	public $single;
	public $plural;
	public $listing_slug;
	public $category_slug;
	public $location_slug;
	public $tag_slug;
	public $categories = array();
	public $locations = array();
	public $levels = array();
	
	public function __construct() {
		$this->listing_slug 	= 'business-listing';
		$this->category_slug 	= 'business-category';
		$this->location_slug 	= 'business-place';
		$this->tag_slug 		= 'business-tag';
	}

	public function buildDirectoryFromArray($array) {
		$this->id = w2dc_getValue($array, 'id');
		$this->name = w2dc_getValue($array, 'name');
		$this->single = w2dc_getValue($array, 'single');
		$this->plural = w2dc_getValue($array, 'plural');
		$this->listing_slug = w2dc_getValue($array, 'listing_slug', $this->listing_slug);
		$this->category_slug = w2dc_getValue($array, 'category_slug', $this->category_slug);
		$this->location_slug = w2dc_getValue($array, 'location_slug', $this->location_slug);
		$this->tag_slug = w2dc_getValue($array, 'tag_slug', $this->tag_slug);
		$this->categories = w2dc_getValue($array, 'categories');
		$this->locations = w2dc_getValue($array, 'locations');
		$this->levels = w2dc_getValue($array, 'levels');
		
		$this->convertCategories();
		$this->convertLocations();
		$this->convertLevels();
		
		apply_filters('w2dc_directories_loading', $this, $array);
	}
	
	public function convertCategories() {
		if ($this->categories) {
			$unserialized_categories = maybe_unserialize($this->categories);
			if (count($unserialized_categories) > 1 || $unserialized_categories != array(''))
				$this->categories = $unserialized_categories;
			else
				$this->categories = array();
		} else
			$this->categories = array();
		return $this->categories;
	}

	public function convertLocations() {
		if ($this->locations) {
			$unserialized_locations = maybe_unserialize($this->locations);
			if (count($unserialized_locations) > 1 || $unserialized_locations != array(''))
				$this->locations = $unserialized_locations;
			else
				$this->locations = array();
		} else
			$this->locations = array();
		return $this->locations;
	}

	public function convertLevels() {
		if ($this->levels) {
			$unserialized_levels = maybe_unserialize($this->levels);
			if (count($unserialized_levels) > 1 || $unserialized_levels != array(''))
				$this->levels = $unserialized_levels;
			else
				$this->levels = array();
		} else {
			$this->levels = array();
		}
		
		return $this->levels;
	}
	
	/**
	 * this is required to have an URL in advance in 'init' hook
	 * 
	 * @return string
	 */
	public function setAdvanceURL() {
		global $w2dc_instance;
		
		$pattern = get_shortcode_regex(array(W2DC_MAIN_SHORTCODE));

		foreach ($w2dc_instance->index_pages_all AS $index_page) {
			$page_obj = get_post($index_page['id']);
			if (preg_match_all('/'.$pattern.'/s', $page_obj->post_content, $matches) && array_key_exists(2, $matches)) {
				foreach ($matches[2] AS $key=>$shortcode) {
					if ($shortcode == W2DC_MAIN_SHORTCODE) {
						if ($attrs = shortcode_parse_atts($matches[3][$key])) {
							if (isset($attrs['id']) && is_numeric($attrs['id']) && $this->id == $attrs['id']) {
								$this->url = get_permalink($page_obj);
							} elseif (!isset($attrs['id']) && $this->id == $w2dc_instance->directories->getDefaultDirectory()->id) {
								$this->url = get_permalink($page_obj);
							}
						} elseif ($this->id == $w2dc_instance->directories->getDefaultDirectory()->id) {
							$this->url = get_permalink($page_obj);
						}
					}
				}
			}
		}

		return $this->url;
	}

	/**
	 * this will give complete URL of directory after current Directory was loaded,
	 * will run in 'wp' hook
	 * 
	 * @return string
	 */
	public function setDirectoryURL() {
		global $w2dc_instance;
		
		// it is possible to have some pages with same [webdirectory] shortcodes,
		// URL of the current page has priority, so we will try to catch current page to build correct links
		$possible_url = '';
		$current_page_url = '';
	
		$pattern = get_shortcode_regex(array(W2DC_MAIN_SHORTCODE));
	
		foreach ($w2dc_instance->index_pages_all AS $index_page) {
			$page_obj = get_post($index_page['id']);
			if (preg_match_all('/'.$pattern.'/s', $page_obj->post_content, $matches) && array_key_exists(2, $matches)) {
				foreach ($matches[2] AS $key=>$shortcode) {
					if ($shortcode == W2DC_MAIN_SHORTCODE) {
						if (
							$w2dc_instance->current_directory &&
							$this->id == $w2dc_instance->current_directory->id &&
							$page_obj->ID == $w2dc_instance->index_page_id &&
							($directory_of_page = $w2dc_instance->directories->getDirectoryOfPage($page_obj->ID)) && 
							$this->id == $directory_of_page->id
						) {
							$current_page_url = get_permalink($page_obj);
							break;
							break;
						}
						if ($attrs = shortcode_parse_atts($matches[3][$key])) {
							if (isset($attrs['id']) && is_numeric($attrs['id']) && $this->id == $attrs['id']) {
								$possible_url = get_permalink($page_obj);
							} elseif (!isset($attrs['id']) && $this->id == $w2dc_instance->directories->getDefaultDirectory()->id) {
								$possible_url = get_permalink($page_obj);
							}
						} elseif ($this->id == $w2dc_instance->directories->getDefaultDirectory()->id) {
							$possible_url = get_permalink($page_obj);
						}
					}
				}
			}
		}

		if ($current_page_url) {
			$this->url = $current_page_url;
		} elseif ($possible_url) {
			$this->url = $possible_url;
		}

		return $this->url;
	}
	
	public function isAllLevels() {
		return empty($this->levels);
	}
}

// adapted for WPML
add_action('init', 'w2dc_directories_names_into_strings');
function w2dc_directories_names_into_strings() {
	global $w2dc_instance, $sitepress;

	if (function_exists('wpml_object_id_filter') && $sitepress) {
		foreach ($w2dc_instance->directories->directories_array AS &$directory) {
			$directory->single = apply_filters('wpml_translate_single_string', $directory->single, 'Web 2.0 Directory', 'Single item of directory #' . $directory->id);
			$directory->plural = apply_filters('wpml_translate_single_string', $directory->plural, 'Web 2.0 Directory', 'Plural item of directory #' . $directory->id);
		}
	}
}

add_filter('w2dc_level_create_edit_args', 'w2dc_filter_directory_categories_locations', 10, 2);
function w2dc_filter_directory_categories_locations($insert_update_args, $array) {
	global $sitepress;

	if (function_exists('wpml_object_id_filter') && $sitepress) {
		if ($sitepress->get_default_language() != ICL_LANGUAGE_CODE) {
			if (isset($_GET['action']) && $_GET['action'] == 'edit' && isset($_GET['directory_id'])) {
				$directory_id = $_GET['directory_id'];
				if ($single_string_id = icl_st_is_registered_string('Web 2.0 Directory', 'Single item of directory #' . $directory_id))
					icl_add_string_translation($single_string_id, ICL_LANGUAGE_CODE, $insert_update_args['single'], ICL_TM_COMPLETE);
				if ($plural_string_id = icl_st_is_registered_string('Web 2.0 Directory', 'Plural item of directory #' . $directory_id))
					icl_add_string_translation($plural_string_id, ICL_LANGUAGE_CODE, $insert_update_args['plural'], ICL_TM_COMPLETE);
				unset($insert_update_args['single']);
				unset($insert_update_args['plural']);
				
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

add_action('w2dc_update_directory', 'w2dc_save_directory_categories_locations', 10, 2);
function w2dc_save_directory_categories_locations($directory_id, $array) {
	global $sitepress;

	if (function_exists('wpml_object_id_filter') && $sitepress) {
		if ($sitepress->get_default_language() != ICL_LANGUAGE_CODE) {
			update_option('w2dc_wpml_directory_categories_'.$directory_id.'_'.ICL_LANGUAGE_CODE, w2dc_getValue($array, 'categories'));
			update_option('w2dc_wpml_directory_locations_'.$directory_id.'_'.ICL_LANGUAGE_CODE, w2dc_getValue($array, 'locations'));
		}
		
		if ($sitepress->get_default_language() == ICL_LANGUAGE_CODE) {
			do_action('wpml_register_single_string', 'Web 2.0 Directory', 'Single item of directory #' . $directory_id, w2dc_getValue($array, 'single'));
			do_action('wpml_register_single_string', 'Web 2.0 Directory', 'Plural item of directory #' . $directory_id, w2dc_getValue($array, 'plural'));
		}
	}
}
	
add_action('init', 'w2dc_load_directory_categories_locations');
function w2dc_load_directory_categories_locations() {
	global $w2dc_instance, $sitepress;

	if (function_exists('wpml_object_id_filter') && $sitepress) {
		if ($sitepress->get_default_language() != ICL_LANGUAGE_CODE) {
			foreach ($w2dc_instance->directories->directories_array AS &$directory) {
				$_categories = get_option('w2dc_wpml_directory_categories_'.$directory->id.'_'.ICL_LANGUAGE_CODE);
				$_locations = get_option('w2dc_wpml_directory_locations_'.$directory->id.'_'.ICL_LANGUAGE_CODE);
				if ($_categories && (count($_categories) > 1 || $_categories != array('')))
					$directory->categories = $_categories;
				else
					$directory->categories = array();
				if ($_locations && (count($_locations) > 1 || $_locations != array('')))
					$directory->locations = $_locations;
				else
					$directory->locations = array();
			}
		}
	}
}

?>