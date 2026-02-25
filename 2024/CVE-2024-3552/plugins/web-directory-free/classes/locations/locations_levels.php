<?php 

class w2dc_locations_levels {
	public $levels_array = array();

	public function __construct() {
		$this->getLevelsFromDB();
	}

	public function getLevelsFromDB() {
		global $wpdb;
		$this->levels_array = array();

		$array = $wpdb->get_results("SELECT * FROM {$wpdb->w2dc_locations_levels}", ARRAY_A);
		foreach ($array AS $row) {
			$level = new w2dc_locations_level;
			$level->buildLevelFromArray($row);
			$this->levels_array[$row['id']] = $level;
		}
	}
	
	public function getNamesArray() {
		$names = array();
		foreach ($this->levels_array AS $level) {
			$names[] = $level->name;
		}
		
		return $names;
	}

	public function getSelectionsArray() {
		$selections = array();
		foreach ($this->levels_array AS $level) {
			$selections[] = $level->name;
		}
		
		return $selections;
	}
	
	public function getAllowAddTermArray() {
		$allow_add_term = array();
		foreach ($this->levels_array AS $level) {
			$allow_add_term[] = $level->allow_add_term;
		}
		
		return $allow_add_term;
	}
	
	public function isAddTermAllowed($parent_id) {
		$allow_add_term = $this->getAllowAddTermArray();
		
		// allow to add in the root
		if ((int)$parent_id === 0 && $allow_add_term[0]) {
			return true;
		}
		
		$term = get_term($parent_id);
		
		$level = 1;
		while ($term->parent != 0) {
			$level++;
			
			$term = get_term($term->parent);
		}
		
		if (!empty($allow_add_term[$level])) {
			return true;
		}
		
		return false;
	}
	
	public function getLevelById($level_id) {
		if (isset($this->levels_array[$level_id])) {
			return $this->levels_array[$level_id];
		}
	}
	
	public function createLevelFromArray($array) {
		global $wpdb;
		
		$insert_update_args = array(
				'name' => w2dc_getValue($array, 'name'),
				'in_address_line' => w2dc_getValue($array, 'in_address_line'),
				'allow_add_term' => w2dc_getValue($array, 'allow_add_term'),
		);
		
		$insert_update_args = apply_filters('w2dc_locations_level_create_edit_args', $insert_update_args, $array);
	
		if ($wpdb->insert($wpdb->w2dc_locations_levels, $insert_update_args)) {
			$new_level_id = $wpdb->insert_id;

			do_action('w2dc_update_locations_level', $new_level_id, $insert_update_args);
			
			$this->getLevelsFromDB();
			
			return true;
		}
	}
	
	public function saveLevelFromArray($level_id, $array) {
		global $wpdb;
		
		$insert_update_args = array(
				'name' => w2dc_getValue($array, 'name'),
				'in_address_line' => w2dc_getValue($array, 'in_address_line'),
				'allow_add_term' => w2dc_getValue($array, 'allow_add_term'),
		);
		
		$insert_update_args = apply_filters('w2dc_locations_level_create_edit_args', $insert_update_args, $array);
	
		if ($wpdb->update($wpdb->w2dc_locations_levels, $insert_update_args,	array('id' => $level_id), null, array('%d')) !== false) {
			do_action('w2dc_update_locations_level', $level_id, $insert_update_args);
			
			$this->getLevelsFromDB();
				
			return true;
		}
	}
	
	public function deleteLevel($level_id) {
		global $wpdb;
	
		if ($wpdb->delete($wpdb->w2dc_locations_levels, array('id' => $level_id))) {
			$this->getLevelsFromDB();

			return true;
		}
	}
}

class w2dc_locations_level {
	public $id;
	public $name;
	public $allow_add_term = 1;
	public $in_address_line = 1;

	public function buildLevelFromArray($array) {
		$this->id = w2dc_getValue($array, 'id');
		$this->name = w2dc_getValue($array, 'name');
		$this->allow_add_term = w2dc_getValue($array, 'allow_add_term');
		$this->in_address_line =w2dc_getValue($array, 'in_address_line');
	}
}


if( ! class_exists( 'WP_List_Table' ) ) {
	require_once( ABSPATH . 'wp-admin/includes/class-wp-list-table.php' );
}
class w2dc_manage_locations_levels_table extends WP_List_Table {

	public function __construct() {
		parent::__construct(array(
				'singular' => __('locations level', 'W2DC'),
				'plural' => __('locations levels', 'W2DC'),
				'ajax' => false
		));
	}

	public function get_columns() {
		$columns = array(
				'locations_level_name' => __('Name', 'W2DC'),
				'in_address_line' => __('In address line', 'W2DC'),
				'allow_add_term' => __('Allow add location', 'W2DC'),
		);

		return $columns;
	}

	public function getItems($locations_levels) {
		$items_array = array();
		foreach ($locations_levels->levels_array as $id=>$level) {
			$items_array[$id] = array(
					'id' => $level->id,
					'locations_level_name' => $level->name,
					'in_address_line' => $level->in_address_line,
					'allow_add_term' => $level->allow_add_term,
			);
		}
		return $items_array;
	}

	public function prepareItems($locations_levels) {
		$this->_column_headers = array($this->get_columns(), array(), array());

		$this->items = $this->getItems($locations_levels);
	}

	public function column_locations_level_name($item) {
		$actions = array(
				'edit' => sprintf('<a href="?page=%s&action=%s&level_id=%d">' . __('Edit', 'W2DC') . '</a>', $_GET['page'], 'edit', $item['id']),
				'delete' => sprintf('<a href="?page=%s&action=%s&level_id=%d">' . __('Delete', 'W2DC') . '</a>', $_GET['page'], 'delete', $item['id']),
		);
		return sprintf('%1$s %2$s', sprintf('<a href="?page=%s&action=%s&level_id=%d">' . $item['locations_level_name'] . '</a>', $_GET['page'], 'edit', $item['id']), $this->row_actions($actions));
	}

	public function column_in_address_line($item) {
		if ($item['in_address_line'])
			return '<img src="' . W2DC_RESOURCES_URL . 'images/accept.png" />';
		else
			return '<img src="' . W2DC_RESOURCES_URL . 'images/delete.png" />';
	}
	
	public function column_allow_add_term($item) {
		if ($item['allow_add_term'])
			return '<img src="' . W2DC_RESOURCES_URL . 'images/accept.png" />';
		else
			return '<img src="' . W2DC_RESOURCES_URL . 'images/delete.png" />';
	}

	public function column_default($item, $column_name) {
		switch($column_name) {
			default:
				return $item[$column_name];
		}
	}

	function no_items() {
		__('No locations levels found', 'W2DC');
	}
}

add_action('init', 'w2dc_locations_levels_names_into_strings');
function w2dc_locations_levels_names_into_strings() {
	global $w2dc_instance, $sitepress;

	if (function_exists('wpml_object_id_filter') && $sitepress) {
		foreach ($w2dc_instance->locations_levels->levels_array AS &$locations_level) {
			$locations_level->name = apply_filters('wpml_translate_single_string', $locations_level->name, 'Web 2.0 Directory', 'The name of locations level #' . $locations_level->id);
		}
	}
}

add_filter('w2dc_locations_level_create_edit_args', 'w2dc_filter_locations_level_fields', 10, 2);
function w2dc_filter_locations_level_fields($insert_update_args, $array) {
	global $sitepress, $wpdb;

	if (function_exists('wpml_object_id_filter') && $sitepress) {
		if ($sitepress->get_default_language() != ICL_LANGUAGE_CODE) {
			if (isset($_GET['action']) && $_GET['action'] == 'edit' && isset($_GET['level_id'])) {
				$level_id = $_GET['level_id'];
				if ($name_string_id = icl_st_is_registered_string('Web 2.0 Directory', 'The name of locations level #' . $level_id))
					icl_add_string_translation($name_string_id, ICL_LANGUAGE_CODE, $insert_update_args['name'], ICL_TM_COMPLETE);
				unset($insert_update_args['name']);
			}
		}
	}
	return $insert_update_args;
}

add_action('w2dc_update_locations_level', 'w2dc_update_locations_level', 10, 2);
function w2dc_update_locations_level($level_id, $array) {
	global $sitepress;
	
	if (function_exists('wpml_object_id_filter') && $sitepress) {
		if ($sitepress->get_default_language() == ICL_LANGUAGE_CODE) {
			do_action('wpml_register_single_string', 'Web 2.0 Directory', 'The name of locations level #' . $level_id, w2dc_getValue($array, 'name'));
		}
	}
}

?>