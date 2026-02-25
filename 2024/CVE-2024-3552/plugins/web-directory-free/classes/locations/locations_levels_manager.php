<?php 

class w2dc_locations_levels_manager {
	
	public function __construct() {
		add_action('admin_menu', array($this, 'menu'));
	}

	public function menu() {
		if (defined('W2DC_DEMO') && W2DC_DEMO) {
			$capability = 'publish_posts';
		} else {
			$capability = 'manage_options';
		}

		add_submenu_page('w2dc_settings',
				__('Locations levels', 'W2DC'),
				__('Locations levels', 'W2DC'),
				$capability,
				'w2dc_locations_levels',
				array($this, 'w2dc_locations_levels')
		);
	}
	
	public function w2dc_locations_levels() {
		if (isset($_GET['action']) && $_GET['action'] == 'add') {
			$this->addOrEditLocationsLevel();
		} elseif (isset($_GET['action']) && $_GET['action'] == 'edit' && isset($_GET['level_id'])) {
			$this->addOrEditLocationsLevel($_GET['level_id']);
		} elseif (isset($_GET['action']) && $_GET['action'] == 'delete' && isset($_GET['level_id'])) {
			$this->deleteLocationsLevel($_GET['level_id']);
		} else {
			$this->showLocationsLevelsTable();
		}
	}
	
	public function showLocationsLevelsTable() {
		global $w2dc_instance;
		
		$locations_levels = $w2dc_instance->locations_levels;
	
		$locations_levels_table = new w2dc_manage_locations_levels_table();
		$locations_levels_table->prepareItems($locations_levels);
	
		w2dc_renderTemplate('locations/locations_levels_table.tpl.php', array('locations_levels_table' => $locations_levels_table));
	}
	
	public function addOrEditLocationsLevel($level_id = null) {
		global $w2dc_instance;
	
		$locations_levels = $w2dc_instance->locations_levels;
	
		if (!$locations_level = $locations_levels->getLevelById($level_id))
			$locations_level = new w2dc_locations_level();
	
		if (w2dc_getValue($_POST, 'submit') && wp_verify_nonce($_POST['w2dc_locations_levels_nonce'], W2DC_PATH)) {
			$validation = new w2dc_form_validation();
			$validation->set_rules('name', __('Level name', 'W2DC'), 'required');
			$validation->set_rules('in_address_line', __('In address line', 'W2DC'), 'is_checked');
			$validation->set_rules('allow_add_term', __('Allow add term', 'W2DC'), 'is_checked');
	
			if ($validation->run()) {
				if ($locations_level->id) {
					if ($locations_levels->saveLevelFromArray($level_id, $validation->result_array())) {
						w2dc_addMessage(__('Level was updated successfully!', 'W2DC'));
					}
				} else {
					if ($locations_levels->createLevelFromArray($validation->result_array())) {
						w2dc_addMessage(__('Level was created succcessfully!', 'W2DC'));
					}
				}
				$this->showLocationsLevelsTable();
				//wp_redirect(admin_url('admin.php?page=w2dc_locations_levels'));
				//die();
			} else {
				$locations_level->buildLevelFromArray($validation->result_array());
				w2dc_addMessage($validation->error_array(), 'error');
	
				w2dc_renderTemplate('locations/add_edit_locations_level.tpl.php', array('locations_level' => $locations_level, 'locations_level_id' => $level_id));
			}
		} else {
			w2dc_renderTemplate('locations/add_edit_locations_level.tpl.php', array('locations_level' => $locations_level, 'locations_level_id' => $level_id));
		}
	}
	
	public function deleteLocationsLevel($level_id) {
		global $w2dc_instance;
	
		$locations_levels = $w2dc_instance->locations_levels;
		if ($locations_level = $locations_levels->getLevelById($level_id)) {
			if (w2dc_getValue($_POST, 'submit')) {
				if ($locations_levels->deleteLevel($level_id))
					w2dc_addMessage(__('Level was deleted successfully!', 'W2DC'));
	
				$this->showLocationsLevelsTable();
				//wp_redirect(admin_url('admin.php?page=w2dc_locations_levels'));
				//die();
			} else
				w2dc_renderTemplate('delete_question.tpl.php', array('heading' => __('Delete locations level', 'W2DC'), 'question' => sprintf(__('Are you sure you want delete "%s" locations level?', 'W2DC'), $locations_level->name), 'item_name' => $locations_level->name));
		} else
			$this->showLocationsLevelsTable();
	}
}

?>