<?php

class w2dc_content_fields_manager {
	public $menu_page_hook;
	
	public function __construct() {
		if (w2dc_isListingEditPageInAdmin()) {
			add_action('add_meta_boxes', array($this, 'addContentFieldsMetabox'));
			add_action('post_edit_form_tag', array($this, 'addFormEnctype'));
		}
		
		add_action('admin_menu', array($this, 'menu'));

		add_action('delete_term_taxonomy', array($this, 'renew_assigned_categories'));

		// adapted for WPML
		//add_filter('wpml_config_array', array($this, 'wpml_config_array'));
	}

	public function menu() {
		if (defined('W2DC_DEMO') && W2DC_DEMO) {
			$capability = 'publish_posts';
		} else {
			$capability = 'manage_options';
		}

		$this->menu_page_hook = add_submenu_page('w2dc_settings',
			__('Content fields', 'W2DC'),
			__('Content fields', 'W2DC'),
			$capability,
			'w2dc_content_fields',
			array($this, 'w2dc_content_fields')
		);
	}
	
	public function w2dc_content_fields() {
		if (isset($_GET['action']) && $_GET['action'] == 'add') {
			$this->addOrEditContentField();
		} elseif (isset($_GET['action']) && $_GET['action'] == 'edit' && isset($_GET['field_id'])) {
			$this->addOrEditContentField($_GET['field_id']);
		} elseif (isset($_GET['action']) && $_GET['action'] == 'delete' && isset($_GET['field_id'])) {
			$this->deleteContentField($_GET['field_id']);
		} elseif (isset($_GET['action']) && $_GET['action'] == 'configure' && isset($_GET['field_id'])) {
			$this->configureContentField($_GET['field_id']);
		} elseif (isset($_GET['action']) && $_GET['action'] == 'add_group') {
			$this->addOrEditContentFieldsGroup();
		} elseif (isset($_GET['action']) && $_GET['action'] == 'edit_group' && isset($_GET['group_id'])) {
			$this->addOrEditContentFieldsGroup($_GET['group_id']);
		} elseif (isset($_GET['action']) && $_GET['action'] == 'delete_group' && isset($_GET['group_id'])) {
			$this->deleteContentFieldsGroup($_GET['group_id']);
		} elseif (!isset($_GET['action'])) {
			$this->showContentFieldsTable();
		}
	}
	
	public function showContentFieldsTable() {
		global $w2dc_instance;
		
		$content_fields = $w2dc_instance->content_fields;

		wp_enqueue_script('jquery-ui-sortable');
		
		if (isset($_POST['submit_table'])) {
			if (isset($_POST['content_fields_order']) && $_POST['content_fields_order']) {
				if ($content_fields->saveOrder())
					w2dc_addMessage(__('Content fields order were updated!', 'W2DC'), 'updated');
			}
			if ($content_fields->saveGroupsRelations())
				w2dc_addMessage(__('Content fields relations were updated!', 'W2DC'), 'updated');
		}

		$content_fields_table = new w2dc_manage_content_fields_table();
		$content_fields_table->prepareItems($content_fields);

		$content_fields_groups_table = new w2dc_manage_content_fields_groups_table();
		$content_fields_groups_table->prepareItems($content_fields);
		
		w2dc_renderTemplate('content_fields/content_fields_table.tpl.php', array('content_fields_table' => $content_fields_table, 'content_fields_groups_table' => $content_fields_groups_table, 'fields_types_names' => $content_fields->fields_types_names));
	}
	
	public function addOrEditContentField($field_id = null) {
		global $w2dc_instance;
	
		$content_fields = $w2dc_instance->content_fields;
	
		if (!$content_field = $content_fields->getContentFieldById($field_id)) {
			// this will be new field
			if (isset($_POST['type']) && $_POST['type']) {
				// load dummy content field by its type from $_POST
				$field_class_name = 'w2dc_content_field_' . $_POST['type'];
				if (class_exists($field_class_name)) {
					$content_field = new $field_class_name;
				}
			} else 
				$content_field = new w2dc_content_field();
		}

		if (w2dc_getValue($_POST, 'submit') && wp_verify_nonce($_POST['w2dc_content_fields_nonce'], W2DC_PATH)) {
			$validation = $content_field->validation();

			if ($validation->run()) {
				$vallidation_results = $validation->result_array();
				if (!$vallidation_results['icon_image'] && ($upload_icon_image_id = w2dc_getValue($_POST, 'w2dc-upload-image-input-field-icon-image', false)) !== false) {
					$vallidation_results['icon_image'] = $upload_icon_image_id;
				}
				
				if ($content_field->id) {
					if ($content_fields->saveContentFieldFromArray($field_id, $vallidation_results)) {
						w2dc_addMessage(__('Content field was updated successfully!', 'W2DC'));
					}
				} else {
					if ($content_fields->createContentFieldFromArray($vallidation_results)) {
						w2dc_addMessage(__('Content field was created succcessfully!', 'W2DC'));
					}
				}
				$this->showContentFieldsTable();
				//wp_redirect(admin_url('admin.php?page=w2dc_content_fields'));
				//die();
			} else {
				$content_field->buildContentFieldFromArray($validation->result_array());
				w2dc_addMessage($validation->error_array(), 'error');
				
				$upload_icon = new w2dc_upload_image('field-icon-image', $content_field->icon_image, array(21, 21));
	
				w2dc_renderTemplate('content_fields/add_edit_content_field.tpl.php',
						array(
								'content_fields' => $content_fields,
								'content_field' => $content_field,
								'field_id' => $field_id,
								'fields_types_names' => $content_fields->fields_types_names,
								'upload_icon' => $upload_icon,
						)
				);
			}
		} else {
			$upload_icon = new w2dc_upload_image('field-icon-image', $content_field->icon_image, array(21, 21));
			
			w2dc_renderTemplate('content_fields/add_edit_content_field.tpl.php',
					array(
							'content_fields' => $content_fields,
							'content_field' => $content_field,
							'field_id' => $field_id,
							'fields_types_names' => $content_fields->fields_types_names,
							'upload_icon' => $upload_icon,
					)
			);
		}
	}

	public function addOrEditContentFieldsGroup($group_id = null) {
		global $w2dc_instance;
	
		$content_fields = $w2dc_instance->content_fields;
	
		if (!$content_fields_group = $content_fields->getContentFieldsGroupById($group_id)) {
			// this will be new fields group
			$content_fields_group = new w2dc_content_fields_group();
		}

		if (w2dc_getValue($_POST, 'submit') && wp_verify_nonce($_POST['w2dc_content_fields_nonce'], W2DC_PATH)) {
			$validation = $content_fields_group->validation();

			if ($validation->run()) {
				if ($content_fields_group->id) {
					if ($content_fields->saveContentFieldsGroupFromArray($group_id, $validation->result_array())) {
						w2dc_addMessage(__('Content fields group was updated successfully!', 'W2DC'));
					}
				} else {
					if ($content_fields->createContentFieldsGroupFromArray($validation->result_array())) {
						w2dc_addMessage(__('Content fields group was created succcessfully!', 'W2DC'));
					}
				}
				$this->showContentFieldsTable();
				//wp_redirect(admin_url('admin.php?page=w2dc_content_fields'));
				//die();
			} else {
				$content_fields->buildContentFieldsGroupFromArray($validation->result_array());
				w2dc_addMessage($validation->error_array(), 'error');
	
				w2dc_renderTemplate('content_fields/add_edit_content_fields_group.tpl.php', array('content_fields' => $content_fields, 'content_fields_group' => $content_fields_group, 'group_id' => $group_id));
			}
		} else {
			w2dc_renderTemplate('content_fields/add_edit_content_fields_group.tpl.php', array('content_fields' => $content_fields, 'content_fields_group' => $content_fields_group, 'group_id' => $group_id));
		}
	}

	public function configureContentField($field_id) {
		global $w2dc_instance;
	
		if (($content_field = $w2dc_instance->content_fields->getContentFieldById($field_id)) && $content_field->isConfigurationPage()) {
			$content_field->configure();
			
			if (w2dc_getValue($_POST, 'submit')) {
				do_action("w2dc_save_content_field_config");
			}
		} else {
			w2dc_addMessage(esc_attr__("This content field can't be configured", 'W2DC'), 'error');
			$this->showContentFieldsTable();
		}
	}

	public function deleteContentField($field_id) {
		global $w2dc_instance;
	
		$content_fields = $w2dc_instance->content_fields;
		// core fields can't be deleted
		if (($content_field = $content_fields->getContentFieldById($field_id)) && !$content_field->is_core_field) {
			if (w2dc_getValue($_POST, 'submit')) {
				if ($content_fields->deleteContentField($field_id))
					w2dc_addMessage(__('Content field was deleted successfully!', 'W2DC'));
	
				$this->showContentFieldsTable();
				//wp_redirect(admin_url('admin.php?page=w2dc_content_fields'));
				//die();
			} else
				w2dc_renderTemplate('delete_question.tpl.php', array('heading' => __('Delete content field', 'W2DC'), 'question' => sprintf(__('Are you sure you want delete "%s" content field?', 'W2DC'), $content_field->name), 'item_name' => $content_field->name));
		} else
			$this->showContentFieldsTable();
	}

	public function deleteContentFieldsGroup($group_id) {
		global $w2dc_instance;
	
		$content_fields = $w2dc_instance->content_fields;
		if ($content_fields_group = $content_fields->getContentFieldsGroupById($group_id)) {
			if (w2dc_getValue($_POST, 'submit')) {
				if ($content_fields->deleteContentFieldsGroup($group_id))
					w2dc_addMessage(__('Content fields group was deleted successfully!', 'W2DC'));
	
				$this->showContentFieldsTable();
				//wp_redirect(admin_url('admin.php?page=w2dc_content_fields'));
				//die();
			} else
				w2dc_renderTemplate('delete_question.tpl.php', array('heading' => __('Delete content fields group', 'W2DC'), 'question' => sprintf(__('Are you sure you want delete "%s" content fields group?', 'W2DC'), $content_fields_group->name), 'item_name' => $content_fields_group->name));
		} else
			$this->showContentFieldsTable();
	}
	
	public function addFormEnctype($post) {
		if ($post->post_type == W2DC_POST_TYPE) {
			echo ' enctype="multipart/form-data" ';
		}
	}

	public function addContentFieldsMetabox($post_type) {
		if ($post_type == W2DC_POST_TYPE) {
			global $w2dc_instance;
			
			if ($w2dc_instance->content_fields->getNotCoreContentFields())
				add_meta_box('w2dc_content_fields',
						__('Content fields', 'W2DC'),
						array($this, 'contentFieldsMetabox'),
						W2DC_POST_TYPE,
						'normal',
						'high');
		}
	}
	
	public function contentFieldsMetabox($post) {
		global $w2dc_instance;
		
		if ($content_fields = $w2dc_instance->content_fields->getNotCoreContentFields()) {
			w2dc_renderTemplate('content_fields/content_fields_metabox.tpl.php', array('content_fields' => $content_fields, 'post' => $post));
		}
	}

	/**
	 * This action called before directory category item would be deleted,
	 * refresh categories array, those assigned with content fields.
	 * 
	 * @param int $tt_id - term taxonomy id
	 */
	public function renew_assigned_categories($tt_id) {
		if ($term = get_term_by('term_taxonomy_id', $tt_id, W2DC_CATEGORIES_TAX)) {
			global $wpdb;
			$content_fields = $wpdb->get_results("SELECT * FROM {$wpdb->w2dc_content_fields}", ARRAY_A);
			foreach ($content_fields AS $content_field) {
				if ($content_field['categories']) {
					$unserialized_categories = unserialize($content_field['categories']);
					if (count($unserialized_categories) > 1 || $unserialized_categories != array(''))
						if (($key = array_search($term->term_id, $unserialized_categories)) !== FALSE) {
							unset($unserialized_categories[$key]);
							$wpdb->update($wpdb->w2dc_content_fields, array('categories' => serialize($unserialized_categories)), array('id' => $content_field['id']));
						}
				}
			}
		}
	}
	
	// adapted for WPML
	/* public function wpml_config_array($config_all) {
		global $w2dc_instance;
		foreach ($w2dc_instance->content_fields->content_fields_array AS $content_field) {
			$config_all['wpml-config']['custom-fields']['custom-field'][] = array(
					'value' => '_content_field_' . $content_field->id,
					'attr' => array('action' => 'copy')
			);
		}
	
		return $config_all;
	} */
}

if( ! class_exists( 'WP_List_Table' ) ) {
	require_once( ABSPATH . 'wp-admin/includes/class-wp-list-table.php' );
}
class w2dc_manage_content_fields_table extends WP_List_Table {

	public function __construct() {
		parent::__construct(array(
				'singular' => __('content field', 'W2DC'),
				'plural' => __('content fields', 'W2DC'),
				'ajax' => false
		));
	}

	public function get_columns() {
		$columns = array(
				'id' => __('ID', 'W2DC'),
				'field_name' => __('Name', 'W2DC'),
				'field_type' => __('Field type', 'W2DC'),
				'required' => __('Required', 'W2DC'),
				'icon_image' => __('Icon image', 'W2DC'),
				'in_pages' => __('Visibility', 'W2DC'),
				'group_id' => __('Group', 'W2DC'),
		);
		$columns = apply_filters('w2dc_content_field_table_header', $columns);

		return $columns;
	}

	public function getItems($content_fields_object) {
		global $w2dc_instance;
		
		$items_array = array();
		foreach ($content_fields_object->content_fields_array as $id=>$content_field) {
			$items_array[$id] = array(
					'id' => $content_field->id,
					'is_core_field' => $content_field->is_core_field,
					'field_name' => $content_field->name,
					'field_type' => $content_field->type,
					'required' => $content_field->is_required,
					'can_be_required' => $content_field->canBeRequired(),
					'is_configuration_page' => $content_field->isConfigurationPage(),
					'icon_image' => $content_field->icon_image,
					'on_exerpt_page' => $content_field->on_exerpt_page,
					'on_listing_page' => $content_field->on_listing_page,
					'on_search_form' => $content_field->on_search_form,
					'on_map' => $content_field->on_map,
					'group_id' => $content_field->group_id,
					'content_field' => $content_field,
			);
			
			$items_array[$id]['categories'] = array();
			if ($content_field->isCategories()) {
				$items_array[$id]['categories'] = $content_field->categories;
			}
			
			$items_array[$id]['levels'] = array();
			foreach ($w2dc_instance->levels->levels_array AS $level) {
				if (empty($level->content_fields) || in_array($content_field->id, $level->content_fields)) {
					$items_array[$id]['levels'][] = $level->name;
				}
			}
			
			$items_array[$id] = apply_filters('w2dc_content_field_table_row', $items_array[$id], $content_field);
		}
		return $items_array;
	}

	public function prepareItems($content_fields_object) {
		$this->_column_headers = array($this->get_columns(), array(), array());

		$this->items = $this->getItems($content_fields_object);
	}

	public function column_field_name($item) {
		$actions['edit'] = sprintf('<a href="?page=%s&action=%s&field_id=%d">' . __('Edit', 'W2DC') . '</a>', $_GET['page'], 'edit', $item['id']);
		if ($item['is_configuration_page']) {
			$actions['configure'] = sprintf('<a href="?page=%s&action=%s&field_id=%d">' . __('Configure', 'W2DC') . '</a>', $_GET['page'], 'configure', $item['id']);
		}
		
		$actions = apply_filters('w2dc_content_fields_column_options', $actions, $item);

		if (!$item['is_core_field'])
			$actions['delete'] = sprintf('<a href="?page=%s&action=%s&field_id=%d">' . __('Delete', 'W2DC') . '</a>', $_GET['page'], 'delete', $item['id']);
		return sprintf('%1$s %2$s', sprintf('<a href="?page=%s&action=%s&field_id=%d">' . $item['field_name'] . '</a><input type="hidden" class="content_field_weight_id" value="%d" />', $_GET['page'], 'edit', $item['id'], $item['id']), $this->row_actions($actions));
	}

	public function column_field_type($item) {
		global $w2dc_instance;

		return $w2dc_instance->content_fields->fields_types_names[$item['field_type']];
	}

	public function column_required($item) {
		if ($item['can_be_required'])
			if ($item['required'])
				return '<img src="' . W2DC_RESOURCES_URL . 'images/accept.png" />';
			else
				return '<img src="' . W2DC_RESOURCES_URL . 'images/delete.png" />';
		else
			return ' ';
	}

	public function column_icon_image($item) {
		if ($item['icon_image'] && !is_numeric($item['icon_image'])) {
			return '<span class="w2dc-icon-tag w2dc-fa ' . $item['icon_image'] . '"></span>';
		} elseif (is_numeric($item['icon_image'])) {
			$content_field = $item['content_field'];
			
			return '<span class="w2dc-field-caption"><span ' . $content_field->getIconImageTagParams() . '></span></span>';
		} else {
			return ' ';
		}
	}

	public function column_in_pages($item) {
		global $w2dc_instance;
		
		$html = array();
		if ($item['on_exerpt_page'])
			$html[] = __('On excerpt pages', 'W2DC');
		if ($item['on_listing_page'])
			$html[] = __('On listing page', 'W2DC');
		if ($item['on_map'])
			$html[] = __('In map marker InfoWindow', 'W2DC');
		if ($item['on_search_form'])
			$html_array[] = __('On search form', 'W2DC');
		
		if (!$item['is_core_field']) {
			if (empty($item['categories'])) {
				$html[] = '<hr /><img src="' . W2DC_RESOURCES_URL . 'images/accept.png" /> ' . __('All Categories', 'W2DC');
			} else {
				$html[] = '<hr /><img src="' . W2DC_RESOURCES_URL . 'images/delete.png" /> ' . __('Partial Categories', 'W2DC');
			}
			
			if (count($item['levels']) == count($w2dc_instance->levels->levels_array)) {
				$html[] = '<hr /><img src="' . W2DC_RESOURCES_URL . 'images/accept.png" /> ' . __('All Levels', 'W2DC');
			} else {
				$html[] = '<hr /><img src="' . W2DC_RESOURCES_URL . 'images/delete.png" /> ' . __('Partial Levels', 'W2DC');
			}
		}
		
		$html = apply_filters('w2dc_content_fields_in_pages_options', $html, $item);
		
		if ($html)
			return implode('<br />', $html);
		else
			return ' ';
	}
	
	public function column_group_id($item) {
		global $w2dc_instance;

		echo '<select name="group_id_' . $item['id'] . '">';
		echo '<option value=0>' . __('- no group -', 'W2DC') . '</option>';
		foreach ($w2dc_instance->content_fields->content_fields_groups_array AS $group)
			echo '<option value=' . $group->id . ' ' . selected($item['group_id'], $group->id) . '>' . $group->name . '</option>';
		echo '</select>';
	}

	public function column_default($item, $column_name) {
		switch($column_name) {
			default:
				return $item[$column_name];
		}
	}

	public function no_items() {
		__('No content fields found.', 'W2DC');
	}
}

class w2dc_manage_content_fields_groups_table extends WP_List_Table {

	public function __construct() {
		parent::__construct(array(
				'singular' => __('content fields group', 'W2DC'),
				'plural' => __('content fields groups', 'W2DC'),
				'ajax' => false
		));
	}

	public function get_columns() {
		$columns = array(
				'id' => __('ID', 'W2DC'),
				'group_name' => __('Name', 'W2DC'),
				'on_tab' => __('On tab', 'W2DC'),
				'hide_anonymous' => __('Hide from anonymous', 'W2DC'),
		);
		$columns = apply_filters('w2dc_content_field_table_header', $columns);

		return $columns;
	}

	public function getItems($content_fields_object) {
		$items_array = array();
		foreach ($content_fields_object->content_fields_groups_array as $id=>$content_fields_group) {
			$items_array[$id] = array(
					'id' => $content_fields_group->id,
					'group_name' => $content_fields_group->name,
					'on_tab' => $content_fields_group->on_tab,
					'hide_anonymous' => $content_fields_group->hide_anonymous,
			);
		}
		return $items_array;
	}

	public function prepareItems($content_fields_object) {
		$this->_column_headers = array($this->get_columns(), array(), array());

		$this->items = $this->getItems($content_fields_object);
	}

	public function column_id($item) {
		return $item['id'];
	}
	
	public function column_group_name($item) {
		$actions['edit'] = sprintf('<a href="?page=%s&action=%s&group_id=%d">' . __('Edit', 'W2DC') . '</a>', $_GET['page'], 'edit_group', $item['id']);
		$actions['delete'] = sprintf('<a href="?page=%s&action=%s&group_id=%d">' . __('Delete', 'W2DC') . '</a>', $_GET['page'], 'delete_group', $item['id']);
		return sprintf('%1$s %2$s', sprintf('<a href="?page=%s&action=%s&group_id=%d">' . $item['group_name'] . '</a>', $_GET['page'], 'edit_group', $item['id']), $this->row_actions($actions));
	}

	public function column_on_tab($item) {
		if ($item['on_tab'])
			return '<img src="' . W2DC_RESOURCES_URL . 'images/accept.png" />';
		else
			return '<img src="' . W2DC_RESOURCES_URL . 'images/delete.png" />';
	}

	public function column_hide_anonymous($item) {
		if ($item['hide_anonymous'])
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

	public function no_items() {
		__('No content fields groups found.', 'W2DC');
	}
}
?>