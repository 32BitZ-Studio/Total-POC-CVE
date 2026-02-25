<?php 

class w2dc_content_field_select extends w2dc_content_field {
	public $selection_items = array();

	protected $can_be_ordered = false;
	protected $is_configuration_page = true;
	protected $can_be_searched = true;
	
	public function isNotEmpty($listing) {
		if ($this->value)
			return true;
		else
			return false;
	}
	
	public function __construct() {
		// adapted for WPML
		add_action('init', array($this, 'content_fields_options_into_strings'));
	}

	public function configure() {
		global $wpdb, $w2dc_instance;

		wp_enqueue_script('jquery-ui-sortable');

		if (w2dc_getValue($_POST, 'submit') && wp_verify_nonce($_POST['w2dc_configure_content_fields_nonce'], W2DC_PATH)) {
			$validation = new w2dc_form_validation();
			$validation->set_rules('selection_items[]', __('Selection items', 'W2DC'), 'required');
			if ($validation->run()) {
				$result = $validation->result_array();
				
				$insert_update_args['selection_items'] = $result['selection_items[]'];

				$insert_update_args = apply_filters('w2dc_selection_items_update_args', $insert_update_args, $this, $result);

				if ($insert_update_args) {
					$wpdb->update($wpdb->w2dc_content_fields, array('options' => serialize($insert_update_args)), array('id' => $this->id), null, array('%d'));
				}

				w2dc_addMessage(__('Field configuration was updated successfully!', 'W2DC'));
				
				do_action('w2dc_update_selection_items', $result['selection_items[]'], $this);
				
				$w2dc_instance->content_fields_manager->showContentFieldsTable();
			} else {
				$this->selection_items = $validation->result_array('selection_items[]');
				w2dc_addMessage($validation->error_array(), 'error');

				w2dc_renderTemplate('content_fields/fields/select_configuration.tpl.php', array('content_field' => $this));
			}
		} else {
			w2dc_renderTemplate('content_fields/fields/select_configuration.tpl.php', array('content_field' => $this));
		}
	}
	
	public function buildOptions() {
		if (isset($this->options['selection_items'])) {
			$this->selection_items = $this->options['selection_items'];
		}
	}
	
	public function renderInput() {
		if (!($template = w2dc_isTemplate('content_fields/fields/select_input_'.$this->id.'.tpl.php'))) {
			$template = 'content_fields/fields/select_input.tpl.php';
		}
		
		$template = apply_filters('w2dc_content_field_input_template', $template, $this);
			
		w2dc_renderTemplate($template, array('content_field' => $this));
	}
	
	public function validateValues(&$errors, $data) {
		$field_index = 'w2dc-field-input-' . $this->id;

		$validation = new w2dc_form_validation();
		$rules = '';
		if ($this->canBeRequired() && $this->is_required)
			$rules .= '|required';
		$validation->set_rules($field_index, $this->name, $rules);
		if (!$validation->run())
			$errors[] = $validation->error_array();
		elseif ($selected_item = $validation->result_array($field_index)) {
			if (!in_array($selected_item, array_keys($this->selection_items)))
				$errors[] = sprintf(__("This selection option index \"%d\" doesn't exist", 'W2DC'), $selected_item);

			return $selected_item;
		}
	}
	
	public function saveValue($post_id, $validation_results) {
		return update_post_meta($post_id, '_content_field_' . $this->id, $validation_results);
	}
	
	public function loadValue($post_id) {
		$this->value = get_post_meta($post_id, '_content_field_' . $this->id, true);
		
		$this->value = apply_filters('w2dc_content_field_load', $this->value, $this, $post_id);
		return $this->value;
	}
	
	public function renderOutput($listing, $group = null, $css_classes = '') {
		if (!($template = w2dc_isTemplate('content_fields/fields/select_radio_output_'.$this->id.'.tpl.php'))) {
			$template = 'content_fields/fields/select_radio_output.tpl.php';
		}
		
		$template = apply_filters('w2dc_content_field_output_template', $template, $this, $listing, $group);
			
		w2dc_renderTemplate($template, array('content_field' => $this, 'listing' => $listing, 'group' => $group, 'css_classes' => $css_classes));
	}

	public function validateCsvValues($value, &$errors) {
		if ($value) {
			if (array_key_exists($value, $this->selection_items))
				return $value;
				
			if (!in_array($value, $this->selection_items))
				$errors[] = sprintf(__("This selection option \"%s\" doesn't exist", 'W2DC'), $value);
			else
				return array_search($value, $this->selection_items);
		} else 
			return '';
	}
	
	public function renderOutputForMap($location, $listing) {
		if ($this->value && isset($this->selection_items[$this->value])) {
			return $this->selection_items[$this->value];
		}
	}

	// adapted for WPML
	public function content_fields_options_into_strings() {
		global $sitepress;

		if (function_exists('wpml_object_id_filter') && $sitepress) {
			foreach ($this->selection_items AS $key=>&$item) {
				$item = apply_filters('wpml_translate_single_string', $item, 'Web 2.0 Directory', 'The option #' . $key . ' of content field #' . $this->id);
			}
		}
	}
	
	public function getWidgetParams() {
		if ($this->on_search_form) {
			return array(
					array(
							'type' => 'checkbox',
							'param_name' => $this->slug,
							'heading' => $this->name,
							'value' => array_flip($this->selection_items),
					),
			);
		}
	}
	
	public function exportCSV() {
		if ($this->value && isset($this->selection_items[$this->value])) {
			return $this->selection_items[$this->value];
		}
	}
}

add_filter('w2dc_selection_items_update_args', 'w2dc_filter_selection_items', 10, 3);
function w2dc_filter_selection_items($insert_update_args, $content_field, $array) {
	global $sitepress, $wpdb;

	if (function_exists('wpml_object_id_filter') && $sitepress) {
		if ($sitepress->get_default_language() != ICL_LANGUAGE_CODE) {
			if (isset($_GET['action']) && $_GET['action'] == 'configure' && isset($_GET['field_id'])) {
				foreach ($insert_update_args['selection_items'] AS $key=>$item) {
					$content_field_id = $_GET['field_id'];
					if ($option_string_id = icl_st_is_registered_string('Web 2.0 Directory', 'The option #' . $key . ' of content field #' . $content_field_id))
						icl_add_string_translation($option_string_id, ICL_LANGUAGE_CODE, $item, ICL_TM_COMPLETE);
					unset($insert_update_args['selection_items']);
				}
			}
		}
	}
	return $insert_update_args;
}

add_action('w2dc_update_selection_items', 'w2dc_update_selection_items', 10, 2);
function w2dc_update_selection_items($selection_items, $content_field) {
	global $sitepress;

	if (function_exists('wpml_object_id_filter') && $sitepress) {
		if ($sitepress->get_default_language() == ICL_LANGUAGE_CODE) {
			foreach ($selection_items AS $key=>&$item) {
				do_action('wpml_register_single_string', 'Web 2.0 Directory',  'The option #' . $key . ' of content field #' . $content_field->id, $item);
			}
		}
	}
}
?>