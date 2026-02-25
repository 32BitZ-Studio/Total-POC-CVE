<?php 

class w2dc_content_field_checkbox extends w2dc_content_field_select {
	public $how_display_items = 'checked';
	public $columns_number = 3;
	public $value = array();
	public $icon_images = array();
	
	protected $can_be_searched = true;
	
	public function configure() {
		global $wpdb, $w2dc_instance;
		
		wp_enqueue_script('jquery-ui-sortable');
	
		if (w2dc_getValue($_POST, 'submit') && wp_verify_nonce($_POST['w2dc_configure_content_fields_nonce'], W2DC_PATH)) {
			$validation = new w2dc_form_validation();
			$validation->set_rules('selection_items[]', __('Selection items', 'W2DC'), 'required');
			$validation->set_rules('icon_images[]', __('Icon images', 'W2DC'));
			$validation->set_rules('how_display_items', __('How to display items', 'W2DC'), 'required');
			$validation->set_rules('columns_number', __('Columns number', 'W2DC'), 'required|integer');
			if ($validation->run()) {
				$result = $validation->result_array();
	
				$insert_update_args['selection_items'] = $result['selection_items[]'];
				$insert_update_args['icon_images'] = $result['icon_images[]'];
				$insert_update_args['how_display_items'] = $result['how_display_items'];
				$insert_update_args['columns_number'] = $result['columns_number'];
	
				$insert_update_args = apply_filters('w2dc_selection_items_update_args', $insert_update_args, $this, $result);
	
				if ($insert_update_args) {
					$wpdb->update($wpdb->w2dc_content_fields, array('options' => serialize($insert_update_args)), array('id' => $this->id), null, array('%d'));
				}
	
				w2dc_addMessage(__('Field configuration was updated successfully!', 'W2DC'));
	
				do_action('w2dc_update_selection_items', $result['selection_items[]'], $this);
	
				$w2dc_instance->content_fields_manager->showContentFieldsTable();
			} else {
				$this->selection_items = $validation->result_array('selection_items[]');
				$this->icon_images = $validation->result_array('icon_images[]');
				$this->how_display_items = $validation->result_array('how_display_items');
				$this->columns_number = $validation->result_array('columns_number');
				w2dc_addMessage($validation->error_array(), 'error');
	
				w2dc_renderTemplate('content_fields/fields/checkboxes_configuration.tpl.php', array('content_field' => $this));
			}
		} else {
			w2dc_renderTemplate('content_fields/fields/checkboxes_configuration.tpl.php', array('content_field' => $this));
		}
	}
	
	public function buildOptions() {
		if (isset($this->options['selection_items'])) {
			$this->selection_items = $this->options['selection_items'];
		}
		if (isset($this->options['icon_images'])) {
			$this->icon_images = $this->options['icon_images'];
		} else {
			foreach ($this->selection_items AS $key=>$item) {
				$this->icon_images[$key] = '';
			}
		}
		if (isset($this->options['how_display_items'])) {
			$this->how_display_items = $this->options['how_display_items'];
		}
		if (isset($this->options['columns_number'])) {
			$this->columns_number = $this->options['columns_number'];
		}
	}

	public function renderInput() {
		if (!($template = w2dc_isTemplate('content_fields/fields/checkbox_input_'.$this->id.'.tpl.php'))) {
			$template = 'content_fields/fields/checkbox_input.tpl.php';
		}
		
		$template = apply_filters('w2dc_content_field_input_template', $template, $this);
			
		w2dc_renderTemplate($template, array('content_field' => $this));
	}
	
	public function validateValues(&$errors, $data) {
		$field_index = 'w2dc-field-input-' . $this->id . '[]';

		$validation = new w2dc_form_validation();
		$validation->set_rules($field_index, $this->name);
		if (!$validation->run())
			$errors[] = $validation->error_array();
		elseif ($selected_items_array = $validation->result_array($field_index)) {
			foreach ($selected_items_array AS $selected_item) {
				if (!in_array($selected_item, array_keys($this->selection_items)))
					$errors[] = sprintf(__("This selection option index \"%d\" doesn't exist", 'W2DC'), $selected_item);
			}
	
			return $selected_items_array;
		} elseif ($this->canBeRequired() && $this->is_required)
			$errors[] = sprintf(__('At least one option must be selected in "%s" content field', 'W2DC'), $this->name);
	}
	
	public function saveValue($post_id, $validation_results) {
		delete_post_meta($post_id, '_content_field_' . $this->id);
		if ($validation_results && is_array($validation_results)) {
			foreach ($validation_results AS $value)
				add_post_meta($post_id, '_content_field_' . $this->id, $value);
		}
		return true;
	}
	
	public function loadValue($post_id) {
		if (!($this->value = get_post_meta($post_id, '_content_field_' . $this->id)) || $this->value[0] == '')
			$this->value = array();
		else {
			$result = array();
			foreach ($this->selection_items AS $key=>$value) {
				if (array_search($key, $this->value) !== FALSE)
					$result[] = $key;
			}
			$this->value = $result;
		}
		
		$this->value = apply_filters('w2dc_content_field_load', $this->value, $this, $post_id);
		return $this->value;
	}
	
	public function renderOutput($listing, $group = null, $css_classes = '') {
		if (!($template = w2dc_isTemplate('content_fields/fields/checkbox_output_'.$this->id.'.tpl.php'))) {
			$template = 'content_fields/fields/checkbox_output.tpl.php';
		}

		$template = apply_filters('w2dc_content_field_output_template', $template, $this, $listing, $group);
			
		w2dc_renderTemplate($template, array('content_field' => $this, 'listing' => $listing, 'group' => $group, 'css_classes' => $css_classes));
	}
	
	public function validateCsvValues($value, &$errors) {
		if ($value) {
			$output = array();
			foreach ((array) $value AS $key=>$selected_item) {
				if (array_key_exists($selected_item, $this->selection_items)) {
					$output[] = $selected_item;
					continue;
				}

				if (!in_array($selected_item, $this->selection_items))
					$errors[] = sprintf(__("This selection option \"%s\" doesn't exist", 'W2DC'), $selected_item);
				else
					$output[] = array_search($selected_item, $this->selection_items);
			}
			return $output;
		} else 
			return '';
	}
	
	public function exportCSV() {
		$result_values = array();
		foreach ($this->value AS $key=>$val) {
			$result_values[] = $this->selection_items[$val];
		}
		
		return implode(';', $result_values);
	}
	
	public function renderOutputForMap($location, $listing) {
		return w2dc_renderTemplate('content_fields/fields/checkbox_output_map.tpl.php', array('content_field' => $this, 'listing' => $listing), true);
	}
}
?>