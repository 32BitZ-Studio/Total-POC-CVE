<?php 

class w2dc_content_field_string extends w2dc_content_field {
	public $max_length = 255;
	public $regex;
	
	protected $can_be_searched = true;
	protected $is_configuration_page = true;
	
	public function isNotEmpty($listing) {
		if ($this->value)
			return true;
		else
			return false;
	}

	public function configure() {
		global $wpdb, $w2dc_instance;

		if (w2dc_getValue($_POST, 'submit') && wp_verify_nonce($_POST['w2dc_configure_content_fields_nonce'], W2DC_PATH)) {
			$validation = new w2dc_form_validation();
			$validation->set_rules('max_length', __('Max length', 'W2DC'), 'required|is_natural_no_zero');
			$validation->set_rules('regex', __('PHP RegEx template', 'W2DC'));
			if ($validation->run()) {
				$result = $validation->result_array();
				if ($wpdb->update($wpdb->w2dc_content_fields, array('options' => serialize(array('max_length' => $result['max_length'], 'regex' => $result['regex']))), array('id' => $this->id), null, array('%d'))) {
					w2dc_addMessage(__('Field configuration was updated successfully!', 'W2DC'));
				}
				
				$w2dc_instance->content_fields_manager->showContentFieldsTable();
			} else {
				$this->max_length = $validation->result_array('max_length');
				$this->regex = $validation->result_array('regex');
				w2dc_addMessage($validation->error_array(), 'error');

				w2dc_renderTemplate('content_fields/fields/string_configuration.tpl.php', array('content_field' => $this));
			}
		} else
			w2dc_renderTemplate('content_fields/fields/string_configuration.tpl.php', array('content_field' => $this));
	}
	
	public function buildOptions() {
		if (isset($this->options['max_length'])) {
			$this->max_length = $this->options['max_length'];
		}

		if (isset($this->options['regex'])) {
			$this->regex = $this->options['regex'];
		}
	}
	
	public function renderInput() {
		if (!($template = w2dc_isTemplate('content_fields/fields/string_input_'.$this->id.'.tpl.php'))) {
			$template = 'content_fields/fields/string_input.tpl.php';
		}
		
		$template = apply_filters('w2dc_content_field_input_template', $template, $this);
			
		w2dc_renderTemplate($template, array('content_field' => $this));
	}
	
	public function validateValues(&$errors, $data) {
		$field_index = 'w2dc-field-input-' . $this->id;
		
		if (isset($_POST[$field_index]) && $_POST[$field_index] && $this->regex)
			if (@!preg_match('/^' . $this->regex . '$/', $_POST[$field_index]))
				$errors[] = sprintf(__("Field %s doesn't match template!", 'W2DC'), $this->name);

		$validation = new w2dc_form_validation();
		$rules = 'max_length[' . $this->max_length . ']';
		if ($this->canBeRequired() && $this->is_required) {
			$rules .= '|required';
		}
		$validation->set_rules($field_index, $this->name, $rules);
		if (!$validation->run()) {
			$errors[] = $validation->error_array();
		}

		return $validation->result_array($field_index);
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
		if (!($template = w2dc_isTemplate('content_fields/fields/string_output_'.$this->id.'.tpl.php'))) {
			$template = 'content_fields/fields/string_output.tpl.php';
		}
		
		$template = apply_filters('w2dc_content_field_output_template', $template, $this, $listing, $group);
			
		w2dc_renderTemplate($template, array('content_field' => $this, 'listing' => $listing, 'group' => $group, 'css_classes' => $css_classes));
	}
	
	public function orderParams($order_args) {
		$order_args['orderby'] = 'meta_value_num';
		$order_args['meta_key'] = '_content_field_' . $this->id;
		
		if (get_option('w2dc_orderby_exclude_null')) {
			$order_args['meta_query'][] = array(
				array(
					'key' => '_content_field_' . $this->id,
					'value'   => array(''),
					'compare' => 'NOT IN'
				)
			);
		}
		return $order_args;
	}

	public function validateCsvValues($value, &$errors) {
		if (!is_string($value))
			$errors[] = sprintf(__('Field %s must be a string!', 'W2DC'), $this->name);
		elseif ($this->regex && @!preg_match('/^' . $this->regex . '$/', $value))
			$errors[] = sprintf(__("Field %s doesn't match template!", 'W2DC'), $this->name);
		elseif (strlen($value) > $this->max_length)
			$errors[] = sprintf(__('The %s field can not exceed %s characters in length.', 'W2DC'), $this->name, $this->max_length);
		else
			return $value;
	}
	
	public function renderOutputForMap($location, $listing) {
		return $this->value;
	}
	
	public function getWidgetParams() {
		return array(
				array(
						'type' => 'textfield',
						'param_name' => $this->slug,
						'heading' => $this->name,
				),
		);
	}
}
?>