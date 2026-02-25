<?php 

class w2dc_content_field_number extends w2dc_content_field {
	public $is_integer = false;
	public $decimal_separator = ',';
	public $thousands_separator = ' ';
	public $min = 0;
	public $max;

	protected $is_configuration_page = true;
	protected $can_be_searched = true;
	
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
			$validation->set_rules('is_integer', __('Is integer or decimal', 'W2DC'), 'required|natural');
			$validation->set_rules('decimal_separator', __('Decimal separator',  'W2DC'), 'required|max_length[1]');
			$validation->set_rules('thousands_separator', __('Thousands separator', 'W2DC'), 'max_length[1]');
			$validation->set_rules('min', __('Min', 'W2DC'), 'numeric');
			$validation->set_rules('max', __('Max', 'W2DC'), 'numeric');
			if ($validation->run()) {
				$result = $validation->result_array();
				if ($wpdb->update($wpdb->w2dc_content_fields, array('options' => serialize(array('is_integer' => $result['is_integer'], 'decimal_separator' => $result['decimal_separator'], 'thousands_separator' => $result['thousands_separator'], 'min' => $result['min'], 'max' => $result['max']))), array('id' => $this->id), null, array('%d')))
					w2dc_addMessage(__('Field configuration was updated successfully!', 'W2DC'));
				
				$w2dc_instance->content_fields_manager->showContentFieldsTable();
			} else {
				$this->is_integer = $validation->result_array('is_integer');
				$this->decimal_separator = $validation->result_array('decimal_separator');
				$this->thousands_separator = $validation->result_array('thousands_separator');
				$this->min = $validation->result_array('min');
				$this->max = $validation->result_array('max');
				w2dc_addMessage($validation->error_array(), 'error');

				w2dc_renderTemplate('content_fields/fields/number_configuration.tpl.php', array('content_field' => $this));
			}
		} else
			w2dc_renderTemplate('content_fields/fields/number_configuration.tpl.php', array('content_field' => $this));
	}
	
	public function buildOptions() {
		if (isset($this->options['is_integer']))
			$this->is_integer = $this->options['is_integer'];
		if (isset($this->options['decimal_separator']))
			$this->decimal_separator = $this->options['decimal_separator'];
		if (isset($this->options['thousands_separator']))
			$this->thousands_separator = $this->options['thousands_separator'];
		if (isset($this->options['min']))
			$this->min = $this->options['min'];
		if (isset($this->options['max']))
			$this->max = $this->options['max'];
	}
	
	public function renderInput() {
		if (!($template = w2dc_isTemplate('content_fields/fields/number_input_'.$this->id.'.tpl.php'))) {
			$template = 'content_fields/fields/number_input.tpl.php';
		}
		
		$template = apply_filters('w2dc_content_field_input_template', $template, $this);
			
		w2dc_renderTemplate($template, array('content_field' => $this));
	}
	
	public function validateValues(&$errors, $data) {
		$field_index = 'w2dc-field-input-' . $this->id;

		$validation = new w2dc_form_validation();
		$rules = 'numeric';
		if ($this->canBeRequired() && $this->is_required)
			$rules .= '|required';
		if ($this->is_integer)
			$rules .= '|integer';
		if (is_numeric($this->min))
			$rules .= '|greater_than[' . $this->min . ']';
		if (is_numeric($this->max))
			$rules .= '|less_than[' . $this->max . ']';
		$validation->set_rules($field_index, $this->name, $rules);
		if (!$validation->run())
			$errors[] = $validation->error_array();
	
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
		if (is_numeric($this->value)) {
			$formatted_number = $this->formatValue();

			if (!($template = w2dc_isTemplate('content_fields/fields/number_output_'.$this->id.'.tpl.php'))) {
				$template = 'content_fields/fields/number_output.tpl.php';
			}
			
			$template = apply_filters('w2dc_content_field_output_template', $template, $this, $listing, $group);
			
			w2dc_renderTemplate($template, array('content_field' => $this, 'formatted_number' => $formatted_number, 'listing' => $listing, 'group' => $group, 'css_classes' => $css_classes));
		}
	}
	
	public function formatValue($value = null) {
		
		if (is_null($value)) {
			$value = $this->value;
		}
		
		if ($this->is_integer) {
			$decimals = 0;
		} else { 
			$decimals = 2;
		}
		
		return number_format($value, $decimals, $this->decimal_separator, $this->thousands_separator);
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
		if (!is_numeric($value))
			$errors[] = sprintf(__('The %s field must contain only numbers.', 'W2DC'), $this->name);
		elseif ($this->is_integer && !ctype_digit($value))
			$errors[] = sprintf(__('The %s field must contain an integer.', 'W2DC'), $this->name);
		elseif (is_numeric($this->min) && $value < $this->min)
			$errors[] = sprintf(__('The %s field must contain a number greater than %s.', 'W2DC'), $this->name, $this->min);
		elseif (is_numeric($this->max) && $value > $this->max)
			$errors[] = sprintf(__('The %s field must contain a number less than %s.', 'W2DC'), $this->name, $this->max);

		return $value;
	}
	
	public function renderOutputForMap($location, $listing) {
		if (is_numeric($this->value)) {
			$formatted_number = $this->formatValue();
	
			return $formatted_number;
		}
	}
	
	public function getWidgetParams() {
		return array(
				array(
						'type' => 'textfield',
						'param_name' => $this->slug,
						'heading' => $this->name,
						'description' => esc_html__("Example: 1-10, 5-, -5", "W2DC")
				),
		);
	}
	
}
?>