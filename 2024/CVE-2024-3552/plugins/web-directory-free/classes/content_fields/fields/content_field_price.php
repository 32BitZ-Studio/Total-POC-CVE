<?php 

class w2dc_content_field_price extends w2dc_content_field {
	public $is_integer = false; // required for the search function
	public $currency_symbol = '$';
	public $decimal_separator = ',';
	public $thousands_separator = ' ';
	public $symbol_position = 1;
	public $hide_decimals = 0;

	protected $is_configuration_page = true;
	protected $can_be_searched = true;
	
	public function isNotEmpty($listing) {
		if ($this->value) {
			return true;
		} else {
			return false;
		}
	}

	public function configure() {
		global $wpdb, $w2dc_instance;

		if (w2dc_getValue($_POST, 'submit') && wp_verify_nonce($_POST['w2dc_configure_content_fields_nonce'], W2DC_PATH)) {
			$validation = new w2dc_form_validation();
			$validation->set_rules('currency_symbol', __('Currency symbol', 'W2DC'), 'required');
			$validation->set_rules('decimal_separator', __('Decimal separator', 'W2DC'), 'required|max_length[1]');
			$validation->set_rules('thousands_separator', __('Thousands separator', 'W2DC'), 'max_length[1]');
			$validation->set_rules('symbol_position', __('Currency symbol position', 'W2DC'), 'integer');
			$validation->set_rules('hide_decimals', __('Hide decimals', 'W2DC'), 'required');
			if ($validation->run()) {
				$result = $validation->result_array();
				if ($wpdb->update($wpdb->w2dc_content_fields, array('options' => serialize(
						array(
								'currency_symbol' => $result['currency_symbol'],
								'decimal_separator' => $result['decimal_separator'],
								'thousands_separator' => $result['thousands_separator'],
								'symbol_position' => $result['symbol_position'],
								'hide_decimals' => $result['hide_decimals'],
						)
					)), array('id' => $this->id), null, array('%d'))) {
						w2dc_addMessage(__('Field configuration was updated successfully!', 'W2DC'));
				}
				
				$w2dc_instance->content_fields_manager->showContentFieldsTable();
			} else {
				$this->currency_symbol = $validation->result_array('currency_symbol');
				$this->decimal_separator = $validation->result_array('decimal_separator');
				$this->thousands_separator = $validation->result_array('thousands_separator');
				$this->symbol_position = $validation->result_array('symbol_position');
				$this->hide_decimals = $validation->result_array('hide_decimals');
				w2dc_addMessage($validation->error_array(), 'error');

				w2dc_renderTemplate('content_fields/fields/price_configuration.tpl.php', array('content_field' => $this));
			}
		} else
			w2dc_renderTemplate('content_fields/fields/price_configuration.tpl.php', array('content_field' => $this));
	}
	
	public function buildOptions() {
		if (isset($this->options['currency_symbol'])) {
			$this->currency_symbol = $this->options['currency_symbol'];
		}
		if (isset($this->options['decimal_separator'])) {
			$this->decimal_separator = $this->options['decimal_separator'];
		}
		if (isset($this->options['thousands_separator'])) {
			$this->thousands_separator = $this->options['thousands_separator'];
		}
		if (isset($this->options['symbol_position'])) {
			$this->symbol_position = $this->options['symbol_position'];
		}
		if (isset($this->options['hide_decimals'])) {
			$this->hide_decimals = $this->options['hide_decimals'];
		}
	}
	
	public function renderInput() {
		if (!($template = w2dc_isTemplate('content_fields/fields/price_input_'.$this->id.'.tpl.php'))) {
			$template = 'content_fields/fields/price_input.tpl.php';
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
		if (is_numeric($this->value)) {
			if (!($template = w2dc_isTemplate('content_fields/fields/price_output_'.$this->id.'.tpl.php'))) {
				$template = 'content_fields/fields/price_output.tpl.php';
			}
			
			$template = apply_filters('w2dc_content_field_output_template', $template, $this, $listing, $group);
				
			w2dc_renderTemplate($template, array('content_field' => $this, 'listing' => $listing, 'group' => $group, 'css_classes' => $css_classes));
		}
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
		if (!is_numeric($value)) {
			$errors[] = sprintf(__('The %s field must contain only numbers.', 'W2DC'), $this->name);
		}

		return $value;
	}
	
	public function renderOutputForMap($location, $listing) {
		if (is_numeric($this->value)) {
			return $this->formatValue();
		}
	}
	
	public function formatValue($value = null) {
		if (is_null($value)) {
			$value = $this->value;
		}
		if ($this->hide_decimals) {
			$decimals = 0;
		} else {
			$decimals = 2;
		}
		if ($this->thousands_separator == ' ') {
			$thousands_separator = '&nbsp;';
		} else {
			$thousands_separator = $this->thousands_separator;
		}
		$formatted_price = number_format($value, $decimals, $this->decimal_separator, $thousands_separator);

		$out = $formatted_price;
		switch ($this->symbol_position) {
			case 1:
				$out = $this->currency_symbol . $out;
				break;
			case 2:
				$out = $this->currency_symbol . '&nbsp' . $out;
				break;
			case 3:
				$out = $out . $this->currency_symbol;
				break;
			case 4:
				$out = $out . '&nbsp' . $this->currency_symbol;
				break;
		}
		return $out;
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