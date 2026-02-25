<?php 

class w2dc_content_field_datetime extends w2dc_content_field {
	public $is_time = true;
	public $hide_past_dates = false;
	
	protected $is_configuration_page = true;
	protected $can_be_searched = true;
	
	public function __construct() {
		// adapted for WPML
		//add_filter('wpml_config_array', array($this, 'wpml_config_array'));
	}
	
	public function isNotEmpty($listing) {
		if ((isset($this->value['date_start']) && $this->value['date_start']) || (isset($this->value['date_end']) && $this->value['date_end'])) {
			return true;
		} if ($this->is_time) {
			if ((isset($this->value['hour']) && $this->value['hour'] != '00') || (isset($this->value['minute']) && $this->value['minute'] != '00')) {
				return true;
			}
		}

		return false;
	}

	public function configure() {
		global $wpdb, $w2dc_instance;

		if (w2dc_getValue($_POST, 'submit') && wp_verify_nonce($_POST['w2dc_configure_content_fields_nonce'], W2DC_PATH)) {
			$validation = new w2dc_form_validation();
			$validation->set_rules('is_time', __('Enable time in field', 'W2DC'), 'is_checked');
			$validation->set_rules('hide_past_dates', __('Hide listings with passed dates', 'W2DC'), 'is_checked');
			if ($validation->run()) {
				$result = $validation->result_array();
				$serialized_options = serialize(array(
						'is_time' 			=> $result['is_time'],
						'hide_past_dates' 	=> $result['hide_past_dates']
				));
				if ($wpdb->update($wpdb->w2dc_content_fields, array('options' => $serialized_options), array('id' => $this->id), null, array('%d')))
					w2dc_addMessage(__('Field configuration was updated successfully!', 'W2DC'));
				
				$w2dc_instance->content_fields_manager->showContentFieldsTable();
			} else {
				$this->is_time = $validation->result_array('is_time');
				$this->hide_past_dates = $validation->result_array('hide_past_dates');
				w2dc_addMessage($validation->error_array(), 'error');

				w2dc_renderTemplate('content_fields/fields/datetime_configuration.tpl.php', array('content_field' => $this));
			}
		} else
			w2dc_renderTemplate('content_fields/fields/datetime_configuration.tpl.php', array('content_field' => $this));
	}
	
	public function buildOptions() {
		if (isset($this->options['is_time'])) {
			$this->is_time = $this->options['is_time'];
		}
		if (isset($this->options['hide_past_dates'])) {
			$this->hide_past_dates = $this->options['hide_past_dates'];
		}
	}
	
	public function delete() {
		global $wpdb;
	
		$wpdb->delete($wpdb->postmeta, array('meta_key' => '_content_field_' . $this->id . '_date'));
		$wpdb->delete($wpdb->postmeta, array('meta_key' => '_content_field_' . $this->id . '_date_start'));
		$wpdb->delete($wpdb->postmeta, array('meta_key' => '_content_field_' . $this->id . '_date_end'));
		$wpdb->delete($wpdb->postmeta, array('meta_key' => '_content_field_' . $this->id . '_hour'));
		$wpdb->delete($wpdb->postmeta, array('meta_key' => '_content_field_' . $this->id . '_minute'));
	
		$wpdb->delete($wpdb->w2dc_content_fields, array('id' => $this->id));
		return true;
	}
	
	public function renderInput() {
		if (!($template = w2dc_isTemplate('content_fields/fields/datetime_input_'.$this->id.'.tpl.php'))) {
			$template = 'content_fields/fields/datetime_input.tpl.php';
		}
		
		$template = apply_filters('w2dc_content_field_input_template', $template, $this);
			
		w2dc_renderTemplate($template, array('content_field' => $this, 'dateformat' => w2dc_getDatePickerFormat()));
	}
	
	public function validateValues(&$errors, $data) {
		$field_index_date_start = 'w2dc-field-input-' . $this->id . '-start';
		$field_index_date_end = 'w2dc-field-input-' . $this->id . '-end';
		$field_index_hour = 'w2dc-field-input-hour_' . $this->id;
		$field_index_minute = 'w2dc-field-input-minute_' . $this->id;

		$validation = new w2dc_form_validation();
		$rules = 'valid_date';
		/* if ($this->canBeRequired() && $this->is_required)
			$rules .= 'required|is_natural_no_zero'; */
		$validation->set_rules($field_index_date_start, $this->name, $rules);
		$validation->set_rules($field_index_date_end, $this->name, $rules);
		$validation->set_rules($field_index_hour, $this->name);
		$validation->set_rules($field_index_minute, $this->name);
		if (!$validation->run()) {
			$errors[] = $validation->error_array();
		}

		return array(
				'date_start' => $validation->result_array($field_index_date_start),
				'date_end' => $validation->result_array($field_index_date_end),
				'hour' => $validation->result_array($field_index_hour),
				'minute' => $validation->result_array($field_index_minute)
		);
	}
	
	public function saveValue($post_id, $validation_results) {
		if ($validation_results && is_array($validation_results)) {
			if (!empty($validation_results['date_start']) || !empty($validation_results['date_end'])) {
				update_post_meta($post_id, '_content_field_' . $this->id . '_date_start', $validation_results['date_start']);
				update_post_meta($post_id, '_content_field_' . $this->id . '_date_end', $validation_results['date_end']);
			} else {
				delete_post_meta($post_id, '_content_field_' . $this->id . '_date_start');
				delete_post_meta($post_id, '_content_field_' . $this->id . '_date_end');
			}
			update_post_meta($post_id, '_content_field_' . $this->id . '_hour', $validation_results['hour']);
			update_post_meta($post_id, '_content_field_' . $this->id . '_minute', $validation_results['minute']);
			return true;
		}
	}
	
	public function loadValue($post_id) {
		$this->value = array(
			'date_start' => 0,
			'date_end' => 0,
			'hour' => 0,
			'minute' => 0,
		);
		$date_start = 0;
		$date_end = 0;
		if (get_post_meta($post_id, '_content_field_' . $this->id . '_date_start', true)) {
			$date_start = get_post_meta($post_id, '_content_field_' . $this->id . '_date_start', true);
		}
		if (get_post_meta($post_id, '_content_field_' . $this->id . '_date_end', true)) {
			$date_end = get_post_meta($post_id, '_content_field_' . $this->id . '_date_end', true);
		}
		$hour = (get_post_meta($post_id, '_content_field_' . $this->id . '_hour', true) ? get_post_meta($post_id, '_content_field_' . $this->id . '_hour', true) : '00');
		$minute = (get_post_meta($post_id, '_content_field_' . $this->id . '_minute', true) ? get_post_meta($post_id, '_content_field_' . $this->id . '_minute', true) : '00');
		
		$validation = new w2dc_form_validation();
		if ($validation->valid_date($date_start) && $validation->valid_date($date_end)) {
			$this->value = array(
				'date_start' => $date_start,
				'date_end' => $date_end,
				'hour' => $hour,
				'minute' => $minute,
			);
			
			$this->value = apply_filters('w2dc_content_field_load', $this->value, $this, $post_id);
		}

		return $this->value;
	}
	
	public function renderOutput($listing, $group = null, $css_classes = '') {
		if ($this->value['date_start'] || $this->value['date_end']) {
			$formatted_date_start = ($this->value['date_start']) ? mysql2date(w2dc_getDateFormat(), date('Y-m-d H:i:s', $this->value['date_start'])) : false;
			$formatted_date_end = ($this->value['date_end']) ? mysql2date(w2dc_getDateFormat(), date('Y-m-d H:i:s', $this->value['date_end'])) : false;

			if (!($template = w2dc_isTemplate('content_fields/fields/datetime_output_'.$this->id.'.tpl.php'))) {
				$template = 'content_fields/fields/datetime_output.tpl.php';
			}
			
			$template = apply_filters('w2dc_content_field_output_template', $template, $this, $listing, $group);
				
			w2dc_renderTemplate($template, array('content_field' => $this, 'formatted_date_start' => $formatted_date_start, 'formatted_date_end' => $formatted_date_end, 'listing' => $listing, 'group' => $group, 'css_classes' => $css_classes));
		}
	}
	
	public function orderParams($order_args) {
		$order_args['orderby'] = 'meta_value_num';
		$order_args['meta_key'] = '_content_field_' . $this->id .'_date_start';
		
		if (get_option('w2dc_orderby_exclude_null'))
			$order_args['meta_query'][] = array(
				array(
					'key' => '_content_field_' . $this->id . '_date_start',
					'value'   => array(''),
					'compare' => 'NOT IN'
				)
			);
		return $order_args;
	}
	
	/*
	 * Possible formats:
	 * dd.mm.yyyy
	 * dd.mm.yyyy HH:MM
	 * dd.mm.yyyy HH:MM - dd.mm.yyyy HH:MM
	 * dd.mm.yyyy - dd.mm.yyyy
	 * dd.mm.yyyy HH:MM - dd.mm.yyyy
	 */
	public function validateCsvValues($value, &$errors) {
		$output = array();
		
		$start_end = explode('-', $value);
		if (isset($start_end[0])) {
			$start_value = $start_end[0];
			if ($tmstmp = strtotime($start_value)) {
				$output['minute'] = date('i', $tmstmp);
				$output['hour'] = date('H', $tmstmp);
				$output['date_start'] = $tmstmp - 3600*$output['hour'] - 60*$output['minute'];
				
				if (isset($start_end[1])) {
					$end_value = $start_end[1];
					if ($tmstmp = strtotime($end_value)) {
						$output['date_end'] = $tmstmp - 3600*$output['hour'] - 60*$output['minute'];
					} else {
						$errors[] = __("End Date-Time field is invalid", "W2DC");
					}
				} else {
					$output['date_end'] = $output['date_start'];
				}
			} else {
				$errors[] = __("Start Date-Time field is invalid", "W2DC");
			}
		}

		return $output;
	}
	
	public function exportCSV() {
		if ($this->value['date_start'] && $this->value['date_end']) {
			return date('d.m.Y H:i', $this->value['date_start']) . ' - ' . date('d.m.Y H:i', $this->value['date_end']);
		}
	}
	
	public function renderOutputForMap($location, $listing) {
		if ($this->value['date_start'] || $this->value['date_end']) {
			$formatted_date_start = mysql2date(w2dc_getDateFormat(), date('Y-m-d H:i:s', $this->value['date_start']));
			$formatted_date_end = mysql2date(w2dc_getDateFormat(), date('Y-m-d H:i:s', $this->value['date_end']));
	
			return w2dc_renderTemplate('content_fields/fields/datetime_output_map.tpl.php', array('content_field' => $this, 'formatted_date_start' => $formatted_date_start, 'formatted_date_end' => $formatted_date_end, 'listing' => $listing), true);
		}
	}
	
	public function getWidgetParams() {
		return array(
				array(
						'type' => 'datefieldmin',
						'param_name' => $this->slug . '_min',
						'heading' => __('From ', 'W2DC') . $this->name,
						'field_id' => $this->id,
				),
				array(
						'type' => 'datefieldmax',
						'param_name' => $this->slug . '_max',
						'heading' => __('To ', 'W2DC') . $this->name,
						'field_id' => $this->id,
				)
		);
	}
	
	// adapted for WPML
	/* public function wpml_config_array($config_all) {
		$config_all['wpml-config']['custom-fields']['custom-field'][] = array(
				'value' => '_content_field_' . $this->id . '_date',
				'attr' => array('action' => 'copy')
		);
		$config_all['wpml-config']['custom-fields']['custom-field'][] = array(
				'value' => '_content_field_' . $this->id . '_hour',
				'attr' => array('action' => 'copy')
		);
		$config_all['wpml-config']['custom-fields']['custom-field'][] = array(
				'value' => '_content_field_' . $this->id . '_minute',
				'attr' => array('action' => 'copy')
		);

		return $config_all;
	} */
}
?>