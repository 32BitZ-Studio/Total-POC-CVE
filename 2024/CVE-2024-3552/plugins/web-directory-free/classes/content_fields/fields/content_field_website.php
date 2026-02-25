<?php 

class w2dc_content_field_website extends w2dc_content_field {
	public $is_blank = false;
	public $is_nofollow = false;
	public $use_link_text = 1;
	public $default_link_text = '';
	public $use_default_link_text = 0;
	public $value = array('url' => '', 'text' => '');
	
	protected $can_be_ordered = false;
	protected $is_configuration_page = true;
	
	public function isNotEmpty($listing) {
		if ($this->value['url'])
			return true;
		else
			return false;
	}

	public function configure() {
		global $wpdb, $w2dc_instance;

		if (w2dc_getValue($_POST, 'submit') && wp_verify_nonce($_POST['w2dc_configure_content_fields_nonce'], W2DC_PATH)) {
			$validation = new w2dc_form_validation();
			$validation->set_rules('is_blank', __('Open link in new window', 'W2DC'), 'is_checked');
			$validation->set_rules('is_nofollow', __('Add nofollow attribute', 'W2DC'), 'is_checked');
			$validation->set_rules('use_link_text', __('Placeholder link text', 'W2DC'), 'is_checked');
			$validation->set_rules('default_link_text', __('Placeholder link text', 'W2DC'));
			$validation->set_rules('use_default_link_text', __('Use placeholder link text', 'W2DC'), 'is_checked');
			if ($validation->run()) {
				$result = $validation->result_array();
				if ($wpdb->update($wpdb->w2dc_content_fields, array('options' => serialize(array('is_blank' => $result['is_blank'], 'is_nofollow' => $result['is_nofollow'], 'use_link_text' => $result['use_link_text'], 'default_link_text' => $result['default_link_text'], 'use_default_link_text' => $result['use_default_link_text']))), array('id' => $this->id), null, array('%d')))
					w2dc_addMessage(__('Field configuration was updated successfully!', 'W2DC'));
				
				$w2dc_instance->content_fields_manager->showContentFieldsTable();
			} else {
				$this->is_blank = $validation->result_array('is_blank');
				$this->is_nofollow = $validation->result_array('is_nofollow');
				$this->use_link_text = $validation->result_array('use_link_text');
				$this->default_link_text = $validation->result_array('default_link_text');
				$this->use_default_link_text = $validation->result_array('use_default_link_text');
				w2dc_addMessage($validation->error_array(), 'error');

				w2dc_renderTemplate('content_fields/fields/website_configuration.tpl.php', array('content_field' => $this));
			}
		} else
			w2dc_renderTemplate('content_fields/fields/website_configuration.tpl.php', array('content_field' => $this));
	}
	
	public function buildOptions() {
		if (isset($this->options['is_blank']))
			$this->is_blank = $this->options['is_blank'];

		if (isset($this->options['is_nofollow']))
			$this->is_nofollow = $this->options['is_nofollow'];

		if (isset($this->options['use_link_text']))
			$this->use_link_text = $this->options['use_link_text'];

		if (isset($this->options['default_link_text']))
			$this->default_link_text = $this->options['default_link_text'];

		if (isset($this->options['use_default_link_text']))
			$this->use_default_link_text = $this->options['use_default_link_text'];
	}
	
	public function renderInput() {
		// Placeholder link text
		if ($this->value['text'] == '')
			$this->value['text'] = $this->default_link_text;

		if (!($template = w2dc_isTemplate('content_fields/fields/website_input_'.$this->id.'.tpl.php'))) {
			$template = 'content_fields/fields/website_input.tpl.php';
		}
		
		$template = apply_filters('w2dc_content_field_input_template', $template, $this);
			
		w2dc_renderTemplate($template, array('content_field' => $this));
	}
	
	public function validateValues(&$errors, $data) {
		$field_index_url = 'w2dc-field-input-url_' . $this->id;
		$field_index_text = 'w2dc-field-input-text_' . $this->id;

		$validation = new w2dc_form_validation();
		$rules = 'valid_url[1]'; // 1 - is the second parameter, must be $prepare_url=true
		if ($this->canBeRequired() && $this->is_required)
			$rules .= '|required';
		$validation->set_rules($field_index_url, $this->name, $rules);
		$validation->set_rules($field_index_text, $this->name);
		if (!$validation->run())
			$errors[] = $validation->error_array();

		return array('url' => $validation->result_array($field_index_url), 'text' => $validation->result_array($field_index_text));
	}
	
	public function saveValue($post_id, $validation_results) {
		return update_post_meta($post_id, '_content_field_' . $this->id, $validation_results);
	}
	
	public function loadValue($post_id) {
		if ($value = get_post_meta($post_id, '_content_field_' . $this->id, true)) {
			$this->value = maybe_unserialize($value);
		}
		
		// It has value, but was not formated as URL>Text, probably swithed from another type
		if (!empty($this->value) && is_string($this->value) && empty($this->value['url'])) {
			$this->value['url'] = $this->value;
		}
		if (!isset($this->value['url'])) {
			$this->value['url'] = '';
		}
		
		// Placeholder link text
		if (empty($this->value['text']) && $this->use_default_link_text) {
			$this->value['text'] = $this->default_link_text;
		}
		if (!isset($this->value['text'])) {
			$this->value['text'] = '';
		}

		$this->value = apply_filters('w2dc_content_field_load', $this->value, $this, $post_id);
		return $this->value;
	}
	
	public function renderOutput($listing, $group = null, $css_classes = '') {
		if (!($template = w2dc_isTemplate('content_fields/fields/website_output_'.$this->id.'.tpl.php'))) {
			$template = 'content_fields/fields/website_output.tpl.php';
		}
		
		$template = apply_filters('w2dc_content_field_output_template', $template, $this, $listing, $group);
		
		w2dc_renderTemplate($template, array('content_field' => $this, 'listing' => $listing, 'group' => $group, 'css_classes' => $css_classes));
	}
	
	public function validateCsvValues($value, &$errors) {
		$value = explode('>', $value);
		$url = $value[0];
		$validation = new w2dc_form_validation();
		if (!$validation->valid_url($url))
			$errors[] = __("Website URL field is invalid", "W2DC");

		$text = (isset($value[1]) ? $value[1] : '');
		return array('url' => $url, 'text' => $text);
	}
	
	public function exportCSV() {
		if (is_array($this->value)) {
			if ($this->value['url']) {
				$output = $this->value['url'];
				if ($this->value['text'] && $this->value['text'] != $this->value['url'] && (!$this->use_default_link_text || $this->value['text'] != $this->default_link_text)) {
					$output .= ">" . $this->value['text'];
				}
				return  $output;
			}
		} else {
			return $this->value;
		}
	}
	
	public function renderOutputForMap($location, $listing) {
		return w2dc_renderTemplate('content_fields/fields/website_output_map.tpl.php', array('content_field' => $this, 'listing' => $listing), true);
	}
}
?>