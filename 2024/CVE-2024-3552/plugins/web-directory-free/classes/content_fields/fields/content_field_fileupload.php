<?php 

class w2dc_content_field_fileupload extends w2dc_content_field {
	public $use_text = true;
	public $default_text = '';
	public $use_default_text = false;
	public $allowed_mime_types = array('images');
	public $value = array('id' => '', 'text' => '');
	
	protected $can_be_ordered = false;
	protected $is_configuration_page = true;
	
	public function isNotEmpty($listing) {
		if ($this->value['id'])
			return true;
		else
			return false;
	}

	public function configure() {
		global $wpdb, $w2dc_instance;

		if (w2dc_getValue($_POST, 'submit') && wp_verify_nonce($_POST['w2dc_configure_content_fields_nonce'], W2DC_PATH)) {
			$validation = new w2dc_form_validation();
			$validation->set_rules('use_text', __('Default file title text', 'W2DC'), 'is_checked');
			$validation->set_rules('default_text', __('Default file title text', 'W2DC'));
			$validation->set_rules('use_default_text', __('Use default file title text', 'W2DC'), 'is_checked');
			$validation->set_rules('allowed_mime_types', __('Use default file title text', 'W2DC'));
			if ($validation->run()) {
				$result = $validation->result_array();
				if ($wpdb->update($wpdb->w2dc_content_fields, array('options' => serialize(array('use_text' => $result['use_text'], 'default_text' => $result['default_text'], 'use_default_text' => $result['use_default_text'], 'allowed_mime_types' => $result['allowed_mime_types']))), array('id' => $this->id), null, array('%d')))
					w2dc_addMessage(__('Field configuration was updated successfully!', 'W2DC'));
				
				$w2dc_instance->content_fields_manager->showContentFieldsTable();
			} else {
				$this->use_text = $validation->result_array('use_text');
				$this->default_text = $validation->result_array('default_text');
				$this->use_default_text = $validation->result_array('use_default_text');
				$this->allowed_mime_types = $validation->result_array('allowed_mime_types');
				w2dc_addMessage($validation->error_array(), 'error');

				w2dc_renderTemplate('content_fields/fields/fileupload_configuration.tpl.php', array('content_field' => $this));
			}
		} else
			w2dc_renderTemplate('content_fields/fields/fileupload_configuration.tpl.php', array('content_field' => $this));
	}
	
	public function buildOptions() {
		if (isset($this->options['use_text']))
			$this->use_text = $this->options['use_text'];

		if (isset($this->options['default_text']))
			$this->default_text = $this->options['default_text'];

		if (isset($this->options['use_default_text']))
			$this->use_default_text = $this->options['use_default_text'];

		if (isset($this->options['allowed_mime_types']))
			$this->allowed_mime_types = $this->options['allowed_mime_types'];
	}
	
	public function renderInput() {
		// Default text
		if ($this->value['text'] == '') {
			$this->value['text'] = $this->default_text;
		}

		$file = null;
		if ($this->value['id']) {
			$file = get_post($this->value['id']);
		}

		if (!($template = w2dc_isTemplate('content_fields/fields/fileupload_input_'.$this->id.'.tpl.php'))) {
			$template = 'content_fields/fields/fileupload_input.tpl.php';
		}
		
		$template = apply_filters('w2dc_content_field_input_template', $template, $this);
			
		w2dc_renderTemplate($template, array('content_field' => $this, 'file' => $file));
	}
	
	public function validateValues(&$errors, $data) {
		global $w2dc_instance;
		$listing = $w2dc_instance->current_listing;

		$field_index_input = 'w2dc-field-input-' . $this->id;
		$field_index_text = 'w2dc-field-input-text-' . $this->id;
		$field_index_uploaded = 'w2dc-uploaded-file-' . $this->id;
		$field_index_reset = 'w2dc-reset-file-' . $this->id;
		
		$upload_errors = array();

		$validation = new w2dc_form_validation();
		$validation->set_rules($field_index_text, $this->name);
		if (!$validation->run()) {
			$upload_errors[] = $validation->error_array();
		}

		if (empty($_POST[$field_index_reset]) && !empty($_POST[$field_index_uploaded]) && (empty($_FILES) || !isset($_FILES[$field_index_input]) || !$_FILES[$field_index_input]['tmp_name'])) {
			return array('id' => $_POST[$field_index_uploaded], 'text' => $validation->result_array($field_index_text));
		}

		if (!empty($_POST[$field_index_reset]) && (empty($_FILES) || !isset($_FILES[$field_index_input]) || !$_FILES[$field_index_input]['tmp_name'])) {
			return array('id' => 0, 'text' => '');
		}

		if ($this->canBeRequired() && $this->is_required) {
			if (empty($_POST[$field_index_uploaded]) && (empty($_FILES) || !isset($_FILES[$field_index_input]) || !$_FILES[$field_index_input]['tmp_name'])) {
				$errors[] = sprintf(__('%s is required to be uploaded!', 'W2DC'), $this->name);
				return false;
			}
		} elseif (empty($_FILES) || !isset($_FILES[$field_index_input]) || !$_FILES[$field_index_input]['tmp_name']) {
			return array('id' => 0, 'text' => '');
		}

		$mimes = $this->get_mime_types();
		$allowed_mimes = array();
		foreach ($this->allowed_mime_types AS $type)
			$allowed_mimes = array_merge($allowed_mimes, $mimes[$type]['mimes']);

		$file = $_FILES[$field_index_input];

		$file['name'] = sanitize_file_name($file['name']);

		if ($file['tmp_name'] == "") {
			$upload_errors[] = __('File upload failed!', 'W2DC');
		}

		$typecheck = wp_check_filetype_and_ext($file['tmp_name'], $file['name'], false);
		if (!in_array($typecheck['type'], $allowed_mimes)) {
			$upload_errors[] = __('This type of file is not allowed!', 'W2DC');
		}

		if ($this->check_file_contents(file_get_contents($file['tmp_name'])) !== 0) {
			$upload_errors[] = __('The content of file is not allowed!', 'W2DC');
		}

		if (!$upload_errors) {
			include_once(ABSPATH . 'wp-admin/includes/admin.php');
			$upload_id = media_handle_sideload($file, (int)$listing->post->ID);
			if (!is_wp_error($upload_id)) {
				$media_id = $upload_id;
				return array('id' => $media_id, 'text' => $validation->result_array($field_index_text));
			} else {
				$upload_errors[] = __('Error during file upload!', 'W2DC');
				$errors = array_merge($errors, $upload_errors);
				return false;
			}
		} else {
			$errors = array_merge($errors, $upload_errors);
			return false;
		}
	}
	
	public function check_file_contents($str = '') {
		if (!is_string($str))
			return 0;
		
		return preg_match_all('/<\?php|eval\s*\(|base64_decode|gzinflate|gzuncompress/imsU', $str, $matches);
	}
	
	public function saveValue($post_id, $validation_results) {
		return update_post_meta($post_id, '_content_field_' . $this->id, $validation_results);
	}

	public function loadValue($post_id) {
		if ($value = get_post_meta($post_id, '_content_field_' . $this->id, true)) {
			$this->value = maybe_unserialize($value);
		}
		
		// Default text
		if ($this->value['text'] == '' && $this->use_default_text)
			$this->value['text'] = $this->default_text;

		$this->value = apply_filters('w2dc_content_field_load', $this->value, $this, $post_id);
		return $this->value;
	}
	
	public function renderOutput($listing, $group = null, $css_classes = '') {
		$file = null;
		if ($this->value['id']) {
			$file = get_post($this->value['id']);
		}

		if (!($template = w2dc_isTemplate('content_fields/fields/fileupload_output_'.$this->id.'.tpl.php'))) {
			$template = 'content_fields/fields/fileupload_output.tpl.php';
		}
		
		$template = apply_filters('w2dc_content_field_output_template', $template, $this, $listing, $group);

		w2dc_renderTemplate($template, array('content_field' => $this, 'listing' => $listing, 'group' => $group, 'file' => $file, 'css_classes' => $css_classes));
	}
	
	public function validateCsvValues($value, &$errors) {
		$value = explode('>', $value);
		$id = $value[0];
		if (is_integer($id))
			$errors[] = __("ID of media attachment is invalid", "W2DC");

		$text = (isset($value[1]) ? $value[1] : '');
		return array('id' => $id, 'text' => $text);
	}
	
	public function exportCSV() {
		if ($this->value['id']) {
			$file = get_post($this->value['id']);
			
			$output = basename($file->guid);
			if ($this->value['text'] && (!$this->use_default_text || $this->value['text'] != $this->default_text))
				$output .= ">" . $this->value['text'];
			return  $output;
		}
	}
	
	public function renderOutputForMap($location, $listing) {
		$file = null;
		if ($this->value['id']) {
			$file = get_post($this->value['id']);
		}

		return w2dc_renderTemplate('content_fields/fields/fileupload_output_map.tpl.php', array('content_field' => $this, 'listing' => $listing, 'file' => $file), true);
	}
	
	public function get_mime_types() {
		$mimes_exts = array(
			'images'=>
			array(
				'label'=> 'Images (jpg, png, gif)',
				'mimes'=>
				array(
					'image/jpg',
					'image/jpeg',
					'image/gif',
					'image/png'
				),
			),
			'txt'=>
			array(
				'label'=> 'Text',
				'mimes'=>
				array(
					'text/plain',
				),
			),
			'doc'=>
			array(
				'label'=> 'Microsoft Word Document',
				'mimes'=>
				array(
					'application/msword',
				),
			),
			'docx'=>
			array(
				'label'=> 'Microsoft Word Open XML Document',
				'mimes'=>
				array(
					'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
				),
			),
			'xls'=>
			array(
				'label'=> 'Excel Spreadsheet',
				'mimes'=>
				array(
					'application/vnd.ms-excel',
					'application/msexcel',
					'application/x-msexcel',
					'application/x-ms-excel',
					'application/vnd.ms-excel',
					'application/x-excel',
					'application/x-dos_ms_excel',
					'application/xls',
				),
			),
			'xlsx'=>
			array(
				'label'=> 'Microsoft Excel Open XML Spreadsheet',
				'mimes'=>
				array(
					'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
				),
			),
			'pdf'=>
			array(
				'label'=> 'Portable Document Format File',
				'mimes'=>
				array(
					'application/pdf',
					'application/x-pdf',
					'application/acrobat',
					'applications/vnd.pdf',
					'text/pdf',
					'text/x-pdf',
				),
			),
			'psd'=>
			array(
				'label'=> 'Adobe Photoshop Document',
				'mimes'=>
				array(
					'image/photoshop',
					'image/x-photoshop',
					'image/psd',
					'application/photoshop',
					 'application/psd',
					'zz-application/zz-winassoc-psd',
					'image/vnd.adobe.photoshop',
				),
			),
			'csv'=>
			array(
				'label'=> 'Comma Separated Values File',
				'mimes'=>
				array(
					'text/comma-separated-values',
					'text/csv',
					'application/csv',
					'application/excel',
					'application/vnd.ms-excel',
					'application/vnd.msexcel',
					'text/anytext',
				),
			),
			'ppt'=>
			array(
				'label'=> 'PowerPoint Presentation',
				'mimes'=>
				array(
					'application/vnd.ms-powerpoint',
					'application/mspowerpoint',
					'application/ms-powerpoint',
					'application/mspowerpnt',
					'application/vnd-mspowerpoint',
				),
			),
			'pptx'=>
			array(
				'label'=> 'PowerPoint Open XML Presentation',
				'mimes'=>
				array(
					'application/vnd.openxmlformats-officedocument.presentationml.presentation',
				),
			),
			'mp3'=>
			array(
				'label'=> 'MP3 Audio File',
				'mimes'=>
				array(
					'audio/mpeg',
					'audio/x-mpeg',
					'audio/mp3',
					'audio/x-mp3',
					'audio/mpeg3',
					'audio/x-mpeg3',
					'audio/mpg',
					'audio/x-mpg',
					'audio/x-mpegaudio',
				),
			),
			'avi'=>
			array(
				'label'=> 'Audio Video Interleave File',
				'mimes'=>
				array(
					'video/avi',
					'video/msvideo',
					'video/x-msvideo',
					'image/avi',
					'video/xmpg2',
					'application/x-troff-msvideo',
					'audio/aiff',
					'audio/avi',
				),
			),
			'mp4'=>
			array(
				'label'=> 'MPEG-4 Video File',
				'mimes'=>
				array(
					'video/mp4',
					'video/mp4v-es',
					'audio/mp4',
					'application/mp4',
				),
			),
			'm4a'=> array(
				'label'=> 'MPEG-4 Audio File',
				'mimes'=> array(
					'audio/aac', 'audio/aacp', 'audio/3gpp', 'audio/3gpp2', 'audio/mp4', 'audio/MP4A-LATM','audio/mpeg4-generic', 'audio/x-m4a', 'audio/m4a'
				) ),
			'mov'=>
			array(
				'label'=> 'Apple QuickTime Movie',
				'mimes'=>
				array(
					'video/quicktime',
					'video/x-quicktime',
					'image/mov',
					'audio/aiff',
					'audio/x-midi',
					'audio/x-wav',
					'video/avi',
				),
			),
			'mpg'=>
			array(
				'label'=> 'MPEG Video File',
				'mimes'=>
				array(
					'video/mpeg',
					'video/mpg',
					'video/x-mpg',
					'video/mpeg2',
					'application/x-pn-mpg',
					'video/x-mpeg',
					'video/x-mpeg2a',
					'audio/mpeg',
					'audio/x-mpeg',
					'image/mpg',
				),
			),
			'mid'=>
			array(
				'label'=> 'MIDI File',
				'mimes'=>
				array(
					'audio/mid',
					'audio/m',
					'audio/midi',
					'audio/x-midi',
					'application/x-midi',
					'audio/soundtrack',
				),
			),
			'wav'=>
			array(
				'label'=> 'WAVE Audio File',
				'mimes'=>
				array(
					'audio/wav',
					'audio/x-wav',
					'audio/wave',
					'audio/x-pn-wav',
				),
			),
			'wma'=>
			array(
				'label'=> 'Windows Media Audio File',
				'mimes'=>
				array(
					'audio/x-ms-wma',
					'video/x-ms-asf',
				),
			),
			'wmv'=>
			array(
				'label'=> 'Windows Media Video File',
				'mimes'=>
				array(
					'video/x-ms-wmv',
				),
			),
		);
	
		return $mimes_exts;
	}
}
?>