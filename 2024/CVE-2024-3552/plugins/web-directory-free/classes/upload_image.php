<?php

add_action('wp_ajax_w2dc_upload_image_single', 'w2dc_upload_image_single');
add_action('wp_ajax_nopriv_w2dc_upload_image_single', 'w2dc_upload_image_single');
function w2dc_upload_image_single() {
	$name = w2dc_getValue($_GET, 'input_name');
	$upload = new w2dc_upload_image(esc_attr($name));
	$upload->do_upload();
}

class w2dc_upload_image {
	public $input_name;
	public $action_url;
	public $default_attachment_id;
	public $default_url;
	public $size;
	
	public function __construct($input_name, $attachment_id = false, $size = 'full') {
		$this->input_name = $input_name;
		$this->size = $size;
		
		if (is_numeric($attachment_id)) {
			$this->default_attachment_id = $attachment_id;
			
			if ($img = wp_get_attachment_image_src($this->default_attachment_id, $size)) {
				$this->default_url = $img[0];
			}
		}
		
		if (is_admin() && current_user_can('upload_files')) {
			wp_enqueue_media();
		}
		add_action('wp_enqueue_scripts', array($this, 'enqueue_scripts_styles'));
	}
	
	public function get_field_name() {
		return 'w2dc-upload-image-input-' . $this->input_name;
	}
	
	public function get_attachment_id_from_post() {
		$field = $this->get_field_name();
		return w2dc_getValue($_POST, $field, '');
	}
	
	public function display_form() {
		$this->action_url = admin_url('admin-ajax.php?action=w2dc_upload_image_single&input_name='.$this->input_name.'&_wpnonce='.wp_create_nonce('upload_images'));
		
		w2dc_renderTemplate(W2DC_TEMPLATES_PATH . 'upload_image.tpl.php', array('upload' => $this));
	}
	
	public function do_upload() {
		$result = array('error_msg' => '', 'uploaded_file' => '');
		
		if (wp_verify_nonce($_GET['_wpnonce'], 'upload_images') && isset($_FILES['browse_file']) && ($_FILES['browse_file']['size'] > 0) && isset($_GET['input_name']) && ($input_name = $_GET['input_name'])) {
			if (is_user_logged_in() && current_user_can('upload_files')) {
				// Get the type of the uploaded file. This is returned as "type/extension"
				$arr_file_type = wp_check_filetype(basename($_FILES['browse_file']['name']));
				$uploaded_file_type = $arr_file_type['type'];
		
				// Set an array containing a list of acceptable formats
				$allowed_file_types = array('image/jpg', 'image/jpeg', 'image/gif', 'image/png');
		
				// If the uploaded file is the right format
				if (in_array($uploaded_file_type, $allowed_file_types)) {
					// Options array for the wp_handle_upload function. 'test_upload' => false
					$upload_overrides = array('test_form' => false);
		
					// Handle the upload using WP's wp_handle_upload function. Takes the posted file and an options array
					$uploaded_file = wp_handle_upload($_FILES['browse_file'], $upload_overrides);
		
					// If the wp_handle_upload call returned a local path for the image
					if (isset($uploaded_file['file'])) {
						// The wp_insert_attachment function needs the literal system path, which was passed back from wp_handle_upload
						$file_name_and_location = $uploaded_file['file'];
		
						// Set up options array to add this file as an attachment
						$attachment = array(
								'post_mime_type' => $uploaded_file_type,
								'post_title' => '',
								'post_content' => '',
								'post_status' => 'inherit'
						);
		
						// Run the wp_insert_attachment function. This adds the file to the media library and generates the thumbnails. If you wanted to attch this image to a post, you could pass the post id as a third param and it'd magically happen.
						$attachment_id = wp_insert_attachment($attachment, $file_name_and_location);
						require_once(ABSPATH . 'wp-admin/includes/image.php');
						$attach_data = wp_generate_attachment_metadata($attachment_id, $file_name_and_location);
						wp_update_attachment_metadata($attachment_id,  $attach_data);
								
						$src = wp_get_attachment_image_src($attachment_id, $this->size);
						
						$result['uploaded_file'] = $src[0];
						$result['attachment_id'] = $attachment_id;
						$result['metadata']['size'] = size_format(filesize(get_attached_file($attachment_id)));
						$metadata = wp_get_attachment_metadata($attachment_id);
						$result['metadata']['width'] = $metadata['width'];
						$result['metadata']['height'] = $metadata['height'];
					} else // wp_handle_upload returned some kind of error. the return does contain error details, so you can use it here if you want.
						$result['error_msg'] = 'There was a problem with your upload: ' . $uploaded_file['error'];
				}  else // wrong file type
					$result['error_msg'] = esc_html__('Please upload only image files (jpg, gif or png).', 'W2DC');
			} else
				$result['error_msg'] = esc_html__('You do not have permissions to edit this post!', 'W2DC');
		} else // no file was passed
			$result['error_msg'] = esc_html__('Choose image to upload first!', 'W2DC');
		
		echo json_encode($result);
		die();
	}
	
	public function enqueue_scripts_styles() {
		wp_enqueue_script('jquery-ui-widget');
		wp_register_script('w2dc_fileupload', W2DC_RESOURCES_URL . 'js/jquery.fileupload.js', array('jquery'), false, true);
		wp_register_script('w2dc_fileupload_iframe', W2DC_RESOURCES_URL . 'js/jquery.iframe-transport.js', array('jquery'), false, true);
		wp_enqueue_script('w2dc_fileupload');
		wp_enqueue_script('w2dc_fileupload_iframe');
	}
}