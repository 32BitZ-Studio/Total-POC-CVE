<?php

define('WCSEARCH_DEMO_DATA_PATH', WCSEARCH_PATH . 'demo-data/');

class wcsearch_demo_data_manager {
	public function __construct() {
		add_action('admin_menu', array($this, 'menu'));
		add_action('admin_init', array($this, 'export'));
	}

	public function export() {
		global $wpdb, $wcsearch_instance, $wcsearch_default_model_settings;
		
		if (wcsearch_getValue($_POST, 'export') && (!defined('WCSEARCH_DEMO') || !WCSEARCH_DEMO)) {
				
			if (!isset($GLOBALS['wp_filesystem']) || !is_object($GLOBALS['wp_filesystem'])) {
				WP_Filesystem();
			}
			$zip_file = trailingslashit(get_temp_dir()) . 'wcsearch_export_' . time() . '.zip';
		
			require_once(ABSPATH . 'wp-admin/includes/class-pclzip.php');
				
			$zip = new PclZip($zip_file);
			$wp_file = new WP_Filesystem_Direct(array());
			$all_files = array();
				
			$demo_links_controller = new wcsearch_demo_links_controller();
			
			foreach ($demo_links_controller->pages AS $page_slug=>$page_title) {
				$post_ids = get_posts(array(
						'name'				=> $page_slug,
						'post_type'			=> 'page',
						'posts_per_page'	=> 1,
				));
				if ($post_ids) {
					$page = array_shift($post_ids);
						
					$content = $page->post_content;
						
					$dir = get_temp_dir();
					$file_name = $dir . $page_title . '.txt';
					$wp_file->put_contents($file_name, $content);
						
					$zip->add($file_name, PCLZIP_OPT_ADD_PATH, 'pages', PCLZIP_OPT_REMOVE_PATH, $dir);
					$all_files[] = $file_name;
				}
			}
			
			foreach ($demo_links_controller->search_forms AS $page_slug=>$page_title) {
				$post_ids = get_posts(array(
						's'					=> $page_title,
						'post_type'			=> WCSEARCH_FORM_TYPE,
						'posts_per_page'	=> 1,
				));
				if ($post_ids) {
					$search_form_post = array_shift($post_ids);
					
					foreach ($wcsearch_default_model_settings AS $setting=>$value) {
						if (metadata_exists('post', $search_form_post->ID, '_'.$setting)) {
							$search_form_data[$setting] = get_post_meta($search_form_post->ID, '_'.$setting, true);
						} else {
							$search_form_data[$setting] = $wcsearch_default_model_settings[$setting];
						}
					}
					
					if (count($search_form_data)) {
						$content = json_encode($search_form_data);

						$dir = get_temp_dir();
						$file_name = $dir . $page_title . '.txt';
						$wp_file->put_contents($file_name, $content);
							
						$zip->add($file_name, PCLZIP_OPT_ADD_PATH, 'search_forms', PCLZIP_OPT_REMOVE_PATH, $dir);
						$all_files[] = $file_name;
					}
				}
			}
				
			header("Pragma: public");
			header("Expires: 0");
			header("Cache-Control: must-revalidate, post-check=0, pre-check=0");
			header("Cache-Control: private", false);
			header("Content-Type: application/octet-stream");
			header('Content-Disposition: attachment; filename="' . basename($zip_file) . '"');
			header('Content-Length: ' . filesize($zip_file));
			flush();
			readfile($zip_file);
				
			$wp_file = new WP_Filesystem_Direct(array());
			$wp_file->delete($zip_file);
				
			foreach ($all_files AS $file_name) {
				$wp_file->delete($file_name);
			}
		}
	}
	
	public function menu() {
		if (defined('WCSEARCH_DEMO') && WCSEARCH_DEMO) {
			$capability = 'publish_posts';
		} else {
			$capability = 'manage_options';
		}
		
		add_submenu_page('edit.php?post_type=wcsearch_form',
		__('Demo data Import', 'WCSEARCH'),
		__('Demo data Import', 'WCSEARCH'),
		$capability,
		'wcsearch_demo_data',
		array($this, 'wcsearch_demo_data_import_page')
		);
	}
	
	public function wcsearch_demo_data_import_page() {
		if (wcsearch_getValue($_POST, 'submit') && wp_verify_nonce($_POST['wcsearch_csv_import_nonce'], WCSEARCH_PATH) && (!defined('WCSEARCH_DEMO') || !WCSEARCH_DEMO)) {
			
			$pages_files = glob(WCSEARCH_DEMO_DATA_PATH . 'pages/*.{txt}', GLOB_BRACE);
			foreach ($pages_files AS $file) {
				$title = basename($file, '.txt');
				$content = file_get_contents($file);
				
				$page_id = wp_insert_post(array(
						'post_type' => 'page',
						'post_title' => $title,
						'post_content' => $content,
						'post_status' => 'publish',
						'post_author' => get_current_user_id(),
				));
			}
			
			$search_forms_files = glob(WCSEARCH_DEMO_DATA_PATH . 'search_forms/*.{txt}', GLOB_BRACE);
			foreach ($search_forms_files AS $file) {
				$title = basename($file, '.txt');
					
				$search_form_id = wp_insert_post(array(
						'post_type' => WCSEARCH_FORM_TYPE,
						'post_title' => $title,
						'post_content' => '',
						'post_status' => 'publish',
						'post_author' => get_current_user_id(),
				));
			
				$json = json_decode(file_get_contents($file), true);
				foreach ($json AS $meta_key=>$meta_value) {
					update_post_meta($search_form_id, '_' . $meta_key, $meta_value);
				}
			}
			
			wcsearch_addMessage(sprintf(__("Import of the demo data was successfully completed. Look at your <a href='%s'>search forms</a> and <a href='%s'>demo pages</a>.", "WCSEARCH"), admin_url('edit.php?post_type=wcsearch_form'), admin_url('edit.php?post_type=page')));
			
			wcsearch_renderTemplate('demo_data_import.tpl.php');
		} else {
			$this->importInstructions();
		}
	}
	
	public function importInstructions() {
		wcsearch_renderTemplate('demo_data_import.tpl.php');
	}
}

?>