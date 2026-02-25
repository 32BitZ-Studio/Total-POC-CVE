<?php

define('W2DC_DEMO_DATA_PATH', W2DC_PATH . 'demo-data/');

class w2dc_demo_data_manager {
	public function __construct() {
		add_action('admin_menu', array($this, 'menu'));
		add_action('admin_init', array($this, 'export'));
	}
	
	public function export() {
		global $wpdb, $wcsearch_default_model_settings;
	
		if (w2dc_getValue($_POST, 'export') && wp_verify_nonce($_POST['w2dc_csv_import_nonce'], W2DC_PATH) && (!defined('W2DC_DEMO') || !W2DC_DEMO)) {
	
			if (!isset($GLOBALS['wp_filesystem']) || !is_object($GLOBALS['wp_filesystem'])) {
				WP_Filesystem();
			}
			$zip_file = trailingslashit(get_temp_dir()) . 'w2dc_export_' . time() . '.zip';
	
			require_once(ABSPATH . 'wp-admin/includes/class-pclzip.php');
	
			$zip = new PclZip($zip_file);
			$wp_file = new WP_Filesystem_Direct(array());
			$all_files = array();
	
			$demo_links_controller = new w2dc_demo_links_controller();
				
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
		if (defined('W2DC_DEMO') && W2DC_DEMO) {
			$capability = 'publish_posts';
		} else {
			$capability = 'manage_options';
		}
		
		add_submenu_page('w2dc_settings',
		__('Demo data Import', 'W2DC'),
		__('Demo data Import', 'W2DC'),
		$capability,
		'w2dc_demo_data',
		array($this, 'w2dc_demo_data_import_page')
		);
	}
	
	public function w2dc_demo_data_import_page() {
		if (w2dc_getValue($_POST, 'submit') && wp_verify_nonce($_POST['w2dc_csv_import_nonce'], W2DC_PATH) && (!defined('W2DC_DEMO') || !W2DC_DEMO)) {
			global $w2dc_instance;
			
			$csv_manager = new w2dc_csv_manager();
			$csv_manager->setImportType('create_listings');
			$csv_manager->createHelper();
			$csv_manager->columns_separator = ',';
			$csv_manager->values_separator = ';';
			$csv_manager->if_term_not_found = 'create';
			$csv_manager->selected_user = get_current_user_id();
			$csv_manager->do_geocode = false;
			$csv_manager->is_claimable = false;
			$csv_manager->collated_fields = array(
					'title',
					'level_id',
					'content',
					'excerpt',
					'categories_list',
					'locations_list',
					'address_line_1',
					'address_line_2',
					'latitude',
					'longitude',
					'map_icon_file',
					'phone',
					'website',
					'email',
					'images',
			);
			$csv_file_name = W2DC_DEMO_DATA_PATH . 'listings.csv';
			$csv_manager->extractCsv($csv_file_name);
			$zip_images_file_name = W2DC_DEMO_DATA_PATH . 'images.zip';
			$csv_manager->extractImages($zip_images_file_name);
			
			ob_start();
			$csv_manager->processCSV();
			ob_clean();
			
			if ($csv_manager->images_dir) {
				$csv_manager->removeImagesDir($csv_manager->images_dir);
			}
			
			$pages_files = glob(W2DC_DEMO_DATA_PATH . 'pages/*.{txt}', GLOB_BRACE);
			foreach ($pages_files AS $file) {
				$title = basename($file, '.txt');
				$title = str_replace("[", "", $title);
				$title = str_replace("]", "", $title);
				$content = file_get_contents($file);
				
				$page_id = wp_insert_post(array(
						'post_type' => 'page',
						'post_title' => $title,
						'post_content' => $content,
						'post_status' => 'publish',
						'post_author' => get_current_user_id(),
				));
			}
			
			$search_forms_files = glob(W2DC_DEMO_DATA_PATH . 'search_forms/*.{txt}', GLOB_BRACE);
			foreach ($search_forms_files AS $file) {
				$title = basename($file, '.txt');
				$title = str_replace("[", "", $title);
				$title = str_replace("]", "", $title);
					
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
			
			w2dc_addMessage(sprintf(__("Import of the demo data was successfully completed. Look at your <a href='%s'>listings</a>, <a href='%s'>search forms</a> and <a href='%s'>custom pages</a>.", "W2DC"), admin_url('edit.php?post_type=w2dc_listing'), admin_url('edit.php?post_type=wcsearch_form'), admin_url('edit.php?post_type=page')));
			
			w2dc_renderTemplate('demo_data_import.tpl.php');
		} else {
			$this->importInstructions();
		}
	}
	
	public function importInstructions() {
		w2dc_renderTemplate('demo_data_import.tpl.php');
	}
}

?>