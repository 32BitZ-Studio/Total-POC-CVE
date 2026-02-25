<?php

class w2dc_csv_import_export_listings {
	public $csv_manager;
	public $collation_fields;
	public $export_rows_counter;
	public $total_rejected_lines;
	
	public function __construct($csv_manager) {
		$this->csv_manager = $csv_manager;
	}
	
	public function buildCollationColumns() {
		global $w2dc_instance;
		
		$this->csv_manager->collation_fields = array(
				'post_id' => __('Post ID* (existing listing)', 'W2DC'),
				'title' => __('Title*', 'W2DC'),
				'level_id' => __('Level ID*', 'W2DC'),
				'directory_id' => __('Directory ID', 'W2DC'),
				'user' => __('Author', 'W2DC'),
				'status' => __('Status (active, expired, unpaid)', 'W2DC'),
				'categories_list' => __('Categories', 'W2DC'),
				'listing_tags' => __('Tags', 'W2DC'),
				'content' => __('Description', 'W2DC'),
				'excerpt' => __('Summary', 'W2DC'),
				'locations_list' => __('Locations (existing or new)', 'W2DC'),
				'address_line_1' => __('Address line 1', 'W2DC'),
				'address_line_2' => __('Address line 2', 'W2DC'),
				'zip' => __('Zip code or postal index', 'W2DC'),
				'latitude' => __('Latitude', 'W2DC'),
				'longitude' => __('Longitude', 'W2DC'),
				'map_icon_file' => __('Map icon file', 'W2DC'),
				'additional_address_info' => __('Additional info for map marker', 'W2DC'),
				'images' => __('Images files', 'W2DC'),
				'videos' => __('YouTube or Vimeo videos', 'W2DC'),
				'expiration_date' => __('Listing expiration date', 'W2DC'),
				'contact_email' => __('Listing contact email', 'W2DC'),
				'claimable' => __('Make listing claimable', 'W2DC'),
		);
		
		// adapted for WPML
		global $sitepress;
		if (function_exists('wpml_object_id_filter') && $sitepress) {
			$this->csv_manager->collation_fields['wpml_translation_source_id'] = __('WPML translation source ID', 'W2DC');
		}
		
		$this->csv_manager->collation_fields = apply_filters('w2dc_csv_collation_fields_list', $this->csv_manager->collation_fields);
		
		foreach ($w2dc_instance->content_fields->content_fields_array AS $field) {
			if (!$field->is_core_field) {
				$this->csv_manager->collation_fields[$field->slug] = $field->name;
			}
		}
		
		if ($this->csv_manager->import_type == 'create_listings') {
			unset($this->csv_manager->collation_fields['post_id']);
		}
		
		return $this->csv_manager->collation_fields;
	}
	
	public function validateSettings($validation) {
		$validation->set_rules('if_term_not_found', __('Category not found', 'W2DC'), 'required');
		$validation->set_rules('author', __('Listings author', 'W2DC'), 'required|numeric');
		$validation->set_rules('do_geocode', __('Geocode imported listings', 'W2DC'));
		if (get_option('w2dc_fsubmit_addon') && get_option('w2dc_claim_functionality')) {
			$validation->set_rules('is_claimable', __('Configure imported listings as claimable', 'W2DC'));
		}
	}
	
	public function buildSettings($validation) {
		$this->csv_manager->if_term_not_found = $validation->result_array('if_term_not_found');
		$this->csv_manager->selected_user = $validation->result_array('author');
		$this->csv_manager->do_geocode = $validation->result_array('do_geocode');
		if (get_option('w2dc_fsubmit_addon') && get_option('w2dc_claim_functionality')) {
			$this->csv_manager->is_claimable = $validation->result_array('is_claimable');
		}
	}
	
	public function addTemplateFields($template_fields) {
		$add_template_fields = array(
				'if_term_not_found' => $this->csv_manager->if_term_not_found,
				'author' => $this->csv_manager->selected_user,
				'do_geocode' => $this->csv_manager->do_geocode,
		);
		if (get_option('w2dc_fsubmit_addon') && get_option('w2dc_claim_functionality')) {
			$add_template_fields['is_claimable'] = $this->csv_manager->is_claimable;
		}
		
		return array_merge($template_fields, $add_template_fields);
	}
	
	public function checkFields() {
		if ($this->csv_manager->import_type == 'update_listings' && !in_array('post_id', $this->csv_manager->collated_fields)) {
			$this->csv_manager->log['errors'][] = esc_attr__("Post ID field wasn't collated", 'W2DC');
		}
		if ($this->csv_manager->import_type == 'create_listings' && !in_array('title', $this->csv_manager->collated_fields)) {
			$this->csv_manager->log['errors'][] = esc_attr__("Title field wasn't collated", 'W2DC');
		}
		if ($this->csv_manager->import_type == 'create_listings' && !in_array('level_id', $this->csv_manager->collated_fields)) {
			$this->csv_manager->log['errors'][] = esc_attr__("Level ID field wasn't collated", 'W2DC');
		}
		if ($this->csv_manager->import_type == 'create_listings' && $this->csv_manager->selected_user != 0 && !get_userdata($this->csv_manager->selected_user)) {
			$this->csv_manager->log['errors'][] = esc_attr__("There isn't author user you selected", 'W2DC');
		}
		if ($this->csv_manager->import_type == 'create_listings' && $this->csv_manager->selected_user == 0 && !in_array('user', $this->csv_manager->collated_fields)) {
			$this->csv_manager->log['errors'][] = esc_attr__("Author field wasn't collated and default author wasn't selected", 'W2DC');
		}
	}
	
	public function processCSVImport() {
		global $wpdb, $w2dc_instance;
		
		$directories = $w2dc_instance->directories->directories_array;
		$directories_ids = array_keys($directories);
		
		$levels = $w2dc_instance->levels->levels_array;
		$levels_ids = array_keys($levels);
		
		$this->total_rejected_lines = 0;
		foreach ($this->csv_manager->rows as $line=>$row) {
			$n = $line+1;
			printf(__('Importing line %d...', 'W2DC'), $n);
			echo "<br />";
			$error_on_line = false;
			$listing_data = array();
			foreach ($this->csv_manager->collated_fields as $i=>$field) {
				$value = htmlspecialchars_decode(trim($row[$i])); // htmlspecialchars_decode() needed due to &amp; symbols in import files, ';' symbols can break import
		
				if ($field == 'post_id' && $this->csv_manager->import_type == 'update_listings') {
					if (($post = get_post($value)) && ($listing = w2dc_getListing($post))) {
						$listing_data['existing_listing'] = $listing;
						$listing_data['post_id'] = $value;
					} else {
						$error = sprintf(__('Error on line %d: ', 'W2DC') . esc_attr__("Listing with ID \"%d\" doesn't exist", 'W2DC'), $n, $value);
						$error_on_line = $this->csv_manager->setErrorOnLine($error);
					}
				}
		
				if ($field == 'title') {
					$listing_data['title'] = $value;
					printf(__('Listing title: %s', 'W2DC'), $value);
					echo "<br />";
				} elseif ($field == 'user') {
					if (!$this->csv_manager->selected_user) {
						$user_info = explode('>', $value);
						if (is_array($user_info) && !is_numeric($user_info[0]) && filter_var($user_info[1], FILTER_VALIDATE_EMAIL) && ($key = array_search($user_info[1], $this->csv_manager->users_emails)) !== FALSE) {
							// if it is existing user with format user_name>user@email.com
							$listing_data['user_id'] = $this->csv_manager->users_ids[$key];
						} elseif ((($key = array_search($value, $this->csv_manager->users_logins)) !== FALSE) || (($key = array_search($value, $this->csv_manager->users_emails)) !== FALSE) || (($key = array_search($value, $this->csv_manager->users_ids))) !== FALSE) {
							// if it is existing user by login, email or ID
							$listing_data['user_id'] = $this->csv_manager->users_ids[$key];
						} else {
							// it is new user
							if (!is_numeric($user_info[0]) && filter_var($user_info[1], FILTER_VALIDATE_EMAIL)) {
								$listing_data['user_info'] = $user_info;
							} else {
								$error = sprintf(__('Error on line %d: ', 'W2DC') . esc_attr__("User \"%s\" doesn't exist and format does not allow to create new user", 'W2DC'), $n, $value);
								$error_on_line = $this->csv_manager->setErrorOnLine($error);
							}
						}
					} else {
						$listing_data['user_id'] = $this->csv_manager->selected_user;
					}
				} elseif ($field == 'level_id') {
					if (in_array($value, $levels_ids)) {
						$listing_data['level_id'] = $value;
					} else {
						$error = sprintf(__('Error on line %d: ', 'W2DC') . __('Wrong level ID', 'W2DC'), $n);
						$error_on_line = $this->csv_manager->setErrorOnLine($error);
					}
				} elseif ($field == 'directory_id') {
					if (in_array($value, $directories_ids)) {
						$listing_data['directory_id'] = $value;
					} else {
						$error = sprintf(__('Error on line %d: ', 'W2DC') . __('Wrong directory ID', 'W2DC'), $n);
						$error_on_line = $this->csv_manager->setErrorOnLine($error);
					}
				} elseif ($field == 'content') {
					$listing_data['content'] = $value;
				} elseif ($field == 'excerpt') {
					$listing_data['excerpt'] = $value;
				} elseif ($field == 'categories_list') {
					$listing_data['categories'] = array_filter(array_map('trim', explode($this->csv_manager->values_separator, $value)));
				} elseif ($field == 'listing_tags') {
					$listing_data['tags'] = array_filter(array_map('trim', explode($this->csv_manager->values_separator, $value)));
				} elseif ($field == 'locations_list') {
					$listing_data['locations'] = array_map('trim', explode($this->csv_manager->values_separator, $value));
				} elseif ($field == 'address_line_1') {
					$listing_data['address_line_1'] = array_map('trim', explode($this->csv_manager->values_separator, $value));
				} elseif ($field == 'address_line_2') {
					$listing_data['address_line_2'] = array_map('trim', explode($this->csv_manager->values_separator, $value));
				} elseif ($field == 'zip') {
					$listing_data['zip'] = array_map('trim', explode($this->csv_manager->values_separator, $value));
				} elseif ($field == 'latitude') {
					$listing_data['latitude'] = array_map('trim', explode($this->csv_manager->values_separator, $value));
				} elseif ($field == 'longitude') {
					$listing_data['longitude'] = array_map('trim', explode($this->csv_manager->values_separator, $value));
				} elseif ($field == 'map_icon_file') {
					$listing_data['map_icon_file'] = array_map('trim', explode($this->csv_manager->values_separator, $value));
				} elseif ($field == 'additional_address_info') {
					$listing_data['additional_address_info'] = array_map('trim', explode($this->values_separator, $value));
				} elseif ($field == 'videos') {
					$listing_data['videos'] = array_filter(array_map('trim', explode($this->csv_manager->values_separator, $value)));
				} elseif ($field == 'images') {
					if ($this->csv_manager->images_dir) {
						$listing_data['images'] = array_filter(array_map('trim', explode($this->csv_manager->values_separator, $value)));
					} else {
						$images_value = array_filter(array_map('trim', explode($this->csv_manager->values_separator, $value)));
						$validation = new w2dc_form_validation();
						$this_is_import_by_URL = false;
						foreach ($images_value AS $image_url) {
							if ($validation->valid_url($image_url, false)) {
								$listing_data['images'][] = $image_url;
								$this_is_import_by_URL = true;
							} else {
								$error = sprintf(__('Error on line %d: ', 'W2DC') . sprintf(esc_attr__("Incorrect image URL %s", 'W2DC'), $image_url), $n);
								$error_on_line = $this->csv_manager->setErrorOnLine($error);
							}
						}
						if (!$this_is_import_by_URL) {
							$error = sprintf(__('Error on line %d: ', 'W2DC') . esc_attr__("Images column was specified, but ZIP archive wasn't upload", 'W2DC'), $n);
							$error_on_line = $this->csv_manager->setErrorOnLine($error);
						}
					}
				} elseif ($content_field = $w2dc_instance->content_fields->getContentFieldBySlug($field)) {
					if (is_a($content_field, 'w2dc_content_field_checkbox')) {
						if ($value = array_map('trim', explode($this->csv_manager->values_separator, $value))) {
							if (count($value) == 1) {
								$value = array_shift($value);
							}
						}
					} elseif (is_string($value)) {
						$value = trim($value);
					}
		
					if ($value !== false && $value !== "") {
						$errors = array();
						$listing_data['content_fields'][$field] = $content_field->validateCsvValues($value, $errors);
						foreach ($errors AS $_error) {
							$error = sprintf(__('Error on line %d: ', 'W2DC') . $_error, $n);
							$error_on_line = $this->csv_manager->setErrorOnLine($error);
						}
					}
				} elseif ($field == 'expiration_date') {
					if (!($timestamp = strtotime($value))) {
						$error = sprintf(__('Error on line %d: ', 'W2DC') . esc_attr__("Expiration date value is incorrect", 'W2DC'), $n);
						$error_on_line = $this->csv_manager->setErrorOnLine($error);
					} else
						$listing_data['expiration_date'] = $timestamp;
				} elseif ($field == 'contact_email') {
					if ($value) {
						if (!is_email($value)) {
							$error = sprintf(__('Error on line %d: ', 'W2DC') . esc_attr__("Contact email is incorrect", 'W2DC'), $n);
							$error_on_line = $this->csv_manager->setErrorOnLine($error);
						} else {
							$listing_data['contact_email'] = $value;
						}
					}
				} elseif (get_option('w2dc_fsubmit_addon') && get_option('w2dc_claim_functionality') && (($field == 'claimable' && $value) || $this->csv_manager->is_claimable)) {
					$listing_data['claimable'] = true;
				} elseif ($field == 'wpml_translation_source_id') {
					$listing_data['wpml_translation_source_id'] = $value;
				} elseif ($field == 'status') {
					if (in_array($value, array("active", "expired", "unpaid", "stopped"))) {
						$listing_data['status'] = $value;
					} elseif (in_array($value, array("publish", "private", "draft", "pending"))) {
						$listing_data['post_status'] = $value;
					} else {
						$error = sprintf(__('Error on line %d: ', 'W2DC') . esc_attr__("Listing status must be one of the following: active, expired, unpaid or stopped", 'W2DC'), $n);
						$error_on_line = $this->csv_manager->setErrorOnLine($error);
					}
				}
		
				$listing_data = apply_filters('w2dc_csv_process_fields', $listing_data, $field, $value);
			}
		
			if (!$error_on_line) {
				if (!$this->csv_manager->test_mode) {
					if ($this->csv_manager->import_type == 'create_listings') {
						$listing_data_level = $levels[$listing_data['level_id']];
						
						if (isset($listing_data['post_status'])) {
							$post_status = $listing_data['post_status'];
						} else {
							$post_status = "publish";
						}
		
						$new_post_args = array(
								'post_title' => $listing_data['title'],
								'post_type' => W2DC_POST_TYPE,
								'post_author' => $this->csv_manager->processUser($listing_data, $n),
								'post_status' => $post_status,
								'post_content' => (isset($listing_data['content']) ? $listing_data['content'] : ''),
								'post_excerpt' => (isset($listing_data['excerpt']) ? $listing_data['excerpt'] : ''),
						);
						$new_post_id = wp_insert_post($new_post_args);
		
						if (isset($listing_data['directory_id'])) {
							$directory_id = $listing_data['directory_id'];
						} else {
							$directory_id = $w2dc_instance->directories->getDefaultDirectory()->id;
						}
						add_post_meta($new_post_id, '_directory_id', $directory_id);
		
						$wpdb->query($wpdb->prepare("INSERT INTO {$wpdb->w2dc_levels_relationships} (post_id, level_id) VALUES(%d, %d) ON DUPLICATE KEY UPDATE level_id=%d", $new_post_id, $listing_data_level->id, $listing_data_level->id));
		
						add_post_meta($new_post_id, '_listing_created', true);
						add_post_meta($new_post_id, '_order_date', time());
						if (isset($listing_data['status'])) {
							$status = $listing_data['status'];
						} else {
							$status = 'active';
						}
						add_post_meta($new_post_id, '_listing_status', $status);
		
						if (!$listing_data_level->eternal_active_period) {
							$expiration_date = w2dc_calcExpirationDate(current_time('timestamp'), $listing_data_level);
							add_post_meta($new_post_id, '_expiration_date', $expiration_date);
						}
		
						if (isset($listing_data['locations'])) {
							$this->processDirectoryLocations($listing_data, $n);
						}
		
						if (isset($listing_data['locations_ids']) || isset($listing_data['address_line_1']) || (isset($listing_data['latitude']) && isset($listing_data['longitude']))) {
							$this->processListingLocations($new_post_id, $listing_data, $listing_data_level, $n);
						}
		
						if (isset($listing_data['categories'])) {
							$this->processCategories($new_post_id, $listing_data, $n);
						}
		
						if (isset($listing_data['tags'])) {
							$this->processTags($new_post_id, $listing_data, $n);
						}
		
						if (isset($listing_data['content_fields'])) {
							$this->processContentFields($new_post_id, $listing_data, $n);
						}
		
						if (isset($listing_data['images'])) {
							$this->csv_manager->processImages($new_post_id, $listing_data, $n);
						}
		
						if (isset($listing_data['videos'])) {
							$this->processVideos($new_post_id, $listing_data, $n);
						}
		
						if (isset($listing_data['expiration_date'])) {
							update_post_meta($new_post_id, '_expiration_date', $listing_data['expiration_date']);
						}
		
						if (isset($listing_data['contact_email'])) {
							add_post_meta($new_post_id, '_contact_email', $listing_data['contact_email']);
						}
		
						if (isset($listing_data['claimable'])) {
							add_post_meta($new_post_id, '_is_claimable', true);
						}
		
						if (isset($listing_data['wpml_translation_source_id'])) {
							$this->assignTranslation($new_post_id, $listing_data, $n);
						}
		
						do_action('w2dc_csv_create_listing', $new_post_id, $listing_data);
					} elseif ($this->csv_manager->import_type == 'update_listings') {
						// -------------------- Update existing listing by ID ------------------------------------------------------------------------------------------------------------------
						$existing_post_id = $listing_data['post_id'];
		
						if (isset($listing_data['directory_id'])) {
							$directory_id = $listing_data['directory_id'];
							update_post_meta($existing_post_id, '_directory_id', $directory_id);
						}
		
						if (isset($listing_data['level_id'])) {
							$listing_data_level = $levels[$listing_data['level_id']];
		
							$wpdb->query($wpdb->prepare("UPDATE {$wpdb->w2dc_levels_relationships} SET level_id=%d WHERE post_id=%d", $listing_data_level->id, $existing_post_id));
						} else {
							$listing_data_level = $listing_data['existing_listing']->level;
						}
		
						if (isset($listing_data['status'])) {
							update_post_meta($existing_post_id, '_listing_status', $listing_data['status']);
						}
		
						$existing_post_args = array(
								'ID' => $existing_post_id,
						);
						if (isset($listing_data['post_status'])) {
							$existing_post_args['post_status'] = $listing_data['post_status'];
						}
						if (isset($listing_data['user_id']) || isset($listing_data['user_info']) || $this->csv_manager->selected_user) {
							$existing_post_args['post_author'] = $this->csv_manager->processUser($listing_data, $n);
						}
						if (isset($listing_data['title'])) {
							$existing_post_args['post_title'] = $listing_data['title'];
						}
						if (isset($listing_data['content'])) {
							$existing_post_args['post_content'] = $listing_data['content'];
						}
						if (isset($listing_data['excerpt'])) {
							$existing_post_args['post_excerpt'] = $listing_data['excerpt'];
						}
						wp_update_post($existing_post_args);
		
						if (isset($listing_data['locations'])) {
							$this->processDirectoryLocations($listing_data, $n);
						}
		
						if (isset($listing_data['locations_ids']) || isset($listing_data['address_line_1']) || (isset($listing_data['latitude']) && isset($listing_data['longitude']))) {
							$this->processListingLocations($existing_post_id, $listing_data, $listing_data_level, $n);
						}
		
						if (isset($listing_data['categories'])) {
							wp_set_object_terms($existing_post_id, array(), W2DC_CATEGORIES_TAX);
		
							$this->processCategories($existing_post_id, $listing_data, $n);
						}
		
						if (isset($listing_data['tags'])) {
							wp_set_object_terms($existing_post_id, array(), W2DC_TAGS_TAX);
		
							$this->processTags($existing_post_id, $listing_data, $n);
						}
		
						if (isset($listing_data['content_fields'])) {
							$this->processContentFields($existing_post_id, $listing_data, $n);
						}
		
						if (isset($listing_data['images'])) {
							wp_delete_attachment($existing_post_id);
							delete_post_meta($existing_post_id, '_attached_image');
		
							$this->csv_manager->processImages($existing_post_id, $listing_data, $n);
						}
		
						if (isset($listing_data['videos'])) {
							delete_post_meta($existing_post_id, '_attached_video_id');
								
							$this->processVideos($existing_post_id, $listing_data, $n);
						}
		
						if (isset($listing_data['expiration_date'])) {
							delete_post_meta($existing_post_id, '_expiration_date');
								
							update_post_meta($existing_post_id, '_expiration_date', $listing_data['expiration_date']);
						}
		
						if (isset($listing_data['contact_email'])) {
							delete_post_meta($existing_post_id, '_contact_email');
		
							add_post_meta($existing_post_id, '_contact_email', $listing_data['contact_email']);
						}
		
						if (isset($listing_data['claimable'])) {
							if ($listing_data['claimable'])
								add_post_meta($existing_post_id, '_is_claimable', true);
							else
								add_post_meta($existing_post_id, '_is_claimable', false);
						}
		
						if (isset($listing_data['wpml_translation_source_id'])) {
							$this->assignTranslation($existing_post_id, $listing_data, $n);
						}
		
						do_action('w2dc_csv_update_listing', $existing_post_id, $listing_data);
					}
					wp_cache_flush();
				}
			} else {
				$this->total_rejected_lines++;
			}
		}
	}
	
	public function processDirectoryLocations(&$listing_data, $line_n) {
		foreach ($listing_data['locations'] as $location_item) {
			if (!is_numeric($location_item)) {
				$locations_chain = array_filter(array_map('trim', explode('>', $location_item)));
				$listing_term_id = 0;
				foreach ($locations_chain as $key => $location_name) {
					if (is_numeric($location_name)) {
						$location_name = intval($location_name);
					}
					if ($term = term_exists(htmlspecialchars($location_name), W2DC_LOCATIONS_TAX, $listing_term_id)) { // htmlspecialchars() needed due to &amp; symbols in import files
						$term_id = intval($term['term_id']);
						$listing_term_id = $term_id;
					} else {
						if ($this->csv_manager->if_term_not_found == 'create') {
							if ($newterm = wp_insert_term($location_name, W2DC_LOCATIONS_TAX, array('parent' => $listing_term_id))) {
								if (!is_wp_error($newterm)) {
									$term_id = intval($newterm['term_id']);
									$listing_term_id = $term_id;
								} else {
									$error = sprintf(__('Error on line %d: ', 'W2DC') . __('Something went wrong with directory location "%s"', 'W2DC'), $line_n, $location_name);
									$error_on_line = $this->csv_manager->setErrorOnLine($error);
								}
							}
						} else {
							$error = sprintf(__('Error on line %d: ', 'W2DC') . esc_attr__("Directory location \"%s\" wasn't found, was skipped", 'W2DC'), $line_n, $location_name);
							$error_on_line = $this->csv_manager->setErrorOnLine($error);
						}
					}
				}
				if ($listing_term_id)
					$listing_data['locations_ids'][] = $listing_term_id;
			} elseif (get_term($location_item, W2DC_LOCATIONS_TAX)) {
				$listing_data['locations_ids'][] = $location_item;
			} else {
				$error = sprintf(__('Error on line %d: ', 'W2DC') . esc_attr__("Directory location with ID \"%d\" wasn't found", 'W2DC'), $line_n, $location_item);
				$error_on_line = $this->csv_manager->setErrorOnLine($error);
			}
		}
	}
	
	public function geocodeLocationsProcess() {
		global $wpdb;
		
		$results = $wpdb->get_results("SELECT id, location_id, address_line_1, address_line_2, zip_or_postal_index  FROM {$wpdb->w2dc_locations_relationships}", ARRAY_A);
	
		printf(esc_html__("Found locations: %s", "W2DC"), count($results));
		echo "<br />";
		
		foreach ($results AS $row) {
			
			$location_string = '';
			
			if ($row['location_id']) {
				$chain = array();
				$parent_id = $row['location_id'];
				while ($parent_id != 0) {
					if ($term = get_term($parent_id, W2DC_LOCATIONS_TAX)) {
						$chain[] = $term->name;
						$parent_id = $term->parent;
					} else
						$parent_id = 0;
				}
				$location_string = implode(', ', $chain);
			}
			if ($row['address_line_1']) {
				$location_string = $row['address_line_1'] . ' ' . $location_string;
			}
			if ($row['address_line_2']) {
				$location_string = $row['address_line_2'] . ', ' . $location_string;
			}
			if ($row['zip_or_postal_index']) {
				$location_string = $location_string . ' ' . $row['zip_or_postal_index'];
			}
			if (get_option('w2dc_default_geocoding_location')) {
				$location_string = $location_string . ' ' . get_option('w2dc_default_geocoding_location');
			}
			
			if ($location_string) {
				printf(__('Geocoding address: %s', 'W2DC'), $location_string);
				echo "<br />";
				
				$geoname = new w2dc_locationGeoname ;
				$result = $geoname->geocodeRequest($location_string, 'coordinates');
				if (!is_wp_error($result) && is_array($result)) {
					$location_data = array(
							'map_coords_1' 	=> $result[1],
							'map_coords_2' 	=> $result[0],
							'place_id' 		=> $result[2],
					);
					
					$wpdb->update($wpdb->w2dc_locations_relationships, $location_data, array('id' => $row['id']));
				} else {
					printf(__('Following address can not be geocoded: %s. Status: %s, error: %s', 'W2DC'), $location_string, $geoname->getLastStatus(), $geoname->getLastError());
					echo "<br />";
				}
			}
		}
	}
	
	public function processListingLocations($post_id, &$listing_data, $listing_data_level, $line_n) {
		global $w2dc_instance;
	
		if (!empty($listing_data['locations_ids'])) {
			$locations_items = $listing_data['locations_ids'];
		} elseif (!empty($listing_data['address_line_1'])) {
			$locations_items = $listing_data['address_line_1'];
		} elseif (!empty($listing_data['longitude']) && !empty($listing_data['latitude'])) {
			$locations_items = $listing_data['longitude'];
		}
	
		$locations_args = array();
		foreach ($locations_items AS $key=>$location_item) {
			if ($this->csv_manager->do_geocode) {
				$location_string = '';
				if (isset($listing_data['locations_ids'][$key])) {
					$chain = array();
					$parent_id = $listing_data['locations_ids'][$key];
					while ($parent_id != 0) {
						if ($term = get_term($parent_id, W2DC_LOCATIONS_TAX)) {
							$chain[] = $term->name;
							$parent_id = $term->parent;
						} else
							$parent_id = 0;
					}
					$location_string = implode(', ', $chain);
				}
				if (isset($listing_data['address_line_1'][$key]))
					$location_string = $listing_data['address_line_1'][$key] . ' ' . $location_string;
				if (isset($listing_data['address_line_2'][$key]))
					$location_string = $listing_data['address_line_2'][$key] . ', ' . $location_string;
				if (isset($listing_data['zip'][$key]))
					$location_string = $location_string . ' ' . $listing_data['zip'][$key];
				if (get_option('w2dc_default_geocoding_location'))
					$location_string = $location_string . ' ' . get_option('w2dc_default_geocoding_location');
	
				$location_string = trim($location_string);
				
				printf(__('Geocoding address: %s', 'W2DC'), $location_string);
				echo "<br />";
	
				$geoname = new w2dc_locationGeoname ;
				$result = $geoname->geocodeRequest($location_string, 'coordinates');
				if (!is_wp_error($result) && is_array($result)) {
					$listing_data['longitude'][$key] = $result[0];
					$listing_data['latitude'][$key] = $result[1];
					$listing_data['place_id'][$key] = $result[2];
				} else {
					printf(__('Following address can not be geocoded: %s. Status: %s, error: %s', 'W2DC'), $location_string, $geoname->getLastStatus(), $geoname->getLastError());
					echo "<br />";
				}
				
				$locations_args['manual_coords[]'][] = 0;
			} else {
				if (isset($listing_data['latitude'][$key]) && isset($listing_data['longitude'][$key])) {
					$locations_args['manual_coords[]'][] = 1;
				} else {
					$locations_args['manual_coords[]'][] = 0;
				}
			}
	
			$locations_args['w2dc_location[]'][] = 1;
			$locations_args['selected_tax[]'][] = (isset($listing_data['locations_ids'][$key]) ? $listing_data['locations_ids'][$key] : 0);
			$locations_args['place_id[]'][] = (isset($listing_data['place_id'][$key]) ? $listing_data['place_id'][$key] : '');
			$locations_args['address_line_1[]'][] = (isset($listing_data['address_line_1'][$key]) ? $listing_data['address_line_1'][$key] : '');
			$locations_args['address_line_2[]'][] = (isset($listing_data['address_line_2'][$key]) ? $listing_data['address_line_2'][$key] : '');
			$locations_args['zip_or_postal_index[]'][] = (isset($listing_data['zip'][$key]) ? $listing_data['zip'][$key] : '');
	
			$locations_args['map_coords_1[]'][] = (isset($listing_data['latitude'][$key]) ? $listing_data['latitude'][$key] : '');
			$locations_args['map_coords_2[]'][] = (isset($listing_data['longitude'][$key]) ? $listing_data['longitude'][$key] : '');
			$locations_args['map_zoom'] = get_option('w2dc_default_map_zoom');
			$locations_args['map_icon_file[]'][] = (isset($listing_data['map_icon_file'][$key]) ? $listing_data['map_icon_file'][$key] : '');
			$locations_args['additional_info[]'][] = (isset($listing_data['additional_address_info'][$key]) ? $listing_data['additional_address_info'][$key] : '');
		}
		$args = apply_filters('w2dc_csv_save_location_args', $locations_args, $post_id, $listing_data);
	
		$w2dc_instance->locations_manager->saveLocations($listing_data_level, $post_id, $locations_args);
	}
	
	public function processCategories($post_id, &$listing_data, $line_n) {
		foreach ($listing_data['categories'] as $category_item) {
			$categories_chain = array_filter(array_map('trim', explode('>', $category_item)));
			$listing_term_id = 0;
			foreach ($categories_chain as $key => $category_name) {
				if (is_numeric($category_name)) {
					$category_name = intval($category_name);
				}
				if ($term = term_exists(htmlspecialchars($category_name), W2DC_CATEGORIES_TAX, $listing_term_id)) { // htmlspecialchars() needed due to &amp; symbols in import files
					$term_id = intval($term['term_id']);
					$listing_term_id = $term_id;
				} else {
					if ($this->csv_manager->if_term_not_found == 'create') {
						if ($newterm = wp_insert_term($category_name, W2DC_CATEGORIES_TAX, array('parent' => $listing_term_id)))
						if (!is_wp_error($newterm)) {
							$term_id = intval($newterm['term_id']);
							$listing_term_id = $term_id;
						} else {
							$error = sprintf(__('Error on line %d: ', 'W2DC') . __('Something went wrong with directory category "%s"', 'W2DC'), $line_n, $category_name);
							$error_on_line = $this->csv_manager->setErrorOnLine($error);
						}
					} else {
						$error = sprintf(__('Error on line %d: ', 'W2DC') . esc_attr__("Directory category \"%s\" wasn't found, was skipped", 'W2DC'), $line_n, $category_name);
						$error_on_line = $this->csv_manager->setErrorOnLine($error);
					}
				}
			}
			if ($listing_term_id)
				$listing_data['categories_ids'][] = $listing_term_id;
		}
		if (isset($listing_data['categories_ids']))
			wp_set_object_terms($post_id, $listing_data['categories_ids'], W2DC_CATEGORIES_TAX);
	}
	
	public function processTags($post_id, &$listing_data, $line_n) {
		foreach ($listing_data['tags'] as $tag_name) {
			if (is_numeric($tag_name)) {
				$tag_name = intval($tag_name);
			}
			if ($term = term_exists(htmlspecialchars($tag_name), W2DC_TAGS_TAX)) { // htmlspecialchars() needed due to &amp; symbols in import files
				$listing_data['tags_ids'][] = intval($term['term_id']);
			} else {
				if ($this->csv_manager->if_term_not_found == 'create') {
					if ($newterm = wp_insert_term($tag_name, W2DC_TAGS_TAX))
					if (!is_wp_error($newterm))
						$listing_data['tags_ids'][] = intval($newterm['term_id']);
					else {
						$error = sprintf(__('Error on line %d: ', 'W2DC') . __('Something went wrong with directory tag "%s"', 'W2DC'), $line_n, $tag_name);
						$error_on_line = $this->csv_manager->setErrorOnLine($error);
					}
				} else {
					$error = sprintf(__('Error on line %d: ', 'W2DC') . esc_attr__("Directory tag \"%s\" wasn't found, was skipped", 'W2DC'), $line_n, $tag_name);
					$error_on_line = $this->csv_manager->setErrorOnLine($error);
				}
			}
		}
		if (isset($listing_data['tags_ids']))
			wp_set_object_terms($post_id, $listing_data['tags_ids'], W2DC_TAGS_TAX);
	}
	
	public function processContentFields($post_id, &$listing_data, $line_n) {
		global $w2dc_instance;
	
		foreach ($listing_data['content_fields'] AS $field=>$values) {
			$content_field = $w2dc_instance->content_fields->getContentFieldBySlug($field);
			$content_field->saveValue($post_id, $values);
		}
	}
	
	public function processVideos($post_id, &$listing_data, $line_n) {
		$validation = new w2dc_form_validation();
		foreach ($listing_data['videos'] AS $video_item) {
			$video_id = null;
			if ($validation->valid_url($video_item, false)) {
				preg_match("#(?<=v=)[a-zA-Z0-9-]+(?=&)|(?<=v\/)[^&\n]+(?=\?)|(?<=v=)[^&\n]+|(?<=youtu.be/)[^&\n]+#", $video_item, $matches_youtube);
				preg_match("#(https?:\/\/)?(www\.)?(player\.)?vimeo\.com\/([a-z]*\/)*([вЂЊвЂ‹0-9]{6,11})[?]?.*#", $video_item, $matches_vimeo);
				if (isset($matches_youtube[0]) && strlen($matches_youtube[0]) == 11)
					$video_id = $matches_youtube[0];
				elseif (isset($matches_vimeo[5]) && strlen($matches_vimeo[5]) == 9) {
					$video_id = $matches_vimeo[5];
				} else {
					$error = sprintf(__('Error on line %d: ', 'W2DC') . esc_attr__("YouTube or Vimeo video URL is incorrect", 'W2DC'), $line_n);
					$error_on_line = $this->csv_manager->setErrorOnLine($error);
				}
			} else
				$video_id = $video_item;
			if ($video_id)
				add_post_meta($post_id, '_attached_video_id', $video_id);
		}
	}
	
	public function assignTranslation($post_id, &$listing_data, $line_n) {
		// adapted for WPML
		global $sitepress, $wpdb;
		if (function_exists('wpml_object_id_filter') && $sitepress) {
			$source_post_id = $listing_data['wpml_translation_source_id'];
			$lang = ICL_LANGUAGE_CODE;

			if ($trid = $sitepress->get_element_trid($source_post_id, 'post_w2dc_listing')) {
				$sql = "DELETE FROM wp_icl_translations
						WHERE trid = '{$trid}' AND
						language_code = '{$lang}' AND
						element_type='post_w2dc_listing'";
				$wpdb->query($sql);
				
				$sql = "UPDATE wp_icl_translations SET
						trid = '{$trid}',
						language_code = '{$lang}'
						WHERE element_id = '{$post_id}' AND
						element_type='post_w2dc_listing'";
				$wpdb->query($sql);
			}
		}
	}
	
	public function csvExport($number, $offset) {
		global $w2dc_instance;
		
		$csv_columns = array(
				'post_id',
				'title',
				'level_id',
				'directory_id',
				'status',
				'user',
				'description',
				'excerpt',
				'categories',
				'locations',
				'place_id',
				'address_line_1',
				'address_line_2',
				'zip',
				'latitude',
				'longitude',
				'map_icon_file',
				'additional_info',
				'tags',
				'images',
				'videos',
				'expiration_date',
				'contact_email',
				'claimable',
		);
		
		foreach ($w2dc_instance->content_fields->content_fields_array AS $field)
		if (!$field->is_core_field)
			$csv_columns[] = $field->slug;
		
		$csv_output[] = $csv_columns;
		
		$args = array(
				'post_type' => W2DC_POST_TYPE,
				'orderby' => 'ID',
				'order' => 'ASC',
				'post_status' => 'publish,private,draft,pending',
				'posts_per_page' => $number,
				'offset' => $offset,
		);
		
		$args = apply_filters("w2dc_csv_export_args", $args);
		
		$query = new WP_Query($args);
		$this->export_rows_counter = 0;
		while ($query->have_posts()) {
			$this->export_rows_counter++;
			$query->the_post();
			$post = get_post();
			$listing = w2dc_getListing($post);
				
			$listing_id = $listing->post->ID;
				
			$categories = array();
			$categories_objects = wp_get_object_terms($listing_id, W2DC_CATEGORIES_TAX);
			foreach ($categories_objects AS $category) {
				$listing_categories = w2dc_get_term_parents($category->term_id, W2DC_CATEGORIES_TAX, false, true);
				$categories[] = implode(">", $listing_categories);
			}
		
			$tags = array();
			$tags_objects = wp_get_object_terms($listing_id, W2DC_TAGS_TAX);
			foreach ($tags_objects AS $tag) {
				$tags[] = $tag->name;
			}
				
			$selected_location = array();
			$place_id = array();
			$address_line_1 = array();
			$address_line_2 = array();
			$zip = array();
			$map_coords_1 = array();
			$map_coords_2 = array();
			$map_icon_file = array();
			$additional_info = array();
			foreach ($listing->locations AS $location) {
				if ($location->selected_location) {
					$listing_locations = w2dc_get_term_parents($location->selected_location, W2DC_LOCATIONS_TAX, false, true);
					$selected_location[] = implode(">", $listing_locations);
				} else {
					$selected_location[] = '';
				}
		
				$place_id[] = ($location->place_id) ? $location->place_id : '';
				$address_line_1[] = ($location->address_line_1) ? $location->address_line_1 : '';
				$address_line_2[] = ($location->address_line_2) ? $location->address_line_2 : '';
				$zip[] = ($location->zip_or_postal_index) ? $location->zip_or_postal_index : '';
				$map_coords_1[] = ($location->map_coords_1) ? $location->map_coords_1 : '';
				$map_coords_2[] = ($location->map_coords_2) ? $location->map_coords_2 : '';
				$map_icon_file[] = ($location->map_icon_file) ? $location->map_icon_file : '';
				$additional_info[] = ($location->additional_info) ? $location->additional_info : '';
			}
				
			$images = array();
			foreach ($listing->images AS $attachment_id=>$image) {
				$image_src = wp_get_attachment_image_src($attachment_id, 'full');
				$image_item = basename($image_src[0]);
				if ($image['post_title']) {
					$image_item .= ">" . $image['post_title'];
				}
				$images[] = $image_item;
			}
				
			$videos = array();
			foreach ($listing->videos AS $video) {
				$videos[] = $video['id'];
			}
		
			$row = array(
					$listing_id,
					$listing->title(),
					$listing->level->id,
					$listing->directory->id,
					$listing->status,
					$listing->post->post_author,
					$listing->post->post_content,
					$listing->post->post_excerpt,
					implode(';', $categories),
					implode(';', $selected_location),
					implode(';', $place_id),
					implode(';', $address_line_1),
					implode(';', $address_line_2),
					implode(';', $zip),
					implode(';', $map_coords_1),
					implode(';', $map_coords_2),
					implode(';', $map_icon_file),
					implode(';', $additional_info),
					implode(';', $tags),
					implode(';', $images),
					implode(';', $videos),
					((!$listing->level->eternal_active_period && $listing->expiration_date) ?  date('d.m.Y H:i', $listing->expiration_date) : ''),
					get_post_meta($listing_id, '_contact_email', true),
					get_post_meta($listing_id, '_is_claimable', true),
			);
				
			foreach ($w2dc_instance->content_fields->content_fields_array AS $field) {
				if (!$field->is_core_field) {
					if (isset($listing->content_fields[$field->id])) {
						$row[] = $listing->content_fields[$field->id]->exportCSV();
					} else {
						$row[] = '';
					}
				}
			}
		
			$csv_output[] = $row;
		}
		
		$csv_output = apply_filters("w2dc_csv_export_output", $csv_output);
		
		return $csv_output;
	}
	
	public function csvExportFileName() {
		return 'w2dc-listings--' . date('Y-m-d_H_i_s') . '--' . $this->export_rows_counter . '.csv';
	}
}

/*
 * 
 * Example on how to add columns in CSV output

add_filter("w2dc_csv_export_output", "w2dc_csv_export_output_add_columns");
function w2dc_csv_export_output_add_columns($csv_output) {
	
	$csv_output[0][] = "total_clicks";
	
	foreach ($csv_output AS $key=>$row) {
		
		$post_id = $row[0];
		$total_clicks = get_post_meta($post_id, '_total_clicks', true);
		
		$csv_output[$key][] = $total_clicks;
	}
	
	return $csv_output;
} */

?>