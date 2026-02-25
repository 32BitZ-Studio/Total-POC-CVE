<?php 

class w2dc_listing extends w2dc_post {
	public $post;
	public $directory;
	public $level;
	public $expiration_date;
	public $order_date;
	public $listing_created = false;
	public $status; // active, expired, unpaid, stopped
	public $categories = array();
	public $locations = array();
	public $content_fields = array();
	public $map_zoom;
	public $logo_image;
	public $images = array();
	public $videos = array();
	public $map;
	public $is_claimable;
	public $claim;
	public $logo_animation_effect;
	public $contact_email;
	public $avg_rating;

	public function __construct($level_id = null) {
		if ($level_id) {
			// New listing
			$this->setLevelByID($level_id);
		}
	}
	
	// Load existed listing
	public function loadListingFromPost($post) {
		if (!$post) {
			return false;
		}
		
		if ($this->setPost($post)) {
			if ($this->post->post_type == W2DC_POST_TYPE) {
				if ($this->setLevelByPostId()) {
					$this->setMetaInformation();
					$this->setLocations();
					$this->setContentFields();
					$this->setMapZoom();
					$this->setMedia();
					$this->setClaiming();
					
					apply_filters('w2dc_listing_loading', $this);
		
					return true;
				}
			}
		}
	}

	public function setLevelByID($level_id) {
		global $w2dc_instance;

		$levels = $w2dc_instance->levels;
		if ($level = $levels->getLevelById($level_id)) {
			$this->level = $level;
		}
	}
	
	public function setMetaInformation() {
		if (!$this->level->eternal_active_period)
			$this->expiration_date = get_post_meta($this->post->ID, '_expiration_date', true);

		$this->order_date = get_post_meta($this->post->ID, '_order_date', true);

		$this->status = get_post_meta($this->post->ID, '_listing_status', true);

		$this->listing_created = get_post_meta($this->post->ID, '_listing_created', true);

		if (get_option('w2dc_listing_contact_form') && get_option('w2dc_custom_contact_email')) {
			$this->contact_email = get_post_meta($this->post->ID, '_contact_email', true);
		}
		
		$this->contact_email = apply_filters('w2dc_listing_contact_email', $this->contact_email);

		return $this->expiration_date;
	}

	public function setLevelByPostId($post_id = null) {
		global $w2dc_instance, $wpdb;

		if (!$post_id) {
			$post_id = $this->post->ID;
		}
		
		if (($directory_id = get_post_meta($post_id, '_directory_id', true)) && ($directory = $w2dc_instance->directories->getDirectoryById($directory_id))) {
			$this->directory = $directory;
		} else {
			$this->directory = $w2dc_instance->directories->getDefaultDirectory();
		}

		if ($level_id = $wpdb->get_var("SELECT level_id FROM {$wpdb->w2dc_levels_relationships} WHERE post_id=" . $post_id)) {
			$this->level = $w2dc_instance->levels->getLevelById($level_id);
		}
		if (!$this->level) {
			$this->level = $w2dc_instance->levels->getDefaultLevel();
		}

		return $this->level;
	}

	public function setLocations() {
		global $wpdb;

		$results = $wpdb->get_results("SELECT * FROM {$wpdb->w2dc_locations_relationships} WHERE post_id=".$this->post->ID, ARRAY_A);
		
		if ($this->level->map) {
			$listing_categories = wp_get_object_terms($this->post->ID, W2DC_CATEGORIES_TAX, array('orderby' => 'name'));
			$current_category = w2dc_getCurrentCategory();
			
			// try to reorder $listing_categories array to get current category on the 1st place
			if ($current_category && $listing_categories) {
				$categories = array();
				
				foreach ($listing_categories AS $category_obj) {
					if ($category_obj->term_id == $current_category->term_id) {
						$categories[] = $category_obj;
						break;
					}
				}
				foreach ($listing_categories AS $category_obj) {
					if ($category_obj->term_id != $current_category->term_id) {
						$categories[] = $category_obj;
					}
				}
			} else {
				$categories = $listing_categories;
			}
		}
		
		foreach ($results AS $row) {
			if ($row['location_id'] || $row['map_coords_1'] != '0.000000' || $row['map_coords_2'] != '0.000000' || $row['address_line_1'] || $row['zip_or_postal_index']) {
				$location = new w2dc_location($this->post->ID);
				$location_settings = array(
						'id' 					=> $row['id'],
						'selected_location' 	=> $row['location_id'],
						'place_id' 				=> $row['place_id'],
						'address_line_1' 		=> $row['address_line_1'],
						'address_line_2' 		=> $row['address_line_2'],
						'zip_or_postal_index' 	=> $row['zip_or_postal_index'],
						'additional_info' 		=> $row['additional_info'],
				);
				if ($this->level->map) {
					$location_settings['manual_coords'] = w2dc_getValue($row, 'manual_coords');
					$location_settings['map_coords_1'] = w2dc_getValue($row, 'map_coords_1');
					$location_settings['map_coords_2'] = w2dc_getValue($row, 'map_coords_2');
					if (get_option('w2dc_map_markers_type') == 'images') {
						// PNG files here
						if (($marker = w2dc_getValue($row, 'map_icon_file')) && $this->level->map_markers && strpos($marker, 'w2dc-fa-') === false) {
							// exact marker was selected
							$location_settings['map_icon_file'] = $marker;
							$location_settings['map_icon_manually_selected'] = true;
						} else {
							$location_settings['map_icon_manually_selected'] = false;
							// search in categories
							if ($categories) {
								$images = get_option('w2dc_categories_marker_images');
								$image_found = false;
								foreach ($categories AS $category_obj) {
									if (!$image_found && isset($images[$category_obj->term_id])) {
										$location_settings['map_icon_file'] = $images[$category_obj->term_id];
										$image_found = true;
									}
									if ($image_found)
										break;
									if ($parent_categories = w2dc_get_term_parents_ids($category_obj->term_id, W2DC_CATEGORIES_TAX)) {
										foreach ($parent_categories AS $parent_category_id) {
											if (!$image_found && isset($images[$parent_category_id])) {
												$location_settings['map_icon_file'] = $images[$parent_category_id];
												$image_found = true;
											}
											if ($image_found) {
												break;
												break;
											}
										}
									}
								}
							}
						}
					} else {
						// in FA icons we can work with color of the marker markup
						$marker = w2dc_getValue($row, 'map_icon_file');
						if ($marker && in_array($marker, w2dc_get_fa_icons_names()) && $this->level->map_markers) {
							// exact marker was selected
							$location_settings['map_icon_file'] = $marker;
							$location_settings['map_icon_manually_selected'] = true;
							// search in categories
							if ($categories) {
								$colors = get_option('w2dc_categories_marker_colors');
								$color_found = false;
								foreach ($categories AS $category_obj) {
									if (!$color_found && isset($colors[$category_obj->term_id])) {
										$location_settings['map_icon_color'] = $colors[$category_obj->term_id];
										$color_found = true;
									}
									if ($color_found)
										break;
									if ($parent_categories = w2dc_get_term_parents_ids($category_obj->term_id, W2DC_CATEGORIES_TAX)) {
										foreach ($parent_categories AS $parent_category_id) {
											if (!$color_found && isset($colors[$parent_category_id])) {
												$location_settings['map_icon_color'] = $colors[$parent_category_id];
												$color_found = true;
											}
											if ($color_found) {
												break;
												break;
											}
										}
									}
								}
							}
						} else {
							$location_settings['map_icon_manually_selected'] = false;
							if ($categories) {
								$icons = get_option('w2dc_categories_marker_icons');
								$colors = get_option('w2dc_categories_marker_colors');
								$icon_found = false;
								$color_found = false;
								// search in categories
								foreach ($categories AS $category_obj) {
									if (!$icon_found && isset($icons[$category_obj->term_id])) {
										$location_settings['map_icon_file'] = $icons[$category_obj->term_id];
										$icon_found = true;
									}
									if (!$color_found && isset($colors[$category_obj->term_id])) {
										$location_settings['map_icon_color'] = $colors[$category_obj->term_id];
										$color_found = true;
									}
									if ($icon_found && $color_found)
										break;
									if ($parent_categories = w2dc_get_term_parents_ids($category_obj->term_id, W2DC_CATEGORIES_TAX)) {
										foreach ($parent_categories AS $parent_category_id) {
											if (!$icon_found && isset($icons[$parent_category_id])) {
												$location_settings['map_icon_file'] = $icons[$parent_category_id];
												$icon_found = true;
											}
											if (!$color_found && isset($colors[$parent_category_id])) {
												$location_settings['map_icon_color'] = $colors[$parent_category_id];
												$color_found = true;
											}
											if ($icon_found && $color_found) {
												break;
												break;
											}
										}
									}
									// icon from one category and color from another - this would be bad idea
									if ($icon_found || $color_found)
										break;
								}
							}
						}
					}
				}
				
				$location_settings = apply_filters('w2dc_listing_locations', $location_settings, $this);
				
				$location->createLocationFromArray($location_settings);
				
				$this->locations[] = $location;
			}
		}
	}

	public function setMapZoom() {
		if (!$this->map_zoom = get_post_meta($this->post->ID, '_map_zoom', true))
			$this->map_zoom = get_option('w2dc_default_map_zoom');
	}

	public function setContentFields() {
		global $w2dc_instance;

		$post_categories_ids = wp_get_post_terms($this->post->ID, W2DC_CATEGORIES_TAX, array('fields' => 'ids'));
		$this->content_fields = $w2dc_instance->content_fields->loadValues($this->post->ID, $post_categories_ids, $this->level->id);
		
		$this->content_fields = apply_filters('w2dc_listing_content_fields', $this->content_fields, $this);
	}
	
	public function setMedia() {
		if ($this->level->images_number) {
			if ($images = get_post_meta($this->post->ID, '_attached_image')) {
				if ($images_order = explode(',', get_post_meta($this->post->ID, '_attached_images_order', true))) {
					$images = array_flip(array_replace(array_flip(array_unique(array_filter($images_order))), array_flip($images)));
				}
				foreach ($images AS $image_id) {
					// temporarily remove this code to test,
					// media manager saved images especially for each post separately, so we do not need to take their equivalent from translation post.
					// adapted for WPML
					/* global $sitepress;
					if (function_exists('wpml_object_id_filter') && $sitepress) {
						$image_id = apply_filters('wpml_object_id', $image_id, 'attachment', true);
					} */

					if ($image_post = get_post($image_id, ARRAY_A)) {
						$this->images[$image_id] = $image_post;
					}
				}
				
				$this->images = array_slice($this->images, 0, $this->level->images_number, true);

				if (($logo_id = (int)get_post_meta($this->post->ID, '_attached_image_as_logo', true)) && in_array($logo_id, array_keys($this->images))) {
					$this->logo_image = $logo_id;
				} else {
					$images_keys = array_keys($this->images);
					$this->logo_image = array_shift($images_keys);
				}
			} else {
				$this->images = array();
			}
		}
		
		$this->images = apply_filters('w2dc_listing_images', $this->images, $this);
		
		if ($this->level->videos_number) {
			if ($videos = get_post_meta($this->post->ID, '_attached_video_id')) {
				foreach ($videos AS $key=>$video) {
					$this->videos[] = array('id' => $video);
				}
			}
		}
		
		$this->videos = apply_filters('w2dc_listing_videos', $this->videos, $this);
	}
	
	public function setClaiming() {
		$this->is_claimable = get_post_meta($this->post->ID, '_is_claimable', true);
		$this->is_claimable = apply_filters('w2dc_listing_is_claimable', $this->is_claimable, $this);
		
		$this->claim = new w2dc_listing_claim($this->post->ID);
		$this->claim = apply_filters('w2dc_listing_claim', $this->claim, $this);
	}
	
	public function getContentField($field_id) {
		if (isset($this->content_fields[$field_id])) {
			return $this->content_fields[$field_id];
		}
	}

	public function renderContentField($field_id, $css_classes = '') {
		if (isset($this->content_fields[$field_id])) {
			$this->content_fields[$field_id]->renderOutput($this, null, $css_classes);
		}
	}
	
	public function renderContentFieldsGroup($fields_group_id, $css_classes = '') {
		global $w2dc_instance;
		
		if (isset($w2dc_instance->content_fields->content_fields_groups_array[$fields_group_id])) {
			$content_fields_group = $w2dc_instance->content_fields->content_fields_groups_array[$fields_group_id];
			
			$content_fields_group->setContentFields($this->content_fields);
			$content_fields_group->renderOutput($this, true, $css_classes);
		}
	}
	
	public function renderSummary() {
		$summary = new w2dc_content_field_excerpt();
		$summary->icon_image = false;
		$summary->is_hide_name = true;
		$summary->renderOutput($this);
	}

	public function display($frontend_controller, $is_single = false, $return = false) {
		$template = 'frontend/listing.tpl.php';
		
		$template = apply_filters('w2dc_listing_display_template', $template, $is_single, $this);
		
		return w2dc_renderTemplate($template, array('frontend_controller' => $frontend_controller, 'listing' => $this, 'is_single' => $is_single), $return);
	}
	
	public function renderContentFields($is_single = true) {
		global $w2dc_instance;
		
		$content_fields = apply_filters('w2dc_listing_content_fields_pre_render', $this->content_fields, $this);

		$content_fields_on_single = array();
		foreach ($content_fields AS $content_field) {
			if (
				$content_field->isNotEmpty($this) &&
				$content_field->filterForAdmins($this) &&
				((!$is_single && $content_field->on_exerpt_page) || ($is_single && $content_field->on_listing_page))
			) {
				if ($is_single) {
					$content_fields_on_single[] = $content_field;
				} else {
					do_action("w2dc_content_field_pre_output", $this, $content_field);
					
					$content_field->renderOutput($this);
					
					do_action("w2dc_content_field_pre_output", $this, $content_field);
				}
			}
		}

		if ($is_single && $content_fields_on_single) {
			$content_fields_by_groups = $w2dc_instance->content_fields->sortContentFieldsByGroups($content_fields_on_single);
			foreach ($content_fields_by_groups AS $item) {
				
				do_action("w2dc_content_field_pre_output_single", $this, $item);
				
				if (is_a($item, 'w2dc_content_field')) {
					$item->renderOutput($this);
				} elseif (is_a($item, 'w2dc_content_fields_group') && !$item->on_tab) {
					$item->renderOutput($this, $item);
				}
				
				do_action("w2dc_content_field_post_output_single", $this, $item);
			}
		}
	}
	
	public function getFieldsGroupsOnTabs() {
		global $w2dc_instance;

		$fields_groups = array();
		foreach ($this->content_fields AS $content_field) {
			if (
				$content_field->on_listing_page &&
				$content_field->group_id &&
				$content_field->isNotEmpty($this) &&
				$content_field->filterForAdmins($this) &&
				($content_fields_group = $w2dc_instance->content_fields->getContentFieldsGroupById($content_field->group_id)) &&
				$content_fields_group->on_tab &&
				!in_array($content_field->group_id, array_keys($fields_groups))
			) {
				$content_fields_group->setContentFields($this->content_fields);
				if ($content_fields_group->content_fields_array)
					$fields_groups[$content_field->group_id] = $content_fields_group;
			}
		}
		
		$fields_groups = apply_filters('w2dc_listing_content_fields_groups_on_tabs', $fields_groups, $this);

		return $fields_groups;
	}

	public function isMap() {
		$is_map = true;
		
		if (get_option("w2dc_map_type") == "none") {
			$is_map = false;
		} else {
			if (!$this->level->map) {
				$is_map = false;
			} else {
				if (!$this->locations) {
					$is_map = false;
				} else {
					$is_map = false;
					foreach ($this->locations AS $location) {
						if ($location->map_coords_1 != '0.000000' || $location->map_coords_2 != '0.000000') {
							$is_map = true;
						}
					}
				}
			}
		}
		
		$is_map = apply_filters('w2dc_listing_is_map', $is_map, $this);

		return $is_map;
	}
	
	public function renderMap($map_id = null, $show_directions = true, $static_image = false, $enable_radius_circle = false, $enable_clusters = false, $show_summary_button = false, $show_readmore_button = false) {
		$this->map = new w2dc_maps(array(
				'search_on_map' => 0,
				'search_on_map_open' => 0,
				'search_on_map_listings' => '',
				'geolocation' => 0,
				'start_zoom' => 0,
		));
		$this->map->setUniqueId($map_id);
		$this->map->collectLocations($this, $show_summary_button, $show_readmore_button);
		$this->map->display(
				array(
						'show_directions' => $show_directions,
						'static_image' => $static_image,
						'enable_radius_circle' => $enable_radius_circle,
						'enable_clusters' => $enable_clusters,
						'show_summary_button' => $show_summary_button,
						'show_readmore_button' => $show_readmore_button,
						'width' => false,
						'height' => get_option('w2dc_default_map_height'),
						'sticky_scroll' => false,
						'sticky_scroll_toppadding' => 10,
						'map_style' => w2dc_getSelectedMapStyleName(),
						'search_form' => false,
						'draw_panel' => false,
						'custom_home' => false,
						'enable_full_screen' => get_option('w2dc_enable_full_screen'),
						'enable_wheel_zoom' => get_option('w2dc_enable_wheel_zoom'),
						'enable_dragging_touchscreens' => get_option('w2dc_enable_dragging_touchscreens'),
						'center_map_onclick' => get_option('w2dc_center_map_onclick'),
				)
		);
	}

	public function processRaiseUp($invoke_hooks = true) {
		if ($this->level->raiseup_enabled) {
			$continue = true;
			$continue_invoke_hooks = true;
			if ($invoke_hooks)
				$continue = apply_filters('w2dc_listing_raiseup', $continue, $this, array(&$continue_invoke_hooks));

			if ($continue) {
				$listings_ids = array($this->post->ID);

				// adapted for WPML
				global $sitepress;
				if (function_exists('wpml_object_id_filter') && $sitepress) {
					$trid = $sitepress->get_element_trid($this->post->ID, 'post_' . W2DC_POST_TYPE);
					$translations = $sitepress->get_element_translations($trid);
					foreach ($translations AS $lang=>$translation)
						$listings_ids[] = $translation->element_id;
				} else
					$listings_ids[] = $this->post->ID;
				
				$listings_ids = array_unique($listings_ids);

				foreach ($listings_ids AS $listing_id)
					update_post_meta($listing_id, '_order_date', time());

				return true;
			}
		}
	}

	public function processActivate($invoke_hooks = true, $activate_package = true) {
		$continue = true;
		$continue_invoke_hooks = true;
		// $invoke_hooks = true will call the hook to create an invoice, if you just need to activate a listing - set it to false
		if ($invoke_hooks) {
			// try to renew listing
			$continue = apply_filters('w2dc_listing_renew', $continue, $this, array(&$continue_invoke_hooks));
		}

		if ($continue) {
			$listings = array($this);
			
			// if it is expired listing - post_status = publish
			/* if (get_post_meta($this->post->ID, '_expiration_notification_sent', true)) {
				wp_update_post(array('ID' => $this->post->ID, 'post_status' => 'publish'));
			} */

			// adapted for WPML
			global $sitepress;
			if (function_exists('wpml_object_id_filter') && $sitepress) {
				$trid = $sitepress->get_element_trid($this->post->ID, 'post_' . W2DC_POST_TYPE);
				$translations = $sitepress->get_element_translations($trid, 'post_' . W2DC_POST_TYPE, false, true);
				foreach ($translations AS $lang=>$translation) {
					$listing = w2dc_getListing($translation->element_id);
					$listings[] = $listing;
				}
			} else {
				$listings[] = $this;
			}
			
			$listings = array_unique($listings, SORT_REGULAR);

			foreach ($listings AS $listing) {
				if (!$listing->level->eternal_active_period) {
					// current time + level active period only when listing is still active (pre-payment)
					if ($listing->status == 'active') {
						$time = $listing->expiration_date;
					} else { 
						$time = current_time('timestamp');
					}
					$expiration_date = w2dc_calcExpirationDate($time, $listing->level);
					update_post_meta($listing->post->ID, '_expiration_date', $expiration_date);
				}
				update_post_meta($listing->post->ID, '_order_date', time());
				if ($listing->status != 'stopped') {
					update_post_meta($listing->post->ID, '_listing_status', 'active');
					$post_status = apply_filters('w2dc_post_status_on_activation', 'publish', $listing);
					wp_update_post(array('ID' => $listing->post->ID, 'post_status' => $post_status));
				}

				delete_post_meta($listing->post->ID, '_expiration_notification_sent');
				delete_post_meta($listing->post->ID, '_preexpiration_notification_sent');

				if ($activate_package) {
					do_action('w2dc_listing_package_process_activate', $listing, $invoke_hooks);
				}
					
				do_action('w2dc_listing_process_activate', $listing, $invoke_hooks);
			}
			return true;
		}
	}
	
	public function makeExpired() {
		
		update_post_meta($this->post->ID, '_listing_status', 'expired');
		wp_update_post(array('ID' => $this->post->ID, 'post_status' => 'draft')); // This needed in order terms counts were always actual
		
		$this->loadListingFromPost($this->post->ID);
		
		do_action('w2dc_listing_make_expired', $this);
	}
	
	public function saveExpirationDate($date_array) {
		$new_tmstmp = $date_array['expiration_date_tmstmp'] + $date_array['expiration_date_hour']*3600 + $date_array['expiration_date_minute']*60;
		
		$listings_ids = array($this->post->ID);
		
		// adapted for WPML
		global $sitepress;
		if (function_exists('wpml_object_id_filter') && $sitepress) {
			$trid = $sitepress->get_element_trid($this->post->ID, 'post_' . W2DC_POST_TYPE);
			$translations = $sitepress->get_element_translations($trid);
			foreach ($translations AS $lang=>$translation)
				$listings_ids[] = $translation->element_id;
		} else
			$listings_ids[] = $this->post->ID;
		
		$listings_ids = array_unique($listings_ids);

		$updated = false;
		foreach ($listings_ids AS $listing_id)
			if ($new_tmstmp != get_post_meta($listing_id, '_expiration_date', true)) {
				$new_tmstmp = apply_filters('w2dc_listing_save_expiration_date', $new_tmstmp, $date_array, $this);
				
				update_post_meta($listing_id, '_expiration_date', $new_tmstmp);
				$updated = true;
			}

		return $updated;
	}
	
	public function saveOrderDate($date_array) {
		$new_tmstmp = $date_array['order_date_tmstmp'] + $date_array['order_date_hour']*3600 + $date_array['order_date_minute']*60;
		
		$listings_ids = array($this->post->ID);
		
		// adapted for WPML
		global $sitepress;
		if (function_exists('wpml_object_id_filter') && $sitepress) {
			$trid = $sitepress->get_element_trid($this->post->ID, 'post_' . W2DC_POST_TYPE);
			$translations = $sitepress->get_element_translations($trid);
			foreach ($translations AS $lang=>$translation)
				$listings_ids[] = $translation->element_id;
		} else
			$listings_ids[] = $this->post->ID;
		
		$listings_ids = array_unique($listings_ids);

		$updated = false;
		foreach ($listings_ids AS $listing_id)
			if ($new_tmstmp != get_post_meta($listing_id, '_order_date', true)) {
				$new_tmstmp = apply_filters('w2dc_listing_save_order_date', $new_tmstmp, $date_array, $this);
				
				update_post_meta($listing_id, '_order_date', $new_tmstmp);
				$updated = true;
			}

		return $updated;
	}
	
	public function changeLevel($new_level_id, $invoke_hooks = true) {
		global $w2dc_instance, $wpdb;
		
		if (isset($w2dc_instance->levels->levels_array[$new_level_id])) {
			$new_level = $w2dc_instance->levels->levels_array[$new_level_id];
			
			if (
				(
					!$this->level->upgrade_meta[$new_level_id]['disabled'] || // old level allows upgrade/downgrade
					(current_user_can('editor') || current_user_can('manage_options'))
				)
				&&
				(!$invoke_hooks || w2dc_is_user_allowed($new_level->who_can_submit)) // pass when called by payment processing or user online
			) {
				$listings = array($this);
				
				// adapted for WPML
				global $sitepress;
				if (function_exists('wpml_object_id_filter') && $sitepress) {
					$trid = $sitepress->get_element_trid($this->post->ID, 'post_' . W2DC_POST_TYPE);
					$translations = $sitepress->get_element_translations($trid);
					foreach ($translations AS $lang=>$translation) {
						$listing = new w2dc_listing();
						$listing->loadListingFromPost($translation->element_id);
						$listings[] = $listing;
					}
				} else
					$listings[] = $this;
				
				$listings = array_unique($listings, SORT_REGULAR);
	
				foreach ($listings AS $listing) {
					update_post_meta($listing->post->ID, '_old_level_id', $listing->level->id);
					update_post_meta($listing->post->ID, '_new_level_id', $new_level_id);
				}
	
				$continue = true;
				$continue_invoke_hooks = true;
				if ($invoke_hooks) {
					$continue = apply_filters('w2dc_listing_upgrade', $continue, $this, array(&$continue_invoke_hooks));
				}
				
				if ($continue) {
					foreach ($listings AS $listing) {
						if ($wpdb->query("UPDATE {$wpdb->w2dc_levels_relationships} SET level_id=" . $new_level_id . "  WHERE post_id=" . $listing->post->ID)) {
							if ($this->level->upgrade_meta[$new_level_id]['raiseup']) {
								update_post_meta($listing->post->ID, '_order_date', time());
							}
		
							$listing->setLevelByPostId($listing->post->ID);
	
							//  If new level has an option of limited active period - expiration date of listing will be recalculated automatically
							if (!$listing->level->eternal_active_period) {
								$expiration_date = w2dc_calcExpirationDate(current_time('timestamp'), $listing->level);
								update_post_meta($listing->post->ID, '_expiration_date', $expiration_date);
							}
							
							if ($listing->status == 'expired' || $listing->status == 'unpaid') {
								update_post_meta($listing->post->ID, '_listing_status', 'active');
								delete_post_meta($listing->post->ID, '_expiration_notification_sent');
								delete_post_meta($listing->post->ID, '_preexpiration_notification_sent');
								
								do_action('w2dc_listing_process_activate_on_level_change', $listing, true);
							}
						}
					}
					return true;
				}
			}
		}
	}


	/**
	 * Load existed listing especially for map info window
	 * 
	 * @param $post is required and must be object
	 */
	public function loadListingForMap($post) {
		$this->post = $post;
	
		if ($this->setLevelByPostId()) {
			$this->setLocations();
			$this->setMapZoom();
			$this->setLogoImage();
				
			apply_filters('w2dc_listing_map_loading', $this);
		}
		return true;
	}

	/**
	 * Load existed listing especially for AJAX map - set only locations
	 * 
	 * @param $post is required and must be object
	 */
	public function loadListingForAjaxMap($post) {
		$this->post = $post;
	
		if ($this->setLevelByPostId())
			$this->setLocations();
			$this->setLogoImage();
		
		apply_filters('w2dc_listing_map_loading', $this);

		return true;
	}

	public function setLogoImage() {
		if ($this->level->images_number) {
			if ($logo_id = (int)get_post_meta($this->post->ID, '_attached_image_as_logo', true))
				$this->logo_image = $logo_id;
			else {
				$images = get_post_meta($this->post->ID, '_attached_image');
				$this->logo_image = array_shift($images);
			}
		}
		
		$this->logo_image = apply_filters('w2dc_listing_logo_image', $this->logo_image, $this);
	}

	public function setInfoWindowContent($map_id, $location, $show_summary_button = true, $show_readmore_button = true) {
		global $w2dc_instance;
		
		$post_categories_ids = wp_get_post_terms($this->post->ID, W2DC_CATEGORIES_TAX, array('fields' => 'ids'));
		
		$content_fields_output = array();
		$map_content_fields_icons = array();
		
		if ($location_info = $location->renderInfoFieldForMap()) {
			$content_fields_output['location_info'] = $location_info;
			$map_content_fields_icons['location_info'] = 'w2dc-fa-info-circle';
		}
		
		$map_content_fields = $w2dc_instance->content_fields->getMapContentFields();
		
		foreach ($map_content_fields AS $field_slug=>$content_field) {
			if (is_a($content_field, 'w2dc_content_field') && $content_field->icon_image) {
				$map_content_fields_icons[$field_slug] = $content_field->icon_image;
			} else {
				$map_content_fields_icons[$field_slug] = '';
			}
		}
		
		foreach ($map_content_fields AS $field_slug=>$content_field) {
			// is it native content field
			if (is_a($content_field, 'w2dc_content_field')) {
				if (
					(!$content_field->isCategories() || $content_field->categories === array() || (is_array($content_field->categories) && !is_wp_error($post_categories_ids) && array_intersect($content_field->categories, $post_categories_ids))) &&
					($content_field->is_core_field || !$this->level->content_fields || in_array($content_field->id, $this->level->content_fields))
				) {
					$content_field->loadValue($this->post->ID);
					$output = $content_field->renderOutputForMap($location, $this);
					$content_fields_output[$field_slug] = apply_filters('w2dc_map_content_field_output', $output, $content_field, $location, $this);
				} else {
					$content_fields_output[$field_slug] = null;
				}
			} else {
				$content_fields_output[$field_slug] = apply_filters('w2dc_map_info_window_fields_values', $content_field, $field_slug, $this);
			}
		}
		
		$logo_image = '';
		if ($this->level->logo_enabled) {
			if ($this->logo_image) {
				$height = apply_filters('w2dc_map_infowindow_logo_height', 0);
					
				$logo_image = $this->get_logo_url(array(get_option('w2dc_map_infowindow_logo_width'), $height));
			} elseif (get_option('w2dc_enable_nologo') && get_option('w2dc_nologo_url')) {
				$logo_image = get_option('w2dc_nologo_url');
			}
		}

		$template_args = array(
				'map_id' => $map_id,
				'listing' => $this,
				'map_content_fields' => $map_content_fields,
				'map_content_fields_icons' => $map_content_fields_icons,
				'content_fields_output' => $content_fields_output,
				'logo_image' => $logo_image,
				'show_summary_button' => $show_summary_button,
				'show_readmore_button' => $show_readmore_button,
		);
		$output = w2dc_renderTemplate('frontend/info_window.tpl.php', $template_args, true);

		return apply_filters('w2dc_map_info_window_content_output', $output, $this);
	}
	
	public function renderMapSidebarContentFields($location) {
		$info_output = '';
		$fields_output = '';
		
		if ($location->renderInfoFieldForMap()) {
			$info_output = '<div class="w2dc-map-listing-field">
							<span class="w2dc-map-listing-field-icon w2dc-fa w2dc-fa-info-circle"></span> ' . $location->renderInfoFieldForMap() . '
						</div>';
		}
	
		foreach ($this->content_fields AS $content_field) {
			if (
				$content_field->isNotEmpty($this) &&
				$content_field->filterForAdmins($this) &&
				$content_field->on_map
			) {
				if ($content_field->type != 'address') {
					$fields_output .= '<div class="w2dc-map-listing-field w2dc-map-listing-field-' . $content_field->type . '">';
						if (is_a($content_field, 'w2dc_content_field') && $content_field->icon_image) {
							$fields_output .= '<span class="w2dc-map-listing-field-icon w2dc-fa ' . $content_field->icon_image . '"></span>';
						}
						$fields_output .= $content_field->renderOutputForMap($location, $this);
					$fields_output .= '</div>';
				} else {
					$fields_output .= '<div class="w2dc-map-listing-field w2dc-map-listing-field-' . $content_field->type . '">';
						if (is_a($content_field, 'w2dc_content_field') && $content_field->icon_image) {
							$fields_output .= '<span class="w2dc-map-listing-field-icon w2dc-fa ' . $content_field->icon_image . '"></span>';
						}
						$fields_output .= '<address class="w2dc-location">';
							if ($location->map_coords_1 && $location->map_coords_2) {
								$fields_output .= '<span class="w2dc-show-on-map" data-location-id="' . $location->id . '">';
							}
							$fields_output .= $location->getWholeAddress();
							$fields_output .= w2dc_get_distance($location);
							if ($location->map_coords_1 && $location->map_coords_2) {
								$fields_output .= '</span>';
							}
						$fields_output .= '</address>';
					$fields_output .= '</div>';
				}
			}
		}
		
		echo $info_output;
		echo $fields_output;
	}

	public function isLogoOnExcerpt() {
		$is_logo = false;

		if ($this->level->logo_enabled && ($this->logo_image || (get_option('w2dc_enable_nologo') && get_option('w2dc_nologo_url')))) {
			$is_logo = true;
		}
		
		$is_logo = apply_filters('w2dc_is_logo_on_excerpt', $is_logo, $this);
		
		return $is_logo;
	}
	
	public function getPendingStatus() {
		if ($this->post->post_status == 'pending') {
			if ($this->status == 'unpaid') {
				return __('Pending payment', 'W2DC');
			}
			
			$is_moderation = get_post_meta($this->post->ID, '_requires_moderation', true);
			$is_approved = get_post_meta($this->post->ID, '_listing_approved', true);
			if ($is_moderation && !$is_approved) {
				return __('Pending approval', 'W2DC');
			}
			
			return __('Pending', 'W2DC');
		}
	}
	
	public function renderImagesGallery() {
		$thumbs = array();
		$images = array();
		foreach ($this->images AS $attachment_id=>$image) {
			if (!get_option('w2dc_exclude_logo_from_listing') || $this->logo_image != $attachment_id) {
				$image_src = wp_get_attachment_image_src($attachment_id, 'full');
				$image_title = $image['post_title'];
				
				$image_tag = '<img src="' . $image_src[0] . '" alt="' . esc_attr($image_title) . '" title="' . esc_attr($image_title) . '" />';
				$thumbs[] = $image_tag;
				
				if (get_option('w2dc_enable_lightbox_gallery')) {
					$images[] = '<a href="' . $image_src[0] . '" data-w2dc_lightbox="listing_images" title="' . esc_attr($image_title) . '">' . $image_tag . '</a>';
				} else {
					$images[] = $image_tag;
				}
			}
		}
		
		$images = apply_filters('w2dc_render_images_gallery', $images, $this);
		
		$gallery_options = array(
			'captions' => true,
			'pager' => true,
			'width' => (!get_option('w2dc_100_single_logo_width')) ? get_option('w2dc_single_logo_width') : false,
			'height' => (get_option('w2dc_single_logo_height')) ? get_option('w2dc_single_logo_height') : false,
			'images' => $images,
			'thumbs' => $thumbs,
			'crop' => (get_option('w2dc_big_slide_bg_mode') == 'contain') ? 0 : 1,
			'auto_slides' => get_option('w2dc_auto_slides_gallery'),
			'auto_slides_delay' => get_option('w2dc_auto_slides_gallery_delay'),
			'id' => w2dc_generateRandomVal(),
			'slide_width' => false,
			'max_slides' => false,
		);
		
		$gallery_options = apply_filters('w2dc_listing_gallery_options', $gallery_options);
		
		w2dc_renderTemplate('frontend/slider.tpl.php', $gallery_options);
	}
	
	public function isContactForm() {
		if (
			get_option('w2dc_listing_contact_form') &&
			(!$this->is_claimable || !get_option('w2dc_hide_claim_contact_form')) &&
			(
				(($listing_owner = get_userdata($this->post->post_author)) && $listing_owner->user_email) ||
				$this->contact_email
			)
		) {
			return true;
		}
	}
}

class w2dc_listing_claim {
	public $listing_id;
	public $claimer_id;
	public $claimer;
	public $claimer_message;
	public $status = null;
	
	public function __construct($listing_id) {
		$this->listing_id = $listing_id;
		if ($claim_record = get_post_meta($listing_id, '_claim_data', true)) {
			if (isset($claim_record['claimer_id'])) {
				$this->claimer_id = $claim_record['claimer_id'];
				if ($claimer = get_userdata($claim_record['claimer_id']))
					$this->claimer = $claimer;
			}
			if (isset($claim_record['claimer_message']))
				$this->claimer_message = $claim_record['claimer_message'];
			if (isset($claim_record['status']))
				$this->status = $claim_record['status'];
			else 
				$this->status = 'pending';
		}
	}
	
	public function updateRecord($claimer_id = null, $claimer_message = null, $status = null) {
		if ($claimer_id !== null) {
			$this->claimer_id = $claimer_id;
			update_post_meta($this->listing_id, '_claimer_id', $this->claimer_id);
			if ($claimer = get_userdata($claimer_id))
				$this->claimer = $claimer;
		}
		if ($claimer_message !== null)
			$this->claimer_message = $claimer_message;
		if ($status !== null)
			$this->status = $status;
		return update_post_meta($this->listing_id, '_claim_data', array('claimer_id' => $this->claimer_id, 'claimer_message' => $this->claimer_message, 'status' => $this->status));
	}
	
	public function deleteRecord() {
		delete_post_meta($this->listing_id, '_claimer_id');
		return delete_post_meta($this->listing_id, '_claim_data');
	}
	
	public function isClaimed() {
		return (bool) ($this->status == 'pending');
	}

	public function getClaimMessage() {
		if ($this->claimer_id == get_current_user_id()) {
			if ($this->status == 'approved')
				return __('Your claim was approved successully', 'W2DC');
			else
				return __('Your claim was not approved yet', 'W2DC');
		} else {
			if ($this->status != 'approved')
				return sprintf(__('You may approve or decline claim <a href="%s">here</a>', 'W2DC'), w2dc_dashboardUrl(array('listing_id' => $this->listing_id, 'w2dc_action' => 'process_claim')));
		}
	}

	public function approve() {
		
		if ($listing = w2dc_getListing($this->listing_id)) {
		
			$postarr = array(
					'ID' => $this->listing_id,
					'post_author' => $this->claimer_id
			);
			$result = wp_update_post($postarr, true);
			if (!is_wp_error($result)) {
				if (get_option('w2dc_after_claim') == 'expired') {
					$listing->makeExpired();
				}
				update_post_meta($this->listing_id, '_is_claimable', false);
				update_post_meta($this->listing_id, '_original_owner', $listing->post->post_author);
	
				return $this->updateRecord(null, null, 'approved');
			}
		}
	}
}

// use this to allow previous owner to edit a listing
/* add_filter("w2dc_user_can_edit_listing", "w2dc_user_can_edit_listing", 10, 2);
function w2dc_user_can_edit_listing($can_edit, $listing_id) {
	
	if ($listing = w2dc_getListing($listing_id)) {
		if ($owner_id = get_post_meta($listing->post->ID, '_original_owner', true)) {
			$current_user = wp_get_current_user();
			if ($current_user->ID == $owner_id) {
				$can_edit = true;
			}
		}
	}
	
	return $can_edit;
} */

?>