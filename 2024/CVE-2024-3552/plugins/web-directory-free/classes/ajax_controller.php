<?php 

class w2dc_ajax_controller {

	public function __construct() {
		add_action('wp_ajax_w2dc_get_map_marker_info', array($this, 'get_map_marker_info'));
		add_action('wp_ajax_nopriv_w2dc_get_map_marker_info', array($this, 'get_map_marker_info'));

		add_action('wp_ajax_w2dc_get_sharing_buttons', array($this, 'get_sharing_buttons'));
		add_action('wp_ajax_nopriv_w2dc_get_sharing_buttons', array($this, 'get_sharing_buttons'));

		add_action('wp_ajax_w2dc_controller_request', array($this, 'controller_request'));
		add_action('wp_ajax_nopriv_w2dc_controller_request', array($this, 'controller_request'));
		
		add_action('wp_ajax_w2dc_select_fa_icon', array($this, 'select_field_icon'));
		add_action('wp_ajax_nopriv_w2dc_select_fa_icon', array($this, 'select_field_icon'));
		
		add_action('wp_ajax_w2dc_contact_form', array($this, 'contact_form'));
		add_action('wp_ajax_nopriv_w2dc_contact_form', array($this, 'contact_form'));

		// is used in wcsearch 'wcsearch_keywords_search_action' filter
		add_action('wp_ajax_w2dc_keywords_search', array($this, 'keywords_search'));
		add_action('wp_ajax_nopriv_w2dc_keywords_search', array($this, 'keywords_search'));
		
		add_action('wp_ajax_w2dc_add_term', array($this, 'add_term'));
		add_action('wp_ajax_nopriv_w2dc_add_term', array($this, 'add_term'));
		add_action('wp_ajax_w2dc_update_tax_wrapper', array($this, 'update_tax_wrapper'));
		add_action('wp_ajax_nopriv_w2dc_update_tax_wrapper', array($this, 'update_tax_wrapper'));
	}

	public function controller_request() {
		global $w2dc_instance, $w2dc_global_base_url;
		
		$w2dc_instance->setCurrentDirectory();

		$post_args = $_POST;

		$shortcode_atts = array_merge(array(
				'custom_home' => 0,
				//'perpage' => (!empty($post_args['is_home'])) ? get_option('w2dc_listings_number_index') : get_option('w2dc_listings_number_excerpt'),
				'onepage' => 0,
				'map_markers_is_limit' => get_option('w2dc_map_markers_is_limit'),
				'sticky_featured' => 0,
				'order_by' => get_option('w2dc_default_orderby'),
				'order' => get_option('w2dc_default_order'),
				'hide_order' => (int)(!(get_option('w2dc_show_orderby_links'))),
				'hide_count' => (int)(!(get_option('w2dc_show_listings_count'))),
				'hide_paginator' => 0,
				'show_views_switcher' => (int)get_option('w2dc_views_switcher'),
				'listings_view_type' => get_option('w2dc_views_switcher_default'),
				'listings_view_grid_columns' => (int)get_option('w2dc_views_switcher_grid_columns'),
				'listing_thumb_width' => (int)get_option('w2dc_listing_thumb_width'),
				'wrap_logo_list_view' => (int)get_option('w2dc_wrap_logo_list_view'),
				'logo_animation_effect' => get_option('w2dc_logo_animation_effect'),
				'hide_content' => 0,
				'rating_stars' => 1,
				'summary_on_logo_hover' => 0,
				'author' => 0,
				'paged' => 1,
				'include_categories_children' => 1,
				'template' => 'frontend/listings_block.tpl.php',
				'ajax_map_loading' => 0,
				'geo_poly' => 0,
				'show_summary_button' => 1,
				'show_readmore_button' => 1,
				'ajax_action' => '', // 'search', 'geo_poly', 'order', 'paginator', 'show_more', 'ajax_initial_load', 'ajax_markers'
		), $post_args);
					
		// disable initial load
		$shortcode_atts['ajax_initial_load'] = 0;
				
		// This is required workaround
		if (wcsearch_get_query_string("order_by")) {
				$_REQUEST['order_by'] = $shortcode_atts['order_by'] = wcsearch_get_query_string("order_by");
				$_REQUEST['order'] = $shortcode_atts['order'] = wcsearch_get_query_string("order");
		}
		
		$listings_controller = false;
		$map_controller = false;
		if (!empty($shortcode_atts['ajax_map_loading']) || !empty($shortcode_atts['geo_poly'])) {
			
			$map_args = $shortcode_atts;
			
			// now its time to load all AJAX markers
			$map_args['ajax_map_loading'] = 0;
			$map_args['perpage'] = -1;
			
			// no need map markers in these actions
			if (in_array($shortcode_atts['ajax_action'], array('show_more', 'paginator'))) {
				$map_args['do_not_load_markers'] = 1;
			}
			
			$map_controller = new w2dc_map_controller();
			$map_controller->init($map_args);
			
			$listings_args = $shortcode_atts;
			if (!empty($map_controller->args['post__in'])) {
				$listings_args['post__in'] = $map_controller->args['post__in'];
			}
			
			// reset pages to 1 when no pagination
			if (!in_array($shortcode_atts['ajax_action'], array('show_more', 'paginator'))) {
				$listings_args['paged'] = 1;
			}
			
			// Strongly required for paginator
			set_query_var('page', $listings_args['paged']);
			
			$listings_controller = new w2dc_listings_controller();
			$listings_controller->init($listings_args);
			$listings_controller->args = $shortcode_atts;
			
			//unset($listings_controller->args['geo_poly']);
		} else {
			// Strongly required for paginator
			set_query_var('page', $shortcode_atts['paged']);
			
			$listings_args = $shortcode_atts;
			
			if (empty($post_args['without_listings'])) {
				$listings_controller = new w2dc_listings_controller();
				$listings_controller->init($listings_args);
				$listings_controller->custom_home = (isset($shortcode_atts['custom_home']) && $shortcode_atts['custom_home']);
			}
			
			if (!empty($shortcode_atts['with_map'])) {
				$map_args = $shortcode_atts;
				
				// no limit
				if (empty($map_args['map_markers_is_limit'])) {
					if (in_array($shortcode_atts['ajax_action'], array('search', 'ajax_initial_load'))) {
						$map_controller = new w2dc_map_controller();
						$map_controller->init($map_args);
					}
				} else {
					if ($listings_controller) {
						$map_args['do_not_load_markers'] = 1;
					}
					
					$map_controller = new w2dc_map_controller();
					$map_controller->init($map_args);
					
					if ($listings_controller && $map_controller) {
						foreach ($listings_controller->listings AS $listing) {
							if (!empty($shortcode_atts['ajax_markers_loading'])) {
								$map_controller->map->collectLocationsForAjax($listing);
							} else {
								$map_controller->map->collectLocations($listing, $shortcode_atts['show_summary_button'], $shortcode_atts['show_readmore_button']);
							}
						}
					}
				}
			}
		}

		$listings_html = '';
		if (empty($post_args['without_listings'])) {
			if (!empty($post_args['do_append'])) {
				if ($listings_controller->listings)
					while ($listings_controller->query->have_posts()) {
						$listings_controller->query->the_post(); 
						$listings_html .= '<article id="post-' . get_the_ID() . '" class="w2dc-row w2dc-listing ' . $listings_controller->getListingClasses() . '">';
						$listings_html .= $listings_controller->listings[get_the_ID()]->display($listings_controller, false, true);
						$listings_html .= '</article>';
					}
				unset($listings_controller->args['do_append']);
			} else {
				$listings_html = $listings_controller->display();
			}
		}
		wp_reset_postdata();
		
		$hash = ($listings_controller) ? $listings_controller->hash : (($map_controller) ? $map_controller->hash : '');
		$map_markers = ((!empty($post_args['with_map']) && !empty($map_controller->map)) ? $map_controller->map->locations_option_array : '');
		$map_listings = ((!empty($post_args['map_listings']) && !empty($map_controller->map)) ? $map_controller->map->buildListingsContent() : '');
		$hide_show_more_listings_button = ($listings_controller && $shortcode_atts['paged'] >= $listings_controller->query->max_num_pages) ? 1 : 0;
		$sql = ((defined('WP_DEBUG') && true === WP_DEBUG) ? (($listings_controller) ? $listings_controller->query->request : $map_controller->listings_controller->query->request) : '');
		$params = ((defined('WP_DEBUG') && true === WP_DEBUG) ? $shortcode_atts : '');

		$out = array(
				'html' => $listings_html,
				'hash' => $hash,
				'map_markers' => $map_markers,
				'map_listings' => $map_listings,
				'hide_show_more_listings_button' => $hide_show_more_listings_button,
				'sql' => $sql,
				'params' => $params,
				'base_url' => $w2dc_global_base_url,
		);
		
		global $w2dc_radius_params;
		if ($w2dc_radius_params) {
			$out['radius_params'] = array(
					'radius_value' => $w2dc_radius_params['radius_value'],
					'map_coords_1' => $w2dc_radius_params['map_coords_1'],
					'map_coords_2' => $w2dc_radius_params['map_coords_2'],
					'dimension' => get_option('w2dc_miles_kilometers_in_search')
			);
		}
		
		if ($json = json_encode(w2dc_utf8ize($out))) {
			echo $json;
		} else {
			echo json_last_error_msg();
		}
		
		die();
	}
	
	public function get_map_marker_info() {
		global $wpdb;

		if (isset($_POST['locations_ids'])) {
			
			$locations_option_array = array();
			
			$locations_ids = w2dc_getValue($_POST, 'locations_ids');
			foreach ($locations_ids AS $location_id) {
				$map_id = w2dc_getValue($_POST, 'map_id');
				$show_summary_button = w2dc_getValue($_POST, 'show_summary_button');
				$show_readmore_button = w2dc_getValue($_POST, 'show_readmore_button');
	
				$row = $wpdb->get_row("SELECT * FROM {$wpdb->w2dc_locations_relationships} WHERE id=".$location_id, ARRAY_A);
	
				if ($row && $row['location_id'] || $row['map_coords_1'] != '0.000000' || $row['map_coords_2'] != '0.000000' || $row['address_line_1'] || $row['zip_or_postal_index']) {
					$listing = new w2dc_listing;
					if ($listing->loadListingFromPost($row['post_id'])) {
						$location = new w2dc_location($row['post_id']);
						$location_settings['id'] = w2dc_getValue($row, 'id');
						$location_settings['selected_location'] = w2dc_getValue($row, 'location_id');
						$location_settings['address_line_1'] = w2dc_getValue($row, 'address_line_1');
						$location_settings['address_line_2'] = w2dc_getValue($row, 'address_line_2');
						$location_settings['zip_or_postal_index'] = w2dc_getValue($row, 'zip_or_postal_index');
						$location_settings['additional_info'] = w2dc_getValue($row, 'additional_info');
						if ($listing->level->map) {
							$location_settings['manual_coords'] = w2dc_getValue($row, 'manual_coords');
							$location_settings['map_coords_1'] = w2dc_getValue($row, 'map_coords_1');
							$location_settings['map_coords_2'] = w2dc_getValue($row, 'map_coords_2');
							if ($listing->level->map_markers) {
								$location_settings['map_icon_file'] = w2dc_getValue($row, 'map_icon_file');
							}
						}
						$location->createLocationFromArray($location_settings);
							
						$logo_image = '';
						if ($listing->logo_image) {
							$logo_image = $listing->get_logo_url(array(80, 80));
						}
							
						$listing_link = '';
						if ($listing->level->listings_own_page) {
							$listing_link = get_permalink($listing->post->ID);
						}
							
						$content_fields_output = $listing->setInfoWindowContent($map_id, $location, $show_summary_button, $show_readmore_button);
	
						$locations_option_array[] = array(
								$location->id,
								$location->map_coords_1,
								$location->map_coords_2,
								$location->map_icon_file,
								$location->map_icon_color,
								$listing->map_zoom,
								$listing->title(),
								$logo_image,
								$listing_link,
								$content_fields_output,
								'post-' . $listing->post->ID,
						);
					}
				}
			}
			
			if ($json = json_encode($locations_option_array)) {
				echo $json;
			} else {
				echo json_last_error_msg();
			}
			
		}
		die();
	}
	
	public function select_field_icon() {
		w2dc_renderTemplate('select_fa_icons.tpl.php', array('icons' => w2dc_get_fa_icons_names()));
		die();
	}
	
	public function get_sharing_buttons() {
		w2dc_renderTemplate('frontend/single_parts/sharing_buttons_ajax_response.tpl.php', array('post_id' => w2dc_getValue($_POST, 'post_id'), 'post_url' => sanitize_url($_POST['post_url'])));
		die();
	}
	
	public function contact_form() {
		$success = '';
		$error = '';
		if (!($type = $_REQUEST['type'])) {
			$error = __('The type of message required!', 'W2DC');
		} else {
			check_ajax_referer('w2dc_' . $type . '_nonce', 'security');
	
			$validation = new w2dc_form_validation;
			if (!is_user_logged_in()) {
				$validation->set_rules('name', __('Contact name', 'W2DC'), 'required');
				$validation->set_rules('email', __('Contact email', 'W2DC'), 'required|valid_email');
			}
			$validation->set_rules('listing_id', __('Listing ID', 'W2DC'), 'required');
			$validation->set_rules('message', __('Your message', 'W2DC'), 'required|max_length[1500]');
			if ($validation->run()) {
				$listing = new w2dc_listing();
				if ($listing->loadListingFromPost($validation->result_array('listing_id'))) {
					if (!is_user_logged_in()) {
						$name = $validation->result_array('name');
						$email = $validation->result_array('email');
					} else {
						$current_user = wp_get_current_user();
						$name = $current_user->display_name;
						$email = $current_user->user_email;
					}
					$message = $validation->result_array('message');
		
					if (w2dc_is_recaptcha_passed()) {
						if ($type == 'contact') {
							if (get_option('w2dc_custom_contact_email') && $listing->contact_email) {
								$send_to_email = $listing->contact_email;
							} else {
								$listing_owner = get_userdata($listing->post->post_author);
								$send_to_email = $listing_owner->user_email;
							}
						} elseif ($type == 'report') {
							$send_to_email = get_option('admin_email');
						}
		
						$headers[] = "From: $name <$email>";
						$headers[] = "Reply-To: $email";
						$headers[] = "Content-Type: text/html";
	
						$subject = sprintf(__('%s contacted you about listing "%s"', 'W2DC'), $name, $listing->title());
		
						$body = w2dc_renderTemplate('emails/' . $type . '_form.tpl.php',
								array(
										'name' => $name,
										'email' => $email,
										'message' => $message,
										'listing_title' => $listing->title(),
										'listing_url' => get_permalink($listing->post->ID)
								), true);
	
						do_action('w2dc_send_' . $type . '_email', $listing, $send_to_email, $subject, $body, $headers);
						
						if (w2dc_mail($send_to_email, $subject, $body, $headers)) {
							unset($_POST['name']);
							unset($_POST['email']);
							unset($_POST['message']);
							$success = __('Your message was sent successfully!', 'W2DC');
						} else {
							$error = esc_attr__("An error occurred and your message wasn't sent!", 'W2DC');
						}
					} else {
						$error = esc_attr__("Anti-bot test wasn't passed!", 'W2DC');
					}
				}
			} else {
				$error = $validation->error_array();
			}
		}
	
		echo json_encode(array('error' => $error, 'success' => $success));
	
		die();
	}
	
	public function keywords_search() {
		$validation = new w2dc_form_validation;
		$validation->set_rules('term', __('Search term', 'W2DC'));
		$validation->set_rules('directories', __('Directories IDs', 'W2DC'));
		$validation->set_rules('do_links', __('Links to products in autocomplete suggestion', 'W2DC'));
		$validation->set_rules('do_links_blank', __('How to open links', 'W2DC'));
		if ($validation->run()) {
			$term = $validation->result_array('term');
			$directories = $validation->result_array('directories');
			$do_links = $validation->result_array('do_links');
			$do_links_blank = $validation->result_array('do_links_blank');
			
			$default_orderby_args = array('order_by' => get_option('w2dc_default_orderby'), 'order' => get_option('w2dc_default_order'));
			$order_args = apply_filters('w2dc_order_args', array(), $default_orderby_args);
		
			$args = array(
					'post_type' => W2DC_POST_TYPE,
					'post_status' => 'publish',
					'posts_per_page' => apply_filters('w2dc_ajax_search_listings_number', 10),
					//'orderby'   => 'post_title',
					//'order'   => 'ASC',
					's' => $term
			);
			$args = array_merge($args, $order_args);
			
			if ($directories) {
				$directories = explode(',', $directories);
				$args = w2dc_set_directory_args($args, $directories);
			}

			$query = new WP_Query($args);
			
			// adapted for Relevanssi
			if (w2dc_is_relevanssi_search()) {
				$query->query_vars['s'] = $term;
				$query->query_vars['posts_per_page'] = apply_filters('w2dc_ajax_search_listings_number', 10);
				relevanssi_do_query($query);
			}
			
			// disable hyphens to dashes conversion
			remove_filter('the_title', 'wptexturize');
			
			$listings_json = array();
			while ($query->have_posts()) {
				$query->the_post();
			
				$listing = new w2dc_listing;
				$listing->loadListingFromPost(get_post());
				
				$content = w2dc_crop_content($listing->post->ID, get_option('w2dc_excerpt_length'), true, false, false, '...');
				
				if (!$listing->level->listings_own_page) {
					$title = '<strong>' . $listing->title() . '</strong>';
				} else {
					
					if ($do_links) {
						if ($do_links_blank == 'blank') {
							$target = apply_filters('w2dc_listing_title_search_target', 'target="_blank"');
						} elseif ($do_links_blank == 'self') {
							$target = apply_filters('w2dc_listing_title_search_target', '');
						}
						$link_begin = '<a href="' . get_the_permalink($listing->post) . '" ' . $target . ' title="' . esc_attr__("open listing", "W2DC") . '" ' . (($listing->level->nofollow) ? 'rel="nofollow"' : '') . '>';
						$link_end = '</a>';
						
						$title = '<strong>' . $link_begin . $listing->title() . $link_end . '</strong>';
						$content = $link_begin . $content . $link_end;
					} else {
						$title = '<strong>' . $listing->title() . '</strong>';
					}
				}
				
				if ($listing->logo_image) {
					$listing_logo = $listing->get_logo_url(array(50, 50));
				} else {
					$listing_logo = get_option('w2dc_nologo_url');
				}

				$listing_json_field = array();
				$listing_json_field['title'] = apply_filters('w2dc_listing_title_search_html', $title, $listing);
				$listing_json_field['name'] = htmlspecialchars_decode($listing->title()); // htmlspecialchars_decode() needed due to &amp; symbols
				$listing_json_field['url'] = get_the_permalink($listing->post);
				$listing_json_field['icon'] = $listing_logo;
				$listing_json_field['sublabel'] = $content;
				$listings_json[] = $listing_json_field;
			}
			
			if ($json = json_encode(array('listings' => $listings_json))) {
				echo $json;
			} else {
				echo json_last_error_msg();
			}
		}
		
		die();
	}
	
	public function add_term() {
		global $w2dc_instance;
		
		$tax = w2dc_getValue($_POST, 'tax');
		$parent_id = w2dc_getValue($_POST, 'parent_id');
		$val = w2dc_getValue($_POST, 'val');
		
		if ($val) {
			check_ajax_referer('w2dc_add_term_nonce', 'security');
			
			$locations_levels = $w2dc_instance->locations_levels;
			if ($locations_levels->isAddTermAllowed($parent_id)) {
				$term = wp_insert_term($val, $tax, array(
					'parent' => $parent_id,
				));
				
				if (!is_wp_error($term)) {
					echo trim($term['term_id']);
				}
			}
		}
		
		die();
	}
	
	public function update_tax_wrapper() {
		global $w2dc_instance;
		
		$tax = w2dc_getValue($_POST, 'tax');
		$selected_term = w2dc_getValue($_POST, 'selected_term');
		$uID = w2dc_getValue($_POST, 'uid');
		if (w2dc_getValue($_POST, 'exact_terms')) {
			$exact_terms = explode(',', w2dc_getValue($_POST, 'exact_terms'));
		} else {
			$exact_terms = array();
		}
		
		$locations_levels = $w2dc_instance->locations_levels;
		
		if (w2dc_is_anyone_in_taxonomy($tax)) {
			w2dc_tax_dropdowns_init(
				array(
						'tax' => $tax,
						'term_id' => $selected_term,
						'count' => false,
						'labels' => $locations_levels->getNamesArray(),
						'titles' => $locations_levels->getSelectionsArray(),
						'allow_add_term' => $locations_levels->getAllowAddTermArray(),
						'uID' => $uID,
						'exact_locations' => $exact_terms,
				)
			);
		}
		
		die();
	}
}
?>