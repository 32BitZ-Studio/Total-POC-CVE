<?php 

class w2dc_directory_controller extends w2dc_frontend_controller {
	public $is_home = false;
	public $is_search = false;
	public $is_single = false;
	public $is_listing = false;
	public $is_directory_page = false;
	public $object_single;
	public $listing;
	public $term;
	public $is_category = false;
	public $category;
	public $is_location = false;
	public $location;
	public $is_tag = false;
	public $tag;
	public $is_favourites = false;
	public $custom_home = false;

	public function init($shortcode_atts = array(), $shortcode = W2DC_MAIN_SHORTCODE) {
		global $w2dc_instance;
		
		// requrires for is_plugin_active() function at the frontend
		include_once(ABSPATH . 'wp-admin/includes/plugin.php');
		
		parent::init($shortcode_atts);
		
		$shortcode_atts['include_get_params'] = 1;

		if (isset($shortcode_atts['hide_listings']) && $shortcode_atts['hide_listings']) {
			$this->do_initial_load = false;
			
			// listings will not load, query will not be processed,
			// make 'hide_listings' = 0 so AJAX can be called later
			$shortcode_atts['hide_listings'] = 0;
		}
		
		if (isset($shortcode_atts['custom_home']) && $shortcode_atts['custom_home']) {
			$this->custom_home = true;
		}
		
		// default directory needed
		if (empty($shortcode_atts['id'])) {
			$shortcode_atts['id'] = $w2dc_instance->current_directory->id;
		}

		if (get_query_var('page')) {
			$paged = get_query_var('page');
		} elseif (get_query_var('paged')) {
			$paged = get_query_var('paged');
		} else {
			$paged = 1;
		}
		
		// display these listings by default, then directory searches as usual
		if (!empty($shortcode_atts['start_listings'])) {
			$shortcode_atts['post__in'] = $shortcode_atts['start_listings'];
		}
		
		$this->is_home = (!empty($shortcode_atts['custom_home']) ? 1 : 0);
		
		$process_directory_controller = apply_filters("w2dc_do_process_directory_controller", false);

		if ($process_directory_controller) {
			
		} elseif ($listing = w2dc_isListing()) {
			$args = array(
					'post_type' => W2DC_POST_TYPE,
					'name' => $listing->post->post_name,
					'posts_per_page' => 1,
			);
				
			add_filter('post_limits', array($this, 'findOnlyOnePost'));
			$this->query = new WP_Query($args);
			remove_filter('post_limits', array($this, 'findOnlyOnePost'));
			$this->processQuery();
			// Map uID must be absolutely unique on single listing page
			$this->hash = md5(time());

			if (count($this->listings)) {
				$listings_array = $this->listings;
				$listing = array_shift($listings_array);
				$this->listing = $listing;
				$this->object_single = $listing;
				if ((!$this->listing->level->listings_own_page || $this->listing->post->post_status != 'publish') && !current_user_can('edit_others_posts')) {
					wp_redirect(w2dc_directoryUrl());
				}
				
				$this->is_single = true;
				$this->is_listing = true;
				$this->template = 'frontend/listing_single.tpl.php';
				
				if (w2dc_is_user_allowed($listing->level->who_can_view)) {
					if (!wp_doing_ajax()) {
						$this->listing->increaseClicksStats();
					}
				} else {
					w2dc_addMessage(esc_html__("Sorry, you are not allowed to view this page.", "W2DC"));
					$this->template = 'frontend/listing_single_blocked.tpl.php';
				}
				
				// here directory ID we will take from post meta
				$w2dc_instance->setCurrentDirectory();

				$this->page_title = $listing->title();

				if (get_option('w2dc_enable_breadcrumbs')) {
					switch (get_option('w2dc_breadcrumbs_mode')) {
						
						case 'category':
							if ($terms = get_the_terms($this->listing->post->ID, W2DC_CATEGORIES_TAX)) {
								
								$term = array_shift($terms);
								
								if (get_option('w2dc_permalinks_structure') == 'category_slug' && count($terms) > 1) {
									foreach ($terms AS $_term) {
										if ($parents = w2dc_get_term_parents_slugs($_term->term_id, W2DC_CATEGORIES_TAX)) {
											$uri = implode('/', $parents);
											if ($uri == get_query_var('tax-slugs-w2dc')) {
												$term = $_term;
											}
										}
									}
								}
								
								$this->addBreadCrumbs(w2dc_get_term_parents($term, W2DC_CATEGORIES_TAX, true, true));
							}
							break;
							
						case 'location':
							if ($terms = get_the_terms($this->listing->post->ID, W2DC_LOCATIONS_TAX)) {
							
								$term = array_shift($terms);
							
								if (get_option('w2dc_permalinks_structure') == 'location_slug' && count($terms) > 1) {
									foreach ($terms AS $_term) {
										if ($parents = w2dc_get_term_parents_slugs($_term->term_id, W2DC_LOCATIONS_TAX)) {
											$uri = implode('/', $parents);
											if ($uri == get_query_var('tax-slugs-w2dc')) {
												$term = $_term;
											}
										}
									}
								}
							
								$this->addBreadCrumbs(w2dc_get_term_parents($term, W2DC_LOCATIONS_TAX, true, true));
							}
					}
					$this->addBreadCrumbs($listing->title());
				}

				if (get_option('w2dc_listing_contact_form') && defined('WPCF7_VERSION') && w2dc_get_wpml_dependent_option('w2dc_listing_contact_form_7')) {
					add_filter('wpcf7_form_action_url', array($this, 'w2dc_add_listing_id_to_wpcf7'));
					add_filter('wpcf7_form_hidden_fields', array($this, 'w2dc_add_listing_id_to_wpcf7_field'));
					// Add duplicated hidden tag _wpcf7_container_post to set real post ID
					add_filter('wpcf7_form_elements', array($this, 'w2dc_add_wpcf7_container_post'));
				}
				
				if (get_option("w2dc_imitate_mode")) {
					add_filter('language_attributes', array($this, 'add_opengraph_doctype'));
					
					// Disable OpenGraph in Jetpack
					if (get_option('w2dc_share_buttons')) {
						add_filter('jetpack_enable_open_graph', '__return_false', 99);
					}
					
					add_action('wp_head', array($this, 'insert_fb_in_head'), -10);
				}
				
				// process shortcodes on listing single template page when any of [webdirectory-listing-XXXX] shortcodes persist on the page
				if ($shortcode == W2DC_LISTING_SHORTCODE && $w2dc_instance->listing_page_id) {
					if (w2dc_isListingElementsOnPage()) {
						$this->template  = false;
					}
				}
			} else {
				$this->set404();
			}
		} elseif (get_query_var(W2DC_CATEGORIES_TAX)) {		// categories
			if ($category_object = w2dc_isCategory()) {
				$this->is_category = true;
				$this->term = $category_object;
				$this->category = $category_object;
				$this->template = 'frontend/category.tpl.php';
				$this->page_title = $category_object->name;
				
				if (get_option('w2dc_main_search')) {
					$this->search_form = new w2dc_search_form($this->hash, array('form_id' => get_option('w2dc_search_form_id')));
				}
				
				$args = apply_filters("w2dc_query_input_args", $shortcode_atts);
				
				$args['perpage'] = w2dc_getValue($shortcode_atts, 'perpage', (int)get_option('w2dc_listings_number_excerpt'));
				$args['paged'] = $paged;
				
				$get_orderby_args = $this->getOrderByArgs($args);
				$args = array_merge($args, $get_orderby_args);
					
				$query = new w2dc_search_query($args);
				$this->query = $query->get_query();
				$this->processQuery();
				//var_dump($this->query->request);
				
				if (w2dc_is_maps_used() && get_option('w2dc_map_on_excerpt')) {
					$map_args = $this->getDefaultMapArgs($args);
					
					if (get_option('w2dc_map_markers_is_limit')) {
						
						$this->map = new w2dc_maps($map_args);
						$this->map->setUniqueId($this->hash);
							
						foreach ($this->listings AS $listing) {
							$this->map->collectLocations($listing);
						}
					} else {
						$map_controller = new w2dc_map_controller();
						$map_controller->init($map_args);
							
						$this->map = $map_controller->map;
					}
				}
				
				$this->base_url = get_term_link($category_object, W2DC_CATEGORIES_TAX);
				$this->page_url = $this->base_url;
					
				// pass order args into listings_block.tpl.php
				$this->args = $get_orderby_args;
				$this->args['categories'] = $category_object->term_id;
				
				if (get_option('w2dc_enable_breadcrumbs')) {
					$this->addBreadCrumbs(w2dc_get_term_parents($category_object, W2DC_CATEGORIES_TAX, true, true));
				}
			} else {
				$this->set404();
			}
		} elseif (get_query_var(W2DC_LOCATIONS_TAX)) { // locations
			if ($location_object = w2dc_isLocation()) {
				$this->is_location = true;
				$this->term = $location_object;
				$this->location = $location_object;
				$this->template = 'frontend/location.tpl.php';
				$this->page_title = $location_object->name;
				
				if (get_option('w2dc_main_search')) {
					$this->search_form = new w2dc_search_form($this->hash, array('form_id' => get_option('w2dc_search_form_id')));
				}
				
				$args = apply_filters("w2dc_query_input_args", $shortcode_atts);
				
				$args['perpage'] = w2dc_getValue($shortcode_atts, 'perpage', (int)get_option('w2dc_listings_number_excerpt'));
				$args['paged'] = $paged;
				
				$get_orderby_args = $this->getOrderByArgs($args);
				$args = array_merge($args, $get_orderby_args);
					
				$query = new w2dc_search_query($args);
				$this->query = $query->get_query();
				$this->processQuery();
				//var_dump($this->query->request);
				
				if (w2dc_is_maps_used() && get_option('w2dc_map_on_excerpt')) {
					$map_args = $this->getDefaultMapArgs($args);
					
					if (get_option('w2dc_map_markers_is_limit')) {
						
						$this->map = new w2dc_maps($map_args);
						$this->map->setUniqueId($this->hash);
							
						foreach ($this->listings AS $listing) {
							$this->map->collectLocations($listing);
						}
					} else {
						$map_controller = new w2dc_map_controller();
						$map_controller->init($map_args);
							
						$this->map = $map_controller->map;
					}
				}
				
				$this->base_url = get_term_link($location_object, W2DC_LOCATIONS_TAX);
				$this->page_url = $this->base_url;
					
				// pass order args into listings_block.tpl.php
				$this->args = $get_orderby_args;
				$this->args['locations'] = $location_object->term_id;
				
				if (get_option('w2dc_enable_breadcrumbs')) {
					$this->addBreadCrumbs(w2dc_get_term_parents($location_object, W2DC_LOCATIONS_TAX, true, true));
				}
			} else {
				$this->set404();
			}
		} elseif (get_query_var(W2DC_TAGS_TAX)) {		// tags
			if ($tag_object = w2dc_isTag()) {
				$this->is_tag = true;
				$this->term = $tag_object;
				$this->tag = $tag_object;
				$this->template = 'frontend/tag.tpl.php';
				$this->page_title = $tag_object->name;
				
				if (get_option('w2dc_main_search')) {
					$this->search_form = new w2dc_search_form($this->hash, array('form_id' => get_option('w2dc_search_form_id')));
				}
				
				$args = apply_filters("w2dc_query_input_args", $shortcode_atts);
				
				$args['perpage'] = w2dc_getValue($shortcode_atts, 'perpage', (int)get_option('w2dc_listings_number_excerpt'));
				$args['paged'] = $paged;
				
				$get_orderby_args = $this->getOrderByArgs($args);
				$args = array_merge($args, $get_orderby_args);
					
				$query = new w2dc_search_query($args);
				$this->query = $query->get_query();
				$this->processQuery();
				//var_dump($this->query->request);
				
				if (w2dc_is_maps_used() && get_option('w2dc_map_on_excerpt')) {
					$map_args = $this->getDefaultMapArgs($args);
					
					if (get_option('w2dc_map_markers_is_limit')) {
						
						$this->map = new w2dc_maps($map_args);
						$this->map->setUniqueId($this->hash);
							
						foreach ($this->listings AS $listing) {
							$this->map->collectLocations($listing);
						}
					} else {
						$map_controller = new w2dc_map_controller();
						$map_controller->init($map_args);
							
						$this->map = $map_controller->map;
					}
				}
				
				$this->base_url = get_term_link($tag_object, W2DC_TAGS_TAX);
				$this->page_url = $this->base_url;
					
				// pass order args into listings_block.tpl.php
				$this->args = $get_orderby_args;
				$this->args['tags'] = $tag_object->term_id;
				
				if (get_option('w2dc_enable_breadcrumbs')) {
					$this->addBreadCrumbs(w2dc_get_term_parents($tag_object, W2DC_TAGS_TAX, true, true));
				}
			} else {
				$this->set404();
			}
		} elseif ($w2dc_instance->action == 'myfavourites') {		// favourites
			$this->is_favourites = true;
			$this->template = 'frontend/favourites.tpl.php';
			$this->page_title = __("My bookmarks", "W2DC");

			$args = apply_filters("w2dc_query_input_args", $shortcode_atts);
			
			if (!$favourites = w2dc_checkQuickList()) {
				$favourites = array(0);
			}
			$args['post__in'] = $favourites;
			$args['perpage'] = w2dc_getValue($shortcode_atts, 'perpage', (int)get_option('w2dc_listings_number_excerpt'));
			
			$query = new w2dc_search_query($args);
			$this->query = $query->get_query();
			$this->processQuery();
			
			if (get_option('w2dc_enable_breadcrumbs')) {
				$this->addBreadCrumbs(esc_html__('My bookmarks', 'W2DC'));
			}
			$this->args['hide_order'] = 1;
		} elseif (!$w2dc_instance->action && $shortcode == W2DC_MAIN_SHORTCODE && !wcsearch_get_query_string()) {		// index
			$this->template = 'frontend/index.tpl.php';
			$this->page_title = get_post($w2dc_instance->index_page_id)->post_title;

			if (get_option('w2dc_main_search')) {
				$this->search_form = new w2dc_search_form($this->hash, array('form_id' => get_option('w2dc_search_form_id')));
			}
			
			$args = apply_filters("w2dc_query_input_args", $shortcode_atts);
			
			$args['perpage'] = w2dc_getValue($shortcode_atts, 'perpage', (int)get_option('w2dc_listings_number_index'));
			$args['paged'] = $paged;
			
			$get_orderby_args = $this->getOrderByArgs($args);
			$args = array_merge($args, $get_orderby_args);
			
			if (get_option('w2dc_listings_on_index') || get_option('w2dc_map_on_index')) {
				$query = new w2dc_search_query($args);
				$this->query = $query->get_query();
				$this->processQuery();
				//var_dump($this->query->request);
			}
			
			if (get_option('w2dc_map_on_index')) {
				$map_args = $this->getDefaultMapArgs($args);
				
				if (get_option('w2dc_map_markers_is_limit')) {
					
					$this->map = new w2dc_maps($map_args);
					$this->map->setUniqueId($this->hash);
						
					foreach ($this->listings AS $listing) {
						$this->map->collectLocations($listing);
					}
				} else {
					$map_controller = new w2dc_map_controller();
					$map_controller->init($map_args);
						
					$this->map = $map_controller->map;
				}
			}

			$this->base_url = add_query_arg(wcsearch_get_query_string(), get_permalink(get_the_ID()));
			$this->page_url = get_permalink(get_the_ID());
			
			// pass default args from shortcode params into listings_block.tpl.php
			$this->args = $args;
		} elseif ($query_string = wcsearch_get_query_string()) {		// search
			$this->is_search = true;
			$this->template = 'frontend/search.tpl.php';
			$this->page_title = __("Search results", "W2DC");
			
			if (get_option('w2dc_main_search')) {
				$this->search_form = new w2dc_search_form($this->hash, array('form_id' => get_option('w2dc_search_form_id')));
			}
			
			$args = apply_filters("w2dc_query_input_args", $shortcode_atts);
			
			$args['perpage'] = w2dc_getValue($shortcode_atts, 'perpage', (int)get_option('w2dc_listings_number_excerpt'));
			$args['paged'] = $paged;
			
			$get_orderby_args = $this->getOrderByArgs($args);
			$args = array_merge($args, $get_orderby_args);
			
			$query = new w2dc_search_query($args);
			$this->query = $query->get_query();
			$this->processQuery();
			
			if (w2dc_is_maps_used() && get_option('w2dc_map_on_excerpt')) {
				$map_args = $this->getDefaultMapArgs();
				
				if (get_option('w2dc_map_markers_is_limit')) {
					
					$this->map = new w2dc_maps($map_args);
					$this->map->setUniqueId($this->hash);
						
					foreach ($this->listings AS $listing) {
						$this->map->collectLocations($listing);
					}
				} else {
					$map_controller = new w2dc_map_controller();
					$map_controller->init($map_args);
						
					$this->map = $map_controller->map;
				}
			}
			
			$this->base_url = add_query_arg(wcsearch_get_query_string(), get_permalink(get_the_ID()));
			$this->page_url = get_permalink(get_the_ID());
			
			// pass order args into listings_block.tpl.php
			$this->args = $get_orderby_args;
		}
		
		$this->args['directories'] = (!empty($shortcode_atts['directories']) ? $shortcode_atts['directories'] : $w2dc_instance->current_directory->id);
		$this->args['is_home'] = $this->is_home;
		$this->args['paged'] = $paged;
		$this->args['custom_home'] = (int)$this->custom_home;

		$this->args['onepage'] = 0;
		$this->args['hide_paginator'] = 0;
		$this->args['hide_count'] = w2dc_getValue($shortcode_atts, 'hide_count', (int)(!(get_option('w2dc_show_listings_count'))));
		$this->args['hide_content'] = w2dc_getValue($shortcode_atts, 'hide_content', 0);
		// Hide order on My Favourites page
		if (!isset($this->args['hide_order'])) {
			$this->args['hide_order'] = w2dc_getValue($shortcode_atts, 'hide_order', (int)(!(get_option('w2dc_show_orderby_links'))));
		}
		$this->args['show_views_switcher'] = w2dc_getValue($shortcode_atts, 'show_views_switcher', (int)get_option('w2dc_views_switcher'));
		$this->args['listings_view_type'] = w2dc_getValue($shortcode_atts, 'listings_view_type', get_option('w2dc_views_switcher_default'));
		$this->args['listings_view_grid_columns'] = w2dc_getValue($shortcode_atts, 'listings_view_grid_columns', (int)get_option('w2dc_views_switcher_grid_columns'));
		$this->args['listing_thumb_width'] = w2dc_getValue($shortcode_atts, 'listing_thumb_width', (int)get_option('w2dc_listing_thumb_width'));
		$this->args['wrap_logo_list_view'] = w2dc_getValue($shortcode_atts, 'wrap_logo_list_view', (int)get_option('w2dc_wrap_logo_list_view'));
		$this->args['logo_animation_effect'] = w2dc_getValue($shortcode_atts, 'logo_animation_effect', (int)get_option('w2dc_logo_animation_effect'));
		$this->args['grid_view_logo_ratio'] = w2dc_getValue($shortcode_atts, 'grid_view_logo_ratio', get_option('w2dc_grid_view_logo_ratio'));
		$this->args['scrolling_paginator'] = w2dc_getValue($shortcode_atts, 'scrolling_paginator', 0);
		$this->args['show_summary_button'] = 1;
		$this->args['show_readmore_button'] = 1;
		
		if (get_option("w2dc_imitate_mode")) {
			
			if (!is_plugin_active('wordpress-seo/wp-seo.php') && !is_plugin_active('wordpress-seo-premium/wp-seo-premium.php')) {
				// since WP 4.4, just use the new hook.
				add_filter('pre_get_document_title', array($this, 'page_title'), 16);
				add_filter('wp_title', array($this, 'page_title'), 10, 2);
				
				if (function_exists('rel_canonical')) {
					remove_action('wp_head', 'rel_canonical');
				}
				// replace the default WordPress canonical URL function with your own
				add_action('wp_head', array($this, 'rel_canonical_with_custom_tag_override'));
			}
			
			if (get_option('w2dc_overwrite_page_title')) {
				add_filter('the_title', array($this, 'setThemePageTitle'), 10, 2);
			}
		}
		
		// place levels="" parameter into the shortcode
		if ($this->levels_ids) {
			remove_filter('posts_join', 'w2dc_join_levels');
			remove_filter('posts_where', array($this, 'where_levels_ids'));
		}
	
		// adapted for WPML
		add_filter('icl_ls_languages', array($this, 'adapt_wpml_urls'));

		// this is possible to build custom home page instead of static set of blocks
		if (!$this->is_single && $this->custom_home) {
			$this->template = 'frontend/listings_block.tpl.php';
		}
		
		$this->template = apply_filters('w2dc_frontend_controller_template', $this->template, $this);

		apply_filters('w2dc_directory_controller_construct', $this);
	}
	
	public function getDefaultMapArgs($args = array()) {
		
		$map_args = array(
				'hash' => $this->hash,
				'query_string' => wcsearch_get_query_string(),
				'start_address' => '',
				'start_zoom' => get_option('w2dc_start_zoom'),
				'min_zoom' => get_option('w2dc_map_min_zoom'),
				'max_zoom' => get_option('w2dc_map_max_zoom'),
				'geolocation' => get_option('w2dc_enable_geolocation'),
				'map_markers_is_limit' => get_option('w2dc_map_markers_is_limit'),
				'search_on_map' => get_option('w2dc_search_on_map'),
				'search_on_map_id' => get_option('w2dc_search_map_form_id'),
				'search_on_map_open' => 0,
				'search_on_map_right' => 0,
				'search_on_map_listings' => 'sidebar',
		);
		
		$map_args = array_merge($map_args, $args);
		
		$map_args = apply_filters("w2dc_default_map_args_directory_controller", $map_args);
		
		return $map_args;
	}
	
	public function getOrderByArgs($args) {
		
		$order_by = wcsearch_get_query_string('order_by');
		$address = wcsearch_get_query_string('address');
		$radius = wcsearch_get_query_string('radius');
		$place_id = wcsearch_get_query_string('place_id');
		
		if ((!$order_by || $order_by == 'distance') && ($address || $place_id) && $radius && get_option('w2dc_orderby_distance')) {
			$get_orderby_args['order_by'] = 'distance';
			$get_orderby_args['order'] = 'ASC';
		} else {
			$get_orderby_args = array(
					'order_by' => w2dc_getValue($_GET, "order_by", get_option('w2dc_default_orderby')),
					'order' => w2dc_getValue($_GET, "order", get_option('w2dc_default_order'))
			);
			array_walk_recursive($get_orderby_args, 'sanitize_text_field');
		}
		
		return $get_orderby_args;
	}
	
	public function set404() {
		global $wp_query;
		$wp_query->set_404();
		status_header(404);
	}
	
	public function setThemePageTitle($title, $id = null) {
		global $w2dc_instance;
	
		if (
			!is_admin() &&
			/* !in_the_loop() && */
			is_page() &&
			($w2dc_instance->index_page_id == $id || in_array($id, $w2dc_instance->listing_pages_all))
		) {
			return $this->getPageTitle();
		} else {
			return $title;
		}
	}

	public function tempLangToWPML() {
		return $this->temp_lang;
	}
	
	// adapted for WPML
	public function adapt_wpml_urls($w_active_languages) {
		global $sitepress, $w2dc_instance;

		// WPML will not switch language using $sitepress->switch_lang() function when there is 'lang=' parameter in the URL, so we have to use such hack
		if ($sitepress->get_option('language_negotiation_type') == 3)
			remove_all_filters('icl_current_language');

		foreach ($w_active_languages AS $key=>&$language) {
			$sitepress->switch_lang($language['language_code']);
			$this->temp_lang = $language['language_code'];
			add_filter('icl_current_language', array($this, 'tempLangToWPML'));
			$w2dc_instance->getAllDirectoryPages();
			$w2dc_instance->getIndexPage();
			$w2dc_instance->directories->setDirectoriesURLs();

			$is_w2dc_page = false;
			$w2dc_page_url = false;
			if ($this->is_single || $this->is_category || $this->is_location || $this->is_tag || $this->is_favourites) {
				$is_w2dc_page = true;
			}

			if ($this->is_single && ($tobject_post_id = apply_filters('wpml_object_id', $this->object_single->post->ID, W2DC_POST_TYPE, false, $language['language_code']))) {
				$w2dc_page_url = get_permalink($tobject_post_id);
			}
			if ($this->is_category && ($tterm_id = apply_filters('wpml_object_id', $this->category->term_id, W2DC_CATEGORIES_TAX, false, $language['language_code']))) {
				$tterm = get_term($tterm_id, W2DC_CATEGORIES_TAX);
				$w2dc_page_url = get_term_link($tterm);
			}
			if ($this->is_location && ($tterm_id = apply_filters('wpml_object_id', $this->location->term_id, W2DC_LOCATIONS_TAX, false, $language['language_code']))) {
				$tterm = get_term($tterm_id, W2DC_LOCATIONS_TAX);
				$w2dc_page_url = get_term_link($tterm, W2DC_LOCATIONS_TAX);
			}
			if ($this->is_tag && ($tterm_id = apply_filters('wpml_object_id', $this->tag->term_id, W2DC_TAGS_TAX, false, $language['language_code']))) {
				$tterm = get_term($tterm_id, W2DC_TAGS_TAX);
				$w2dc_page_url = get_term_link($tterm, W2DC_TAGS_TAX);
			}
			if ($this->is_favourites) {
				$w2dc_page_url = w2dc_directoryUrl(array('w2dc_action' => 'myfavourites'));
			}

			// show links only to pages, which have translations
			if ($is_w2dc_page) {
				if ($w2dc_page_url)
					$language['url'] = $w2dc_page_url;
				else
					unset($w_active_languages[$key]);
			}

			remove_filter('icl_current_language', array($this, 'tempLangToWPML'));
		}
		$sitepress->switch_lang(ICL_LANGUAGE_CODE);
		$w2dc_instance->getAllDirectoryPages();
		$w2dc_instance->getIndexPage();
		$w2dc_instance->directories->setDirectoriesURLs();
		return $w_active_languages;
	}

	// Add listing ID to query string while rendering Contact Form 7
	public function w2dc_add_listing_id_to_wpcf7($url) {
		if ($this->is_single) {
			$url = esc_url(add_query_arg('listing_id', $this->listing->post->ID, $url));
		}
		
		return $url;
	}
	// Add listing ID to hidden fields while rendering Contact Form 7
	public function w2dc_add_listing_id_to_wpcf7_field($fields) {
		if ($this->is_single) {
			$fields["listing_id"] = $this->listing->post->ID;
		}
		
		return $fields;
	}
	// Add duplicated hidden tag _wpcf7_container_post to set real post ID,
	// we can not overwrite _wpcf7_container_post in wpcf7_form_hidden_fields filter
	public function w2dc_add_wpcf7_container_post($tags) {
		if ($this->is_single) {
			$tags = '<input type="hidden" name="_wpcf7_container_post" value="' . $this->listing->post->ID . '" />' . $tags;
		}
	
		return $tags;
	}
	
	public function configure_seo_filters() {
		if ($this->is_home || $this->is_single || $this->is_search || $this->is_category || $this->is_location || $this->is_tag || $this->is_favourites || $this->is_directory_page) {
				
			// since WP 4.4, just use the new hook.
			add_filter('pre_get_document_title', array($this, 'page_title'), 16);
			add_filter('wp_title', array($this, 'page_title'), 10, 2);
		}
	}
	
	public function page_title($title, $separator = ' - ') {

		if ($this->getPageTitle()) {
			$title = $this->getPageTitle() . ' ' . $separator . ' ';
		}
		if (w2dc_get_wpml_dependent_option('w2dc_directory_title')) {
			$title .= w2dc_get_wpml_dependent_option('w2dc_directory_title');
		} else {
			$title .= get_option('blogname');
		}
	
		return $title;
	}
	
	// rewrite canonical URL
	public function rel_canonical_with_custom_tag_override() {
		
		if (!is_plugin_active('wordpress-seo/wp-seo.php') && !is_plugin_active('wordpress-seo-premium/wp-seo-premium.php')) {
			
			$permalink = false;
			if ($this->is_single) {
				$permalink = get_permalink($this->object_single->post->ID);
			}
			if ( $this->is_category || $this->is_location || $this->is_tag) {
				$permalink = get_term_link($this->term);
			}
			
			if ($permalink) {
				echo '<link rel="canonical" href="' . $permalink . '" />
';
			}
		}
	}
	
	// Adding the Open Graph in the Language Attributes
	public function add_opengraph_doctype($output) {
		
		if (!is_plugin_active('wordpress-seo/wp-seo.php') && !is_plugin_active('wordpress-seo-premium/wp-seo-premium.php')) {
			return $output . ' xmlns:og="http://opengraphprotocol.org/schema/" xmlns:fb="http://www.facebook.com/2008/fbml"';
		}
		
		return $output;
	}
	
	// Lets add Open Graph Meta Info
	public function insert_fb_in_head() {
		
		if (!is_plugin_active('wordpress-seo/wp-seo.php') && !is_plugin_active('wordpress-seo-premium/wp-seo-premium.php')) {
			
			echo '<meta property="og:type" content="article" data-w2dc-og-meta="true" />
';
			echo '<meta property="og:title" content="' . $this->og_title() . '" />
';
			echo '<meta property="og:description" content="' . $this->og_description() . '" />
';
			echo '<meta property="og:url" content="' . $this->og_url() . '" />
';
			echo '<meta property="og:site_name" content="' . $this->og_site_name() . '" />
';
			if ($thumbnail_src = $this->og_image()) {
			echo '<meta property="og:image" content="' . esc_attr($thumbnail_src) . '" />
';
			}
		}
	
		add_filter('wpseo_opengraph_title', array($this, 'og_title'), 10, 2);
		add_filter('wpseo_opengraph_desc', array($this, 'og_description'), 10, 2);
		add_filter('wpseo_opengraph_url', array($this, 'og_url'), 10, 2);
		add_filter('wpseo_opengraph_image', array($this, 'og_image'), 10, 2);
		add_filter('wpseo_opengraph_site_name', array($this, 'og_site_name'), 10, 2);
	}
	
	public function og_title() {
		return esc_attr($this->object_single->title()) . ' - ' . w2dc_get_wpml_dependent_option('w2dc_directory_title');
	}
	
	public function og_description() {
		if ($this->object_single->post->post_excerpt) {
			$excerpt = $this->object_single->post->post_excerpt;
		} else {
			$excerpt = $this->object_single->getExcerptFromContent();
		}
	
		return esc_attr($excerpt);
	}
	
	public function og_url() {
		return get_permalink($this->object_single->post->ID);
	}
	
	public function og_site_name() {
		return w2dc_get_wpml_dependent_option('w2dc_directory_title');
	}
	
	public function og_image() {
		return $this->object_single->get_logo_url();
	}
}

add_action('init', 'w2dc_handle_wpcf7');
function w2dc_handle_wpcf7() {
	if (defined('WPCF7_VERSION')) {
		if (get_option('w2dc_listing_contact_form') && defined('WPCF7_VERSION') && w2dc_get_wpml_dependent_option('w2dc_listing_contact_form_7')) {
			add_filter('wpcf7_mail_components', 'w2dc_wpcf7_handle_email', 10, 2);
		}
			
		function w2dc_wpcf7_handle_email($WPCF7_components, $WPCF7_currentform) {
			if (isset($_REQUEST['listing_id'])) {
				$post = get_post($_REQUEST['listing_id']);
	
				$mail = $WPCF7_currentform->prop('mail');
				// DO not touch mail_2
				if ($mail['recipient'] == $WPCF7_components['recipient']) {
					if ($post && isset($_POST['_wpcf7']) && preg_match_all('/'.get_shortcode_regex().'/s', w2dc_get_wpml_dependent_option('w2dc_listing_contact_form_7'), $matches)) {
						foreach ($matches[2] AS $key=>$shortcode) {
							if ($shortcode == 'contact-form-7') {
								if ($attrs = shortcode_parse_atts($matches[3][$key])) {
									if (isset($attrs['id']) && $attrs['id'] == $_POST['_wpcf7']) {
										$contact_email = null;
										if (get_option('w2dc_custom_contact_email') && ($listing = w2dc_getListing($post)) && $listing->contact_email) {
											$contact_email = $listing->contact_email;
										} elseif (($listing_owner = get_userdata($post->post_author)) && $listing_owner->user_email) {
											$contact_email = $listing_owner->user_email;
										}
										if ($contact_email) {
											$WPCF7_components['recipient'] .= ','.$contact_email;
										}
									}
								}
							}
						}
					}
				}
			}
			return $WPCF7_components;
		}
	}
}

?>