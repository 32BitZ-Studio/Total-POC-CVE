<?php

class w2dc_admin {

	public function __construct() {
		global $w2dc_instance;

		add_action('admin_menu', array($this, 'menu'));

		$w2dc_instance->settings_manager = new w2dc_settings_manager;

		$w2dc_instance->levels_manager = new w2dc_levels_manager;

		$w2dc_instance->listings_manager = new w2dc_listings_manager;

		$w2dc_instance->locations_manager = new w2dc_locations_manager;

		$w2dc_instance->locations_levels_manager = new w2dc_locations_levels_manager;

		$w2dc_instance->categories_manager = new w2dc_categories_manager;

		$w2dc_instance->content_fields_manager = new w2dc_content_fields_manager;

		$w2dc_instance->media_manager = new w2dc_media_manager;

		$w2dc_instance->csv_manager = new w2dc_csv_manager;
		
		$w2dc_instance->demo_data_manager = new w2dc_demo_data_manager;
		
		add_filter('w2dc_build_settings', array($this, 'addAddonsSettings'));

		add_action('admin_menu', array($this, 'addChooseLevelPage'));
		add_action('load-post-new.php', array($this, 'handleLevel'));

		// hide some meta-blocks when create/edit posts
		add_action('admin_init', array($this, 'hideMetaBoxes'));
		add_filter('default_hidden_meta_boxes', array($this, 'showAuthorMetaBox'), 10, 2);
		
		add_action('admin_head-post-new.php', array($this, 'hidePreviewButton'));
		add_action('admin_head-post.php', array($this, 'hidePreviewButton'));
		
		add_filter('post_row_actions', array($this, 'removeQuickEdit'), 10, 2);
		add_filter('quick_edit_show_taxonomy', array($this, 'removeQuickEditTax'), 10, 2);

		add_action('admin_enqueue_scripts', array($this, 'admin_enqueue_scripts_styles'), 0);
		add_action('admin_print_scripts', array($w2dc_instance, 'dequeue_maps_googleapis'), 1000);
		
		add_filter('admin_body_class', array($this, 'addBodyClasses'));

		add_action('wp_ajax_w2dc_generate_color_palette', array($this, 'generate_color_palette'));
		add_action('wp_ajax_nopriv_w2dc_generate_color_palette', array($this, 'generate_color_palette'));
		add_action('wp_ajax_w2dc_get_jqueryui_theme', array($this, 'get_jqueryui_theme'));
		add_action('wp_ajax_nopriv_w2dc_get_jqueryui_theme', array($this, 'get_jqueryui_theme'));
		add_action('vp_w2dc_option_before_ajax_save', array($this, 'remove_colorpicker_cookie'));
		add_action('wp_footer', array($this, 'render_palette_picker'));
		
		add_action('admin_notices', array($this, 'renderAdminMessages'));
	}
	
	public function renderAdminMessages() {
		global $pagenow;
		
		if (!empty($_GET['page']) && $_GET['page'] == 'w2dc_settings') {
			echo '<div class="notice notice-info is-dismissible">
				<p>Love Web 2.0 Directory plugin? Consider buying full version at <a href="https://www.salephpscripts.com">salephpscripts.com</a></p>
			</div>';
		}
		
		if ((($pagenow == 'edit.php' || $pagenow == 'post-new.php') && ($post_type = w2dc_getValue($_GET, 'post_type')) &&
				(in_array($post_type, array(W2DC_POST_TYPE, 'w2dc_invoice')))
		) ||
		($pagenow == 'post.php' && ($post_id = w2dc_getValue($_GET, 'post')) && ($post = get_post($post_id)) && w2dc_getValue($_GET, 'action') == 'edit' &&
				(in_array($post->post_type, array(W2DC_POST_TYPE, 'w2dc_invoice', 'shop_order', 'shop_subscription')))
		) ||
		(($pagenow == 'edit-tags.php' || $pagenow == 'term.php') && ($taxonomy = w2dc_getValue($_GET, 'taxonomy')) &&
				(in_array($taxonomy, array(W2DC_LOCATIONS_TAX, W2DC_CATEGORIES_TAX, W2DC_TAGS_TAX)))
		)) {
			w2dc_renderMessages();
		}
	}

	public function addChooseLevelPage() {
		add_submenu_page('options.php',
			__('Choose level of new listing', 'W2DC'),
			__('Choose level of new listing', 'W2DC'),
			'publish_posts',
			'w2dc_choose_level',
			array($this, 'chooseLevelsPage')
		);
	}

	// Special page to choose the level for new listing
	public function chooseLevelsPage() {
		global $w2dc_instance;

		$w2dc_instance->levels_manager->displayChooseLevelTable();
	}
	
	public function handleLevel() {
		global $w2dc_instance;

		if (isset($_GET['post_type']) && $_GET['post_type'] == W2DC_POST_TYPE) {
			if (!isset($_GET['level_id'])) {
				// adapted for WPML
				global $sitepress;
				if (function_exists('wpml_object_id_filter') && $sitepress && isset($_GET['trid']) && isset($_GET['lang']) && isset($_GET['source_lang'])) {
					global $sitepress;
					$listing_id = $sitepress->get_original_element_id_by_trid($_GET['trid']);
					
					$listing = new w2dc_listing();
					$listing->loadListingFromPost($listing_id);
					wp_redirect(add_query_arg(array('post_type' => 'w2dc_listing', 'level_id' => $listing->level->id, 'trid' => $_GET['trid'], 'lang' => $_GET['lang'], 'source_lang' => $_GET['source_lang']), admin_url('post-new.php')));
				} else {
					if (count($w2dc_instance->levels->levels_array) != 1) {
						wp_redirect(add_query_arg('page', 'w2dc_choose_level', admin_url('options.php')));
					} else {
						$single_level = array_shift($w2dc_instance->levels->levels_array);
						wp_redirect(add_query_arg(array('post_type' => 'w2dc_listing', 'level_id' => $single_level->id), admin_url('post-new.php')));
					}
				}
				die();
			}
		}
	}

	public function menu() {
		if (defined('W2DC_DEMO') && W2DC_DEMO) {
			$capability = 'publish_posts';
		} else {
			$capability = 'manage_options';
		}

		add_menu_page(__("Directory settings", "W2DC"),
			__('Directory Admin', 'W2DC'),
			$capability,
			'w2dc_settings',
			'',
			W2DC_RESOURCES_URL . 'images/menuicon.png'
		);
		add_submenu_page(
			'w2dc_settings',
			__("Directory settings", "W2DC"),
			__("Directory settings", "W2DC"),
			$capability,
			'w2dc_settings'
		);

		add_submenu_page(
			'',
			__("Directory Debug", "W2DC"),
			__("Directory Debug", "W2DC"),
			$capability,
			'w2dc_debug',
			array($this, 'debug')
		);
		add_submenu_page(
			'',
			__("Directory Reset", "W2DC"),
			__("Directory Reset", "W2DC"),
			'manage_options',
			'w2dc_reset',
			array($this, 'reset')
		);
	}

	public function debug() {
		global $w2dc_instance, $wpdb;
		
		$w2dc_locationGeoname = new w2dc_locationGeoname();
		$geolocation_response = $w2dc_locationGeoname->geocodeRequest('1600 Amphitheatre Parkway Mountain View, CA 94043', 'test');

		$settings = $wpdb->get_results("SELECT option_name, option_value FROM {$wpdb->options} WHERE option_name LIKE 'w2dc_%'", ARRAY_A);

		w2dc_renderTemplate('debug.tpl.php', array(
			'rewrite_rules' => get_option('rewrite_rules'),
			'geolocation_response' => $geolocation_response,
			'settings' => $settings,
			'levels' => $w2dc_instance->levels,
			'content_fields' => $w2dc_instance->content_fields,
		));
	}

	public function reset() {
		global $w2dc_instance, $wpdb;
		
		if (isset($_GET['reset']) && $_GET['reset'] == 'installation') {
			if (delete_option('w2dc_installed_directory')) {
				w2dc_save_dynamic_css();
				w2dc_addMessage('Directory installation will be repeated!');
			}
		}
		if (isset($_GET['reset']) && ($_GET['reset'] == 'settings' || $_GET['reset'] == 'settings_tables')) {
			if ($wpdb->query("DELETE FROM $wpdb->options WHERE option_name LIKE 'w2dc_%'") !== false) {
				delete_option('vpt_option');
				w2dc_save_dynamic_css();
				w2dc_addMessage('All directory settings were deleted!');
			}
		}
		if (isset($_GET['reset']) && $_GET['reset'] == 'settings_tables') {
			$wpdb->query("DROP TABLE IF EXISTS $wpdb->w2dc_content_fields_groups");
			$wpdb->query("DROP TABLE IF EXISTS $wpdb->w2dc_content_fields");
			$wpdb->query("DROP TABLE IF EXISTS $wpdb->w2dc_directories");
			$wpdb->query("DROP TABLE IF EXISTS $wpdb->w2dc_levels");
			$wpdb->query("DROP TABLE IF EXISTS $wpdb->w2dc_levels_relationships");
			$wpdb->query("DROP TABLE IF EXISTS $wpdb->w2dc_locations_levels");
			$wpdb->query("DROP TABLE IF EXISTS $wpdb->w2dc_locations_relationships");
			w2dc_addMessage('W2DC database tables were dropped!');
		}
		w2dc_renderTemplate('reset.tpl.php');
	}
	
	public function hideMetaBoxes() {
		global $post, $pagenow;

		if (($pagenow == 'post-new.php' && isset($_GET['post_type']) && $_GET['post_type'] == W2DC_POST_TYPE) || ($pagenow == 'post.php' && $post && $post->post_type == W2DC_POST_TYPE)) {
			$user_id = get_current_user_id();
			update_user_meta($user_id, 'metaboxhidden_' . W2DC_POST_TYPE, array('trackbacksdiv', 'commentstatusdiv', 'postcustom'));
		}
	}
	
	public function showAuthorMetaBox($hidden, $screen) {
		if ($screen->post_type == W2DC_POST_TYPE) {
			if ($key = array_search('authordiv', $hidden)) {
				unset($hidden[$key]);
			}
		}
	
		return $hidden;
	}

	public function hidePreviewButton() {
		global $post_type;
		
    	if ($post_type == W2DC_POST_TYPE) {
    		echo '<style type="text/css">#preview-action {display: none;}</style>';
    	}
	}

	public function removeQuickEdit($actions, $post) {
		if ($post->post_type == W2DC_POST_TYPE) {
			unset($actions['inline hide-if-no-js']);
			unset($actions['view']);
		}
		return $actions;
	}

	public function removeQuickEditTax($show_in_quick_edit, $taxonomy_name) {
		if ($taxonomy_name == W2DC_CATEGORIES_TAX || $taxonomy_name == W2DC_LOCATIONS_TAX)
			$show_in_quick_edit = false;
		
		return $show_in_quick_edit;
	}
	
	public function addBodyClasses($classes) {
		return "$classes w2dc-body";
	}
	
	public function addAddonsSettings($options) {
		$options['template']['menus']['general']['controls'] = array_merge(
				array('addons' => array(
					'type' => 'section',
					'title' => __('Addons', 'W2DC'),
					'description' => __('Refresh this page after switch on/off any addon.', 'W2DC'),
					'fields' => array(
					 	array(
							'type' => 'toggle',
							'name' => 'w2dc_ratings_addon',
							'label' => __('Ratings & Comments addon', 'W2DC'),
					 		'description' => __('Ability to place ratings and comments for listings.', 'W2DC'),
							'default' => get_option('w2dc_ratings_addon'),
						),
					),
				)),
				$options['template']['menus']['general']['controls']
		);
		
		return $options;
	}
	
	public function admin_enqueue_scripts_styles($hook) {
		global $w2dc_instance;
		
		// include admin.css, rtl.css, bootstrap, custom.css and datepicker files in admin,
		// also in customizer and required for VC plugin, SiteOrigin plugin and widgets
		if (
			w2dc_isDirectoryPageInAdmin() ||
			is_customize_preview() ||
			$hook == "widgets.php" ||
			get_post_meta(get_the_ID(), '_wpb_vc_js_status', true)
		) {
			wp_enqueue_script('jquery-ui-datepicker');
			wp_register_style('w2dc-jquery-ui-style', W2DC_RESOURCES_URL . 'css/jquery-ui/themes/smoothness/jquery-ui.css');
			wp_enqueue_style('w2dc-jquery-ui-style');
			if ($i18n_file = w2dc_getDatePickerLangFile(get_locale())) {
				wp_register_script('datepicker-i18n', $i18n_file, array('jquery-ui-datepicker'));
				wp_enqueue_script('datepicker-i18n');
			}
			
			if (is_customize_preview())
				$this->enqueue_global_vars();
			else
				add_action('admin_head', array($this, 'enqueue_global_vars'));
			
			wp_register_style('w2dc_bootstrap', W2DC_RESOURCES_URL . 'css/bootstrap.css', array(), W2DC_VERSION_TAG);
			wp_register_style('w2dc_admin', W2DC_RESOURCES_URL . 'css/admin.css', array(), W2DC_VERSION_TAG);
			if (function_exists('is_rtl') && is_rtl()) {
				wp_register_style('w2dc_admin_rtl', W2DC_RESOURCES_URL . 'css/admin-rtl.css', array(), W2DC_VERSION_TAG);
			}
			
			if ($admin_custom = w2dc_isResource('css/admin-custom.css')) {
				wp_register_style('w2dc_admin-custom', $admin_custom, array(), W2DC_VERSION_TAG);
			}
		}
		
		if (w2dc_isDirectoryPageInAdmin()) {
			// some plugins decide to disable this thing
			//wp_enqueue_script('jquery-migrate');
			
			add_action('wp_print_scripts', array($w2dc_instance, 'dequeue_maps_googleapis'), 1000);

			wp_register_style('w2dc_font_awesome', W2DC_RESOURCES_URL . 'css/font-awesome.css', array(), W2DC_VERSION_TAG);
			wp_register_script('w2dc_js_functions', W2DC_RESOURCES_URL . 'js/js_functions.js', array('jquery'), false, true);

			wp_register_script('w2dc_categories_edit_scripts', W2DC_RESOURCES_URL . 'js/categories_icons.js', array('jquery'));
			wp_register_script('w2dc_categories_scripts', W2DC_RESOURCES_URL . 'js/manage_categories.js', array('jquery'));
			
			wp_register_script('w2dc_locations_edit_scripts', W2DC_RESOURCES_URL . 'js/locations_icons.js', array('jquery'));
			
			wp_register_style('w2dc_media_styles', W2DC_RESOURCES_URL . 'lightbox/css/lightbox.min.css', array(), W2DC_VERSION_TAG);
			wp_register_script('w2dc_media_scripts_lightbox', W2DC_RESOURCES_URL . 'lightbox/js/lightbox.js', array('jquery'));
			
			wp_localize_script(
				'w2dc_js_functions',
				'w2dc_maps_callback',
				array(
						'callback' => 'w2dc_load_maps_api_backend'
				)
			);
			
			wp_enqueue_script('jquery-ui-selectmenu');
			wp_enqueue_script('jquery-ui-autocomplete');
		}
		
		wp_enqueue_style('w2dc_bootstrap');
		wp_enqueue_style('w2dc_font_awesome');
		wp_enqueue_style('w2dc_admin');
		wp_enqueue_style('w2dc_admin_rtl');
		wp_enqueue_script('jquery-ui-dialog');
		wp_enqueue_script('w2dc_js_functions');
		wp_enqueue_style('w2dc_admin-custom');
		
		if (w2dc_isDirectoryPageInAdmin() && w2dc_is_maps_used()) {
			if (w2dc_getMapEngine() == 'mapbox') {
				wp_register_script('w2dc_mapbox_gl', 'https://api.tiles.mapbox.com/mapbox-gl-js/' . W2DC_MAPBOX_VERSION . '/mapbox-gl.js');
				wp_enqueue_script('w2dc_mapbox_gl');
				wp_register_style('w2dc_mapbox_gl', 'https://api.tiles.mapbox.com/mapbox-gl-js/' . W2DC_MAPBOX_VERSION . '/mapbox-gl.css');
				wp_enqueue_style('w2dc_mapbox_gl');
				wp_register_script('w2dc_mapbox', W2DC_RESOURCES_URL . 'js/mapboxgl.js', array('jquery'), W2DC_VERSION_TAG, true);
				wp_enqueue_script('w2dc_mapbox');
	
				wp_register_script('w2dc_mapbox_draw', 'https://api.mapbox.com/mapbox-gl-js/plugins/mapbox-gl-draw/v1.4.3/mapbox-gl-draw.js');
				wp_enqueue_script('w2dc_mapbox_draw');
				wp_register_style('w2dc_mapbox_draw', 'https://api.mapbox.com/mapbox-gl-js/plugins/mapbox-gl-draw/v1.4.3/mapbox-gl-draw.css');
				wp_enqueue_style('w2dc_mapbox_draw');
					
				wp_register_script('w2dc_mapbox_directions', 'https://api.mapbox.com/mapbox-gl-js/plugins/mapbox-gl-directions/v4.1.1/mapbox-gl-directions.js');
				wp_enqueue_script('w2dc_mapbox_directions');
				wp_register_style('w2dc_mapbox_directions', 'https://api.mapbox.com/mapbox-gl-js/plugins/mapbox-gl-directions/v4.1.1/mapbox-gl-directions.css');
				wp_enqueue_style('w2dc_mapbox_directions');
					
				if (in_array(get_option('w2dc_mapbox_map_style'), array(
						'mapbox://styles/mapbox/streets-v11',
						'mapbox://styles/mapbox/outdoors-v11',
						'mapbox://styles/mapbox/light-v10',
						'mapbox://styles/mapbox/dark-v10',
				))) {
					wp_register_script('w2dc_mapbox_language', 'https://api.mapbox.com/mapbox-gl-js/plugins/mapbox-gl-language/v1.0.0/mapbox-gl-language.js');
					wp_enqueue_script('w2dc_mapbox_language');
				}
			} else {
				wp_register_script('w2dc_google_maps', W2DC_RESOURCES_URL . 'js/google_maps.js', array('jquery'), W2DC_VERSION_TAG, true);
				wp_enqueue_script('w2dc_google_maps');
			}
		}
	}

	public function enqueue_global_vars() {
		// adapted for WPML
		global $sitepress;
		if (function_exists('wpml_object_id_filter') && $sitepress) {
			$ajaxurl = admin_url('admin-ajax.php?lang=' .  $sitepress->get_current_language());
		} else {
			$ajaxurl = admin_url('admin-ajax.php');
		}

		echo '
<script>
';
		echo 'var w2dc_js_objects = ' . json_encode(
				array(
						'ajaxurl' => $ajaxurl,
						'is_rtl' => (int)is_rtl(),
						'is_maps_used' => (int)w2dc_is_maps_used(),
						'lang' => (($sitepress && get_option('w2dc_map_language_from_wpml')) ? ICL_LANGUAGE_CODE : ''),
						'fields_in_categories' => array(),
						'is_admin' => (int)is_admin(),
						'cancel_button' => __('Cancel', 'W2DC'),
				)
		) . ';
';

		echo 'var w2dc_maps_objects = ' . json_encode(
				array(
						'notinclude_maps_api' => ((defined('W2DC_NOTINCLUDE_MAPS_API') && W2DC_NOTINCLUDE_MAPS_API) ? 1 : 0),
						'google_api_key' => get_option('w2dc_google_api_key'),
						'mapbox_api_key' => get_option('w2dc_mapbox_api_key'),
						'map_markers_type' => get_option('w2dc_map_markers_type'),
						'default_marker_color' => get_option('w2dc_default_marker_color'),
						'default_marker_icon' => get_option('w2dc_default_marker_icon'),
						'global_map_icons_path' => W2DC_MAP_ICONS_URL,
						'marker_image_width' => (int)get_option('w2dc_map_marker_width'),
						'marker_image_height' => (int)get_option('w2dc_map_marker_height'),
						'marker_image_anchor_x' => (int)get_option('w2dc_map_marker_anchor_x'),
						'marker_image_anchor_y' => (int)get_option('w2dc_map_marker_anchor_y'),
						'default_geocoding_location' => get_option('w2dc_default_geocoding_location'),
						'map_style' => w2dc_getSelectedMapStyle(),
						'address_autocomplete' => (int)get_option('w2dc_address_autocomplete'),
						'address_autocomplete_code' => get_option('w2dc_address_autocomplete_code'),
						'enable_my_location_button' => (int)get_option('w2dc_address_geocode'),
						'my_location_button' => __('My Location', 'W2DC'),
						'my_location_button_error' => __('GeoLocation service does not work on your device!', 'W2DC'),
						'default_latitude' => apply_filters('w2dc_default_latitude', 34),
						'default_longitude' => apply_filters('w2dc_default_longitude', 0),
				)
		) . ';
';
		echo '</script>
';
	}

	public function generate_color_palette() {
		ob_start();
		include W2DC_PATH . '/classes/customization/dynamic_css.php';
		$dynamic_css = ob_get_contents();
		ob_get_clean();

		echo $dynamic_css;
		die();
	}

	public function get_jqueryui_theme() {
		global $w2dc_color_schemes;

		if (isset($_COOKIE['w2dc_compare_palettes']) && get_option('w2dc_compare_palettes')) {
			$scheme = $_COOKIE['w2dc_compare_palettes'];
			if ($scheme && isset($w2dc_color_schemes[$scheme]['w2dc_jquery_ui_schemas']))
				echo '//ajax.googleapis.com/ajax/libs/jqueryui/1.10.4/themes/' . $w2dc_color_schemes[$scheme]['w2dc_jquery_ui_schemas'] . '/jquery-ui.css';
		}
		die();
	}
	
	public function remove_colorpicker_cookie($opt) {
		if (isset($_COOKIE['w2dc_compare_palettes'])) {
			unset($_COOKIE['w2dc_compare_palettes']);
			setcookie('w2dc_compare_palettes', '', -1, '/');
		}
	}

	public function render_palette_picker() {
		global $w2dc_instance;

		if (!empty($w2dc_instance->frontend_controllers) &&
			$w2dc_instance->action != 'printlisting' &&
			$w2dc_instance->action != 'pdflisting' &&
			$w2dc_instance->action != 'printinvoice'
		) {
			if (
				(get_option('w2dc_compare_palettes') && current_user_can('manage_options')) ||
				(defined('W2DC_DEMO') && W2DC_DEMO) ||
				apply_filters("w2dc_show_compare_palettes", false)
			) {
				w2dc_renderTemplate('color_picker/color_picker_panel.tpl.php');
			}
		}
	}
}
?>