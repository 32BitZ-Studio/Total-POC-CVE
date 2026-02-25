<?php

global $w2dc_wpml_dependent_options;
$w2dc_wpml_dependent_options[] = 'w2dc_listing_contact_form_7';
$w2dc_wpml_dependent_options[] = 'w2dc_directory_title';
$w2dc_wpml_dependent_options[] = 'w2dc_sticky_label';
$w2dc_wpml_dependent_options[] = 'w2dc_featured_label';

class w2dc_settings_manager {
	public function __construct() {
		add_action('init', array($this, 'plugin_settings'));
		
		if (!defined('W2DC_DEMO') || !W2DC_DEMO) {
			add_action('vp_w2dc_option_after_ajax_save', array($this, 'save_option'), 10, 3);
		}
		
		add_action('w2dc_settings_panel_bottom', array($this, 'our_plugins'));
	}
	
	public function our_plugins() {
		w2dc_renderTemplate('our_plugins.tpl.php');
	}
	
	public function plugin_settings() {
		global $w2dc_instance, $w2dc_social_services, $w2dc_google_maps_styles, $sitepress;
		
		if (defined('W2DC_DEMO') && W2DC_DEMO) {
			$capability = 'publish_posts';
		} else {
			$capability = 'edit_theme_options';
		}

		if ($w2dc_instance->index_page_id === 0 && isset($_GET['action']) && $_GET['action'] == 'directory_page_installation') {
			$page = array('post_status' => 'publish', 'post_title' => __('Web 2.0 Directory', 'W2DC'), 'post_type' => 'page', 'post_content' => '[webdirectory]', 'comment_status' => 'closed');
			if (wp_insert_post($page)) {
				w2dc_addMessage(__('"Web 2.0 Directory" page with [webdirectory] shortcode was successfully created, thank you!'));
			}
		}
		
		$w2dc_search_forms = array();
		foreach (wcsearch_get_search_forms_posts() AS $id=>$title) {
			$w2dc_search_forms[$id] = array('value' => $id, 'label' => $title);
		}

		$ordering_items = w2dc_orderingItems();
		
		$w2dc_social_services = array(
			'facebook' => array('value' => 'facebook', 'label' => __('Facebook', 'W2DC')),
			'twitter' => array('value' => 'twitter', 'label' => __('Twitter', 'W2DC')),
			'google' => array('value' => 'google', 'label' => __('Google+', 'W2DC')),
			'linkedin' => array('value' => 'linkedin', 'label' => __('LinkedIn', 'W2DC')),
			'digg' => array('value' => 'digg', 'label' => __('Digg', 'W2DC')),
			'reddit' => array('value' => 'reddit', 'label' => __('Reddit', 'W2DC')),
			'pinterest' => array('value' => 'pinterest', 'label' => __('Pinterest', 'W2DC')),
			'tumblr' => array('value' => 'tumblr', 'label' => __('Tumblr', 'W2DC')),
			'stumbleupon' => array('value' => 'stumbleupon', 'label' => __('StumbleUpon', 'W2DC')),
			'vk' => array('value' => 'vk', 'label' => __('VK', 'W2DC')),
			'whatsapp' => array('value' => 'whatsapp', 'label' => __('WhatsApp', 'W2DC')),
			'telegram' => array('value' => 'telegram', 'label' => __('Telegram', 'W2DC')),
			'viber' => array('value' => 'viber', 'label' => __('Viber', 'W2DC')),
			'email' => array('value' => 'email', 'label' => __('Email', 'W2DC')),
		);

		$listings_tabs = array(
				array('value' => 'addresses-tab', 'label' => __('Addresses tab', 'W2DC')),
				array('value' => 'comments-tab', 'label' => __('Comments tab', 'W2DC')),
				array('value' => 'videos-tab', 'label' => __('Videos tab', 'W2DC')),
				array('value' => 'contact-tab', 'label' => __('Contact tab', 'W2DC')),
				array('value' => 'report-tab', 'label' => __('Report tab', 'W2DC')));
		foreach ($w2dc_instance->content_fields->content_fields_groups_array AS $fields_group) {
			if ($fields_group->on_tab) {
				$listings_tabs[] = array('value' => 'field-group-tab-'.$fields_group->id, 'label' => $fields_group->name);
			}
		}
			
		$google_map_styles = array(array('value' => 'default', 'label' => 'Default style'));
		foreach ($w2dc_google_maps_styles AS $name=>$style) {
			$google_map_styles[] = array('value' => $name, 'label' => $name);
		}
		$mapbox_map_styles = array();
		foreach (w2dc_getMapBoxStyles() AS $name=>$style) {
			$mapbox_map_styles[] = array('value' => $style, 'label' => $name);
		}

		$country_codes = array(array('value' => 0, 'label' => 'Worldwide'));
		$w2dc_country_codes = w2dc_country_codes();
		foreach ($w2dc_country_codes AS $country=>$code) {
			$country_codes[] = array('value' => $code, 'label' => $country);
		}
		
		$map_zooms = array(
						array(
							'value' => '0',
							'label' =>__('Auto', 'W2DC'),
						),
						array('value' => 1, 'label' => 1),
						array('value' => 2, 'label' => 2),
						array('value' => 3, 'label' => 3),
						array('value' => 4, 'label' => 4),
						array('value' => 5, 'label' => 5),
						array('value' => 6, 'label' => 6),
						array('value' => 7, 'label' => 7),
						array('value' => 8, 'label' => 8),
						array('value' => 9, 'label' => 9),
						array('value' => 10, 'label' => 10),
						array('value' => 11, 'label' => 11),
						array('value' => 12, 'label' => 12),
						array('value' => 13, 'label' => 13),
						array('value' => 14, 'label' => 14),
						array('value' => 15, 'label' => 15),
						array('value' => 16, 'label' => 16),
						array('value' => 17, 'label' => 17),
						array('value' => 18, 'label' => 18),
						array('value' => 19, 'label' => 19),
		);
		
		$theme_options = array(
				//'is_dev_mode' => true,
				'option_key' => 'vpt_option',
				'page_slug' => 'w2dc_settings',
				'template' => array(
					'title' => __('Web 2.0 Directory Settings', 'W2DC'),
					'logo' => W2DC_RESOURCES_URL . 'images/settings.png',
					'menus' => array(
						'general' => array(
							'name' => 'general',
							'title' => __('General settings', 'W2DC'),
							'icon' => 'font-awesome:w2dc-fa-home',
							'controls' => array(
								'ajax_map_loading' => array(
									'type' => 'section',
									'title' => __('AJAX loading', 'W2DC'),
									'fields' => array(
									 	array(
											'type' => 'toggle',
											'name' => 'w2dc_ajax_load',
											'label' => __('Use AJAX loading', 'W2DC'),
									 		'description' => __('Load maps and listings using AJAX when click sorting buttons and pagination buttons. Manage search settings', 'W2DC') . " " . "<a href='" . admin_url("edit.php?post_type=wcsearch_form") . "'>" . esc_html__("here", "W2DC") . "</a>",
											'default' => get_option('w2dc_ajax_load'),
										),
									 	array(
											'type' => 'toggle',
											'name' => 'w2dc_show_more_button',
											'label' => __('Display "Show More Listings" button instead of default paginator', 'W2DC'),
											'default' => get_option('w2dc_show_more_button'),
										),
									),
								),
								'title_slugs' => array(
									'type' => 'section',
									'title' => __('Titles, Labels & Permalinks', 'W2DC'),
									'fields' => array(
									 	array(
											'type' => 'textbox',
											'name' => w2dc_get_wpml_dependent_option_name('w2dc_directory_title'), // adapted for WPML
											'label' => __('Directory title', 'W2DC'),
									 		'description' => w2dc_get_wpml_dependent_option_description(),
											'default' => w2dc_get_wpml_dependent_option('w2dc_directory_title'),  // adapted for WPML
										),
									 	array(
											'type' => 'textbox',
											'name' => w2dc_get_wpml_dependent_option_name('w2dc_sticky_label'), // adapted for WPML
											'label' => __('Sticky listing label', 'W2DC'),
									 		'description' => w2dc_get_wpml_dependent_option_description(),
											'default' => w2dc_get_wpml_dependent_option('w2dc_sticky_label'),  // adapted for WPML
										),
									 	array(
											'type' => 'textbox',
											'name' => w2dc_get_wpml_dependent_option_name('w2dc_featured_label'), // adapted for WPML
											'label' => __('Featured listing label', 'W2DC'),
									 		'description' => w2dc_get_wpml_dependent_option_description(),
											'default' => w2dc_get_wpml_dependent_option('w2dc_featured_label'),  // adapted for WPML
										),
										array(
											'type' => 'notebox',
											'name' => 'slugs_warning',
											'label' => __('Notice about slugs:', 'W2DC'),
											'description' => sprintf(__('You can manage listings, categories, locations and tags slugs in <a href="%s">directories settings</a>', 'W2DC'), admin_url('admin.php?page=w2dc_directories')),
											'status' => 'warning',
										),
										array(
											'type' => 'radiobutton',
											'name' => 'w2dc_permalinks_structure',
											'label' => __('Listings permalinks structure', 'W2DC'),
											'description' => __('<b>/%postname%/</b> works only when directory page is not front page.<br /><b>/%post_id%/%postname%/</b> will not work when /%post_id%/%postname%/ or /%year%/%postname%/ was enabled for native WP posts.', 'W2DC'),
											'default' => array(get_option('w2dc_permalinks_structure')),
											'items' => array(
													array(
														'value' => 'postname',
														'label' => '/%postname%/',	
													),
													array(
														'value' => 'post_id',
														'label' => '/%post_id%/%postname%/',	
													),
													array(
														'value' => 'listing_slug',
														'label' => '/%listing_slug%/%postname%/',	
													),
													array(
														'value' => 'category_slug',
														'label' => '/%listing_slug%/%category%/%postname%/',	
													),
													array(
														'value' => 'location_slug',
														'label' => '/%listing_slug%/%location%/%postname%/',	
													),
													array(
														'value' => 'tag_slug',
														'label' => '/%listing_slug%/%tag%/%postname%/',	
													),
											),
										),
									),
								),
							),
						),
						'listings' => array(
							'name' => 'listings',
							'title' => __('Listings', 'W2DC'),
							'icon' => 'font-awesome:w2dc-fa-list-alt',
							'controls' => array(
								'listings' => array(
									'type' => 'section',
									'title' => __('Listings settings', 'W2DC'),
									'fields' => array(
										array(
											'type' => 'toggle',
											'name' => 'w2dc_listings_on_index',
											'label' => __('Show listings on home page', 'W2DC'),
											'default' => get_option('w2dc_listings_on_index'),
										),
										array(
											'type' => 'textbox',
											'name' => 'w2dc_listings_number_index',
											'label' => __('Number of listings on home page', 'W2DC'),
											'description' => __('Per page', 'W2DC'),
											'default' => get_option('w2dc_listings_number_index'),
											'validation' => 'numeric',
										),
										array(
											'type' => 'textbox',
											'name' => 'w2dc_listings_number_excerpt',
											'label' => __('Number of listings on excerpt pages (categories, locations, tags, search results)', 'W2DC'),
											'description' => __('Per page', 'W2DC'),
											'default' => get_option('w2dc_listings_number_excerpt'),
											'validation' => 'numeric',
										),
										array(
											'type' => 'toggle',
											'name' => 'w2dc_listing_contact_form',
											'label' => __('Enable contact form on listing page', 'W2DC'),
											'description' => __('Contact Form 7 or standard form will be displayed on each listing page', 'W2DC'),
											'default' => get_option('w2dc_listing_contact_form'),
										),
										array(
											'type' => 'textbox',
											'name' => w2dc_get_wpml_dependent_option_name('w2dc_listing_contact_form_7'),
											'label' => __('Contact Form 7 shortcode', 'W2DC'),
											'description' => __('This will work only when Contact Form 7 plugin enabled, otherwise standard contact form will be displayed.', 'W2DC') . w2dc_get_wpml_dependent_option_description(),
											'default' => w2dc_get_wpml_dependent_option('w2dc_listing_contact_form_7'),
										),
										array(
											'type' => 'toggle',
											'name' => 'w2dc_hide_anonymous_contact_form',
											'label' => __('Show contact form only for logged in users', 'W2DC'),
											'default' => get_option('w2dc_hide_anonymous_contact_form'),
										),
										array(
											'type' => 'toggle',
											'name' => 'w2dc_custom_contact_email',
											'label' => __('Allow custom contact emails', 'W2DC'),
											'description' => __('When enabled users may set up custom contact emails, otherwise messages will be sent directly to authors emails', 'W2DC'),
											'default' => get_option('w2dc_custom_contact_email'),
										),
										array(
											'type' => 'toggle',
											'name' => 'w2dc_report_form',
											'label' => __('Enable report form', 'W2DC'),
											'default' => get_option('w2dc_report_form'),
										),
										array(
											'type' => 'toggle',
											'name' => 'w2dc_favourites_list',
											'label' => __('Enable bookmarks list', 'W2DC'),
											'default' => get_option('w2dc_favourites_list'),
										),
										array(
											'type' => 'toggle',
											'name' => 'w2dc_print_button',
											'label' => __('Show print listing button', 'W2DC'),
											'default' => get_option('w2dc_print_button'),
										),
										array(
											'type' => 'toggle',
											'name' => 'w2dc_pdf_button',
											'label' => __('Show listing in PDF button', 'W2DC'),
											'default' => get_option('w2dc_pdf_button'),
										),
										array(
											'type' => 'radiobutton',
											'name' => 'w2dc_pdf_page_orientation',
											'label' => __('PDF page orientation', 'W2DC'),
											'default' => get_option('w2dc_pdf_page_orientation'),
											'items' => array(
													array(
														'value' => 'portrait',
														'label' => __('Portrait', 'W2DC'),	
													),
													array(
														'value' => 'landscape',
														'label' => __('Landscape', 'W2DC'),	
													),
											),
										),
										array(
											'type' => 'toggle',
											'name' => 'w2dc_change_expiration_date',
											'label' => __('Allow regular users to change listings expiration dates', 'W2DC'),
											'default' => get_option('w2dc_change_expiration_date'),
										),
										array(
											'type' => 'toggle',
											'name' => 'w2dc_hide_comments_number_on_index',
											'label' => __('Hide comments (reviews) number on index and excerpt pages', 'W2DC'),
											'default' => get_option('w2dc_hide_comments_number_on_index'),
										),
										array(
											'type' => 'toggle',
											'name' => 'w2dc_hide_listing_title',
											'label' => __('Hide listing title', 'W2DC'),
											'description' => __('Hides title on a single listing page.', 'W2DC'),
											'default' => get_option('w2dc_hide_listing_title'),
										),
										array(
											'type' => 'toggle',
											'name' => 'w2dc_hide_views_counter',
											'label' => __('Hide listings views counter', 'W2DC'),
											'default' => get_option('w2dc_hide_views_counter'),
										),
										array(
											'type' => 'toggle',
											'name' => 'w2dc_hide_listings_creation_date',
											'label' => __('Hide listings creation date', 'W2DC'),
											'default' => get_option('w2dc_hide_listings_creation_date'),
										),
										array(
											'type' => 'toggle',
											'name' => 'w2dc_hide_author_link',
											'label' => __('Hide author information', 'W2DC'),
											'description' => __('Author name and possible link to author website will be hidden on single listing pages.', 'W2DC'),
											'default' => get_option('w2dc_hide_author_link'),
										),
										array(
											'type' => 'radiobutton',
											'name' => 'w2dc_listings_comments_mode',
											'label' => __('Listings comments (reviews) mode', 'W2DC'),
											'default' => array(get_option('w2dc_listings_comments_mode')),
											'items' => array(
													array(
														'value' => 'enabled',
														'label' => __('Always enabled', 'W2DC'),	
													),
													array(
														'value' => 'disabled',
														'label' => __('Always disabled', 'W2DC'),	
													),
													array(
														'value' => 'wp_settings',
														'label' => __('As configured in WP settings', 'W2DC'),	
													),
											),
										),
										array(
											'type' => 'sorter',
											'name' => 'w2dc_listings_tabs_order',
											'label' => __('Listing tabs order', 'W2DC'),
									 		'items' => $listings_tabs,
											'default' => get_option('w2dc_listings_tabs_order'),
										),
										array(
											'type' => 'toggle',
											'name' => 'w2dc_enable_stats',
											'label' => __('Enable statistics functionality', 'W2DC'),
											'default' => get_option('w2dc_enable_stats'),
										),
									),
								),
								'breadcrumbs' => array(
									'type' => 'section',
									'title' => __('Breadcrumbs settings', 'W2DC'),
									'fields' => array(
										array(
											'type' => 'toggle',
											'name' => 'w2dc_enable_breadcrumbs',
											'label' => __('Enable breadcrumbs', 'W2DC'),
											'default' => get_option('w2dc_enable_breadcrumbs'),
										),
										array(
											'type' => 'toggle',
											'name' => 'w2dc_hide_home_link_breadcrumb',
											'label' => __('Hide home link in breadcrumbs', 'W2DC'),
											'default' => get_option('w2dc_hide_home_link_breadcrumb'),
										),
										array(
											'type' => 'radiobutton',
											'name' => 'w2dc_breadcrumbs_mode',
											'label' => __('Breadcrumbs mode on single listing page', 'W2DC'),
											'default' => array(get_option('w2dc_breadcrumbs_mode')),
											'items' => array(
													array(
														'value' => 'title',
														'label' => __('%listing title%', 'W2DC'),	
													),
													array(
														'value' => 'category',
														'label' => __('%category% » %listing title%', 'W2DC'),	
													),
													array(
														'value' => 'location',
														'label' => __('%location% » %listing title%', 'W2DC'),	
													),
											),
										),
									),
								),
								'logos' => array(
									'type' => 'section',
									'title' => __('Listings logos & images', 'W2DC'),
									'fields' => array(
										array(
											'type' => 'toggle',
											'name' => 'w2dc_images_submit_required',
											'label' => __('Images required', 'W2DC'),
											'default' => get_option('w2dc_images_submit_required'),
										),
										array(
											'type' => 'toggle',
											'name' => 'w2dc_enable_lightbox_gallery',
											'label' => __('Enable lightbox on images gallery', 'W2DC'),
											'default' => get_option('w2dc_enable_lightbox_gallery'),
										),
										array(
											'type' => 'toggle',
											'name' => 'w2dc_auto_slides_gallery',
											'label' => __('Enable automatic rotating slideshow on images gallery', 'W2DC'),
											'default' => get_option('w2dc_auto_slides_gallery'),
										),
										array(
											'type' => 'textbox',
											'name' => 'w2dc_auto_slides_gallery_delay',
											'label' => __('The delay in rotation (in ms)', 'W2DC'),
											'default' => get_option('w2dc_auto_slides_gallery_delay'),
										),
										array(
											'type' => 'toggle',
											'name' => 'w2dc_exclude_logo_from_listing',
											'label' => __('Exclude logo image from images gallery on single listing page', 'W2DC'),
											'default' => get_option('w2dc_exclude_logo_from_listing'),
										),
										array(
											'type' => 'toggle',
											'name' => 'w2dc_enable_nologo',
											'label' => __('Enable default logo image', 'W2DC'),
											'default' => get_option('w2dc_enable_nologo'),
										),
										array(
											'type' => 'upload',
											'name' => 'w2dc_nologo_url',
											'label' => __('Default logo image', 'W2DC'),
									 		'description' => __('This image will appear when listing owner did not upload own logo.', 'W2DC'),
											'default' => get_option('w2dc_nologo_url'),
										),
										array(
											'type' => 'toggle',
											'name' => 'w2dc_100_single_logo_width',
											'label' => __('Enable 100% width of images gallery', 'W2DC'),
											'default' => get_option('w2dc_100_single_logo_width'),
										),
										array(
											'type' => 'slider',
											'name' => 'w2dc_single_logo_width',
											'label' => __('Images gallery width (in pixels)', 'W2DC'),
											'description' => __('This option needed only when 100% width of images gallery is switched off'),
											'min' => 100,
											'max' => 800,
											'default' => get_option('w2dc_single_logo_width'),
										),
										array(
											'type' => 'slider',
											'name' => 'w2dc_single_logo_height',
											'label' => __('Images gallery height (in pixels)', 'W2DC'),
											'description' => __('Set to 0 to fit full height'),
											'min' => 0,
											'max' => 800,
											'default' => get_option('w2dc_single_logo_height'),
										),
										array(
											'type' => 'radiobutton',
											'name' => 'w2dc_big_slide_bg_mode',
											'label' => __('Do crop images gallery', 'W2DC'),
											'default' => array(get_option('w2dc_big_slide_bg_mode')),
											'items' => array(
													array(
														'value' => 'cover',
														'label' => __('Cut off image to fit width and height of main slide', 'W2DC'),	
													),
													array(
														'value' => 'contain',
														'label' => __('Full image inside main slide', 'W2DC'),	
													),
											),
											'description' => __('Works when gallery height is limited (not set to 0)', 'W2DC'),
										),
									),
								),
								'excerpts' => array(
									'type' => 'section',
									'title' => __('Description & Excerpt settings', 'W2DC'),
									'fields' => array(
										array(
											'type' => 'toggle',
											'name' => 'w2dc_enable_description',
											'label' => __('Enable description field', 'W2DC'),
											'default' => get_option('w2dc_enable_description'),
										),
										array(
											'type' => 'toggle',
											'name' => 'w2dc_enable_html_description',
											'label' => __('Enable HTML and shortcodes in description field', 'W2DC'),
											'default' => get_option('w2dc_enable_html_description'),
										),
										array(
											'type' => 'toggle',
											'name' => 'w2dc_enable_summary',
											'label' => __('Enable summary field', 'W2DC'),
											'default' => get_option('w2dc_enable_summary'),
										),
										array(
											'type' => 'textbox',
											'name' => 'w2dc_excerpt_length',
											'label' => __('Excerpt max length', 'W2DC'),
											'description' => __('Insert the number of words you want to show in the listings excerpts', 'W2DC'),
											'default' => get_option('w2dc_excerpt_length'),
											'validation' => 'numeric',
										),
										array(
											'type' => 'toggle',
											'name' => 'w2dc_cropped_content_as_excerpt',
											'label' => __('Use cropped content as excerpt', 'W2DC'),
											'description' => __('When excerpt field is empty - use cropped main content', 'W2DC'),
											'default' => get_option('w2dc_cropped_content_as_excerpt'),
										),
										array(
											'type' => 'toggle',
											'name' => 'w2dc_strip_excerpt',
											'label' => __('Strip HTML from excerpt', 'W2DC'),
											'description' => __('Check the box if you want to strip HTML from the excerpt content only', 'W2DC'),
											'default' => get_option('w2dc_strip_excerpt'),
										),
									),
								),
							),
						),
						'pages_views' => array(
							'name' => 'pages_views',
							'title' => __('Pages & Views', 'W2DC'),
							'icon' => 'font-awesome:w2dc-fa-external-link ',
							'controls' => array(
								'excerpt_views' => array(
									'type' => 'section',
									'title' => __('Excerpt views', 'W2DC'),
									'fields' => array(
										array(
											'type' => 'toggle',
											'name' => 'w2dc_show_listings_count',
											'label' => __('Show listings number', 'W2DC'),
											'default' => get_option('w2dc_show_listings_count'),
										),
										array(
											'type' => 'toggle',
											'name' => 'w2dc_views_switcher',
											'label' => __('Enable views switcher', 'W2DC'),
											'default' => get_option('w2dc_views_switcher'),
										),
										array(
											'type' => 'radiobutton',
											'name' => 'w2dc_views_switcher_default',
											'label' => __('Listings view by default', 'W2DC'),
											'description' => __('Selected view will be stored in cookies', 'W2DC'),
											'default' => array(get_option('w2dc_views_switcher_default')),
											'items' => array(
													array(
														'value' => 'list',
														'label' => __('List view', 'W2DC'),
													),
													array(
														'value' => 'grid',
														'label' => __('Grid view', 'W2DC'),
													),
											),
										),
										array(
											'type' => 'radiobutton',
											'name' => 'w2dc_listing_title_mode',
											'label' => __('Listing title mode', 'W2DC'),
											'description' => __('How to display listing title', 'W2DC'),
											'default' => array(get_option('w2dc_listing_title_mode')),
											'items' => array(
													array(
														'value' => 'inside',
														'label' => __('On listing logo', 'W2DC'),
													),
													array(
														'value' => 'outside',
														'label' => __('Outside listing logo', 'W2DC'),
													),
											),
										),
										array(
											'type' => 'radiobutton',
											'name' => 'w2dc_listing_logo_bg_mode',
											'label' => __('Logo image mode', 'W2DC'),
											'default' => array(get_option('w2dc_listing_logo_bg_mode')),
											'items' => array(
													array(
														'value' => 'cover',
														'label' => __('Cut off image to fit width and height listing logo', 'W2DC'),	
													),
													array(
														'value' => 'contain',
														'label' => __('Full image inside listing logo', 'W2DC'),	
													),
											),
										),
										array(
											'type' => 'slider',
											'name' => 'w2dc_views_switcher_grid_columns',
											'label' => __('Number of columns for listings Grid View', 'W2DC'),
											'min' => 1,
											'max' => 4,
											'default' => get_option('w2dc_views_switcher_grid_columns'),
										),
										array(
											'type' => 'slider',
											'name' => 'w2dc_mobile_listings_grid_columns',
											'label' => __('Number of columns for mobile devices', 'W2DC'),
											'min' => 1,
											'max' => 2,
											'default' => get_option('w2dc_mobile_listings_grid_columns'),
										),
										array(
											'type' => 'radiobutton',
											'name' => 'w2dc_grid_view_logo_ratio',
											'label' => __('Aspect ratio of logo in Grid View', 'W2DC'),
											'default' => array(get_option('w2dc_grid_view_logo_ratio')),
											'items' => array(
													array(
														'value' => '100',
														'label' => __('1:1 (square)', 'W2DC'),
													),
													array(
														'value' => '75',
														'label' => __('4:3', 'W2DC'),
													),
													array(
														'value' => '56.25',
														'label' => __('16:9', 'W2DC'),
													),
													array(
														'value' => '50',
														'label' => __('2:1', 'W2DC'),
													),
											),
										),
										array(
											'type' => 'toggle',
											'name' => 'w2dc_wrap_logo_list_view',
											'label' => __('Wrap logo image by text content in List View', 'W2DC'),
											'default' => get_option('w2dc_wrap_logo_list_view'),
										),
										array(
											'type' => 'slider',
											'name' => 'w2dc_listing_thumb_width',
											'label' => __('Listing thumbnail logo width (in pixels) in List View', 'W2DC'),
											'min' => '70',
											'max' => '640',
											'default' => '290',
										),
									),
								),
								'categories' => array(
									'type' => 'section',
									'title' => __('Categories settings', 'W2DC'),
									'fields' => array(
										array(
											'type' => 'toggle',
											'name' => 'w2dc_show_categories_index',
											'label' => __('Show categories list on index and excerpt pages', 'W2DC'),
											'default' => get_option('w2dc_show_categories_index'),
										),
										array(
											'type' => 'slider',
											'name' => 'w2dc_categories_nesting_level',
											'label' => __('Categories depth level', 'W2DC'),
											'min' => 1,
											'max' => 2,
											'default' => get_option('w2dc_categories_nesting_level'),
										),
										array(
											'type' => 'slider',
											'name' => 'w2dc_categories_columns',
											'label' => __('Categories columns number', 'W2DC'),
											'min' => 1,
											'max' => 4,
											'default' => get_option('w2dc_categories_columns'),
										),
										array(
											'type' => 'textbox',
											'name' => 'w2dc_subcategories_items',
											'label' => __('Show subcategories items number', 'W2DC'),
											'description' => __('Leave 0 to show all subcategories', 'W2DC'),
											'default' => get_option('w2dc_subcategories_items'),
											'validation' => 'numeric',
										),
										array(
											'type' => 'toggle',
											'name' => 'w2dc_show_category_count',
											'label' => __('Show category listings count', 'W2DC'),
											'default' => get_option('w2dc_show_category_count'),
										),
										array(
											'type' => 'select',
											'name' => 'w2dc_categories_order',
											'label' => __('Order by', 'W2DC'),
											'items' => array(
												array(
													'value' => 'default',
													'label' => __('Default (drag & drop in categories tree)', 'W2DC'),
												),
												array(
													'value' => 'name',
													'label' => __('Alphabetically', 'W2DC'),
												),
												array(
													'value' => 'count',
													'label' => __('Count', 'W2DC'),
												),
											),
											'default' => array(get_option('w2dc_categories_order')),
										),
									),
								),
								'locations' => array(
									'type' => 'section',
									'title' => __('Locations settings', 'W2DC'),
									'fields' => array(
										array(
											'type' => 'toggle',
											'name' => 'w2dc_show_locations_index',
											'label' => __('Show locations list on index and excerpt pages', 'W2DC'),
											'default' => get_option('w2dc_show_locations_index'),
										),
										array(
											'type' => 'slider',
											'name' => 'w2dc_locations_nesting_level',
											'label' => __('Locations depth level', 'W2DC'),
											'min' => 1,
											'max' => 2,
											'default' => get_option('w2dc_locations_nesting_level'),
										),
										array(
											'type' => 'slider',
											'name' => 'w2dc_locations_columns',
											'label' => __('Locations columns number', 'W2DC'),
											'min' => 1,
											'max' => 4,
											'default' => get_option('w2dc_locations_columns'),
										),
										array(
											'type' => 'textbox',
											'name' => 'w2dc_sublocations_items',
											'label' => __('Show sublocations items number', 'W2DC'),
											'description' => __('Leave 0 to show all sublocations', 'W2DC'),
											'default' => get_option('w2dc_sublocations_items'),
											'validation' => 'numeric',
										),
										array(
											'type' => 'toggle',
											'name' => 'w2dc_show_location_count',
											'label' => __('Show location listings count', 'W2DC'),
											'default' => get_option('w2dc_show_locations_count'),
										),
										array(
											'type' => 'select',
											'name' => 'w2dc_locations_order',
											'label' => __('Order by', 'W2DC'),
											'items' => array(
												array(
													'value' => 'default',
													'label' => __('Default (drag & drop in locations tree)', 'W2DC'),
												),
												array(
													'value' => 'name',
													'label' => __('Alphabetically', 'W2DC'),
												),
												array(
													'value' => 'count',
													'label' => __('Count', 'W2DC'),
												),
											),
											'default' => array(get_option('w2dc_locations_order')),
										),
									),
								),
								'sorting' => array(
									'type' => 'section',
									'title' => __('Sorting settings', 'W2DC'),
									'fields' => array(
										array(
											'type' => 'toggle',
											'name' => 'w2dc_show_orderby_links',
											'label' => __('Show "order by" options', 'W2DC'),
											'default' => get_option('w2dc_show_orderby_links'),
										),
										array(
											'type' => 'toggle',
											'name' => 'w2dc_orderby_date',
											'label' => __('Allow sorting by date', 'W2DC'),
											'default' => get_option('w2dc_orderby_date'),
										),
										array(
											'type' => 'toggle',
											'name' => 'w2dc_orderby_title',
											'label' => __('Allow sorting by title', 'W2DC'),
											'default' => get_option('w2dc_orderby_title'),
										),
										array(
											'type' => 'toggle',
											'name' => 'w2dc_orderby_distance',
											'label' => __('Allow sorting by distance when search by radius', 'W2DC'),
											'default' => get_option('w2dc_orderby_distance'),
										),
										array(
											'type' => 'select',
											'name' => 'w2dc_default_orderby',
											'label' => __('Default order by', 'W2DC'),
											'items' => $ordering_items,
											'default' => get_option('w2dc_default_orderby'),
										),
										array(
											'type' => 'select',
											'name' => 'w2dc_default_order',
											'label' => __('Default order direction', 'W2DC'),
											'items' => array(
												array(
													'value' => 'ASC',
													'label' => __('Ascending', 'W2DC'),
												),
												array(
													'value' => 'DESC',
													'label' => __('Descending', 'W2DC'),
												),
											),
											'default' => get_option('w2dc_default_order'),
										),
										array(
											'type' => 'toggle',
											'name' => 'w2dc_orderby_exclude_null',
											'label' => __('Exclude listings with empty values from sorted results', 'W2DC'),
											'default' => get_option('w2dc_orderby_exclude_null'),
										),
										array(
											'type' => 'toggle',
											'name' => 'w2dc_orderby_sticky_featured',
											'label' => __('Sticky and featured listings always will be on top', 'W2DC'),
											'description' => __('When switched off - sticky and featured listings will be on top only when listings were sorted by date.', 'W2DC'),
											'default' => get_option('w2dc_orderby_sticky_featured'),
										),
									),
								),
							),
						),
						'search' => array(
							'name' => 'search',
							'title' => __('Search settings', 'W2DC'),
							'icon' => 'font-awesome:w2dc-fa-search',
							'controls' => array(
								'search' => array(
									'type' => 'section',
									'title' => __('Search settings', 'W2DC'),
									'fields' => array(
										array(
											'type' => 'select',
											'name' => 'w2dc_search_form_id',
											'label' => __('Search form', 'W2DC'),
											'description' => esc_html__("Manage search forms and settings", "W2DC") . " " . "<a href='" . admin_url("edit.php?post_type=wcsearch_form") . "'>" . esc_html__("here", "W2DC") . "</a>",
											'items' => $w2dc_search_forms,
											'default' => get_option('w2dc_search_form_id'),
										),
										array(
											'type' => 'toggle',
											'name' => 'w2dc_main_search',
											'label' => __('Display search form in main part of a page', 'W2DC'),
											'default' => get_option('w2dc_main_search'),
										),
										array(
											'type' => 'radiobutton',
											'name' => 'w2dc_miles_kilometers_in_search',
											'label' => __('Dimension in radius search', 'W2DC'),
											'items' => array(
												array(
													'value' => 'miles',
													'label' => __('miles', 'W2DC'),
												),
												array(
													'value' => 'kilometers',
													'label' => __('kilometers', 'W2DC'),
												),
											),
											'default' => array(get_option('w2dc_miles_kilometers_in_search')),
										),
									),
								),
							),
						),
						'maps' => array(
							'name' => 'maps',
							'title' => __('Maps & Addresses', 'W2DC'),
							'icon' => 'font-awesome:w2dc-fa-map-marker',
							'controls' => array(
								'map_type' => array(
									'type' => 'section',
									'title' => __('Map type', 'W2DC'),
									'fields' => array(
										array(
											'type' => 'radiobutton',
											'name' => 'w2dc_map_type',
											'label' => __('Select map engine', 'W2DC'),
											'items' => array(
												array(
													'value' => 'none',
													'label' =>__('No maps', 'W2DC'),
												),
												array(
													'value' => 'google',
													'label' =>__('Google Maps', 'W2DC'),
												),
												array(
													'value' => 'mapbox',
													'label' =>__('MapBox (OpenStreetMap)', 'W2DC'),
												),
											),
											'default' => array(
												get_option('w2dc_map_type')
											),
										),
									),
								),
								'google_setting' => array(
									'type' => 'section',
									'title' => __('Google Maps Settings', 'W2DC'),
									'name' => 'section_google_setting',
									'dependency' => array(
										'field'    => 'w2dc_map_type',
										'function' => 'w2dc_google_type_setting',
									),
									'fields' => array(
										array(
											'type' => 'textbox',
											'name' => 'w2dc_google_api_key',
											'label' => __('Google browser API key*', 'W2DC'),
											'description' => sprintf(__('get your Google API key <a href="%s" target="_blank">here</a>, following APIs must be enabled in the console: Directions API, Geocoding API, Maps JavaScript API and Static Maps API.', 'W2DC'), 'https://console.developers.google.com/flows/enableapi?apiid=maps_backend,geocoding_backend,directions_backend,static_maps_backend&keyType=CLIENT_SIDE&reusekey=true'),
											'default' => get_option('w2dc_google_api_key'),
										),
										array(
											'type' => 'textbox',
											'name' => 'w2dc_google_api_key_server',
											'label' => __('Google server API key*', 'W2DC'),
											'description' => sprintf(__('get your Google API key <a href="%s" target="_blank">here</a>, following APIs must be enabled in the console: Geocoding API and Places API.', 'W2DC'), 'https://console.developers.google.com/flows/enableapi?apiid=geocoding_backend,places_backend&keyType=CLIENT_SIDE&reusekey=true') . ' ' . sprintf(__('Then check geolocation <a href="%s">response</a>.', 'W2DC'), admin_url('admin.php?page=w2dc_debug')),
											'default' => get_option('w2dc_google_api_key_server'),
										),
										array(
											'type' => 'radiobutton',
											'name' => 'w2dc_directions_functionality',
											'label' => __('Directions functionality', 'W2DC'),
											'items' => array(
												array(
													'value' => 'builtin',
													'label' =>__('Built-in routing', 'W2DC'),
												),
												array(
													'value' => 'google',
													'label' =>__('Link to Google Maps', 'W2DC'),
												),
											),
											'default' => array(
													get_option('w2dc_directions_functionality')
											),
											'description' => __("On a single listing page", "W2DC"),
										),
										array(
											'type' => 'select',
											'name' => 'w2dc_google_map_style',
											'label' => __('Google Maps style', 'W2DC'),
									 		'items' => $google_map_styles,
											'default' => array(get_option('w2dc_google_map_style')),
										),
									),
								),
								'mapbox_settings' => array(
									'type' => 'section',
									'title' => __('MapBox Settings', 'W2DC'),
									'name' => 'section_mapbox_setting',
									'dependency' => array(
										'field'    => 'w2dc_map_type',
										'function' => 'w2dc_mapbox_type_setting',
									),
									'fields' => array(
										array(
											'type' => 'textbox',
											'name' => 'w2dc_mapbox_api_key',
											'label' => __('MapBox Access Token', 'W2DC'),
											'description' => sprintf(__('get your MapBox Access Token <a href="%s" target="_blank">here</a>', 'W2DC'), 'https://www.mapbox.com/account/'),
											'default' => get_option('w2dc_mapbox_api_key'),
										),
										array(
											'type' => 'select',
											'name' => 'w2dc_mapbox_map_style',
											'label' => __('MapBox Maps style', 'W2DC'),
									 		'items' => $mapbox_map_styles,
											'default' => array(get_option('w2dc_mapbox_map_style')),
										),
										array(
											'type' => 'textbox',
											'name' => 'w2dc_mapbox_map_style_custom',
											'label' => __('MapBox Custom Map Style', 'W2DC'),
											'description' => __('Will be used instead of native styles. Example mapbox://styles/shamalli/cjhrfxqxu3zki2rmkka3a3hkp'),
											'default' => get_option('w2dc_mapbox_map_style_custom'),
										),
									),
								),
								'maps' => array(
									'type' => 'section',
									'title' => __('General Maps settings', 'W2DC'),
									'fields' => array(
									 	array(
											'type' => 'toggle',
											'name' => 'w2dc_map_on_index',
											'label' => __('Show map on home page', 'W2DC'),
											'default' => get_option('w2dc_map_on_index'),
										),
									 	array(
											'type' => 'toggle',
											'name' => 'w2dc_map_on_excerpt',
											'label' => __('Show map on excerpt pages', 'W2DC'),
									 		'description' => __('Search results, categories, locations and tags pages', 'W2DC'),
											'default' => get_option('w2dc_map_on_excerpt'),
										),
									 	array(
											'type' => 'toggle',
											'name' => 'w2dc_map_on_single',
											'label' => __('Show map on single listing', 'W2DC'),
											'default' => get_option('w2dc_map_on_single'),
										),
										array(
											'type' => 'radiobutton',
											'name' => 'w2dc_map_markers_is_limit',
											'label' => __('How many map markers to display on the map', 'W2DC'),
											'items' => array(
												array(
													'value' => 1,
													'label' =>__('The only map markers of visible listings will be displayed', 'W2DC'),
												),
												array(
													'value' => 0,
													'label' =>__('Display all map markers (lots of markers on one page may slow down page loading)', 'W2DC'),
												),
											),
											'default' => array(
													get_option('w2dc_map_markers_is_limit')
											),
										),
									 	array(
											'type' => 'toggle',
											'name' => 'w2dc_show_directions',
											'label' => __('Show directions panel on a single listing page', 'W2DC'),
											'default' => get_option('w2dc_show_directions'),
										),
									 	array(
											'type' => 'slider',
											'name' => 'w2dc_default_map_zoom',
											'label' => __('Default map zoom level (for submission page)', 'W2DC'),
									 		'min' => 1,
									 		'max' => 19,
											'default' => get_option('w2dc_default_map_zoom'),
										),
										array(
											'type' => 'textbox',
											'name' => 'w2dc_default_map_height',
											'label' => __('Default map height (in pixels)', 'W2DC'),
											'default' => get_option('w2dc_default_map_height'),
											'validation' => 'numeric',
										),
										array(
											'type' => 'toggle',
											'name' => 'w2dc_enable_radius_search_circle',
											'label' => __('Show circle during radius search', 'W2DC'),
											'default' => get_option('w2dc_enable_radius_search_circle'),
										),
										array(
											'type' => 'toggle',
											'name' => 'w2dc_enable_clusters',
											'label' => __('Enable clusters of map markers', 'W2DC'),
											'default' => get_option('w2dc_enable_clusters'),
										),
										array(
											'type' => 'toggle',
											'name' => 'w2dc_map_markers_required',
											'label' => __('Make map markers mandatory during submission of listings', 'W2DC'),
											'default' => get_option('w2dc_map_markers_required'),
										),
										array(
											'type' => 'toggle',
											'name' => 'w2dc_enable_geolocation',
											'label' => __('Enable automatic user Geolocation', 'W2DC'),
											'default' => get_option('w2dc_enable_geolocation'),
											'description' => __("Requires https", "W2DC"),
										),
										array(
											'type' => 'select',
											'name' => 'w2dc_start_zoom',
											'label' => __('Default zoom level', 'W2DC'),
											'items' => $map_zooms,
											'default' => array(
												get_option('w2dc_start_zoom')
											),
										),
										array(
											'type' => 'select',
											'name' => 'w2dc_map_min_zoom',
											'label' => __('The farest zoom level', 'W2DC'),
											'items' => $map_zooms,
											'default' => array(
												get_option('w2dc_map_min_zoom')
											),
											'description' => __("How far we can zoom out: 1 - the farest (whole world)", "W2DC"),
										),
										array(
											'type' => 'select',
											'name' => 'w2dc_map_max_zoom',
											'label' => __('The closest zoom level', 'W2DC'),
											'items' => $map_zooms,
											'default' => array(
												get_option('w2dc_map_max_zoom')
											),
											'description' => __("How close we can zoom in: 19 - the closest", "W2DC"),
										),
									),
								),
								'maps_controls' => array(
									'type' => 'section',
									'title' => __('Maps controls settings', 'W2DC'),
									'fields' => array(
										array(
											'type' => 'toggle',
											'name' => 'w2dc_enable_draw_panel',
											'label' => __('Enable Draw Panel', 'W2DC'),
											'description' => __('Very important: MySQL version must be 5.6.1 and higher or MySQL server variable "thread stack" must be 256K and higher. Ask your hoster about it if "Draw Area" does not work.', 'W2DC'),
											'default' => get_option('w2dc_enable_draw_panel'),
										),
									 	array(
											'type' => 'toggle',
											'name' => 'w2dc_search_on_map',
											'label' => __('Show search form and listings sidebar on the map', 'W2DC'),
											'default' => get_option('w2dc_search_on_map'),
										),
										array(
											'type' => 'select',
											'name' => 'w2dc_search_map_form_id',
											'label' => __('Select search form', 'W2DC'),
											'items' => $w2dc_search_forms,
											'default' => get_option('w2dc_search_map_form_id'),
										),
										array(
											'type' => 'toggle',
											'name' => 'w2dc_enable_full_screen',
											'label' => __('Enable full screen button', 'W2DC'),
											'default' => get_option('w2dc_enable_full_screen'),
										),
										array(
											'type' => 'toggle',
											'name' => 'w2dc_enable_wheel_zoom',
											'label' => __('Enable zoom by mouse wheel', 'W2DC'),
											'description' => __('For desktops', 'W2DC'),
											'default' => get_option('w2dc_enable_wheel_zoom'),
										),
										array(
											'type' => 'toggle',
											'name' => 'w2dc_enable_dragging_touchscreens',
											'label' => __('Enable map dragging on touch screen devices', 'W2DC'),
											'default' => get_option('w2dc_enable_dragging_touchscreens'),
										),
										array(
											'type' => 'toggle',
											'name' => 'w2dc_center_map_onclick',
											'label' => __('Center map on marker click', 'W2DC'),
											'default' => get_option('w2dc_center_map_onclick'),
										),
										array(
											'type' => 'toggle',
											'name' => 'w2dc_hide_search_on_map_mobile',
											'label' => __('Hide compact search form on the map for mobile devices', 'W2DC'),
											'description' => __('This setting for all maps', 'W2DC'),
											'default' => get_option('w2dc_hide_search_on_map_mobile'),
										),
									),
								),
								'addresses' => array(
									'type' => 'section',
									'title' => __('Addresses settings', 'W2DC'),
									'fields' => array(
										array(
											'type' => 'textbox',
											'name' => 'w2dc_default_geocoding_location',
											'label' => __('Default country/state for correct geocoding', 'W2DC'),
											'description' => __('This value needed when you build local directory, all your listings place in one local area - country or state. This hidden string will be automatically added to the address for correct geocoding when users create/edit listings and when they search by address.', 'W2DC'),
											'default' => get_option('w2dc_default_geocoding_location'),
										),
										array(
											'type' => 'sorter',
											'name' => 'w2dc_addresses_order',
											'label' => __('Address format', 'W2DC'),
									 		'items' => array(
									 			array('value' => 'location', 'label' => __('Selected location', 'W2DC')),
									 			array('value' => 'line_1', 'label' => __('Address Line 1', 'W2DC')),
									 			array('value' => 'line_2', 'label' => __('Address Line 2', 'W2DC')),
									 			array('value' => 'zip', 'label' => __('Zip code or postal index', 'W2DC')),
									 			array('value' => 'space1', 'label' => __('-- Space ( ) --', 'W2DC')),
									 			array('value' => 'space2', 'label' => __('-- Space ( ) --', 'W2DC')),
									 			array('value' => 'space3', 'label' => __('-- Space ( ) --', 'W2DC')),
									 			array('value' => 'comma1', 'label' => __('-- Comma (,) --', 'W2DC')),
									 			array('value' => 'comma2', 'label' => __('-- Comma (,) --', 'W2DC')),
									 			array('value' => 'comma3', 'label' => __('-- Comma (,) --', 'W2DC')),
									 			array('value' => 'break1', 'label' => __('-- Line Break --', 'W2DC')),
									 			array('value' => 'break2', 'label' => __('-- Line Break --', 'W2DC')),
									 			array('value' => 'break3', 'label' => __('-- Line Break --', 'W2DC')),
									 		),
											'description' => __('Order address elements as you wish, commas and spaces help to build address line.'),
											'default' => get_option('w2dc_addresses_order'),
										),
										array(
											'type' => 'select',
											'name' => 'w2dc_address_autocomplete_code',
											'label' => __('Restriction of address fields for one specific country (autocomplete submission and search fields)', 'W2DC'),
									 		'items' => $country_codes,
											'default' => get_option('w2dc_address_autocomplete_code'),
										),
										array(
											'type' => 'toggle',
											'name' => 'w2dc_enable_address_line_1',
											'label' => __('Enable address line 1 field', 'W2DC'),
											'default' => get_option('w2dc_enable_address_line_1'),
										),
										array(
											'type' => 'toggle',
											'name' => 'w2dc_enable_address_line_2',
											'label' => __('Enable address line 2 field', 'W2DC'),
											'default' => get_option('w2dc_enable_address_line_2'),
										),
										array(
											'type' => 'toggle',
											'name' => 'w2dc_enable_postal_index',
											'label' => __('Enable zip code', 'W2DC'),
											'default' => get_option('w2dc_enable_postal_index'),
										),
										array(
											'type' => 'toggle',
											'name' => 'w2dc_enable_additional_info',
											'label' => __('Enable additional info field', 'W2DC'),
											'default' => get_option('w2dc_enable_additional_info'),
										),
										array(
											'type' => 'toggle',
											'name' => 'w2dc_enable_manual_coords',
											'label' => __('Enable manual coordinates fields', 'W2DC'),
											'default' => get_option('w2dc_enable_manual_coords'),
										),
										array(
											'type' => 'radiobutton',
											'name' => 'w2dc_zip_or_postal_text',
											'label' => __('Use Zip or Postal code label', 'W2DC'),
											'items' => array(
												array(
													'value' => 'zip',
													'label' =>__('Zip code', 'W2DC'),
												),
												array(
													'value' => 'postal',
													'label' =>__('Postal code', 'W2DC'),
												),
											),
											'default' => get_option('w2dc_zip_or_postal_text'),
										),
									),
								),
								'markers' => array(
									'type' => 'section',
									'title' => __('Map markers & InfoWindow settings', 'W2DC'),
									'fields' => array(
										array(
											'type' => 'radiobutton',
											'name' => 'w2dc_map_markers_type',
											'label' => __('Type of Map Markers', 'W2DC'),
											'items' => array(
												array(
													'value' => 'icons',
													'label' =>__('Font Awesome icons (recommended)', 'W2DC'),
												),
												array(
													'value' => 'images',
													'label' =>__('PNG images', 'W2DC'),
												),
											),
											'default' => array(
													get_option('w2dc_map_markers_type')
											),
										),
										array(
											'type' => 'color',
											'name' => 'w2dc_default_marker_color',
											'label' => __('Default Map Marker color', 'W2DC'),
											'default' => get_option('w2dc_default_marker_color'),
											'description' => __('For Font Awesome icons.', 'W2DC'),
											'dependency' => array(
												'field'    => 'w2dc_map_markers_type',
												'function' => 'w2dc_map_markers_icons_setting',
											),
										),
										array(
											'type' => 'fontawesome',
											'name' => 'w2dc_default_marker_icon',
											'label' => __('Default Map Marker icon'),
											'description' => __('For Font Awesome icons.', 'W2DC'),
											'default' => array(
												get_option('w2dc_default_marker_icon')
											),
											'dependency' => array(
												'field'    => 'w2dc_map_markers_type',
												'function' => 'w2dc_map_markers_icons_setting',
											),
										),
										array(
											'type' => 'slider',
											'name' => 'w2dc_map_marker_size',
											'label' => __('Map marker size (in pixels)', 'W2DC'),
											'description' => __('For Font Awesome images.', 'W2DC'),
											'default' => get_option('w2dc_map_marker_size'),
									 		'min' => 30,
									 		'max' => 70,
											'dependency' => array(
												'field'    => 'w2dc_map_markers_type',
												'function' => 'w2dc_map_markers_icons_setting',
											),
										),
										array(
											'type' => 'slider',
											'name' => 'w2dc_map_marker_width',
											'label' => __('Map marker width (in pixels)', 'W2DC'),
											'description' => __('For PNG images.', 'W2DC'),
											'default' => get_option('w2dc_map_marker_width'),
									 		'min' => 10,
									 		'max' => 64,
											'dependency' => array(
												'field'    => 'w2dc_map_markers_type',
												'function' => 'w2dc_map_markers_images_setting',
											),
										),
									 	array(
											'type' => 'slider',
											'name' => 'w2dc_map_marker_height',
											'label' => __('Map marker height (in pixels)', 'W2DC'),
									 		'description' => __('For PNG images.', 'W2DC'),
											'default' => get_option('w2dc_map_marker_height'),
									 		'min' => 10,
									 		'max' => 64,
									 		'dependency' => array(
												'field'    => 'w2dc_map_markers_type',
												'function' => 'w2dc_map_markers_images_setting',
											),
										),
									 	array(
											'type' => 'slider',
											'name' => 'w2dc_map_marker_anchor_x',
											'label' => __('Map marker anchor horizontal position (in pixels)', 'W2DC'),
									 		'description' => __('For PNG images.', 'W2DC'),
											'default' => get_option('w2dc_map_marker_anchor_x'),
									 		'min' => 0,
									 		'max' => 64,
									 		'dependency' => array(
												'field'    => 'w2dc_map_markers_type',
												'function' => 'w2dc_map_markers_images_setting',
											),
										),
									 	array(
											'type' => 'slider',
											'name' => 'w2dc_map_marker_anchor_y',
											'label' => __('Map marker anchor vertical position (in pixels)', 'W2DC'),
									 		'description' => __('For PNG images.', 'W2DC'),
											'default' => get_option('w2dc_map_marker_anchor_y'),
									 		'min' => 0,
									 		'max' => 64,
									 		'dependency' => array(
												'field'    => 'w2dc_map_markers_type',
												'function' => 'w2dc_map_markers_images_setting',
											),
										),
									 	array(
											'type' => 'slider',
											'name' => 'w2dc_map_infowindow_width',
											'label' => __('Map InfoWindow width (in pixels)', 'W2DC'),
											'default' => get_option('w2dc_map_infowindow_width'),
									 		'min' => 100,
									 		'max' => 600,
									 		'step' => 10,
										),
										array(
											'type' => 'slider',
											'name' => 'w2dc_map_infowindow_offset',
											'label' => __('Map InfoWindow vertical position above marker (in pixels)', 'W2DC'),
											'default' => get_option('w2dc_map_infowindow_offset'),
									 		'min' => 30,
									 		'max' => 120,
											'dependency' => array(
												'field'    => 'w2dc_map_type',
												'function' => 'w2dc_google_type_setting',
											),
										),
										array(
											'type' => 'slider',
											'name' => 'w2dc_map_infowindow_logo_width',
											'label' => __('Map InfoWindow logo width (in pixels)', 'W2DC'),
											'default' => get_option('w2dc_map_infowindow_logo_width'),
									 		'min' => 40,
									 		'max' => 300,
											'step' => 10,
										),
									),
								),
							),
						),
						'notifications' => array(
							'name' => 'notifications',
							'title' => __('Email notifications', 'W2DC'),
							'icon' => 'font-awesome:w2dc-fa-envelope',
							'controls' => array(
								'notifications' => array(
									'type' => 'section',
									'title' => __('Email notifications', 'W2DC'),
									'fields' => array(
										array(
											'type' => 'textbox',
											'name' => 'w2dc_admin_notifications_email',
											'label' => __('This email will be used for notifications to admin and in "From" field. Required to send emails.', 'W2DC'), // . "<a href='" . . "'>" .  . "</a>",
											'default' => get_option('w2dc_admin_notifications_email'),
										),
										array(
											'type' => 'textbox',
											'name' => 'w2dc_send_expiration_notification_days',
											'label' => __('Days before pre-expiration notification will be sent', 'W2DC'),
											'default' => get_option('w2dc_send_expiration_notification_days'),
										),
									 	array(
											'type' => 'textarea',
											'name' => 'w2dc_preexpiration_notification',
											'label' => __('Pre-expiration notification text', 'W2DC'),
											'default' => get_option('w2dc_preexpiration_notification'),
									 		'description' => __('Tags allowed: ', 'W2DC') . '[listing], [days], [link]',
										),
									 	array(
											'type' => 'textarea',
											'name' => 'w2dc_expiration_notification',
											'label' => __('Expiration notification text', 'W2DC'),
											'default' => get_option('w2dc_expiration_notification'),
									 		'description' => __('Tags allowed: ', 'W2DC') . '[listing], [link]',
										),
									),
								),
							),
						),
						'advanced' => array(
							'name' => 'advanced',
							'title' => __('Advanced settings', 'W2DC'),
							'icon' => 'font-awesome:w2dc-fa-gear',
							'controls' => array(
								'js_css' => array(
									'type' => 'section',
									'title' => __('JavaScript & CSS', 'W2DC'),
									'description' => __('Do not touch these settings if you do not know what they mean. It may cause lots of problems.', 'W2DC'),
									'fields' => array(
										array(
											'type' => 'toggle',
											'name' => 'w2dc_force_include_js_css',
											'label' => __('Include directory JS and CSS files on all pages', 'W2DC'),
											'default' => get_option('w2dc_force_include_js_css'),
										),
										array(
											'type' => 'toggle',
											'name' => 'w2dc_images_lightbox',
											'label' => __('Include lightbox slideshow library', 'W2DC'),
											'description' =>  __('Some themes and 3rd party plugins include own lightbox library - this may cause conflicts.', 'W2DC'),
											'default' => get_option('w2dc_images_lightbox'),
										),
										array(
											'type' => 'toggle',
											'name' => 'w2dc_notinclude_jqueryui_css',
											'label' => __('Do not include jQuery UI CSS', 'W2DC'),
									 		'description' =>  __('Some themes and 3rd party plugins include own jQuery UI CSS - this may cause conflicts in styles.', 'W2DC'),
											'default' => get_option('w2dc_notinclude_jqueryui_css'),
										),
									),
								),
								'miscellaneous' => array(
									'type' => 'section',
									'title' => __('Miscellaneous', 'W2DC'),
									'fields' => array(
									 	array(
											'type' => 'toggle',
											'name' => 'w2dc_imitate_mode',
											'label' => __('Enable imitation mode', 'W2DC'),
											'default' => get_option('w2dc_imitate_mode'),
									 		'description' => __("Some themes require imitation mode to get working listings/categories/locations/tags pages.", "W2DC"),
										),
										array(
											'type' => 'toggle',
											'name' => 'w2dc_overwrite_page_title',
											'label' => __('Overwrite WordPress page title by directory page title', 'W2DC'),
									 		'description' =>  __('Some themes do not allow this or may cause issues.', 'W2DC'),
											'default' => get_option('w2dc_overwrite_page_title'),
										),
									 	array(
											'type' => 'toggle',
											'name' => 'w2dc_prevent_users_see_other_media',
											'label' => __('Prevent users to see media items of another users', 'W2DC'),
											'default' => get_option('w2dc_prevent_users_see_other_media'),
										),
									 	array(
											'type' => 'toggle',
											'name' => 'w2dc_address_autocomplete',
											'label' => __('Enable autocomplete on addresses fields', 'W2DC'),
											'default' => get_option('w2dc_address_autocomplete'),
									 		'description' => __("Requires enabled maps", "W2DC"),
										),
									 	array(
											'type' => 'toggle',
											'name' => 'w2dc_address_geocode',
											'label' => __('Enable "Get my location" button on addresses fields', 'W2DC'),
											'default' => get_option('w2dc_address_geocode'),
									 		'description' => __("Requires https", "W2DC"),
										),
									),
								),
								'recaptcha' => array(
									'type' => 'section',
									'title' => __('reCaptcha settings', 'W2DC'),
									'fields' => array(
									 	array(
											'type' => 'toggle',
											'name' => 'w2dc_enable_recaptcha',
											'label' => __('Enable reCaptcha', 'W2DC'),
											'default' => get_option('w2dc_enable_recaptcha'),
										),
									 	array(
											'type' => 'radiobutton',
											'name' => 'w2dc_recaptcha_version',
											'label' => __('reCaptcha version', 'W2DC'),
											'default' => get_option('w2dc_recaptcha_version'),
									 		'items' => array(
												array('value' => 'v2', 'label' => __('reCaptcha v2', 'W2DC')),
												array('value' => 'v3', 'label' => __('reCaptcha v3', 'W2DC')),
											),
										),
									 	array(
											'type' => 'textbox',
											'name' => 'w2dc_recaptcha_public_key',
											'label' => __('reCaptcha site key', 'W2DC'),
											'description' => sprintf(__('get your reCAPTCHA API Keys <a href="%s" target="_blank">here</a>', 'W2DC'), 'http://www.google.com/recaptcha'),
											'default' => get_option('w2dc_recaptcha_public_key'),
										),
									 	array(
											'type' => 'textbox',
											'name' => 'w2dc_recaptcha_private_key',
											'label' => __('reCaptcha secret key', 'W2DC'),
											'default' => get_option('w2dc_recaptcha_private_key'),
										),
									),
								),
							),
						),
						'customization' => array(
							'name' => 'customization',
							'title' => __('Customization', 'W2DC'),
							'icon' => 'font-awesome:w2dc-fa-check',
							'controls' => array(
								'color_schemas' => array(
									'type' => 'section',
									'title' => __('Color palettes', 'W2DC'),
									'fields' => array(
										array(
											'type' => 'toggle',
											'name' => 'w2dc_compare_palettes',
											'label' => __('Compare palettes at the frontend', 'W2DC'),
									 		'description' =>  __('Do not forget to switch off this setting when comparison will be completed.', 'W2DC'),
											'default' => get_option('w2dc_compare_palettes'),
										),
										array(
											'type' => 'select',
											'name' => 'w2dc_color_scheme',
											'label' => __('Color palette', 'W2DC'),
											'items' => array(
												array('value' => 'default', 'label' => __('Default', 'W2DC')),
												array('value' => 'orange', 'label' => __('Orange', 'W2DC')),
												array('value' => 'red', 'label' => __('Red', 'W2DC')),
												array('value' => 'yellow', 'label' => __('Yellow', 'W2DC')),
												array('value' => 'green', 'label' => __('Green', 'W2DC')),
												array('value' => 'gray', 'label' => __('Gray', 'W2DC')),
												array('value' => 'blue', 'label' => __('Blue', 'W2DC')),
											),
											'default' => array(get_option('w2dc_color_scheme')),
										),
										array(
											'type' => 'notebox',
											'description' => esc_attr__("Don't forget to clear cache of your browser and on server (when used) after customization changes were made.", 'W2DC'),
											'status' => 'warning',
										),
									),
								),
								'main_colors' => array(
									'type' => 'section',
									'title' => __('Main colors', 'W2DC'),
									'fields' => array(
										array(
												'type' => 'color',
												'name' => 'w2dc_primary_color',
												'label' => __('Primary color', 'W2DC'),
												'description' =>  __('The color of categories, tags labels, map info window caption, pagination elements', 'W2DC'),
												'default' => get_option('w2dc_primary_color'),
												'binding' => array(
														'field' => 'w2dc_color_scheme',
														'function' => 'w2dc_affect_setting_w2dc_primary_color'
												),
										),
										array(
												'type' => 'color',
												'name' => 'w2dc_secondary_color',
												'label' => __('Secondary color', 'W2DC'),
												'default' => get_option('w2dc_secondary_color'),
												'binding' => array(
														'field' => 'w2dc_color_scheme',
														'function' => 'w2dc_affect_setting_w2dc_secondary_color'
												),
										),
									),
								),
								'links_colors' => array(
									'type' => 'section',
									'title' => __('Links & buttons', 'W2DC'),
									'fields' => array(
										array(
											'type' => 'color',
											'name' => 'w2dc_links_color',
											'label' => __('Links color', 'W2DC'),
											'default' => get_option('w2dc_links_color'),
											'binding' => array(
												'field' => 'w2dc_color_scheme',
												'function' => 'w2dc_affect_setting_w2dc_links_color'
											),
										),
										array(
											'type' => 'color',
											'name' => 'w2dc_links_hover_color',
											'label' => __('Links hover color', 'W2DC'),
											'default' => get_option('w2dc_links_hover_color'),
											'binding' => array(
												'field' => 'w2dc_color_scheme',
												'function' => 'w2dc_affect_setting_w2dc_links_hover_color'
											),
										),
										array(
											'type' => 'color',
											'name' => 'w2dc_button_1_color',
											'label' => __('Button primary color', 'W2DC'),
											'default' => get_option('w2dc_button_1_color'),
											'binding' => array(
												'field' => 'w2dc_color_scheme',
												'function' => 'w2dc_affect_setting_w2dc_button_1_color'
											),
										),
										array(
											'type' => 'color',
											'name' => 'w2dc_button_2_color',
											'label' => __('Button secondary color', 'W2DC'),
											'default' => get_option('w2dc_button_2_color'),
											'binding' => array(
												'field' => 'w2dc_color_scheme',
												'function' => 'w2dc_affect_setting_w2dc_button_2_color'
											),
										),
										array(
											'type' => 'color',
											'name' => 'w2dc_button_text_color',
											'label' => __('Button text color', 'W2DC'),
											'default' => get_option('w2dc_button_text_color'),
											'binding' => array(
												'field' => 'w2dc_color_scheme',
												'function' => 'w2dc_affect_setting_w2dc_button_text_color'
											),
										),
										array(
											'type' => 'toggle',
											'name' => 'w2dc_button_gradient',
											'label' => __('Use gradient on buttons', 'W2DC'),
											'description' => __('This will remove all icons from buttons'),
											'default' => get_option('w2dc_button_gradient'),
										),
									),
								),
								'terms_colors' => array(
									'type' => 'section',
									'title' => __('Categories & Locations tables', 'W2DC'),
									'fields' => array(
										array(
											'type' => 'color',
											'name' => 'w2dc_terms_links_color',
											'label' => __('Terms links color', 'W2DC'),
											'default' => get_option('w2dc_terms_links_color'),
										),
										array(
											'type' => 'color',
											'name' => 'w2dc_terms_links_hover_color',
											'label' => __('Terms links hover color', 'W2DC'),
											'default' => get_option('w2dc_terms_links_hover_color'),
										),
										array(
											'type' => 'color',
											'name' => 'w2dc_terms_bg_color',
											'label' => __('Terms background color', 'W2DC'),
											'default' => get_option('w2dc_terms_bg_color'),
										),
										array(
											'type' => 'color',
											'name' => 'w2dc_terms_heading_bg_color',
											'label' => __('Terms heading background color', 'W2DC'),
											'default' => get_option('w2dc_terms_heading_bg_color'),
										),
									),
								),
								'misc_colors' => array(
									'type' => 'section',
									'title' => __('Misc settings', 'W2DC'),
									'fields' => array(
										array(
											'type' => 'select',
											'name' => 'w2dc_logo_animation_effect',
											'label' => __('Logo hover effect on excerpt pages', 'W2DC'),
											'items' => array(
													array(
															'value' => 0,
															'label' => __('Disabled', 'W2DC')
													),
													array(
															'value' => 1,
															'label' => __('Enabled', 'W2DC')
													),
											),
											'default' => array(get_option('w2dc_logo_animation_effect')),
										),
										array(
											'type' => 'slider',
											'name' => 'w2dc_listings_bottom_margin',
											'label' => __('Bottom margin between listings (in pixels)', 'W2DC'),
											'min' => '0',
											'max' => '120',
											'default' => get_option('w2dc_listings_bottom_margin'),
										),
										array(
											'type' => 'slider',
											'name' => 'w2dc_listing_title_font',
											'label' => __('Listing title font size (in pixels)', 'W2DC'),
											'min' => '7',
											'max' => '40',
											'default' => get_option('w2dc_listing_title_font'),
										),
										array(
											'type' => 'radioimage',
											'name' => 'w2dc_jquery_ui_schemas',
											'label' => esc_html__('jQuery UI Style', 'W2DC'),
									 		'description' =>  esc_html__('Controls the color of calendar, dialogs, search dropdowns and slider UI widgets', 'W2DC') . (get_option('w2dc_notinclude_jqueryui_css') ? ' <strong>' . esc_html__('Warning: You have enabled not to include jQuery UI CSS on Advanced settings tab. Selected style will not be applied.', 'W2DC') . '</strong>' : ''),
									 		'items' => array(
									 			array(
									 				'value' => 'blitzer',
									 				'label' => 'Blitzer',
									 				'img' => W2DC_RESOURCES_URL . 'css/jquery-ui/themes/blitzer/thumb.png'
									 			),
									 			array(
									 				'value' => 'smoothness',
									 				'label' => 'Smoothness',
									 				'img' => W2DC_RESOURCES_URL . 'css/jquery-ui/themes/smoothness/thumb.png'
									 			),
									 			array(
									 				'value' => 'redmond',
									 				'label' => 'Redmond',
									 				'img' => W2DC_RESOURCES_URL . 'css/jquery-ui/themes/redmond/thumb.png'
									 			),
									 			array(
									 				'value' => 'ui-darkness',
									 				'label' => 'UI Darkness',
									 				'img' => W2DC_RESOURCES_URL . 'css/jquery-ui/themes/ui-darkness/thumb.png'
									 			),
									 			array(
									 				'value' => 'ui-lightness',
									 				'label' => 'UI Lightness',
									 				'img' => W2DC_RESOURCES_URL . 'css/jquery-ui/themes/ui-lightness/thumb.png'
									 			),
									 			array(
									 				'value' => 'trontastic',
									 				'label' => 'Trontastic',
									 				'img' => W2DC_RESOURCES_URL . 'css/jquery-ui/themes/trontastic/thumb.png'
									 			),
									 			array(
									 				'value' => 'start',
									 				'label' => 'Start',
									 				'img' => W2DC_RESOURCES_URL . 'css/jquery-ui/themes/start/thumb.png'
									 			),
									 			array(
									 				'value' => 'sunny',
									 				'label' => 'Sunny',
									 				'img' => W2DC_RESOURCES_URL . 'css/jquery-ui/themes/sunny/thumb.png'
									 			),
									 			array(
									 				'value' => 'overcast',
									 				'label' => 'Overcast',
									 				'img' => W2DC_RESOURCES_URL . 'css/jquery-ui/themes/overcast/thumb.png'
									 			),
									 			array(
									 				'value' => 'le-frog',
									 				'label' => 'Le Frog',
									 				'img' => W2DC_RESOURCES_URL . 'css/jquery-ui/themes/le-frog/thumb.png'
									 			),
									 			array(
									 				'value' => 'hot-sneaks',
									 				'label' => 'Hot Sneaks',
									 				'img' => W2DC_RESOURCES_URL . 'css/jquery-ui/themes/hot-sneaks/thumb.png'
									 			),
									 			array(
									 				'value' => 'excite-bike',
									 				'label' => 'Excite Bike',
									 				'img' => W2DC_RESOURCES_URL . 'css/jquery-ui/themes/excite-bike/thumb.png'
									 			),
									 		),
											'default' => array(get_option('w2dc_jquery_ui_schemas')),
											'binding' => array(
												'field' => 'w2dc_color_scheme',
												'function' => 'w2dc_affect_setting_w2dc_jquery_ui_schemas'
											),
										),
									),
								),
							),
						),
						'social_sharing' => array(
							'name' => 'social_sharing',
							'title' => __('Social Sharing', 'W2DC'),
							'icon' => 'font-awesome:w2dc-fa-facebook ',
							'controls' => array(
								'social_sharing' => array(
									'type' => 'section',
									'title' => __('Listings Social Sharing Buttons', 'W2DC'),
									'fields' => array(
										array(
											'type' => 'radioimage',
											'name' => 'w2dc_share_buttons_style',
											'label' => __('Buttons style', 'W2DC'),
									 		'items' => array(
									 			array(
									 				'value' => 'arbenta',
									 				'label' =>__('Arbenta', 'W2DC'),
									 				'img' => W2DC_RESOURCES_URL . 'images/social/arbenta/facebook.png'
									 			),
									 			array(
									 				'value' => 'flat',
													'label' =>__('Flat', 'W2DC'),
									 				'img' => W2DC_RESOURCES_URL . 'images/social/flat/facebook.png'
									 			),
									 			array(
									 				'value' => 'somacro',
													'label' =>__('Somacro', 'W2DC'),
									 				'img' => W2DC_RESOURCES_URL . 'images/social/somacro/facebook.png'
									 			),
									 		),
											'default' => array(get_option('w2dc_share_buttons_style')),
										),
										array(
											'type' => 'sorter',
											'name' => 'w2dc_share_buttons',
											'label' => __('Include and order buttons', 'W2DC'),
									 		'items' => $w2dc_social_services,
											'default' => get_option('w2dc_share_buttons'),
										),
										array(
											'type' => 'toggle',
											'name' => 'w2dc_share_counter',
											'label' => __('Enable counter', 'W2DC'),
											'default' => get_option('w2dc_share_counter'),
										),
										array(
											'type' => 'radiobutton',
											'name' => 'w2dc_share_buttons_place',
											'label' => __('Where to place buttons on a listing page', 'W2DC'),
											'items' => array(
												array(
													'value' => 'title',
													'label' =>__('After title', 'W2DC'),
												),
												array(
													'value' => 'before_content',
													'label' =>__('Before text content', 'W2DC'),
												),
												array(
													'value' => 'after_content',
													'label' =>__('After text content', 'W2DC'),
												),
											),
											'default' => array(
													get_option('w2dc_share_buttons_place')
											),
										),
										array(
											'type' => 'slider',
											'name' => 'w2dc_share_buttons_width',
											'label' => __('Social buttons width (in pixels)', 'W2DC'),
											'default' => get_option('w2dc_share_buttons_width'),
									 		'min' => 24,
									 		'max' => 64,
										),
									),
								),
							),
						),
					)
				),
				//'menu_page' => 'w2dc_settings',
				'use_auto_group_naming' => true,
				'use_util_menu' => false,
				'minimum_role' => $capability,
				'layout' => 'fixed',
				'page_title' => __('Directory settings', 'W2DC'),
				'menu_label' => __('Directory settings', 'W2DC'),
		);
		
		// adapted for WPML /////////////////////////////////////////////////////////////////////////
		global $sitepress;
		if (function_exists('wpml_object_id_filter') && $sitepress) {
			$theme_options['template']['menus']['advanced']['controls']['wpml'] = array(
				'type' => 'section',
				'title' => __('WPML Settings', 'W2DC'),
				'fields' => array(
					array(
						'type' => 'toggle',
						'name' => 'w2dc_map_language_from_wpml',
						'label' => __('Force WPML language on maps', 'W2DC'),
						'description' => __("Ignore the browser's language setting and force it to display information in a particular WPML language", 'W2DC'),
						'default' => get_option('w2dc_map_language_from_wpml'),
					),
				),
			);
		}
		
		$theme_options = apply_filters('w2dc_build_settings', $theme_options);

		$VP_W2DC_Option = new VP_W2DC_Option($theme_options);
	}

	public function save_option($opts, $old_opts, $status) {
		global $w2dc_wpml_dependent_options, $sitepress;

		if ($status) {
			foreach ($opts AS $option=>$value) {
				// adapted for WPML
				if (in_array($option, $w2dc_wpml_dependent_options)) {
					if (function_exists('wpml_object_id_filter') && $sitepress) {
						if ($sitepress->get_default_language() != ICL_LANGUAGE_CODE) {
							update_option($option.'_'.ICL_LANGUAGE_CODE, $value);
							continue;
						}
					}
				}

				if (
					$option == 'w2dc_google_api_key' ||
					$option == 'w2dc_google_api_key_server' ||
					$option == 'w2dc_mapbox_api_key'
				) {
					$value = trim($value);
				}
				update_option($option, $value);
			}
			
			w2dc_save_dynamic_css();
			flush_rewrite_rules();
		}
	}
}

function w2dc_save_dynamic_css() {
	$upload_dir = wp_upload_dir();
	$filename = trailingslashit($upload_dir['basedir']) . 'w2dc-plugin.css';
		
	ob_start();
	include W2DC_PATH . '/classes/customization/dynamic_css.php';
	$dynamic_css = ob_get_contents();
	ob_get_clean();
		
	global $wp_filesystem;
	if (empty($wp_filesystem)) {
		require_once(ABSPATH .'/wp-admin/includes/file.php');
		WP_Filesystem();
	}
		
	if ($wp_filesystem) {
		$wp_filesystem->put_contents(
				$filename,
				$dynamic_css,
				FS_CHMOD_FILE // predefined mode settings for WP files
		);
	}
}

// adapted for WPML
function w2dc_get_wpml_dependent_option_name($option) {
	global $w2dc_wpml_dependent_options, $sitepress;

	if (in_array($option, $w2dc_wpml_dependent_options))
		if (function_exists('wpml_object_id_filter') && $sitepress)
			if ($sitepress->get_default_language() != ICL_LANGUAGE_CODE)
				if (get_option($option.'_'.ICL_LANGUAGE_CODE) !== false)
					return $option.'_'.ICL_LANGUAGE_CODE;

	return $option;
}
function w2dc_get_wpml_dependent_option($option) {
	return get_option(w2dc_get_wpml_dependent_option_name($option));
}
function w2dc_get_wpml_dependent_option_description() {
	global $sitepress;
	return ((function_exists('wpml_object_id_filter') && $sitepress) ? sprintf(__('%s This is multilingual option, each language may have own value.', 'W2DC'), '<br /><img src="'.W2DC_RESOURCES_URL . 'images/multilang.png" /><br />') : '');
}


function w2dc_google_type_setting($value) {
	if ($value == 'google') {
		return true;
	}
}
VP_W2DC_Security::instance()->whitelist_function('w2dc_google_type_setting');

function w2dc_mapbox_type_setting($value) {
	if ($value == 'mapbox') {
		return true;
	}
}
VP_W2DC_Security::instance()->whitelist_function('w2dc_mapbox_type_setting');

function w2dc_map_markers_icons_setting($value) {
	if ($value == 'icons') {
		return true;
	}
}
VP_W2DC_Security::instance()->whitelist_function('w2dc_map_markers_icons_setting');

function w2dc_map_markers_images_setting($value) {
	if ($value == 'images') {
		return true;
	}
}
VP_W2DC_Security::instance()->whitelist_function('w2dc_map_markers_images_setting');

?>