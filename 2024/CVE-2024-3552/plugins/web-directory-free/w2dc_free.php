<?php
/*
Plugin Name: Web Directory Free
Plugin URI: https://www.salephpscripts.com/wordpress_directory/
Description: Free version of Web 2.0 Directory plugin. Build Directory or Classifieds site in some minutes. The plugin combines flexibility of WordPress and functionality of Directory and Classifieds
Version: 1.6.9
Author: salephpscripts.com
Author URI: http://www.salephpscripts.com
License: GPLv2 or any later version
*/

define('W2DCF_VERSION', '1.6.9');
define('W2DC_VERSION_TAG', W2DCF_VERSION);
define('W2DC_INSTALLED_VERSION_SETTING_NAME', 'w2dcf_installed_directory_version');
define('W2DC_VERSION_COMPATIBLE', '2.9.26');

if (defined('W2DC_VERSION')) {
	deactivate_plugins(basename(__FILE__)); // Deactivate ourself
	wp_die(sprintf("Sorry, but free version of Web 2.0 Directory plugin isn't compatible with its full version. Only one of them can work on the site. Deactivate Web 2.0 Directory plugin first. <a href='%s'>Back to plugin's page</a>", admin_url('plugins.php')));
}

define('W2DC_PATH', plugin_dir_path(__FILE__));
define('W2DC_URL', plugins_url('/', __FILE__));

define('W2DC_TEMPLATES_PATH', W2DC_PATH . 'templates/');

define('W2DC_RESOURCES_PATH', W2DC_PATH . 'resources/');
define('W2DC_RESOURCES_URL', W2DC_URL . 'resources/');

define('W2DC_POST_TYPE', 'w2dc_listing');
define('W2DC_CATEGORIES_TAX', 'w2dc-category');
define('W2DC_LOCATIONS_TAX', 'w2dc-location');
define('W2DC_TAGS_TAX', 'w2dc-tag');

define('W2DC_MAPBOX_VERSION', 'v3.0.1');

include_once W2DC_PATH . 'install.php';
include_once W2DC_PATH . 'classes/admin.php';
include_once W2DC_PATH . 'classes/form_validation.php';
include_once W2DC_PATH . 'classes/post.php';
include_once W2DC_PATH . 'classes/ordering.php';
include_once W2DC_PATH . 'search/adapter.php';
include_once W2DC_PATH . 'classes/listings/listings_manager.php';
include_once W2DC_PATH . 'classes/listings/listing.php';
include_once W2DC_PATH . 'classes/listings/listings_packages.php';
include_once W2DC_PATH . 'classes/categories_manager.php';
include_once W2DC_PATH . 'classes/media_manager.php';
include_once W2DC_PATH . 'classes/upload_image.php';
include_once W2DC_PATH . 'classes/content_fields/content_fields_manager.php';
include_once W2DC_PATH . 'classes/content_fields/content_fields.php';
include_once W2DC_PATH . 'classes/locations/locations_manager.php';
include_once W2DC_PATH . 'classes/locations/locations_levels_manager.php';
include_once W2DC_PATH . 'classes/locations/locations_levels.php';
include_once W2DC_PATH . 'classes/locations/location.php';
include_once W2DC_PATH . 'classes/levels/levels_manager.php';
include_once W2DC_PATH . 'classes/levels/levels.php';
include_once W2DC_PATH . 'classes/directories/directories.php';
include_once W2DC_PATH . 'classes/demo_data.php';
include_once W2DC_PATH . 'classes/frontend_controller.php';
include_once W2DC_PATH . 'classes/shortcodes/directory_controller.php';
include_once W2DC_PATH . 'classes/shortcodes/listings_controller.php';
include_once W2DC_PATH . 'classes/shortcodes/map_controller.php';
include_once W2DC_PATH . 'classes/shortcodes/categories_controller.php';
include_once W2DC_PATH . 'classes/shortcodes/locations_controller.php';
include_once W2DC_PATH . 'classes/shortcodes/search_controller.php';
include_once W2DC_PATH . 'classes/shortcodes/slider_controller.php';
include_once W2DC_PATH . 'classes/shortcodes/buttons_controller.php';
include_once W2DC_PATH . 'classes/shortcodes/term_title_controller.php';
include_once W2DC_PATH . 'classes/shortcodes/term_description_controller.php';
include_once W2DC_PATH . 'classes/shortcodes/breadcrumbs_controller.php';
include_once W2DC_PATH . 'classes/shortcodes/page_header_controller.php';
include_once W2DC_PATH . 'classes/shortcodes/page_title_controller.php';
include_once W2DC_PATH . 'classes/shortcodes/content_field_controller.php';
include_once W2DC_PATH . 'classes/shortcodes/content_fields_group_controller.php';
include_once W2DC_PATH . 'classes/shortcodes/demo_links_controller.php';
include_once W2DC_PATH . 'classes/shortcodes/listing_header_controller.php';
include_once W2DC_PATH . 'classes/shortcodes/listing_gallery_controller.php';
include_once W2DC_PATH . 'classes/shortcodes/listing_map_controller.php';
include_once W2DC_PATH . 'classes/shortcodes/listing_videos_controller.php';
include_once W2DC_PATH . 'classes/shortcodes/listing_contact_controller.php';
include_once W2DC_PATH . 'classes/shortcodes/listing_report_controller.php';
include_once W2DC_PATH . 'classes/shortcodes/listing_comments_controller.php';
include_once W2DC_PATH . 'classes/shortcodes/listing_fields_controller.php';
include_once W2DC_PATH . 'classes/shortcodes/directory_source_controller.php';
include_once W2DC_PATH . 'classes/breadcrumbs.php';
include_once W2DC_PATH . 'classes/ajax_controller.php';
include_once W2DC_PATH . 'vafpress-framework/bootstrap.php';
include_once W2DC_PATH . 'classes/settings_manager.php';
include_once W2DC_PATH . 'classes/maps/maps.php';
include_once W2DC_PATH . 'classes/maps/map_sidebar.php';
include_once W2DC_PATH . 'classes/widgets/widget.php';
include_once W2DC_PATH . 'classes/widgets/directory.php';
include_once W2DC_PATH . 'classes/widgets/breadcrumbs.php';
include_once W2DC_PATH . 'classes/widgets/search.php';
include_once W2DC_PATH . 'classes/widgets/categories.php';
include_once W2DC_PATH . 'classes/widgets/categories_sidebar.php';
include_once W2DC_PATH . 'classes/widgets/locations.php';
include_once W2DC_PATH . 'classes/widgets/locations_sidebar.php';
include_once W2DC_PATH . 'classes/widgets/map.php';
include_once W2DC_PATH . 'classes/widgets/slider.php';
include_once W2DC_PATH . 'classes/widgets/listings.php';
include_once W2DC_PATH . 'classes/widgets/listings_sidebar.php';
include_once W2DC_PATH . 'classes/widgets/buttons.php';
include_once W2DC_PATH . 'classes/widgets/levels_table.php';
include_once W2DC_PATH . 'classes/widgets/listing_comments.php';
include_once W2DC_PATH . 'classes/widgets/listing_contact.php';
include_once W2DC_PATH . 'classes/widgets/listing_fields.php';
include_once W2DC_PATH . 'classes/widgets/listing_gallery.php';
include_once W2DC_PATH . 'classes/widgets/listing_header.php';
include_once W2DC_PATH . 'classes/widgets/listing_map.php';
include_once W2DC_PATH . 'classes/widgets/listing_page.php';
include_once W2DC_PATH . 'classes/widgets/listing_report.php';
include_once W2DC_PATH . 'classes/widgets/listing_videos.php';
include_once W2DC_PATH . 'classes/widgets/content_field.php';
include_once W2DC_PATH . 'classes/widgets/content_fields_group.php';
include_once W2DC_PATH . 'classes/widgets/page_header.php';
include_once W2DC_PATH . 'classes/widgets/elementor/elementor.php';
include_once W2DC_PATH . 'classes/csv/csv_manager.php';
include_once W2DC_PATH . 'classes/csv/listings.php';
include_once W2DC_PATH . 'classes/location_geoname.php';
include_once W2DC_PATH . 'classes/search_form.php';
include_once W2DC_PATH . 'classes/frontpanel_buttons.php';
include_once W2DC_PATH . 'classes/terms/terms_view.php';
include_once W2DC_PATH . 'classes/terms/sort_terms.php';
include_once W2DC_PATH . 'functions.php';
include_once W2DC_PATH . 'functions_ui.php';
include_once W2DC_PATH . 'classes/maps/google_maps_styles.php';
include_once W2DC_PATH . 'classes/compatibility/elementor.php';
include_once W2DC_PATH . 'classes/compatibility/vc.php';
include_once W2DC_PATH . 'classes/customization/color_schemes.php';

// Categories icons constant
if ($custom_dir = w2dc_isCustomResourceDir('images/categories_icons/')) {
	define('W2DC_CATEGORIES_ICONS_PATH', $custom_dir);
	define('W2DC_CATEGORIES_ICONS_URL', w2dc_getCustomResourceDirURL('images/categories_icons/'));
} else {
	define('W2DC_CATEGORIES_ICONS_PATH', W2DC_RESOURCES_PATH . 'images/categories_icons/');
	define('W2DC_CATEGORIES_ICONS_URL', W2DC_RESOURCES_URL . 'images/categories_icons/');
}

// Locations icons constant
if ($custom_dir = w2dc_isCustomResourceDir('images/locations_icons/')) {
	define('W2DC_LOCATION_ICONS_PATH', $custom_dir);
	define('W2DC_LOCATIONS_ICONS_URL', w2dc_getCustomResourceDirURL('images/locations_icons/'));
} else {
	define('W2DC_LOCATION_ICONS_PATH', W2DC_RESOURCES_PATH . 'images/locations_icons/');
	define('W2DC_LOCATIONS_ICONS_URL', W2DC_RESOURCES_URL . 'images/locations_icons/');
}

// Map Markers Icons Path
if ($custom_dir = w2dc_isCustomResourceDir('images/map_icons/')) {
	define('W2DC_MAP_ICONS_PATH', $custom_dir);
	define('W2DC_MAP_ICONS_URL', w2dc_getCustomResourceDirURL('images/map_icons/'));
} else {
	define('W2DC_MAP_ICONS_PATH', W2DC_RESOURCES_PATH . 'images/map_icons/');
	define('W2DC_MAP_ICONS_URL', W2DC_RESOURCES_URL . 'images/map_icons/');
}

global $w2dc_instance;
global $w2dc_messages;

define('W2DC_MAIN_SHORTCODE', 'webdirectory');
define('W2DC_LISTING_SHORTCODE', 'webdirectory-listing-page');

/*
 * There are 2 types of shortcodes in the system:
1. those process as simple wordpress shortcodes
2. require initialization on 'wp' hook

[webdirectory] shortcode must be initialized on 'wp' hook and then renders as simple shortcode
*/
global $w2dc_shortcodes, $w2dc_shortcodes_init;
$w2dc_shortcodes = array(
		W2DC_MAIN_SHORTCODE => 'w2dc_directory_controller',
		W2DC_LISTING_SHORTCODE => 'w2dc_directory_controller', // listings page
		'webdirectory-listings' => 'w2dc_listings_controller',
		'webdirectory-map' => 'w2dc_map_controller',
		'webdirectory-categories' => 'w2dc_categories_controller',
		'webdirectory-locations' => 'w2dc_locations_controller',
		'webdirectory-search' => 'w2dc_search_controller',
		'webdirectory-slider' => 'w2dc_slider_controller',
		'webdirectory-buttons' => 'w2dc_buttons_controller',
		'webdirectory-term-title' => 'w2dc_term_title_controller',
		'webdirectory-term-description' => 'w2dc_term_description_controller',
		'webdirectory-breadcrumbs' => 'w2dc_breadcrumbs_controller',
		'webdirectory-page-header' => 'w2dc_page_header_controller',
		'webdirectory-page-title' => 'w2dc_page_title_controller',
		'webdirectory-content-field' => 'w2dc_content_field_controller',
		'webdirectory-content-fields-group' => 'w2dc_content_fields_group_controller',
		'webdirectory-demo-links' => 'w2dc_demo_links_controller',
		'webdirectory-listing-header' => 'w2dc_listing_header_controller',
		'webdirectory-listing-gallery' => 'w2dc_listing_gallery_controller',
		'webdirectory-listing-map' => 'w2dc_listing_map_controller',
		'webdirectory-listing-videos' => 'w2dc_listing_videos_controller',
		'webdirectory-listing-contact' => 'w2dc_listing_contact_controller',
		'webdirectory-listing-report' => 'w2dc_listing_report_controller',
		'webdirectory-listing-comments' => 'w2dc_listing_comments_controller',
		'webdirectory-listing-fields' => 'w2dc_listing_fields_controller',
);
$w2dc_shortcodes_init = array(
		W2DC_MAIN_SHORTCODE => 'w2dc_directory_controller',
		W2DC_LISTING_SHORTCODE => 'w2dc_directory_controller', // listings page
		'webdirectory-listings' => 'w2dc_listings_controller',
);

class w2dc_plugin {
	public $admin;
	public $listings_manager;
	public $locations_manager;
	public $locations_levels_manager;
	public $categories_manager;
	public $content_fields_manager;
	public $media_manager;
	public $settings_manager;
	public $demo_data_manager;
	public $levels_manager;
	public $csv_manager;
	public $comments_manager;

	public $current_directory = null;
	public $directories;
	public $current_listing; // this is object of listing under edition right now
	public $levels;
	public $locations_levels;
	public $content_fields;
	public $ajax_controller;
	public $listings_packages;
	public $sort_terms;
	public $index_page_id;
	public $index_page_slug;
	public $index_page_url;
	public $index_pages_all = array();
	public $listing_pages_all = array();
	public $original_index_page_id;
	public $listing_page_id;
	public $listing_page_slug;
	public $listing_page_url;
	public $frontend_controllers = array();
	public $_frontend_controllers = array(); // this duplicate property needed because we unset each controller when we render shortcodes, but WP doesn't really know which shortcode already was processed
	public $action;
	
	public $query_change_counter = 0;
	
	private $_temp_post;
	private $_temp_query;
	
	public $radius_values_array = array();
	
	public $order_by_date = false; // special flag, used to display or hide sticky pin

	public function __construct() {
		register_activation_hook(__FILE__, array($this, 'activation'));
		register_deactivation_hook(__FILE__, array($this, 'deactivation'));
	}
	
	public function activation() {
		global $wp_version;

		if (version_compare($wp_version, '3.6', '<')) {
			deactivate_plugins(basename(__FILE__)); // Deactivate ourself
			wp_die("Sorry, but you can't run this plugin on current WordPress version, it requires WordPress v3.6 or higher.");
		}
		flush_rewrite_rules();
		
		wp_schedule_event(current_time('timestamp'), 'hourly', 'scheduled_events');
	}

	public function deactivation() {
		flush_rewrite_rules();

		wp_clear_scheduled_hook('scheduled_events');
	}
	
	public function init() {
		global $w2dc_instance, $w2dc_shortcodes, $w2dc_google_maps_styles, $wpdb;

		if (isset($_REQUEST['w2dc_action'])) {
			$this->action = $_REQUEST['w2dc_action'];
		}

		add_action('plugins_loaded', array($this, 'load_textdomains'));

		if (!isset($wpdb->w2dc_content_fields))
			$wpdb->w2dc_content_fields = $wpdb->prefix . 'w2dc_content_fields';
		if (!isset($wpdb->w2dc_content_fields_groups))
			$wpdb->w2dc_content_fields_groups = $wpdb->prefix . 'w2dc_content_fields_groups';
		if (!isset($wpdb->w2dc_directories))
			$wpdb->w2dc_directories = $wpdb->prefix . 'w2dc_directories';
		if (!isset($wpdb->w2dc_levels))
			$wpdb->w2dc_levels = $wpdb->prefix . 'w2dc_levels';
		if (!isset($wpdb->w2dc_levels_relationships))
			$wpdb->w2dc_levels_relationships = $wpdb->prefix . 'w2dc_levels_relationships';
		if (!isset($wpdb->w2dc_locations_levels))
			$wpdb->w2dc_locations_levels = $wpdb->prefix . 'w2dc_locations_levels';
		if (!isset($wpdb->w2dc_locations_relationships))
			$wpdb->w2dc_locations_relationships = $wpdb->prefix . 'w2dc_locations_relationships';

		add_action('scheduled_events', array($this, 'suspend_expired_listings'));
		add_action('init', array($this, 'suspend_expired_listings'));
		
		foreach ($w2dc_shortcodes AS $shortcode=>$function) {
			add_shortcode($shortcode, array($this, 'renderShortcode'));
		}
		
		add_action('init', array($this, 'register_post_type'), 0);
		add_action('init', array($this, 'getAllDirectoryPages'), 1);
		add_action('wp', array($this, 'loadPagesDirectories'), 1);
		add_action('admin_init', array($this, 'loadPagesDirectories'), 1);
		add_action('admin_init', array($this, 'checkMainShortcode'), 1);
		add_filter('body_class', array($this, 'addBodyClasses'));
		
		add_action('wp', array($this, 'loadFrontendControllers'), 1);

		if (!get_option('w2dc_installed_directory') || get_option(W2DC_INSTALLED_VERSION_SETTING_NAME) != W2DC_VERSION_TAG) {
			// load classes ONLY after directory was fully installed, otherwise it can not get directories, levels, content fields, e.t.c. from the database
			if (get_option('w2dc_installed_directory')) {
				$this->loadClasses();
			}

			add_action('init', 'w2dc_install_directory', 0);
		} else {
			$this->loadClasses();
		}

		add_filter('template_include', array($this, 'printlisting_template'), 100000);

		add_action('wp', array($this, 'wp_loaded'));
		add_filter('query_vars', array($this, 'add_query_vars'));
		add_filter('rewrite_rules_array', array($this, 'rewrite_rules'), 11);
		
		add_filter('redirect_canonical', array($this, 'prevent_wrong_redirect'), 10, 2);
		add_filter('post_type_link', array($this, 'listing_permalink'), 10, 3);
		add_filter('term_link', array($this, 'category_permalink'), 10, 3);
		add_filter('term_link', array($this, 'location_permalink'), 10, 3);
		add_filter('term_link', array($this, 'tag_permalink'), 10, 3);

		// adapted for Polylang
		add_action('init', array($this, 'pll_setup'));

		add_filter('comments_open', array($this, 'filter_comment_status'), 100, 2);
		
		add_filter('wp_unique_post_slug_is_bad_flat_slug', array($this, 'reserve_slugs'), 10, 2);
		
		add_filter('no_texturize_shortcodes', array($this, 'w2dc_no_texturize'));

		add_action('wp_enqueue_scripts', array($this, 'enqueue_scripts_styles'));
		add_action('wp_enqueue_scripts', array($this, 'enqueue_scripts_styles_custom'), 9999);
		add_action('wp_enqueue_scripts', array($this, 'enqueue_dynamic_css'));
		
		add_filter('wpseo_sitemap_post_type_archive_link', array($this, 'exclude_post_type_archive_link'), 10, 2);
		
		add_filter('w2dc_dequeue_maps_googleapis', array($this, 'divi_not_dequeue_maps_api'));
		
		add_filter('plugin_row_meta', array($this, 'plugin_row_meta'), 10, 2);
		add_filter('plugin_action_links_' . plugin_basename(__FILE__), array($this, 'plugin_action_links'));
		
		/*
		 * disabled - listings/categories/locations/tags "pages" work as real listings/categories/locations/tags pages, 
		 * enabled  - all "pages" are wp post type pages, introduced since Version 2.7.5 - April 21, 2021
		*/
		if (!get_option("w2dc_imitate_mode")) {
			add_action('pre_get_posts', array($this, 'pre_get_posts'), 11);
			add_action('template_redirect', array($this, 'template_redirect'));
			add_filter('template_include', array($this, 'template_include'), 99);
			add_filter('the_content', array($this, 'the_content'));
			add_filter('has_post_thumbnail', array($this, 'has_post_thumbnail'), 10, 3);
			add_filter('the_title', array($this, 'the_title'));
			add_filter('get_edit_post_link', array($this, 'get_edit_post_link'), 10, 3);
			
			add_action('loop_start', array($this, 'limit_posts_on_tax_pages'), 0);
			
			add_action('wp_head', array($this, 'change_wp_query'), -99999);
		} else {
			add_action('wp_head', array($this, 'change_wp_query'), -99999);
			add_action('wp_head', array($this, 'back_wp_query_imitate'), 99999);
			
			add_filter('pre_get_document_title', array($this, '_change_wp_query'), -99999);
			add_filter('pre_get_document_title', array($this, '_back_wp_query_imitate'), 99999);
		}
		
		$w2dc_google_maps_styles = apply_filters('w2dc_google_maps_styles', $w2dc_google_maps_styles);
	}
	
	public function limit_posts_on_tax_pages($query) {
		
		if ($query->is_main_query() && !$query->is_admin) {
			if (w2dc_isListing() || w2dc_isCategory() || w2dc_isLocation() || w2dc_isTag()) {
				$query->posts = array(get_post($this->index_page_id));
				$query->post_count = 1;
			}
		}
	}
	
	public function _change_wp_query($title) {
	
		$this->query_change_counter++;

		$this->change_wp_query();
		
		return $title;
	}
	
	public function change_wp_query() {
		global $post;
		global $wp_query;
	
		if (($queried_object = w2dc_isListing())) {
			$this->_temp_post				= $post;
			$this->_temp_query				= $wp_query;

			$wp_query = new WP_Query(array(
					'post_type' => W2DC_POST_TYPE,
					'name' => $queried_object->post->post_name,
					'posts_per_page' => 1,
			));

			$post							= $queried_object->post;
			$GLOBALS['wp_the_query']		= $wp_query;
			
		} elseif (($queried_object = w2dc_isCategory()) || ($queried_object = w2dc_isLocation()) || ($queried_object = w2dc_isTag())) {
			$this->_temp_post				= $post;
			$this->_temp_query				= $wp_query;
	
			$wp_query->is_tax				= true;
			$wp_query->is_singular			= false;
			$wp_query->is_archive			= false;
			$wp_query->is_home				= false;
			$wp_query->is_page				= false;
			$wp_query->queried_object		= $queried_object;
			$wp_query->queried_object_id	= $queried_object->term_id;
			$wp_query->tax_query = new WP_Tax_Query(array(
					'taxonomy' => $queried_object->taxonomy,
					'terms' => $queried_object->term_id,
					'fields' => 'term_id',
			));
			
			$GLOBALS['wp_the_query']		= $wp_query;
		}
	}
	
	public function _back_wp_query_imitate($title) {
		
		$this->query_change_counter--;

		if ($this->query_change_counter == 0) {
			$this->back_wp_query_imitate();
		}
		
		return $title;
	}
	
	public function back_wp_query_imitate() {
	
		if ($this->_temp_query) {
			global $post;
			global $wp_query;
			
			// $post can be changed to 'page' type inside functions, so we have to use $wp_query->query_vars['post_type']
			if ($wp_query->query_vars['post_type'] == W2DC_POST_TYPE && $this->listing_page_id) {
				$post						= get_post($this->listing_page_id);
			} else {
				$post						= get_post($this->index_page_id);
			}
			
			$wp_query						= $this->_temp_query;
			$GLOBALS['wp_the_query']		= $wp_query;
			
			$wp_query->is_singular			= true;
			$wp_query->is_tax				= false;
			$wp_query->is_home				= false;
			$wp_query->is_page				= true;
			$wp_query->queried_object_id	= $post->ID;
			$wp_query->queried_object		= $post;
		}
	}
	
	public function get_edit_post_link($link, $post_id, $context) {
		
		if (!is_admin()) {
			if (get_post_type($post_id) == W2DC_POST_TYPE) {
				if (w2dc_isCategory() || w2dc_isLocation() || w2dc_isTag()) {
					return false;
				}
			}
		}
		
		return $link;
	}
	
	public function pre_get_posts($query) {
		
		if ($query->is_main_query() && !$query->is_admin) {
			if (w2dc_isCategory() || w2dc_isLocation() || w2dc_isTag()) {
				$query->set('posts_per_page', get_option("w2dc_listings_number_excerpt"));
			}
		}
	}
	
	public function the_title($title) {
		
		if (in_the_loop() && is_main_query()) {
			
			remove_filter("the_title", array($this, "the_title"));
			
			if (w2dc_isListing() || w2dc_isCategory() || w2dc_isLocation() || w2dc_isTag()) {
				if (!empty(w2dc_getFrontendControllers(W2DC_MAIN_SHORTCODE))) {
					$controllers = w2dc_getFrontendControllers(W2DC_MAIN_SHORTCODE);
					
					$title = $controllers[0]->page_title;
				}
			}
		}
	
		return $title;
	}
	
	public function has_post_thumbnail($has_thumbnail, $post, $thumbnail_id) {
		
		if (get_post_type($post) == W2DC_POST_TYPE) {
			return false;
		}
	
		return $has_thumbnail;
	}

	public function template_redirect() {
		
		if (w2dc_isListing() || w2dc_isCategory() || w2dc_isLocation() || w2dc_isTag()) {

			global $wp_query;
			// empty tax pages does not render any content
			if ($wp_query->post_count == 0) {
				$wp_query->post_count = 1;
				$wp_query->posts[] = get_post($this->index_page_id);
			}
			
			$controller = new w2dc_directory_controller();
			
			$args = array();
			if (w2dc_isCustomHomePage()) {
				$args = array('custom_home' => 1);
			}
			$controller->init($args);
			
			if (w2dc_isListing() && $this->listing_page_id) {
				$shortcode = W2DC_LISTING_SHORTCODE;
			} else {
				$shortcode = W2DC_MAIN_SHORTCODE;
			}

			w2dc_setFrontendController($shortcode, $controller);
		}
	}
	
	public function template_include($template) {
		
		if (w2dc_isListing() || w2dc_isCategory() || w2dc_isLocation() || w2dc_isTag()) {
			$default_template = w2dc_directory_locate_template();
			
			$default_template = apply_filters("w2dc_page_default_template", $default_template);
			
			if ($default_template != '') {
				return $default_template;
			}
		}
		
		return $template;
	}
	
	public function the_content($content) {
		
		if (in_the_loop() && is_main_query()) {
			
			remove_filter("the_content", array($this, "the_content"));
			
			global $w2dc_do_listing_content;
			if ($w2dc_do_listing_content) {
				return $content;
			}
			
			if (w2dc_isListing() || w2dc_isCategory() || w2dc_isLocation() || w2dc_isTag()) {
				
				if (w2dc_isListing() && $this->listing_page_id) {
					$content = get_the_content(null, false, $this->listing_page_id);
					$content = do_shortcode($content);
					
					$content = apply_filters("w2dc_the_content_listing_page", $content);
					
					if ($content) {
						return $content;
					}
				}
				
				/* if (w2dc_isCategory() || w2dc_isLocation() || w2dc_isTag()) {
					$content = get_the_content(null, false, $this->index_page_id);
					
					if ($content) {
						return $content;
					}
				} */
				
				if (!empty(w2dc_getFrontendControllers(W2DC_MAIN_SHORTCODE))) {
					$controllers = w2dc_getFrontendControllers(W2DC_MAIN_SHORTCODE);
					
					$content = $controllers[0]->display();
					echo $content;
					return "";
				}
			}
		}
		
		return $content;
	}
	
	public function load_textdomains() {
		load_plugin_textdomain('W2DC', '', dirname(plugin_basename( __FILE__ )) . '/languages');
	}
	
	public function loadClasses() {
		$this->directories = new w2dc_directories;
		$this->levels = new w2dc_levels;
		$this->locations_levels = new w2dc_locations_levels;
		$this->content_fields = new w2dc_content_fields;
		$this->ajax_controller = new w2dc_ajax_controller;
		$this->admin = new w2dc_admin;
		$this->listings_packages = new w2dc_listings_packages;
		$this->sort_terms = new w2dc_sort_terms;
	}

	public function w2dc_no_texturize($shortcodes) {
		global $w2dc_shortcodes;
		
		foreach ($w2dc_shortcodes AS $shortcode=>$function)
			$shortcodes[] = $shortcode;
		
		return $shortcodes;
	}

	public function renderShortcode() {
		global $w2dc_shortcodes;
	
		// remove content filters in order not to break the layout of page
		$filters_to_remove = array(
				'wpautop',
				'wptexturize',
				'shortcode_unautop',
				'convert_chars',
				'prepend_attachment',
				'convert_smilies',
		);
		$filters_to_repair = array();
		foreach ($filters_to_remove AS $filter) {
			while (($priority = has_filter('the_content', $filter)) !== false) {
				$filters_to_repair[$filter] = $priority;
				
				remove_filter('the_content', $filter, $priority);
			}
		}
	
		$attrs = func_get_args();
		$shortcode = $attrs[2];
	
		$filters_where_not_to_display = array(
				'wp_head',
				'init',
				'wp',
				'edit_attachment',
		);
			
		//var_dump(current_filter());
		if (isset($this->_frontend_controllers[$shortcode]) && !in_array(current_filter(), $filters_where_not_to_display)) {
			$shortcode_controllers = $this->_frontend_controllers[$shortcode];
			foreach ($shortcode_controllers AS $key=>&$controller) {
				unset($this->_frontend_controllers[$shortcode][$key]); // there are possible more than 1 same shortcodes on a page, so we have to unset which already was displayed
				if (method_exists($controller, 'display')) {
					$out = $controller->display();
				
					if ($filters_to_repair) {
						foreach ($filters_to_repair AS $filter=>$priority) {
							add_filter('the_content', $filter, $priority);
						}
					}
					
					return $out;
				}
			}
		}
	
		if (isset($w2dc_shortcodes[$shortcode])) {
			$shortcode_class = $w2dc_shortcodes[$shortcode];
			if ($attrs[0] === '')
				$attrs[0] = array();
			$shortcode_instance = new $shortcode_class();
			$shortcode_instance->init($attrs[0], $shortcode);
			
			w2dc_setFrontendController($shortcode, $shortcode_instance, false);
	
			if (method_exists($shortcode_instance, 'display')) {
				
				$out = $shortcode_instance->display();
				
				if ($filters_to_repair) {
					foreach ($filters_to_repair AS $filter=>$priority) {
						add_filter('the_content', $filter, $priority);
					}
				}
				
				return $out;
			}
		}
	}

	public function loadFrontendControllers() {
		global $post, $wp_query;

		if ($wp_query->posts) {
			$pattern = get_shortcode_regex();
			foreach ($wp_query->posts AS $archive_post) {
				if (isset($archive_post->post_content)) {
					$this->loadNestedFrontendController($pattern, $archive_post->post_content);
				}
				do_action("w2dc_load_frontend_controllers", $archive_post);
			}
		} elseif ($post && isset($post->post_content)) {
			$pattern = get_shortcode_regex();
			$this->loadNestedFrontendController($pattern, $post->post_content);
			
			do_action("w2dc_load_frontend_controllers", $post);
		}
	}

	// this may be recursive function to catch nested shortcodes
	public function loadNestedFrontendController($pattern, $content) {
		global $w2dc_shortcodes_init, $w2dc_shortcodes;

		if (preg_match_all('/'.$pattern.'/s', $content, $matches) && array_key_exists(2, $matches)) {
			foreach ($matches[2] AS $key=>$shortcode) {
				if ($shortcode != 'shortcodes') {
					if (isset($w2dc_shortcodes_init[$shortcode]) && class_exists($w2dc_shortcodes_init[$shortcode])) {
						$shortcode_class = $w2dc_shortcodes_init[$shortcode];
						if (!($attrs = shortcode_parse_atts($matches[3][$key]))) {
							$attrs = array();
						}
						
						$shortcode_instance = new $shortcode_class();
						
						w2dc_setFrontendController($shortcode, $shortcode_instance);
						
						$shortcode_instance->init($attrs, $shortcode);
					} elseif (isset($w2dc_shortcodes[$shortcode]) && class_exists($w2dc_shortcodes[$shortcode])) {
						$shortcode_class = $w2dc_shortcodes[$shortcode];
						w2dc_setFrontendController($shortcode, $shortcode_class, false);
					}
					if ($shortcode_content = $matches[5][$key])
						$this->loadNestedFrontendController($pattern, $shortcode_content);
				}
			}
		}
	}
	
	public function getAllDirectoryPages() {
		$this->index_pages_all = w2dc_getAllDirectoryPages();
		$this->listing_pages_all = w2dc_getAllListingPages();
	}
	
	public function loadPagesDirectories() {
		$this->getIndexPage();
		$this->setCurrentDirectory();

		do_action('w2dc_load_pages_directories');
	}
	
	public function checkMainShortcode() {
		if ($this->index_page_id === 0 && is_admin()) {
			w2dc_addMessage(sprintf(__("<b>Web 2.0 Directory plugin</b>: sorry, but there isn't any page with [webdirectory] shortcode. This is mandatory page. Create <a href=\"%s\">this special page</a> for you?", 'W2DC'), admin_url('admin.php?page=w2dc_settings&action=directory_page_installation')), 'error');
		}
		
		if (w2dc_is_maps_used() && w2dc_getMapEngine() == 'google' && !get_option('w2dc_google_api_key') && is_admin()) {
			w2dc_addMessage(sprintf(__("<b>Web 2.0 Directory plugin</b>: Google requires mandatory Maps API key for maps created on NEW websites/domains. Please, <a href=\"https://www.salephpscripts.com/wordpress_directory/demo/documentation/#google_maps_keys\" target=\"_blank\">follow instructions</a> and enter API key on <a href=\"%s\">directory settings page</a>. Otherwise it may cause problems with Google Maps, Geocoding, addition/edition listings locations, autocomplete on addresses fields.", 'W2DC'), admin_url('admin.php?page=w2dc_settings#_advanced')), 'error');
		}
	}

	public function getIndexPage() {
		if ($array = w2dc_getIndexPage()) {
			$this->index_page_id = $array['id'];
			$this->index_page_slug = $array['slug'];
			$this->index_page_url = $array['url'];
		}
		
		if ($array = w2dc_getListingPage()) {
			$this->listing_page_id = $array['id'];
			$this->listing_page_slug = $array['slug'];
			$this->listing_page_url = $array['url'];
		}
	}
	
	public function setCurrentDirectory($current_directory = null) {
		global $pagenow;

		if (isset($_REQUEST['directory']) && is_numeric($_REQUEST['directory']) && ($directory = $this->directories->getDirectoryById($_REQUEST['directory']))) {
			$current_directory = $directory;
		}
		if (isset($_REQUEST['directories']) && is_numeric($_REQUEST['directories']) && ($directory = $this->directories->getDirectoryById($_REQUEST['directories']))) {
			$current_directory = $directory;
		}
		if (is_admin() && $pagenow == 'post-new.php' && isset($_GET['post_type']) && $_GET['post_type'] == W2DC_POST_TYPE && isset($_GET['directory_id']) && is_numeric($_GET['directory_id']) && ($directory = $this->directories->getDirectoryById($_GET['directory_id']))) {
			$current_directory = $directory;
		}

		if (!$current_directory && ($listing = w2dc_isListing())) {
			$current_directory = $listing->directory;
		}

		if (!$current_directory && get_query_var('directory-w2dc')) {
			$current_directory = $this->directories->getDirectoryById(get_query_var('directory-w2dc'));
		}

		if (!$current_directory) {
			// If current page is not webdirectory index page, then pass, and make current directory = default directory
			if (($this->index_page_id == get_queried_object_id()) || (wp_doing_ajax() && $this->isAJAXIndexPage()) ) {
				$current_directory = $this->directories->getDirectoryOfPage($this->index_page_id);
			}
		}
		if (!$current_directory) {
			$current_directory = $this->directories->getDefaultDirectory();
		}
		return ($this->current_directory = $current_directory);
	}
	
	public function isAJAXIndexPage() {
		global $wp_rewrite;

		if ($wp_rewrite->using_permalinks()) {
			if (isset($_REQUEST['base_url'])) {
				$base_url = $_REQUEST['base_url'];
				if (strtok($base_url, '?') == $this->index_page_url) {
					return true;
				}
			}
		} else {
			if (
				isset($_REQUEST['base_url']) && 
				($base_url = wp_parse_args($_REQUEST['base_url'])) &&
				isset($base_url['homepage']) &&
				$base_url['homepage'] == $this->index_page_id
			) {
				return true;
			}
		}
		return false;
	}
	
	public function addBodyClasses($classes) {
		$classes[] = 'w2dc-body';
		
		if (!empty($this->frontend_controllers)) {
			$classes[] = 'w2dc-directory-' . $this->current_directory->id;
		}
		
		if (get_option("w2dc_imitate_mode")) {
			$classes[] = 'w2dc-imitate-mode';
		}
		
		return $classes;
	}

	public function add_query_vars($vars) {
		$vars[] = 'directory-w2dc';
		$vars[] = 'tax-slugs-w2dc';
		$vars[] = 'listing-w2dc';
		$vars[] = 'homepage';

		if (!is_admin()) {
			// order query var may damage sorting of listings at the frontend - it shows WP posts instead of directory listings
			$key = array_search('order', $vars);
			unset($vars[$key]);
		}

		return $vars;
	}
	
	public function rewrite_rules($rules) {
		return $this->w2dc_addRules() + $rules;
	}
	
	public function w2dc_addRules() {
		$rules = array();
		foreach ($this->index_pages_all AS $page) {
			$this->index_page_id = $page['id'];
			$this->index_page_slug = $page['slug'];
			$this->index_page_url = get_permalink($page['id']);
				
			// adapted for WPML
			global $sitepress;
			if (function_exists('wpml_object_id_filter') && $sitepress && ($languages = $sitepress->get_active_languages()) && count($languages) > 1) {
				$this->original_index_page_id = $this->index_page_id;
				//$this->original_listing_page_id = $this->listing_page_id;
				foreach ($languages AS $lang_code=>$lang) {
					if ($this->index_page_id = apply_filters('wpml_object_id', $this->original_index_page_id, 'page', false, $lang_code)) {
						$post = get_post($this->index_page_id);
						$this->index_page_slug = $post->post_name;
						//$this->listing_page_id = apply_filters('wpml_object_id', $original_listing_page_id, 'page', true, $lang_code);
	
						//var_dump($this->buildRules($lang_code));
						$rules = $rules + $this->buildRules($lang_code);
					}
				}
				//$this->getIndexPage();
				//return $rules;
			} else {
				$rules = $rules + $this->buildRules();
			}
		}
		$this->getIndexPage();
		return $rules;
	}
	
	public function buildRules($lang_code = '') {
		global $w2dc_instance;
		
		// adapted for WPML
		//
		// If it was set to use different languages in directories ((http://wp/ - English, http://wp/it/ - Italian)),
		// WPML removes this directory from home page url and we can not match "language-based" rewrite rule by exact request - 
		// home_url() simply gives path without directory and $wp->parse_request() does not see any difference between language URLs,
		// so we have to build rules "on the fly" for each switching of language.
		// The last chance we might have when webdirectory page could not be home page.
		global $sitepress;
		if (function_exists('wpml_object_id_filter') && $sitepress) {
			if (
			$sitepress->get_setting('language_negotiation_type') == 1 &&
			$lang_code != ICL_LANGUAGE_CODE &&
			get_option('show_on_front') != 'posts' &&
			get_option('page_on_front') == $this->original_index_page_id
			) {
				return array();
			}
		}
		
		global $wp_rewrite;

		$lang_param = '';

		// adapted for WPML
		global $sitepress;
		if ($lang_code && function_exists('wpml_object_id_filter') && $sitepress) {
			if ($sitepress->get_setting('language_negotiation_type') == 3 && $lang_code != $sitepress->get_default_language()) {
				//$lang_param = '\?lang=ru';
				$lang_param = '';
				// Need research!  latest version of WPML do not need lang param to be matched with rule, it is not included into request. Example:
				// Request:        listing/united-states-ru/california-ru/los-angeles-ru/super-shopping-in-la
				// Matched Rule:   (directory-classifieds-it)?/?listing/(.+?)/([^\/.]+)/?$
			}
		}

		$page_url = $this->index_page_slug;

		foreach (get_post_ancestors($this->index_page_id) AS $parent_id) {
			$parent = get_page($parent_id);
			$page_url = $parent->post_name . '/' . $page_url;
		}
		
		$rules['(' . $page_url . ')/' . $wp_rewrite->pagination_base . '/?([0-9]{1,})/?' . $lang_param . '$'] = 'index.php?page_id=' .  $this->index_page_id . '&paged=$matches[2]';
		$rules['(' . $page_url . ')/?' . $lang_param . '$'] = 'index.php?page_id=' .  $this->index_page_id;
		
		$category_page_id = $this->index_page_id;
		$location_page_id = $this->index_page_id;
		$tag_page_id = $this->index_page_id;

		if (!($directory = $w2dc_instance->directories->getDirectoryOfPage($this->index_page_id))) {
			$directory = $w2dc_instance->directories->getDefaultDirectory();
		}

		if (isset($this->listing_pages_all[$directory->id])) {
			$listing_page_id = $this->listing_pages_all[$directory->id];
		} elseif (isset($this->listing_pages_all[$this->directories->getDefaultDirectory()->id])) {
			$listing_page_id = $this->listing_pages_all[$this->directories->getDefaultDirectory()->id];
		} else {
			$listing_page_id = $this->index_page_id;
		}
		// adapted for WPML
		global $sitepress;
		if (function_exists('wpml_object_id_filter') && $sitepress) {
			$listing_page_id = apply_filters('wpml_object_id', $listing_page_id, 'page', true, $lang_code);
		}
		
		$review_page_id = apply_filters('w2dc_review_page_id', $listing_page_id);
		$all_reviews_page_id = apply_filters('w2dc_all_reviews_page_id', $listing_page_id);
		
		$listing_slug = $directory->listing_slug;
		$category_slug = $directory->category_slug;
		$location_slug = $directory->location_slug;
		$tag_slug = $directory->tag_slug;

		if (get_option("w2dc_imitate_mode")) {
			$page_param = 'page_id=' .  $category_page_id . '&';
		} else {
			$page_param = '';
		}
		$rules['(' . $page_url . ')?/?' . $category_slug . '/(.+?)/' . $wp_rewrite->pagination_base . '/?([0-9]{1,})/?' . $lang_param . '$'] = 'index.php?'.$page_param.W2DC_CATEGORIES_TAX.'=$matches[2]&paged=$matches[3]';
		$rules['(' . $page_url . ')?/?' . $category_slug . '/(.+?)/?' . $lang_param . '$'] = 'index.php?'.$page_param.W2DC_CATEGORIES_TAX.'=$matches[2]&directory-w2dc=' . $directory->id;
	
		if (get_option("w2dc_imitate_mode")) {
			$page_param = 'page_id=' .  $location_page_id . '&';
		} else {
			$page_param = '';
		}
		$rules['(' . $page_url . ')?/?' . $location_slug . '/(.+?)/' . $wp_rewrite->pagination_base . '/?([0-9]{1,})/?' . $lang_param . '$'] = 'index.php?'.$page_param.W2DC_LOCATIONS_TAX.'=$matches[2]&paged=$matches[3]';
		$rules['(' . $page_url . ')?/?' . $location_slug . '/(.+?)/?' . $lang_param . '$'] = 'index.php?'.$page_param.W2DC_LOCATIONS_TAX.'=$matches[2]&directory-w2dc=' . $directory->id;
	
		if (get_option("w2dc_imitate_mode")) {
			$page_param = 'page_id=' .  $tag_page_id . '&';
		} else {
			$page_param = '';
		}
		$rules['(' . $page_url . ')?/?' . $tag_slug . '/([^\/.]+)/' . $wp_rewrite->pagination_base . '/?([0-9]{1,})/?' . $lang_param . '$'] = 'index.php?'.$page_param.W2DC_TAGS_TAX.'=$matches[2]&paged=$matches[3]';
		$rules['(' . $page_url . ')?/?' . $tag_slug . '/([^\/.]+)/?' . $lang_param . '$'] = 'index.php?'.$page_param.W2DC_TAGS_TAX.'=$matches[2]&directory-w2dc=' . $directory->id;

		if (get_option("w2dc_imitate_mode")) {
			$page_param = 'page_id=' .  $listing_page_id . '&';
			$listing_param = 'listing-w2dc=$matches[2]';
		} else {
			$page_param = '';
			$listing_param = W2DC_POST_TYPE.'=$matches[2]';
		}
		// /%listing_slug%/%postname%/
		$rules['(' . $page_url . ')?/?' . $listing_slug . '/([^\/.]+)/?' . $lang_param . '$'] = 'index.php?'.$page_param.$listing_param;
		// /%listing_slug%/%postname%/reviews/%review%/
		/* if (defined('W2RR_REVIEW_TYPE')) {
			if (get_option("w2rr_display_mode") == "shortcodes") {
				$rules['(' . $page_url . ')?/?' . $listing_slug . '/([^\/.]+)/reviews/([^\/.]+)/?' . $lang_param . '$'] = 'index.php?' . $page_param . 'target-post=$matches[2]&review-w2rr=$matches[3]&name=$matches[3]&post_type=' . W2RR_REVIEW_TYPE;
			} elseif (get_option("w2rr_display_mode") == "comments") {
				$rules['(' . $page_url . ')?/?' . $listing_slug . '/([^\/.]+)/reviews/([^\/.]+)/?' . $lang_param . '$'] = 'index.php?' . $page_param . 'target-post=$matches[2]&review-w2rr=$matches[3]&'.$listing_param;
			}
		} */
		// /%listing_slug%/%postname%/reviews/page/%n%/
		//$rules['(' . $page_url . ')?/?' . $listing_slug . '/([^\/.]+)/reviews/' . $wp_rewrite->pagination_base . '/([0-9]{1,})/?' . $lang_param . '$'] = 'index.php?' . $page_param . 'target-post=$matches[2]&reviews-all=1&paged=matches[3]&' . $listing_param;
		// /%listing_slug%/%postname%/reviews/
		//$rules['(' . $page_url . ')?/?' . $listing_slug . '/([^\/.]+)/reviews/?' . $lang_param . '$'] = 'index.php?' . $page_param . 'target-post=$matches[2]&reviews-all=1&' . $listing_param;
		
		if (get_option("w2dc_imitate_mode")) {
			$page_param = 'page_id=' .  $listing_page_id . '&';
			$listing_param = 'listing-w2dc=$matches[1]';
		} else {
			$page_param = '';
			$listing_param = W2DC_POST_TYPE.'=$matches[1]';
		}
		// /%postname%/
		$rules[$page_url . '/([^\/.]+)/?' . $lang_param . '$'] = 'index.php?'.$page_param.$listing_param;
		// /%postname%/reviews/%review%/
		/* if (defined('W2RR_REVIEW_TYPE')) {
			if (get_option("w2rr_display_mode") == "shortcodes") {
				$rules[$page_url . '/([^\/.]+)/reviews/([^\/.]+)/?' . $lang_param . '$'] = 'index.php?' . $page_param . 'target-post=$matches[1]&review-w2rr=$matches[2]&name=$matches[2]&post_type=' . W2RR_REVIEW_TYPE;
			} elseif (get_option("w2rr_display_mode") == "comments") {
				$rules[$page_url . '/([^\/.]+)/reviews/([^\/.]+)/?' . $lang_param . '$'] = 'index.php?' . $page_param . 'target-post=$matches[1]&review-w2rr=$matches[2]&name=$matches[1]&' . $listing_param;
			}
		} */
		// /%postname%/reviews/page/%n%/
		//$rules[$page_url . '/([^\/.]+)/reviews/' . $wp_rewrite->pagination_base . '/([0-9]{1,})/?' . $lang_param . '$'] = 'index.php?page_id=' . $all_reviews_page_id . '&target-post=$matches[1]&reviews-all=1&paged=$matches[2]&' . $listing_param;
		// /%postname%/reviews/
		//$rules[$page_url . '/([^\/.]+)/reviews/?' . $lang_param . '$'] = 'index.php?page_id=' . $all_reviews_page_id . '&target-post=$matches[1]&reviews-all=1&' . $listing_param;
		
		// /%post_id%/%postname%/
		if (
			strpos(get_option('permalink_structure'), '/%post_id%/%postname%') === FALSE &&
			strpos(get_option('permalink_structure'), '/%year%/%postname%') === FALSE
		) {
			if (get_option("w2dc_imitate_mode")) {
				$page_param = 'page_id=' .  $listing_page_id . '&';
				$listing_param = 'listing-w2dc=$matches[3]';
			} else {
				$page_param = '';
				$listing_param = W2DC_POST_TYPE.'=$matches[3]';
			}
			// /%post_id%/%postname%/ will not work when /%post_id%/%postname%/ or /%year%/%postname%/ was enabled for native WP posts
			// also avoid mismatches with archive pages with /%year%/%monthnum%/ permalinks structure
			$rules['(' . $page_url . ')?/?(?!(?:199[0-9]|20[012][0-9])/(?:0[1-9]|1[012]))([0-9]+)/([^\/.]+)/?' . $lang_param . '$'] = 'index.php?'.$page_param.$listing_param;
			// /%post_id%/%postname%/reviews/%review%/
			/* if (defined('W2RR_REVIEW_TYPE')) {
				if (get_option("w2rr_display_mode") == "shortcodes") {
					$rules['(' . $page_url . ')?/?(?!(?:199[0-9]|20[012][0-9])/(?:0[1-9]|1[012]))([0-9]+)/([^\/.]+)/reviews/([^\/.]+)/?' . $lang_param . '$'] = 'index.php?' . $page_param . 'target-post=$matches[3]&review-w2rr=$matches[4]&name=$matches[4]&post_type=' . W2RR_REVIEW_TYPE;
				} elseif (get_option("w2rr_display_mode") == "comments") {
					$rules['(' . $page_url . ')?/?(?!(?:199[0-9]|20[012][0-9])/(?:0[1-9]|1[012]))([0-9]+)/([^\/.]+)/reviews/([^\/.]+)/?' . $lang_param . '$'] = 'index.php?' . $page_param . 'target-post=$matches[3]&review-w2rr=$matches[4]&name=$matches[3]&' . $listing_param;
				}
			} */
			// /%post_id%/%postname%/reviews/page/%n%/
			//$rules['(' . $page_url . ')?/?(?!(?:199[0-9]|20[012][0-9])/(?:0[1-9]|1[012]))([0-9]+)/([^\/.]+)/reviews/' . $wp_rewrite->pagination_base . '/([0-9]{1,})/?' . $lang_param . '$'] = 'index.php?page_id=' . $all_reviews_page_id . '&target-post=$matches[3]&reviews-all=1&paged=$matches[4]&' . $listing_param;
			// /%post_id%/%postname%/reviews/
			//$rules['(' . $page_url . ')?/?(?!(?:199[0-9]|20[012][0-9])/(?:0[1-9]|1[012]))([0-9]+)/([^\/.]+)/reviews/?' . $lang_param . '$'] = 'index.php?page_id=' . $all_reviews_page_id . '&target-post=$matches[3]&reviews=all&' . $listing_param;
		}
		
		/* if (get_option("w2dc_imitate_mode")) {
			$page_param = 'page_id=' .  $listing_page_id . '&';
			$listing_param = 'listing-w2dc=$matches[3]';
		} else {
			$page_param = '';
			$listing_param = W2DC_POST_TYPE.'=$matches[3]';
		} */
		// /%listing_slug%/%tax_slugs%/%postname%/reviews/%review%/
		/* if (defined('W2RR_REVIEW_TYPE')) {
			if (get_option("w2rr_display_mode") == "shortcodes") {
				$rules['(' . $page_url . ')?/?' . $listing_slug . '/(.+?)/([^\/.]+)/reviews/([^\/.]+)/?' . $lang_param . '$'] = 'index.php?' . $page_param . 'tax-slugs-w2dc=$matches[2]&target-post=$matches[3]&review-w2rr=$matches[4]&name=$matches[4]&post_type=' . W2RR_REVIEW_TYPE;
			} elseif (get_option("w2rr_display_mode") == "comments") {
				$rules['(' . $page_url . ')?/?' . $listing_slug . '/(.+?)/([^\/.]+)/reviews/([^\/.]+)/?' . $lang_param . '$'] = 'index.php?' . $page_param . 'tax-slugs-w2dc=$matches[2]&target-post=$matches[3]&review-w2rr=$matches[4]&name=$matches[3]&' . $listing_param;
			}
		} */
		// /%listing_slug%/%tax_slugs%/%postname%/reviews/page/%n%/
		//$rules['(' . $page_url . ')?/?' . $listing_slug . '/(.+?)/([^\/.]+)/reviews/' . $wp_rewrite->pagination_base . '/([0-9]{1,})/?' . $lang_param . '$'] = 'index.php?' . $page_param . 'tax-slugs-w2dc=$matches[2]&target-post=$matches[3]&reviews-all=1&paged=$matches[4]&' . $listing_param;
		// /%listing_slug%/%tax_slugs%/%postname%/reviews/
		//$rules['(' . $page_url . ')?/?' . $listing_slug . '/(.+?)/([^\/.]+)/reviews/?' . $lang_param . '$'] = 'index.php?' . $page_param . 'tax-slugs-w2dc=$matches[2]&target-post=$matches[3]&reviews-all=1&' . $listing_param;
		
		if (get_option("w2dc_imitate_mode")) {
			$page_param = 'page_id=' .  $listing_page_id . '&';
			$listing_param = 'listing-w2dc=$matches[3]';
		} else {
			$page_param = '';
			$listing_param = W2DC_POST_TYPE.'=$matches[3]';
		}
		// /%listing_slug%/%category%/%postname%/page/%n%/
		// /%listing_slug%/%location%/%postname%/page/%n%/
		// /%listing_slug%/%tag%/%postname%/page/%n%/
		$rules['(' . $page_url . ')?/?' . $listing_slug . '/(.+?)/([^\/.]+)/?' . $wp_rewrite->pagination_base . '/([0-9]{1,})/?' . $lang_param . '$'] = 'index.php?'.$page_param.'tax-slugs-w2dc=$matches[2]&'.$listing_param.'&paged=$matches[4]';
		// /%listing_slug%/%category%/%postname%/
		// /%listing_slug%/%location%/%postname%/
		// /%listing_slug%/%tag%/%postname%/
		$rules['(' . $page_url . ')?/?' . $listing_slug . '/(.+?)/([^\/.]+)/?' . $lang_param . '$'] = 'index.php?'.$page_param.'tax-slugs-w2dc=$matches[2]&'.$listing_param;
		
		$rules = apply_filters('w2dc_build_rules', $rules, $page_url, $listing_page_id, $directory);
		
		return $rules;
	}
	
	public function wp_loaded() {
		if ($rules = get_option('rewrite_rules'))
			foreach ($this->w2dc_addRules() as $key=>$value) {
				if (!isset($rules[$key]) || $rules[$key] != $value) {
					global $wp_rewrite;
					$wp_rewrite->flush_rules();
					return;
				}
			}
	}
	
	public function prevent_wrong_redirect($redirect_url, $requested_url) {
		
		if ($this->frontend_controllers) {
			// add/remove www. into/from $requested_url when needed
			$user_home = @parse_url(home_url());
			if (!empty($user_home['host'])) {
				if (strpos($user_home['host'], 'www.') === 0) {
					$requested_home = @parse_url($requested_url);
					if (!empty($requested_home['host'])) {
						if (strpos($requested_home['host'], 'www.') !== 0) {
							$requested_url = str_replace($requested_home['host'], 'www.'.$requested_home['host'], $requested_url);
						}
					}
				} else {
					$requested_home = @parse_url($requested_url);
					if (!empty($requested_home['host'])) {
						if (strpos($requested_home['host'], 'www.') === 0) {
							$pos = strpos($requested_url, 'www.');
							$requested_url = substr_replace($requested_url, '', $pos, 4);
						}
					}
				}
			}
			return $requested_url;
		}
	
		return $redirect_url;
	}

	public function listing_permalink($permalink, $post, $leavename) {
		if ($post->post_type == W2DC_POST_TYPE) {
			global $wp_rewrite;
			if ($wp_rewrite->using_permalinks()) {
				if ($leavename) {
					$postname = '%postname%';
				} else {
					$postname = $post->post_name;
				}

				$listing_directory = w2dc_getListingDirectory($post->ID);
				$listing_slug = $listing_directory->listing_slug;
				
				if (!$listing_directory->url) {
					return false;
				}

				switch (get_option('w2dc_permalinks_structure')) {
					case 'post_id':
						return w2dc_directoryUrl($post->ID . '/' . $postname, $listing_directory);
						break;
					case 'postname':
						if (get_option('page_on_front') == $this->index_page_id)
							return w2dc_directoryUrl($post->ID . '/' . $postname, $listing_directory);
						else
							return w2dc_directoryUrl($postname, $listing_directory);
						break;
					case 'listing_slug':
						if ($listing_slug)
							return w2dc_directoryUrl($listing_slug . '/' . $postname, $listing_directory);
						else
							if (get_option('page_on_front') == $this->index_page_id)
								return w2dc_directoryUrl($post->ID . '/' . $postname, $listing_directory);
							else
								return w2dc_directoryUrl($postname, $listing_directory);
						break;
					case 'category_slug':
						if ($listing_slug && ($terms = get_the_terms($post->ID, W2DC_CATEGORIES_TAX))) {
							$term = array_shift($terms);
							if ($cur_term = w2dc_isCategory()) {
								foreach ($terms AS $lterm) {
									$term_path_ids = w2dc_get_term_parents_ids($lterm->term_id, W2DC_CATEGORIES_TAX);
									if ($cur_term->term_id == $lterm->term_id) { $term = $lterm; break; }  // exact term much more better
									if (in_array($cur_term->term_id, $term_path_ids)) { $term = $lterm; break; }
								}
							}
							$uri = '';
							if ($parents = w2dc_get_term_parents_slugs($term->term_id, W2DC_CATEGORIES_TAX))
								$uri = implode('/', $parents);
							return w2dc_directoryUrl($listing_slug . '/' . $uri . '/' . $postname, $listing_directory);
						} else
							if (get_option('page_on_front') == $this->index_page_id)
								return w2dc_directoryUrl($post->ID . '/' . $postname, $listing_directory);
							else
								return w2dc_directoryUrl($postname, $listing_directory);
						break;
					case 'location_slug':
						if ($listing_slug && ($terms = get_the_terms($post->ID, W2DC_LOCATIONS_TAX)) && ($term = array_shift($terms))) {
							if ($cur_term = w2dc_isLocation()) {
								foreach ($terms AS $lterm) {
									$term_path_ids = w2dc_get_term_parents_ids($lterm->term_id, W2DC_LOCATIONS_TAX);
									if ($cur_term->term_id == $lterm->term_id) { $term = $lterm; break; }  // exact term much more better
									if (in_array($cur_term->term_id, $term_path_ids)) { $term = $lterm; break; }
								}
							}
							$uri = '';
							if ($parents = w2dc_get_term_parents_slugs($term->term_id, W2DC_LOCATIONS_TAX))
								$uri = implode('/', $parents);
							return w2dc_directoryUrl($listing_slug . '/' . $uri . '/' . $postname, $listing_directory);
						} else {
							if (get_option('page_on_front') == $this->index_page_id)
								return w2dc_directoryUrl($post->ID . '/' . $postname, $listing_directory);
							else
								return w2dc_directoryUrl($postname, $listing_directory);
						}
						break;
					case 'tag_slug':
						if ($listing_slug && ($terms = get_the_terms($post->ID, W2DC_TAGS_TAX)) && ($term = array_shift($terms))) {
							return w2dc_directoryUrl($listing_slug . '/' . $term->slug . '/' . $postname, $listing_directory);
						} else
							if (get_option('page_on_front') == $this->index_page_id)
								return w2dc_directoryUrl($post->ID . '/' . $postname, $listing_directory);
							else
								return w2dc_directoryUrl($postname, $listing_directory);
						break;
					default:
						if (get_option('page_on_front') == $this->index_page_id)
							return w2dc_directoryUrl($post->ID . '/' . $postname, $listing_directory);
						else
							return w2dc_directoryUrl($postname, $listing_directory);
				}
			} else {
				return w2dc_templatePageUri(array(W2DC_POST_TYPE => $post->post_name), home_url());
			}
		}
		return $permalink;
	}

	public function category_permalink($permalink, $category, $tax) {
		
		if ($tax == W2DC_CATEGORIES_TAX) {
			global $wp_rewrite;
			if ($wp_rewrite->using_permalinks()) {
				
				global $w2dc_directory_flag;
				if ($w2dc_directory_flag) {
					$directory = $this->directories->getDirectoryById($w2dc_directory_flag);
				} else {
					$directory = w2dc_getListingDirectory(get_the_ID());
				}
				$category_slug = $directory->category_slug;

				$uri = '';
				if ($parents = w2dc_get_term_parents_slugs($category->term_id, W2DC_CATEGORIES_TAX)) {
					$uri = implode('/', $parents);
				}
				
				return w2dc_directoryUrl($category_slug . '/' . $uri, $directory);
			} else {
				return w2dc_templatePageUri(array(W2DC_CATEGORIES_TAX => $category->slug), home_url());
			}
		}
		return $permalink;
	}

	public function location_permalink($permalink, $location, $tax) {
		
		if ($tax == W2DC_LOCATIONS_TAX) {
			global $wp_rewrite;
			if ($wp_rewrite->using_permalinks()) {
				
				global $w2dc_directory_flag;
				if ($w2dc_directory_flag) {
					$directory = $this->directories->getDirectoryById($w2dc_directory_flag);
				} else {
					$directory = w2dc_getListingDirectory(get_the_ID());
				}
				$location_slug = $directory->location_slug;

				$uri = '';
				if ($parents = w2dc_get_term_parents_slugs($location->term_id, W2DC_LOCATIONS_TAX)) {
					$uri = implode('/', $parents);
				}
				
				return w2dc_directoryUrl($location_slug . '/' . $uri, $directory);
			} else {
				return w2dc_templatePageUri(array('location-w2dc' => $location->slug), home_url());
			}
		}
		return $permalink;
	}

	public function tag_permalink($permalink, $tag, $tax) {
		
		if ($tax == W2DC_TAGS_TAX) {
			
			global $wp_rewrite;
			if ($wp_rewrite->using_permalinks()) {
				$directory = w2dc_getListingDirectory(get_the_ID());
				$tag_slug = $directory->tag_slug;

				return w2dc_directoryUrl($tag_slug . '/' . $tag->slug, $directory);
			} else {
				return w2dc_templatePageUri(array('tag-w2dc' => $tag->slug), home_url());
			}
		}
		return $permalink;
	}
	
	public function reserve_slugs($is_bad_flat_slug, $slug) {
		
		if ($this->directories) {
			$slugs_to_check = array();
			foreach ($this->directories->directories_array AS $directory) {
				$slugs_to_check[] = $directory->listing_slug;
				$slugs_to_check[] = $directory->category_slug;
				$slugs_to_check[] = $directory->location_slug;
				$slugs_to_check[] = $directory->tag_slug;
			}
	
			if (in_array($slug, $slugs_to_check)) {
				return true;
			}
		}
		
		return $is_bad_flat_slug;
	}

	public function register_post_type() {
		$args = array(
			'labels' => array(
				'name' => __('Directory listings', 'W2DC'),
				'singular_name' => __('Directory listing', 'W2DC'),
				'add_new' => __('Create new listing', 'W2DC'),
				'add_new_item' => __('Create new listing', 'W2DC'),
				'edit_item' => __('Edit listing', 'W2DC'),
				'new_item' => __('New listing', 'W2DC'),
				'view_item' => __('View listing', 'W2DC'),
				'search_items' => __('Search listings', 'W2DC'),
				'not_found' =>  __('No listings found', 'W2DC'),
				'not_found_in_trash' => __('No listings found in trash', 'W2DC')
			),
			'hierarchical' => true,
			'has_archive' => true,
			'description' => __('Directory listings', 'W2DC'),
			'public' => true,
			'exclude_from_search' => false, // this must be false otherwise it breaks pagination for custom taxonomies
			'supports' => array('title', 'author', 'comments'),
			'menu_icon' => W2DC_RESOURCES_URL . 'images/menuicon.png',
		);
		if (get_option('w2dc_enable_description')) {
			$args['supports'][] = 'editor';
		}
		if (get_option('w2dc_enable_summary')) {
			$args['supports'][] = 'excerpt';
		}
		$args['exclude_from_search'] = apply_filters('w2dc_exclude_from_search', false);
		
		register_post_type(W2DC_POST_TYPE, $args);
		
		register_taxonomy(W2DC_CATEGORIES_TAX, W2DC_POST_TYPE, array(
				'hierarchical' => true,
				'has_archive' => true,
				'labels' => array(
					'name' =>  __('Listing categories', 'W2DC'),
					'menu_name' =>  __('Directory categories', 'W2DC'),
					'singular_name' => __('Category', 'W2DC'),
					'add_new_item' => __('Create category', 'W2DC'),
					'new_item_name' => __('New category', 'W2DC'),
					'edit_item' => __('Edit category', 'W2DC'),
					'view_item' => __('View category', 'W2DC'),
					'update_item' => __('Update category', 'W2DC'),
					'search_items' => __('Search categories', 'W2DC'),
				),
				'rewrite' => array('hierarchical' => true),
			)
		);
		register_taxonomy(W2DC_LOCATIONS_TAX, W2DC_POST_TYPE, array(
				'hierarchical' => true,
				'has_archive' => true,
				'labels' => array(
					'name' =>  __('Listing locations', 'W2DC'),
					'menu_name' =>  __('Directory locations', 'W2DC'),
					'singular_name' => __('Location', 'W2DC'),
					'add_new_item' => __('Create location', 'W2DC'),
					'new_item_name' => __('New location', 'W2DC'),
					'edit_item' => __('Edit location', 'W2DC'),
					'view_item' => __('View location', 'W2DC'),
					'update_item' => __('Update location', 'W2DC'),
					'search_items' => __('Search locations', 'W2DC'),
				),
				'rewrite' => array('hierarchical' => true),
			)
		);
		register_taxonomy(W2DC_TAGS_TAX, W2DC_POST_TYPE, array(
				'hierarchical' => false,
				'labels' => array(
					'name' =>  __('Listing tags', 'W2DC'),
					'menu_name' =>  __('Directory tags', 'W2DC'),
					'singular_name' => __('Tag', 'W2DC'),
					'add_new_item' => __('Create tag', 'W2DC'),
					'new_item_name' => __('New tag', 'W2DC'),
					'edit_item' => __('Edit tag', 'W2DC'),
					'view_item' => __('View tag', 'W2DC'),
					'update_item' => __('Update tag', 'W2DC'),
					'search_items' => __('Search tags', 'W2DC'),
				),
			)
		);
	}

	public function suspend_expired_listings() {
		global $wpdb;
		
		$scheduled_events_time = get_option("w2dc_scheduled_events_time");
		if ($scheduled_events_time === false) {
			w2dc_update_scheduled_events_time();
			return false;
		}
		if ($scheduled_events_time > (time() - 3600)) {
			return false;
		}

		$posts_ids = $wpdb->get_col($wpdb->prepare("
				SELECT
					wp_pm1.post_id
				FROM
					{$wpdb->postmeta} AS wp_pm1
				LEFT JOIN
					{$wpdb->postmeta} AS wp_pm2 ON wp_pm1.post_id=wp_pm2.post_id
				LEFT JOIN
					{$wpdb->w2dc_levels_relationships} AS wp_lr ON wp_lr.post_id=wp_pm1.post_id
				LEFT JOIN
					{$wpdb->w2dc_levels} AS wp_l ON wp_l.id=wp_lr.level_id
				WHERE
					wp_pm1.meta_key = '_expiration_date' AND
					wp_pm1.meta_value < %d AND
					wp_pm2.meta_key = '_listing_status' AND
					(wp_pm2.meta_value = 'active' OR wp_pm2.meta_value = 'stopped') AND
					(wp_l.eternal_active_period = '0')
			", current_time('timestamp')));
		$listings_ids_to_suspend = $posts_ids;
		foreach ($posts_ids AS $post_id) {
			if (!get_post_meta($post_id, '_expiration_notification_sent', true) && $listing = w2dc_getListing($post_id)) {
				if (get_option('w2dc_expiration_notification')) {
					$listing_owner = get_userdata($listing->post->post_author);
			
					$subject = __('Expiration notification', 'W2DC');
			
					$body = str_replace('[listing]', $listing->title(),
							str_replace('[link]', ((get_option('w2dc_fsubmit_addon') && isset($this->dashboard_page_url) && $this->dashboard_page_url) ? w2dc_dashboardUrl(array('w2dc_action' => 'renew_listing', 'listing_id' => $post_id)) : admin_url('options.php?page=w2dc_renew&listing_id=' . $post_id)),
							get_option('w2dc_expiration_notification')));
					w2dc_mail($listing_owner->user_email, $subject, $body);
					
					add_post_meta($post_id, '_expiration_notification_sent', true);
				}
			}

			// adapted for WPML
			global $sitepress;
			if (function_exists('wpml_object_id_filter') && $sitepress) {
				$trid = $sitepress->get_element_trid($post_id, 'post_' . W2DC_POST_TYPE);
				$translations = $sitepress->get_element_translations($trid, 'post_' . W2DC_POST_TYPE, false, true);
				foreach ($translations AS $lang=>$translation) {
					$listings_ids_to_suspend[] = $translation->element_id;
				}
			} else {
				$listings_ids_to_suspend[] = $post_id;
			}
		}
		$listings_ids_to_suspend = array_unique($listings_ids_to_suspend);
		foreach ($listings_ids_to_suspend AS $listing_id) {
			$listing = w2dc_getListing($listing_id);
			if ($listing->level->change_level_id && ($new_level = $this->levels->getLevelById($listing->level->change_level_id))) {
				if ($wpdb->query("UPDATE {$wpdb->w2dc_levels_relationships} SET level_id=" . $new_level->id . "  WHERE post_id=" . $listing->post->ID)) {
					$listing->setLevelByPostId($listing->post->ID);
					
					$listing->processActivate(false, false);
				}
			} else {
				update_post_meta($listing_id, '_listing_status', 'expired');
				wp_update_post(array('ID' => $listing_id, 'post_status' => 'draft')); // This needed in order terms counts were always actual
			}
			
			$continue = true;
			$continue_invoke_hooks = true;
			apply_filters('w2dc_listing_renew', $continue, $listing, array(&$continue_invoke_hooks));
		}

		$posts_ids = $wpdb->get_col($wpdb->prepare("
				SELECT
					wp_pm1.post_id
				FROM
					{$wpdb->postmeta} AS wp_pm1
				LEFT JOIN
					{$wpdb->postmeta} AS wp_pm2 ON wp_pm1.post_id=wp_pm2.post_id
				LEFT JOIN
					{$wpdb->w2dc_levels_relationships} AS wp_lr ON wp_lr.post_id=wp_pm1.post_id
				LEFT JOIN
					{$wpdb->w2dc_levels} AS wp_l ON wp_l.id=wp_lr.level_id
				WHERE
					wp_pm1.meta_key = '_expiration_date' AND
					wp_pm1.meta_value < %d AND
					wp_pm2.meta_key = '_listing_status' AND
					(wp_pm2.meta_value = 'active' OR wp_pm2.meta_value = 'stopped') AND
					(wp_l.eternal_active_period = '0')
			", current_time('timestamp')+(get_option('w2dc_send_expiration_notification_days')*86400)));

		$listings_ids = $posts_ids;

		// adapted for WPML
		global $sitepress;
		if (function_exists('wpml_object_id_filter') && $sitepress) {
			foreach ($posts_ids AS $post_id) {
				$trid = $sitepress->get_element_trid($post_id, 'post_' . W2DC_POST_TYPE);
				$listings_ids[] = $trid;
			}
		} else {
			$listings_ids = $posts_ids;
		}

		$listings_ids = array_unique($listings_ids);
		foreach ($listings_ids AS $listing_id) {
			if (!get_post_meta($listing_id, '_preexpiration_notification_sent', true) && ($listing = w2dc_getListing($listing_id))) {
				if (get_option('w2dc_preexpiration_notification')) {
					$listing_owner = get_userdata($listing->post->post_author);

					$subject = __('Pre-expiration notification', 'W2DC');
					
					$body = str_replace('[listing]', $listing->title(),
							str_replace('[days]', get_option('w2dc_send_expiration_notification_days'),
							str_replace('[link]', ((get_option('w2dc_fsubmit_addon') && isset($this->dashboard_page_url) && $this->dashboard_page_url) ? w2dc_dashboardUrl(array('w2dc_action' => 'renew_listing', 'listing_id' => $listing_id)) : admin_url('options.php?page=w2dc_renew&listing_id=' . $listing_id)),
							get_option('w2dc_preexpiration_notification'))));
					w2dc_mail($listing_owner->user_email, $subject, $body);
					
					add_post_meta($listing_id, '_preexpiration_notification_sent', true);
				}

				$continue_invoke_hooks = true;
				if ($listing = $this->listings_manager->loadListing($listing_id)) {
					apply_filters('w2dc_listing_renew', false, $listing, array(&$continue_invoke_hooks));
				}
			}
		}
		
		w2dc_update_scheduled_events_time();
	}

	/**
	 * Special template for listings printing functionality
	 */
	public function printlisting_template($template) {
		if ($this->action == 'printlisting' || $this->action == 'pdflisting') {
			if (!($template = w2dc_isTemplate('frontend/listing_print.tpl.php')) && !($template = w2dc_isTemplate('frontend/listing_print-custom.tpl.php'))) {
				$template = w2dc_isTemplate('frontend/listing_print.tpl.php');
			}
		}
		return $template;
	}
	
	function filter_comment_status($open, $post_id) {
		$post = get_post($post_id);
		if ($post->post_type == W2DC_POST_TYPE) {
			if (get_option('w2dc_listings_comments_mode') == 'enabled')
				return true;
			elseif (get_option('w2dc_listings_comments_mode') == 'disabled')
				return false;
		}

		return $open;
	}

	/**
	 * Get property by shortcode name
	 * 
	 * @param string $shortcode
	 * @param string $property if property missed - return controller object
	 * @return mixed
	 */
	public function getShortcodeProperty($shortcode, $property = false) {
		if (!isset($this->frontend_controllers[$shortcode]) || !isset($this->frontend_controllers[$shortcode][0]))
			return false;

		if ($property && !isset($this->frontend_controllers[$shortcode][0]->$property))
			return false;

		if ($property)
			return $this->frontend_controllers[$shortcode][0]->$property;
		else 
			return $this->frontend_controllers[$shortcode][0];
	}
	
	public function getShortcodeByHash($hash) {
		if (!isset($this->frontend_controllers) || !is_array($this->frontend_controllers) || empty($this->frontend_controllers))
			return false;

		foreach ($this->frontend_controllers AS $shortcodes)
			foreach ($shortcodes AS $controller)
				if (is_object($controller) && $controller->hash == $hash)
					return $controller;
	}
	
	public function getListingsShortcodeByuID($uid) {
		foreach ($this->frontend_controllers AS $shortcodes)
			foreach ($shortcodes AS $controller)
				if (is_object($controller) && get_class($controller) == 'w2dc_listings_controller' && $controller->args['uid'] == $uid)
					return $controller;
	}
	
	public function enqueue_scripts_styles($load_scripts_styles = false) {
		global $w2dc_enqueued;
		if ((($this->frontend_controllers || $load_scripts_styles) && !$w2dc_enqueued) || get_option('w2dc_force_include_js_css')) {
			add_action('wp_head', array($this, 'enqueue_global_vars'));
			
			global $wcsearch_instance;
			if ($wcsearch_instance) {
				$wcsearch_instance->enqueue_scripts_styles(true);
			}
			
			//wp_enqueue_script('jquery');
			wp_enqueue_script('jquery', false, array(), false, false);

			wp_register_style('w2dc_bootstrap', W2DC_RESOURCES_URL . 'css/bootstrap.css', array(), W2DC_VERSION_TAG);
			wp_register_style('w2dc_frontend', W2DC_RESOURCES_URL . 'css/frontend.css', array(), W2DC_VERSION_TAG);

			if (function_exists('is_rtl') && is_rtl()) {
				wp_register_style('w2dc_frontend_rtl', W2DC_RESOURCES_URL . 'css/frontend-rtl.css', array(), W2DC_VERSION_TAG);
			}

			wp_register_style('w2dc_font_awesome', W2DC_RESOURCES_URL . 'css/font-awesome.css', array(), W2DC_VERSION_TAG);

			wp_register_script('w2dc_js_functions', W2DC_RESOURCES_URL . 'js/js_functions.js', array('jquery'), W2DC_VERSION_TAG, true);

			wp_register_script('w2dc_categories_scripts', W2DC_RESOURCES_URL . 'js/manage_categories.js', array('jquery'), false, true);

			wp_register_style('w2dc_media_styles', W2DC_RESOURCES_URL . 'lightbox/css/lightbox.min.css', array(), W2DC_VERSION_TAG);
			wp_register_script('w2dc_media_scripts_lightbox', W2DC_RESOURCES_URL . 'lightbox/js/lightbox.js', array('jquery'), false, true);

			// jQuery UI version 1.10.4
			if (get_option('w2dc_jquery_ui_schemas')) $ui_theme = w2dc_get_dynamic_option('w2dc_jquery_ui_schemas'); else $ui_theme = 'smoothness';
			wp_register_style('w2dc-jquery-ui-style', W2DC_RESOURCES_URL . 'css/jquery-ui/themes/' . $ui_theme . '/jquery-ui.css');
			
			wp_register_style('w2dc_listings_slider', W2DC_RESOURCES_URL . 'css/bxslider/jquery.bxslider.css', array(), W2DC_VERSION_TAG);
			wp_enqueue_style('w2dc_listings_slider');

			wp_enqueue_style('w2dc_bootstrap');
			wp_enqueue_style('w2dc_font_awesome');
			wp_enqueue_style('w2dc_frontend');
			wp_enqueue_style('w2dc_frontend_rtl');
			
			// Include dynamic-css file only when we are not in palettes comparison mode
			if (!isset($_COOKIE['w2dc_compare_palettes']) || !get_option('w2dc_compare_palettes')) {
				// Include dynamically generated css file if this file exists
				$upload_dir = wp_upload_dir();
				$filename = trailingslashit(set_url_scheme($upload_dir['baseurl'])) . 'w2dc-plugin.css';
				$filename_dir = trailingslashit($upload_dir['basedir']) . 'w2dc-plugin.css';
				global $wp_filesystem;
				if (empty($wp_filesystem)) {
					require_once(ABSPATH .'/wp-admin/includes/file.php');
					WP_Filesystem();
				}
				if ($wp_filesystem && trim($wp_filesystem->get_contents($filename_dir))) { // if css file creation success
					wp_enqueue_style('w2dc-dynamic-css', $filename, array(), time());
				}
			}

			wp_enqueue_script('jquery-ui-dialog');
			wp_enqueue_script('jquery-ui-draggable');
			wp_enqueue_script('jquery-ui-selectmenu');
			wp_enqueue_script('jquery-ui-autocomplete');
			wp_enqueue_script('jquery-ui-datepicker');
			if ($i18n_file = w2dc_getDatePickerLangFile(get_locale())) {
				wp_register_script('datepicker-i18n', $i18n_file, array('jquery-ui-datepicker'));
				wp_enqueue_script('datepicker-i18n');
			}
			if (!get_option('w2dc_notinclude_jqueryui_css')) {
				wp_enqueue_style('w2dc-jquery-ui-style');
			}

			wp_enqueue_script('w2dc_js_functions');

			if (w2dc_is_maps_used()) {
				
				global $w2dc_radius_params;
				if ($w2dc_radius_params) {
					wp_localize_script(
						'w2dc_js_functions',
						'radius_params',
						$w2dc_radius_params
					);
				}
				
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
					add_action('wp_print_scripts', array($this, 'dequeue_maps_googleapis'), 1000);
					wp_register_script('w2dc_google_maps', W2DC_RESOURCES_URL . 'js/google_maps.js', array('jquery'), W2DC_VERSION_TAG, true);
					wp_enqueue_script('w2dc_google_maps');
				}
			}

			// Single Listing page
			if (
				$this->getShortcodeProperty(W2DC_MAIN_SHORTCODE, 'is_single') ||
				$this->getShortcodeProperty(W2DC_LISTING_SHORTCODE, 'is_single') ||
				apply_filters('w2dc_include_lightbox_files', false)
			) {
				if (get_option('w2dc_images_lightbox') && get_option('w2dc_enable_lightbox_gallery')) {
					wp_enqueue_style('w2dc_media_styles');
					wp_enqueue_script('w2dc_media_scripts_lightbox');
				}
			}
			
			wp_localize_script(
				'w2dc_js_functions',
				'w2dc_maps_callback',
				array(
						'callback' => 'w2dc_load_maps_api'
				)
			);
			
			if (get_option('w2dc_enable_recaptcha') && get_option('w2dc_recaptcha_public_key') && get_option('w2dc_recaptcha_private_key')) {
				if (get_option('w2dc_recaptcha_version') == 'v2') {
					wp_register_script('w2dc_recaptcha', '//google.com/recaptcha/api.js');
				} elseif (get_option('w2dc_recaptcha_version') == 'v3') {
					wp_register_script('w2dc_recaptcha', '//google.com/recaptcha/api.js?render='.get_option('w2dc_recaptcha_public_key'));
				}
				wp_enqueue_script('w2dc_recaptcha');
			}

			$w2dc_enqueued = true;
		}
	}
	
	public function enqueue_scripts_styles_custom($load_scripts_styles = false) {
		if ((($this->frontend_controllers || $load_scripts_styles)) || get_option('w2dc_force_include_js_css')) {
			if ($frontend_custom = w2dc_isResource('css/frontend-custom.css')) {
				wp_register_style('w2dc_frontend-custom', $frontend_custom, array(), W2DC_VERSION_TAG);
				
				wp_enqueue_style('w2dc_frontend-custom');
			}
		}
	}
	
	public function dequeue_maps_googleapis() {
		$dequeue = false;
		if ((w2dc_is_maps_used() && get_option('w2dc_google_api_key') && !(defined('W2DC_NOTINCLUDE_MAPS_API') && W2DC_NOTINCLUDE_MAPS_API)) && !(defined('W2DC_NOT_DEQUEUE_MAPS_API') && W2DC_NOT_DEQUEUE_MAPS_API)) {
			$dequeue = true;
		}
		
		$dequeue = apply_filters('w2dc_dequeue_maps_googleapis', $dequeue);
		
		if ($dequeue) {
			// dequeue only at the frontend or at admin directory pages
			if (!is_admin() || (is_admin() && w2dc_isDirectoryPageInAdmin())) {
				global $wp_scripts;
				foreach ($wp_scripts->registered AS $key=>$script) {
					if (strpos($script->src, 'maps.googleapis.com') !== false || strpos($script->src, 'maps.google.com/maps/api') !== false) {
						unset($wp_scripts->registered[$key]);
					}
				}
			}
		}
	}
	
	public function enqueue_global_vars() {
		// adapted for WPML
		global $sitepress;
		if (function_exists('wpml_object_id_filter') && $sitepress) {
			$ajaxurl = admin_url('admin-ajax.php?lang=' .  $sitepress->get_current_language());
		} else
			$ajaxurl = admin_url('admin-ajax.php');
		
		echo '
<script>
';
		echo 'var w2dc_controller_args_array = {};
';
		echo 'var w2dc_map_markers_attrs_array = [];
';
		echo 'var w2dc_map_markers_attrs = (function(map_id, markers_array, enable_radius_circle, enable_clusters, show_summary_button, show_readmore_button, draw_panel, map_style, enable_full_screen, enable_wheel_zoom, enable_dragging_touchscreens, center_map_onclick, show_directions, enable_infowindow, close_infowindow_out_click, map_attrs) {
		this.map_id = map_id;
		this.markers_array = markers_array;
		this.enable_radius_circle = enable_radius_circle;
		this.enable_clusters = enable_clusters;
		this.show_summary_button = show_summary_button;
		this.show_readmore_button = show_readmore_button;
		this.draw_panel = draw_panel;
		this.map_style = map_style;
		this.enable_full_screen = enable_full_screen;
		this.enable_wheel_zoom = enable_wheel_zoom;
		this.enable_dragging_touchscreens = enable_dragging_touchscreens;
		this.center_map_onclick = center_map_onclick;
		this.show_directions = show_directions;
		this.enable_infowindow = enable_infowindow;
		this.close_infowindow_out_click = close_infowindow_out_click;
		this.map_attrs = map_attrs;
		});
';
		echo 'var w2dc_js_objects = ' . json_encode(
				array(
						'ajaxurl' => $ajaxurl,
						'search_map_button_text' => __('Search on map', 'W2DC'),
						'in_favourites_icon' => 'w2dc-glyphicon-heart',
						'not_in_favourites_icon' => 'w2dc-glyphicon-heart-empty',
						'in_favourites_msg' => __('Add Bookmark', 'W2DC'),
						'not_in_favourites_msg' => __('Remove Bookmark', 'W2DC'),
						'ajax_load' => (int)get_option('w2dc_ajax_load'),
						'ajax_initial_load' => (int)get_option('w2dc_ajax_initial_load'),
						'is_rtl' => is_rtl(),
						'leave_comment' => __('Leave a comment', 'W2DC'),
						'leave_reply' => __('Leave a reply to', 'W2DC'),
						'cancel_reply' => __('Cancel reply', 'W2DC'),
						'more' => __('More', 'W2DC'),
						'less' => __('Less', 'W2DC'),
						'send_button_text' => __('Send message', 'W2DC'),
						'send_button_sending' => __('Sending...', 'W2DC'),
						'recaptcha_public_key' => ((get_option('w2dc_enable_recaptcha') && get_option('w2dc_recaptcha_public_key') && get_option('w2dc_recaptcha_private_key')) ? get_option('w2dc_recaptcha_public_key') : ''),
						'lang' => (($sitepress && get_option('w2dc_map_language_from_wpml')) ? ICL_LANGUAGE_CODE : apply_filters('w2dc_map_language', '')),
						'is_maps_used' => (int)w2dc_is_maps_used(),
						'desktop_screen_width' => 992,
						'mobile_screen_width' => 768,
						'fields_in_categories' => array(),
						'is_admin' => (int)is_admin(),
						'prediction_note' => __('search nearby', 'W2DC'),
						'listing_tabs_order' => get_option('w2dc_listings_tabs_order'),
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
						'infowindow_width' => (int)get_option('w2dc_map_infowindow_width'),
						'infowindow_offset' => -(int)get_option('w2dc_map_infowindow_offset'),
						'infowindow_logo_width' => (int)get_option('w2dc_map_infowindow_logo_width'),
						'draw_area_button' => __('Draw Area', 'W2DC'),
						'edit_area_button' => __('Edit Area', 'W2DC'),
						'apply_area_button' => __('Apply Area', 'W2DC'),
						'reload_map_button' => __('Refresh Map', 'W2DC'),
						'enable_my_location_button' => (int)get_option('w2dc_address_geocode'),
						'my_location_button' => __('My Location', 'W2DC'),
						'my_location_button_error' => __('GeoLocation service does not work on your device!', 'W2DC'),
						'map_style' => w2dc_getSelectedMapStyle(),
						'address_autocomplete' => (int)get_option('w2dc_address_autocomplete'),
						'address_autocomplete_code' => get_option('w2dc_address_autocomplete_code'),
						'mapbox_directions_placeholder_origin' => __('Choose a starting place', 'W2DC'),
						'mapbox_directions_placeholder_destination' => __('Choose destination', 'W2DC'),
						'mapbox_directions_profile_driving_traffic' => __('Traffic', 'W2DC'),
						'mapbox_directions_profile_driving' => __('Driving', 'W2DC'),
						'mapbox_directions_profile_walking' => __('Walking', 'W2DC'),
						'mapbox_directions_profile_cycling' => __('Cycling', 'W2DC'),
						'default_latitude' => apply_filters('w2dc_default_latitude', 34),
						'default_longitude' => apply_filters('w2dc_default_longitude', 0),
						'dimension_unit' => get_option('w2dc_miles_kilometers_in_search'),
				)
		) . ';
';
		echo '</script>
';
	}

	// Include dynamically generated css code if css file does not exist.
	public function enqueue_dynamic_css($load_scripts_styles = false) {
		$upload_dir = wp_upload_dir();
		$filename = trailingslashit(set_url_scheme($upload_dir['baseurl'])) . 'w2dc-plugin.css';
		$filename_dir = trailingslashit($upload_dir['basedir']) . 'w2dc-plugin.css';
		global $wp_filesystem;
		if (empty($wp_filesystem)) {
			require_once(ABSPATH .'/wp-admin/includes/file.php');
			WP_Filesystem();
		}
		if ((!$wp_filesystem || !trim($wp_filesystem->get_contents($filename_dir))) ||
			// When we are in palettes comparison mode - this will build css according to $_COOKIE['w2dc_compare_palettes']
			(isset($_COOKIE['w2dc_compare_palettes']) && get_option('w2dc_compare_palettes')))
		{
			ob_start();
			include W2DC_PATH . '/classes/customization/dynamic_css.php';
			$dynamic_css = ob_get_contents();
			ob_get_clean();
				
			wp_add_inline_style('w2dc_frontend', $dynamic_css);
		}
	}
	
	public function exclude_post_type_archive_link($archive_url, $post_type) {
		if ($post_type == W2DC_POST_TYPE) {
			return false;
		}
		
		return $archive_url;
	}
	
	public function plugin_row_meta($links, $file) {
		if (dirname(plugin_basename(__FILE__) == $file)) {
			$row_meta = array(
					'docs' => '<a href="https://www.salephpscripts.com/wordpress_directory/demo/documentation/">' . esc_html__("Documentation", "W2DC") . '</a>',
					'codecanoyn' => '<a href="https://codecanyon.net/item/web-20-directory-plugin-for-wordpress/6463373#item-description__changelog">' . esc_html__("Changelog", "W2DC") . '</a>',
			);
	
			return array_merge($links, $row_meta);
		}
	
		return $links;
	}
	
	public function plugin_action_links($links) {
		$action_links = array(
				'settings' => '<a href="' . admin_url('admin.php?page=w2dc_settings') . '">' . esc_html__("Settings", "W2DC") . '</a>',
		);
		
		if (defined('W2DCF_VERSION')) {
			$premium_link = '<a style="font-weight: bold;" href="https://www.salephpscripts.com/directory/" target="_blank">' . esc_html__('Get Premium', 'W2DC') . '</a>';
			array_unshift($action_links, $premium_link);
		}
	
		return array_merge($action_links, $links);
	}

	// adapted for Polylang
	public function pll_setup() {
		if (defined("POLYLANG_VERSION")) {
			add_filter('post_type_link', array($this, 'pll_stop_add_lang_to_url_post'), 0, 2);
			add_filter('post_type_link', array($this, 'pll_start_add_lang_to_url_post'), 100, 2);
			add_filter('term_link', array($this, 'pll_stop_add_lang_to_url_term'), 0, 3);
			add_filter('term_link', array($this, 'pll_start_add_lang_to_url_term'), 100, 3);
			add_filter('rewrite_rules_array', array($this, 'pll_rewrite_rules'));
		}
	}
	public function pll_stop_add_lang_to_url_post($permalink, $post) {
		$this->pll_force_lang = false;
		if ($post->post_type == W2DC_POST_TYPE) {
			global $polylang;
			if (isset($polylang->links->links_model->model->options['force_lang']) && $polylang->links->links_model->model->options['force_lang']) {
				$this->pll_force_lang = true;
				$polylang->links->links_model->model->options['force_lang'] = 0;
			}
		}
		return $permalink;
	}
	public function pll_start_add_lang_to_url_post($permalink, $post) {
		if ($this->pll_force_lang && $post->post_type == W2DC_POST_TYPE) {
			global $polylang;
			$polylang->links->links_model->model->options['force_lang'] = 1;
		}
		return $permalink;
	}
	public function pll_stop_add_lang_to_url_term($permalink, $term, $tax) {
		$this->pll_force_lang = false;
		if ($tax == W2DC_CATEGORIES_TAX || $tax == W2DC_LOCATIONS_TAX || $tax == W2DC_TAGS_TAX) {
			global $polylang;
			if (isset($polylang->links->links_model->model->options['force_lang']) && $polylang->links->links_model->model->options['force_lang']) {
				$this->pll_force_lang = true;
				$polylang->links->links_model->model->options['force_lang'] = 0;
			}
		}
		return $permalink;
	}
	public function pll_start_add_lang_to_url_term($permalink, $term, $tax) {
		if ($this->pll_force_lang && ($tax == W2DC_CATEGORIES_TAX || $tax == W2DC_LOCATIONS_TAX || $tax == W2DC_TAGS_TAX)) {
			global $polylang;
			$polylang->links->links_model->model->options['force_lang'] = 1;
		}
		return $permalink;
	}
	public function pll_rewrite_rules($rules) {
		global $polylang, $wp_current_filter;
		$wp_current_filter[] = 'w2dc_listing';
		//return $polylang->links->links_model->rewrite_rules($this->buildRules()) + $rules;
		return $rules;
	}
	
	// when dequeue google maps api from divi VISUAL builder - it breaks the page and does not complete loading
	public function divi_not_dequeue_maps_api($dequeue) {
		if (get_option('et_enqueue_google_maps_script')) {
			return false;
		}
	}
}

$w2dc_instance = new w2dc_plugin();
$w2dc_instance->init();

if (get_option('w2dc_ratings_addon'))
	include_once W2DC_PATH . 'addons/w2dc_ratings/w2dc_ratings.php';

?>