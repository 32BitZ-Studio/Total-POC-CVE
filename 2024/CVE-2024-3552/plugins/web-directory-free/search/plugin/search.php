<?php
/*
Plugin Name: WooCommerce Search & Filter
Plugin URI: https://www.salephpscripts.com/wordpress-search/
Description: Search and filter WooCommerce products
Version: 1.2.11
WC tested up to: 8.3
Author: salephpscripts.com
Author URI: https://www.salephpscripts.com
License: GPLv2 or any later version
*/

if (defined("WCSEARCH_VERSION")) {
	return ;
}

define('WCSEARCH_VERSION', '1.2.11');

define('WCSEARCH_PATH', plugin_dir_path(__FILE__));
define('WCSEARCH_URL', plugins_url('/', __FILE__));

define('WCSEARCH_TEMPLATES_PATH', WCSEARCH_PATH . 'templates/');

define('WCSEARCH_RESOURCES_PATH', WCSEARCH_PATH . 'resources/');
define('WCSEARCH_RESOURCES_URL', WCSEARCH_URL . 'resources/');

define('WCSEARCH_FORM_TYPE', 'wcsearch_form');

include_once WCSEARCH_PATH . 'install.php';
include_once WCSEARCH_PATH . 'classes/admin.php';
include_once WCSEARCH_PATH . 'classes/query.php';
include_once WCSEARCH_PATH . 'classes/filters/price.php';
include_once WCSEARCH_PATH . 'classes/filters/ratings.php';
include_once WCSEARCH_PATH . 'classes/filters/tax.php';
include_once WCSEARCH_PATH . 'classes/filters/keywords.php';
include_once WCSEARCH_PATH . 'classes/filters/featured.php';
include_once WCSEARCH_PATH . 'classes/filters/onsale.php';
include_once WCSEARCH_PATH . 'classes/filters/instock.php';
include_once WCSEARCH_PATH . 'classes/filters/orderby.php';
include_once WCSEARCH_PATH . 'classes/filters/page.php';
include_once WCSEARCH_PATH . 'classes/search/search_forms_manager.php';
include_once WCSEARCH_PATH . 'classes/search/search_form_model.php';
include_once WCSEARCH_PATH . 'classes/demo_data.php';
include_once WCSEARCH_PATH . 'classes/shortcodes/search_controller.php';
include_once WCSEARCH_PATH . 'classes/shortcodes/products_controller.php';
include_once WCSEARCH_PATH . 'classes/shortcodes/demo_links_controller.php';
include_once WCSEARCH_PATH . 'classes/ajax_controller.php';
include_once WCSEARCH_PATH . 'classes/widgets/widget.php';
include_once WCSEARCH_PATH . 'classes/widgets/search.php';
include_once WCSEARCH_PATH . 'classes/search_form.php';
include_once WCSEARCH_PATH . 'classes/updater.php';
include_once WCSEARCH_PATH . 'functions.php';
include_once WCSEARCH_PATH . 'functions_wc.php';

global $wcsearch_instance;
global $wcsearch_messages;

define('WCSEARCH_MAIN_SHORTCODE', 'wcsearch');
define('WCSEARCH_PRODUCTS_SHORTCODE', 'wcsearch-products');
define('WCSEARCH_DEMO_LINKS_SHORTCODE', 'wcsearch-demo-links');

/*
 * There are 2 types of shortcodes in the system:
 1. those process as simple wordpress shortcodes
 2. require initialization on 'wp' hook
 
 */
global $wcsearch_shortcodes, $wcsearch_shortcodes_init;
$wcsearch_shortcodes = array(
		WCSEARCH_MAIN_SHORTCODE => 'wcsearch_search_form_controller',
		WCSEARCH_PRODUCTS_SHORTCODE => 'wcsearch_products_controller',
		WCSEARCH_DEMO_LINKS_SHORTCODE => 'wcsearch_demo_links_controller',
);
$wcsearch_shortcodes_init = array(
		
);

class wcsearch_plugin {
	public $admin;
	public $demo_data_manager;
	public $updater;

	public $search_forms;
	public $ajax_controller;
	public $frontend_controllers = array();
	public $_frontend_controllers = array(); // this duplicate property needed because we unset each controller when we render shortcodes, but WP doesn't really know which shortcode already was processed
	public $form_on_shop_page;

	public function __construct() {
		register_activation_hook(__FILE__, array($this, 'activation'));
		register_deactivation_hook(__FILE__, array($this, 'deactivation'));
	}
	
	public function activation() {
		global $wp_version;

		if (version_compare($wp_version, '5.6', '<')) {
			deactivate_plugins(basename(__FILE__)); // Deactivate ourself
			wp_die("Sorry, but you can't run this plugin on current WordPress version, it requires WordPress v5.6 or higher.");
		}
		flush_rewrite_rules();
	}

	public function deactivation() {
		flush_rewrite_rules();
	}
	
	public function init() {
		global $wcsearch_instance, $wcsearch_shortcodes, $wpdb;

		add_action('plugins_loaded', array($this, 'load_textdomains'));
		
		foreach ($wcsearch_shortcodes AS $shortcode=>$function) {
			add_shortcode($shortcode, array($this, 'renderShortcode'));
		}
		
		add_action('init', array($this, 'register_post_type'), 0);

		add_action('wp', array($this, 'loadFrontendControllers'), 1);

		if (!get_option('wcsearch_installed_search') || get_option('wcsearch_installed_search_version') != WCSEARCH_VERSION) {
			if (get_option('wcsearch_installed_search')) {
				$this->loadClasses();
			}

			add_action('init', 'wcsearch_install_search', 0);
		} else {
			$this->loadClasses();
		}
		
		// used in products controller
		add_filter('wcsearch_query_input_args', array($this, 'set_query_input_args'), 0);
		
		add_filter('no_texturize_shortcodes', array($this, 'wcsearch_no_texturize'));

		add_action('wp_enqueue_scripts', array($this, 'enqueue_scripts_styles'));
		add_action('wp_enqueue_scripts', array($this, 'enqueue_scripts_styles_custom'), 9999);
		
		if (wcsearch_is_standalone_plugin()) {
			add_filter('wpseo_sitemap_post_type_archive_link', array($this, 'exclude_post_type_archive_link'), 10, 2);
			
			add_filter('plugin_row_meta', array($this, 'plugin_row_meta'), 10, 2);
			add_filter('plugin_action_links_' . plugin_basename(__FILE__), array($this, 'plugin_action_links'));
			
			// include search form on a shop page
			add_action('woocommerce_before_shop_loop', array($this, 'search_form_on_shop_page'), 0);
			add_action('woocommerce_before_shop_loop', array($this, 'open_wrap_woo_products'), 1);
			add_action('woocommerce_after_shop_loop', array($this, 'close_wrap_woo_products'), 100);
			add_action('woocommerce_before_shop_loop', array($this, 'visible_search_params'), 3);
			
			add_action('woocommerce_no_products_found', array($this, 'search_form_on_shop_page'), 2);
			add_action('woocommerce_no_products_found', array($this, 'open_wrap_woo_products'), 2);
			add_action('woocommerce_no_products_found', array($this, 'close_wrap_woo_products'), 100);
			add_action('woocommerce_no_products_found', array($this, 'visible_search_params'), 3);
			
			add_action('woocommerce_shortcode_products_loop_no_results', array($this, 'search_form_on_shop_page'), 2);
			add_action('woocommerce_shortcode_products_loop_no_results', array($this, 'open_wrap_woo_products'), 2);
			add_action('woocommerce_shortcode_products_loop_no_results', array($this, 'close_wrap_woo_products'), 100);
			add_action('woocommerce_shortcode_products_loop_no_results', array($this, 'visible_search_params'), 3);
			add_action('woocommerce_shortcode_products_loop_no_results', array($this, 'no_products_found'));
			
			add_action('woocommerce_update_product', array($this, 'clear_count_cache'));
			add_action('woocommerce_new_product', array($this, 'clear_count_cache'));
			add_action('wp_trash_post', array($this, 'trash_post'));
			add_action('untrashed_post', array($this, 'trash_post'));
			
			// follow search query in default shop page loop
			add_action('woocommerce_product_query', array($this, 'woocommerce_product_query'));
			
			// check home page
			add_filter('request', array($this, 'request'));
			
			add_action('wp_footer', array($this, 'elementor_support_wp_footer'));
		}
	}
	
	public function no_products_found() {
		if (wcsearch_is_woo_active()) {
			wc_no_products_found();
		}
	}
	
	public function set_query_input_args($args) {
		
		$_args = array_merge(array(
				'price' => '',
				'featured' => 0,
				'onsale' => 0,
				'instock' => 0,
				'orderby' => '',
				'order' => '',
				'keywords' => '',
				'page' => 1,
				'posts_per_page' => -1,
				'taxonomies' => array(),
		), wcsearch_get_default_query(), $args, wcsearch_get_query_string());
		
		if (wcsearch_is_woo_active()) {
			$_args['page'] = (get_query_var('paged')) ? absint(get_query_var('paged')) : $_args['page'];
			$_args['posts_per_page'] = apply_filters('loop_shop_per_page', wc_get_default_products_per_row() * wc_get_default_product_rows_per_page());
			
			$_taxonomies = wcsearch_get_all_taxonomies();
			foreach ($_taxonomies AS $tax_name=>$tax_slug) {
				if (wcsearch_get_tax_terms_from_query_string($tax_slug)) {
					$_args['taxonomies'][$tax_name] = wcsearch_get_tax_terms_from_query_string($tax_slug);
				} elseif (wcsearch_get_tax_terms_from_args($tax_slug, $args)) {
					$_args['taxonomies'][$tax_name] = wcsearch_get_tax_terms_from_args($tax_slug, $args);
				}
			}
		}
		
		return $_args;
	}
	
	public function request($query_vars) {
		
		// home page takes taxonomy names as query vars, remove them and gives Page not found error
		if (wcsearch_get_query_string() && (in_array($_SERVER["REQUEST_URI"], array('/', '')) || strpos($_SERVER["REQUEST_URI"], '/?') === 0)) {
			unset($query_vars['product_cat']);
			unset($query_vars['product_tag']);
		}
		
		return $query_vars;
	}
	
	public function woocommerce_product_query($q) {
		
		if (!wcsearch_get_query_string()) {
			return $q;
		}
		
		// do not action on AJAX search query
		if (wp_doing_ajax()) {
			return $q;
		}
		
		// change taxes search by ID to search by slug
		$taxes_to_check = array('product_cat', 'product_tag');
		foreach ($taxes_to_check AS $tax_to_check) {
			if (!empty($q->query_vars[$tax_to_check])) {
				$new_query_var = array();
				$terms = explode(',', $q->query_vars[$tax_to_check]);
				foreach ($terms AS $term_id) {
					if (is_numeric($term_id)) {
						$term_obj = get_term($term_id, $tax_to_check);
						if ($term_obj) {
							$new_query_var[] = $term_obj->slug;
						}
					}
				}
				if ($new_query_var) {
					$q->query_vars[$tax_to_check] = implode(',', $new_query_var);
				}
			}
		}
		
		$args = apply_filters("wcsearch_query_input_args", array());
		
		$v_args = apply_filters("wcsearch_query_args_validate", $args);
		
		$q_args = array(
				'post_type' => array('product'),
				'post_status' => 'publish',
				'posts_per_page' => $v_args['posts_per_page'],
				'tax_query' => array(
						array(
								'taxonomy' => 'product_visibility',
								'field'    => 'name',
								'terms'    => 'exclude-from-search',
								'operator' => 'NOT IN',
						)
				),
		);
		
		$q_args = apply_filters("wcsearch_query_args", $q_args, $v_args);
		
		if (!empty($q_args['tax_query'])) {
			$q->set('tax_query', $q_args['tax_query']);
		}
		if (!empty($q_args['meta_query'])) {
			$q->set('meta_query', $q_args['meta_query']);
		}
		
		if (!empty($q_args['s'])) {
			$q->set('s', $q_args['s']);
		}
		if (!empty($q_args['post__in'])) {
			$q->set('post__in', $q_args['post__in']);
		}
		
		$orderby_query = wcsearch_get_query_string("orderby");
		if ($orderby_query) {
			$meta_key = '';
			global $wpdb;
			switch ($orderby_query) {
				case 'price-desc':
					$orderby = "meta_value_num {$wpdb->posts}.ID";
					$order = 'DESC';
					$meta_key = '_price';
					break;
				case 'price':
					$orderby = "meta_value_num {$wpdb->posts}.ID";
					$order = 'ASC';
					$meta_key = '_price';
					break;
				case 'popularity' :
					add_filter('posts_clauses', array(WC()->query, 'order_by_popularity_post_clauses'));
					$meta_key = 'total_sales';
					break;
				case 'rating' :
					$orderby = "meta_value_num {$wpdb->posts}.ID";
					$order = 'DESC';
					$meta_key = apply_filters('wcsearch_wc_rating_order_meta_key', '_wc_average_rating');
					break;
				case 'title' :
					$orderby = 'title';
					break;
				case 'title-desc':
					$orderby = "title";
					$order = 'DESC';
					break;
				case 'title-asc':
					$orderby = "title";
					$order = 'ASC';
					break;
				case 'rand' :
					$orderby = 'rand';
					break;
				case 'date' :
					$order = 'DESC';
					$orderby = 'date';
					break;
				default:
					$order = 'ASC';
					$orderby = 'menu_order title';
					break;
			}
			
			if (!empty($orderby)) {
				$q->set('orderby', $orderby);
			
				if (!empty($order)) {
					$q->set('orderby', $order);
				}
				if (!empty($meta_key)) {
					$q->set('meta_key', $meta_key);
				}
			}
		}
		
		return $q;
	}
	
	public function load_textdomains() {
		load_plugin_textdomain('WCSEARCH', '', dirname(plugin_basename( __FILE__ )) . '/languages');
	}
	
	public function loadClasses() {
		$this->search_forms = new wcsearch_search_forms_manager;
		$this->ajax_controller = new wcsearch_ajax_controller;
		$this->admin = new wcsearch_admin;
		if (wcsearch_is_standalone_plugin()) {
			$this->updater = new wcsearch_updater(__FILE__, get_option('wcsearch_purchase_code'), get_option('wcsearch_access_token'));
		}
	}

	public function wcsearch_no_texturize($shortcodes) {
		global $wcsearch_shortcodes;
		
		foreach ($wcsearch_shortcodes AS $shortcode=>$function)
			$shortcodes[] = $shortcode;
		
		return $shortcodes;
	}

	public function renderShortcode() {
		global $wcsearch_shortcodes;
	
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
	
		if (isset($wcsearch_shortcodes[$shortcode])) {
			$shortcode_class = $wcsearch_shortcodes[$shortcode];
			if ($attrs[0] === '')
				$attrs[0] = array();
			$shortcode_instance = new $shortcode_class();
			$this->frontend_controllers[$shortcode][] = $shortcode_instance;
			$shortcode_instance->init($attrs[0], $shortcode);
			
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
	
	public function visible_search_params() {
		if ($query_array = wcsearch_get_query_string()) {
			$visible_search_params = array();
			$visible_search_params = apply_filters("wcsearch_visible_params", $visible_search_params, $query_array);
			
			echo '<div class="wcsearch-visible-search-params">';
			
			foreach ($visible_search_params AS $query_string=>$param_label) {
				$permalink = '?' . $query_string;
				echo '<div class="wcsearch-search-param"><a class="wcsearch-search-param-delete" href="' . $permalink . '">×</a>';
				echo wp_kses(
						wp_unslash($param_label),
						array(
								'span' => array(
										'class' => array()
								),
								'small' => array(
										'class' => array()
								),
								'bdi' => array(
										'class' => array()
								)
						)
				);
				echo '</div>';
			}
			echo '</div>';
		}
	}
	
	public function search_form_on_shop_page() {
		
		if (wcsearch_is_shop() || wcsearch_is_product_category() || wcsearch_is_product_tag()) {
			// wrap the loop only the first time
			if (!wp_doing_ajax()) {
				$search_form_id = wcsearch_getValue($_REQUEST, 'wcsearch_test_form');
				if (!$search_form_id || !current_user_can('manage_options')) {
					$search_form_id = $this->form_on_shop_page;
				}
				
				if ($search_form_id) {
					echo $this->renderShortcode(array('id' => $search_form_id), '', WCSEARCH_MAIN_SHORTCODE);
				}
			}
		}
	}
	
	public function open_wrap_woo_products() {
		// wrap the loop only the first time
		if (!wp_doing_ajax()) {
			// products loop ID,
			// it needs to send request by ordering and paginator
			$id = wcsearch_generateRandomVal();
			
			echo '<div id="wcsearch-woo-loop" class="wcsearch-woo-loop" data-id="' . esc_attr($id) . '">';
		}
	}
	
	public function close_wrap_woo_products() {
		if (!wp_doing_ajax()) {
			echo '</div><!-- close wrap woo products -->';
		}
	}

	public function loadFrontendControllers() {
		global $post, $wp_query;

		if ($page_id = wcsearch_isWooPage()) {
			$wc_page = get_post($page_id);
			
			$pattern = get_shortcode_regex();
			$this->loadNestedFrontendController($pattern, $wc_page->post_content);
		} elseif ($wp_query->posts) {
			$pattern = get_shortcode_regex();
			foreach ($wp_query->posts AS $archive_post) {
				if (isset($archive_post->post_content)) {
					$this->loadNestedFrontendController($pattern, $archive_post->post_content);
				}
			}
		} elseif ($post && isset($post->post_content)) {
			$pattern = get_shortcode_regex();
			$this->loadNestedFrontendController($pattern, $post->post_content);
		}
	}

	// this may be recursive function to catch nested shortcodes
	public function loadNestedFrontendController($pattern, $content) {
		global $wcsearch_shortcodes_init, $wcsearch_shortcodes;

		if (preg_match_all('/'.$pattern.'/s', $content, $matches) && array_key_exists(2, $matches)) {
			foreach ($matches[2] AS $key=>$shortcode) {
				if ($shortcode != 'shortcodes') {
					if (isset($wcsearch_shortcodes_init[$shortcode]) && class_exists($wcsearch_shortcodes_init[$shortcode])) {
						$shortcode_class = $wcsearch_shortcodes_init[$shortcode];
						if (!($attrs = shortcode_parse_atts($matches[3][$key])))
							$attrs = array();
						$shortcode_instance = new $shortcode_class();
						$this->frontend_controllers[$shortcode][] = $shortcode_instance;
						$this->_frontend_controllers[$shortcode][] = $shortcode_instance;
						$shortcode_instance->init($attrs, $shortcode);
					} elseif (isset($wcsearch_shortcodes[$shortcode]) && class_exists($wcsearch_shortcodes[$shortcode])) {
						$shortcode_class = $wcsearch_shortcodes[$shortcode];
						$this->frontend_controllers[$shortcode][] = $shortcode_class;
					}
					if ($shortcode_content = $matches[5][$key])
						$this->loadNestedFrontendController($pattern, $shortcode_content);
				}
			}
		}
	}

	public function register_post_type() {
		global $wpdb;
		
		if (!isset($wpdb->wcsearch_cache)) {
			$wpdb->wcsearch_cache = $wpdb->prefix . 'wcsearch_cache';
		}
		
		$this->form_on_shop_page = wcsearch_get_on_shop_page();

		$args = array(
				'labels' => array(
						'name' => esc_html__('Search Forms', 'WCSEARCH'),
						'singular_name' => esc_html__('Search Form', 'WCSEARCH'),
						'add_new' => esc_html__('Create new search form', 'WCSEARCH'),
						'add_new_item' => esc_html__('Create new search form', 'WCSEARCH'),
						'edit_item' => esc_html__('Edit search form', 'WCSEARCH'),
						'new_item' => esc_html__('New search form', 'WCSEARCH'),
						'view_item' => esc_html__('View search form', 'WCSEARCH'),
						'search_items' => esc_html__('Search search forms', 'WCSEARCH'),
						'not_found' =>  esc_html__('No search forms found', 'WCSEARCH'),
						'not_found_in_trash' => esc_html__('No search forms found in trash', 'WCSEARCH'),
						'item_updated' => esc_html__('Search form updated', 'WCSEARCH'),
						'item_published' => esc_html__('Search form published', 'WCSEARCH'),
				),
				'description' => esc_html__('Search forms', 'WCSEARCH'),
				'public' => false,
				'publicly_queryable' => false, // removes "Preview changes" button
				'show_ui' => true,
				'exclude_from_search' => true,
				'show_in_nav_menus' => false,
				'has_archive' => false,
				'rewrite' => false,
				'supports' => array('title'),
				'menu_icon' => WCSEARCH_RESOURCES_URL . 'images/menuicon.png',
		);
		register_post_type(WCSEARCH_FORM_TYPE, $args);
	}
	
	public function clear_count_cache() {
		global $wpdb;
		
		$wpdb->query("TRUNCATE TABLE {$wpdb->wcsearch_cache}");
	}
	
	public function trash_post($id) {
		if (!$id) {
			return;
		}
	
		$post_type = get_post_type($id);

		if ('product' === $post_type) {
			$this->clear_count_cache();
		}
	}
	
	public function elementor_support_wp_footer() {
		if (!defined('ELEMENTOR_VERSION')) {
			return;
		}
		?>
		<script>
			jQuery(function($) {
				if (window.elementorFrontend && typeof elementorFrontend.hooks != 'undefined') {
					elementorFrontend.hooks.addAction('frontend/element_ready/global', function(el) {
						if (el.data("widget_type") && el.data("widget_type").indexOf("wcsearch_") != -1) {
							wcsearch_init();
						}
					});
				}
			});
		</script>
		<?php
	}

	public function enqueue_scripts_styles($load_scripts_styles = false) {
		global $wcsearch_enqueued;
		
		if (wcsearch_do_enqueue_scripts_styles($load_scripts_styles)) {
			add_action('wp_head', array($this, 'enqueue_global_vars'));
			
			wp_enqueue_script('jquery', false, array(), false, false);

			wp_register_style('wcsearch_frontend', WCSEARCH_RESOURCES_URL . 'css/frontend.css', array(), WCSEARCH_VERSION);

			if (function_exists('is_rtl') && is_rtl()) {
				wp_register_style('wcsearch_frontend_rtl', WCSEARCH_RESOURCES_URL . 'css/frontend-rtl.css', array(), WCSEARCH_VERSION);
			}

			wp_register_style('wcsearch_font_awesome', WCSEARCH_RESOURCES_URL . 'css/font-awesome.css', array(), WCSEARCH_VERSION);

			wp_register_script('wcsearch_js_functions', WCSEARCH_RESOURCES_URL . 'js/js_functions.js', array('jquery'), WCSEARCH_VERSION, true);

			// this jQuery UI version 1.10.4
			$ui_theme = 'smoothness';
			wp_register_style('wcsearch-jquery-ui-style', WCSEARCH_RESOURCES_URL . 'css/jquery-ui/themes/' . $ui_theme . '/jquery-ui.css');

			wp_enqueue_style('wcsearch_font_awesome');
			wp_enqueue_style('wcsearch_frontend');
			wp_enqueue_style('wcsearch_frontend_rtl');

			wp_enqueue_script('jquery-ui-draggable');
			wp_enqueue_script('jquery-ui-selectmenu');
			wp_enqueue_script('jquery-ui-autocomplete');
			wp_enqueue_script('jquery-ui-slider');
			wp_enqueue_script('jquery-ui-datepicker');
			wp_enqueue_script('jquery-touch-punch');
			if (!get_option('wcsearch_notinclude_jqueryui_css') && wcsearch_is_standalone_plugin()) {
				wp_enqueue_style('wcsearch-jquery-ui-style');
			}

			wp_enqueue_script('wcsearch_js_functions');

			$wcsearch_enqueued = true;
		}
	}
	
	public function enqueue_scripts_styles_custom($load_scripts_styles = false) {
		if ((($this->frontend_controllers || $load_scripts_styles)) || get_option('wcsearch_force_include_js_css')) {
			if ($frontend_custom = wcsearch_isResource('css/frontend-custom.css')) {
				wp_register_style('wcsearch_frontend-custom', $frontend_custom, array(), WCSEARCH_VERSION);
				
				wp_enqueue_style('wcsearch_frontend-custom');
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
		
		$adapter_options = apply_filters("wcsearch_adapter_options", array());
		
		echo 'var wcsearch_js_objects = ' . json_encode(
				array(
						'ajaxurl' => $ajaxurl,
						'pagination_base' => wcsearch_get_pagination_base(),
						'query_string' => http_build_query(wcsearch_get_query_string()),
						'default_query' => wcsearch_get_default_query(), // submits along with other data to 'wcsearch_search_request'
						'desktop_screen_width' => 992,
						'mobile_screen_width' => 768,
						'radio_reset_btn_title' => esc_html__('unselect', 'WCSEARCH'),
						'geocode_functions' => wcsearch_geocode_functions(),
						'prediction_note' => esc_html__('search nearby', 'WCSEARCH'),
						'get_my_location_title' => esc_html__('My location', 'WCSEARCH'),
						'adapter_options' => $adapter_options,
						'reset_same_inputs' => apply_filters("wcsearch_reset_same_inputs", true), // do reset the same type of inputs before submit
				)
		) . ';
';

		echo '</script>
';
	}
	
	public function exclude_post_type_archive_link($archive_url, $post_type) {
		if ($post_type == WCSEARCH_FORM_TYPE) {
			return false;
		}
		
		return $archive_url;
	}
	
	public function plugin_row_meta($links, $file) {
		if (dirname(plugin_basename(__FILE__) == $file)) {
			$row_meta = array(
					'docs' => '<a href="https://www.salephpscripts.com/wordpress-search/demo/documentation/">' . esc_html__("Documentation", "WCSEARCH") . '</a>',
					'codecanoyn' => '<a href="https://www.salephpscripts.com/wc-search/#changelog">' . esc_html__("Changelog", "WCSEARCH") . '</a>',
			);
	
			return array_merge($links, $row_meta);
		}
	
		return $links;
	}
	
	public function plugin_action_links($links) {
		$action_links = array(
				'settings' => '<a href="' . admin_url('admin.php?page=wcsearch_settings') . '">' . esc_html__("Settings", "WCSEARCH") . '</a>',
		);
	
		return array_merge($action_links, $links);
	}
}

$wcsearch_instance = new wcsearch_plugin();
$wcsearch_instance->init();

?>