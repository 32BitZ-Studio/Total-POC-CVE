<?php 

class w2dc_frontend_controller {
	public $args = array();
	public $query;
	public $page_title;
	public $template;
	public $listings = array();
	public $search_form;
	public $map;
	public $paginator;
	public $breadcrumbs = array();
	public $base_url ='';
	public $page_url = '';
	public $messages = array();
	public $hash = null;
	public $levels_ids;
	public $do_initial_load = true;
	public $template_args = array();
	private $global_post;

	public function __construct($args = array()) {
		apply_filters('w2dc_frontend_controller_construct', $this);
		
		$this->template_args = array('frontend_controller' => $this);
	}
	
	public function add_template_args($args = array()) {
		$this->template_args += $args;
	}
	
	public function init($attrs = array()) {
		$this->args['logo_animation_effect'] = get_option('w2dc_logo_animation_effect');

		if (!$this->hash) {
			if (isset($attrs['hash'])) {
				$this->hash = $attrs['hash'];
			} else {
				if (isset($attrs['custom_home']) && $attrs['custom_home']) {
					$this->hash = md5('custom_home');
				} elseif (isset($attrs['uid']) && $attrs['uid']) {
					$this->hash = md5($attrs['uid']);
				} else {
					$this->hash = md5(get_class($this).serialize($attrs));
				}
			}
		}
		
		if (!empty($attrs['levels'])) {
			if (!is_array($attrs['levels'])) {
				$levels = array_filter(explode(',', $attrs['levels']), 'trim');
			} else {
				$levels = $attrs['levels'];
				
				// trim levels IDs due to Elementor's " ID" trick with keys order
				//array_walk($levels, 'trim');
				$levels = array_map('trim', $levels);
			}
			$this->levels_ids = $levels;
			add_filter('posts_join', 'w2dc_join_levels');
			add_filter('posts_where', array($this, 'where_levels_ids'));
		}
		
		if (!empty($attrs['levels']) || !empty($attrs['sticky_featured'])) {
			add_filter('posts_join', 'w2dc_join_levels');
			if (!empty($attrs['sticky_featured'])) {
				add_filter('posts_join', 'w2dc_join_levels');
				add_filter('posts_where', 'w2dc_where_sticky_featured');
			}
		}
	}
	
	public function init_end() {
		remove_filter('posts_join', 'w2dc_join_levels');
		remove_filter('posts_where', 'w2dc_where_sticky_featured');
	
		if ($this->levels_ids) {
			remove_filter('posts_where', array($this, 'where_levels_ids'));
		}
		
		apply_filters('w2dc_listings_controller_construct', $this);
	}
	
	// Temporarily change global $post variable in head
	public function save_global_post() {
		global $post;
		$this->global_post = $post;
	}
	
	public function back_global_post() {
		global $post;
		$post = $this->global_post;
	}

	public function processQuery($how_to_load = 'full') {
		
		$this->save_global_post();
		
		// this is special construction,
		// this needs when we order by any postmeta field, this adds listings to the list with "empty" fields
		if (($this->getQueryVars('orderby') == 'meta_value_num' || $this->getQueryVars('orderby') == 'meta_value') && ($this->getQueryVars('meta_key') != '_order_date')) {
			$args = $this->getQueryVars();

			// there is strange thing - WP adds `taxonomy` and `term_id` args to the root of query vars array
			// this may cause problems
			unset($args['taxonomy']);
			unset($args['term_id']);
			if (empty($args['s'])) {
				unset($args['s']);
			}
			
			$original_posts_per_page = $args['posts_per_page'];

			$ordered_posts_ids = get_posts(array_merge($args, array('fields' => 'ids', 'nopaging' => true)));
			$ordered_max_num_pages = ceil(count($ordered_posts_ids)/$original_posts_per_page) - (int) $ordered_posts_ids;

			$args['paged'] = $args['paged'] - $ordered_max_num_pages;
			$args['orderby'] = 'meta_value_num';
			$args['meta_key'] = '_order_date';
			$args['order'] = 'DESC';
			$args['posts_per_page'] = $original_posts_per_page - $this->query->post_count;
			$all_posts_ids = get_posts(array_merge($args, array('fields' => 'ids', 'nopaging' => true)));
			$all_posts_count = count($all_posts_ids);
			//var_dump($all_posts_count);

			// commented this line, because it gives duplicates on rating_order for example,
			// when rated listings already have been shown, on the next 'Show more listings' step it just gives empty query - so it does not include post__not_in with shown listings and just gives first query
			//if ($this->query->found_posts) {
				$args['post__not_in'] = array_map('intval', $ordered_posts_ids);
				if (!empty($args['post__in']) && is_array($args['post__in'])) {
					$args['post__in'] = array_diff($args['post__in'], $args['post__not_in']);
					if (!$args['post__in']) {
						$args['posts_per_page'] = 0;
					}
				}
			//}

			$unordered_query = new WP_Query($args);

			if ($args['posts_per_page']) {
				$this->query->posts = array_merge($this->query->posts, $unordered_query->posts);
			}

			$this->query->post_count = count($this->query->posts);
			$this->query->found_posts = $all_posts_count;
			$this->query->max_num_pages = ceil($all_posts_count/$original_posts_per_page);
		}
		
		// while random sorting - we have to exclude already shown listings,
		// also when it has "posts_per_page" parameter with -1 value, exclude them as well
		if (
			isset($this->args['existing_listings']) &&
			(w2dc_getValue($_REQUEST, 'order_by') == 'rand' /*|| $this->getQueryVars('posts_per_page') == -1 */))
		{
			$existing_listings = array_filter(explode(',', $this->args['existing_listings']));
			foreach ($this->query->posts AS $key=>$post) {
				if (in_array($post->ID, $existing_listings)) {
					unset($this->query->posts[$key]);
				}
			}
			
			if (empty($this->args['perpage']) || !is_numeric($this->args['perpage'])) {
				$this->args['perpage'] = count($this->query->posts) ? count($this->query->posts) : 1;
			}
			
			$this->query->posts = array_values($this->query->posts);
			$this->query->posts = array_slice($this->query->posts, 0, $this->args['perpage']);

			$this->query->post_count = count($this->query->posts);
			$this->query->max_num_pages = ceil($this->query->found_posts/$this->args['perpage']);
		}

		while ($this->query->have_posts()) {
			$this->query->the_post();

			$listing = new w2dc_listing;
			
			if ($how_to_load == 'for_map') {
				$listing->loadListingForMap(get_post());
			} elseif ($how_to_load == 'for_ajax_map') {
				$listing->loadListingForAjaxMap(get_post());
			} else {
				$listing->loadListingFromPost(get_post());
				$listing->logo_animation_effect = (isset($this->args['logo_animation_effect'])) ? $this->args['logo_animation_effect'] : get_option('w2dc_logo_animation_effect');
			}
			
			$this->listings[get_the_ID()] = $listing;
		}

		// this is reset is really required after the loop ends 
		wp_reset_postdata();
		
		$this->back_global_post();
		
		remove_filter('posts_join', 'w2dc_join_levels');
		remove_filter('posts_orderby', 'w2dc_orderby_levels', 1);
		remove_filter('get_meta_sql', 'w2dc_add_null_values');
	}
	
	public function collectAllLocations() {
		$args = $this->getQueryVars();
		
		unset($args['orderby']);
		unset($args['order']);
		if (empty($args['s'])) {
			unset($args['s']);
		}
		$args['nopaging'] = 1;
		
		$unlimited_query = new WP_Query($args);
		
		while ($unlimited_query->have_posts()) {
			$unlimited_query->the_post();
		
			$listing = new w2dc_listing;
			$listing->loadListingFromPost(get_post());
		
			$this->map->collectLocations($listing);
		}
		
		wp_reset_postdata();
	}
	
	public function getQueryVars($var = null) {
		if (is_null($var)) {
			return $this->query->query_vars;
		} else {
			if (isset($this->query->query_vars[$var])) {
				return $this->query->query_vars[$var];
			}
		}
		return false;
	}
	
	public function getPageTitle() {
		return $this->page_title;
	}

	public function addBreadCrumbs($breadcrumb) {
		if (is_array($breadcrumb)) {
			foreach ($breadcrumb AS $_breadcrumb) {
				$this->addBreadCrumbs($_breadcrumb);
			}
		} else {
			if (is_object($breadcrumb) && get_class($breadcrumb) == 'w2dc_breadcrumb') {
				$this->breadcrumbs[] = $breadcrumb;
			} else {
				$this->breadcrumbs[] = new w2dc_breadcrumb($breadcrumb);
			}
		}
	}
	
	public function printBreadCrumbs($separator = ' » ') {
		
		do_action("w2dc_print_breadcrumbs", $this);
		
		if ($breadcrumbs_process = $this->breadcrumbs) {
			$do_schema = false;
			if (count($this->breadcrumbs) > 1) {
				$do_schema = true;
			}
			
			$do_schema = apply_filters('w2dc_do_schema', $do_schema);
			
			if ($do_schema) {
				echo '<ol class="w2dc-breadcrumbs" itemscope itemtype="http://schema.org/BreadcrumbList">';
			} else {
				echo '<ol class="w2dc-breadcrumbs">';
			}
			
			if (!get_option('w2dc_hide_home_link_breadcrumb')) {
				array_unshift($breadcrumbs_process, new w2dc_breadcrumb(esc_html__('Home', 'W2DC'), w2dc_directoryUrl()));
			}
			
			$breadcrumbs_process = apply_filters("w2dc_breadcrumbs_process", $breadcrumbs_process, $this);
			
			$counter = 0;
			foreach ($breadcrumbs_process AS $key=>$breadcrumb) {
				$title = '';
				if ($breadcrumb->title) {
					$title = 'title="' . $breadcrumb->title . '"';
				}
				
				if ($breadcrumb->url) {
					if ($do_schema) {
						$counter++;
						echo '<li itemprop="itemListElement" itemscope="" itemtype="http://schema.org/ListItem"><a href="' . $breadcrumb->url . '" itemprop="item" ' . $title . '><span itemprop="name">' . $breadcrumb->name . '</span><meta itemprop="position" content="' . $counter . '" /></a></li>';
					} else {
						echo '<li><a href="' . $breadcrumb->url . '" ' . $title . '>' . $breadcrumb->name . '</a></li>';
					}
				} else {
					echo '<li>' . $breadcrumb->name . '</li>';
				}
				
				if ($key+1 < count($breadcrumbs_process)) {
					echo $separator;
				}
			}
			echo '</ol>';
		}
	}

	public function getBaseUrl() {
		return $this->base_url;
	}
	
	public function where_levels_ids($where = '') {
		if ($this->levels_ids)
			$where .= " AND (w2dc_levels.id IN (" . implode(',', $this->levels_ids) . "))";
		return $where;
	}
	
	public function getListingsDirectory() {
		global $w2dc_instance;
		
		if (isset($this->args['directories']) && !empty($this->args['directories'])) {
			if (is_object($this->args['directories'])) {
				return $this->args['directories'];
			} elseif (is_string($this->args['directories'])) {
				if ($directories_ids = array_filter(explode(',', $this->args['directories']), 'trim')) {
					if (count($directories_ids) == 1 && ($directory = $w2dc_instance->directories->getDirectoryById($directories_ids[0]))) {
						return $directory;
					}
				}
			}
		}
		
		return $w2dc_instance->current_directory;
	}
	
	public function getListingClasses() {
		$classes = array();
		$listing = $this->listings[get_the_ID()];
		
		$classes[] = 'w2dc-listing-level-' . $listing->level->id;
		
		if ($listing->level->featured) {
			$classes[] = 'w2dc-featured';
		}
		if ($listing->level->sticky) {
			$classes[] = 'w2dc-sticky';
		}
		if (!empty($this->args['summary_on_logo_hover'])) {
			$classes[] = 'w2dc-summary-on-logo-hover';
		}
		if (!empty($this->args['hide_content'])) {
			$classes[] = 'w2dc-hidden-content';
		}
		if ($listing->isMap()) {
			foreach ($listing->locations AS $location) {
				$classes[] = 'w2dc-listing-has-location-'.$location->id;
			}
		}
		
		$classes = apply_filters("w2dc_listing_classes", $classes, $listing);
		
		return implode(" ", $classes);
	}
	
	public function getListingsBlockClasses() {
		$classes[] = "w2dc-container-fluid";
		$classes[] = "w2dc-listings-block";
		$classes[] = "w2dc-mobile-listings-grid-" . get_option('w2dc_mobile_listings_grid_columns');
		$views_cookie = false;
		if ($this->args['show_views_switcher'] && isset($_COOKIE['w2dc_listings_view_'.$this->hash])) {
			$views_cookie = $_COOKIE['w2dc_listings_view_'.$this->hash];
		}
		if (($this->args['listings_view_type'] == 'grid' && !$views_cookie) || ($views_cookie == 'grid')) {
			$classes[] = "w2dc-listings-grid";
			$classes[] = "w2dc-listings-grid-" . $this->args['listings_view_grid_columns'];
		} else {
			$classes[] = "w2dc-listings-list-view";
		}
		
		$classes = apply_filters("w2dc_listings_block_classes", $classes, $this);
	
		return implode(" ", $classes);
	}
	
	public function printVisibleSearchParams() {
		if (apply_filters('w2dc_print_visible_search_params', true)) {
			
			if ($query_array = wcsearch_get_query_string()) {
				$visible_search_params = array();
				$visible_search_params = apply_filters("w2dc_visible_params", $visible_search_params, $query_array);
					
				echo '<div class="wcsearch-visible-search-params">';
					
				foreach ($visible_search_params AS $query_string=>$param_label) {
					if (empty($_REQUEST['page_url'])) {
						global $wp;
							
						$page = home_url($wp->request);
					} else {
							
						$page = $_REQUEST['page_url'];
					}
					$permalink = add_query_arg($query_string, '', $page);
					
					echo '<div class="wcsearch-search-param"><a class="wcsearch-search-param-delete" href="' . $permalink . '">×</a>';
					echo esc_html(wp_unslash($param_label));
					echo '</div>';
				}
				echo '</div>';
			}
		}
	}
	
	public function getPagenumLink($result) {
		global $w2dc_global_base_url;
	
		if ($w2dc_global_base_url) {
			preg_match('/paged=(\d+)/', $result, $matches);
			if (isset($matches[1])) {
				global $wp_rewrite;
				if ($wp_rewrite->using_permalinks()) {
					$parsed_url = parse_url($w2dc_global_base_url);
					$query_args = (isset($parsed_url['query'])) ? wp_parse_args($parsed_url['query']) : array();
					foreach ($query_args AS $key=>$arg) {
						if (!is_array($arg)) {
							$query_args[$key] = urlencode($arg);
						}
					}
					$url_without_get = ($pos_get = strpos($w2dc_global_base_url, '?')) ? substr($w2dc_global_base_url, 0, $pos_get) : $w2dc_global_base_url;
					return esc_url(add_query_arg($query_args, trailingslashit(trailingslashit($url_without_get) . 'page/' . $matches[1])));
				} else {
					return add_query_arg('page', $matches[1], $w2dc_global_base_url);
				}
			} else {
				if (strpos($result, "admin-ajax.php") === false) {
					return $result;
				} else {
					return $w2dc_global_base_url;
				}
			}
		} else {
			return $result;
		}
	}
	
	public function getShortcodeController() {
		return w2dc_getShortcodeController();
	}
	
	/**
	 * posts_per_page does not work in WP_Query when we search by name='slug' parameter,
	 * we have to use this hack
	 * 
	 * @return string
	 */
	public function findOnlyOnePost() {
		return 'LIMIT 0, 1';
	}
	
	public function clearStartListingsArgs() {
		
		// clear starting listings, not to save them in the args for any further AJAX requests
		if (!empty($this->args['start_listings'])) {
			$this->args['start_listings'] = array();
			$this->args['post__in'] = 0;
		}
	}
	
	public function display() {
		
		$this->clearStartListingsArgs();
		
		$output =  w2dc_renderTemplate($this->template, $this->template_args, true);
		wp_reset_postdata();
		
		remove_filter('get_pagenum_link', array($this, 'getPagenumLink'));
	
		return $output;
	}
}

/**
 * join levels_relationships and levels tables into the query
 * 
 * */
function w2dc_join_levels($join = '') {
	global $wpdb;

	$join .= " LEFT JOIN {$wpdb->w2dc_levels_relationships} AS w2dc_lr ON w2dc_lr.post_id = {$wpdb->posts}.ID ";
	$join .= " LEFT JOIN {$wpdb->w2dc_levels} AS w2dc_levels ON w2dc_levels.id = w2dc_lr.level_id ";

	return $join;
}

/**
 * sticky and featured listings in the first order
 * 
 */
function w2dc_orderby_levels($orderby = '') {
	$orderby_array[] = " w2dc_levels.sticky DESC";
	$orderby_array[] = "w2dc_levels.featured DESC";
	$orderby_array[] = $orderby;
	
	$orderby_array = apply_filters('w2dc_orderby_levels', $orderby_array, $orderby);
	
	return implode(', ', $orderby_array);
}

// this filter orders sticky levels by their order num
/* add_filter("w2dc_orderby_levels", "w2dc_orderby_levels_num", 10, 2);
function w2dc_orderby_levels_num($orderby_array, $orderby) {

	array_splice($orderby_array, 1, 0, array("w2dc_levels.order_num ASC"));
	
	return $orderby_array;
} */

/**
 * sticky and featured listings in the first order
 * 
 */
function w2dc_where_sticky_featured($where = '') {
	$where .= " AND (w2dc_levels.sticky=1 OR w2dc_levels.featured=1)";
	return $where;
}

/**
 * Listings with empty values must be sorted as well
 * 
 */
function w2dc_add_null_values($clauses) {
	$clauses['where'] = preg_replace("/wp_postmeta\.meta_key = '_content_field_([0-9]+)'/", "(wp_postmeta.meta_key = '_content_field_$1' OR wp_postmeta.meta_value IS NULL)", $clauses['where']);
	return $clauses;
}


add_filter('w2dc_order_args', 'w2dc_order_listings', 10, 3);
function w2dc_order_listings($order_args = array(), $defaults = array()) {
	global $w2dc_instance;
	
	// adapted for Relevanssi
	if (w2dc_is_relevanssi_search($defaults)) {
		return $order_args;
	}

	if (isset($_REQUEST['order_by']) && $_REQUEST['order_by']) {
		$order_by = $_REQUEST['order_by'];
		$order = w2dc_getValue($_REQUEST, 'order', 'ASC');
	} else {
		if (isset($defaults['order_by']) && $defaults['order_by']) {
			$order_by = $defaults['order_by'];
			$order = w2dc_getValue($defaults, 'order', 'ASC');
		} else {
			$order_by = 'post_date';
			$order = 'DESC';
		}
	}
	
	global $w2dc_radius_params;
	if ($w2dc_radius_params) {
		if (
			(
					(empty($defaults['order_by']) || $defaults['order_by'] == 'distance') ||
					(empty(wcsearch_get_query_string('order_by')) || wcsearch_get_query_string('order_by') == 'distance')
			) &&
			get_option('w2dc_orderby_distance')
		) {
			$order_args['orderby'] = 'post__in';
			$order_args['order'] = 'ASC';
			
			return $order_args;
		}
	}
	
	// search by keyword - do not randomize it
	if (wcsearch_get_query_string("keywords") && ($order_by == 'rand' || $order_by == 'random')) {
		return $order_args;
	}

	$order_args['orderby'] = $order_by;
	$order_args['order'] = $order;

	if ($order_by == 'rand' || $order_by == 'random') {
		if (get_option('w2dc_orderby_sticky_featured')) {
			add_filter('posts_join', 'w2dc_join_levels');
			add_filter('posts_orderby', 'w2dc_orderby_levels', 1);
		}
		$order_args['orderby'] = 'rand';
	}

	if ($order_by == 'title') {
		$order_args['orderby'] = array('title' => $order_args['order'], 'meta_value_num' => 'ASC');
		$order_args['meta_key'] = '_order_date';
		if (get_option('w2dc_orderby_sticky_featured')) {
			add_filter('posts_join', 'w2dc_join_levels');
			add_filter('posts_orderby', 'w2dc_orderby_levels', 1);
		}
	} elseif ($order_by == 'post_date' || get_option('w2dc_orderby_sticky_featured')) {
		// Do not affect levels weights when already ordering by posts IDs
		if (!isset($order_args['orderby']) || $order_args['orderby'] != 'post__in') {
			add_filter('posts_join', 'w2dc_join_levels');
			add_filter('posts_orderby', 'w2dc_orderby_levels', 1);
			add_filter('get_meta_sql', 'w2dc_add_null_values');
		}

		if ($order_by == 'post_date') {
			$w2dc_instance->order_by_date = true;
			// First of all order by _order_date parameter
			$order_args['orderby'] = 'meta_value_num';
			$order_args['meta_key'] = '_order_date';
		} else {
			$order_args = $w2dc_instance->content_fields->getOrderParams($order_args, $defaults);
		}
	} else {
		$order_args = $w2dc_instance->content_fields->getOrderParams($order_args, $defaults);
	}

	return $order_args;
}

/**
 * order listings by title as the second ordering
 */
add_filter('w2dc_order_args', 'w2dc_the_second_order_listings', 102, 3);
function w2dc_the_second_order_listings($order_args = array(), $defaults = array()) {
	if (isset($order_args['orderby'])) {
		if (is_array($order_args['orderby']) && count($order_args['orderby']) == 1) {
			$order_args['orderby'] = array(
					array_shift($order_args['orderby']) => $order_args['order'],
					'title' => 'ASC',
			);
		} elseif (!is_array($order_args['orderby']) && $order_args['orderby'] != 'meta_value_num') {
			$order_args['orderby'] = array(
					$order_args['orderby'] => $order_args['order'],
					'title' => 'ASC',
			);
		}
	}
	
	return $order_args;
}

function w2dc_related_shortcode_args($shortcode_atts) {
	global $w2dc_instance;
	
	if ((isset($shortcode_atts['directories']) && $shortcode_atts['directories'] == 'related') || (isset($shortcode_atts['related_directory']) && $shortcode_atts['related_directory'])) {
		if ($shortcode_controller = w2dc_getShortcodeController()) {
			if ($shortcode_controller->is_home || $shortcode_controller->is_search || $shortcode_controller->is_category || $shortcode_controller->is_location || $shortcode_controller->is_tag) {
				$shortcode_atts['directories'] = $w2dc_instance->current_directory->id;
			} elseif ($shortcode_controller->is_single) {
				if ($shortcode_controller->is_listing) {
					$listing = $shortcode_controller->listing;
				}
				$shortcode_atts['directories'] = $listing->directory->id;
				$shortcode_atts['post__not_in'] = $listing->post->ID;
			}
		}
	}

	if ((isset($shortcode_atts['categories']) && $shortcode_atts['categories'] == 'related') || (isset($shortcode_atts['related_categories']) && $shortcode_atts['related_categories'])) {
		if ($shortcode_controller = w2dc_getShortcodeController()) {
			if ($shortcode_controller->is_category) {
				$shortcode_atts['categories'] = $shortcode_controller->category->term_id;
			} elseif ($shortcode_controller->is_single) {
				if ($shortcode_controller->is_listing) {
					$listing = $shortcode_controller->listing;
				}
				if ($terms = get_the_terms($listing->post->ID, W2DC_CATEGORIES_TAX)) {
					$terms_ids = array();
					foreach ($terms AS $term)
						$terms_ids[] = $term->term_id;
					$shortcode_atts['categories'] = implode(',', $terms_ids);
				}
				$shortcode_atts['post__not_in'] = $listing->post->ID;
			}
		}
	}

	if ((isset($shortcode_atts['locations']) && $shortcode_atts['locations'] == 'related') || (isset($shortcode_atts['related_locations']) && $shortcode_atts['related_locations'])) {
		if ($shortcode_controller = w2dc_getShortcodeController()) {
			if ($shortcode_controller->is_location) {
				$shortcode_atts['locations'] = $shortcode_controller->location->term_id;
			} elseif ($shortcode_controller->is_single) {
				if ($shortcode_controller->is_listing) {
					$listing = $shortcode_controller->listing;
				}
				if ($terms = get_the_terms($listing->post->ID, W2DC_LOCATIONS_TAX)) {
					$terms_ids = array();
					foreach ($terms AS $term)
						$terms_ids[] = $term->term_id;
					$shortcode_atts['locations'] = implode(',', $terms_ids);
				}
				$shortcode_atts['post__not_in'] = $listing->post->ID;
			}
		}
	}

	if (isset($shortcode_atts['related_tags']) && $shortcode_atts['related_tags']) {
		if ($shortcode_controller = w2dc_getShortcodeController()) {
			if ($shortcode_controller->is_tag) {
				$shortcode_atts['tags'] = $shortcode_controller->tag->term_id;
			} elseif ($shortcode_controller->is_single) {
				if ($shortcode_controller->is_listing) {
					$listing = $shortcode_controller->listing;
				}
				if ($terms = get_the_terms($listing->post->ID, W2DC_TAGS_TAX)) {
					$terms_ids = array();
					foreach ($terms AS $term)
						$terms_ids[] = $term->term_id;
					$shortcode_atts['tags'] = implode(',', $terms_ids);
				}
				$shortcode_atts['post__not_in'] = $listing->post->ID;
			}
		}
	}

	if (isset($shortcode_atts['author']) && $shortcode_atts['author'] === 'related') {
		if ($shortcode_controller = w2dc_getShortcodeController()) {
			if ($shortcode_controller->is_single) {
				if ($shortcode_controller->is_listing) {
					$listing = $shortcode_controller->listing;
				}
				$shortcode_atts['author'] = $listing->post->post_author;
				$shortcode_atts['post__not_in'] = $listing->post->ID;
			}
		} elseif ($user_id = get_the_author_meta('ID')) {
			$shortcode_atts['author'] = $user_id;
		}
	}
	
	if (isset($shortcode_atts['related_listing']) && $shortcode_atts['related_listing']) {
		if ($shortcode_controller = w2dc_getShortcodeController()) {
			if ($shortcode_controller->is_single) {
				if ($shortcode_controller->is_listing) {
					$listing = $shortcode_controller->listing;
					$shortcode_atts['post__in'] = $listing->post->ID;
				}
			}
		}
	}

	return $shortcode_atts;
}
add_filter('w2dc_related_shortcode_args', 'w2dc_related_shortcode_args');

function w2dc_set_directory_args($args, $directories_ids = array()) {
	global $w2dc_instance;
	
	if ($w2dc_instance->directories->isMultiDirectory()) {
		if (!isset($args['meta_query'])) {
			$args['meta_query'] = array();
		}
	
		$args['meta_query'] = array_merge($args['meta_query'], array(
				array(
						'key' => '_directory_id',
						'value' => esc_sql($directories_ids),
						'compare' => 'IN',
				)
		));
	}

	return $args;
}


?>