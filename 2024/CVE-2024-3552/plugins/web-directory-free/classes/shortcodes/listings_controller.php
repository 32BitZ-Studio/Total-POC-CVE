<?php 

/**
 *  [webdirectory-listings] shortcode
 *
 *
 */
class w2dc_listings_controller extends w2dc_frontend_controller {
	
	public $custom_home = false;

	public function init($args = array()) {
		global $w2dc_instance;
		
		parent::init($args);
	
		if (get_query_var('page')) {
			$paged = get_query_var('page');
		} elseif (get_query_var('paged')) {
			$paged = get_query_var('paged');
		} else {
			$paged = 1;
		}
		
		$shortcode_atts = array_merge(array(
				'how_to_load' => 'full', // full, for_map, for_ajax_map
				'perpage' => 10,
				'onepage' => 0,
				'sticky_featured' => 0,
				'order_by' => 'post_date',
				'order' => 'DESC',
				'hide_order' => 0,
				'hide_count' => 0,
				'hide_paginator' => 0,
				'show_views_switcher' => 1,
				'listings_view_type' => 'list',
				'listings_view_grid_columns' => 2,
				'listing_thumb_width' => (int)get_option('w2dc_listing_thumb_width'),
				'wrap_logo_list_view' => 0,
				'logo_animation_effect' => (int)get_option('w2dc_logo_animation_effect'),
				'hide_content' => 0,
				'rating_stars' => 1,
				'summary_on_logo_hover' => 0,
				'carousel' => 0,
				'carousel_show_slides' => 4,
				'carousel_slide_width' => 250,
				'carousel_slide_height' => 300,
				'carousel_full_width' => 0,
				'author' => 0,
				'paged' => $paged,
				'ajax_initial_load' => 0, // 1 - loads listings after initialization, map can follow this when using uid
				'include_categories_children' => 1,
				'categories' => '',
				'locations' => '',
				'tags' => '',
				'levels' => '',
				'related_directory' => 0,
				'related_categories' => 0,
				'related_locations' => 0,
				'related_tags' => 0,
				'scrolling_paginator' => 0,
				'grid_view_logo_ratio' => get_option('w2dc_grid_view_logo_ratio'), // 100 (1:1), 75 (4:3), 56.25 (16:9), 50 (2:1)
				'ratings' => '',
				'hide_listings' => 0, // hide listings on initial load
				'template' => 'frontend/listings_block.tpl.php',
				'uid' => null,
				'start_listings' => array(),
				'include_get_params' => 1,
		), $args);
		$this->args = apply_filters('w2dc_related_shortcode_args', $shortcode_atts, $args);

		if (!empty($this->args['page_url']) && wcsearch_get_query_string()) {
			$this->base_url = add_query_arg(wcsearch_get_query_string(), $this->args['page_url']);
		} elseif (!empty($this->args['page_url'])) {
			$this->base_url = $this->args['page_url'];
		} else {
			global $wp;
				
			$this->base_url = add_query_arg(wcsearch_get_query_string(), home_url($wp->request));
		}
		
		$this->page_url = get_permalink(get_the_ID());
		
		global $w2dc_global_base_url;
		if (!$w2dc_global_base_url) {
			$w2dc_global_base_url = $this->base_url;
			add_filter('get_pagenum_link', array($this, 'getPagenumLink'));
		}

		$this->template = $this->args['template'];
		
		if ($this->args['carousel']) {
			$this->template = 'frontend/listings_carousel.tpl.php';
		}
		
		// display these listings by default, then directory searches as usual
		if (!empty($this->args['start_listings'])) {
			$this->args['post__in'] = $this->args['start_listings'];
		}
		
		if (!empty($this->args['hide_listings'])) {
			$this->do_initial_load = false;
			
			// listings will not load, query will not be processed,
			// make 'hide_listings' = 0 so AJAX can be called later
			$this->args['hide_listings'] = 0;
			
			return false;
		}
		
		// 'num' parameter from the maps controller
		if (empty($args["perpage"]) && !empty($args['num'])) {
			$this->args['perpage'] = $this->args['num'];
		}
		unset($this->args['num']);

		if (empty($this->args['ajax_initial_load']) || !empty($this->args['from_set_ajax'])) {
			$q_args = apply_filters("w2dc_query_input_args", $this->args);
			
			$query = new w2dc_search_query($q_args);
			$this->query = $query->get_query();
			//var_dump($this->query->request);
			
			$this->processQuery();
		} else {
			$this->do_initial_load = false;
		}
		
		$this->init_end();
	}
}

?>