<?php 

class wcsearch_ajax_controller {

	public function __construct() {
		add_action('wp_ajax_wcsearch_keywords_search', array($this, 'keywords_search'));
		add_action('wp_ajax_nopriv_wcsearch_keywords_search', array($this, 'keywords_search'));
		
		add_action('wp_ajax_wcsearch_tax_hierarhical_dropdowns_hook', array($this, 'tax_hierarhical_dropdowns_hook'));
		add_action('wp_ajax_nopriv_wcsearch_tax_hierarhical_dropdowns_hook', array($this, 'tax_hierarhical_dropdowns_hook'));
		
		add_action('wp_ajax_wcsearch_search_request', array($this, 'search_request'));
		add_action('wp_ajax_nopriv_wcsearch_search_request', array($this, 'search_request'));
		
		add_action('wp_ajax_wcsearch_recount_request', array($this, 'recount_request'));
		add_action('wp_ajax_nopriv_wcsearch_recount_request', array($this, 'recount_request'));
		
		add_action('wp_ajax_wcsearch_get_tax_options', array($this, 'get_tax_options'));
		add_action('wp_ajax_nopriv_wcsearch_get_tax_options', array($this, 'get_tax_options'));
		
		add_action('wp_ajax_wcsearch_get_search_model', array($this, 'get_search_model'));
		add_action('wp_ajax_nopriv_wcsearch_get_search_model', array($this, 'get_search_model'));
	}
	
	public function get_search_model() {
	
		$search_form_model = new wcsearch_search_form_model_field;
		$html = $search_form_model->getFieldModel();
	
		echo json_encode(array("html" => $html));
	
		die();
	}
	
	public function keywords_search() {
		
		if (wcsearch_is_woo_active()) {
			$term = wcsearch_getValue($_POST, 'term');
			$orderby = wcsearch_getValue($_POST, 'orderby', 'relevance');
			$order = wcsearch_getValue($_POST, 'order', 'ASC');
			$do_links = wcsearch_getValue($_POST, 'do_links', true);
			$do_links_blank = wcsearch_getValue($_POST, 'do_links_blank', 'blank');
			
			$args = array(
					'post_type' => 'product',
					'post_status' => 'publish',
					'posts_per_page' => apply_filters('wcsearch_ajax_search_products_number', 10),
					's' => $term
			);
			
			if ($orderby == 'price') {
				global $wpdb;
				$args['orderby'] = "meta_value_num {$wpdb->posts}.ID";
				$args['order'] = $order;
				$args['meta_key'] = '_price';
			}
			
			$query = new WP_Query($args);
				
			// disable hyphens to dashes conversion
			remove_filter('the_title', 'wptexturize');
			
			$listings_json = array();
			while ($query->have_posts()) {
				$query->the_post();
			
				$product = wc_get_product(get_post());
				$name = $product->get_name();
				$permalink = $product->get_permalink();
				$description = $product->get_description();
				$image = wp_get_attachment_image_url($product->get_image_id(), 'woocommerce_thumbnail');
				
				if ($do_links) {
					$nofollow = true;
					
					if ($do_links_blank == 'blank') {
						$target = apply_filters('wcsearch_listing_title_search_target', 'target="_blank"');
					}  elseif ($do_links_blank == 'self') {
						$target = apply_filters('wcsearch_listing_title_search_target', '');
					}
					
					$title = '<strong><a href="' . esc_url($permalink) . '" ' . $target . ' title="' . esc_attr__("open product", "WCSEARCH") . '" ' . (($nofollow) ? 'rel="nofollow"' : '') . '>' . esc_html($name) . '</a></strong>';
				} else {
					$title = '<strong>' . esc_html($name) . '</strong>';
				}
	
				$listing_json_field = array();
				$listing_json_field['title'] = $title;
				$listing_json_field['name'] = htmlspecialchars_decode($name); // htmlspecialchars_decode() needed due to &amp; symbols
				$listing_json_field['url'] = $permalink;
				$listing_json_field['icon'] = $image;
				$listing_json_field['sublabel'] = wc_price($product->get_price());
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
	
	public function tax_hierarhical_dropdowns_hook() {
		$tax = wcsearch_getValue($_POST, 'tax');
		$parent = wcsearch_getValue($_POST, 'parentid');
		$uID = wcsearch_getValue($_POST, 'uID');
		$placeholders = wcsearch_getValue($_POST, 'placeholders');
		$depth_level = wcsearch_getValue($_POST, 'depth_level');
		$orderby = wcsearch_getValue($_POST, 'orderby');
		$order = wcsearch_getValue($_POST, 'order');
		$hide_empty = wcsearch_getValue($_POST, 'hide_empty');
		
		$exact_terms = wcsearch_getValue($_POST, 'exact_terms');
		$exact_terms = array_filter(explode(",", $exact_terms));
		
		$args = array(
				'uID' => $uID,
				'placeholders' => $placeholders,
				'depth_level' => $depth_level,
				'tax' => $tax,
				'parent' => $parent,
				'orderby' => $orderby,
				'order' => $order,
				'exact_terms' => $exact_terms,
				'hide_empty' => $hide_empty,
		);
		
		wcsearch_heirarhical_dropdowns_menu_init($args);
		
		die();
	}
	
	public function search_request() {
		
		$post_params = array_filter($_POST, function($k) {
			return in_array($k, wcsearch_get_allowed_search_params());
		}, ARRAY_FILTER_USE_KEY);
		
		$products_controller = new wcsearch_products_controller();
		$products_controller->init($post_params);
		$products_output = $products_controller->display();
		
		$json = json_encode($products_output);
		echo $json;
		
		die();
	}
	
	public function recount_request() {
		
		$counter_tags = array();
		
		if ($counters = wcsearch_getValue($_REQUEST, 'counters')) {
			if (is_array($counters)) {
				
				$used_by = wcsearch_getValue($_REQUEST, 'used_by');
				
				$counters = array_unique($counters, SORT_REGULAR);
				
				foreach ($counters AS $counter) {
					if (isset($counter['termid'])) {
						$counter_term_id = $counter['termid'];
						$counter_term_tax = $counter['tax'];
						$counter_term_mode = wcsearch_getValue($counter, 'termmode', 'checkboxes');
						$counter_number = false;
						$counter_tags[] = array('counter_term_id' => $counter_term_id, 'counter_term_tax' => $counter_term_tax, 'counter_item' => wcsearch_get_count(array('term' => wcsearch_wrapper_get_term($counter_term_id, $counter_term_tax), 'mode' => $counter_term_mode), $counter_number), 'counter_number' => $counter_number, 'used_by' => $used_by);
					} elseif (isset($counter['price'])) {
						$counter_price = $counter['price'];
						$counter_tags[] = array('counter_price' => $counter_price, 'counter_item' => wcsearch_get_count(array('price' => $counter_price, 'used_by' => $used_by)));
					} elseif (isset($counter['option'])) {
						$counter_option = $counter['option'];
						$counter_tags[] = array('counter_option' => $counter_option, 'counter_item' => wcsearch_get_count(array('option' => $counter_option, 'used_by' => $used_by)));
					} elseif (isset($counter['hours'])) {
						$counter_hours = $counter['hours'];
						$counter_tags[] = array('counter_hours' => $counter_hours, 'counter_item' => wcsearch_get_count(array('hours' => $counter_hours, 'used_by' => $used_by)));
					} elseif (isset($counter['ratings'])) {
						$counter_ratings = $counter['ratings'];
						$counter_tags[] = array('counter_ratings' => $counter_ratings, 'counter_item' => wcsearch_get_count(array('ratings' => $counter_ratings, 'used_by' => $used_by)));
					}
				}
			}
		}
		
		$json = json_encode(array('counters' => $counter_tags));
		echo $json;
		
		die();
	}
	
	public function get_tax_options() {
		
		$html = '';
		
		if ($tax = wcsearch_getValue($_REQUEST, 'tax')) {
			
			$field_name = wcsearch_getValue($_REQUEST, 'field_name');
			$field_class = wcsearch_getValue($_REQUEST, 'field_class');
			
			if ($items = wcsearch_getValue($_REQUEST, 'items', array())) {
				$items = explode(',', $items);
			} else {
				$items = array();
			}
			
			// "categories" instead of "w2dc-category",
			// "locations" instead of "w2dc-location",
			// "tags" instead of "w2dc-tag"
			$taxes = wcsearch_get_all_taxonomies();
			foreach ($taxes AS $tax_slug=>$tax_synonym) {
				if ($tax == $tax_synonym) {
					$tax = $tax_slug;
					break;
				}
			}
			
			$categories_options = array(
					'taxonomy' => $tax,
					'parent' => 0,
			);
			
			$terms = wcsearch_wrapper_get_categories($categories_options);
			
			$html = '<select name="' . $field_name . '[]" class="' . $field_class . ' wcsearch-search-model-tax-terms wcsearch-search-model-options-input" multiple="multiple">';
			foreach ($terms AS $term) {
				if (in_array($term->term_id, $items) || in_array($term->slug, $items)) {
					$selected = "selected='selected'";
				} else {
					$selected = '';
				}
				$html .= '<option value="' . esc_attr($term->term_id) . '" ' . $selected . '>' . $term->name . '</option>';
				
				$html .= $this->_get_tax_options($term, 1);
			}
			
			$html .= '<select>';
		}
		
		$json = json_encode(array('html' => $html));
		echo $json;
		
		die();
	}
	
	public function _get_tax_options($parent_term, $level) {
		
		if ($items = wcsearch_getValue($_REQUEST, 'items', array())) {
			$items = explode(',', $items);
		} else {
			$items = array();
		}
		
		$tax = $parent_term->taxonomy;
		// "categories" instead of "w2dc-category",
		// "locations" instead of "w2dc-location",
		// "tags" instead of "w2dc-tag"
		$taxes = wcsearch_get_all_taxonomies();
		foreach ($taxes AS $tax_slug=>$tax_synonym) {
			if ($tax == $tax_synonym) {
				$tax = $tax_slug;
				break;
			}
		}
		
		$categories_options = array(
				'taxonomy' => $tax,
				'parent' => $parent_term->term_id,
		);
			
		$terms = wcsearch_wrapper_get_categories($categories_options);
		
		$html = '';
		foreach ($terms AS $term) {
			if (in_array($term->term_id, $items) || in_array($term->slug, $items)) {
				$selected = "selected='selected'";
			} else {
				$selected = '';
			}
			$html .= '<option value="' . esc_attr($term->term_id) . '" ' . $selected . '>' . str_repeat("- ", $level) . $term->name . '</option>';
		
			$html .= $this->_get_tax_options($term, $level+1);
		}
		
		return $html;
	}
}
?>