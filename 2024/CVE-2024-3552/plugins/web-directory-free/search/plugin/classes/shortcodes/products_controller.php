<?php 

/*
 * [wcsearch-products] shortcode
 * 
 * 
 */
class wcsearch_products_controller {
	public $args;
	public $query;

	public function init($args = array()) {
		
		$this->args = array_merge(array(
				'columns' => '',
		), $args);
		
		$this->args = apply_filters("wcsearch_query_input_args", $this->args);
		
		$query = new wcsearch_query($this->args);
		$this->query = $query->get_query();
		
		apply_filters('wcsearch_products_controller_construct', $this);
	}
	
	public function woocommerce_pagination_args($args) {
	
		if (!empty($_REQUEST['pagination_base'])) {
			$base = $_REQUEST['pagination_base'];
			
			if (!empty($_REQUEST['query_string'])) {
				$base = str_replace('%#%', 999999999, $base);
				
				$uri_params = wcsearch_get_query_string();
				$base = add_query_arg($uri_params, $base);
				
				$base = str_replace(999999999, '%#%', $base);
			}
			
			$args['base'] = $base;
		}
	
		return $args;
	}
	
	public function woocommerce_default_catalog_orderby($orderby) {
	
		if (!empty($this->args['orderby'])) {
			$orderby = $this->args['orderby'];
		}
	
		return $orderby;
	}

	public function display() {
		
		if (wcsearch_is_woo_active()) {
			
			add_filter("woocommerce_pagination_args", array($this, "woocommerce_pagination_args"));
			add_filter("woocommerce_default_catalog_orderby", array($this, "woocommerce_default_catalog_orderby"), 11);
			
			wc_set_loop_prop('current_page', $this->args['page']);
			wc_set_loop_prop('is_paginated', true);
			wc_set_loop_prop('page_template', get_page_template_slug());
			wc_set_loop_prop('per_page', $this->args['posts_per_page']);
			wc_set_loop_prop('total', $this->query->found_posts);
			wc_set_loop_prop('total_pages', $this->query->max_num_pages);
			wc_set_loop_prop('is_filtered', true);
			if (!empty($this->args['columns'])) {
				wc_set_loop_prop('columns', $this->args['columns']);
			}
			
			ob_start();
			$args = array(
					'total'    => wc_get_loop_prop('total'),
					'per_page' => wc_get_loop_prop('per_page'),
					'current'  => wc_get_loop_prop('current_page'),
			);
				
			wc_get_template('loop/result-count.php', $args);
			$result_count = ob_get_clean();
			
			$total = wc_get_loop_prop('total');
			
			ob_start();
			
			if ($this->query->have_posts()) {
				do_action('woocommerce_before_shop_loop');
				woocommerce_product_loop_start();
				while ($this->query->have_posts()) {
					$this->query->the_post();
					
					wc_get_template_part('content', 'product');
				}
				wp_reset_postdata();
				woocommerce_product_loop_end();
				do_action('woocommerce_after_shop_loop');
			} else {
				do_action('woocommerce_no_products_found');
			}
			
			$products_output = ob_get_clean();
			
			if (wp_doing_ajax()) {
				return array(
						'products' => $products_output,
						'result_count' => $result_count,
						'total' => $total,
						'query' => $this->query->request,
				);
			} else {
				return $products_output;
			}
		}
	}
}

?>