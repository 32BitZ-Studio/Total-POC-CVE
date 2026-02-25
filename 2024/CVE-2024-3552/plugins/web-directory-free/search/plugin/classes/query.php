<?php

class wcsearch_query {
	public $query;
	public $args;
	public $q_args;

	public function __construct($args) {

		$this->args = apply_filters("wcsearch_query_args_validate", $args);

		$this->q_args = array(
				'post_type' => array('product'),
				'post_status' => 'publish',
				'posts_per_page' => $this->args['posts_per_page'],
				'tax_query' => array(
						array(
								'taxonomy' => 'product_visibility',
								'field'    => 'name',
								'terms'    => 'exclude-from-search',
								'operator' => 'NOT IN',
						)
				),
		);

		$this->q_args = apply_filters("wcsearch_query_args", $this->q_args, $this->args);
		
		add_action('pre_get_posts', array($this, 'pre_get_posts'));

		$this->query = new WP_Query($this->q_args);
		//var_dump($this->query->request);
		
		remove_action('pre_get_posts', array($this, 'pre_get_posts'));
	}

	public function pre_get_posts($q) {
		
		do_action("woocommerce_product_query", $q);
	}
	
	public function get_query() {
		return $this->query;
	}
}

?>