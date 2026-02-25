<?php

add_filter("wcsearch_query_args_validate", "wcsearch_query_args_validate_orderby");
function wcsearch_query_args_validate_orderby($args) {
	
	if (!empty($args['orderby'])) {
		$args['orderby'] = $args['orderby'];
	}
	if (!empty($args['order'])) {
		$args['order'] = $args['order'];
	}
	
	return $args;
}

add_filter("wcsearch_query_args", "wcsearch_query_args_orderby", 10, 2);
function wcsearch_query_args_orderby($q_args, $args) {
	
	if ($args['orderby']) {
		$meta_key = '';
		global $wpdb;
		switch ($args['orderby']) {
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
	} else {
		if (wcsearch_is_woo_active()) {
			$ordering = WC()->query->get_catalog_ordering_args();
			$orderby = $ordering['orderby'];
			$order = $ordering['order'];
		}
	}
	if (!empty($orderby)) {
		$q_args['orderby'] = $orderby;

		if (!empty($order)) {
			$q_args['order'] = $order;
		}
		if (!empty($meta_key)) {
			$q_args['meta_key'] = $meta_key;
		}
	}
	
	return $q_args;
}

?>