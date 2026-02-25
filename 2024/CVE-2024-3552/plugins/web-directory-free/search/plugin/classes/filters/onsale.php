<?php

add_filter("wcsearch_query_args_validate", "wcsearch_query_args_validate_onsale");
function wcsearch_query_args_validate_onsale($args) {
	if (!empty($args['onsale'])) {
		$args['onsale'] = 1;
	}
	
	return $args;
}

add_filter("wcsearch_query_args", "wcsearch_query_args_onsale", 10, 2);
function wcsearch_query_args_onsale($q_args, $args) {
	if (!empty($args['onsale'])) {
		if (wcsearch_is_woo_active()) {
			$q_args = array_merge($q_args, array('post__in' => wc_get_product_ids_on_sale()));
		}
	}
	
	return $q_args;
}

add_filter("wcsearch_visible_params", "wcsearch_visible_params_onsale", 10, 2);
function wcsearch_visible_params_onsale($params, $query_array) {
	if (!empty($query_array['onsale'])) {
		$label = esc_html__("On sale", "WCSEARCH");
		
		unset($query_array['onsale']);
		$query_string = http_build_query($query_array);
		
		$params[$query_string] = $label;
	}
		
	return $params;
}

?>