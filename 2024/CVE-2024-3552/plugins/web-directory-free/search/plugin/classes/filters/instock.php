<?php

add_filter("wcsearch_query_args_validate", "wcsearch_query_args_validate_instock");
function wcsearch_query_args_validate_instock($args) {
	if (!empty($args['instock'])) {
		$args['instock'] = 1;
	}
	
	return $args;
}

add_filter("wcsearch_query_args", "wcsearch_query_args_instock", 10, 2);
function wcsearch_query_args_instock($q_args, $args) {
	if (!empty($args['instock'])) {
		$q_args['meta_query'][] = array(
				'relation' => 'OR',
				array(
						'key'     => '_stock_status',
						'value'   => 'outofstock',
						'compare' => '!=',
				),
				array(
						'key'     => '_stock_status',
						'compare' => 'NOT EXISTS',
				)
		);
	}
	
	return $q_args;
}

add_filter("wcsearch_visible_params", "wcsearch_visible_params_instock", 10, 2);
function wcsearch_visible_params_instock($params, $query_array) {
	if (!empty($query_array['instock'])) {
		$label = esc_html__("In stock", "WCSEARCH");
		
		unset($query_array['instock']);
		$query_string = http_build_query($query_array);
		
		$params[$query_string] = $label;
	}
		
	return $params;
}

?>