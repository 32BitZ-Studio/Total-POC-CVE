<?php

add_filter("wcsearch_query_args_validate", "wcsearch_query_args_validate_featured");
function wcsearch_query_args_validate_featured($args) {
	if (!empty($args['featured'])) {
		$args['featured'] = 1;
	}
	
	return $args;
}

add_filter("wcsearch_query_args", "wcsearch_query_args_featured", 10, 2);
function wcsearch_query_args_featured($q_args, $args) {
	if (!empty($args['featured'])) {
		$q_args['tax_query'][] = array(
				'taxonomy' => 'product_visibility',
				'field'    => 'name',
				'terms'    => 'featured',
				'operator' => 'IN',
		);
	}
	
	return $q_args;
}

add_filter("wcsearch_visible_params", "wcsearch_visible_params_featured", 10, 2);
function wcsearch_visible_params_featured($params, $query_array) {
	if (!empty($query_array['featured'])) {
		$label = esc_html__("Featured", "WCSEARCH");
		
		unset($query_array['featured']);
		$query_string = http_build_query($query_array);
		
		$params[$query_string] = $label;
	}
		
	return $params;
}

?>