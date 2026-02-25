<?php

add_filter("wcsearch_query_args", "wcsearch_query_args_keywords", 10, 2);
function wcsearch_query_args_keywords($q_args, $args) {
	if (!empty($args['keywords'])) {
		$q_args['s'] = urldecode($args['keywords']);
	}
	
	return $q_args;
}

add_filter("wcsearch_visible_params", "wcsearch_visible_params_keywords", 10, 2);
function wcsearch_visible_params_keywords($params, $query_array) {
	if (!empty($query_array['keywords'])) {
		$label = esc_html(urldecode($query_array['keywords']));
		
		unset($query_array['keywords']);
		$query_string = http_build_query($query_array);
		
		$params[$query_string] = $label;
	}
		
	return $params;
}

?>