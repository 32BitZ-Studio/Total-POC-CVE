<?php

add_filter("wcsearch_query_args_validate", "wcsearch_query_args_validate_ratings");
function wcsearch_query_args_validate_ratings($args) {
	
	if (!empty($args['ratings']) && !is_array($args['ratings'])) {
		$args['ratings'] = explode(',', urldecode($args['ratings']));
	}
	
	return $args;
}

add_filter("wcsearch_query_args", "wcsearch_query_args_ratings", 10, 2);
function wcsearch_query_args_ratings($q_args, $args) {
	if (!empty($args['ratings'])) {
		$ratings_meta_query = array('relation' => 'OR');
		foreach ($args['ratings'] AS $rating) {
			$ratings_meta_query[] = array(
					'key' => '_wc_average_rating',
					'value' => array((int)$rating, (int)$rating + 1 - 0.001),
					'type' => 'DECIMAL(3, 2)',
					'compare' => 'BETWEEN',
			);
		}
		$q_args['meta_query'][] = $ratings_meta_query;
	}
	
	return $q_args;
}

add_filter("wcsearch_visible_params", "wcsearch_visible_params_ratings", 10, 2);
function wcsearch_visible_params_ratings($params, $query_array) {
	if (!empty($query_array['ratings'])) {
		$ratings_array = explode(',', urldecode($query_array['ratings']));
		
		for ($i = 1; $i <= 5; $i++) {
			if (in_array($i, $ratings_array)) {
				$label = $i;
				$label .= ' ';
				$label .= _n(esc_html__("star", "WCSEARCH"), esc_html__("stars", "WCSEARCH"), $i);
				
				if (count($ratings_array) > 1) {
					$_ratings_array = $ratings_array;
					$key = array_search($i, $_ratings_array);
					unset($_ratings_array[$key]);
					$query_array['ratings'] = implode(',', $_ratings_array);
				} else {
					unset($query_array['ratings']);
				}
				$query_string = http_build_query($query_array);
				
				$params[$query_string] = $label;
			}
		}
	}
		
	return $params;
}

?>