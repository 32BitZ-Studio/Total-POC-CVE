<?php

add_filter("wcsearch_query_args_validate", "wcsearch_query_args_validate_price");
function wcsearch_query_args_validate_price($args) {
	if (isset($args['price'])) {
		$min_max_options_range = explode('-', $args['price']);
		if (count($min_max_options_range) == 2) {
			$args['price'] = $min_max_options_range;
		} elseif (count($min_max_options_range) == 1) {
			$args['price'] = $min_max_options_range[0];
		}
	}
	
	return $args;
}

add_filter("wcsearch_query_args", "wcsearch_query_args_price", 10, 2);
function wcsearch_query_args_price($q_args, $args) {
	
	if (!empty($args['price'])) {
		if (is_array($args['price'])) {
			$price = $args['price'];
			if (is_array($price) && count(array_filter($price)) == 2) {
				$q_args['meta_query'] = array(
						array(
								'key' => '_price',
								'value' => $args['price'],
								'compare' => 'BETWEEN',
								'type' => 'DECIMAL',
						)
				);
			} elseif (count(array_filter($price)) == 1) {
				if (is_numeric($price[0])) {
					$min_number = $price[0];
						
					$q_args['meta_query'][] = array(
							'key' => '_price',
							'value' => $min_number,
							'compare' => '>=',
							'type' => 'DECIMAL',
					);
				} elseif (is_numeric($price[1])) {
					$max_number = $price[1];
						
					$q_args['meta_query'][] = array(
							'key' => '_price',
							'value' => $max_number,
							'compare' => '<=',
							'type' => 'DECIMAL',
					);
				}
					
				$q_args['meta_query'][] = array(
						'relation' => 'AND',
						array(
								'key' => '_price',
								'compare' => '>=',
								'value' => '0',
								'type' => 'DECIMAL',
						),
				);
			}
		} else {
			$price = $args['price'];
				
			$q_args['meta_query'][] = array(
					'key' => '_price',
					'value' => $price,
					'type' => 'DECIMAL',
			);
		}
	}
	
	return $q_args;
}

add_filter("wcsearch_visible_params", "wcsearch_visible_params_price", 10, 2);
function wcsearch_visible_params_price($params, $query_array) {
	
	if (!empty($query_array['price'])) {
		$min_max_options_range = explode('-', $query_array['price']);
		if (count($min_max_options_range) == 2) {
			
			$label = __("Price", "WCSEARCH") . ' ';

			if ($min_max_options_range[0] !== '') {
				$label .= esc_html__("from", "WCSEARCH");
				$label .= ' ';
				if (is_numeric($min_max_options_range[0])) {
					$label .= wc_price($min_max_options_range[0], array('decimals' => 0));
				} else {
					$label .= $min_max_options_range[0];
				}
			}
			if ($min_max_options_range[0] !== '' && $min_max_options_range[1] !== '') {
				$label .= ' ';
			}
			if ($min_max_options_range[1] !== '') {
				$label .= esc_html__("to", "WCSEARCH");
				$label .= ' ';
				if (is_numeric($min_max_options_range[1])) {
					$label .= wc_price($min_max_options_range[1], array('decimals' => 0));
				} else {
					$label .= $min_max_options_range[1];
				}
			}
		
			unset($query_array['price']);
			$query_string = http_build_query($query_array);
			
			$params[$query_string] = $label;
		}  elseif (isset($min_max_options_range[0])) {
			
			$label = __("Price", "WCSEARCH") . ' ' . $min_max_options_range[0];
			
			unset($query_array['price']);
			$query_string = http_build_query($query_array);
				
			$params[$query_string] = $label;
		}
	}
		
	return $params;
}

?>