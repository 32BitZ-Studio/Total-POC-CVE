<?php

add_filter("w2dc_query_args_validate", "w2dc_query_args_validate_number");
function w2dc_query_args_validate_number($args) {
	
	$search_fields = w2dc_get_search_fields();
	foreach ($search_fields AS $search_field) {
		if (in_array($search_field->content_field->type, array('price', 'number'))) {
			$slug = $search_field->content_field->slug;
			
			// back compatibility
			if (!isset($args[$slug]) && isset($args['field_' . $slug])) {
				$slug = 'field_' . $slug;
			}
			
			if (isset($args[$slug])) {
				$min_max_options_range = explode('-', $args[$slug]);
				if (count($min_max_options_range) == 2) {
					$args[$slug] = $min_max_options_range;
				} elseif (count($min_max_options_range) == 1) {
					$args[$slug] = $min_max_options_range[0];
				}
			}
		}
	}
	
	return $args;
}

add_filter("w2dc_query_args", "w2dc_query_args_number", 10, 2);
function w2dc_query_args_number($q_args, $args) {
	
	$search_fields = w2dc_get_search_fields();
	foreach ($search_fields AS $search_field) {
		if (in_array($search_field->content_field->type, array('price', 'number'))) {
			$slug = $search_field->content_field->slug;
			
			if (!empty($args[$slug])) {
				if (is_array($args[$slug])) {
					$number = $args[$slug];
					if (is_array($number) && count(array_filter($number)) == 2) {
						$q_args['meta_query'][] = array(
										'key' => '_content_field_' . $search_field->content_field->id,
										'value' => $args[$slug],
										'compare' => 'BETWEEN',
										'type' => 'DECIMAL',
						);
					} elseif (count(array_filter($number)) == 1) {
						if (is_numeric($number[0])) {
							$min_number = $number[0];
				
							$q_args['meta_query'][] = array(
											'key' => '_content_field_' . $search_field->content_field->id,
											'value' => $min_number,
											'compare' => '>=',
											'type' => 'DECIMAL',
							);
						} elseif (is_numeric($number[1])) {
							$max_number = $number[1];
				
							$q_args['meta_query'][] = array(
											'key' => '_content_field_' . $search_field->content_field->id,
											'value' => $max_number,
											'compare' => '<=',
											'type' => 'DECIMAL',
							);
						}
						
						$q_args['meta_query'][] = array(
								'relation' => 'AND',
								array(
										'key' => '_content_field_' . $search_field->content_field->id,
										'compare' => '>=',
										'value' => '0',
										'type' => 'DECIMAL',
								),
						);
					}
				} else {
					$number = $args[$slug];
					
					$q_args['meta_query'][] = array(
							'key' => '_content_field_' . $search_field->content_field->id,
							'value' => $args[$slug],
							'type' => 'DECIMAL',
					);
				}
			}
		}
	}
	
	return $q_args;
}

add_filter("w2dc_visible_params", "w2dc_visible_params_number", 10, 2);
function w2dc_visible_params_number($params, $query_array) {
	
	$search_fields = w2dc_get_search_fields();
	foreach ($search_fields AS $search_field) {
		if (in_array($search_field->content_field->type, array('price', 'number'))) {
			$slug = $search_field->content_field->slug;
			
			if (!empty($query_array[$slug])) {
				$min_max_options_range = explode('-', $query_array[$slug]);
				if (count($min_max_options_range) == 2) {
					
					$label = $search_field->content_field->name . ' ';
		
					if ($min_max_options_range[0] !== '') {
						$label .= esc_html__("from", "W2DC");
						$label .= ' ';
						if (is_numeric($min_max_options_range[0])) {
							$label .= $search_field->content_field->formatValue($min_max_options_range[0]);
						} else {
							$label .= $min_max_options_range[0];
						}
					}
					if ($min_max_options_range[0] !== '' && $min_max_options_range[1] !== '') {
						$label .= ' ';
					}
					if ($min_max_options_range[1] !== '') {
						$label .= esc_html__("to", "W2DC");
						$label .= ' ';
						if (is_numeric($min_max_options_range[1])) {
							$label .= $search_field->content_field->formatValue($min_max_options_range[1]);
						} else {
							$label .= $min_max_options_range[1];
						}
					}
				
					unset($query_array[$slug]);
					$query_string = http_build_query($query_array);
					
					$params[$query_string] = $label;
				} elseif (isset($min_max_options_range[0])) {
					
					$label = $search_field->content_field->name . ' ' . $min_max_options_range[0];
					
					unset($query_array[$slug]);
					$query_string = http_build_query($query_array);
						
					$params[$query_string] = $label;
				}
			}
		}
	}
		
	return $params;
}

?>