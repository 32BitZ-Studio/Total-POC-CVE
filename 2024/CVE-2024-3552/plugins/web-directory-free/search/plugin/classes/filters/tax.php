<?php

add_filter("wcsearch_query_args_validate", "wcsearch_query_args_validate_tax");
function wcsearch_query_args_validate_tax($args) {

	if (!empty($args['taxonomies'])) {
		// the result of wcsearch_get_tax_terms_from_query_string() function
		foreach ($args['taxonomies'] AS $tax_name=>$query_array) {
			if (!empty($query_array['query'])) {
				if (!is_array($query_array['query'])) {
					$terms = explode(',', $query_array['query']);
				} else {
					$terms = array_filter($query_array['query']);
				}
				
				if (count($terms) == 1) {
					$terms_range = explode('-', $terms[0]);
					if (count($terms_range) == 2) {
						$selection_items = wcsearch_wrapper_get_categories(array(
								'taxonomy' => $tax_name,
								'orderby' => 'name',
								'order' => 'ASC',
						));
						
						$min_max_options = array();
						foreach ($selection_items AS $term) {
							$min_max_options[$term->term_id] = $term->term_id;
						}
						
						if ($terms_range[0] === '' || $terms_range[1] === '') {
							if ($terms_range[0] === '') {
								$offset = 0;
							} else {
								$offset = -1;
								foreach ($min_max_options AS $term_id) {
									$offset++;
									if ($term_id == $terms_range[0]) {
										break;
									}
								}
							}
							if ($terms_range[1] === '') {
								$length = count($selection_items);
							} else {
								$length = 0;
								foreach ($min_max_options AS $term_id) {
									$length++;
									if ($length > $offset) {
										if ($term_id == $terms_range[1]) {
											break;
										}
									}
								}
							}
							
							$terms = array_slice(array_flip($min_max_options), $offset, $length);
						} else {
							$terms = array_slice(
									$min_max_options,
									array_search($terms_range[0], array_keys($min_max_options)),
									array_search($terms_range[1], array_keys($min_max_options)) - 
									array_search($terms_range[0], array_keys($min_max_options)) + 1
							);
						}
					}
				}
				
				$args['taxonomies'][$tax_name]['terms'] = $terms;
			}
		}
	}
	
	return $args;
}

add_filter("wcsearch_query_args", "wcsearch_query_args_tax", 10, 2);
function wcsearch_query_args_tax($q_args, $args) {
	
	if (!empty($args['taxonomies'])) {
	
		$select_fields = apply_filters("wcsearch_select_fields", array());
	
		foreach ($args['taxonomies'] AS $tax_name=>$tax_array) {
			if (!empty($tax_array['terms'])) {
				$terms = $tax_array['terms'];
				// default relation
				$relation = 'OR';
				if (!empty($tax_array['relation'])) {
					$relation = $tax_array['relation'];
				}
	
				if (in_array($tax_name, $select_fields)) {
					$content_field = apply_filters("wcsearch_get_select_field", null, $tax_name);
						
					if ($content_field) {
						if ($relation == 'OR') {
							$q_args['meta_query'][] = array(
									'key' => '_content_field_' . $content_field->id,
									'value' => $terms,
									'compare' => 'IN'
							);
						} elseif ($relation == 'AND') {
							foreach ($terms AS $term) {
								$meta_query_array[] = array(
										'key' => '_content_field_' . $content_field->id,
										'value' => $term,
								);
							}
							$q_args['meta_query'] = array(
									'relation' => 'AND',
									$meta_query_array
							);
						}
					}
				} else {
					
					$field = 'term_id';
					foreach ($terms AS $term) {
						if (!is_numeric($term)) {
							$field = 'slug';
							break;
						}
					}
					
					if ($relation == 'OR') {
						$q_args['tax_query'][] = array(
								'taxonomy' => $tax_name,
								'field'    => $field,
								'terms'    => $terms,
						);
					} elseif ($relation == 'AND') {
						foreach ($terms AS $term) {
							$tax_query_array[] = array(
									'taxonomy' => $tax_name,
									'field'    => $field,
									'terms'    => $term,
							);
						}
						$q_args['tax_query'] = array(
								'relation' => 'AND',
								$tax_query_array
						);
					}
				}
			}
		}
	}
	
	return $q_args;
}

add_filter("wcsearch_visible_params", "wcsearch_visible_params_tax", 10, 2);
function wcsearch_visible_params_tax($params, $query_array) {
	
	$_taxonomies = wcsearch_get_all_taxonomies();
	foreach ($_taxonomies AS $tax_name=>$tax_slug) {
		$taxonomies[$tax_name] = wcsearch_get_tax_terms_from_query_string($tax_slug);
	}
	
	if (!empty($taxonomies)) {
		foreach ($taxonomies AS $tax_name=>$query_terms_array) {
			if ($query_terms_array) {
				
				$terms = explode(',', $query_terms_array['query']);
				
				if (count($terms) == 1 && count(explode('-', $terms[0])) == 2) {
					$terms_range = explode('-', $terms[0]);
					if (count($terms_range) == 2) {
						$selection_items = wcsearch_wrapper_get_categories(array(
								'taxonomy' => $tax_name,
								'orderby' => 'name',
								'order' => 'ASC',
						));
							
						$min_max_options = array();
						foreach ($selection_items AS $term) {
							$min_max_options[$term->term_id] = $term->term_id;
						}
							
						if ($terms_range[0] === '') {
							$first = reset($min_max_options);
						} else {
							$first = $terms_range[0];
						}
						if ($terms_range[1] === '') {
							$last = end($min_max_options);
						} else {
							$last = $terms_range[1];
						}
							
						$first = wcsearch_wrapper_get_term($first, $tax_name);
						$last = wcsearch_wrapper_get_term($last, $tax_name);
						
						unset($query_array[$tax_name]);
						$query_string = http_build_query($query_array);
							
						$params[$query_string] = $first->name . ' - ' . $last->name;
					}
				} else {
					$_query_array = $query_array;
					foreach ($terms AS $term_id) {
						if ($term = wcsearch_wrapper_get_term($term_id, $tax_name)) {
							$label = $term->name;
							
							if (count($terms) > 1) {
								$_terms_array = $terms;
								$key = array_search($term_id, $_terms_array);
								unset($_terms_array[$key]);
								$_query_array[$tax_name] = implode(',', $_terms_array);
							} else {
								unset($_query_array[$tax_name]);
							}
							$query_string = http_build_query($_query_array);
								
							$params[$query_string] = $label;
						}
					}
				}
			}
		}
	}
		
	return $params;
}

?>