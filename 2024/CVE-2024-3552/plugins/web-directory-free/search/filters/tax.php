<?php

add_filter("w2dc_query_args_validate", "w2dc_query_args_validate_tax");
function w2dc_query_args_validate_tax($args) {

	// the result of wcsearch_get_tax_terms_from_query_string() function
	if (!empty($args['taxonomies'])) {
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
								'pad_counts' => true,
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

add_filter("w2dc_query_args", "w2dc_query_args_tax", 10, 2);
function w2dc_query_args_tax($q_args, $args) {
	
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
					
					if ($content_field && $content_field->on_search_form) {
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
					
					$include_tax_children = w2dc_getValue($args, 'include_categories_children', true);
					
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
								'include_children' => $include_tax_children,
						);
					} elseif ($relation == 'AND') {
						foreach ($terms AS $term) {
							$tax_query_array[] = array(
									'taxonomy' => $tax_name,
									'field'    => $field,
									'terms'    => $term,
									'include_children' => $include_tax_children,
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

add_filter("w2dc_visible_params", "w2dc_visible_params_tax", 10, 2);
function w2dc_visible_params_tax($params, $query_array) {
	
	$taxonomy_names = w2dc_get_taxonomies();
	
	$select_fields = apply_filters("wcsearch_select_fields", array());
	
	$_taxonomies = w2dc_get_taxonomies();
	foreach ($_taxonomies AS $tax_name=>$tax_slug) {
		$taxonomies_args[$tax_name] = wcsearch_get_tax_terms_from_query_string($tax_slug);
	}
	
	if (!empty($taxonomies_args)) {
		foreach ($taxonomies_args AS $tax_name=>$query_terms_array) {
			if ($query_terms_array) {
				
				if (in_array($tax_name, $select_fields)) {
					$content_field = apply_filters("wcsearch_get_select_field", null, $tax_name);
					
					// content field does not affect on search
					if ($content_field && !$content_field->on_search_form) {
						continue;
					}
				}
				
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
						
						unset($query_array[$taxonomy_names[$tax_name]]);
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
								$_query_array[$taxonomy_names[$tax_name]] = implode(',', $_terms_array);
								
							} else {
								unset($_query_array[$taxonomy_names[$tax_name]]);
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