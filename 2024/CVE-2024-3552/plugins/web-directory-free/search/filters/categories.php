<?php

add_filter("w2dc_query_args_validate", "w2dc_query_args_validate_categories");
function w2dc_query_args_validate_categories($args) {
	
	if (!empty($args['categories'])) {
		if (!is_array($args['categories'])) {
			$args['categories'] = explode(',', $args['categories']);
		}
	}
	
	return $args;
}

add_filter("w2dc_query_args", "w2dc_query_args_categories", 10, 2);
function w2dc_query_args_categories($q_args, $args) {
	
	if (!empty($args['categories'])) {
		
		$include_tax_children = w2dc_getValue($args, 'include_categories_children', false);
		
		$categories = $args['categories'];
		
		$field = 'term_id';
		foreach ($categories AS $category) {
			if (!is_numeric($category)) {
				$field = 'slug';
				break;
			}
		}
		
		$q_args['tax_query'][] = array(
				'taxonomy' => W2DC_CATEGORIES_TAX,
				'terms' => $categories,
				'field' => $field,
				'include_children' => $include_tax_children
		);
	}
	
	return $q_args;
}

?>