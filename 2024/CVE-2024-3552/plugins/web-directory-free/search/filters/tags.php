<?php

add_filter("w2dc_query_args_validate", "w2dc_query_args_validate_tags");
function w2dc_query_args_validate_tags($args) {
	
	if (!empty($args['tags'])) {
		if (!is_array($args['tags'])) {
			$args['tags'] = explode(',', $args['tags']);
		}
	}
	
	return $args;
}

add_filter("w2dc_query_args", "w2dc_query_args_tags", 10, 2);
function w2dc_query_args_tags($q_args, $args) {
	
	if (!empty($args['tags'])) {
		
		$include_tax_children = w2dc_getValue($args, 'include_tags_children', false);
		
		$tags = $args['tags'];
		
		$field = 'term_id';
		foreach ($tags AS $tag) {
			if (!is_numeric($tag)) {
				$field = 'slug';
				break;
			}
		}
		
		$q_args['tax_query'][] = array(
				'taxonomy' => W2DC_TAGS_TAX,
				'terms' => $tags,
				'field' => $field,
				'include_children' => $include_tax_children
		);
	}
	
	return $q_args;
}

?>