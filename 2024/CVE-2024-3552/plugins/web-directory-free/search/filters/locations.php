<?php

add_filter("w2dc_query_args_validate", "w2dc_query_args_validate_locations");
function w2dc_query_args_validate_locations($args) {
	
	if (!empty($args['locations'])) {
		if (!is_array($args['locations'])) {
			$args['locations'] = explode(',', $args['locations']);
		}
	}
	
	return $args;
}

add_filter("w2dc_query_args", "w2dc_query_args_locations", 10, 2);
function w2dc_query_args_locations($q_args, $args) {
	
	if (!empty($args['locations'])) {
		
		$include_tax_children = w2dc_getValue($args, 'include_locations_children', false);
		
		$locations = $args['locations'];
		
		$field = 'term_id';
		foreach ($locations AS $location) {
			if (!is_numeric($location)) {
				$field = 'slug';
				break;
			}
		}
		
		$q_args['tax_query'][] = array(
				'taxonomy' => W2DC_LOCATIONS_TAX,
				'terms' => $locations,
				'field' => $field,
				'include_children' => $include_tax_children
		);
	}
	
	return $q_args;
}

?>