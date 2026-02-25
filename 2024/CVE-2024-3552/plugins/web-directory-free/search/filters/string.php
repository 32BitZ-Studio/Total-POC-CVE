<?php

add_filter("w2dc_query_args", "w2dc_query_args_string", 10, 2);
function w2dc_query_args_string($q_args, $args) {
	
	$search_fields = w2dc_get_search_fields();
	foreach ($search_fields AS $search_field) {
		if (in_array($search_field->content_field->type, array('string', 'textarea', 'phone'))) {
			$slug = $search_field->content_field->slug;
			
			// back compatibility
			if (!isset($args[$slug]) && isset($args['field_' . $slug])) {
				$slug = 'field_' . $slug;
			}
			
			if (!empty($args[$slug])) {
				$q_args['meta_query'][] = array(
						'key' => '_content_field_' . $search_field->content_field->id,
						'value' => stripslashes(urldecode($args[$slug])),
						'compare' => 'LIKE'
				);
			}
		}
	}
	
	return $q_args;
}

add_filter("w2dc_visible_params", "w2dc_visible_params_string", 10, 2);
function w2dc_visible_params_string($params, $query_array) {
	
	$search_fields = w2dc_get_search_fields();
	foreach ($search_fields AS $search_field) {
		if (in_array($search_field->content_field->type, array('string', 'textarea', 'phone'))) {
			$slug = $search_field->content_field->slug;
			
			if (!empty($query_array[$slug])) {
				$label = esc_html(urldecode($query_array[$slug]));
				
				unset($query_array[$slug]);
				$query_string = http_build_query($query_array);
				
				$params[$query_string] = $label;
			}
		}
	}
		
	return $params;
}

?>