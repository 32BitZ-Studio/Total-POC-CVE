<?php

add_filter("w2dc_query_args_validate", "w2dc_query_args_validate_date");
function w2dc_query_args_validate_date($args) {
	
	$search_fields = w2dc_get_search_fields();
	foreach ($search_fields AS $search_field) {
		if (in_array($search_field->content_field->type, array('datetime'))) {
			$slug = $search_field->content_field->slug;
			
			// back compatibility
			if (!isset($args[$slug]) && (isset($args['field_' . $slug]) || isset($args['field_' . $slug . '_min']) || isset($args['field_' . $slug . '_max']))) {
				$slug = 'field_' . $slug;
			}
			
			if (isset($args[$slug])) {
				$min_max_options_range = explode('-', $args[$slug]);
				if (count($min_max_options_range) == 2) {
					$args[$slug] = $min_max_options_range;
				}
			} else {
				$start_date = '';
				if (isset($args[$slug . '_min'])) {
					$start_date = $args[$slug . '_min'];
				}
				$end_date = '';
				if (isset($args[$slug . '_max'])) {
					$end_date = $args[$slug . '_max'];
				}
				$args[$slug] = array($start_date, $end_date);
			}
		}
	}
	
	return $args;
}

add_filter("w2dc_query_args", "w2dc_query_args_date", 10, 2);
function w2dc_query_args_date($q_args, $args) {
	
	global $wpdb;
	
	$search_fields = w2dc_get_search_fields();
	foreach ($search_fields AS $search_field) {
		if (in_array($search_field->content_field->type, array('datetime'))) {
			$slug = $search_field->content_field->slug;
			$id = $search_field->content_field->id;

			// back compatibility
			if (!isset($args[$slug]) && (isset($args['field_' . $slug]) || isset($args['field_' . $slug . '_min']) || isset($args['field_' . $slug . '_max']))) {
				$slug = 'field_' . $slug;
			}
			
			$start_date = '';
			$end_date = '';
			
			if (!empty($args[$slug]) && is_array($args[$slug])) {
				$date = $args[$slug];
				$start_date = $date[0];
				$end_date = $date[1];
			}
			
			if (!$start_date && !$end_date && $search_field->content_field->hide_past_dates) {
				$start_date = time(); // set up current Start Date and just check if listings End Dates haven't been passed yet
			}
				
			$wheres = array();
			if ($start_date && ((is_numeric($start_date) && $start_date > 0) || strtotime($start_date))) {
				$value = $start_date;
				if (!is_numeric($value)) {
					$value = strtotime($start_date);
				}
				$wheres[] = "(meta1.meta_key = '_content_field_" . $id . "_date_end' AND (CAST(meta1.meta_value AS SIGNED) >= " . $value . " OR meta1.meta_value = '0'))";
			}
			if ($end_date && ((is_numeric($end_date) && $end_date > 0) || strtotime($end_date))) {
				$value = $end_date;
				if (!is_numeric($value)) {
					$value = strtotime($end_date);
				}
				$wheres[] = "(meta2.meta_key = '_content_field_" . $id . "_date_start' AND (CAST(meta2.meta_value AS SIGNED) <= " . $value . " OR meta2.meta_value = '0'))";
			}
			
			if ($wheres) {
				$query = "SELECT DISTINCT meta1.post_id FROM {$wpdb->postmeta} AS meta1 INNER JOIN {$wpdb->postmeta} AS meta2 ON meta1.post_id = meta2.post_id WHERE (" . implode(" AND ", $wheres) . ")";
			
				$posts_in = array();
				$results = $wpdb->get_results($query, ARRAY_A);
				foreach ($results AS $row) {
					$posts_in[] = $row['post_id'];
				}
				
				if ($posts_in) {
					$posts_in = array_unique($posts_in);
			
					if (!empty($q_args['post__in'])) {
						$q_args['post__in'] = array_intersect($q_args['post__in'], $posts_in);
					} else {
						$q_args['post__in'] = $posts_in;
					}
				} else {
					$q_args['post__in'] = array(0);
				}
			}
		}
	}
	
	return $q_args;
}

add_filter("w2dc_visible_params", "w2dc_visible_params_date", 10, 2);
function w2dc_visible_params_date($params, $query_array) {
	
	$search_fields = w2dc_get_search_fields();
	foreach ($search_fields AS $search_field) {
		if (in_array($search_field->content_field->type, array('datetime'))) {
			$slug = $search_field->content_field->slug;
			
			if (!empty($query_array[$slug])) {
				$min_max_options_range = explode('-', $query_array[$slug]);
				if (count($min_max_options_range) == 2) {
					
					$label = '';
		
					if ($min_max_options_range[0] !== '') {
						$label .= esc_html__("from", "W2DC");
						$label .= ' ';
						if (is_numeric($min_max_options_range[0])) {
							$label .= mysql2date(w2dc_getDateFormat(), date('Y-m-d H:i:s', $min_max_options_range[0]));
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
							$label .= mysql2date(w2dc_getDateFormat(), date('Y-m-d H:i:s', $min_max_options_range[1]));
						} else {
							$label .= $min_max_options_range[1];
						}
					}
				
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