<?php

add_filter("w2dc_query_args", "w2dc_query_args_hours", 10, 2);
function w2dc_query_args_hours($q_args, $args) {
	
	$search_fields = w2dc_get_search_fields();
	foreach ($search_fields AS $search_field) {
		if (in_array($search_field->content_field->type, array('hours'))) {
			$slug = $search_field->content_field->slug;
			$id = $search_field->content_field->id;
			
			if (!empty($args[$slug])) {
				
				global $wpdb;
				
				$week_days = array_values($search_field->content_field->orderWeekDays());
				$this_week_day = $week_days[wp_date("N")-1];
				
				$from_to_options = $search_field->content_field->getFromToOptions();
				$from_options = $from_to_options[0];
				if ($from_options) {
					$to_options = $from_to_options[1];
					
					$like_from = array();
					$like_to = array();
					$like_closed = array();
					
					foreach ($from_options AS $from) {
						$like_from[] = "'" . serialize(array($this_week_day."_from"=>$from)) . "'";
					}
					foreach ($to_options AS $to) {
						$like_to[] = "'" . serialize(array($this_week_day."_to"=>$to)) . "'";
					}
					$line_not_in = "'" . serialize(array($this_week_day."_closed"=>"1")) . "'";
					
					$query = "SELECT DISTINCT pm1.post_id FROM {$wpdb->postmeta} AS pm1 LEFT JOIN {$wpdb->postmeta} AS pm2 ON pm1.post_id=pm2.post_id LEFT JOIN {$wpdb->postmeta} AS pm3 ON pm2.post_id=pm3.post_id WHERE pm1.meta_key='_content_field_{$search_field->content_field->id}'";
					if ($like_from) {
						$query .= " AND pm1.meta_value IN (" . implode(",", $like_from) . ")";
					}
					if ($like_to) {
						$query .= " AND pm2.meta_value IN (" . implode(",", $like_to) . ")";
					}
					$query .= "AND pm3.meta_value != " . $line_not_in;
					
					if ($results = $wpdb->get_results($query, ARRAY_A)) {
						$posts_in = array();
						foreach ($results AS $row) {
							$posts_in[] = $row['post_id'];
						}
						if ($posts_in) {
							if (!empty($q_args['post__in'])) {
								$q_args['post__in'] = array_intersect($q_args['post__in'], $posts_in);
							} else {
								$q_args['post__in'] = $posts_in;
							}
						} else {
							$q_args['post__in'] = array(0);
						}
					} else {
						$q_args['post__in'] = array(0);
					}
				} else {
					$q_args['post__in'] = array(0);
				}
				
				if (empty($q_args['post__in'])) {
					$q_args['post__in'] = array(0);
				}
			}
		}
	}
	
	return $q_args;
}

add_filter("w2dc_visible_params", "w2dc_visible_params_hours", 10, 2);
function w2dc_visible_params_hours($params, $query_array) {
	
	$search_fields = w2dc_get_search_fields();
	foreach ($search_fields AS $search_field) {
		if (in_array($search_field->content_field->type, array('hours'))) {
			$slug = $search_field->content_field->slug;
			
			if (!empty($query_array[$slug])) {
				
				$label = $search_field->content_field->name;
				
				unset($query_array[$slug]);
				$query_string = http_build_query($query_array);
					
				$params[$query_string] = $label;
			}
		}
	}
		
	return $params;
}

?>