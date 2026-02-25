<?php

add_filter("w2dc_query_args", "w2dc_query_args_address", 10, 2);
function w2dc_query_args_address($q_args, $args) {
	
	if ((wcsearch_get_query_string("address") && w2dc_do_follow_get_params($args)) || !empty($args['address']) || !empty($args['start_address']) || (!empty($args['start_latitude']) && !empty($args['start_longitude']))) {
		global $wpdb;
		
		$radius = false;
		
		if (wcsearch_get_query_string("address") && w2dc_do_follow_get_params($args)) {
			$address = urldecode(wcsearch_get_query_string("address"));
			
			if (wcsearch_get_query_string("radius") && w2dc_do_follow_get_params($args)) {
				$radius = wcsearch_get_query_string("radius");
			} else {
				// when coordinates in address - try to take radius from default $args
				$address_coords_array = explode(',', $address);
				if (count($address_coords_array) == 2 && is_numeric($address_coords_array[0]) && is_numeric($address_coords_array[1])) {
					if (!empty($args['radius'])) {
						$radius = $args['radius'];
					}
				}
			}
		} else {
			$address = urldecode(w2dc_getValue($args, 'address', w2dc_getValue($args, 'start_address')));
			
			if (!empty($args['radius'])) {
				$radius = $args['radius'];
			}
		}
		
		if ($radius) {
			
			global $get_count_num_flag;
			// do not call geocoder when it is counting search items
			if ($get_count_num_flag) {
				return $q_args;
			}
			
			if ((wcsearch_get_query_string("address") && w2dc_do_follow_get_params($args))) {
				
				$address = urldecode(wcsearch_get_query_string("address"));
				
				$address_coords_array = explode(',', $address);
					
				if (count($address_coords_array) == 2 && is_numeric($address_coords_array[0]) && is_numeric($address_coords_array[1])) {
					$result[1] = $address_coords_array[0];
					$result[0] = $address_coords_array[1];
				} else {
					$geoname = new w2dc_locationGeoname;
					
					$result = $geoname->geocodeRequest($address, 'coordinates');
				}
			} elseif (!empty($args['geocoded_params'])) {
				$result[1] = $args['geocoded_params']['map_coords_1'];
				$result[0] = $args['geocoded_params']['map_coords_2'];
			} elseif (!empty($args['start_latitude']) && !empty($args['start_longitude'])) {
				$result[1] = $args['start_latitude'];
				$result[0] = $args['start_longitude'];
			} else {
				$geoname = new w2dc_locationGeoname;
				$result = $geoname->geocodeRequest($address, 'coordinates');
			}
			
			if (!is_wp_error($result) && is_array($result)) {
				if (get_option('w2dc_miles_kilometers_in_search') == 'miles') {
					$R = 3956; // earth's mean radius in miles
				} else {
					$R = 6367; // earth's mean radius in km
				}

				$dLat = '((map_coords_1-'.$result[1].')*PI()/180)';
				$dLong = '((map_coords_2-'.$result[0].')*PI()/180)';
				$a = '(sin('.$dLat.'/2) * sin('.$dLat.'/2) + cos('.$result[1].'*pi()/180) * cos(map_coords_1*pi()/180) * sin('.$dLong.'/2) * sin('.$dLong.'/2))';
				$c = '2*atan2(sqrt('.$a.'), sqrt(1-'.$a.'))';
				$sql = $R.'*'.$c; 

				$results = $wpdb->get_results($wpdb->prepare(
						"SELECT DISTINCT
							id, post_id, " . $sql . " AS distance FROM {$wpdb->w2dc_locations_relationships}
						HAVING
							distance <= %f
						ORDER BY
							distance
						", $radius), ARRAY_A);
				
				global $w2dc_order_by_distance;

				$post_ids = array();
				foreach ($results AS $row) {
					$post_ids[] = $row['post_id'];
					
					$w2dc_order_by_distance[$row['id']] = $row['distance'];
				}
				
				if (empty($args['geo_poly'])) {
					global $w2dc_address_locations;
					$w2dc_address_locations = array();
					foreach ($results AS $row) {
						$w2dc_address_locations[] = $row['id'];
					}
				}
				
				if (!empty($q_args['post__in']) && $post_ids) {
					$q_args['post__in'] = array_intersect($post_ids, $q_args['post__in']);
					if (empty($q_args['post__in'])) {
						// Do not show any listings
						$q_args['post__in'] = array(0);
					}
				} else {
					if ($post_ids) {
						$q_args['post__in'] = $post_ids;
					} else {
						// Do not show any listings
						$q_args['post__in'] = array(0);
					}
				}
				
				global $w2dc_radius_params;
				$w2dc_radius_params = array(
								'radius_value' 		=> $radius,
								'map_coords_1' 		=> $result[1],
								'map_coords_2' 		=> $result[0],
								'dimension' 		=> get_option('w2dc_miles_kilometers_in_search')
				);
				wp_localize_script(
						'w2dc_js_functions',
						'radius_params',
						$w2dc_radius_params
				);
			}
		} elseif (!empty($args['place_id'])) {
			
			$place_id = $args['place_id'];
			
			$results = $wpdb->get_results($wpdb->prepare("SELECT id, post_id FROM {$wpdb->w2dc_locations_relationships} WHERE place_id = '%s'", $place_id), ARRAY_A);
			
			$post_ids = array();
			foreach ($results AS $row) {
				$post_ids[] = $row['post_id'];
			}
			
			if (empty($args['geo_poly'])) {
				global $w2dc_address_locations;
				$w2dc_address_locations = array();
				foreach ($results AS $row) {
					$w2dc_address_locations[] = $row['id'];
				}
			}
			
			if (!empty($q_args['post__in'])) {
				$q_args['post__in'] = array_intersect($q_args['post__in'], $post_ids);
				if (empty($q_args['post__in'])) {
					// Do not show any listings
					$q_args['post__in'] = array(0);
				}
			} else {
				$q_args['post__in'] = $post_ids;
			}
		} elseif ((wcsearch_get_query_string("address") && w2dc_do_follow_get_params($args)) || !empty($args['address'])) {
			$where_sql_array[] = $wpdb->prepare("(address_line_1 LIKE %s OR address_line_2 LIKE %s OR zip_or_postal_index LIKE %s)", '%' . $address . '%', '%' . $address . '%', '%' . $address . '%');
			
			// Search keyword in locations terms
			$t_args = array(
					'taxonomy'      => array(W2DC_LOCATIONS_TAX),
					'orderby'       => 'id',
					'order'         => 'ASC',
					'hide_empty'    => true,
					'fields'        => 'tt_ids',
					'name__like'    => $address
			);
			$address_locations = get_terms($t_args);
	
			foreach ($address_locations AS $address_location) {
				$term_ids = get_terms(W2DC_LOCATIONS_TAX, array('child_of' => $address_location, 'fields' => 'ids', 'hide_empty' => false));
				$term_ids[] = $address_location;
				$where_sql_array[] = "(location_id IN (" . implode(', ', $term_ids) . "))";
			}
			
			$results = $wpdb->get_results("SELECT id, post_id FROM {$wpdb->w2dc_locations_relationships} WHERE " . implode(' OR ', $where_sql_array), ARRAY_A);
			$post_ids = array();
			
			global $w2dc_address_locations;
			$w2dc_address_locations = array();
			foreach ($results AS $row) {
				$post_ids[] = $row['post_id'];
				$w2dc_address_locations[] = $row['id'];
			}
			if ($post_ids) {
				if (!empty($q_args['post__in'])) {
					$q_args['post__in'] = array_intersect($q_args['post__in'], $post_ids);
					if (empty($q_args['post__in'])) {
						// Do not show any listings
						$q_args['post__in'] = array(0);
					}
				} else {
					$q_args['post__in'] = $post_ids;
				}
			} else {
				// Do not show any listings
				$q_args['post__in'] = array(0);
			}
		}
	}
	
	return $q_args;
}

add_filter("w2dc_visible_params", "w2dc_visible_params_address", 10, 2);
function w2dc_visible_params_address($params, $query_array) {
	if (!empty($query_array['address'])) {
		$label = esc_html(urldecode($query_array['address']));

		unset($query_array['address']);
		$query_string = http_build_query($query_array);

		$params[$query_string] = $label;
	}

	return $params;
}

?>