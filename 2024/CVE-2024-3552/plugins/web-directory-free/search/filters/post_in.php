<?php

add_filter("w2dc_query_args", "w2dc_query_args_post_in", 10, 2);
function w2dc_query_args_post_in($q_args, $args) {
	
	if (!empty($args['post__in'])) {
		if (is_string($args['post__in']) || is_numeric($args['post__in'])) {
			$post__in = array_filter(explode(',', $args['post__in']));
		} elseif (is_array($args['post__in'])) {
			$post__in = $args['post__in'];
		}
		
		if (!empty($q_args['post__in'])) {
			$q_args['post__in'] = array_intersect($q_args['post__in'], $post__in);
			if (empty($q_args['post__in'])) {
				// Do not show any listings
				$q_args['post__in'] = array(0);
			}
		} else {
			$q_args['post__in'] = $post__in;
		}
	}
	
	return $q_args;
}

?>