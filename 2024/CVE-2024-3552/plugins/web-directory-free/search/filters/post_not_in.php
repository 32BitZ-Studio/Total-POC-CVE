<?php

add_filter("w2dc_query_args", "w2dc_query_args_post_not_in", 10, 2);
function w2dc_query_args_post_not_in($q_args, $args) {
	
	if (!empty($args['post__not_in'])) {
		if (is_string($args['post__not_in']) || is_numeric($args['post__not_in'])) {
			$post__not_in = array_filter(explode(',', $args['post__not_in']));
		} elseif (is_array($args['post__not_in'])) {
			$post__not_in = $args['post__not_in'];
		}
	
		if (!empty($q_args['post__not_in'])) {
			$q_args['post__not_in'] = array_merge($q_args['post__not_in'], $post__not_in);
		} else {
			$q_args['post__not_in'] = $post__not_in;
		}
	}
	
	return $q_args;
}

?>