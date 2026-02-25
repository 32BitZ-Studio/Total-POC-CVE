<?php

add_filter("w2dc_query_args", "w2dc_query_args_perpage", 10, 2);
function w2dc_query_args_perpage($q_args, $args) {
	
	// while random sorting and we have to exclude already shown listings - do not limit records, we will take needed later
	if (!empty($args['existing_listings']) && w2dc_getValue($_REQUEST, 'order_by') == 'rand') {
		$q_args['posts_per_page'] = -1;
	} else {
		if (!empty($args['num'])) {
			$q_args['posts_per_page'] = $args['num'];
		} elseif (!empty($args['perpage'])) {
			$q_args['posts_per_page'] = $args['perpage'];
		}
		if (!empty($args['onepage']) || (empty($args['num']) && empty($args['perpage']))) {
			$q_args['posts_per_page'] = -1;
		}
	}
	
	return $q_args;
}

?>