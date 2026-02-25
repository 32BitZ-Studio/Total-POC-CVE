<?php

add_filter("w2dc_query_args", "w2dc_query_args_author", 10, 2);
function w2dc_query_args_author($q_args, $args) {
	
	if (!empty($args['author'])) {
		$q_args['author'] = $args['author'];
	}
	
	return $q_args;
}

?>