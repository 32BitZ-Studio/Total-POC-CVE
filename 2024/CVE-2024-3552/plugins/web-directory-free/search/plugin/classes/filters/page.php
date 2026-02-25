<?php

add_filter("wcsearch_query_args_validate", "wcsearch_query_args_validate_page");
function wcsearch_query_args_validate_page($args) {
	if (!empty($args['page'])) {
		$args['page'] = (int)$args['page'];
	}
	
	return $args;
}

add_filter("wcsearch_query_args", "wcsearch_query_args_page", 10, 2);
function wcsearch_query_args_page($q_args, $args) {
	if ($args['page']) {
		$q_args['paged'] = $args['page'];
	}
	
	return $q_args;
}

?>