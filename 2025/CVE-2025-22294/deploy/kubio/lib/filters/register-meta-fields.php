<?php

use Kubio\Core\Utils;

register_meta(
	'post',
	'saved_in_kubio',
	array(
		'object_subtype'    => '',
		'type'              => 'boolean',
		'single'            => true,
		'default'           => false,
		'sanitize_callback' => 'rest_sanitize_boolean',
		'show_in_rest'      => true,
	)
);


function kubio_set_post_as_saved_in_kubio( $post_id ) {
	if ( Utils::hasKubioEditorReferer() ) {
		$previous_value = get_post_meta( $post_id, 'saved_in_kubio', true );
		update_post_meta( $post_id, 'saved_in_kubio', true, $previous_value );
	}
}


add_action( 'wp_after_insert_post', 'kubio_set_post_as_saved_in_kubio', 10, 1 );
