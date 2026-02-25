<?php

use IlluminateAgnostic\Arr\Support\Arr;

function kubio_set_post_kubio_ai_page_context( $value, $object ) {

	$post_id = $object->ID;

	Arr::forget( $value, array( 'title' ) );

	$previous_value = get_post_meta( $post_id, 'kubio_ai_page_context', true );
	update_post_meta( $post_id, 'kubio_ai_page_context', $value, $previous_value );
}


function kubio_get_post_kubio_ai_page_context( $object ) {
	$post_id = $object['id'];

	$value = get_post_meta( $post_id, 'kubio_ai_page_context', true );

	if ( empty( $value ) ) {
		$value = array();
	}

	return (object) array_merge(
		array(
			'short_desc' => '',
			'purpose'    => 'general',
		),
		$value
	);
}


function kubio_register_kubio_ai_meta_fields() {
	register_rest_field(
		'page',
		'kubio_ai_page_context',
		array(
			'get_callback'    => 'kubio_get_post_kubio_ai_page_context',
			'update_callback' => 'kubio_set_post_kubio_ai_page_context',
		)
	);
}

add_action( 'rest_api_init', 'kubio_register_kubio_ai_meta_fields' );
