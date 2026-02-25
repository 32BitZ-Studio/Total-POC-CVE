<?php

add_filter(
	'wp_content_img_tag',
	function ( $image ) {
		return str_replace( ' sizes="auto, ', ' sizes="', $image );
	}
);

add_filter(
	'wp_get_attachment_image_attributes',
	function ( $attr ) {
		if ( isset( $attr['sizes'] ) ) {
			$attr['sizes'] = preg_replace( '/^auto, /', '', $attr['sizes'] );
		}
		return $attr;
	}
);

add_filter( 'wp_img_tag_add_auto_sizes', '__return_false' );
