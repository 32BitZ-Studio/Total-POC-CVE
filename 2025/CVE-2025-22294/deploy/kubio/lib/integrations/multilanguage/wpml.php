<?php

function kubio_wpml_is_active() {
	static $is_active = null;
	if ( $is_active === null ) {
		$is_active = defined( 'ICL_SITEPRESS_VERSION' );
	}

	return $is_active && ! kubio_polylang_is_active();
}


function kubio_wpml_get_translated_string( $string ) {
	if ( ! kubio_wpml_is_active() || ! is_string( $string ) ) {
		return $string;
	}
	return apply_filters( 'wpml_translate_single_string', $string, KUBIO_WPML_BLOCK_DEFAULTS_ID, $string );
}

function kubio_wpml_get_translated_media_id( $id ) {
	if ( ! kubio_wpml_is_active() ) {
		return $id;

	}
	$current_language = apply_filters( 'wpml_current_language', null );

	$translated_attachment_id = apply_filters( 'wpml_object_id', $id, 'attachment', true, $current_language );

	return $translated_attachment_id;
}

function kubio_wpml_get_translated_media_url( $url ) {
	if ( ! kubio_wpml_is_active() || empty( $url ) ) {
		return $url;
	}
	$image_id = attachment_url_to_postid( $url );
	if ( ! $image_id ) {
		return $url;
	}

	$translated_image_id = \kubio_wpml_get_translated_media_id( $image_id );
	if ( ! $translated_image_id ) {
		return $url;
	}
	$new_url = wp_get_attachment_url( $translated_image_id );
	if ( $new_url ) {
		return $new_url;
	}
	return $url;
}

function kubio_wpml_get_original_language_post_id( $post_id, $post_type ) {
	if ( ! kubio_wpml_is_active() ) {
		return $post_id;
	}

	$translated_id = apply_filters( 'wpml_object_id', $post_id, $post_type, true, wpml_get_default_language() );
	if ( ! empty( $translated_id ) && $translated_id !== 0 && $translated_id !== $post_id ) {
		$post_id = $translated_id;
	}

	return $post_id;
}
