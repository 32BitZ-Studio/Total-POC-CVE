<?php


if ( ! defined( 'WP_TEMPLATE_TYPES' ) ) {
	define( 'WP_TEMPLATE_TYPES', array( 'wp_template', 'wp_template_part' ) );
}


function get_multilanguage_settings() {
	$current_value = kubio_get_global_data( 'globalStyle.props.multilanguage', array() );
	$default_value = array(
		'show'      => true,
		'displayAs' => 'flags',
		'showFlags' => true,
		'showNames' => false,
	);
	$merged_value  = array_merge( $default_value, $current_value );

	return $merged_value;
}
require_once __DIR__ . '/wpml.php';
require_once __DIR__ . '/polylang.php';
