<?php

require_once __DIR__ . '/wpml.php';
require_once __DIR__ . '/polylang.php';


add_action(
	'rest_api_init',
	function () {
		$namespace = 'kubio/v1';

		register_rest_route(
			$namespace,
			'/get-language-selector-html',
			array(
				'methods'             => 'GET',
				'callback'            => 'kubio_api_get_language_selector_html',
				'permission_callback' => function () {
					return current_user_can( 'edit_theme_options' );
				},
			)
		);
	}
);

function kubio_api_get_language_selector_html() {

	$content = '';
	if ( kubio_polylang_is_active() ) {
		$content = kubio_get_polylang_selector_html( true );
	} elseif ( kubio_wpml_is_active() ) {
		$content = kubio_get_wpml_selector_html( true );
	}

	return array(
		'content' => $content,
	);
}
