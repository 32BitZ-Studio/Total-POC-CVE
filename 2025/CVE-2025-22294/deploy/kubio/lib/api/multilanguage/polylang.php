<?php

add_action(
	'rest_api_init',
	function () {
		$namespace = 'kubio/v1/polylang';

		register_rest_route(
			$namespace,
			'/add-page-translation',
			array(
				'methods'             => 'POST',
				'callback'            => 'kubio_api_polylang_add_page_translation',
				'permission_callback' => function () {
					return current_user_can( 'edit_theme_options' );
				},
			)
		);
	}
);

add_action(
	'rest_api_init',
	function () {
		$namespace = 'kubio/v1/polylang';

		register_rest_route(
			$namespace,
			'/add-template-translation',
			array(
				'methods'             => 'POST',
				'callback'            => 'kubio_api_polylang_add_template_translation',
				'permission_callback' => function () {
					return current_user_can( 'edit_theme_options' );
				},
			)
		);
	}
);

add_action(
	'rest_api_init',
	function () {
		$namespace = 'kubio/v1/polylang';

		register_rest_route(
			$namespace,
			'/quick-translate',
			array(
				'methods'             => 'POST',
				'callback'            => 'kubio_api_polylang_quick_translate',
				'permission_callback' => function () {
					return current_user_can( 'edit_theme_options' );
				},
			)
		);
	}
);

function kubio_api_polylang_add_page_translation( WP_REST_Request $request ) {
	//check_ajax_referer('kubio_api_polylang_add_page_translation'); // TODO: check nonce

	$post_id  = $request->get_param( 'postId' );
	$new_lang = $request->get_param( 'newLang' );

	// Duplicate page
	$new_post_id = kubio_polylang_translate_page( $post_id, $new_lang );

	// Duplicate template
	$new_template = kubio_polylang_translate_page_template( $post_id, $new_lang );

	// Duplicate template-parts
	kubio_polylang_translate_page_template_parts( $post_id, $new_lang );

	// Update page template with new one
	if ( $new_post_id && $new_template ) {
		update_post_meta( $new_post_id, '_wp_page_template', $new_template['slug'] );
	} elseif ( get_post_meta( $post_id, '_wp_page_template', true ) === 'default' ) {
		update_post_meta( $new_post_id, '_wp_page_template', 'default' );
	}

	wp_send_json_success();
}

function kubio_api_polylang_add_template_translation( WP_REST_Request $request ) {
	//check_ajax_referer('kubio_api_polylang_add_template_translation'); // TODO: check nonce

	$post_id  = $request->get_param( 'postId' );
	$new_lang = $request->get_param( 'newLang' );

	// Duplicate template
	$new_template = kubio_polylang_translate_page_template( null, $new_lang, intval( $post_id ) );

	if ( ! $new_template ) {
		wp_send_json_error();
	}
	wp_send_json_success();
}

function kubio_api_polylang_quick_translate( WP_REST_Request $request ) {
	//check_ajax_referer('nonce_name'); // TODO: check nonce
	$post_type = $request->get_param( 'postType' );

	$need_translation = \Kubio\Flags::getSetting( 'pll_templates_need_translation' );

	if ( isset( $need_translation[ $post_type ] ) ) {
		foreach ( $need_translation[ $post_type ] as $template_id => $language_ids ) {
			foreach ( $language_ids as $lang_id ) {
				kubio_polylang_translate_page_template( null, get_term( $lang_id )->slug, $template_id );
			}
		}
		\Kubio\Flags::setSetting( 'pll_templates_need_translation', null );
	}

	wp_send_json_success();
}
