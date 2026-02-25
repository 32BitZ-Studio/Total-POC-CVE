<?php

add_action(
	'rest_api_init',
	function () {
		$namespace = 'kubio/v1/wpml';

		register_rest_route(
			$namespace,
			'/add-page-translation',
			array(
				'methods'             => 'POST',
				'callback'            => 'kubio_api_wpml_add_page_translation',
				'permission_callback' => function () {
					return current_user_can( 'edit_theme_options' );
				},
			)
		);
	}
);

function kubio_api_wpml_add_page_translation( WP_REST_Request $request ) {
	//check_ajax_referer('kubio_api_wpml_add_page_translation'); // TODO: check nonce

	$post_id  = $request->get_param( 'postId' );
	$new_lang = $request->get_param( 'newLang' );

	$dup_page_id = kubio_wpml_translate_page( $post_id, $new_lang, true );
	if ( $dup_page_id === 0 ) {
		wp_send_json_success(
			array(
				'hasTranslation' => true,
			)
		);
	} elseif ( $dup_page_id ) {
		wp_send_json_success();
	}

	wp_send_json_error(
		array(
			'message' => "WPML: Cannot create translation for {$post_id}",
		)
	);
}
