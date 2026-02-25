<?php

use Kubio\Core\Utils;
use Kubio\Flags;

add_action(
	'rest_api_init',
	function () {
		$namespace = 'kubio/v1';

		register_rest_route(
			$namespace,
			'/kubio-api-key',
			array(
				'methods'             => 'GET',
				'callback'            => 'kubio_get_api_key',
				'permission_callback' => function () {
					return current_user_can( 'edit_theme_options' );
				},
			)
		);

		register_rest_route(
			$namespace,
			'/kubio-api-key',
			array(
				'methods'             => 'POST',
				'callback'            => 'kubio_update_api_key',
				'permission_callback' => function () {
					return current_user_can( 'edit_theme_options' );
				},
			)
		);
	}
);

/**
 * REST API Callback to get the API connection key, but also checks if the key is still valid.
 *
 * @param WP_REST_Request $data
 * @return void
 */
function kubio_get_api_key( WP_REST_Request $data ) {
	$key = Flags::get( 'kubio_cloud_api_key' );

	if ( empty( $key ) ) {

		wp_send_json_error( __( 'Api key not found', 'kubio' ) );

	}

	$response = wp_remote_get(
		Utils::getCloudURL( '/api/user/validate-api-key' ),
		array(
			'headers' => array(
				'Content-Type'    => 'application/json',
				'X-Authorization' => $key,
			),
		)
	);

	$body    = wp_remote_retrieve_body( $response );
	$code    = wp_remote_retrieve_response_code( $response );
	$decoded = json_decode( $body, true );

	if ( $code === 200 && is_array( $decoded ) && $decoded['isValid'] && ! empty( $decoded['email'] ) ) {
		wp_send_json_success(
			array(
				'email'   => $decoded['email'],
				'name'    => $decoded['name'],
				'role'    => $decoded['role'],
				'isValid' => true,
				'key'     => $key,
			)
		);
	}
	wp_send_json_error( __( 'Api key not found', 'kubio' ) );
}

/**
 * Api callback to save the Kubio cloud API key.
 *
 * @param WP_REST_Request $data
 * @return void
 */
function kubio_update_api_key( WP_REST_Request $data ) {

	if ( isset( $data['key'] ) ) {
		Flags::set( 'kubio_cloud_api_key', sanitize_text_field( $data['key'] ) );
		wp_send_json_success();
	}
	wp_send_json_error( __( 'Api key not found', 'kubio' ) );
}
