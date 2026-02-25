<?php

use Kubio\Flags;

function kubio_api_update_ui_version( WP_REST_Request $request ) {
	$next_version       = intval( $request['version'] );
	$available_versions = array( 1, 2 );
	if ( in_array( $next_version, $available_versions ) ) {
		Flags::setSetting( 'editorUIVersion', $next_version );
	} else {
		return new WP_Error( 'kubio_invalid_ui_version' );
	}

	return array( 'version' => $next_version );
}

function kubio_api_update_ai_capabilities( WP_REST_Request $request ) {
	$next_value = ! ! intval( $request['value'] );
	Flags::setSetting( 'enableAICapabilities', $next_value );
	return array( 'value' => $next_value );
}

function kubio_api_update_editor_mode( WP_REST_Request $request ) {
	$next_value       = $request['value'];
	$available_values = array( 'simple', 'full' );

	if ( in_array( $next_value, $available_values ) ) {
		Flags::setSetting( 'editorMode', $next_value );
	} else {
		return new WP_Error( 'kubio_invalid_value' );
	}

	return array( 'value' => $next_value );
}

function kubio_api_update_excluded_section_categories( WP_REST_Request $request ) {
	$value = $request['value'];

	if ( is_array( $value ) ) {
		Flags::setSetting( 'excludedSectionCategories', $value );
	} else {
		return new WP_Error( 'kubio_invalid_value' );
	}

	return array( 'value' => $value );
}

function kubio_api_update_flag_settings( WP_REST_Request $request ) {
	$path  = $request['path'];
	$value = $request['value'];

	if ( gettype( $path ) === 'string' ) {
		Flags::setSetting( $path, $value );
	} else {
		return new WP_Error( 'kubio_invalid_value' );
	}

	return array(
		'path'  => $path,
		'value' => $value,
	);
}

add_action(
	'rest_api_init',
	function () {
		$namespace = 'kubio/v1';

		register_rest_route(
			$namespace,
			'/update-ui-version',
			array(
				'methods'             => 'GET',
				'callback'            => 'kubio_api_update_ui_version',
				'permission_callback' => function () {
					return current_user_can( 'edit_theme_options' );
				},

			)
		);

		register_rest_route(
			$namespace,
			'/update-enable-ai-capabilities',
			array(
				'methods'             => 'POST',
				'callback'            => 'kubio_api_update_ai_capabilities',
				'permission_callback' => function () {
					return current_user_can( 'edit_theme_options' );
				},

			)
		);

		register_rest_route(
			$namespace,
			'/update-editor-mode',
			array(
				'methods'             => 'POST',
				'callback'            => 'kubio_api_update_editor_mode',
				'permission_callback' => function () {
					return current_user_can( 'edit_theme_options' );
				},

			)
		);

		register_rest_route(
			$namespace,
			'/update-excluded-section-categories',
			array(
				'methods'             => 'POST',
				'callback'            => 'kubio_api_update_excluded_section_categories',
				'permission_callback' => function () {
					return current_user_can( 'edit_theme_options' );
				},

			)
		);

		register_rest_route(
			$namespace,
			'/update-flag-settings',
			array(
				'methods'             => 'POST',
				'callback'            => 'kubio_api_update_flag_settings',
				'permission_callback' => function () {
					return current_user_can( 'edit_theme_options' );
				},

			)
		);
	}
);
