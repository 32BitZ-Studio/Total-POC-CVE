<?php

use IlluminateAgnostic\Arr\Support\Arr;
use Kubio\Flags;
use Kubio\Core\Utils;

add_action(
	'rest_api_init',
	function () {
		$namespace = 'kubio/v1';

		register_rest_route(
			$namespace,
			'/enable-theme',
			array(
				'methods'             => 'GET',
				'callback'            => 'kubio_enable_theme',
				'permission_callback' => function () {
					return current_user_can( 'edit_theme_options' );
				},
			)
		);

		register_rest_route(
			$namespace,
			'/colibri-data-export',
			array(
				'methods'             => 'GET',
				'callback'            => 'kubio_colibri_data_export',
				'permission_callback' => function () {
					return current_user_can( 'edit_theme_options' );
				},
			)
		);

		register_rest_route(
			$namespace,
			'/colibri-data-export-done',
			array(
				'methods'             => 'GET',
				'callback'            => 'kubio_colibri_data_export_done',
				'permission_callback' => function () {
					return current_user_can( 'edit_theme_options' );
				},
			)
		);

		register_rest_route(
			$namespace,
			'/snippet',
			array(
				'methods'             => 'POST',
				'callback'            => 'kubio_save_block_snippet',
				'permission_callback' => function () {
					return current_user_can( 'edit_theme_options' );
				},
			)
		);

		register_rest_route(
			$namespace,
			'/snippet/update',
			array(
				'methods'             => 'POST',
				'callback'            => 'kubio_update_block_snippet',
				'permission_callback' => function () {
					return current_user_can( 'edit_theme_options' );
				},
			)
		);
	}
);


/**
 * API callback for saving a snippet; It creates a zip archive with the html template, the screenshot and the assets.
 * Also sends the zip archive to Kubio cloud.
 *
 * @param WP_REST_Request $request
 * @return void
 */
function kubio_save_block_snippet( WP_REST_Request $request ) {
	if ( ! class_exists( 'ZipArchive' ) ) {
		wp_send_json_error( __( 'Zip Export not supported.', 'kubio' ) );
	}

	$name        = $request->get_param( 'name' );
	$category    = $request->get_param( 'category' );
	$snippet     = $request->get_param( 'snippet' );
	$screenshot  = $request->get_param( 'screenshot' );
	$global_data = $request->get_param( 'globalData' );
	$zip_path    = get_temp_dir() . $name . '.zip';

	$screenshot_ext = explode( ';base64,', $screenshot );
	$screenshot_ext = explode( 'data:image/', $screenshot_ext[0] );

	if ( empty( $screenshot_ext[1] ) ) {
		wp_send_json_error( __( 'Bad screenshot.', 'kubio' ) );
	}

	// allow only letters, numbers, underscore, dashe and space characters.
	if ( preg_match( '/[^A-Za-z0-9_ \-]/', $name ) || strlen( $name ) > 100 ) {
		wp_send_json_error( __( 'Bad name.', 'kubio' ) );
	}

	$zip = kubio_create_snippet_zip( $zip_path, $snippet, $screenshot, $global_data );

	$apiKey = Flags::get( 'kubio_cloud_api_key' );

	$request_url = add_query_arg(
		array(
			'filename'    => $name,
			'category_id' => $category,
			'block'       => $snippet[0],
		),
		Utils::getSnippetsURL( '/save' )
	);

	$response = wp_remote_post(
		$request_url,
		array(
			'headers' => array(
				'X-Authorization' => $apiKey,
				'accept'          => 'application/json',
				'content-type'    => 'application/binary',
			),
			'body'    => file_get_contents( $zip_path ),
		)
	);

	$response_code = wp_remote_retrieve_response_code( $response );

	if ( 200 !== $response_code ) {
		$errorMessage = wp_remote_retrieve_body( $response );
		wp_send_json_error( $errorMessage );
	}

	$body = wp_remote_retrieve_body( $response );

	wp_send_json_success( json_decode( $body ) );
}

function kubio_update_block_snippet( WP_REST_Request $request ) {
	if ( ! class_exists( 'ZipArchive' ) ) {
		wp_send_json_error( __( 'Zip Export not supported.', 'kubio' ) );
	}

	$id          = $request->get_param( 'id' );
	$name        = $request->get_param( 'name' );
	$category    = $request->get_param( 'category' );
	$snippet     = $request->get_param( 'snippet' );
	$screenshot  = $request->get_param( 'screenshot' );
	$global_data = $request->get_param( 'globalData' );

	$zip_path = get_temp_dir() . $name . '.zip';

	if ( empty( $id ) ) {
		wp_send_json_error( __( 'No id.', 'kubio' ) );
	}

	// allow only letters, numbers, underscore, dashe and space characters.
	if ( preg_match( '/[^A-Za-z0-9_ \-]/', $name ) || strlen( $name ) > 100 ) {
		wp_send_json_error( __( 'Bad name.', 'kubio' ) );
	}

	$zip = kubio_create_snippet_zip( $zip_path, $snippet, $screenshot, $global_data );

	$apiKey = Flags::get( 'kubio_cloud_api_key' );

	$args = array(
		'filename'    => $name,
		'category_id' => $category,
		'block'       => $snippet[0],

	);

	$request_url = add_query_arg(
		$args,
		Utils::getSnippetsURL( '/' . $id . '/update' )
	);

	$response = wp_remote_post(
		$request_url,
		array(
			'headers' => array(
				'X-Authorization' => $apiKey,
				'accept'          => 'application/json',
				'content-type'    => 'application/binary',
			),
			'body'    => file_get_contents( $zip_path ),
		)
	);

	$response_code = wp_remote_retrieve_response_code( $response );

	if ( 200 !== $response_code ) {
		$errorMessage = wp_remote_retrieve_body();
		wp_send_json_error( $errorMessage );
	}

	$body = wp_remote_retrieve_body( $response );

	wp_send_json_success( json_decode( $body ) );
}

/**
 * This function creates a temporary zip file for the given snippet.
 *
 * @param $path
 * @param $snippet
 * @param $screenshot_data
 * @return false|ZipArchive
 */
function kubio_create_snippet_zip( $path, $snippet, $screenshot_data, $global_data ) {
	// create the zip archive and start adding.
	$zip = new ZipArchive();
	if ( true !== $zip->open( $path, ZipArchive::CREATE | ZipArchive::OVERWRITE ) ) {
		wp_send_json_error( __( 'Unable to open export file (archive) for writing.', 'kubio' ) );
	}

	// handle the screenshot data and add it to the zip
	if ( preg_match( '/^data:image\/(\w+);base64,/', $screenshot_data, $screenshot_type ) ) {
		$screenshot_data = substr( $screenshot_data, strpos( $screenshot_data, ',' ) + 1 );
		$screenshot_type = strtolower( $screenshot_type[1] ); // jpg, png, gif
		if ( ! in_array( $screenshot_type, array( 'jpg', 'jpeg', 'gif', 'png' ) ) ) {
			return false;
		}

		$screenshot_data = str_replace( ' ', '+', $screenshot_data );
		$screenshot_data = base64_decode( $screenshot_data );

		$zip->addFromString( 'screenshot.' . $screenshot_type, $screenshot_data );
	}

	$zip->addFromString( 'global.json', json_encode( $global_data, JSON_PRETTY_PRINT ) );

	// from now on we search assets from the template, and we save them in the archive.
	//$zip->addEmptyDir( 'assets' );

	// search for media files by urls.
	$upload_settings = wp_get_upload_dir();
	$pattern         = '#' . str_replace( '/', '\/', $upload_settings['baseurl'] ) . '(.*?)"#';
	$pattern         = str_replace( ':', '\:', $pattern );
	preg_match_all( $pattern, json_encode( $snippet, JSON_UNESCAPED_SLASHES ), $matches );

	$uploaded_files = array();

	if ( ! empty( $matches ) ) {
		$uploaded_files = $matches[1];
	}

	// search media files by id.
	$uploaded_files = kubio_parse_blocks_for_media_id_atts_and_stack( $snippet, $uploaded_files );

	foreach ( $uploaded_files as $uploaded_file ) {
		$file_path = $upload_settings['basedir'] . $uploaded_file;

		if ( file_exists( $file_path ) ) {
			$file     = file_get_contents( $file_path );
			$new_path = wp_normalize_path( 'assets' . $uploaded_file );
			$zip->addFromString( $new_path, $file );
		}
	}

	// at last, save the snippet template and close the zip archive.
	$parsed = str_replace( $upload_settings['baseurl'], '{{snippet_url}}', json_encode( $snippet, JSON_UNESCAPED_SLASHES ) );
	$zip->addFromString( 'template.json', $parsed );

	$zip->close();
	return $zip;
}

/**
 * This function searches for attributes that hold media files and adds them to the $uploaded_files stack.
 *
 * @param $block
 * @param $uploaded_files
 * @return mixed
 */
function kubio_parse_blocks_for_media_id_atts_and_stack( $block, $uploaded_files = false ) {
	// $block[0] is the block name.
	$block_type = WP_Block_Type_Registry::get_instance()->get_registered( $block[0] );

	if ( ! empty( $block_type->supports['kubio'] ) ) {
		$assets_importer_map = Arr::get( $block_type->supports['kubio'], 'assetsURLImporterMap', array() );

		if ( ! empty( $assets_importer_map ) ) {
			$id_attr = '';
			foreach ( $assets_importer_map as $url_attr => $import_map ) {
				$id_attr = Arr::get( $import_map, 'assetIdToAttr' );
			}

			// $block[1] holds the attributes
			$id = $block[1][ $id_attr ];

			if ( ! empty( $id ) ) {
				$url      = wp_get_attachment_url( $id );
				$parsed   = wp_parse_url( $url );
				$new_path = str_replace( '/wp-content/uploads', '', $parsed['path'] );
				if ( ! in_array( $new_path, $uploaded_files ) ) {
					$uploaded_files[] = $new_path;
				}
			}
		}
	}

	// at $block['2'] there should be an array of blocks as innerBlocks.
	if ( ! empty( $block['2'] ) ) {
		$uploaded_files = kubio_parse_blocks_for_media_id_atts_and_stack( $block['2'][0], $uploaded_files );
	}

	return $uploaded_files;
}

function kubio_get_installed_theme() {
	$themes       = wp_get_themes();
	$kubio_themes = array( 'kubio', 'elevate-wp' );
	$intersect    = array_values( array_intersect( array_keys( $themes ), $kubio_themes ) );
	$theme        = Arr::get( $intersect, 0, null );
	return $theme;
}

function kubio_enable_theme( WP_REST_Request $data ) {
	switch_theme( $data['name'] );
	return wp_send_json( array( 'switched' => $data['name'] ) );
}

function kubio_colibri_data_export_done() {

	// copy menus location from colibri to kubio;
	$colibri_options = get_option( 'theme_mods_colibri-wp', array() );
	$kubio_options   = get_option( 'theme_mods_kubio', array() );

	$colibri_locations = Arr::get( $colibri_options, 'nav_menu_locations', array() );
	$kubio_locations   = Arr::get( $kubio_options, 'nav_menu_locations', array() );

	$locations_map = array(
		'header-menu'   => 'header-menu',
		'footer-menu'   => 'footer-menu',
		'footer-menu-1' => 'footer-menu-secondary',
		'header-menu-1' => 'header-menu-secondary',
	);

	foreach ( $colibri_locations as $location => $menu ) {
		$location                     = Arr::get( $locations_map, $location, $location );
		$kubio_locations[ $location ] = $menu;
	}

	Arr::set( $kubio_options, 'nav_menu_locations', $kubio_locations );

	if ( $theme = kubio_get_installed_theme() ) {
		update_option( "theme_mods_{$theme}", $kubio_options );
		switch_theme( $theme );

		flush_rewrite_rules();
		update_option( 'theme_switched', false );
	}

	wp_send_json_success();
}

function kubio_colibri_data_export() {

	$theme = kubio_get_installed_theme();

	if ( $theme ) {
		ob_clean();

		// templates are created with colibri-wp theme on kubio activation //
		foreach ( get_block_templates( array(), 'wp_template' ) as $template ) {
			wp_set_post_terms( $template->wp_id, $theme, 'wp_theme' );
		}

		echo wp_json_encode(
			\ExtendBuilder\export_colibri_data(
				array( 'exclude_generated' => true ),
				false
			)
		);
			switch_theme( $theme );
	} else {
		wp_send_json_error(
			array(
				'error' => 'kubio-not-installed',
			)
		);
	}
}

add_filter(
	'colibri_page_builder/get_partial_details',
	function ( $data ) {
		$post     = get_post( $data['id'] );
		$new_data = array(
			'title'         => $post->post_title,
			'page_template' => $post->page_template,
			'parent'        => $post->post_parent,
		);
		return array_merge( $data, $new_data );
	},
	100
);
