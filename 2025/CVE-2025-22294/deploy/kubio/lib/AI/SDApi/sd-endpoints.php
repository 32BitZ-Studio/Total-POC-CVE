<?php

add_action(
	'rest_api_init',
	function () {
		$namespace = 'kubio/v1';

		register_rest_route(
			$namespace,
			'/ai/generate-text-to-image',
			array(
				'methods'             => 'POST',
				'callback'            => 'kubio_ai_api_generate_images',
				'permission_callback' => function () {
					return current_user_can( 'edit_theme_options' );
				},
			)
		);

		register_rest_route(
			$namespace,
			'/ai/generate-image-variations',
			array(
				'methods'             => 'POST',
				'callback'            => 'kubio_ai_api_image_variations',
				'permission_callback' => function () {
					return current_user_can( 'edit_theme_options' );
				},
			)
		);

		register_rest_route(
			$namespace,
			'/ai/image-mask',
			array(
				'methods'             => 'POST',
				'callback'            => 'kubio_ai_api_image_mask',
				'permission_callback' => function () {
					return current_user_can( 'edit_theme_options' );
				},
			)
		);

		register_rest_route(
			$namespace,
			'/ai/ai-search-images',
			array(
				'methods'             => 'POST',
				'callback'            => 'kubio_ai_search_images',
				'permission_callback' => function () {
					return current_user_can( 'edit_theme_options' );
				},
			)
		);

		register_rest_route(
			$namespace,
			'/ai/save-image',
			array(
				'methods'             => 'POST',
				'callback'            => 'kubio_ai_save_image',
				'permission_callback' => function () {
					return current_user_can( 'edit_theme_options' );
				},
			)
		);
	}
);


function kubio_ai_api_generate_images( WP_REST_Request $request ) {
	$image_generate = new Kubio\Ai\KubioImageGenerate();
	$image_style    = Kubio\Ai\KubioImagePrompts::parse_style_and_type( $request['imageType'], $request['imageStyle'] );
	$data           = array(
		'width'        => intval( $request['imageSize'][0] ),
		'height'       => intval( $request['imageSize'][1] ),
		'samples'      => $request['numberOfImages'],
		'style_preset' => $image_style['style_preset'],
		'sampler'      => 'K_DPMPP_2M',
		'steps'        => 50,
		'cfg_scale'    => 14,
	);

	$response = $image_generate->samples(
		$data,
		array( $request['imagePrompt'], $image_style['image_prompt'] )
	);

	return $response;
}

function kubio_ai_api_image_variations( WP_REST_Request $request ) {
	$image_generate = new Kubio\Ai\KubioImageGenerate();
	$image          = new Kubio\Ai\KubioImageManager();
	$image_style    = Kubio\Ai\KubioImagePrompts::parse_style_and_type( $request['imageType'], $request['imageStyle'] );

	$data = array(
		'samples'        => $request['numberOfImages'],
		'style_preset'   => $image_style['style_preset'],
		'image_strength' => 0.35,
		'init_image'     => $image->get_file_contents( $request['currentSelectedImage'] ),
	);

	return $image_generate->variations(
		$data,
		array( $request['imagePrompt'], $image_style['image_prompt'] )
	);
}

function kubio_ai_api_image_mask( WP_REST_Request $request ) {
	$image_generate = new Kubio\Ai\KubioImageGenerate();
	$image          = new Kubio\Ai\KubioImageManager();

	$data = array(
		'samples'     => 1,
		'mask_source' => 'MASK_IMAGE_BLACK',
		'mask_image'  => $request['maskImage'],
		'init_image'  => $image->get_file_contents( $request['currentSelectedImage'] ),
	);

	return $image_generate->mask(
		$data,
		$request['imagePrompt']
	);
}

function kubio_ai_search_images( WP_REST_Request $request ) {
	$image_generate = new Kubio\Ai\KubioImageSearch();

	return $image_generate->search(
		$request,
		array( 'api_dummy_response' => true )
	);
}

function kubio_ai_save_image( WP_REST_Request $request ) {
	$image_generate = new Kubio\Ai\KubioImageSearch();

	return $image_generate->save(
		$request
	);
}

function kubio_utils_data_add_ai_sd_settings( $data ) {
	$data['aiSDImageTypes']  = Kubio\Ai\KubioImagePrompts::get_image_types();
	$data['aiSDImageStyles'] = Kubio\Ai\KubioImagePrompts::get_image_styles();
	return $data;
}
add_filter( 'kubio/kubio-utils-data/extras', 'kubio_utils_data_add_ai_sd_settings' );
