<?php

use IlluminateAgnostic\Arr\Support\Arr;
use Kubio\Core\Importer;
use Kubio\Flags;


add_action(
	'rest_api_init',
	function () {
		$namespace = 'kubio/v1';

		register_rest_route(
			$namespace,
			'/ai/info',
			array(
				'methods'             => 'POST',
				'callback'            => 'kubio_ai_get_service_info',
				'permission_callback' => function () {
					return current_user_can( 'edit_theme_options' );
				},
			)
		);

		register_rest_route(
			$namespace,
			'/ai/usage',
			array(
				'methods'             => 'POST',
				'callback'            => 'kubio_ai_get_service_usage',
				'permission_callback' => function () {
					return current_user_can( 'edit_theme_options' );
				},
			)
		);

		register_rest_route(
			$namespace,
			'/ai/set-ai-key',
			array(
				'methods'             => 'POST',
				'callback'            => 'kubio_ai_store_ai_key',
				'permission_callback' => function () {
					return current_user_can( 'edit_theme_options' );
				},
			)
		);

		register_rest_route(
			$namespace,
			'/ai/settings',
			array(
				'methods'             => 'GET',
				'callback'            => 'kubio_ai_get_general_settings',
				'permission_callback' => function () {
					return current_user_can( 'edit_theme_options' );
				},
			)
		);

		register_rest_route(
			$namespace,
			'/ai/settings',
			array(
				'methods'             => 'POST',
				'callback'            => 'kubio_ai_store_general_settings',
				'permission_callback' => function () {
					return current_user_can( 'edit_theme_options' );
				},
			)
		);

		register_rest_route(
			$namespace,
			'/ai/generate-site-structure',
			array(
				'methods'             => 'POST',
				'callback'            => 'kubio_ai_get_site_structure',
				'permission_callback' => function () {
					return current_user_can( 'edit_theme_options' );
				},
			)
		);

		register_rest_route(
			$namespace,
			'/ai/determine-site-mood',
			array(
				'methods'             => 'POST',
				'callback'            => 'kubio_ai_get_site_mood',
				'permission_callback' => function () {
					return current_user_can( 'edit_theme_options' );
				},
			)
		);

		register_rest_route(
			$namespace,
			'/ai/generate-color-scheme',
			array(
				'methods'             => 'POST',
				'callback'            => 'kubio_ai_get_color_scheme',
				'permission_callback' => function () {
					return current_user_can( 'edit_theme_options' );
				},
			)
		);

		register_rest_route(
			$namespace,
			'/ai/generate-page-structure',
			array(
				'methods'             => 'POST',
				'callback'            => 'kubio_ai_get_page_structure',
				'permission_callback' => function () {
					return current_user_can( 'edit_theme_options' );
				},
			)
		);
		register_rest_route(
			$namespace,
			'/ai/get-default-homepage-sections-summaries-by-anchor',
			array(
				'methods'             => 'POST',
				'callback'            => 'kubio_ai_get_default_homepage_sections_summaries_by_anchor',
				'permission_callback' => function () {
					return current_user_can( 'edit_theme_options' );
				},
			)
		);
		register_rest_route(
			$namespace,
			'/ai/update-default-homepage-sections-used-images',
			array(
				'methods'             => 'POST',
				'callback'            => 'kubio_ai_update_default_homepage_sections_used_images',
				'permission_callback' => function () {
					return current_user_can( 'edit_theme_options' );
				},
			)
		);
		register_rest_route(
			$namespace,
			'/ai/get-default-homepage-sections-used-images',
			array(
				'methods'             => 'POST',
				'callback'            => 'kubio_ai_get_default_homepage_sections_used_images',
				'permission_callback' => function () {
					return current_user_can( 'edit_theme_options' );
				},
			)
		);
		register_rest_route(
			$namespace,
			'/ai/generate-section-content',
			array(
				'methods'             => 'POST',
				'callback'            => 'kubio_ai_get_page_section_content',
				'permission_callback' => function () {
					return current_user_can( 'edit_theme_options' );
				},
			)
		);

		register_rest_route(
			$namespace,
			'/ai/rephrase-section-content',
			array(
				'methods'             => 'POST',
				'callback'            => 'kubio_ai_get_rephrase_section_content',
				'permission_callback' => function () {
					return current_user_can( 'edit_theme_options' );
				},
			)
		);

		register_rest_route(
			$namespace,
			'/ai/search-image',
			array(
				'methods'             => 'POST',
				'callback'            => 'kubio_ai_search_image',
				'permission_callback' => function () {
					return current_user_can( 'edit_theme_options' );
				},
			)
		);

		register_rest_route(
			$namespace,
			'/ai/search-video',
			array(
				'methods'             => 'POST',
				'callback'            => 'kubio_ai_search_video',
				'permission_callback' => function () {
					return current_user_can( 'edit_theme_options' );
				},
			)
		);

		register_rest_route(
			$namespace,
			'/ai/prompt-to-image',
			array(
				'methods'             => 'POST',
				'callback'            => 'kubio_ai_prompt_search_image',
				'permission_callback' => function () {
					return current_user_can( 'edit_theme_options' );
				},
			)
		);

		register_rest_route(
			$namespace,
			'/ai/prompt-to-video',
			array(
				'methods'             => 'POST',
				'callback'            => 'kubio_ai_prompt_search_video',
				'permission_callback' => function () {
					return current_user_can( 'edit_theme_options' );
				},
			)
		);

		register_rest_route(
			$namespace,
			'/ai/process-text',
			array(
				'methods'             => 'POST',
				'callback'            => 'kubio_ai_get_processed_text',
				'permission_callback' => function () {
					return current_user_can( 'edit_theme_options' );
				},
			)
		);

		register_rest_route(
			$namespace,
			'/ai/summarize-prompt',
			array(
				'methods'             => 'POST',
				'callback'            => 'kubio_ai_get_summarized_prompt',
				'permission_callback' => function () {
					return current_user_can( 'edit_theme_options' );
				},
			)
		);

		register_rest_route(
			$namespace,
			'/ai/prompt',
			array(
				'methods'             => 'POST',
				'callback'            => 'kubio_ai_get_prompt',
				'permission_callback' => function () {
					return current_user_can( 'edit_theme_options' );
				},
			)
		);

		register_rest_route(
			$namespace,
			'/ai/change-text',
			array(
				'methods'             => 'POST',
				'callback'            => 'kubio_ai_change_text',
				'permission_callback' => function () {
					return current_user_can( 'edit_theme_options' );
				},
			)
		);

		register_rest_route(
			$namespace,
			'/commercial-flow',
			array(
				'methods'             => 'GET',
				'callback'            => 'kubio_get_commercial_flow_settings',
				'permission_callback' => function () {
					return current_user_can( 'edit_theme_options' );
				},
			)
		);



		register_rest_route(
			$namespace,
			'/commercial-flow',
			array(
				'methods'             => 'POST',
				'callback'            => 'kubio_store_commercial_flow_settings',
				'permission_callback' => function () {
					return current_user_can( 'edit_theme_options' );
				},
			)
		);
	}
);


function kubio_ai_store_ai_key( $request ) {
	$key = sanitize_text_field( Arr::get( $request, 'key', '' ) );
	kubio_ai_set_key( $key );

	return array();
}

function kubio_ai_get_general_settings() {
	return (object) Flags::get( 'aiSettings', array() );
}


function kubio_ai_store_general_settings( WP_REST_Request $request ) {
	Flags::set( 'aiSettings', $request['settings'] );
	return true;
}

function kubio_get_commercial_flow_settings() {
	return (object) Flags::get( 'commercialFlowSettings', array() );
}


function kubio_store_commercial_flow_settings( WP_REST_Request $request ) {
	Flags::set(
		'commercialFlowSettings',
		array(
			'disabled' => $request->get_param( 'disabled' ),
		)
	);
	return true;
}

function kubio_utils_data_add_ai_settings( $data ) {
	$data['aiSettings']       = kubio_ai_get_general_settings();
	$data['aiLanguages']      = kubio_ai_content_languages();
	$data['aiLanguageStyles'] = kubio_ai_content_language_styles();
	$data['aiBusinessTypes']  = kubio_ai_business_types();
	$data['aiIsConnected']    = ! ! kubio_ai_get_key();

	return $data;
}

add_filter( 'kubio/kubio-utils-data/extras', 'kubio_utils_data_add_ai_settings' );


function kubio_ai_get_service_info() {
	return kubio_ai_call_api( 'v1/info' );
}

function kubio_ai_get_service_usage( WP_REST_Request $request ) {
	return kubio_ai_call_api(
		'v1/usage',
		array(),
		array(
			'page'     => Arr::get( $request, 'page', 1 ),
			'per_page' => Arr::get( $request, 'perPage', 20 ),
			'order'    => json_encode(
				array(
					'field'     => 'created_at',
					'direction' => 'DESC',
				)
			),
		)
	);
}

function kubio_ai_get_site_structure( WP_REST_Request $request ) {
	return kubio_ai_call_api(
		'v1/generate-site-structure',
		array(
			'siteContext'       => Arr::get( $request, 'siteContext', array() ),
			'pageContext'       => Arr::get( $request, 'pageContext', array() ),
			'pageTitle'         => Arr::get( $request, 'pageTitle', array() ),
			'theme'             => Arr::get( $request, 'theme', null ),
			'importDesignIndex' => Arr::get( $request, 'importDesignIndex', null ),
		)
	);
}


function kubio_ai_get_site_mood( WP_REST_Request $request ) {
	return kubio_ai_call_api(
		'v1/determine-site-mood',
		array(
			'siteContext' => Arr::get( $request, 'siteContext', array() ),
			'pageContext' => Arr::get( $request, 'pageContext', array() ),
			'pageTitle'   => Arr::get( $request, 'pageTitle', array() ),
		)
	);
}

function kubio_ai_get_color_scheme( WP_REST_Request $request ) {
	return kubio_ai_call_api(
		'v1/generate-color-scheme',
		array(
			'siteContext'      => Arr::get( $request, 'siteContext', array() ),
			'pageContext'      => Arr::get( $request, 'pageContext', array() ),
			'pageTitle'        => Arr::get( $request, 'pageTitle', array() ),
			'mood'             => Arr::get( $request, 'mood', 'neutral' ),
			'primaryColors'    => Arr::get( $request, 'primaryColors', array() ),
			'remainingRetries' => Arr::get( $request, 'remainingRetries', null ),
		)
	);
}


function kubio_ai_get_page_structure( WP_REST_Request $request ) {
	return kubio_ai_call_api(
		'v1/generate-page-structure',
		array(
			'siteContext' => Arr::get( $request, 'siteContext', array() ),
			'pageContext' => Arr::get( $request, 'pageContext', array() ),
			'pageTitle'   => Arr::get( $request, 'pageTitle', array() ),
			'sections'    => Arr::get( $request, 'allowedSections', array() ),
			'rules'       => Arr::get( $request, 'rules', array() ),
		)
	);
}
function kubio_ai_get_default_homepage_sections_summaries_by_anchor( WP_REST_Request $request ) {
	return kubio_ai_call_api(
		'v1/get-default-homepage-sections-summaries-by-anchor',
		array(
			'siteContext'              => Arr::get( $request, 'siteContext', array() ),
			'pageContext'              => Arr::get( $request, 'pageContext', array() ),
			'pageTitle'                => Arr::get( $request, 'pageTitle', array() ),
			'rules'                    => Arr::get( $request, 'rules', array() ),
			'theme'                    => Arr::get( $request, 'theme', null ),
			'importDesignIndex'        => Arr::get( $request, 'importDesignIndex', null ),
			'colorSchemeAndTypography' => Arr::get( $request, 'colorSchemeAndTypography', null ),
		)
	);
}


function kubio_ai_get_page_section_content( WP_REST_Request $request ) {
	return kubio_ai_call_api(
		'v1/generate-page-section',
		array(
			'siteContext'   => Arr::get( $request, 'siteContext', array() ),
			'pageContext'   => Arr::get( $request, 'pageContext', array() ),
			'pageTitle'     => Arr::get( $request, 'pageTitle', array() ),

			'structure'     => Arr::get( $request, 'structure', array() ),
			'category'      => Arr::get( $request, 'category', 'section' ),
			'summary'       => Arr::get( $request, 'summary', '' ),
			'rules'         => Arr::get( $request, 'rules', array() ),

			'sectionParams' => Arr::get( $request, 'sectionParams', array() ),
		)
	);
}

function kubio_ai_get_default_homepage_sections_used_images( WP_REST_Request $request ) {
	return kubio_ai_call_api(
		'v1/get-default-homepage-sections-used-images',
		array(
			'siteContext'       => Arr::get( $request, 'siteContext', array() ),
			'theme'             => Arr::get( $request, 'theme', null ),
			'importDesignIndex' => Arr::get( $request, 'importDesignIndex', null ),
		)
	);
}
function kubio_ai_update_default_homepage_sections_used_images( WP_REST_Request $request ) {
	return kubio_ai_call_api(
		'v1/update-default-homepage-sections-used-images',
		array(
			'siteContext'       => Arr::get( $request, 'siteContext', array() ),
			'theme'             => Arr::get( $request, 'theme', null ),
			'importDesignIndex' => Arr::get( $request, 'importDesignIndex', null ),
			'content'           => Arr::get( $request, 'content', null ),
		)
	);
}


function kubio_ai_get_rephrase_section_content( WP_REST_Request $request ) {
	return kubio_ai_call_api(
		'v1/rephrase-page-section',
		array(
			'siteContext'   => Arr::get( $request, 'siteContext', array() ),
			'pageContext'   => Arr::get( $request, 'pageContext', array() ),
			'pageTitle'     => Arr::get( $request, 'pageTitle', array() ),

			'structure'     => Arr::get( $request, 'structure', array() ),
			'category'      => Arr::get( $request, 'category', 'section' ),
			'summary'       => Arr::get( $request, 'summary', '' ),
			'rules'         => Arr::get( $request, 'rules', array() ),

			'sectionParams' => Arr::get( $request, 'sectionParams', array() ),
		)
	);
}




function kubio_ai_search_image( WP_REST_Request $request ) {
	$dimensions = array();

	if ( Arr::get( $request, 'initialImage', '' ) ) {
		// original
		$dimensions = kubio_ai_get_original_image_dimensions( Arr::get( $request, 'initialImage', '' ) );
	} else {
		$width  = Arr::get( $request, 'width', null );
		$height = Arr::get( $request, 'height', null );

		if ( $width ) {
			$dimensions['width'] = $width;
		}

		if ( $height ) {
			$dimensions['height'] = $height;
		}
	}

	$orientation = Arr::get( $request, 'orientation', null );
	if ( $orientation ) {
		$dimensions['orientation'] = $orientation;
	}

	return kubio_ai_call_api(
		'v1/search-media',
		array_merge(
			$dimensions,
			array(
				'type'             => 'image',
				'search'           => kubio_shuffle_terms( Arr::get( $request, 'search', '' ) ),
				'per_page'         => Arr::get( $request, 'perPage', 10 ),
				'page'             => Arr::get( $request, 'page', 1 ),
				'color'            => Arr::get( $request, 'color', null ),
				'media_attrs'      => Arr::get( $request, 'mediaAttrs', null ),
				'skip_orientation' => Arr::get( $request, 'skipOrientation', null ),
				'crop'             => Arr::get( $request, 'crop', null ),
			)
		)
	);
}

function kubio_shuffle_terms( $str ) {
	// use this to generate more different images between calls
	$terms = explode( ',', $str );
	if ( is_array( $terms ) ) {
		shuffle( $terms );
		return implode( ',', $terms );
	}

	return $str;
}

function kubio_ai_search_video( WP_REST_Request $request ) {

	return kubio_ai_call_api(
		'v1/search-media',
		array(
			'type'        => 'video',
			'search'      => Arr::get( $request, 'search', '' ),
			'per_page'    => Arr::get( $request, 'perPage', 10 ),
			'page'        => Arr::get( $request, 'page', 1 ),
			'media_attrs' => Arr::get( $request, 'mediaAttrs', null ),
		)
	);
}

function kubio_ai_prompt_search_image( WP_REST_Request $request ) {
	$dimensions = kubio_ai_get_original_image_dimensions( Arr::get( $request, 'initialImage', '' ) );
	return kubio_ai_call_api(
		'v1/prompt-search-media',
		array_merge(
			$dimensions,
			array(
				'type'        => 'image',
				'prompt'      => Arr::get( $request, 'prompt', '' ),
				'per_page'    => Arr::get( $request, 'perPage', 10 ),
				'page'        => Arr::get( $request, 'page', 1 ),
				'media_attrs' => Arr::get( $request, 'mediaAttrs', null ),
			)
		)
	);
}

function kubio_ai_prompt_search_video( WP_REST_Request $request ) {
	return kubio_ai_call_api(
		'v1/prompt-search-media',
		array(
			'type'        => 'video',
			'prompt'      => Arr::get( $request, 'prompt', '' ),
			'per_page'    => Arr::get( $request, 'perPage', 10 ),
			'page'        => Arr::get( $request, 'page', 1 ),
			'media_attrs' => Arr::get( $request, 'mediaAttrs', null ),
		)
	);
}

// ---------------



function kubio_ai_get_processed_text( WP_REST_Request $request ) {

	return kubio_ai_call_api(
		'v1/process-text',
		array(
			'siteContext' => Arr::get( $request, 'siteContext', array() ),
			'pageContext' => Arr::get( $request, 'pageContext', array() ),
			'pageTitle'   => Arr::get( $request, 'pageTitle', array() ),
			'action'      => Arr::get( $request, 'action', '' ),
			'content'     => Arr::get( $request, 'content', '' ),
			'extras'      => Arr::get( $request, 'extras', '' ),

		)
	);
}



function kubio_ai_get_summarized_prompt( WP_REST_Request $request ) {
	return kubio_ai_call_api(
		'v1/process-text',
		array(
			'siteContext' => Arr::get( $request, 'siteContext', array() ),
			'pageContext' => Arr::get( $request, 'pageContext', array() ),
			'pageTitle'   => Arr::get( $request, 'pageTitle', array() ),
			'action'      => 'summarize',
			'content'     => Arr::get( $request, 'prompt', '' ),
		)
	);
}
function kubio_ai_get_prompt( WP_REST_Request $request ) {
	return kubio_ai_call_api(
		'v1/process-text',
		array(
			'siteContext' => Arr::get( $request, 'siteContext', array() ),
			'pageContext' => Arr::get( $request, 'pageContext', array() ),
			'pageTitle'   => Arr::get( $request, 'pageTitle', array() ),
			'action'      => 'prompt',
			'prompt'      => Arr::get( $request, 'prompt', '' ),
			'original'    => Arr::get( $request, 'originalContent', '' ),
			'short'       => Arr::get( $request, 'short', false ),
			'type'        => Arr::get( $request, 'type', 'text' ),
		)
	);
}


function kubio_ai_change_text( WP_REST_Request $request ) {

	return kubio_ai_call_api(
		'v1/process-text',
		array(
			'siteContext' => Arr::get( $request, 'siteContext', array() ),
			'pageContext' => Arr::get( $request, 'pageContext', array() ),
			'pageTitle'   => Arr::get( $request, 'pageTitle', array() ),
			'action'      => Arr::get( $request, 'type', 'tone' ),
			'to'          => Arr::get( $request, 'promptData', '' ),
			'content'     => Arr::get( $request, 'text', '' ),
		)
	);
}

function kubio_ai_sd_image_from_text( WP_REST_Request $request ) {

	$image_size           = Arr::get( $request, 'imageSize', array( 1024, 1024 ) );
	list($width, $height) = kubio_ai_sd_xl_determine_appropriate_size( ...$image_size );

	$response = kubio_ai_call_api(
		'v1/image-generation/text-to-image',
		array(
			'steps'        => 40,
			'width'        => 512,
			'height'       => 512,
			'seed'         => 0,
			'cfg_scale'    => 5,
			'samples'      => 1,
			'style_preset' => 'photographic',
			'text_prompts' => array(
				array(
					'text'   => Arr::get( $request, 'prompt', '' ),
					'weight' => 1,
				),
				array(
					'text'   => 'blurry, bad',
					'weight' => -1,
				),
			),
			'width'        => $width,
			'height'       => $height,
		)
	);

	if ( is_wp_error( $response ) ) {
		return $response;
	}

	$artifacts = Arr::get( $response, 'artifacts', array() );

	if ( ! count( $artifacts ) ) {
		return new \WP_Error(
			'error_no_image_generate',
			__( 'No image was generated', 'kubio' )
		);
	}

	$images = array();
	$errors = array();
	foreach ( $artifacts  as $image ) {
		$filename = wp_generate_uuid4() . '.jpg';
		$upload   = Importer::base64ToImage( $filename, $image['base64'] );
		if ( is_wp_error( $upload ) ) {
			$errors[] = $upload;
		} else {
			$images[] = $upload;
		}
	}

	if ( ! empty( $errors ) ) {
		return $errors[0];
	}

	return $images[0]['url'];
}


