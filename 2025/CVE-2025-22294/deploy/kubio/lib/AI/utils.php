<?php

use IlluminateAgnostic\Arr\Support\Arr;
use Kubio\Core\LodashBasic;
use Kubio\Core\Utils;
use Kubio\FileLog;
use Kubio\Flags;

function kubio_ai_content_languages() {
	return array(
		'ar_AR' => 'العربية (Arabic)',
		'az_AZ' => 'Azərbaycan dili (Azerbaijani)',
		'bn_BD' => 'বাংলা (Bengali)',
		'cs_CZ' => 'Čeština (Czech)',
		'cy_GB' => 'Cymraeg (Welsh)',
		'da_DK' => 'Dansk (Danish)',
		'de_DE' => 'Deutsch (German)',
		'el_GR' => 'Ελληνικά (Greek)',
		'en_US' => 'English US',
		'en_GB' => 'English GB (United Kingdom English)',
		'en_AU' => 'English AU (Australian English)',
		'en_CA' => 'English CA (Canadian English)',
		'es_ES' => 'Español (Spanish)',
		'es_MX' => 'Español MX (Mexican Spanish)',
		'et_EE' => 'Eesti keel (Estonian)',
		'fa_IR' => 'فارسی (Persian)',
		'fi_FI' => 'Suomi (Finnish)',
		'fr_FR' => 'Français (French)',
		'fr_CA' => 'Français CA (Canadian French)',
		'ga_IE' => 'Gaeilge (Irish)',
		'he_IL' => 'עברית (Hebrew)',
		'hi_IN' => 'हिन्दी (Hindi)',
		'hr_HR' => 'Hrvatski (Croatian)',
		'hu_HU' => 'Magyar (Hungarian)',
		'hy_AM' => 'Հայերեն (Armenian)',
		'id_ID' => 'Bahasa Indonesia (Indonesian)',
		'is_IS' => 'Íslenska (Icelandic)',
		'it_IT' => 'Italiano (Italian)',
		'ja_JP' => '日本語 (Japanese)',
		'ka_GE' => 'ქართული (Georgian)',
		'kk_KZ' => 'Қазақ тілі (Kazakh)',
		'ko_KR' => '한국어 (Korean)',
		'lt_LT' => 'Lietuvių kalba (Lithuanian)',
		'lv_LV' => 'Latviešu valoda (Latvian)',
		'ms_MY' => 'Bahasa Melayu (Malay)',
		'nb_NO' => 'Norsk bokmål (Norwegian Bokmål)',
		'nl_NL' => 'Nederlands (Dutch)',
		'pl_PL' => 'Polski (Polish)',
		'pt_PT' => 'Português (Portuguese)',
		'pt_BR' => 'Português BR (Portuguese Brasil)',
		'ro_RO' => 'Română (Romanian)',
		'ru_RU' => 'Русский (Russian)',
		'sk_SK' => 'Slovenčina (Slovak)',
		'sl_SI' => 'Slovenščina (Slovenian)',
		'sq_AL' => 'Shqip (Albanian)',
		'sr_RS' => 'Српски (Serbian)',
		'sv_SE' => 'Svenska (Swedish)',
		'ta_IN' => 'தமிழ் (Tamil)',
		'th_TH' => 'ไทย (Thai)',
		'tr_TR' => 'Türkçe (Turkish)',
		'uk_UA' => 'Українська (Ukrainian)',
		'ur_PK' => 'اردو (Urdu)',
		'vi_VN' => 'Tiếng Việt (Vietnamese)',
		'zh_CN' => '中文 (Chinese Simplified)',
		'zh_TW' => '中文 (Chinese Traditional)',
	);
}


function kubio_ai_content_language_styles() {
	return array(
		'natural'    => array(
			'label'       => __( 'Natural', 'kubio' ),
			'description' => __( 'Is the default language style. It can adapt to some extent depending on the cues from the user\'s input.', 'kubio' ),
		),
		'formal'     => array(
			'label'       => __( 'Formal', 'kubio' ),
			'description' => __( 'Used in official documents, academic papers, and professional communication, characterized by complex sentence structures, precise vocabulary, and avoidance of contractions and slang.', 'kubio' ),
		),
		'informal'   => array(
			'label'       => __( 'Informal', 'kubio' ),
			'description' => __( 'Casual and relaxed style used in everyday conversations, personal emails, and informal writing. It often includes contractions, colloquialisms, and a more relaxed sentence structure.', 'kubio' ),
		),
		'technical'  => array(
			'label'       => __( 'Technical', 'kubio' ),
			'description' => __( 'Specific to a particular field or industry, this style uses terminology and jargon understood by experts in that field. It aims for clear and precise communication within that domain.', 'kubio' ),
		),

		'persuasive' => array(
			'label'       => __( 'Persuasive', 'kubio' ),
			'description' => __( "Used to convince or influence the reader's opinion, often employing rhetoric, emotional appeals, and strong arguments to present a particular viewpoint.", 'kubio' ),
		),
		'humorous'   => array(
			'label'       => __( 'Humorous', 'kubio' ),
			'description' => __( 'Intended to amuse the reader, this style uses wit, sarcasm, irony, and clever wordplay to evoke laughter or amusement.', 'kubio' ),
		),

	);
}

function kubio_ai_business_types() {
	return array(
		array(
			'label'       => __( 'Business', 'kubio' ),
			'value'       => 'Business',
			'description' => __( 'Resources and insights for starting, managing, and growing businesses.', 'kubio' ),
		),
		array(
			'label'       => __( 'Services', 'kubio' ),
			'value'       => 'Services',
			'description' => __( 'Promoting and detailing services offered by professionals or businesses.', 'kubio' ),
		),
		array(
			'label'       => __( 'Consulting', 'kubio' ),
			'value'       => 'Consulting',
			'description' => __( 'Offering expert advice, insights, and solutions in specialized fields.', 'kubio' ),
		),

		array(
			'label'       => __( 'Art / Design Portfolio', 'kubio' ),
			'value'       => 'Art / Design Portfolio',
			'description' => __( 'Showcasing artistic and design work, including portfolios, projects, and creative endeavors.', 'kubio' ),
		),

		array(
			'label'       => __( 'Community & Non-profit', 'kubio' ),
			'value'       => 'Community & Non-profit',
			'description' => __( 'Highlighting community initiatives, nonprofit organizations, and philanthropic efforts for social good.', 'kubio' ),
		),
		array(
			'label'       => __( 'Personal', 'kubio' ),
			'value'       => 'Personal',
			'description' => __( 'A platform for sharing personal experiences, thoughts, and interests.', 'kubio' ),
		),
		array(
			'label'       => __( 'Event', 'kubio' ),
			'value'       => 'Event',
			'description' => __( 'Information and details about upcoming events, conferences, or gatherings.', 'kubio' ),
		),

		array(
			'label'       => __( 'Educational', 'kubio' ),
			'value'       => 'Educational',
			'description' => __( 'Online presence for educational institutions, showcasing courses, programs, and achievements.', 'kubio' ),
		),

		array(
			'label'       => __( 'Food & Drink', 'kubio' ),
			'value'       => 'Food & Drink',
			'description' => __( 'Exploring culinary delights, recipes, and beverage-related content.', 'kubio' ),
		),

		array(
			'label'       => __( 'Health & Fitness', 'kubio' ),
			'value'       => 'Health & Fitness',
			'description' => __( 'Promoting a healthy lifestyle, fitness routines, and well-being tips.', 'kubio' ),
		),

		array(
			'label'       => __( 'Fashion & Beauty', 'kubio' ),
			'value'       => 'Fashion & Beauty',
			'description' => __( 'Showcasing the latest fashion trends, beauty tips, and style advice.', 'kubio' ),
		),

		array(
			'label'       => __( 'Technology & Gadgets', 'kubio' ),
			'value'       => 'Technology & Gadgets',
			'description' => __( 'Exploring the world of tech, gadgets, and digital innovations.', 'kubio' ),
		),

		array(
			'label'       => __( 'Gaming', 'kubio' ),
			'value'       => 'Gaming',
			'description' => __( 'Exploring the world of gaming, video games, and esports.', 'kubio' ),
		),

	);
}

function kubio_ai_log( $type, $code, $prompts, $completion, $usage = array(), $call_id = null ) {

	if ( defined( 'KUBIO_AI_LOG' ) && KUBIO_AI_LOG ) {
		kubio_replace_base64_strings( $completion );

		return FileLog::with_type( FileLog::JSONL_LOG )->$type(
			'AI',
			array(
				'call_id'    => $call_id,
				'code'       => $code,
				'prompts'    => $prompts,
				'completion' => $completion,
				'start_time' => Arr::get( $usage, 'start_time', 0 ),
				'usage'      => array_merge(
					array(
						'prompt_tokens'     => 0,
						'completion_tokens' => 0,
						'total_tokens'      => 0,
					),
					$usage
				),
			)
		);
	}
}

function kubio_replace_base64_strings( &$array, $max_length = 500, $replace_with = '[blob]' ) {
	if ( ! is_array(
		$array
	) ) {
		return false;
	}

	foreach ( $array as $key => &$value ) {
		if ( is_array( $value ) ) {
			kubio_replace_base64_strings(
				$value,
				$max_length,
				$replace_with
			);
		} elseif ( is_string( $value ) && strlen( $value ) > $max_length && kubio_is_base64( $value ) ) {
			$array[ $key ] = $replace_with;
		}
	}
}

function kubio_is_base64( $string ) {
	return base64_decode( $string, true ) !== false;
}

function kubio_ai_sd_xl_determine_appropriate_size( $width, $height ) {

	$ar_range     = 0.2;
	$aspect_ratio = $width / $height;

	$sizes = array(
		640  => 1536,
		768  => 1344,
		832  => 1216,
		896  => 1152,
		1024 => 1024,
		1152 => 896,
		1216 => 832,
	);

	$heights_in_range = array();
	foreach ( $sizes as $possible_height => $possible_width ) {
		$possible_ar    = $possible_width / $possible_height;
		$ar_is_in_range = $aspect_ratio * ( 1 - $ar_range ) <= $possible_ar && $possible_ar <= $aspect_ratio * ( 1 + $ar_range );

		if ( $ar_is_in_range ) {
			$heights_in_range[] = $possible_height;
		}
	}

	$final_height = empty( $heights_in_range ) ? 1024 : array_shift( $heights_in_range );

	foreach ( $heights_in_range as $possible_height ) {
		if ( $possible_height > $height ) {
			break;
		}

		$final_height = $height;
	}

	return array( $sizes[ $final_height ], $final_height );
}

function kubio_ai_get_original_image_dimensions( $imag_url ) {

	if ( ! function_exists( 'download_url' ) ) {
		require_once ABSPATH . '/wp-admin/includes/file.php';
	}

	$temp_file       = download_url( $imag_url );
	$image_threshold = 0.2;

	if ( is_wp_error( $temp_file ) ) {
		return array(
			'width'       => 1920,
			'height'      => 1080,
			'orientation' => 'landscape',
		);
	}

	$image_size = getimagesize( $temp_file );

	if ( $image_size === false ) {

		return array(
			'width'       => 1920,
			'height'      => 1080,
			'orientation' => 'landscape',
		);
	}

	list($width, $height) = $image_size;

	wp_delete_file( $temp_file );

	$ratio       = floor( $width / $height * 100 ) / 100;
	$orientation = $ratio < 1 ? 'portrait' : 'landscape';

	if ( ( 1 - $image_threshold ) < $ratio && $ratio < ( 1 + $image_threshold ) ) {
		$orientation = 'square';
	}

	return array(
		'width'       => $width,
		'height'      => $height,
		'orientation' => $orientation,
	);
}

/**
 *
 * @param  string $path
 * @param  array $payload
 * @param  array  $extra
 * @return mixed|null|WP_Error
 */
function kubio_ai_call_api( $path, $payload = array(), $extra = array() ) {

	// phpcs:ignore WordPress.Security.NonceVerification.Recommended, WordPress.Security.ValidatedSanitizedInput.MissingUnslash, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized 
	$is_guest = isset( $_GET['is_guest'] ) && ! ! $_GET['is_guest'];
	// phpcs:ignore WordPress.Security.NonceVerification.Recommended, WordPress.Security.ValidatedSanitizedInput.MissingUnslash, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized 
	$skip_ai_cache = isset( $_GET['skip_ai_cache'] ) && ! ! $_GET['skip_ai_cache'];
	$timeout       = 120;

	// phpcs:ignore Squiz.PHP.DiscouragedFunctions.Discouraged
	ini_set( 'max_execution_time', $timeout );
	// phpcs:ignore Squiz.PHP.DiscouragedFunctions.Discouraged
	set_time_limit( $timeout );

	$log = defined( 'KUBIO_AI_LOG' ) ? KUBIO_AI_LOG : false;
	if ( ! $is_guest ) {
		$base_url = Utils::getCloudURL( "/api/ai/$path" );
	} else {
		$base_url = Utils::getCloudURL( "/api/ai-guest/$path" );
	}

	$url = add_query_arg(
		array(
			'ai_debug' => $log ? 1 : 0,
		),
		$base_url
	);

	$start_time = microtime( true );
	$filter     = "kubio_ai_response_{$path}";
	// add a filter
	if ( has_filter( $filter ) ) {
		$response = apply_filters( $filter, $payload );

		return $response;
	}
	$extra_headers = array();
	if ( $skip_ai_cache ) {
		$extra_headers['X-Kubio-AI-Skip-Cache'] = '1';
	}
	$response = wp_remote_post(
		$url,
		array(
			'timeout'   => $timeout - 1,
			'sslverify' => false,
			'headers'   => array_merge(
				array(
					'Content-Type'      => 'application/json',
					'Accept'            => 'application/json',
					'X-Kubio-AI-Key'    => kubio_ai_get_key(),
					'X-Kubio-Site-UUID' => Flags::getSiteUUID(),
					'X-Kubio-Site-URL'  => get_bloginfo( 'url' ),
				),
				$extra_headers
			),
			'body'      => json_encode(
				array_merge(
					array(
						'params' => $payload,
					),
					$extra
				)
			),
		)
	);

	if ( is_wp_error( $response ) ) {
		return $response;
	}

	$code = wp_remote_retrieve_response_code( $response );

	$result           = null;
	$debug_content    = array();
	$response_content = null;

	if ( $code !== 200 ) {
		$response_content = wp_remote_retrieve_body( $response );
		$body             = json_decode( $response_content, true );
		$error            = Arr::get( (array) $body, 'error', null );
		if ( $error ) {
			$result = new \WP_Error(
				Arr::get( $error, 'code', '' ),
				Arr::get( $error, 'message', '' ),
				$response_content
			);
		} else {
			$result = new \WP_Error(
				$code,
				// translators: %s is the error message
				sprintf( __( 'AI Server error: %s', 'kubio' ), Arr::get( $error, 'message', '' ) ),
				$response_content
			);
		}
	} else {
		$response_content = wp_remote_retrieve_body( $response );
		$body             = json_decode( $response_content, true );

		$result = array(
			'content'      => Arr::get( is_array( $body ) ? $body : array(), 'content', null ),
			'service_info' => (object) Arr::get( $body, 'service_info', array() ),
		);

		if ( ! is_array( $body ) ) {
			$result = new WP_Error(
				'ai_response_not_json',
				__( 'AI response is invalid', 'kubio' ),
				$response_content
			);
		} else {

			$error         = $body['error'];
			$debug_content = Arr::get( $body, 'debug', array() );

			if ( $error ) {
				$result = new WP_Error(
					$error['code'],
					$error['message'],
					array_merge(
						array( 'debug' => LodashBasic::omit( $debug_content, array( 'messages' ) ) ),
						$result
					)
				);
			}
		}
	}

	if ( $log ) {
		$messages = array_merge(
			array(
				array(
					'role'    => 'api payload',
					'content' => json_encode( $payload, JSON_PRETTY_PRINT ),
				),
			),
			Arr::get(
				$debug_content,
				'messages',
				array()
			)
		);

		$log_response = Arr::get( $debug_content, 'response_raw', array() );

		if ( is_wp_error( $result ) ) {

			$response_messages = array();
			foreach ( $result->get_all_error_data() as $error_data ) {
				$error_data = Utils::maybeJSONDecode( $error_data );
				if ( is_array( $error_data ) ) {
					$response_messages[] = Arr::get( $error_data, 'debug', $error_data );
				} else {
					$response_messages[] = $error_data;
				}
			}

			$log_response = array(
				'error_codes'       => $result->get_error_codes(),
				'error_messages'    => $result->get_error_messages(),
				'response_messages' => $response_messages,
			);
		}

		if ( $result === null ) {
			$result       = new WP_Error( 'ai_response_not_json', __( 'AI response is invalid ( Empty response )', 'kubio' ) );
			$log_response = wp_remote_retrieve_body( $response );
		}

		$log_code = $path;
		if ( strpos( $path, '/generate-page-section' ) !== false || strpos( $path, '/rephrase-page-section' ) !== false ) {
			$log_code = sprintf( '%s ( %s )', $log_code, Arr::get( $payload, 'category', 'N/A' ) );
		}

		kubio_ai_log(
			is_wp_error( $result ) ? 'error' : 'info',
			$log_code,
			$messages,
			$log_response,
			array(
				'start_time'        => $start_time,
				'total_tokens'      => Arr::get( $debug_content, 'total_tokens', 0 ),
				'prompt_tokens'     => Arr::get( $debug_content, 'prompt_tokens', 0 ),
				'completion_tokens' => Arr::get( $debug_content, 'completion_tokens', 0 ),
			),
			// phpcs:ignore WordPress.Security.NonceVerification.Recommended
			sanitize_text_field( Arr::get( $_REQUEST, '__kubio_call_id', null ) )
		);
	}

	if ( is_array( $result ) ) {
		$result['upgrade_key'] = sprintf( 'ai:%s', apply_filters( 'kubio/ai/upgrade-key', base64_encode( kubio_ai_get_key() ) ) );
	}

	return $result;
}
