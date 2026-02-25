<?php
namespace Kubio\Ai;

use IlluminateAgnostic\Arr\Support\Arr;
use Kubio\Core\Importer;

class KubioCloudSDApi {
	private $api_key            = false;
	private $api_endpoint       = '';
	private $api_accept_type    = 'application/json';
	private $api_content_type   = 'application/json';
	private $api_dummy_response = false;

	const __DEFAULTS__ = array(
		'steps'        => 40,
		'width'        => 512,
		'height'       => 512,
		'seed'         => 0,
		'cfg_scale'    => 5,
		'samples'      => 1,
		'style_preset' => 'photographic',
	);

	function __construct( $api_key = false, $api_model = false, $api_dummy_response = false ) {
		$this->api_dummy_response = $api_dummy_response;

		// phpcs:ignore Squiz.PHP.DiscouragedFunctions.Discouraged
		@ini_set( 'max_execution_time', 70 );

		// phpcs:ignore Squiz.PHP.DiscouragedFunctions.Discouraged
		set_time_limit( 70 );
	}

	public function post( $data, $files = array() ) {
		if ( $this->api_dummy_response === true ) {
			return $data;
		}

		$response = kubio_ai_call_api(
			$this->get_api_url(),
			$data
		);

		return $this->response( $response );
	}

	public function set_api_endpoint( $api_endpoint ) {
		if ( $api_endpoint !== false ) {
			$this->api_endpoint = $api_endpoint;
		}
	}

	private function get_api_url() {
		return $this->api_endpoint;
	}

	public function set_api_accept_type( $api_accept_type ) {
		$this->api_accept_type = $api_accept_type;
	}

	public function set_api_content_type( $api_content_type ) {
		$this->api_content_type = $api_content_type;
	}

	public function response( $response ) {
		if ( is_wp_error( $response ) || array_key_exists( 'kai', $response ) ) {
			return $response;
		}

		$artifacts = Arr::get( $response, 'content.artifacts', array() );

		if ( ! count( $artifacts ) ) {
			return new \WP_Error(
				'error_no_image_generate',
				__( 'No image was generated', 'kubio' )
			);
		}

		$images = array();
		$errors = array();
		foreach ( $artifacts  as $image ) {
			$filename = wp_generate_uuid4() . '.png';
			$upload   = Importer::base64ToImage( $filename, $image['base64'] );
			if ( is_wp_error( $upload ) ) {
				$errors[] = $upload;
			} else {
				$images[] = $upload['url'];
			}
		}

		if ( ! empty( $errors ) ) {
			return $errors[0];
		}

		return array_merge(
			$response,
			array(
				'content' => $images,
			)
		);
	}

	function maybe_log_response( $resp, $section = 'text_to_image_sd', $level = 'info' ) {
		kubio_ai_log(
			$level,
			$section,
			array(),
			$resp,
			array()
		);
	}
}
