<?php
namespace Kubio\Ai;
class KubioImageGenerate {
	private $api             = null;
	private $negative_prompt = 'worst quality, normal quality, low quality, low res, blurry, text, watermark, logo, banner, extra digits, cropped, jpeg artifacts, signature, username, error, sketch ,duplicate, ugly, monochrome, horror, geometry, mutation, disgusting, camera';

	function __construct( $api_key = false, $api_model = false, $api_dummy_response = false ) {
		$this->api = new KubioCloudSDApi( $api_key, $api_model, $api_dummy_response );
	}

	public function mask( array $data, $image_prompt, $settings = array() ) {
		$this->api->set_api_endpoint( 'v1/image-generation/mask' );
		$data = $this->prepare_data( $data, $image_prompt );

		$response = $this->post(
			$data,
			$settings
		);

		return $response;
	}

	public function variations( array $data, $image_prompt, $settings = array() ) {
		$this->api->set_api_endpoint( 'v1/image-generation/image-to-image' );

		$data = $this->prepare_data( $data, $image_prompt );

		$response = $this->post(
			$data,
			$settings
		);

		return $response;
	}

	public function samples( array $data, $image_prompt, $settings = array() ) {
		$this->api->set_api_endpoint( 'v1/image-generation/text-to-image' );

		$data = $this->prepare_data( $data, $image_prompt );

		$response = $this->post(
			$data,
			$settings
		);

		return $response;
	}

	private function prepare_data( $data, $image_prompt ) {
		if ( is_array( $image_prompt ) ) {
			foreach ( $image_prompt as $prompt ) {
				if ( $prompt !== '' ) {
					$data['text_prompts'][] = array(
						'text'   => $prompt,
						'weight' => 1,
					);
				}
			}

			$data['text_prompts'][] = array(
				'text'   => $this->negative_prompt,
				'weight' => -1,
			);

		} else {
			if ( $image_prompt !== '' ) {
				$data['text_prompts'] = $this->build_text_prompts( $image_prompt );
			}
		}

		return $data;
	}

	public function build_text_prompts( $image_prompt ) {
		return array(
			array(
				'text'   => $image_prompt,
				'weight' => 1,
			),
			array(
				'text'   => $this->negative_prompt,
				'weight' => -1,
			),
		);
	}

	public function set_negative_prompt( $negative_prompt ) {
		$this->negative_prompt = $negative_prompt;
	}

	private function post( $data, $files = array(), $settings = array() ) {
		$response = $this->api->post(
			$data,
			$files,
			$settings
		);

		return $response;
	}
}
