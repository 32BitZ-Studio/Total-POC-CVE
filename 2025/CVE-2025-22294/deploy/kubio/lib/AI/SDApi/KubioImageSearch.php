<?php
namespace Kubio\Ai;
use IlluminateAgnostic\Arr\Support\Arr;
use Kubio\Core\Importer;

class KubioImageSearch {
	public function search( $request, $settings = array() ) {
		$dimensions = $this->get_image_dimensions( $request );
		$api_url    = 'v1/search-media';
		$ai_prompt  = Arr::get( $request, 'aiPrompt', '' );
		$search     = Arr::get( $request, 'search', '' );

		if ( $ai_prompt === '' ) {
			$api_url = 'v1/prompt-search-media';
		} else {
			$search = $ai_prompt;
		}

		$response = kubio_ai_call_api(
			$api_url,
			array_merge(
				$dimensions,
				array(
					'type'        => 'image',
					'prompt'      => $search,
					'search'      => $search,
					'per_page'    => Arr::get( $request, 'perPage', 10 ),
					'page'        => Arr::get( $request, 'page', 1 ),
					'size'        => Arr::get( $request, 'imageSize', 'medium' ),
					'orientation' => Arr::get( $request, 'imageOrientation', 'portrait' ),
					'media_attrs' => array(
						'src.medium',
					),
				)
			)
		);

		return $response;
	}

	public function save( $request ) {
		$image = Arr::get( $request, 'selectedImage', 10 );
		$file  = Importer::importRemoteFile( $image );

		return array( 'content' => $file );
	}

	public function get_image_dimensions( $request ) {
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

		return $dimensions;
	}
}
