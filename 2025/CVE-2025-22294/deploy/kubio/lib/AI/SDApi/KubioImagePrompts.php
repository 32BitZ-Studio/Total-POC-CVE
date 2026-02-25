<?php
namespace Kubio\Ai;

class KubioImagePrompts {
	const STYLE_PHOTOGRAPHIC     = 'photographic';
	const STYLE_3D_MODEL         = '3d-model';
	const STYLE_BACKGROUND_IMAGE = 'tile-texture';
	const STYLE_DIGITAL_ART      = 'digital-art';
	const STYLE_PAINTING         = 'painting';

	public static function get_image_types() {
		return array(
			self::STYLE_PHOTOGRAPHIC     => __( 'Photographic', 'kubio' ),
			self::STYLE_3D_MODEL         => __( '3D Model', 'kubio' ),
			self::STYLE_BACKGROUND_IMAGE => __( 'Background image', 'kubio' ),
			self::STYLE_DIGITAL_ART      => __( 'Digital Art', 'kubio' ),
			self::STYLE_PAINTING         => __( 'Artistic painting', 'kubio' ),
		);
	}

	public static function get_image_styles() {
		return array(
			self::STYLE_PHOTOGRAPHIC     => array(
				'landscape'     => __( 'Landscape', 'kubio' ),
				'macro'         => __( 'Macro', 'kubio' ),
				'portrait'      => __( 'Portrait', 'kubio' ),
				'long-exposure' => __( 'Long Exposure', 'kubio' ),
			),

			self::STYLE_3D_MODEL         => array(
				'clay'    => __( 'Clay', 'kubio' ),
				'digital' => __( 'Digital', 'kubio' ),
				'origami' => __( 'Origami', 'kubio' ),
				'stone'   => __( 'Stone sculpture', 'kubio' ),
				'wood'    => __( 'Wood sculpture', 'kubio' ),
			),

			self::STYLE_BACKGROUND_IMAGE => array(
				'floral'   => __( 'Floral', 'kubio' ),
				'gradient' => __( 'Gradient', 'kubio' ),
				'mosaic'   => __( 'Mosaic', 'kubio' ),
				'neon'     => __( 'Neon', 'kubio' ),
				'bokeh'    => __( 'Bokeh', 'kubio' ),
			),

			self::STYLE_DIGITAL_ART      => array(
				'anime'       => __( 'Anime', 'kubio' ),
				'cartoon'     => __( 'Cartoon', 'kubio' ),
				'cinematic'   => __( 'Cinematic', 'kubio' ),
				'comic-book'  => __( 'Comic Book', 'kubio' ),
				'fantasy-art' => __( 'Fantasy Art', 'kubio' ),
				'isometric'   => __( 'Isometric', 'kubio' ),
				'vector'      => __( 'Vector', 'kubio' ),
				'pixel-art'   => __( 'Pixel Art', 'kubio' ),
				'low-poly'    => __( 'Low Poly', 'kubio' ),
				'neon-punk'   => __( 'Neon Punk', 'kubio' ),
			),

			self::STYLE_PAINTING         => array(
				'doodle'         => __( 'Doodle', 'kubio' ),
				'line-art'       => __( 'Line Art', 'kubio' ),
				'oil-painting'   => __( 'Oil Painting', 'kubio' ),
				'pencil-drawing' => __( 'Pencil Drawing', 'kubio' ),
				'watercolor'     => __( 'Watercolor', 'kubio' ),
			),

		);
	}

	static function parse_style_and_type( $image_type, $image_style = '' ) {
		switch ( $image_type ) {
			case self::STYLE_PHOTOGRAPHIC:
				return self::image_photographic( $image_style );

			case self::STYLE_3D_MODEL:
				return self::image_3d_model( $image_style );

			case self::STYLE_BACKGROUND_IMAGE:
				return self::image_background( $image_style );

			case self::STYLE_DIGITAL_ART:
				return self::image_digital_art( $image_style );

			case self::STYLE_PAINTING:
				return self::image_painting( $image_style );
			default:
				return self::format_response( self::STYLE_PHOTOGRAPHIC, '' );
		}
	}

	static function image_photographic( $image_style ) {
		switch ( $image_style ) {
			case 'macro':
				return self::format_response( self::STYLE_PHOTOGRAPHIC, 'macro photography' );
			case 'portrait':
				return self::format_response( self::STYLE_PHOTOGRAPHIC, 'portrait photography' );
			case 'long-exposure':
				return self::format_response( self::STYLE_PHOTOGRAPHIC, 'long-exposure photography' );
			case 'landscape':
				return self::format_response( self::STYLE_PHOTOGRAPHIC, 'landscape photography' );
			default:
				return self::format_response( self::STYLE_PHOTOGRAPHIC );
		}
	}

	static function image_3d_model( $image_style ) {
		switch ( $image_style ) {
			case 'clay':
				return self::format_response( self::STYLE_3D_MODEL, 'clay material, detailed clay texture, depth of field, ultra detailed' );

			case 'origami':
				return self::format_response( 'origami' );
			case 'stone':
				return self::format_response( self::STYLE_3D_MODEL, 'carved stone sculpture, stone material, detailed stone texture' );
			case 'wood':
				return self::format_response( self::STYLE_3D_MODEL, 'carved wood sculpture, wood material, detailed wood texture' );
			case 'digital':
			default:
				return self::format_response( self::STYLE_3D_MODEL, '3D modelling, 3Ds Max rendered, octane rendered, CG' );
		}
	}

	static function image_background( $image_style ) {
		switch ( $image_style ) {
			case 'floral':
				return self::format_response( self::STYLE_BACKGROUND_IMAGE, 'floral pattern, background pattern' );
			case 'gradient':
				return self::format_response( self::STYLE_BACKGROUND_IMAGE, 'gradient pattern, background pattern' );
			case 'mosaic':
				return self::format_response( self::STYLE_BACKGROUND_IMAGE, 'mosaic tiles, background pattern' );
			case 'neon':
				return self::format_response( self::STYLE_BACKGROUND_IMAGE, 'neon pattern, neon colors, background pattern' );
			case 'bokeh':
				return self::format_response( self::STYLE_BACKGROUND_IMAGE, 'bokeh pattern, background pattern' );
			default:
				return self::format_response( self::STYLE_BACKGROUND_IMAGE, 'background pattern' );
		}
	}

	static function image_digital_art( $image_style ) {
		switch ( $image_style ) {
			case 'anime':
				return self::format_response( 'anime' );
			case 'cartoon':
				return self::format_response( self::STYLE_DIGITAL_ART, 'cartoon drawing' );
			case 'cinematic':
				return self::format_response( 'cinematic' );
			case 'comic-book':
				return self::format_response( 'comic-book' );
			case 'fantasy-art':
				return self::format_response( 'fantasy-art', 'digital artwork' );
			case 'isometric':
				return self::format_response( 'isometric' );
			case 'vector':
				return self::format_response( self::STYLE_DIGITAL_ART, ' vector graphics' );
			case 'pixel-art':
				return self::format_response( 'pixel-art', 'retro pixel art' );
			case 'low-poly':
				return self::format_response( 'low-poly' );
			case 'neon-punk':
				return self::format_response( 'neon-punk' );

			default:
				return self::format_response( self::STYLE_DIGITAL_ART );
		}
	}

	static function image_painting( $image_style ) {
		switch ( $image_style ) {
			case 'doodle':
				return self::format_response( 'line-art', 'doodle art, sketch art, artist sketch, black and white drawing, outline' );
			case 'line-art':
				return self::format_response( 'line-art', 'line art, black and white drawing' );
			case 'oil-painting':
				return self::format_response( 'digital-art', 'oil-painting' );
			case 'pencil-drawing':
				return self::format_response( 'line-art', 'artistic pencil drawing, black and white drawing, crayon' );
			case 'watercolor':
				return self::format_response( 'digital-art', 'watercolor painting, in the style of realistic painter' );
			default:
				return self::format_response( 'digital-art', 'watercolor painting' );
		}
	}

	static function format_response( $preset, $prompt = '' ) {
		return array(
			'style_preset' => $preset,
			'image_prompt' => $prompt,
		);
	}
}
