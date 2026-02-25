<?php

namespace Kubio;
use Kubio\Core\LodashBasic;
use function file_get_contents;
use function json_decode;
use const KUBIO_ROOT_DIR;

class Config {
	public static $name = 'kubio';

	public static $mainAttributeKey;
	public static $elementsKey;
	public static $elementsEnum;
	public static $statesKey;

	public static $config_types = array();


	private static $medias_by_id = null;
	private static $states_by_id = null;

	public static function load() {
		$types_f            = KUBIO_ROOT_DIR . 'build/types.json';
		self::$config_types = apply_filters( 'kubio/style-types', json_decode( file_get_contents( $types_f ), true ) );

		self::$mainAttributeKey = Config::value( 'constants.support.mainAttributeKey' );
		self::$elementsKey      = Config::value( 'constants.support.elementsKey' );
		self::$elementsEnum     = Config::value( 'constants.support.elementsEnum' );
		self::$statesKey        = Config::value( 'constants.support.statesKey' );
	}


	public static function value( $path, $fallback = null ) {
		return LodashBasic::get( self::$config_types, $path, $fallback );
	}

	public static function mediasById() {

		if ( static::$medias_by_id ) {
			return static::$medias_by_id;
		}

		$items  = self::value( 'medias' );
		$result = array();

		foreach ( $items as $item ) {
			$result[ $item['id'] ] = $item;
		}

		static::$medias_by_id = $result;
		return static::$medias_by_id;
	}

	public static function statesById() {

		if ( static::$states_by_id ) {
			return static::$states_by_id;
		}

		$items  = self::value( 'states' );
		$result = array();

		foreach ( $items as $item ) {
			$result[ $item['id'] ] = $item;
		}

		static::$states_by_id = $result;
		return static::$states_by_id;
	}
}


Config::load();
