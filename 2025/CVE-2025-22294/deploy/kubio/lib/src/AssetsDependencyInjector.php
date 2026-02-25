<?php

namespace Kubio;

use IlluminateAgnostic\Arr\Support\Arr;

class AssetsDependencyInjector {


	const KUBIO_DEPENENCY_PREFIX = 'kubio--dep-';

	private static $dependencies_to_inject = array(
		'style'  => array(),
		'script' => array(),
	);


	public static function injectDependencies( $type, $handle, $dependencies ) {
		$dependencies = Arr::wrap( $dependencies );

		$items = null;

		if ( $type === 'style' ) {
			$items = \wp_styles();
		} else {
			$items = \wp_scripts();
		}

		$target = Arr::get( $items->registered, $handle, null );

		foreach ( $dependencies as $dependency ) {
			$items->enqueue( $dependency );
		}

		if ( ! $target ) {
			static::$dependencies_to_inject[ $handle ] = array_unique(
				array_merge(
					Arr::get( static::$dependencies_to_inject, $handle, array() ),
					$dependencies
				)
			);
		} else {
			$target->deps = array_unique( array_merge( $target->deps, $dependencies ) );
		}
	}

	public static function injectScriptDependencies( $handle, $dependencies ) {
		return self::injectDependencies( 'script', $handle, $dependencies );
	}

	public static function injectStyleDependencies( $handle, $dependencies ) {
		return self::injectDependencies( 'style', $handle, $dependencies );
	}

	public static function injectKubioScriptDependencies( $dependencies, $prefix = true ) {
		$dependencies = Arr::wrap( $dependencies );
		if ( $prefix ) {
			$dependencies = array_map(
				function ( $handle ) {
					return AssetsDependencyInjector::KUBIO_DEPENENCY_PREFIX . $handle;
				},
				$dependencies
			);
		}

		self::injectScriptDependencies( 'kubio-scripts', $dependencies );
	}

	public static function injectKubioFrontendStyleDependencies( $dependencies, $prefix = true ) {
		$dependencies = Arr::wrap( $dependencies );
		if ( $prefix ) {
			$dependencies = array_map(
				function ( $handle ) {
					return AssetsDependencyInjector::KUBIO_DEPENENCY_PREFIX . $handle;
				},
				$dependencies
			);
		}

		self::injectStyleDependencies( 'kubio-block-library', $dependencies );
	}


	public static function registerKubioScriptsDependency( $handle, $src, $deps, $version ) {
		wp_register_script( AssetsDependencyInjector::KUBIO_DEPENENCY_PREFIX . $handle, $src, $deps, $version, true );
	}

	public static function registerKubioFrontendStyleDependency( $handle, $src, $deps, $version ) {
		wp_register_style( AssetsDependencyInjector::KUBIO_DEPENENCY_PREFIX . $handle, $src, $deps, $version );
	}
}
