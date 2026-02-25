<?php


namespace Kubio;

class GutenbergControls {
	private static $instance = null;
	protected function __construct() {
		add_action( 'after_setup_theme', array( $this, 'addGutenbergControls' ) );
	}

	public function addGutenbergControls() {
		add_theme_support( 'border' );
		add_theme_support( 'custom-background', array() );
		add_theme_support( 'link-color' );
		add_theme_support( 'custom-spacing' );
		add_theme_support( 'custom-units' );
		add_theme_support( 'link-color' );
	}

	public static function getInstance() {
		if ( ! static::$instance ) {
			static::$instance = new static();
		}

		return static::$instance;
	}

	public static function load() {
		static::getInstance();
	}
}
