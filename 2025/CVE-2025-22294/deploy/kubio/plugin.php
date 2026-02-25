<?php

/**
 * Plugin Name: Kubio
 * Plugin URI: https://kubiobuilder.com
 * Description: Using the power of AI, Kubio gives you a head start by generating a first draft of your website, which you can further customize to your liking.
 * Author: ExtendThemes
 * Author URI: https://extendthemes.com
 * Version: 2.5.1
 * License: GPL3+
 * License URI: https://www.gnu.org/licenses/gpl-2.0.txt
 * Text Domain: kubio
 * Domain Path: /languages
 * Requires PHP: 7.4
 * Requires at least: 5.8
 *
 */

// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// skip loading free version if the Kubio Page Builder PRO is active
if ( ! function_exists( 'kubio_is_free_and_pro_already_active' ) ) {

	function kubio_is_free_and_pro_already_active( $base_path ) {
		$plugin_name = plugin_basename( $base_path );
		$is_free     = strpos( $plugin_name, 'pro' ) === false;

		// these two should be deleted?
		//      $flags_option = get_option( '__kubio_instance_flags' );
		//      update_option( '__kubio_instance_flags', $flags_option );

		$pro_builder_is_active = false;
		if ( $is_free ) {
			$active_plugins        = get_option( 'active_plugins' );
			$pro_builder_is_active = in_array( 'kubio-pro/plugin.php', $active_plugins );
		}

		return $is_free && $pro_builder_is_active;
	}
}
if ( kubio_is_free_and_pro_already_active( __FILE__ ) ) {
	return;
}


if ( defined( 'KUBIO_VERSION' ) ) {
	return;
}

define( 'KUBIO_VERSION', '2.5.1' );
define( 'KUBIO_BUILD_NUMBER', '416' );

define( 'KUBIO_ENTRY_FILE', __FILE__ );
define( 'KUBIO_ROOT_DIR', plugin_dir_path( __FILE__ ) );
define( 'KUBIO_ROOT_URL', untrailingslashit( plugin_dir_url( __FILE__ ) ) );

define( 'KUBIO_BUILD_DIR', plugin_dir_path( __FILE__ ) . '/build' );
define( 'KUBIO_LOGO_URL', plugins_url( '/static/kubio-logo.svg', __FILE__ ) );
define( 'KUBIO_LOGO_PATH', plugin_dir_path( __FILE__ ) . '/static/kubio-logo.svg' );
define( 'KUBIO_LOGO_SVG', file_get_contents( KUBIO_LOGO_PATH ) );

define( 'KUBIO_WPML_BLOCK_DEFAULTS_ID', 'Kubio Defaults' );

if ( ! defined( 'KUBIO_CLOUD_URL' ) ) {
	define( 'KUBIO_CLOUD_URL', 'https://cloud.kubiobuilder.com' );
}

if ( ! defined( 'KUBIO_INCLUDE_TEST_SNIPPETS' ) ) {
	define( 'KUBIO_INCLUDE_TEST_SNIPPETS', false );
}


if ( ! defined( 'KUBIO_MINIMUM_WP_VERSION' ) ) {
	define( 'KUBIO_MINIMUM_WP_VERSION', '6.5' );
}


define( 'KUBIO_SLUG', str_replace( wp_normalize_path( WP_PLUGIN_DIR ) . '/', '', wp_normalize_path( __DIR__ ) ) );

if ( ! function_exists( 'kubio_url' ) ) {
	function kubio_url( $path = '' ) {
		static $url;
		if ( ! $url ) {
			$url = plugins_url( '', __FILE__ );
		}
		return $url . '/' . ltrim( $path, '/' );
	}
}

/**
 * @var \Composer\Autoload\ClassLoader $kubio_autoloader ;
 */
global $kubio_autoloader;
$kubio_autoloader = require_once plugin_dir_path( __FILE__ ) . 'vendor/autoload.php';

require_once 'lib/init.php';
