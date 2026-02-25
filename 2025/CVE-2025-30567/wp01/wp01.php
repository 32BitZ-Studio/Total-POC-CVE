<?php
/**
 * Plugin Name: Улучшения от WP01
 * Plugin URI: https://wp01.ru
 * Description: Плагин для самостоятельного ускорения, seo оптимизации и защиты вашего WordPress сайта.
 * Version: 2.6.2
 * Author: WP01
 * Author URI: https://wp01.ru
 * Text Domain: WP01
 * Domain Path: /languages
 */

if (!defined('ABSPATH')) {
    die('Don\'t hack please!');
}

// Make sure we don't expose any info if called directly
if ( !function_exists( 'add_action' ) ) {
    echo 'Hi there!  I\'m just a plugin, not much I can do when called directly.';
    exit;
}

//ini_set("display_errors",1);
//error_reporting(E_ALL);


define( 'WP01__PLUGIN_FILE', __FILE__ );
define( 'WP01__PLUGIN_DIR', plugin_dir_path( __FILE__ ) );

require_once( WP01__PLUGIN_DIR . 'inc/class-wp01.php' );
require_once( WP01__PLUGIN_DIR . 'inc/class-wp01-installer.php' );
require_once( WP01__PLUGIN_DIR . 'inc/class-wp01-content.php' );
require_once( WP01__PLUGIN_DIR . 'inc/class-wp01-table.php' );

WP01::init();