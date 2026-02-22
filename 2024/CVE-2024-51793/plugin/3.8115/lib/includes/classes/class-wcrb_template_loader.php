<?php
/**
 * Handles the SMS integration and sending
 *
 * Help setup pages to they can be used in notifications and other items
 *
 * @package computer-repair-shop
 * @version 3.7947
 */

defined( 'ABSPATH' ) || exit;

class WCRB_TEMPLATE_LOADER {

    private $identifier = 'wc_rb_page_sms_IDENTIFIER';

    function __construct() {
        add_filter( 'template_include', array( $this, 'wcrb_template_loading' ) );
    }

	function wcrb_template_loading(string $template): string {
		//Single Service Template
		if ( is_single() && get_query_var('post_type') === 'rep_services' ) {
			$templates = [
				'single-rep_services.php',
				'templates/single-rep_services.php'
			];
			$template = locate_template($templates);
			if ( ! $template ) {
				$template = WC_COMPUTER_REPAIR_SHOP_DIR . 'lib' . DS . 'templates' . DS . 'theme-parts' . DS . 'single-rep_services.php';
			}
		} else if ( is_single() && get_query_var('post_type') === 'rep_devices' ) {
			$templates = [
				'single-rep_devices.php',
				'templates/single-rep_devices.php'
			];
			$template = locate_template( $templates );
			if ( ! $template ) {
				$template = WC_COMPUTER_REPAIR_SHOP_DIR . 'lib' . DS . 'templates' . DS . 'theme-parts' . DS . 'single-rep_devices.php';
			}
		}

    	return $template;
	}
}