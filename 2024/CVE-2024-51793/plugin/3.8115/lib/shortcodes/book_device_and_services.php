<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit; // Exit if accessed directly
}
/**
 * Short Code
 * WC Book my Service
 * [wc_book_devices_and_services]
 *
 * @Since : 3.79
 * @package : RepairBuddy CRM
 */

if ( ! function_exists( 'wc_book_devices_and_services' ) ) :
    /**
     * Function Shortcode
     * To add Booking 
     * Page
     */
    function wc_book_devices_and_services() {

        $content = wc_book_my_service();


        return $content;
    } // wc_list_services
    add_shortcode ( 'wc_book_devices_and_services', 'wc_book_devices_and_services' );
endif;