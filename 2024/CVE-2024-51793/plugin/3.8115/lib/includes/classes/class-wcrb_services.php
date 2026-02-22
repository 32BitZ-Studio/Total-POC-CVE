<?php
/**
 * The file contains the functions related to Shortcode Pages
 *
 * Help setup pages to they can be used in notifications and other items
 *
 * @package computer-repair-shop
 * @version 3.7947
 */

defined( 'ABSPATH' ) || exit;

class WCRB_MANAGE_SERVICES {

	private $TABID = "wc_rb_manage_service";

	function __construct() {
        add_action( 'wc_rb_settings_tab_menu_item', array( $this, 'add_service_tab_in_settings_menu' ), 10, 2 );
        add_action( 'wc_rb_settings_tab_body', array( $this, 'add_service_tab_in_settings_body' ), 10, 2 );
		add_action( 'wp_ajax_wc_rb_update_service_settings', array( $this, 'wc_rb_update_service_settings' ) );
    }

	function add_service_tab_in_settings_menu() {
        $active = '';

        $menu_output = '<li class="tabs-title' . esc_attr( $active ) . '" role="presentation">';
        $menu_output .= '<a href="#' . esc_attr( $this->TABID ) . '" role="tab" aria-controls="' . esc_attr( $this->TABID ) . '" aria-selected="true" id="' . esc_attr( $this->TABID ) . '-label">';
        $menu_output .= '<h2>' . esc_html__( 'Service Settings', 'computer-repair-shop' ) . '</h2>';
        $menu_output .=	'</a>';
        $menu_output .= '</li>';

        echo wp_kses_post( $menu_output );
    }
	
	function add_service_tab_in_settings_body() {

        $active = '';
		$default_description = esc_html__( 'Below you can check price by type or brand and to get accurate value check devices.', 'computer-repair-shop' );
		$default_heading	 = esc_html__( 'Book Service', 'computer-repair-shop' );

		$wc_service_sidebar_description  = ( empty( get_option( 'wc_service_sidebar_description' ) ) ) ? $default_description : get_option( 'wc_service_sidebar_description' );
		$wc_service_booking_heading 	 = ( empty( get_option( 'wc_service_booking_heading' ) ) ) ? $default_heading : get_option( 'wc_service_booking_heading' );

		$setting_body = '<div class="tabs-panel team-wrap' . esc_attr( $active ) . '" 
        id="' . esc_attr( $this->TABID ) . '" 
        role="tabpanel" 
        aria-hidden="true" 
        aria-labelledby="' . esc_attr( $this->TABID ) . '-label">';

		$setting_body .= '<div class="wc-rb-manage-devices">';
		$setting_body .= '<h2>' . esc_html__( 'Service Settings', 'computer-repair-shop' ) . '</h2>';
		$setting_body .= '<div class="' . esc_attr( $this->TABID ) . '"></div>';
		$setting_body .= '<form data-async data-abide class="needs-validation" novalidate method="post" data-success-class=".' . esc_attr( $this->TABID ) . '">';

		$setting_body .= '<table class="form-table border"><tbody>';

		$setting_body .= '<tr><th scope="row"><label for="wc_service_sidebar_description">' . esc_html__( 'Single Service Price Sidebar ', 'computer-repair-shop' ) . '</label></th><td>';
		$setting_body .= '<label>' . esc_html__( 'Add some description for prices on single service page sidebar', 'computer-repair-shop' ) . '</label>';
		$setting_body .= '<textarea class="form-control" name="wc_service_sidebar_description" id="wc_service_sidebar_description">' . esc_html( $wc_service_sidebar_description ) . '</textarea>';
		$setting_body .= '</td></tr>';

		$wc_booking_on_service_page_status = get_option( 'wc_booking_on_service_page_status' );
		$wcbookingonservicepage    		   = ( $wc_booking_on_service_page_status == 'on' ) ? 'checked="checked"' : '';

		$setting_body .= '<tr><th scope="row"><label for="wc_booking_on_service_page_status">' . esc_html__( 'Disable Booking on Service Page?', 'computer-repair-shop' ) . '</label></th>';
		$setting_body .= '<td><input type="checkbox"  ' . esc_html( $wcbookingonservicepage ) . ' name="wc_booking_on_service_page_status" id="wc_booking_on_service_page_status" /></td></tr>';
		
		$setting_body .= '<tr><th scope="row"><label for="wc_service_booking_heading">' . esc_html__( 'Single Service Price Sidebar ', 'computer-repair-shop' ) . '</label></th><td>';
		$setting_body .= '<input type="text" class="form-control" name="wc_service_booking_heading" id="wc_service_booking_heading" value="' . esc_html( $wc_service_booking_heading ) . '" />';
		$setting_body .= '</td></tr>';

		$wc_service_booking_form = get_option( 'wc_service_booking_form' );
		$with_type 				 = ( $wc_service_booking_form == 'with_type' ) ? ' selected' : '';
		$without_type 			 = ( $wc_service_booking_form == 'without_type' || $wc_service_booking_form == '' ) ? ' selected' : '';
		$warranty_booking 		 = ( $wc_service_booking_form == 'warranty_booking' ) ? ' selected' : '';

		$setting_body .= '<tr><th scope="row"><label for="wc_service_booking_form">' . esc_html__( 'Booking Form', 'computer-repair-shop' ) . '</label></th><td>';
		$setting_body .= '<select class="form-control" name="wc_service_booking_form" id="wc_service_booking_form">';
		$setting_body .= '<option value="">' . esc_html__( 'Select booking form', 'computer-repair-shop' ) . '</option>';
		$setting_body .= '<option '. esc_attr( $with_type ) .' value="with_type">' . esc_html__( 'Booking with type, manufacture, device and grouped services', 'computer-repair-shop' ) . '</option>';
		$setting_body .= '<option '. esc_attr( $without_type ) .' value="without_type">' . esc_html__( 'Booking with manufacture, device and services no types', 'computer-repair-shop' ) . '</option>';
		$setting_body .= '<option '. esc_attr( $warranty_booking ) .' value="warranty_booking">' . esc_html__( 'Booking without service selection', 'computer-repair-shop' ) . '</option>';
		$setting_body .= '</select>';

		//wc_service_booking_form
		$setting_body .= '</td></tr>';

		$setting_body .= '</tbody></table>';

		$setting_body .= '<input type="hidden" name="form_type" value="wc_rb_update_sett_services" />';
		$setting_body .= wp_nonce_field( 'wcrb_nonce_setting_service', 'wcrb_nonce_setting_service_field', true, false );

		$setting_body .= '<button type="submit" class="button button-primary" data-type="rbssubmitdevices">' . esc_html__( 'Update Options', 'computer-repair-shop' ) . '</button></form>';

		$setting_body .= '</div><!-- wc rb Devices /-->';
		$setting_body .= '</div><!-- Tabs Panel /-->';

		$allowedHTML = ( function_exists( 'wc_return_allowed_tags' ) ) ? wc_return_allowed_tags() : '';
		echo wp_kses( $setting_body, $allowedHTML );
	}

	function wc_rb_update_service_settings() {
		$message = '';
		$success = 'NO';

		if ( ! isset( $_POST['wcrb_nonce_setting_service_field'] ) || ! wp_verify_nonce( $_POST['wcrb_nonce_setting_service_field'], 'wcrb_nonce_setting_service' ) ) {
			$message = esc_html__( 'Couldn\'t verify nonce please reload page.', 'computer-repair-shop' );
		} else {
			// process form data
			$wc_service_sidebar_description    = ( ! isset( $_POST['wc_service_sidebar_description'] ) ) ? '' : sanitize_text_field( $_POST['wc_service_sidebar_description'] );
			$wc_booking_on_service_page_status = ( ! isset( $_POST['wc_booking_on_service_page_status'] ) ) ? '' : sanitize_text_field( $_POST['wc_booking_on_service_page_status'] );
			$wc_service_booking_heading		   = ( ! isset( $_POST['wc_service_booking_heading'] ) ) ? '' : sanitize_text_field( $_POST['wc_service_booking_heading'] );
			$wc_service_booking_form		   = ( ! isset( $_POST['wc_service_booking_form'] ) ) ? '' : sanitize_text_field( $_POST['wc_service_booking_form'] );

			update_option( 'wc_service_booking_form', $wc_service_booking_form );
			update_option( 'wc_service_sidebar_description', $wc_service_sidebar_description );
			update_option( 'wc_booking_on_service_page_status', $wc_booking_on_service_page_status );
			update_option( 'wc_service_booking_heading', $wc_service_booking_heading );

			$message = esc_html__( 'Settings updated!', 'computer-repair-shop' );
		}

		$values['message'] = $message;
		$values['success'] = $success;

		wp_send_json( $values );
		wp_die();
	}
}