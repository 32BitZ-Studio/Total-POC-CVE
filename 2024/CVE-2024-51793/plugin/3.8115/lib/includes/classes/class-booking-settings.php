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

class WCRB_MANAGE_BOOKING {

	private $TABID = "wc_rb_manage_bookings";

	function __construct() {
        add_action( 'wc_rb_settings_tab_menu_item', array( $this, 'add_booking_tab_in_settings_menu' ), 10, 2 );
        add_action( 'wc_rb_settings_tab_body', array( $this, 'add_booking_tab_in_settings_body' ), 10, 2 );
		add_action( 'wp_ajax_wc_rb_update_booking_settings', array( $this, 'wc_rb_update_booking_settings' ) );
    }

	function add_booking_tab_in_settings_menu() {
        $active = '';

        $menu_output = '<li class="tabs-title' . esc_attr($active) . '" role="presentation">';
        $menu_output .= '<a href="#' . esc_attr( $this->TABID ) . '" role="tab" aria-controls="' . esc_attr( $this->TABID ) . '" aria-selected="true" id="' . esc_attr( $this->TABID ) . '-label">';
        $menu_output .= '<h2>' . esc_html__( 'Booking Settings', 'computer-repair-shop' ) . '</h2>';
        $menu_output .=	'</a>';
        $menu_output .= '</li>';

        echo wp_kses_post( $menu_output );
    }
	
	function add_booking_tab_in_settings_body() {
        global $wpdb, $WCRB_MANAGE_DEVICES;

        $active = '';
		
		$wc_device_brand_label = ( empty( get_option( 'wc_device_brand_label' ) ) ) ? esc_html__( 'Device Brand', 'computer-repair-shop' ) : get_option( 'wc_device_brand_label' );
		$wc_device_type_label = ( empty( get_option( 'wc_device_type_label' ) ) ) ? esc_html__( 'Device Type', 'computer-repair-shop' ) : get_option( 'wc_device_type_label' );

		$wc_booking_default_type  = ( empty( get_option( 'wc_booking_default_type' ) ) ) ? '' : get_option( 'wc_booking_default_type' );
		$wc_booking_default_brand  = ( empty( get_option( 'wc_booking_default_brand' ) ) ) ? '' : get_option( 'wc_booking_default_brand' );

		$setting_body = '<div class="tabs-panel team-wrap' . esc_attr( $active ) . '" 
        id="' . esc_attr( $this->TABID ) . '" 
        role="tabpanel" 
        aria-hidden="true" 
        aria-labelledby="' . esc_attr( $this->TABID ) . '-label">';

		$setting_body .= '<div class="wc-rb-manage-devices">';
		$setting_body .= '<h2>' . esc_html__( 'Booking Settings', 'computer-repair-shop' ) . '</h2>';
		$setting_body .= '<div class="booking_success_msg"></div>';
		
		$setting_body .= '<form data-async data-abide class="needs-validation" novalidate method="post" data-success-class=".booking_success_msg">';

		$setting_body .= '<div class="wc-rb-grey-bg-box">';
		$setting_body .= '<h2>' . esc_html__( 'Booking Email To Customer', 'computer-repair-shop' ) . '</h2>';
		$setting_body .= '<div class="grid-container"><div class="grid-x grid-padding-x">';

		$menu_name_p 	= get_option( 'blogname' );
		$value 		  = ( ! empty ( get_option( 'booking_email_subject_to_customer' ) ) ) ? get_option( 'booking_email_subject_to_customer' ) : 'We have received your booking order! | ' . $menu_name_p;

		$setting_body .= '<div class="medium-12 cell"><label for="booking_email_subject_to_customer">
							' . esc_html__( 'Email subject', 'computer-repair-shop' ) . '
								<input type="text" id="booking_email_subject_to_customer" name="booking_email_subject_to_customer" value="' . esc_html( $value ) . '" />
							</label></div>';

		$saved_message = ( empty( get_option( 'booking_email_body_to_customer' ) ) ) ? '' : get_option( 'booking_email_body_to_customer' );

$message = 'Hello {{customer_full_name}},

Thank you for booking. We have received your job id : {{job_id}} and assigned you case number : {{case_number}}

For your device : {{customer_device_label}} 

Note: Job status page will not able to show your job details unless its approved from our side. During our working hours its done quickly.

We will get in touch whenever its needed. You can always check your job status by clicking {{start_anch_status_check_link}} Check Status {{end_anch_status_check_link}}.

Direct status check link : {{status_check_link}}

Details which we have received from you are below. 

{{order_invoice_details}}

Thank you again for your business!';
							
		$saved_message = ( empty( $saved_message ) ) ? $message : $saved_message;						

		$setting_body .= '<div class="medium-12 cell"><label for="booking_email_body_to_customer">
							'. esc_html__( 'Email body', 'computer-repair-shop' ) .'<br>
							'. esc_html__( 'Available Keywords', 'computer-repair-shop' ) .' {{customer_full_name}} {{customer_device_label}} {{status_check_link}} {{start_anch_status_check_link}} Check Status {{end_anch_status_check_link}} {{order_invoice_details}} {{job_id}} {{case_number}}
							<textarea id="booking_email_body_to_customer" name="booking_email_body_to_customer" rows="4">'. esc_textarea( $saved_message ) .'</textarea>
						</label></div>';
						
						
		//Email to Administrator
		$setting_body .= '<h2 class="cell">' . esc_html__( 'Booking email to administrator', 'computer-repair-shop' ) . '</h2>';
		$value 		  = ( ! empty ( get_option( 'booking_email_subject_to_admin' ) ) ) ? get_option( 'booking_email_subject_to_admin' ) : 'You have new booking order | ' . $menu_name_p;

		$setting_body .= '<div class="medium-12 cell"><label for="booking_email_subject_to_admin">
							' . esc_html__( 'Email subject', 'computer-repair-shop' ) . '
								<input type="text" id="booking_email_subject_to_admin" name="booking_email_subject_to_admin" value="' . esc_html( $value ) . '" />
							</label></div>';

		$saved_message = ( empty( get_option( 'booking_email_body_to_admin' ) ) ) ? '' : get_option( 'booking_email_body_to_admin' );

$message = 'Hello,

You have received a new booking job ID: {{job_id}} Case number: {{case_number}}.

From Customer : {{customer_full_name}}

Job Details are listed below.

{{order_invoice_details}}
';
		$saved_message = ( empty( $saved_message ) ) ? $message : $saved_message;						

		$setting_body .= '<div class="medium-12 cell"><label for="booking_email_body_to_admin">
							'. esc_html__( 'Email body', 'computer-repair-shop' ) .'<br>
							'. esc_html__( 'Available Keywords', 'computer-repair-shop' ) .' {{customer_full_name}} {{customer_device_label}} {{status_check_link}} {{start_anch_status_check_link}} Check Status {{end_anch_status_check_link}} {{order_invoice_details}} {{job_id}} {{case_number}}
							<textarea id="booking_email_body_to_admin" name="booking_email_body_to_admin" rows="4">'. esc_textarea( $saved_message ) .'</textarea>
						</label></div>';
		//Email to Administrator Ends

		$setting_body .= '</div></div><!-- End of grid Container and Grid X /-->';
		$setting_body .= '</div>';

		$setting_body .= '<table class="form-table border"><tbody>';

		$setting_body .= '<tr>
							<th scope="row">
								<label for="wcrb_turn_booking_forms_to_jobs_b">
									' . esc_html__( 'Booking & Quote Forms', 'computer-repair-shop' ) . '
								</label>
							</th>';
		$setting_body .= '<td>';

		$wcrb_turn_booking_forms_to_jobs = get_option( 'wcrb_turn_booking_forms_to_jobs' );
		$wcrb_turn_booking_forms_to_jobs = ( $wcrb_turn_booking_forms_to_jobs == 'on' ) ? 'checked="checked"' : '';
		
		$setting_body .= '<input type="checkbox" ' . esc_html( $wcrb_turn_booking_forms_to_jobs ) . ' name="wcrb_turn_booking_forms_to_jobs" id="wcrb_turn_booking_forms_to_jobs_b" />';
		
		$setting_body .= '<label for="wcrb_turn_booking_forms_to_jobs_b">';
		$setting_body .= esc_html__( 'Send booking forms & quote forms to jobs instead of estimates ', 'computer-repair-shop' );
		$setting_body .= '</label></td></tr>';

		$setting_body .= '<tr>
							<th scope="row">
								<label for="wcrb_turn_off_other_device_brands">
									' . esc_html__( 'Other Devices & Brands', 'computer-repair-shop' ) . '
								</label>
							</th>';
		$setting_body .= '<td>';

		$wcrb_turn_off_other_device_brands = get_option( 'wcrb_turn_off_other_device_brands' );
		$wcrb_turn_off_other_device_brands = ( $wcrb_turn_off_other_device_brands == 'on' ) ? 'checked="checked"' : '';
		
		$setting_body .= '<input type="checkbox" ' . esc_html( $wcrb_turn_off_other_device_brands ) . ' name="wcrb_turn_off_other_device_brands" id="wcrb_turn_off_other_device_brands_b" />';
		
		$setting_body .= '<label for="wcrb_turn_off_other_device_brands_b">';
		$setting_body .= esc_html__( 'Turn off other option for devices and brands ', 'computer-repair-shop' );
		$setting_body .= '</label></td></tr>';
		

		$setting_body .= '<tr><th scope="row"><label for="wc_booking_default_type">' . esc_html__( 'Select default ', 'computer-repair-shop' ) . ' ' . $wc_device_type_label . '</label></th><td>';
		$setting_body .= '<label>' . esc_html__( 'Keep selected on booking page', 'computer-repair-shop' ) . '</label>';
		$setting_body .= '<select name="wc_booking_default_type" id="wc_booking_default_type" class="regular-text">';
		$setting_body .= $WCRB_MANAGE_DEVICES->generate_device_type_options( $wc_booking_default_type, '' );
		$setting_body .= '</select>';
		$setting_body .= '</td></tr>';

		$setting_body .= '<tr><th scope="row"><label for="wc_booking_default_brand">' . esc_html__( 'Select default ', 'computer-repair-shop' ) . ' ' . $wc_device_brand_label . '</label></th><td>';
		$setting_body .= '<label>' . esc_html__( 'Keep selected on booking page', 'computer-repair-shop' ) . '</label>';
		$setting_body .= '<select name="wc_booking_default_brand" id="wc_booking_default_brand" class="regular-text">';
		$setting_body .= $WCRB_MANAGE_DEVICES->generate_manufacture_options( $wc_booking_default_brand, '' );
		$setting_body .= '</select>';
		$setting_body .= '</td></tr>';

		$setting_body .= '</tbody></table>';

		$setting_body .= '<input type="hidden" name="form_type" value="wc_rb_update_sett_bookings" />';
		$setting_body .= wp_nonce_field( 'wcrb_nonce_setting_booking', 'wcrb_nonce_setting_booking_field', true, false );

		$setting_body .= '<button type="submit" class="button button-primary" data-type="rbssubmitdevices">' . esc_html__( 'Update Options', 'computer-repair-shop' ) . '</button></form>';

		$setting_body .= '</div><!-- wc rb Devices /-->';
		$setting_body .= '</div><!-- Tabs Panel /-->';

		$allowedHTML = ( function_exists( 'wc_return_allowed_tags' ) ) ? wc_return_allowed_tags() : '';
		echo wp_kses( $setting_body, $allowedHTML );
	}

	function wc_rb_update_booking_settings() {
		$message = '';
		$success = 'NO';

		if ( ! isset( $_POST['wcrb_nonce_setting_booking_field'] ) || ! wp_verify_nonce( $_POST['wcrb_nonce_setting_booking_field'], 'wcrb_nonce_setting_booking' ) ) {
			$message = esc_html__( 'Couldn\'t verify nonce please reload page.', 'computer-repair-shop' );
		} else {
			// process form data
			$wc_booking_default_brand = ( ! isset( $_POST['wc_booking_default_brand'] ) ) ? '' : sanitize_text_field( $_POST['wc_booking_default_brand'] );
			$wc_booking_default_type  = ( ! isset( $_POST['wc_booking_default_type'] ) ) ? '' : sanitize_text_field( $_POST['wc_booking_default_type'] );
			$booking_email_subject_to_customer = ( ! isset( $_POST['booking_email_subject_to_customer'] ) || empty( $_POST['booking_email_subject_to_customer'] ) ) ? '' : sanitize_text_field( $_POST['booking_email_subject_to_customer'] );
			$booking_email_body_to_customer	   = ( ! isset( $_POST['booking_email_body_to_customer'] ) || empty( $_POST['booking_email_body_to_customer'] ) ) ? '' : sanitize_textarea_field( $_POST['booking_email_body_to_customer'] );
			$booking_email_subject_to_admin = ( ! isset( $_POST['booking_email_subject_to_admin'] ) || empty( $_POST['booking_email_subject_to_admin'] ) ) ? '' : sanitize_text_field( $_POST['booking_email_subject_to_admin'] );
			$booking_email_body_to_admin	= ( ! isset( $_POST['booking_email_body_to_admin'] ) || empty( $_POST['booking_email_body_to_admin'] ) ) ? '' : sanitize_textarea_field( $_POST['booking_email_body_to_admin'] );
			$wcrb_turn_booking_forms_to_jobs = ( ! isset( $_POST['wcrb_turn_booking_forms_to_jobs'] ) ) ? '' : sanitize_text_field( $_POST['wcrb_turn_booking_forms_to_jobs'] );
			$wcrb_turn_off_other_device_brands = ( ! isset( $_POST['wcrb_turn_off_other_device_brands'] ) ) ? '' : sanitize_text_field( $_POST['wcrb_turn_off_other_device_brands'] );

			update_option( 'wcrb_turn_booking_forms_to_jobs', 	$wcrb_turn_booking_forms_to_jobs );
			update_option( 'wcrb_turn_off_other_device_brands', $wcrb_turn_off_other_device_brands );
			update_option( 'booking_email_body_to_admin', 		$booking_email_body_to_admin );
			update_option( 'booking_email_subject_to_admin', 	$booking_email_subject_to_admin );
			update_option( 'booking_email_body_to_customer', 	$booking_email_body_to_customer );
			update_option( 'booking_email_subject_to_customer', $booking_email_subject_to_customer );
			update_option( 'wc_booking_default_type', 			$wc_booking_default_type );
			update_option( 'wc_booking_default_brand', 			$wc_booking_default_brand );

			$message = esc_html__( 'Settings updated!', 'computer-repair-shop' );
		}

		$values['message'] = $message;
		$values['success'] = $success;

		wp_send_json( $values );
		wp_die();
	}
}