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

class WCRB_MY_ACCOUNT {

	private $TABID = "wc_rb_manage_account";

	function __construct() {
		//Run much later than everyone else to give other plugins a chance to hook into the filters and actions in this
		add_action( 'init', array( $this, 'init' ), 9000 );

		add_action( 'wc_rb_settings_tab_menu_item', array( $this, 'add_tab_in_settings_menu' ), 10, 2 );
        add_action( 'wc_rb_settings_tab_body', array( $this, 'add_tab_in_settings_body' ), 10, 2 );
		add_action( 'wp_ajax_wc_rb_update_account_settings', array( $this, 'wc_rb_update_account_settings' ) );

		add_action( 'wp_ajax_wc_return_devices_datalist', array( $this, 'wc_return_devices_datalist' ) );
		add_action( 'wp_ajax_nopriv_wc_return_devices_datalist', array( $this, 'wc_return_devices_datalist' ) );
		add_action( 'wp_ajax_wcrb_add_customer_device', array( $this, 'wcrb_add_customer_device' ) );
		add_action( 'wp_ajax_nopriv_wcrb_add_customer_device', array( $this, 'wcrb_add_customer_device' ) );
    }

	function add_tab_in_settings_menu() {
        $active = '';

        $menu_output = '<li class="tabs-title' . esc_attr( $active ) . '" role="presentation">';
        $menu_output .= '<a href="#' . esc_attr( $this->TABID ) . '" role="tab" aria-controls="' . esc_attr( $this->TABID ) . '" aria-selected="true" id="' . esc_attr( $this->TABID ) . '-label">';
        $menu_output .= '<h2>' . esc_html__( 'My Account Settings', 'computer-repair-shop' ) . '</h2>';
        $menu_output .=	'</a>';
        $menu_output .= '</li>';

        echo wp_kses_post( $menu_output );
    }
	
	function add_tab_in_settings_body() {

        $active = '';

		$setting_body = '<div class="tabs-panel team-wrap' . esc_attr( $active ) . '" 
        id="' . esc_attr( $this->TABID ) . '" 
        role="tabpanel" 
        aria-hidden="true" 
        aria-labelledby="' . esc_attr( $this->TABID ) . '-label">';

		$setting_body .= '<div class="wc-rb-manage-devices">';
		$setting_body .= '<h2>' . esc_html__( 'Service Settings', 'computer-repair-shop' ) . '</h2>';
		$setting_body .= '<div class="' . esc_attr( $this->TABID ) . '"></div>';
		$setting_body .= '<form data-async data-abide class="needs-validation" novalidate method="post" data-success-class=".' . esc_attr( $this->TABID ) . '">';

		$setting_body .= '<p>' . esc_html__( 'Same settings will apply on WooCommerce my account page', 'computer-repair-shop' ) . '</p>';

		$setting_body .= '<table class="form-table border"><tbody>';

		$wc_booking_on_account_page_status = get_option( 'wc_booking_on_account_page_status' );
		$wcbookingonservicepage    		   = ( $wc_booking_on_account_page_status == 'on' ) ? 'checked="checked"' : '';

		$setting_body .= '<tr><th scope="row"><label for="wc_booking_on_account_page_status">' . esc_html__( 'Disable Booking on My Account Page?', 'computer-repair-shop' ) . '</label></th>';
		$setting_body .= '<td><input type="checkbox"  ' . esc_html( $wcbookingonservicepage ) . ' name="wc_booking_on_account_page_status" id="wc_booking_on_account_page_status" /></td></tr>';
		

		$wc_account_booking_form = get_option( 'wc_account_booking_form' );
		$with_type 				 = ( $wc_account_booking_form == 'with_type' ) ? ' selected' : '';
		$without_type 			 = ( $wc_account_booking_form == 'without_type' || $wc_account_booking_form == '' ) ? ' selected' : '';
		$warranty_booking 		 = ( $wc_account_booking_form == 'warranty_booking' ) ? ' selected' : '';

		$setting_body .= '<tr><th scope="row"><label for="wc_account_booking_form">' . esc_html__( 'Booking Form', 'computer-repair-shop' ) . '</label></th><td>';
		$setting_body .= '<select class="form-control" name="wc_account_booking_form" id="wc_account_booking_form">';
		$setting_body .= '<option value="">' . esc_html__( 'Select booking form', 'computer-repair-shop' ) . '</option>';
		$setting_body .= '<option '. esc_attr( $with_type ) .' value="with_type">' . esc_html__( 'Booking with type, manufacture, device and grouped services', 'computer-repair-shop' ) . '</option>';
		$setting_body .= '<option '. esc_attr( $without_type ) .' value="without_type">' . esc_html__( 'Booking with manufacture, device and services no types', 'computer-repair-shop' ) . '</option>';
		$setting_body .= '<option '. esc_attr( $warranty_booking ) .' value="warranty_booking">' . esc_html__( 'Booking without service selection', 'computer-repair-shop' ) . '</option>';
		$setting_body .= '</select>';

		//wc_service_booking_form
		$setting_body .= '</td></tr>';

		$setting_body .= '</tbody></table>';

		$setting_body .= '<input type="hidden" name="form_type" value="wc_rb_update_sett_account" />';
		$setting_body .= '<input type="hidden" name="form_action" value="wc_rb_update_account_settings" />';
		$setting_body .= wp_nonce_field( 'wcrb_nonce_setting_service', 'wcrb_nonce_setting_service_field', true, false );

		$setting_body .= '<button type="submit" class="button button-primary" data-type="rbssubmitdevices">' . esc_html__( 'Update Options', 'computer-repair-shop' ) . '</button></form>';

		$setting_body .= '</div><!-- wc rb Devices /-->';
		$setting_body .= '</div><!-- Tabs Panel /-->';

		$allowedHTML = ( function_exists( 'wc_return_allowed_tags' ) ) ? wc_return_allowed_tags() : '';
		echo wp_kses( $setting_body, $allowedHTML );
	}

	function wc_rb_update_account_settings() {
		$message = '';
		$success = 'NO';

		if ( ! isset( $_POST['wcrb_nonce_setting_service_field'] ) || ! wp_verify_nonce( $_POST['wcrb_nonce_setting_service_field'], 'wcrb_nonce_setting_service' ) ) {
			$message = esc_html__( 'Couldn\'t verify nonce please reload page.', 'computer-repair-shop' );
		} else {
			// process form data
			$wc_booking_on_account_page_status = ( ! isset( $_POST['wc_booking_on_account_page_status'] ) ) ? '' : sanitize_text_field( $_POST['wc_booking_on_account_page_status'] );
			$wc_account_booking_form		   = ( ! isset( $_POST['wc_account_booking_form'] ) ) ? '' : sanitize_text_field( $_POST['wc_account_booking_form'] );

			update_option( 'wc_account_booking_form', $wc_account_booking_form );
			update_option( 'wc_booking_on_account_page_status', $wc_booking_on_account_page_status );

			$message = esc_html__( 'Settings updated!', 'computer-repair-shop' );
		}

		$values['message'] = $message;
		$values['success'] = $success;

		wp_send_json( $values );
		wp_die();
	}

	function init() {
		add_filter( 'wc_rb_myaccount_tab_menu_item', array( $this, 'add_my_account_ticket_menu' ), 10, 1 );
		//Tab for book device
		add_filter( 'wc_rb_myaccount_tab_body', array( $this, 'return_tab_body_elements' ), 15 );
	}
	
	function add_my_account_ticket_menu( $arg ) {
		$cl_dashboard = ' is-active';
		$cl_loutout = $cl_profile = $cl_ticket = $cl_reviews = $cl_booking = '';

		if ( isset( $_GET['job_status'] ) && ! empty( $_GET['job_status'] ) ) {
			$cl_dashboard = '';
			$cl_ticket    = ' is-active';
		}
		if ( isset( $_GET['print'] ) && ! empty( $_GET['print'] ) ) {
			$cl_dashboard = '';
			$cl_ticket    = ' is-active';
		}
		if ( isset( $_GET['book_device'] ) && $_GET['book_device'] == 'yes' ) {
			$cl_dashboard = '';
			$cl_booking = ' is-active';
		}

		$wc_device_label = ( empty( get_option( 'wc_device_label_plural' ) ) ) ? esc_html__( 'Devices', 'computer-repair-shop' ) : get_option( 'wc_device_label_plural' );

		$dashboard_link = '<li class="tabs-title' . esc_attr( $cl_dashboard ) . '" role="presentation">';
		$dashboard_link .=	'<a href="#main_page" role="tab" aria-controls="main_page">';
		$dashboard_link .= '<h2>' . esc_html__( 'Dashboard', 'computer-repair-shop' ) . '</h2>';
		$dashboard_link .= '</a></li>';

		$tickets_link = '<li class="tabs-title' . esc_attr( $cl_ticket ) . '" role="presentation">';
		$tickets_link .= '<a href="#tickets_page" role="tab" aria-controls="tickets_page">';
		$tickets_link .= '<h2>' . esc_html__( 'Tickets', 'computer-repair-shop' ) . '</h2>';
		$tickets_link .= '</a></li>';

		$revie_link = '<li class="tabs-title' . esc_attr( $cl_reviews ) . '" role="presentation">';
		$revie_link .= '<a href="#myreviews_page" role="tab" aria-controls="myreviews_page">';
		$revie_link .= '<h2>' . esc_html__( 'Reviews', 'computer-repair-shop' ) . '</h2>';
		$revie_link .= '</a></li>';

		$mydev_link = '<li class="tabs-title' . esc_attr( $cl_ticket ) . '" role="presentation">';
		$mydev_link .= '<a href="#mydevices_page" role="tab" aria-controls="mydevices_page">';
		$mydev_link .= '<h2>' . esc_html__( 'My ', 'computer-repair-shop' ) . esc_html( $wc_device_label ) . '</h2>';
		$mydev_link .= '</a></li>';

		//additional tabs can be used for  add_filter( 'wcrb_additional_tab_links', 'return_function_with_output_for_tab_link', 15 );
		$additional_link = apply_filters( 'wcrb_additional_tab_links', '' );

		$book_link = '';
		if ( ! defined( 'RB_DIAG_DIESEL' ) ) :
		$booking_link = '<li class="tabs-title' . esc_attr( $cl_booking ) . '" role="presentation">';
		$booking_link .= '<a href="#booking_page" role="tab" aria-controls="tickets_page">';
		$booking_link .= '<h2>' . esc_html__( 'Book', 'computer-repair-shop' ) . ' ' . $wc_device_label . '</h2>';
		$booking_link .= '</a></li>';
		endif;

		$edit_profile = '<li class="external-title' . esc_attr( $cl_profile ) . '" ><a href="' . esc_url( get_edit_user_link() ) . '"><h2>' . esc_html__( 'Edit Profile', 'computer-repair-shop' ) . '</h2></a></li>';

		$logout_link = '<li class="external-title' . esc_attr( $cl_loutout ) . '" role="presentation">';
		$logout_link .= '<a href="' . esc_url( wp_logout_url( home_url() ) ) . '">';
		$logout_link .= '<h2>' . esc_html__( 'Logout', 'computer-repair-shop' ) . '</h2>';
		$logout_link .= '</a>';	
		$logout_link .= '</li>';

		return $dashboard_link . $tickets_link . $revie_link . $mydev_link . $additional_link . $booking_link . $edit_profile . $logout_link;
	}

	function return_tab_body_elements() {
		$tickets_body = $this->jobs_tickets_panel_body( '' );
		$my_devices   = $this->job_my_devices_panel_body();
		$my_reviews   = $this->job_reviews_panel_body();
		//additional tabs can be used for  add_filter( 'wcrb_additional_tabs', 'return_function_with_output_for_tab', 15 );
		$extra_plugin = apply_filters( 'wcrb_additional_tabs', '' );
		
		$device_panel = '';
		if ( ! defined( 'RB_DIAG_DIESEL' ) ) :
		$device_panel = $this->job_book_device_panel_body();
		endif;

		return $tickets_body . $my_devices . $my_reviews . $extra_plugin . $device_panel;
	}

	function jobs_tickets_panel_body( $args ) {
		$current_user 	= wp_get_current_user();
		$customer_id	= $current_user->ID;

		$cl_loutout = $cl_profile = $cl_ticket = '';

		if ( isset( $_GET['job_status'] ) && ! empty( $_GET['job_status'] ) ) {
			$cl_dashboard = '';
			$cl_ticket    = ' is-active';
		}
		if ( isset( $_GET['print'] ) && ! empty( $_GET['print'] ) ) {
			$cl_dashboard = '';
			$cl_ticket    = ' is-active';
		}

		$output = '<div class="tabs-panel team-wrap' . esc_attr( $cl_ticket ) . '" id="tickets_page" role="tabpanel" aria-hidden="true" aria-labelledby="tickets_page-label">';

		if( isset( $_GET["print"] ) && isset( $_GET["order_id"] ) && ! empty( $_GET["order_id"] ) ):
			$the_order_id     = sanitize_text_field( $_GET["order_id"] );
			$case_number      = get_post_meta( $the_order_id, '_case_number', true );
			$curr_case_number = ( isset( $_GET["wc_case_number"] ) ) ? sanitize_text_field( $_GET["wc_case_number"] ) : "";

			if($case_number != $curr_case_number) {
				$generatedHTML = esc_html__("You do not have permission to view this record.", "computer-repair-shop");
			} else {
				$generatedHTML = wc_computer_repair_print_functionality(TRUE);
			}
			$generatedHTML .= '<div class="aligncenter mt-25"><a class="hidden-print button button-primary" href="' . esc_url( get_the_permalink() ) . '">' . esc_html__( 'Go Back', 'computer-repair-shop' ) . '</a></div>';
		else:
			$output .= "<p>".esc_html__("Here you can check your jobs and their statuses also you can request new quote.", "computer-repair-shop")."</p>";
			$output .= "<h3>".esc_html__("Filter Jobs", "computer-repair-shop")."</h3>";		
			$output .= "<div class='job_status_holder'><ul class='horizontal wc_menu'>";
			$allowed_html = wc_return_allowed_tags();
			$optionsGenerated = wc_generate_status_links_myaccount( '' );
			$output .= wp_kses($optionsGenerated, $allowed_html);
			$output .= "</ul></div>";

			$job_status = "all";
			$generatedHTML = wc_print_jobs_by_customer_table( $job_status, $customer_id, '' );
		endif;

		$allowedHTML = wc_return_allowed_tags();
		$output .= wp_kses( $generatedHTML, $allowedHTML );

		$output .= '</div>';
		return $output;
	}

	function job_book_device_panel_body() {

		$cl_loutout = $cl_profile = $cl_ticket = $cl_booking = '';

		if ( isset( $_GET['book_device'] ) && $_GET['book_device'] == 'yes' ) {
			$cl_dashboard = '';
			$cl_booking = ' is-active';
		}

		$wc_device_label = ( empty( get_option( 'wc_device_label' ) ) ) ? esc_html__( 'Device', 'computer-repair-shop' ) : get_option( 'wc_device_label' );

		$output = '<div class="tabs-panel team-wrap' . esc_attr( $cl_booking ) . '" id="booking_page" role="tabpanel" aria-hidden="true" aria-labelledby="booking_page-label">';
		$output .= "<h2>" . esc_html__( 'You can book a new', 'computer-repair-shop' ) . ' ' . $wc_device_label . "</h2>";
		
		$wc_account_booking_form = get_option( 'wc_account_booking_form' );
        
        if( $wc_account_booking_form == 'with_type' ) {
          $output .= WCRB_TYPE_GROUPED_SERVICE();
        } elseif ( $wc_account_booking_form == 'warranty_booking' ) {
          $output .= wc_book_my_warranty();
        } else {
          $output .= wc_book_my_service();
        }

		$output .= '</div>';

		$allowedHTML = wc_return_allowed_tags();
		$output = wp_kses( $output, $allowedHTML );

		return $output;
	}

	function job_reviews_panel_body() {
		$selected_status = ( empty( get_option( 'wcrb_send_feedback_request_jobstatus' ) ) ) ? 'delivered' : get_option( 'wcrb_send_feedback_request_jobstatus' );

		$current_user 	= wp_get_current_user();
		$customer_id	= $current_user->ID;

		$cl_loutout = $cl_profile = $cl_ticket = $cl_booking = '';

		$sing_device_label  = ( empty( get_option( 'wc_device_label' ) ) ) ? esc_html__( 'Device', 'computer-repair-shop' ) : get_option( 'wc_device_label' );

		$output = '<div class="tabs-panel team-wrap' . esc_attr( $cl_booking ) . '" id="myreviews_page" role="tabpanel" aria-hidden="true" aria-labelledby="myreviews_page-label">';
		$output .= "<h2>" . esc_html__( 'Your Reviews', 'computer-repair-shop' ) . "</h2>";

		$output .= '<div class="deviceslistcustomer jobs_table_list"><table><thead><tr>';
		$output .= '<th>' . esc_html__( 'ID', 'computer-repair-shop' ) . '</th>';
		$output .= '<th>' . esc_html__( 'Case#', 'computer-repair-shop' ) . '</th>';
		$output .= '<th>' . esc_html__( 'Order Date', 'computer-repair-shop' ) . '</th>';
		$output .= '<th>' . esc_html( $sing_device_label ) . '</th>';
		$output .= '<th>' . esc_html__( 'Total', 'computer-repair-shop' ) . '</th>';
		$output .= '<th>' . esc_html__( 'Rating', 'computer-repair-shop' ) . '</th>';
		$output .= '<th>' . esc_html__( 'Action', 'computer-repair-shop' ) . '</th>';
		$output .= '</tr></thead><tbody>';

		$output .= $this->list_cusomter_reviews( $customer_id, $selected_status );

		$output .= '</tbody></table></div>';

		$output .= '</div>';

		$allowedHTML = wc_return_allowed_tags();
		$output = wp_kses( $output, $allowedHTML );

		return $output;
	}

	function job_my_devices_panel_body() {

		$cl_loutout = $cl_profile = $cl_ticket = $cl_booking = '';

		if ( isset( $_GET['book_device'] ) && $_GET['book_device'] == 'yes' ) {
			$cl_dashboard = '';
			$cl_booking = ' is-active';
		}

		$wc_device_label 	= ( empty( get_option( 'wc_device_label_plural' ) ) ) ? esc_html__( 'Devices', 'computer-repair-shop' ) : get_option( 'wc_device_label_plural' );
		$sing_device_label  = ( empty( get_option( 'wc_device_label' ) ) ) ? esc_html__( 'Device', 'computer-repair-shop' ) : get_option( 'wc_device_label' );
		$wc_device_id_imei_label = ( empty( get_option( 'wc_device_id_imei_label' ) ) ) ? esc_html__( 'ID/IMEI', 'computer-repair-shop' ) : get_option( 'wc_device_id_imei_label' );
		$wc_pin_code_label = ( empty( get_option( 'wc_pin_code_label' ) ) ) ? esc_html__( 'Pin Code/Password', 'computer-repair-shop' ) : get_option( 'wc_pin_code_label' );

		$output = '<div class="tabs-panel team-wrap' . esc_attr( $cl_booking ) . '" id="mydevices_page" role="tabpanel" aria-hidden="true" aria-labelledby="mydevices_page-label">';
		$output .= "<h2>" . esc_html__( 'Your', 'computer-repair-shop' ) . ' ' . $wc_device_label . "</h2>";
		$output .= '<p class="alignright">
		<a class="button button-primary button-small something" title="Add New Device" data-open="deviceFormReveal" aria-controls="deviceFormReveal" 
		aria-haspopup="true" tabindex="0">' . esc_html__( 'Add Your', 'computer-repair-shop' ) . ' ' . esc_html( $sing_device_label ) . '</a><div class="clearfix"></div></p>';

		$output .= $this->return_add_device_form( 'front' );

		$output .= '<div class="deviceslistcustomer jobs_table_list"><table><thead><tr>';
		$output .= '<th>' . esc_html__( 'ID', 'computer-repair-shop' ) . '</th>';
		$output .= '<th>' . esc_html( $sing_device_label ) . ' ' . esc_html__( 'Label', 'computer-repair-shop' ) . '</th>';
		$output .= '<th>' . esc_html( $wc_device_id_imei_label ) . '</th>';
		$output .= '<th>' . esc_html( $wc_pin_code_label ) . '</th>';
		$output .= '</tr></thead><tbody>';

		global $WCRB_MANAGE_DEVICES;
		$output .= $WCRB_MANAGE_DEVICES->list_customer_devices( 'customer' );

		$output .= '</tbody></table></div>';

		$output .= '</div>';

		$allowedHTML = wc_return_allowed_tags();
		$output = wp_kses( $output, $allowedHTML );

		return $output;
	}

	function return_add_device_form( $view ) {
		global $WCRB_MANAGE_DEVICES;

		$view = ( isset( $view ) ) ? $view : 'front';

		$wc_device_id_imei_label = ( empty( get_option( 'wc_device_id_imei_label' ) ) ) ? esc_html__( 'ID/IMEI', 'computer-repair-shop' ) : get_option( 'wc_device_id_imei_label' );
		$wc_pin_code_label = ( empty( get_option( 'wc_pin_code_label' ) ) ) ? esc_html__( 'Pin Code/Password', 'computer-repair-shop' ) : get_option( 'wc_pin_code_label' );

		$wc_device_label 	   = ( empty( get_option( 'wc_device_label' ) ) ) ? esc_html__( 'Device', 'computer-repair-shop' ) : get_option( 'wc_device_label' );
		$wc_device_brand_label = ( empty( get_option( 'wc_device_brand_label' ) ) ) ? esc_html__( 'Device Brand', 'computer-repair-shop' ) : get_option( 'wc_device_brand_label' );
		$wc_device_type_label = ( empty( get_option( 'wc_device_type_label' ) ) ) ? esc_html__( 'Device Type', 'computer-repair-shop' ) : get_option( 'wc_device_type_label' );

		$output = '<div class="small reveal" id="deviceFormReveal" data-reveal>';
		$output .= '<h2>' . esc_html__( 'Add New ', 'computer-repair-shop' ) . $wc_device_label . '</h2>';
	
		$output .= '<div class="adddevicecustomermessage"></div>';
	
		$output .= '<form data-async data-abide class="needs-validation" novalidate method="post" data-success-class=".adddevicecustomermessage">';
		$output .= '<input type="hidden" name="form_action" value="wcrb_add_customer_device" />';
		$output .= '<input type="hidden" name="reload_location" value="deviceslistcustomer" />';

		$output .= '<div class="grid-x grid-margin-x">';

		$output .= '<div class="cell medium-6"><label class="have-addition">' . esc_html__( 'Select ', 'computer-repair-shop' ) . $wc_device_type_label . '*';
		$output .= '<select class="wcrbupdatedatalist form-control" name="devicetype">';
		$output .= $WCRB_MANAGE_DEVICES->generate_device_type_options( '', '' );
		$output .= '</select>';
		$output .= '</label></div>';
		
		$output .= '<div class="cell medium-6">
						<label class="have-addition">' . esc_html__( 'Select ', 'computer-repair-shop' ) . $wc_device_brand_label . '*';
		$output .= '<select class="wcrbupdatedatalist form-control" name="manufacture">';
		$output .= $WCRB_MANAGE_DEVICES->generate_manufacture_options( '', '' );
		$output .= '</select>';
		$output .= '</label>
					</div>';
	
		$output .= '<div class="cell medium-6">
						<label>' . $wc_device_label . esc_html__( ' Name', 'computer-repair-shop' ) . '
						   <input list="device_name_list" class="form-control login-field" type="text" id="device_name" name="device_name" />
						</label>';
		$output .= '<datalist id="device_name_list">';
		$output .= $this->wc_return_devices_datalist();
		$output .= '</datalist>';
		$output .= '</div>';

		$output .= '<div class="cell medium-6">
						<label>' . $wc_device_id_imei_label . '
							<input name="imei_serial" type="text" class="form-control login-field"
								   value="" id="imei_serial"/>
						</label>';
		$output .= '</div>';

		$output .= '<div class="cell medium-6">
						<label>' . $wc_pin_code_label . '
							<input name="device_pincode" type="text" class="form-control login-field"
								   value="" id="device_pincode"/>
						</label>';
		$output .= '</div>';
					
		$output .= '</div>';
		
		$output .= '<input name="form_type" type="hidden" value="add_device_form_front" />';
		$output .=  wp_nonce_field( 'wcrb_add_device_nonce', 'wcrb_add_device_nonce_post', true, false);

		$output .= '<div class="grid-x grid-margin-x">
					<fieldset class="cell medium-6">
						<button class="button" type="submit">' . esc_html__( "Add ", "computer-repair-shop" ) . $wc_device_label . '</button>
					</fieldset>
				</div>
			</form>
	
			<button class="close-button" data-close aria-label="Close modal" type="button">
				<span aria-hidden="true">&times;</span>
			</button>
		</div>';

		$allowedHTML = ( function_exists( 'wc_return_allowed_tags' ) ) ? wc_return_allowed_tags() : '';
		return wp_kses( $output, $allowedHTML );
	}

	function wc_return_devices_datalist() { 
		$values = array();

		//Register User
		$theBrandId = ( isset( $_POST['theBrandId'] ) && $_POST['theBrandId'] != 'All' ) ? sanitize_text_field( $_POST['theBrandId'] ) : '';

		$wcrb_type = 'rep_devices';
		$wcrb_tax = 'device_brand';

		if ( wcrb_use_woo_as_devices() == 'YES' ) {
			$wcrb_type = 'product';
			$wcrb_tax = 'product_cat';
		}
		
		if ( isset( $_POST['theTypeId'] ) && ! empty( $_POST['theTypeId'] ) && $_POST['theTypeId'] != 'All'  && $wcrb_type != 'product' ) {
			$theTypeId = ( isset( $_POST['theTypeId'] ) ) ? sanitize_text_field( $_POST['theTypeId'] ) : '';

			$query_devices = array(
				'posts_per_page' => -1,
				'post_type'      => $wcrb_type,
				'tax_query'      => array(
					'relation'   => 'AND',
					array (
						'taxonomy'  => $wcrb_tax,
						'field'     => 'term_id',
						'terms'     => $theBrandId,
					),
					array (
						'taxonomy'  => 'device_type',
						'field'     => 'term_id',
						'terms'     => $theTypeId,
					),
				),
			);
			if ( empty( $theBrandId ) ) {
				$query_devices = array(
					'posts_per_page' => -1,
					'post_type'      => $wcrb_type,
					'tax_query'      => array(
						array (
							'taxonomy'  => 'device_type',
							'field'     => 'term_id',
							'terms'     => $theTypeId,
						),
					),
				);	
			}
		} else {
			if ( empty( $theBrandId ) ) {
				$query_devices = array(
					'posts_per_page' => -1,
					'post_type'      => $wcrb_type,
				);
			} else {
				$query_devices = array(
					'posts_per_page' => -1,
					'post_type'      => $wcrb_type,
					'tax_query'      => array(
						array (
							'taxonomy'  => $wcrb_tax,
							'field'     => 'term_id',
							'terms'     => $theBrandId,
						),
					),
				);
			}
		}
		$wc_device_query = new WP_Query( $query_devices );
		$values['message'] = '';
		if( $wc_device_query->have_posts() ) : 
			$post_output = '';
			while( $wc_device_query->have_posts() ): 
					$wc_device_query->the_post();
					$device_id = get_the_ID();
					$post_output .= '<option value="' . get_the_title() . '"></option>';
			endwhile;
			$values['message'] = $post_output;
		endif;
		wp_reset_postdata();
		
		if ( isset( $_POST['theBrandId'] ) || isset( $_POST['theTypeId'] ) ) {
			wp_send_json( $values );
			wp_die();
		} else {
			return $values['message'];
		}
	}
	function wcrb_add_customer_device() {
		global $wpdb;

		$message = '';
		if (!isset( $_POST['wcrb_add_device_nonce_post'] ) 
			|| ! wp_verify_nonce( $_POST['wcrb_add_device_nonce_post'], 'wcrb_add_device_nonce' ) ) :
				$message = esc_html__( "Something is wrong with your submission!", "computer-repair-shop");
				$error = 1;
		endif;

		$customer_id = get_current_user_id();

		if ( empty( $customer_id ) ) {
			$message = esc_html__( 'Missing customer', 'computer-repair-shop' );
			$error = 1;
		}

		$wc_device_brand_label = ( empty( get_option( 'wc_device_brand_label' ) ) ) ? esc_html__( 'Device Brand', 'computer-repair-shop' ) : get_option( 'wc_device_brand_label' );
		$wc_device_type_label = ( empty( get_option( 'wc_device_type_label' ) ) ) ? esc_html__( 'Device Type', 'computer-repair-shop' ) : get_option( 'wc_device_type_label' );
		$wc_device_id_imei_label = ( empty( get_option( 'wc_device_id_imei_label' ) ) ) ? esc_html__( 'ID/IMEI', 'computer-repair-shop' ) : get_option( 'wc_device_id_imei_label' );
		$wc_pin_code_label = ( empty( get_option( 'wc_pin_code_label' ) ) ) ? esc_html__( 'Pin Code/Password', 'computer-repair-shop' ) : get_option( 'wc_pin_code_label' );
		$wc_device_label 	   = ( empty( get_option( 'wc_device_label' ) ) ) ? esc_html__( 'Device', 'computer-repair-shop' ) : get_option( 'wc_device_label' );
		
		$error = 0;
		//Process my device
		if ( ! isset( $_POST['devicetype'] ) || $_POST['devicetype'] == 'All' || empty( $_POST['devicetype'] ) ) {
			$message = esc_html__( 'Please select ', 'computer-repair-shop' ) . esc_html( $wc_device_type_label );
			$error = 1;
		} elseif ( ! isset( $_POST['device_name'] ) || empty( $_POST['device_name'] ) ) {
			$message = esc_html__( 'Please enter ', 'computer-repair-shop' ) . esc_html( $wc_device_label );
			$error = 1;
		} elseif ( ! isset( $_POST['imei_serial'] ) || empty( $_POST['imei_serial'] ) ) {
			$message = esc_html__( 'Please enter ', 'computer-repair-shop' ) . esc_html( $wc_device_id_imei_label );
			$error = 1;
		}

		if ( $error == 0 ) {
			$devicetype 	= ( ! empty( $_POST['devicetype'] ) ) ? sanitize_text_field( $_POST['devicetype'] ) : '';
			$manufacture 	= ( ! empty( $_POST['manufacture'] ) || $_POST['manufacture'] != 'All' ) ? sanitize_text_field( $_POST['manufacture'] ) : '';
			$device_name 	= ( ! empty( $_POST['device_name'] ) ) ? sanitize_text_field( $_POST['device_name'] ) : '';
			$imei_serial 	= ( ! empty( $_POST['imei_serial'] ) ) ? sanitize_text_field( $_POST['imei_serial'] ) : '';
			$device_pincode = ( ! empty( $_POST['device_pincode'] ) ) ? sanitize_text_field( $_POST['device_pincode'] ) : '';

			$computer_repair_customer_devices = $wpdb->prefix.'wc_cr_customer_devices';

			$wc_meta_value	 = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$computer_repair_customer_devices} WHERE `customer_id` = %d AND `serial_nuumber` = %s", $customer_id, $imei_serial ) );
			if ( ! empty( $wc_meta_value ) ) {
				$message = esc_html__( 'You already have device with same ', 'computer-repair-shop' ) . esc_html( $wc_device_id_imei_label );
			} else {
				$device_post_id = '';
				$args = array(
					'post_type'  => 'rep_devices',
					'title'		=> $device_name,
					'numberposts' => 1,
				);
				$postslist = get_posts( $args );
		
				foreach( $postslist as $post ) {
					$device_post_id = $post->ID;
				}
				if ( empty( $device_post_id ) ) {
					//Insert post and retrive id.
					$post_arr = array(
						'post_title'   => $device_name,
						'post_type'	   => 'rep_devices',
						'post_content' => '',
						'post_status'  => 'draft',
						'post_author'  => $customer_id,
						'tax_input'    => array(
							'device_brand' => array( $manufacture ),
							'device_type'  => array( $devicetype ),
						)
					);
					$device_post_id = wp_insert_post( $post_arr );
				}

				$device_label = return_device_label( $device_post_id );
				$insert_query = "INSERT INTO 
								`" . $computer_repair_customer_devices . "` 
							VALUES
								(NULL, %d, %s, %s, %s, %d)";
				$wpdb->query(
						$wpdb->prepare( $insert_query, array( $device_post_id, $device_label, $imei_serial, $device_pincode, $customer_id ) )
				);
				$history_id = $wpdb->insert_id;
				$message = esc_html__( 'Records updated!', 'computer-repair-shop' );
				$values['success'] = 'YES';
			}
		}
		$values['message'] = $message;
		wp_send_json( $values );
		wp_die();
	}

	function list_cusomter_reviews( $customer_id, $job_status ) {
		if ( ! is_user_logged_in() ) {
			return esc_html__( 'You are not logged in.', 'computer-repair-shop' );
			exit;
		} 

		if ( empty( $customer_id ) || empty( $job_status ) ) {
			return esc_html__( 'Requires a customer id.', 'computer-repair-shop' );
			exit;	
		}

		$loadAllJobs = 'NO';

		$user_role_string = '_customer';

		$meta_query_b = array(
			'key' 		=> $user_role_string,
			'value' 	=> $customer_id,
			'compare' 	=> '=',
		);
		$meta_query_b = ( $loadAllJobs == 'YES' ) ? array() : $meta_query_b;

		$meta_query_arr = array(
			$meta_query_b,
			array(
				'key'		=> '_wc_order_status',
				'value'		=> sanitize_text_field( $job_status ),
				'compare'	=> '=',
			)
		);

		//WordPress Query for Rep Jobs
		$jobs_args = array(
			'post_type' 		=> 'rep_jobs',
			'orderby'			=> 'id',
			'order' 			=> 'DESC',
			'posts_per_page' 	=> -1,
			'post_status'		=> array('publish'),
			'meta_query' 		=> $meta_query_arr,
		);

		$jobs_query = new WP_Query( $jobs_args );

		$content = '';

		if ( $jobs_query->have_posts() ): while( $jobs_query->have_posts() ): 
			$jobs_query->the_post();

			$job_id 		= $jobs_query->post->ID;
			$case_number 	= get_post_meta( $job_id, '_case_number', true );
			$order_date 	= get_the_date( '', $job_id);
			$order_total 	= wc_order_grand_total( $job_id, 'grand_total' );
			$order_total	= wc_cr_currency_format( $order_total );

			$device_post_id	 = get_post_meta( $job_id, '_device_post_id', true );
			$current_devices = get_post_meta( $job_id, '_wc_device_data', true );

			$devicess = '';
			if ( ! empty( $current_devices )  && is_array( $current_devices ) ) {
				$counter = 0;
				
				foreach( $current_devices as $device_data ) {
					$devicess .= ( $counter != 0 ) ? '<br>' : '';				
					$device_post_id = ( isset( $device_data['device_post_id'] ) ) ? $device_data['device_post_id'] : '';
					$device_id      = ( isset( $device_data['device_id'] ) ) ? $device_data['device_id'] : '';
	
					$devicess .= return_device_label( $device_post_id );
					$devicess .= ( ! empty ( $device_id ) ) ? ' (' . esc_html( $device_id ) . ')' : '';
					$counter++;
				}
			}

			$content .= '<tr>';
			$content .= '<td>' . esc_html( $job_id ) . '</td>';
			$content .= '<td>' . esc_html( $case_number ) . '</td>';
			$content .= '<td>' . esc_html( $order_date ) . '</td>';
			$content .= '<td>' . wp_kses_post( $devicess ) . '</td>';
			$content .= '<td>' . esc_html( $order_total ) . '</td>';

			$review_id 	   = get_post_meta( $job_id, '_review_id', true );
			$review_rating = ( ! empty( $review_id ) ) ? get_post_meta( $review_id, '_review_rating', true ) : 0;
			$review_rating = ( ! empty( $review_rating ) ) ? $review_rating : 0;

			$content .= '<td><div class="ratings column-ratings review-ratings"><i data-star="'. esc_attr( $review_rating ) .'"></i></div></td>';

			$_feedback_page = get_option( 'wc_rb_get_feedback_page_id' );

			if ( ! empty( $_feedback_page ) ) {
				$page_link = wc_rb_return_get_feedback_link( '', $job_id );

				$content .= '<td><a href="' . esc_url( $page_link ) . '" target="_blank">' . esc_html__( 'View/Review', 'computer-repair-shop' ) . '</a></td>';
			} else {
				$content .= '<td><a href="">-</a></td>';
			}
			$content .= '</tr>';

		endwhile;
		else:
			$content .= esc_html__( 'No job found!', 'computer-repair-shop' );
		endif;

		wp_reset_postdata();

		return $content;
	}
}