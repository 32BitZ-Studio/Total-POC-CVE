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

class WCRB_EMAILS {
    public $HEADERS = array('Content-Type: text/html; charset=UTF-8');

	function send_user_logins_after_register( $user_id, $password ) {
		if ( empty( $user_id ) ) {
			return;
		}
		if ( empty( $password ) ) {
			$passMessage = esc_html__( 'Please reset your password if you do not have your password.', 'computer-repair-shop' ) . "/r/n/r/n";	
		} else {
			$passMessage = sprintf( esc_html__( 'Password: %s', 'computer-repair-shop' ), $password );
		}
		
		$user = get_user_by( 'id', $user_id );

		$user_login = stripslashes( $user->user_login );
		$user_email = stripslashes( $user->user_email );
		if ( empty( $user_email ) ) {
			return;
		}

		$blogname	= get_option( 'blogname' );

		$loginURL = ( ! empty( get_option( 'wc_rb_my_account_page_id' ) ) ) ? get_the_permalink( get_option( 'wc_rb_my_account_page_id' ) ) : wp_login_url();

		$message  = '<p>' . esc_html__( 'Hi there,', 'computer-repair-shop' ) . '<br><br>';
		$message .= sprintf( __( "Welcome to %s! Here's how to log in:", 'computer-repair-shop' ), esc_html( $blogname ) ) . "<br><br>";
		$message .= esc_url( $loginURL ) . "<br><br>";
		$message .= sprintf( esc_html__( 'Username: %s', 'computer-repair-shop' ), $user_login ) . "<br>";
		$message .= sprintf( esc_html__( 'Email: %s', 'computer-repair-shop' ), $user_email ) . "<br>";
		$message .= $passMessage . '<br><br>';
		$message .= sprintf( esc_html__( 'If you have any problems, please contact us at %s.', 'computer-repair-shop' ), get_option('admin_email') ) . "<br><br>";
		$message .= esc_html__( 'Thank You!', 'computer-repair-shop' ) . '<br>';

		$subject = sprintf( esc_html__( '[%s] Your credentials.', 'computer-repair-shop' ), $blogname );

		$body_output = wc_rs_get_email_head();
		$body_output .= $message;
		$body_output .= wc_rs_get_email_footer();

		$this->send_email( $user_email, $subject, $body_output );
	}

    function booking_email_to_customer( $job_id, $mailto ) {
        if ( empty( $job_id ) || empty( $mailto ) ) {
            return;
        }

		$email_message = ( empty( get_option( 'booking_email_body_to_customer' ) ) ) ? '' : get_option( 'booking_email_body_to_customer' );

$message = 'Hello {{customer_full_name}},

Thank you for booking. We have received your job id : {{job_id}} and assigned you case number : {{case_number}}

For your device : {{customer_device_label}} 

Note: Job status page will not able to show your job details unless its approved from our side. During our working hours its done quickly.

We will get in touch whenever its needed. You can always check your job status by clicking {{start_anch_status_check_link}} Check Status {{end_anch_status_check_link}}.

Direct status check link : {{status_check_link}}

Details which we have received from you are below. 

{{order_invoice_details}}

Thank you again for your business!';
							
		$email_message = ( empty( $email_message ) ) ? $message : $email_message;

		if ( empty( $email_message ) ) {
			return;
		}

        $body_message = $this->return_body_replacing_keywords( array( 'job_id' => $job_id, 'email_message' => $email_message) );

        $menu_name_p = get_option( 'blogname' );
		$subject 	 = ( ! empty ( get_option( 'booking_email_subject_to_customer' ) ) ) ? get_option( 'booking_email_subject_to_customer' ) : 'We have received your booking order! | ' . $menu_name_p;

        $this->send_email( $mailto, $subject, $body_message );

        //Add Job history
        $args = array(
            "job_id" 		=> $job_id, 
            "name" 			=> esc_html__( 'Booking confirmation email sent to', 'computer-repair-shop' ), 
            "type" 			=> 'public', 
            "field" 		=> '_booking_email_to_customer', 
            "change_detail" => 'To : ' . $mailto
        );
        $WCRB_JOB_HISTORY_LOGS = WCRB_JOB_HISTORY_LOGS::getInstance();
        $WCRB_JOB_HISTORY_LOGS->wc_record_job_history( $args );
	}

    function booking_email_to_administrator( $job_id, $mailto ) {
        if ( empty( $job_id ) || empty( $mailto ) ) {
            return;
        }

		$email_message = ( empty( get_option( 'booking_email_body_to_admin' ) ) ) ? '' : get_option( 'booking_email_body_to_admin' );

$message = 'Hello,

You have received a new booking job ID: {{job_id}} Case number: {{case_number}}.

From Customer : {{customer_full_name}}

Job Details are listed below.

{{order_invoice_details}}
';
		$email_message = ( empty( $email_message ) ) ? $message : $email_message;

		if ( empty( $email_message ) ) {
			return;
		}

        $body_message = $this->return_body_replacing_keywords( array( 'job_id' => $job_id, 'email_message' => $email_message) );

        $menu_name_p = get_option( 'blogname' );
		$subject 	 = ( ! empty ( get_option( 'booking_email_subject_to_admin' ) ) ) ? get_option( 'booking_email_subject_to_admin' ) : 'You have new booking order | ' . $menu_name_p;

        $this->send_email( $mailto, $subject, $body_message );

        //Add Job history
        $args = array(
            "job_id" 		=> $job_id, 
            "name" 			=> esc_html__( 'Booking email sent to', 'computer-repair-shop' ), 
            "type" 			=> 'public', 
            "field" 		=> '_booking_email_to_administrator', 
            "change_detail" => 'To : ' . $mailto
        );
        $WCRB_JOB_HISTORY_LOGS = WCRB_JOB_HISTORY_LOGS::getInstance();
        $WCRB_JOB_HISTORY_LOGS->wc_record_job_history( $args );
    }

    //Available Keywords {{customer_full_name}} {{status_check_link}} {{start_anch_status_check_link}} Check Status {{end_anch_status_check_link}} 
    //{{order_invoice_details}} {{job_id}} {{case_number}} {{customer_device_label}}
    //{{st_feedback_anch}} {{end_feedback_anch}} {{feedback_link}}
    //{{estimate_id}} 
    //{{start_approve_estimate_link}}Approve Estimate{{end_approve_estimate_link}} {{start_reject_estimate_link}}Reject Estimate {{end_reject_estimate_link}}
    //Arguments array( 'job_id' => '', 'email_message' => '', 'record_feed_type' => 'YES/NO' )
    //order_invoice_details
    function return_body_replacing_keywords( $args ) {
        global $WCRB_REVIEWS_OBJ;

        if ( ! isset( $args['job_id'] ) || empty( $args['job_id'] ) || ! isset( $args['email_message'] ) || empty( $args['email_message'] ) ) {
			return;
		}
        $job_id = $args['job_id'];
        $email_message = esc_textarea( $args['email_message'] );

        $customer_full_name = $customer_device_label = $status_check_link = $end_feedback_anch = $st_feedback_anch = $feedback_link = $start_anch_status_check_link = '';
        $end_anch_status_check_link = $order_invoice_details = $case_number = $user_email = $phone_number = '';
        
        $estimate_id = $start_approve_estimate_link = $end_approve_estimate_link = $start_reject_estimate_link = $end_reject_estimate_link = '';

        $estimate_id = $job_id;

        $selected_page = get_option( 'wc_rb_status_check_page_id' );

        if ( ! empty( $selected_page ) ) {
            $page_link = get_the_permalink( $selected_page );
            $case_number = get_post_meta( $estimate_id, '_case_number', true );
            
            $appro_params = array( 'estimate_id' => $job_id, 'case_number' => $case_number, 'choice' => 'approved' );
            $reje_params  = array( 'estimate_id' => $job_id, 'case_number' => $case_number, 'choice' => 'rejected' );
            
            $approve_url = add_query_arg( $appro_params, $page_link );
            $reject_url = add_query_arg( $reje_params, $page_link );

            $start_approve_estimate_link = '<a href="' . esc_url( $approve_url ) . '">';
            $end_approve_estimate_link = '</a>';
            $start_reject_estimate_link = '<a href="' . esc_url( $reject_url ) . '">';
            $end_reject_estimate_link = '</a>';
        }
        $case_number = get_post_meta( $job_id, '_case_number', true );

        $customer_id = get_post_meta( $job_id, "_customer", true );
		if ( ! empty( $customer_id ) ) {
            $user_info 	= get_userdata( $customer_id );
            $customer_full_name = $user_info->first_name . ' ' . $user_info->last_name;
            $user_email = $user_info->user_email;
            $phone_number = get_user_meta( $customer_id, 'billing_phone', true );
        }
		
		$current_devices = get_post_meta( $job_id, '_wc_device_data', true );

		$customer_device_label = '';
		if ( ! empty( $current_devices )  && is_array( $current_devices ) ) {
            foreach( $current_devices as $device_data ) { 
				$device_post_id = ( isset( $device_data['device_post_id'] ) ) ? $device_data['device_post_id'] : '';
				$customer_device_label = return_device_label( $device_post_id );
			}
		}

        if ( isset( $args['record_feed_type'] ) && ! empty( $args['record_feed_type'] ) ) {
            $email_ = ( $args['record_feed_type'] == 'email' ) ? $user_email : '-';
            $phone_ = ( $args['record_feed_type'] == 'sms' ) ? $phone_number : '-';

            $args = array( 'job_id' => $job_id, 'email_to' => $email_, 'sms_to' => $phone_, 'type' => $args['record_feed_type'], 'action' => 'Not clicked' );
            $feedback_id = $WCRB_REVIEWS_OBJ->wcrb_add_feedback_log( $args );
        } else {
            $feedback_id = 'NO';
        }
		$feedback_link = wc_rb_return_get_feedback_link( $feedback_id, $job_id );

		$end_feedback_anch = '</a>';
		$st_feedback_anch = '<a href="' . esc_url( $feedback_link ) . '" target="_blank">';

        $status_check_link              = wc_rb_return_status_check_link( $job_id );

        $end_anch_status_check_link     = '</a>';
		$start_anch_status_check_link   = '<a href="' . esc_url( $status_check_link ) . '" target="_blank">';

        $order_invoice_details = '<div class="repair_box">' . wc_print_order_invoice( $job_id, 'email' ) . '</div>';

		//Available Keywords 
        $email_message = ( ! empty( $customer_full_name ) ) ? str_replace( '{{customer_full_name}}', $customer_full_name, $email_message ) : $email_message;
        $email_message = ( ! empty( $customer_device_label ) ) ? str_replace( '{{customer_device_label}}', $customer_device_label, $email_message ) : $email_message;
        $email_message = ( ! empty( $status_check_link ) ) ? str_replace( '{{status_check_link}}', $status_check_link, $email_message ) : $email_message;
        $email_message = ( ! empty( $end_feedback_anch ) ) ? str_replace( '{{end_feedback_anch}}', $end_feedback_anch, $email_message ) : $email_message;
        $email_message = ( ! empty( $st_feedback_anch ) ) ? str_replace( '{{st_feedback_anch}}', $st_feedback_anch, $email_message ) : $email_message;
        $email_message = ( ! empty( $feedback_link ) ) ? str_replace( '{{feedback_link}}', $feedback_link, $email_message ) : $email_message;
        $email_message = ( ! empty( $estimate_id ) ) ? str_replace( '{{estimate_id}}', $estimate_id, $email_message ) : $email_message;
        $email_message = ( ! empty( $start_approve_estimate_link ) ) ? str_replace( '{{start_approve_estimate_link}}', $start_approve_estimate_link, $email_message ) : $email_message;
        $email_message = ( ! empty( $end_approve_estimate_link ) ) ? str_replace( '{{end_approve_estimate_link}}', $end_approve_estimate_link, $email_message ) : $email_message;
        $email_message = ( ! empty( $start_reject_estimate_link ) ) ? str_replace( '{{start_reject_estimate_link}}', $start_reject_estimate_link, $email_message ) : $email_message;
        $email_message = ( ! empty( $end_reject_estimate_link ) ) ? str_replace( '{{end_reject_estimate_link}}', $end_reject_estimate_link, $email_message ) : $email_message;
        $email_message = ( ! empty( $start_anch_status_check_link ) ) ? str_replace( '{{start_anch_status_check_link}}', $start_anch_status_check_link, $email_message ) : $email_message;
        $email_message = ( ! empty( $end_anch_status_check_link ) ) ? str_replace( '{{end_anch_status_check_link}}', $end_anch_status_check_link, $email_message ) : $email_message;
        $email_message = ( ! empty( $job_id ) ) ? str_replace( '{{job_id}}', $job_id, $email_message ) : $email_message;
        $email_message = ( ! empty( $case_number ) ) ? str_replace( '{{case_number}}', $case_number, $email_message ) : $email_message;

        $email_message = nl2br( $email_message );

        $email_message = ( ! empty( $order_invoice_details ) ) ? str_replace( '{{order_invoice_details}}', $order_invoice_details, $email_message ) : $email_message;

		return $email_message;
    }

    function send_email( $to, $subject, $body  ) {
        if ( empty( $to ) || empty( $subject ) || empty( $body ) ) {
            return;
        }

        $body_output = wc_rs_get_email_head();
        $body_output .= wp_kses_post( $body );
        $body_output .= wc_rs_get_email_footer();

        wp_mail( $to, $subject, $body_output, $this->HEADERS );
    }	
}