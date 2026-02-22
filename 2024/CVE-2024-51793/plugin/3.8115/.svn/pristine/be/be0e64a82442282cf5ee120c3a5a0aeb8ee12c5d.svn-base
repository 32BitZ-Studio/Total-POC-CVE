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

class WCRB_SMS_SYSTEM {

    private $identifier = 'wc_rb_page_sms_IDENTIFIER';

    function __construct() {
        add_action( 'wc_rb_settings_tab_menu_item', array( $this, 'add_sms_page_tab_in_setting_menu' ), 10, 2 );
        add_action( 'wc_rb_settings_tab_body', array( $this, 'add_sms_page_tab_in_setting_body' ), 10, 2 );
		add_action( 'wp_ajax_wc_post_sms_configuration_index', array( $this, 'wc_post_sms_configuration_index' ), 10, 2 );
		add_action( 'wp_ajax_wc_rb_return_sms_api_fields', array( $this, 'wc_rb_return_sms_api_fields' ), 10, 2 );
    }

    function add_sms_page_tab_in_setting_menu() {
        $active = '';

        $menu_output = '<li class="tabs-title' . esc_attr( $active ) . '" role="presentation">';
        $menu_output .= '<a href="#'. $this->identifier .'" role="tab" aria-controls="' . $this->identifier . '" aria-selected="true" id="' . $this->identifier . '-label">';
        $menu_output .= '<h2>' . esc_html__( 'SMS', 'computer-repair-shop' ) . '</h2>';
        $menu_output .=	'</a>';
        $menu_output .= '</li>';

        echo wp_kses_post( $menu_output );
    }
	
	function add_sms_page_tab_in_setting_body() {
        global $wpdb;

        $active = '';

		$setting_body = '<div class="tabs-panel team-wrap' . esc_attr( $active ) . '" 
        id="' . $this->identifier . '" 
        role="tabpanel" 
        aria-hidden="true" 
        aria-labelledby="' . $this->identifier . '-label">';

		if ( ! wc_rs_license_state() ) {
			$setting_body .= '<h2>' . esc_html__( 'Activation of plugin is required to send SMS. However you can still add and gateways reminders', 'computer-repair-shop' ) . '</h2>';
			$setting_body .= wc_cr_new_purchase_link("");
		}

		$setting_body .= '<div class="wrap"><div class="form-message"></div>';
		$setting_body .= '<h3>' . esc_html__( 'Select your SMS Gateway and enter its API codes.', 'computer-repair-shop' ) . '</h3>';

		$setting_body .= '<form data-async data-abide class="needs-validation" name="submit_the_sms_configuration_form" novalidate method="post">';
		$setting_body .= '<table cellpadding="5" cellspacing="5" class="form-table border">';
		$setting_body .= '<tbody>';

		//Turn on SMS 
		$setting_body .= '<tr>
							<th scope="row">
								<label for="wc_rb_sms_active">
									' . esc_html__( 'Activate SMS for selective statuses', 'computer-repair-shop' ) . '
								</label>
							</th>';
		$setting_body .= '<td>';

		$is_sms_active = get_option( 'wc_rb_sms_active' );
		$theChecked    = ( $is_sms_active == 'YES' ) ? 'checked' : '';
		
		$setting_body .= '<input '. esc_attr( $theChecked ) .' type="checkbox" id="wc_rb_sms_active" name="wc_rb_sms_active" value="YES" />';

		$setting_body .= '</td></tr>';
		
		$setting_body .= '<tr>
							<th scope="row">
								<label for="wc_rb_sms_gateway">
									' . esc_html__( 'Select SMS Gateway', 'computer-repair-shop' ) . '
								</label>
							</th>';
		$setting_body .= '<td>';

		$selected_page = get_option( 'wc_rb_sms_gateway' );
		$default_label = esc_html__( 'Select SMS Gateway', 'computer-repair-shop' );

		$setting_body .= '<select name="wc_rb_sms_gateway" id="wc_rb_sms_gateway" class="form-select">';
		$setting_body .= $this->wc_rb_return_sms_gateway_options( $selected_page, $default_label );
		$setting_body .= '</select>';

		$setting_body .= '</td></tr></tbody>';

		$setting_body .= '<tbody id="authenticaion_api_data">';

		$setting_body .= $this->return_sms_api_html_fields( $selected_page );

		$setting_body .= '</tbody>';

		//Select Job Status Options
		$setting_body .= '<tbody><tr>
							<th scope="row">
								<label for="wc_rb_job_status_include">
									' . esc_html__( 'Send message when status changed to', 'computer-repair-shop' ) . '
								</label>
							</th>';
		$setting_body .= '<td>';

		$selected_page = get_option( 'wc_rb_job_status_include' );

		$setting_body .= '<fieldset class="fieldset">
                            <legend>'.esc_html__("Select job status to include", "computer-repair-shop").'</legend>';
		$setting_body .= $this->wc_rb_generate_status_checkboxes( $selected_page );
		$setting_body .= '<p>' . esc_html__( 'To make SMS working do not forget to add message in status message field by editing the status.', 'computer-repair-shop' ) . '</p>';
		$setting_body .= '</fieldset>';

		$setting_body .= '</td></tr>';

		$setting_body .= '<!-- Login Form Ends /-->
				<input name="form_type" type="hidden" 
								value="submit_the_sms_configuration_form" />';

		$setting_body .= '<tr><td colspan="2"><button class="button button-primary" type="submit">' . esc_html__( 'Submit', 'computer-repair-shop' ) . '</button></td></tr>';

		$setting_body .= '</tbody>';
		$setting_body .= '</table>';
		$setting_body .= '</form>';

		$last_sms_response = get_option( 'last_sms_response' );

		if ( ! empty( $last_sms_response ) ) {
			$setting_body .= '<div class="callout"><h2>' . esc_html__( 'Last SMS Response', 'computer-repair-shop' ) . '</h2>' . esc_html__( $last_sms_response ) .'</div>';
		}

		$setting_body .= '</div>';
       
        $setting_body .= '</div><!--Tabs Panel /-->';

		$allowedHTML = ( function_exists( 'wc_return_allowed_tags' ) ) ? wc_return_allowed_tags() : '';
		echo wp_kses( $setting_body, $allowedHTML );
	}
    
	/**
	 * Return SMS Gateway Options
	 */
	function wc_rb_return_sms_gateway_options( $selected, $default_label, $default_value = '' ) {
		if ( empty ( $selected ) ) {
			$selected = '';
		}
		$gateway_array = array(
			'twilio'  		 => esc_html__( 'Twilio', 'computer-repair-shop' ),
			'releans' 		 => esc_html__( 'Releans', 'computer-repair-shop' ),
			'capitolemobile' => esc_html__( 'Capitole Mobile', 'computer-repair-shop' ),
			'bitelietuva' => esc_html__( 'Bite Lietuva', 'computer-repair-shop' ),
			'smschef' 		 => esc_html__( 'SMSChef', 'computer-repair-shop' ),
		);

		$options  = '';

		if ( ! empty( $default_label ) ) {
			$default_value = ( empty( $default_value ) ) ? '' : $default_value;
			$options .= '<option value="' . $default_value . '">' . $default_label . '</option>';
		}

		foreach ( $gateway_array as $key => $gateway ) {
			$selectedLabel = ( $selected == $key ) ? ' selected="selected"' : '';
			$options .= '<option' . $selectedLabel . ' value="' . $key . '">' . $gateway . '</option>';
		}
		return $options;
	}

	function wc_rb_return_sms_api_fields() {
		$form_type 			= sanitize_text_field( $_POST['form_type'] );
		$wc_rb_sms_gateway 	= sanitize_text_field( $_POST['wc_rb_sms_gateway'] );

		$theHTML = '';

		if ( $form_type == 'wc_rb_update_sms_api_fields' ) {
			$theHTML = $this->return_sms_api_html_fields( $wc_rb_sms_gateway );
		}

		$values["html"]	   = $theHTML;
		$values['success'] = "YES";

		wp_send_json( $values );
		wp_die();
	}

	function return_sms_api_html_fields( $gateway_type ) {
		if ( empty ( $gateway_type ) ) {
			return '<tr id="sms-api-settings" class="sms-api-int-field"></tr>';
		}

		if ( $gateway_type == 'twilio' ) :
			$wc_rb_twilio_account_sid  = get_option( 'wc_rb_twilio_account_sid' );
			$wc_rb_twilio_auth_token   = get_option( 'wc_rb_twilio_auth_token' );
			$wc_rb_twilio_from_number  = get_option( 'wc_rb_twilio_from_number' );

			$return_HTML = '';

			//Account SID
		    $return_HTML .= '<tr class="sms-api-int-field">
								<th scope="row">
									<label for="wc_rb_twilio_account_sid">
										' . esc_html__( 'Account SID', 'computer-repair-shop' ) . '
									</label>
								</th>';
			$return_HTML .= '<td>';

			$return_HTML .= '<input type="text" name="wc_rb_twilio_account_sid" id="wc_rb_twilio_account_sid" value="' . esc_html( $wc_rb_twilio_account_sid )  . '" class="form-select">';
			$return_HTML .= '</td></tr>';

			//Account Auth Token
			$return_HTML .= '<tr class="sms-api-int-field">
								<th scope="row">
									<label for="wc_rb_twilio_auth_token">
										' . esc_html__( 'Auth Token', 'computer-repair-shop' ) . '
									</label>
								</th>';
			$return_HTML .= '<td>';

			$return_HTML .= '<input type="text" name="wc_rb_twilio_auth_token" id="wc_rb_twilio_auth_token" value="' . esc_html( $wc_rb_twilio_auth_token ) . '" class="form-select">';
			$return_HTML .= '</td></tr>';

			//From Number
			$return_HTML .= '<tr class="sms-api-int-field">
								<th scope="row">
									<label for="wc_rb_twilio_from_number">
										' . esc_html__( 'From Number', 'computer-repair-shop' ) . '
									</label>
								</th>';
			$return_HTML .= '<td>';

			$return_HTML .= '<input type="text" name="wc_rb_twilio_from_number" id="wc_rb_twilio_from_number" value="' . esc_html( $wc_rb_twilio_from_number )  . '" class="form-select">';
			$return_HTML .= '</td></tr>';
		endif;

		if ( $gateway_type == 'releans' ) {
			$wc_rb_releans_sender_id = get_option( 'wc_rb_releans_sender_id' );
			$wc_rb_releans_api_key   = get_option( 'wc_rb_releans_api_key' );

			$return_HTML = '';

			//Sender ID
		    $return_HTML .= '<tr class="sms-api-int-field">
								<th scope="row">
									<label for="wc_rb_releans_sender_id">
										' . esc_html__( 'Sender ID', 'computer-repair-shop' ) . '
									</label>
								</th>';
			$return_HTML .= '<td>';

			$return_HTML .= '<input type="text" name="wc_rb_releans_sender_id" id="wc_rb_releans_sender_id" value="' . esc_html( $wc_rb_releans_sender_id )  . '" class="form-select">';
			$return_HTML .= '</td></tr>';

			//API Key
			$return_HTML .= '<tr class="sms-api-int-field">
								<th scope="row">
									<label for="wc_rb_releans_api_key">
										' . esc_html__( 'API Key', 'computer-repair-shop' ) . '
									</label>
								</th>';
			$return_HTML .= '<td>';

			$return_HTML .= '<input type="text" name="wc_rb_releans_api_key" id="wc_rb_releans_api_key" value="' . esc_html( $wc_rb_releans_api_key )  . '" class="form-select">';
			$return_HTML .= '</td></tr>';
		}

		if ( $gateway_type == 'smschef' ) {
			$wc_rb_smschef_secret = get_option( 'wc_rb_smschef_secret' );
			$wc_rb_smschef_mode   = get_option( 'wc_rb_smschef_mode' );
			$wc_rb_smschef_sim   = get_option( 'wc_rb_smschef_sim' );
			$wc_rb_smschef_device_id = get_option( 'wc_rb_smschef_device_id' );

			$return_HTML = '';

			//Secret
		    $return_HTML .= '<tr class="sms-api-int-field">
								<th scope="row">
									<label for="wc_rb_smschef_secret">
										' . esc_html__( 'Secret', 'computer-repair-shop' ) . '
									</label>
								</th>';
			$return_HTML .= '<td>';

			$return_HTML .= '<input type="text" name="wc_rb_smschef_secret" id="wc_rb_smschef_secret" value="' . esc_html( $wc_rb_smschef_secret )  . '" class="form-select">';
			$return_HTML .= '</td></tr>';

			$return_HTML .= '<tr class="sms-api-int-field">
								<th scope="row">
									<label for="wc_rb_smschef_mode">
										' . esc_html__( 'Mode (devices, credits)', 'computer-repair-shop' ) . '
									</label>
								</th>';
			$return_HTML .= '<td>';

			$return_HTML .= '<input type="text" name="wc_rb_smschef_mode" disabled value="devices" id="wc_rb_smschef_mode" value="' . esc_html( $wc_rb_smschef_mode )  . '" class="form-select">';
			$return_HTML .= '</td></tr>';

			$return_HTML .= '<tr class="sms-api-int-field">
								<th scope="row">
									<label for="wc_rb_smschef_device_id">
										' . esc_html__( 'Device ID', 'computer-repair-shop' ) . '
									</label>
								</th>';
			$return_HTML .= '<td>';

			$return_HTML .= '<input type="text" name="wc_rb_smschef_device_id" id="wc_rb_smschef_device_id" value="' . esc_html( $wc_rb_smschef_device_id )  . '" class="form-select">';
			$return_HTML .= '</td></tr>';

			$return_HTML .= '<tr class="sms-api-int-field">
								<th scope="row">
									<label for="wc_rb_smschef_sim">
										' . esc_html__( 'Sim (1, 2, 3)', 'computer-repair-shop' ) . '
									</label>
								</th>';
			$return_HTML .= '<td>';
			
			$return_HTML .= '<input type="number" max="10" step="1" name="wc_rb_smschef_sim" placeholder="1" id="wc_rb_smschef_sim"  value="' . esc_html( $wc_rb_smschef_sim )  . '" class="form-select">';
			$return_HTML .= '</td></tr>';

		}

		if ( $gateway_type == 'capitolemobile' ) {
			$wc_rb_capitolemobile_username  = get_option( 'wc_rb_capitolemobile_username' );
			$wc_rb_capitolemobile_password  = get_option( 'wc_rb_capitolemobile_password' );
			$wc_rb_capitolemobile_sender    = get_option( 'wc_rb_capitolemobile_sender' );

			$return_HTML = '';

			//Sender ID
		    $return_HTML .= '<tr class="sms-api-int-field">
								<th scope="row">
									<label for="wc_rb_capitolemobile_username">
										' . esc_html__( 'Username', 'computer-repair-shop' ) . '
									</label>
								</th>';
			$return_HTML .= '<td>';

			$return_HTML .= esc_html__( 'Your connection ID (login)', 'computer-repair-shop' );
			$return_HTML .= '<input type="text" name="wc_rb_capitolemobile_username" id="wc_rb_capitolemobile_username" value="' . esc_html( $wc_rb_capitolemobile_username )  . '" class="form-select">';
			$return_HTML .= '</td></tr>';

			//API Key
			$return_HTML .= '<tr class="sms-api-int-field">
								<th scope="row">
									<label for="wc_rb_capitolemobile_password">
										' . esc_html__( 'Password', 'computer-repair-shop' ) . '
									</label>
								</th>';
			$return_HTML .= '<td>';

			$return_HTML .= esc_html__( 'Your API password (available via "SMS" > "My API" > "API settings")', 'computer-repair-shop' );
			$return_HTML .= '<input type="text" name="wc_rb_capitolemobile_password" id="wc_rb_capitolemobile_password" value="' . esc_html( $wc_rb_capitolemobile_password )  . '" class="form-select">';
			$return_HTML .= '</td></tr>';

			//Sender
			$return_HTML .= '<tr class="sms-api-int-field">
								<th scope="row">
									<label for="wc_rb_capitolemobile_sender">
										' . esc_html__( 'Sender', 'computer-repair-shop' ) . '
									</label>
								</th>';
			$return_HTML .= '<td>';

			$return_HTML .= esc_html__( '(Optional) by default short number or personalized sender (11 characters max.)', 'computer-repair-shop' );
			$return_HTML .= '<input type="text" name="wc_rb_capitolemobile_sender" id="wc_rb_capitolemobile_sender" value="' . esc_html( $wc_rb_capitolemobile_sender )  . '" class="form-select">';
			$return_HTML .= '</td></tr>';
		}

		if ( $gateway_type == 'bitelietuva' ) {
			$wc_rb_bitelietuva_username  = get_option( 'wc_rb_bitelietuva_username' );
			$wc_rb_bitelietuva_password  = get_option( 'wc_rb_bitelietuva_password' );

			$return_HTML = '';

			//Sender ID
		    $return_HTML .= '<tr class="sms-api-int-field">
								<th scope="row">
									<label for="wc_rb_bitelietuva_username">
										' . esc_html__( 'Username', 'computer-repair-shop' ) . '
									</label>
								</th>';
			$return_HTML .= '<td>';

			$return_HTML .= esc_html__( 'Your Username', 'computer-repair-shop' );
			$return_HTML .= '<input type="text" name="wc_rb_bitelietuva_username" id="wc_rb_bitelietuva_username" value="' . esc_html( $wc_rb_bitelietuva_username )  . '" class="form-select">';
			$return_HTML .= '</td></tr>';

			//API Key
			$return_HTML .= '<tr class="sms-api-int-field">
								<th scope="row">
									<label for="wc_rb_bitelietuva_password">
										' . esc_html__( 'Password', 'computer-repair-shop' ) . '
									</label>
								</th>';
			$return_HTML .= '<td>';

			$return_HTML .= esc_html__( 'Password', 'computer-repair-shop' );
			$return_HTML .= '<input type="text" name="wc_rb_bitelietuva_password" id="wc_rb_bitelietuva_password" value="' . esc_html( $wc_rb_bitelietuva_password )  . '" class="form-select">';
			$return_HTML .= '</td></tr>';
		}

		return $return_HTML;
	}

	function wc_rb_generate_status_checkboxes( $selected_page ) {
		global $wpdb;

		$field_to_select 	= 'status_slug';
		
		//Table
		$computer_repair_job_status 	= $wpdb->prefix.'wc_cr_job_status';

		$select_query 	= "SELECT * FROM `" . $computer_repair_job_status . "` WHERE `status_status`='active'";
		$select_results = $wpdb->get_results( $select_query );

		if ( ! empty ( $selected_page ) ) {
			$selected_page = unserialize( $selected_page );
		}
		if ( empty ( $selected_page ) || ! is_array ( $selected_page ) ) {
			$selected_page = array();
		}

		$output = '';
		foreach($select_results as $result) {
			$checked = ( in_array( $result->$field_to_select, $selected_page ) ) ? 'checked' : '';
			$output .= '<label for="' . esc_attr( $result->$field_to_select ) . '">';
			$output .= '<input ' . $checked . ' name="wc_rb_job_status_include[]" value="' . esc_attr( $result->$field_to_select ) . '" id="'.esc_attr( $result->$field_to_select ) . '" type="checkbox">';
			$output .= esc_attr( $result->status_name ) . '</label>';
		} // End Foreach	

		return $output;
	}

	function wc_post_sms_configuration_index() {
		global $wpdb;

		$form_type 			      = sanitize_text_field( $_POST['form_type'] );
		$wc_rb_sms_gateway 	      = sanitize_text_field( $_POST['wc_rb_sms_gateway'] );
		$wc_rb_job_status_include = sanitize_text_field( serialize( $_POST['wc_rb_job_status_include'] ) );
		$wc_rb_sms_active		  = sanitize_text_field( $_POST['wc_rb_sms_active'] );
		
		$wc_rb_sms_active		  = ( $wc_rb_sms_active == 'YES' ) ? 'YES' : 'NO';

		if ( $form_type == 'submit_the_sms_configuration_form' ) {

			update_option( 'wc_rb_job_status_include', $wc_rb_job_status_include );
			update_option( 'wc_rb_sms_gateway', $wc_rb_sms_gateway );

			update_option( 'wc_rb_sms_active', $wc_rb_sms_active );

			$api_posts = array( 'wc_rb_twilio_account_sid', 
								'wc_rb_twilio_auth_token', 
								'wc_rb_twilio_from_number', 
								'wc_rb_releans_sender_id', 
								'wc_rb_releans_api_key',
								'wc_rb_capitolemobile_username',
								'wc_rb_capitolemobile_password',
								'wc_rb_capitolemobile_sender',
								'wc_rb_bitelietuva_username',
								'wc_rb_bitelietuva_password',
								'wc_rb_smschef_secret',
								'wc_rb_smschef_mode',
								'wc_rb_smschef_device_id',
								'wc_rb_smschef_sim',
							);

			foreach ( $api_posts as $api_post ) {
				if ( isset( $_POST[$api_post] ) ) {
					$posted_value = sanitize_text_field( $_POST[$api_post] );
					update_option( $api_post, $posted_value );
				}
			}
			$message = esc_html__( 'Settings have been saved!', 'computer-repair-shop' );
		} else {
			$message = esc_html__( 'Invalid Form', 'computer-repair-shop' );	
		}

		$values['message'] = $message;
		$values['success'] = "YES";

		wp_send_json( $values );
		wp_die();
	}

	function wc_rb_status_send_the_sms( $job_id, $status ) {
		global $wpdb;

		if ( empty( $job_id ) || empty ( $status ) ) {
			return;
		}
		$customer_id = get_post_meta( $job_id, "_customer", true);
		//Get Gateway
		$selected_gateway = get_option( 'wc_rb_sms_gateway' );

		if ( empty( $selected_gateway ) ) {
			return;
		}
		//If Status is selected
		$selected_page = get_option( 'wc_rb_job_status_include' );

		$proceed = 'No';
		if ( ! empty ( $selected_page ) ) {
			$selected_page = unserialize( $selected_page );

			$proceed = ( in_array( $status, $selected_page ) ) ? 'Yes' : 'No';
		} else {
			$proceed = 'No';
		}
		$wc_order_status = wc_return_status_id( $status );
		$message = '';
		
		if ( ! empty ( $wc_order_status ) && is_numeric ( $wc_order_status ) ) {
			$computer_repair_job_status = $wpdb->prefix.'wc_cr_job_status';
			$wc_status_row 				= $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$computer_repair_job_status} WHERE `status_id` = %d", $wc_order_status ) );

			$status_name 			= $wc_status_row->status_name;
			$message 				= stripslashes( $wc_status_row->status_email_message );

			$order_total 	= wc_order_grand_total( $job_id, 'grand_total' );
			$order_total	= wc_cr_currency_format( $order_total );
			$order_balance	= wc_order_grand_total( $job_id, 'balance' );
			$order_balance  = wc_cr_currency_format( $order_balance );


			$available_devices = '';
			$current_devices = get_post_meta( $job_id, '_wc_device_data', true );

			if ( ! empty( $current_devices )  && is_array( $current_devices ) ) {
				foreach( $current_devices as $device_data ) {
					$device_post_id = ( isset( $device_data['device_post_id'] ) ) ? $device_data['device_post_id'] : '';
					$available_devices .= ' - ' . return_device_label( $device_post_id );
				}
			}

			$user_info 	= get_userdata( $customer_id );
			$user_name 	= $user_info->first_name . ' ' . $user_info->last_name;
			
			$message = str_replace( '{{customer_name}}', $user_name, $message );
			$message = str_replace( '{{device_name}}', $available_devices, $message );
			$message = str_replace( '{{order_total}}', $order_total, $message );
			$message = str_replace( '{{order_balance}}', $order_balance, $message );
		}

		if ( empty ( $message ) ) {
			$proceed = 'No';
		}
		$message .= ' ' . wc_rb_return_status_check_link( $job_id );

		//If customer phone # okay.
		$user_info 		= get_userdata( $customer_id );
		$phone_number 	= get_user_meta( $customer_id, 'billing_phone', true );

		if ( empty( $phone_number ) ) {
			$proceed = 'No';
		}

		if ( $proceed == 'No' ) {
			return;
		}
		$message = esc_textarea( $message );
		if ( $selected_gateway == 'twilio' ) {
			$this->send_twilio_sms( $phone_number, $message );
		}
		if ( $selected_gateway == 'releans' ) {
			$this->send_releans_sms( $phone_number, $message );
		}
		if ( $selected_gateway == 'capitolemobile' ) {
			$this->send_capitolemobile_sms( $phone_number, $message );
		}
		if ( $selected_gateway == 'bitelietuva' ) {
			$this->send_bitelietuva_sms( $phone_number, $message );
		}
		if ( $selected_gateway == 'smschef' ) {
			$this->send_smschef_sms( $phone_number, $message, $job_id );
		}
	}

	function send_sms( $phone_number, $message, $job_id ) {
		$selected_gateway = get_option( 'wc_rb_sms_gateway' );

		$is_sms_active = get_option( 'wc_rb_sms_active' );
		if ( $is_sms_active != 'YES' ) {
			return;
		}

		if ( empty( $selected_gateway ) ) {
			return;
		}
		
		if ( empty( $phone_number ) || empty( $message ) ) {
			return;
		}

		if ( $selected_gateway == 'twilio' ) {
			$this->send_twilio_sms( $phone_number, $message );
		}
		if ( $selected_gateway == 'releans' ) {
			$this->send_releans_sms( $phone_number, $message );
		}
		if ( $selected_gateway == 'capitolemobile' ) {
			$this->send_capitolemobile_sms( $phone_number, $message );
		}
		if ( $selected_gateway == 'bitelietuva' ) {
			$this->send_bitelietuva_sms( $phone_number, $message );
		}
		if ( $selected_gateway == 'smschef' ) {
			$this->send_smschef_sms( $phone_number, $message, $job_id );
		}
	}

	function send_smschef_sms( $phone_number, $message, $job_id ) {
		if ( ! wc_rs_license_state() ) {
			return;
		}
		if ( empty ( $phone_number ) || empty ( $message ) ) {
			return;
		}
		$store_id = '';
		if ( ! empty( $job_id ) ) {
			$store_id = get_post_meta( $job_id, '_store_id', true );
		}
		if ( ! empty( $store_id ) ) {
			$smschef_secret 	= get_post_meta( $store_id, '_smschef_secret', true );
			$smschef_mode 		= get_post_meta( $store_id, '_smschef_mode', true );
			$smschef_device_id  = get_post_meta( $store_id, '_smschef_device_id', true );
			$smschef_sim 		= get_post_meta( $store_id, '_smschef_sim', true );

			$wc_rb_smschef_secret 	 = ( ! empty( $smschef_secret ) ) ? $smschef_secret : get_option( 'wc_rb_smschef_secret' );
			$wc_rb_smschef_mode   	 = ( ! empty( $smschef_mode ) ) ? $smschef_mode : get_option( 'wc_rb_smschef_mode' );
			$wc_rb_smschef_sim   	 = ( ! empty( $smschef_sim ) ) ? $smschef_sim : get_option( 'wc_rb_smschef_sim' );
			$wc_rb_smschef_device_id = ( ! empty( $smschef_device_id ) ) ? $smschef_device_id : get_option( 'wc_rb_smschef_device_id' );
		} else {
			$wc_rb_smschef_secret = get_option( 'wc_rb_smschef_secret' );
			$wc_rb_smschef_mode = get_option( 'wc_rb_smschef_mode' );
			$wc_rb_smschef_sim   = get_option( 'wc_rb_smschef_sim' );
			$wc_rb_smschef_device_id = get_option( 'wc_rb_smschef_device_id' );
		}
		if ( empty( $wc_rb_smschef_secret ) ) {
			return;
		}
		if ( empty( $wc_rb_smschef_mode ) ) {
			$wc_rb_smschef_mode = 'devices';
		}
		if ( empty( $wc_rb_smschef_device_id ) ) {
			$wc_rb_smschef_device_id = '00000000-0000-0000-d57d-f30cb6a89289';
		}
		if ( empty( $wc_rb_smschef_sim ) ) {
			$wc_rb_smschef_sim = '1';
		}
		
		$message = [
			"secret" => $wc_rb_smschef_secret,
			"mode" => $wc_rb_smschef_mode,
			"device" => $wc_rb_smschef_device_id,
			"sim" => $wc_rb_smschef_sim,
			"priority" => 1,
			"phone" => $phone_number,
			"message" => $message
		];
	  
		$cURL = curl_init("https://www.cloud.smschef.com/api/send/sms");
		curl_setopt($cURL, CURLOPT_RETURNTRANSFER, true);
		curl_setopt($cURL, CURLOPT_POSTFIELDS, $message);
		$response = curl_exec($cURL);
		curl_close($cURL);
	  
		$result = json_decode($response, true);

		update_option( 'last_sms_response', serialize( $result ) );

		$wc_rb_return_res['return_type'] = 'success';
		$wc_rb_return_res['return_res'] = __( 'SMS Sent Successfully', 'computer-repair-shop' );
	}

	function send_capitolemobile_sms( $phone_number, $message ) {
		if ( ! wc_rs_license_state() ) {
			return;
		}

		if ( empty ( $phone_number ) || empty ( $message ) ) {
			return;
		}

		$wc_rb_capitolemobile_username = get_option( 'wc_rb_capitolemobile_username' );
		$wc_rb_capitolemobile_password = get_option( 'wc_rb_capitolemobile_password' );
		$wc_rb_capitolemobile_sender   = get_option( 'wc_rb_capitolemobile_sender' );

		$wc_rb_capitolemobile_sender   = ( empty ( $wc_rb_capitolemobile_sender ) ) ? 'SystemMsg' : $wc_rb_capitolemobile_sender;
		
		if ( empty ( $wc_rb_capitolemobile_username ) || empty ( $wc_rb_capitolemobile_password ) ) {
			return;
		}

		// CapitoleMobile POST URL
		$postUrl = "https://sms.capitolemobile.com/api/sendsms/xml";

		//Structure de Données XML
		$xmlString = '<SMS>
						<authentification>
							<username>' . esc_html( $wc_rb_capitolemobile_username ) . '</username>
							<password>' . esc_html( $wc_rb_capitolemobile_password ) . '</password>
						</authentification>
						<message>
							<text>'. esc_html( $message ) .'</text>
							<sender>' . esc_html( $wc_rb_capitolemobile_sender ) . '</sender>
						</message>
						<recipients>
							<gsm>' . esc_html( $phone_number ) . '</gsm>
						</recipients>
					</SMS>';

		// insertion du nom de la variable POST "XML" avant les données au format XML
		$fields = "XML=" . urlencode( utf8_encode( $xmlString ) );
		
		// dans cet exemple, la requête POST est realisée grâce à la librairie Curl
		$ch = curl_init();
		curl_setopt( $ch, CURLOPT_URL, $postUrl );
		curl_setopt( $ch, CURLOPT_POST, 1 );
		curl_setopt( $ch, CURLOPT_POSTFIELDS, $fields );

		curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
		curl_setopt($ch, CURLOPT_FOLLOWLOCATION,true);

		// Réponse de la requête POST
		$subResponse = curl_exec( $ch );
		curl_close( $ch );

		$subResponse = ( empty ( $subResponse ) ) ? 'empty' : $subResponse;

		$subResponse = htmlentities( $subResponse );

		update_option( 'last_sms_response', serialize( $subResponse ) );

		$wc_rb_return_res['return_type'] = 'success';
		$wc_rb_return_res['return_res'] = __( 'SMS Sent Successfully', 'computer-repair-shop' );
	}

	function send_bitelietuva_sms( $phone_number, $message ) {
		if ( ! wc_rs_license_state() ) {
			return;
		}

		if ( empty ( $phone_number ) || empty ( $message ) ) {
			return;
		}

		$wc_rb_bitelietuva_username  = get_option( 'wc_rb_bitelietuva_username' );
		$wc_rb_bitelietuva_password  = get_option( 'wc_rb_bitelietuva_password' );

		if ( empty ( $wc_rb_bitelietuva_username ) || empty ( $wc_rb_bitelietuva_password ) ) {
			return;
		}

		//Process SMS

		
		// dans cet exemple, la requête POST est realisée grâce à la librairie Curl
		$ch = curl_init();
		curl_setopt( $ch, CURLOPT_URL, $postUrl );
		curl_setopt( $ch, CURLOPT_POST, 1 );
		curl_setopt( $ch, CURLOPT_POSTFIELDS, $fields );

		curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
		curl_setopt($ch, CURLOPT_FOLLOWLOCATION,true);

		// Réponse de la requête POST
		$subResponse = curl_exec( $ch );
		curl_close( $ch );

		$subResponse = ( empty ( $subResponse ) ) ? 'empty' : $subResponse;

		$subResponse = htmlentities( $subResponse );

		update_option( 'last_sms_response', serialize( $subResponse ) );

		$wc_rb_return_res['return_type'] = 'success';
		$wc_rb_return_res['return_res'] = __( 'SMS Sent Successfully', 'computer-repair-shop' );
	}

	function send_twilio_sms( $phone_number, $message ) {
		if ( ! wc_rs_license_state() ) {
			return;
		}
		if ( empty ( $phone_number ) || empty ( $message ) ) {
			return;
		}

		$wc_rb_twilio_account_sid  = get_option( 'wc_rb_twilio_account_sid' );
		$wc_rb_twilio_auth_token   = get_option( 'wc_rb_twilio_auth_token' );
		$wc_rb_twilio_from_number  = get_option( 'wc_rb_twilio_from_number' );
		
		if ( empty ( $wc_rb_twilio_account_sid ) || empty ( $wc_rb_twilio_auth_token ) || empty ( $wc_rb_twilio_from_number ) ) {
			return;
		}

		$wc_rb_twilio_send_url = "https://api.twilio.com/2010-04-01/Accounts/" .  $wc_rb_twilio_account_sid . "/Messages.json";

		$wc_rb_pwd = $wc_rb_twilio_account_sid . ":" . $wc_rb_twilio_auth_token;

		$wc_rb_twilio_params = array(
			'From' => esc_html( $wc_rb_twilio_from_number ),
			'To' => esc_html( $phone_number ),
			'Body' => esc_html( $message )
		);
	
		$ch = curl_init();
		curl_setopt($ch, CURLOPT_URL, esc_html( $wc_rb_twilio_send_url ) );
		curl_setopt($ch, CURLOPT_RETURNTRANSFER,1);
		curl_setopt($ch, CURLOPT_USERPWD, esc_html( $wc_rb_pwd ) );
		curl_setopt($ch, CURLOPT_HEADER, 1);
		curl_setopt($ch, CURLOPT_HTTPHEADER, array("Content-Type: application/x-www-form-urlencoded"));
		curl_setopt($ch, CURLOPT_POSTFIELDS , http_build_query($wc_rb_twilio_params));
		$wc_rb_send_sms_res = curl_exec($ch);
		curl_close($ch);

		update_option( 'last_sms_response', $wc_rb_send_sms_res );

		$wc_rb_return_res['return_type'] = 'success';
		$wc_rb_return_res['return_res'] = __( 'SMS Sent Successfully', 'computer-repair-shop' );
	}

	function send_releans_sms( $phone_number, $message ) {
		if ( ! wc_rs_license_state() ) {
			return;
		}
		if ( empty ( $phone_number ) || empty ( $message ) ) {
			return;
		}

		$wc_rb_releans_sender_id = get_option( 'wc_rb_releans_sender_id' );
		$wc_rb_releans_api_key   = get_option( 'wc_rb_releans_api_key' );
		
		if ( empty ( $wc_rb_releans_sender_id ) || empty ( $wc_rb_releans_api_key ) ) {
			return;
		}
		$wc_rb_twilio_send_url = "https://api.releans.com/v2/message";

		$curl = curl_init();
            
		curl_setopt_array($curl, array(
			CURLOPT_URL => esc_html( $wc_rb_twilio_send_url ),
			CURLOPT_RETURNTRANSFER => true,
			CURLOPT_ENCODING => "",
			CURLOPT_MAXREDIRS => 10,
			CURLOPT_TIMEOUT => 0,
			CURLOPT_FOLLOWLOCATION => true,
			CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
			CURLOPT_CUSTOMREQUEST => "POST",
			CURLOPT_POSTFIELDS => "sender=" . esc_html( $wc_rb_releans_sender_id ) . "&mobile=". esc_html( $phone_number ) ."&content=" . esc_html( $message ),
			CURLOPT_HTTPHEADER => array(
				"Authorization: Bearer " . esc_html( $wc_rb_releans_api_key )
			),
		));					
		$response = curl_exec($curl);

		update_option( 'last_sms_response', $response );

		curl_close($curl);

		$wc_rb_return_res['return_type'] = 'success';
		$wc_rb_return_res['return_res'] = __( 'SMS Sent Successfully', 'computer-repair-shop' );
	}
}