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

class WCRB_MAINTENANCE_REMINDER {

	private $TABID = "wc_rb_maintenance_reminder";

	function __construct() {
        add_action( 'wc_rb_settings_tab_menu_item', array( $this, 'add_maintenance_reminder_setting_menu' ), 10, 2 );
        add_action( 'wc_rb_settings_tab_body', array( $this, 'add_maintenance_reminder_setting_body' ), 10, 2 );
		add_action( 'wp_ajax_wc_rb_reload_maintenance_update', array( $this, 'wc_rb_reload_maintenance_update' ), 10, 2 );
		add_action( 'wp_ajax_wc_rb_update_maintenance_reminder', array( $this, 'wc_rb_update_maintenance_reminder' ) );

		add_action( 'wp_ajax_wcrb_load_reminder_test_form', array( $this, 'wcrb_load_reminder_test_form' ) );
		add_action( 'wp_ajax_wcrb_send_reminder_test_form', array( $this, 'wcrb_send_reminder_test_form' ) );
    }

	function add_maintenance_reminder_setting_menu() {
        $active = '';

        $menu_output = '<li class="tabs-title' . esc_attr( $active ) . '" role="presentation">';
        $menu_output .= '<a href="#' . esc_attr( $this->TABID ) . '" 
		role="tab" aria-controls="' . esc_attr( $this->TABID ) . '" aria-selected="true" id="' . esc_attr( $this->TABID ) . '-label">';
        $menu_output .= '<h2>' . esc_html__( 'Maintenance Reminders', 'computer-repair-shop' ) . '</h2>';
        $menu_output .=	'</a>';
        $menu_output .= '</li>';

        echo wp_kses_post( $menu_output );
    }
	
	function add_maintenance_reminder_setting_body() {
		global $wpdb;

        $active = '';

		$setting_body = '<div class="tabs-panel team-wrap' . esc_attr( $active ) . '" 
        id="' . esc_attr( $this->TABID ) . '" 
        role="tabpanel" 
        aria-hidden="true" 
        aria-labelledby="' . esc_attr( $this->TABID ) . '-label">';

		$setting_body .= '<div class="wc-rb-manage-devices">';
		$setting_body .= '<h2>' . esc_html__( 'Maintenance Reminders', 'computer-repair-shop' ) . '</h2>';
		$setting_body .= '<p>' . esc_html__( 'Jobs should have delivery date set for reminders to work', 'computer-repair-shop' ) . '</p>';
		
		$setting_body .= '<p class="help-text addmaintenancereminderbtn">
                                <a class="button button-primary button-small" data-open="maintenancereminderReveal">'.
                                     esc_html__("Add New Maintenance Reminder", "computer-repair-shop")
                                .'</a>';
		$logsURL = admin_url( 'admin.php?page=wcrb_reminder_logs' );
		$setting_body .= '<a class="button button-primary button-small alignright" href="' . esc_url( $logsURL ) . '">
						 ' . esc_html__( 'View Reminder Logs', 'computer-repair-shop' ) . '
						  </a></p>';

        add_filter( 'admin_footer', array( $this, 'wc_maintenance_reminder_form' ) );
		
		if ( ! wc_rs_license_state() ) {
			$setting_body .= '<h2>' . esc_html__( 'Activation of plugin is required to run reminders. However you can still add and edit reminders', 'computer-repair-shop' ) . '</h2>';
			$setting_body .= wc_cr_new_purchase_link("");
		}

		//reminder_id	datetime	name	description	interval	email_body	sms_body	device_type	device_brand	email_status	sms_status	reminder_status	last_execution
		$setting_body .= '<div id="reminder_status_wrapper">
        <table id="reminderStatus_poststuff" class="wp-list-table widefat fixed striped posts">
            <thead>
                <tr>
                    <th class="column-id">' . esc_html__( 'ID', 'computer-repair-shop' ) . '</th>
                    <th>' . esc_html__( 'Name', 'computer-repair-shop' ) . '</th>
                    <th>' . esc_html__( 'Interval', 'computer-repair-shop' ) . '</th>
                    <th>' . esc_html__( 'Device Type', 'computer-repair-shop' ) . '</th>
                    <th>' . esc_html__( 'Brand', 'computer-repair-shop' ) . '</th>
                    <th>' . esc_html__( 'Email', 'computer-repair-shop' ) . '</th>
					<th>' . esc_html__( 'SMS', 'computer-repair-shop' ) . '</th>
					<th>' . esc_html__( 'Reminder', 'computer-repair-shop' ) . '</th>
					<th>' . esc_html__( 'Last Run', 'computer-repair-shop' ) . '</th>
					<th class="column-id">' . esc_html__( 'Test', 'computer-repair-shop' ) . '</th>
					<th class="column-id">' . esc_html__( 'Actions', 'computer-repair-shop' ) . '</th>
                </tr>
            </thead>';

        $setting_body .= '<tbody>';

        $computer_repair_maint_reminders = $wpdb->prefix.'wc_cr_maint_reminders';
            
        $select_query 	= "SELECT * FROM `" . $computer_repair_maint_reminders . "`";
        $select_results = $wpdb->get_results( $select_query );
            
        $output = '';
        foreach( $select_results as $result ) {

			$typeName   = ( ! empty( $result->device_type ) && $result->device_type != 'All' ) ? get_term( $result->device_type )->name : $result->device_type;
			$brandName  = ( ! empty( $result->device_brand ) && $result->device_brand != 'All' ) ? get_term( $result->device_brand )->name : $result->device_brand;

            $output .= '<tr><td>' . $result->reminder_id . '</td>';
            $output .= '<td><strong>' . $result->name . '</strong></td>';
            $output .= '<td>' . $result->interval . '</td>';
            $output .= '<td>' . $typeName . '</td>';
			$output .= '<td>' . $brandName . '</td>';
			$output .= '<td>' . $result->email_status . '</td>';
			$output .= '<td>' . $result->sms_status . '</td>';
			$output .= '<td>' . $result->reminder_status . '</td>';
			$output .= '<td>' . $result->last_execution . '</td>';
			
			$output .= '<td><a href="#" data-open="send_reminder_test" recordid="' . $result->reminder_id . '">' . esc_html__( 'Send test to admin', 'computer-repair-shop' ) . '</a></td>';

			$output .= '<td><a href="'.esc_url( add_query_arg( 'update_maintenance_reminder', $result->reminder_id ) ).'" 
			data-open="update_maintenance_reminder" recordid="' . $result->reminder_id . '">' . esc_html__( 'Edit', 'computer-repair-shop' ) . '</a></td>';
            $output .= '</tr>';
        }
        $setting_body .= $output;
        
        $setting_body .= '</tbody>';
        $setting_body .= '</table></div><!-- Payment Status Wrapper /-->';
		$setting_body .= '<div class="send_test_reminder"></div>';

		$setting_body .= '</div><!-- wc rb Devices /-->';
		$setting_body .= '</div><!-- Tabs Panel /-->';

		$allowedHTML = ( function_exists( 'wc_return_allowed_tags' ) ) ? wc_return_allowed_tags() : '';
		echo wp_kses( $setting_body, $allowedHTML );
	}

	function wcrb_send_reminder_test_form() {

		$values  = array();
		$message = '';

		if ( ! isset( $_POST['testmailto'] ) || empty( $_POST['testmailto'] ) ) {
			$message = esc_html__( 'To email is required', 'computer-repair-shop' );
		}
		if ( ! isset( $_POST['reminder_id'] ) || empty( $_POST['reminder_id'] ) ) {
			$message = esc_html__( 'To email is required', 'computer-repair-shop' );
		}

		if ( empty( $message ) ) {
			//Lets process mail here.
			$testmailto  = sanitize_text_field( $_POST['testmailto'] );
			$reminder_id = sanitize_text_field( $_POST['reminder_id'] );

			$email_body = $this->get_field( $reminder_id, 'email_body' );
			$email_body = html_entity_decode( $email_body );

			if ( empty( $email_body ) ) {
				$message = esc_html__( 'No message defined to email', 'computer-repair-shop' );
			} else {
				$to = $testmailto;
				$headers = array('Content-Type: text/html; charset=UTF-8');

				$device_label = 'HP - TEST Printer';
				$user_name = 'John Doe';

				$wc_device_label = ( empty( get_option( 'wc_device_label' ) ) ) ? esc_html__( 'Device', 'computer-repair-shop' ) : get_option( 'wc_device_label' );

				$subject = ( isset( $subject ) ) ? $subject : esc_html__( 'Maintenance reminder for your ', 'computer-repair-shop' ) . $wc_device_label . ' ' . $device_label;
				$subject = $subject . ' | ' . esc_html( $menu_name_p );

				$email_body = str_replace( '{{customer_name}}', $user_name, $email_body );
				$email_body = str_replace( '{{device_name}}', $device_label, $email_body );

				$siteUrl 	= get_site_url();
				$arr_params = array( 'thejobid' => '', 'theunsub' => 'true' );
				$unsubURL 	= esc_url( add_query_arg( $arr_params, $siteUrl ) );

				$email_body = str_replace( '{{unsubscribe_device}}', $unsubURL, $email_body );

				$body = '<div class="repair_box">' . $email_body . '</div>';

				$body_output = wc_rs_get_email_head();
				$body_output .= $body;
				$body_output .= wc_rs_get_email_footer();

				wp_mail( $to, $subject, $body_output, $headers );

				$message = esc_html__( 'Test email have been sent', 'computer-repair-shop' );
			}
		}

		$values['message'] = $message;

		wp_send_json( $values );
		wp_die();
	}

	function wcrb_load_reminder_test_form() {

		$reminder_id = '';
		if ( isset( $_POST['reminder_id'] ) && ! empty( $_POST['reminder_id'] ) ) {
			$reminder_id = sanitize_text_field( $_POST['reminder_id'] );
		} else {
			return;
		}

		$admin_email = ( ! empty( get_option( 'admin_email' ) ) ) ? get_option( 'admin_email' ) : '';

		$values  = array();

		$reminder_name = $this->get_field( $reminder_id, 'name' );

		$message = '<p class="submittheremindertest"></p><form method="post" action="" id="submitTestReminderForm"><div class="grid-x grid-margin-x text-center">';
		$message .= '<h2 class="text-center cell medium-12">' . esc_html__( 'Send test email for ', 'computer-repair-shop' ) . ' - ' . esc_html( $reminder_name ) . '</h2>';

		$message .= '<div class="cell medium-offset-4 medium-4">
						<label for="testReminderMailTo">
							' . esc_html__( 'Enter Email Address', 'computer-repair-shop' ) . '
							<input name="testReminderMailTo" type="text" class="form-control login-field" value="' . esc_html( $admin_email ) . '" required="" id="testReminderMailTo">
						</label>
					</div>';

		$message .= '<input type="hidden" name="testReminderID" value="' . esc_html( $reminder_id ) . '" />';
		$message .= '<div class="cell medium-12"><input type="submit" value="' . esc_html__( 'Send Email', 'computer-repair-shop' ) . '" class="button button-primary button-small" /></div>';
		$message .= '</div></form>';

		$values['message'] = $message;

		wp_send_json( $values );
		wp_die();
	}

	function get_field( $reminder_id, $term ) {
		global $wpdb;

		if ( empty( $reminder_id ) || empty( $term ) ) {
			return;
		}

		$_rec_reminder_id = sanitize_text_field( $reminder_id );

		$computer_repair_maint_reminders = $wpdb->prefix.'wc_cr_maint_reminders';
		$wc_reminder_row				 = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$computer_repair_maint_reminders} WHERE `reminder_id` = %d", $_rec_reminder_id ) );

		if ( ! empty( $wc_reminder_row->$term ) ) {
			return $wc_reminder_row->$term;
		} else {
			return '';
		}
	}

	function execute_reminder() {
		global $wpdb;

		if ( ! wc_rs_license_state() ) {
			return esc_html__( 'Pro feature', 'computer-repair-shop' );
		}

		//Fetch all reminders if active, send_reminder
		$computer_repair_maint_reminders = $wpdb->prefix.'wc_cr_maint_reminders';

		$select_query 	= "SELECT * FROM `" . $computer_repair_maint_reminders . "` WHERE `reminder_status`='active'";
		$select_results = $wpdb->get_results( $select_query );

		foreach( $select_results as $result ) {
			$reminder_id = $result->reminder_id;

			$this->send_reminder( $reminder_id );
		}
	}

	function send_reminder( $reminder_id ) {
		global $wpdb;

		if ( empty( $reminder_id ) ) {
			return;
		}

		$computer_repair_maint_reminders = $wpdb->prefix.'wc_cr_maint_reminders';
		$wc_reminder_row				 = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$computer_repair_maint_reminders} WHERE `reminder_id` = %d", $reminder_id ) );

		if ( $wc_reminder_row == null ) {
			return;
		}

		//Reminder last ran 24 Hours ago?
		$lastRan = $wc_reminder_row->last_execution;
		$timeNow = wp_date( 'Y-m-d H:i:s' );

		$from_time = strtotime( $lastRan ); 
		$to_time   = strtotime( $timeNow ); 
		$diff 	   = $to_time - $from_time;

		if ( $diff <= 0 ) {
			$diff += 86400;
		}
		$hours = $diff / 3600;
		$realDiff = round( $hours, 2 );

		if ( $realDiff < 24 ) {
			return esc_html__( 'Cannot run yet time have not reached', 'computer-repair-shop' );
		}

		$data 	= array(
			"last_execution" => wp_date( 'Y-m-d H:i:s' ),
		);
		$where 	= ['reminder_id' => $reminder_id];

		$update_row = $wpdb->update( $computer_repair_maint_reminders, $data, $where );

		//Is reminder active?
		if ( $wc_reminder_row->reminder_status == 'inactive' ) {
			return esc_html__( 'Reminder is inactive', 'computer-repair-shop' );
		}

		$interval = $wc_reminder_row->interval;

		if ( ! empty( $interval ) ) {
			$_date 	  = date( "Y-m-d" );
			//returns something 2023-08-29
			$_date 	  = date('Y-m-d',strtotime( $_date ) - ( 24*3600*$interval ) );

			$args = array(
				'post_type' => 'rep_jobs',
				'posts_per_page' => -1,
				'meta_query' => array(
					'relation' => 'AND',
					array(
						'key'     => '_delivery_date',
						'compare' => 'EXISTS'
					),
					array(
						'key'     => '_delivery_date',
						'value'	  => '',
						'compare' => '!='
					),
					array(
						'key'     => '_delivery_date',
						'value'   => $_date,
						'compare' => '<',
						'type' => 'DATE'
					),
					),
			);
			$query = new WP_Query( $args );

			if ($query->have_posts()) {
				while ($query->have_posts()) {
					$query->the_post();
					
					$theJobID = $query->post->ID;

					$email_optout = get_post_meta( $theJobID, "_email_optout", true );

					if ( $email_optout != 'YES' ) {
						//We have to now check last 
						$_last_sent = get_post_meta( $theJobID, "_last_reminder_sent", true );

						$send = 'NO';
						if ( ! empty( $_last_sent ) ) {
							//Today Minus - Last Sent if Greater than Interval  
							$date1 = strtotime( date( "Y-m-d" ) );
							$date2 = strtotime( $_last_sent );
							
							$daysDiff = round( abs( $date1 - $date2 ) / (60*60*24),0);

							if ( $interval < $daysDiff ) {
								$send = 'YES';
							}
						} else {
							$send = 'YES';
						}

						if ( $send == 'YES' ) {
							//Send Email
							$this->wcrb_send_reminder_email( $theJobID, $reminder_id );

							//Send SMS
							$this->wcrb_send_reminder_sms( $theJobID, $reminder_id );

							//Update Job _last_reminder_sent
							update_post_meta( $theJobID, '_last_reminder_sent', date( "Y-m-d" ) );
						}
					}
				}//End while
			}//Endif
		}
	}

	function wc_rb_update_maintenance_reminder() {
		global $wpdb;

		$formType = $message = '';
		$values = array();
		$error   = 0;
		$success = 'NO';

		$computer_repair_maint_reminders = $wpdb->prefix.'wc_cr_maint_reminders';
		
		if ( ! isset( $_POST['wcrb_nonce_maintenance_reminder_field'] ) || ! wp_verify_nonce( $_POST['wcrb_nonce_maintenance_reminder_field'], 'wcrb_nonce_maintenance_reminder' ) ) {
			$message = esc_html__( 'Couldn\'t verify nonce please reload page.', 'computer-repair-shop' );
		} else {
			// process form data
			if ( ! isset( $_POST['reminder_name'] ) || empty( $_POST['reminder_name'] )  ) {
				$message = esc_html__( 'Reminder name is required.', 'computer-repair-shop' );
				$error = 1;
			} elseif ( ! isset( $_POST['reminder_interval'] ) || empty( $_POST['reminder_interval'] )  ) {
				$message = esc_html__( 'Please select interval to send reminder.', 'computer-repair-shop' );
				$error = 1;
			} elseif ( ! isset( $_POST['reminder_description'] ) || empty( $_POST['reminder_description'] )  ) {
				$message = esc_html__( 'Add some description to recognize purpose of reminder.', 'computer-repair-shop' );
				$error = 1;
			} elseif ( ! isset( $_POST['email_message'] ) || empty( $_POST['email_message'] ) ) {
				$message = esc_html__( 'Reminders need email body detail to submit.', 'computer-repair-shop' );
				$error = 1;
			} elseif ( ! isset( $_POST['reminder_for_device_types'] ) || empty( $_POST['reminder_for_device_types'] )  ) {
				$message = esc_html__( 'Select device type for which this reminder is.', 'computer-repair-shop' );
				$error = 1;
			} elseif ( ! isset( $_POST['reminder_for_device_brand'] ) || empty( $_POST['reminder_for_device_brand'] )  ) {
				$message = esc_html__( 'Select a brand for which this reminder is.', 'computer-repair-shop' );
				$error = 1;
			} elseif ( ! isset( $_POST['email_reminder_status'] ) || empty( $_POST['email_reminder_status'] )  ) {
				$message = esc_html__( 'Turn on email reminder or deactivate it.', 'computer-repair-shop' );
				$error = 1;
			} elseif ( ! isset( $_POST['sms_reminder_status'] ) || empty( $_POST['sms_reminder_status'] )  ) {
				$message = esc_html__( 'Turn on SMS reminder or deactivate.', 'computer-repair-shop' );
				$error = 1;
			} elseif ( ! isset( $_POST['reminder_status'] ) || empty( $_POST['reminder_status'] )  ) {
				$message = esc_html__( 'Keep reminder active or deactive.', 'computer-repair-shop' );
				$error = 1;
			}

			if ( isset( $_POST['form_type_status_reminder'] ) && ! empty( $_POST['form_type_status_reminder'] ) ) {
				$formType = sanitize_text_field( $_POST['form_type_status_reminder'] );
			}

			$message_us = sanitize_text_field( htmlentities( $_POST['email_message'] ) );
			if ( $error == 0 ) {
				//Let's make values here.
				$reminder_name 			   = sanitize_text_field( $_POST['reminder_name'] );
				$reminder_interval 		   = sanitize_text_field( $_POST['reminder_interval'] );
				$reminder_description 	   = sanitize_text_field( $_POST['reminder_description'] );
				$sms_message 			   = ( isset( $_POST['sms_message'] ) && ! empty( $_POST['sms_message'] ) ) ? sanitize_text_field( $_POST['sms_message'] ) : '';
				$reminder_for_device_types = sanitize_text_field( $_POST['reminder_for_device_types'] );
				$reminder_for_device_brand = sanitize_text_field( $_POST['reminder_for_device_brand'] );

				$active_email_reminder 	   = sanitize_text_field( $_POST['email_reminder_status'] );
				$active_sms_reminder 	   = sanitize_text_field( $_POST['sms_reminder_status'] );
				$reminder_status 	       = sanitize_text_field( $_POST['reminder_status'] );

				$wcrb_reminder_datetime    = wp_date( 'Y-m-d H:i:s' );
				
				if ( $formType == 'add' ) {
					//Add reminder
					//email_status sms_status reminder_status last_execution
					$insert_query =  "INSERT INTO `{$computer_repair_maint_reminders}` VALUES( NULL, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, '0000-00-00 00:00:00' )";
	
					$wpdb->query(
							$wpdb->prepare( $insert_query, $wcrb_reminder_datetime, $reminder_name, $reminder_description, $reminder_interval, $message_us, $sms_message, $reminder_for_device_types, $reminder_for_device_brand, $active_email_reminder, $active_sms_reminder, $reminder_status )
					);

					$reminder_id = $wpdb->insert_id;

					$message = esc_html__( 'You have added reminder.', 'computer-repair-shop' );
					$success = 'YES';
				}
				if ( $formType == 'update' && isset( $_POST['reminder_id'] ) && ! empty( $_POST['reminder_id'] ) ) {
					//Update reminder
					$reminder_id = sanitize_text_field( $_POST['reminder_id'] );
					//Update functionality
					$data 	= array(
						'name' 			  => $reminder_name,
						'description' 	  => $reminder_description,
						'interval' 	      => $reminder_interval,
						'email_body' 	  => $message_us,
						'sms_body' 		  => $sms_message, 
						'device_type' 	  => $reminder_for_device_types,
						'device_brand' 	  => $reminder_for_device_brand,
						'email_status' 	  => $active_email_reminder,
						'sms_status' 	  => $active_sms_reminder,
						'reminder_status' => $reminder_status
					);
					$where 	= ['reminder_id' 	=> $reminder_id];

					$update_row = $wpdb->update( $computer_repair_maint_reminders, $data, $where );

					$message = esc_html__( 'You have updated reminder.', 'computer-repair-shop' );
					$success = 'NO';
				}
			}
		}

		$values['message'] = $message;
		$values['success'] = $success;

		wp_send_json( $values );
		wp_die();
	}
	
	function wc_rb_reload_maintenance_update() {
		global $wpdb, $WCRB_MANAGE_DEVICES;

		$reminder_status = $sms_reminder_status = $email_reminder_status = $thereminder_id = $selected_brand = $selected_types = $sms_message = $email_message = $reminder_description = $reminder_interval = $reminder_name = '';

		if ( isset( $_POST['recordID'] ) && ! empty ( $_POST['recordID'] ) ) :
			$_rec_reminder_id = sanitize_text_field( $_POST['recordID'] );

			$computer_repair_maint_reminders = $wpdb->prefix.'wc_cr_maint_reminders';
			$wc_reminder_row				 = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$computer_repair_maint_reminders} WHERE `reminder_id` = %d", $_rec_reminder_id ) );

			$reminder_status 		= $wc_reminder_row->reminder_status;
			$sms_reminder_status 	= $wc_reminder_row->sms_status;
			$email_reminder_status 	= $wc_reminder_row->email_status;
			$thereminder_id 		= $wc_reminder_row->reminder_id;
			$selected_brand 		= $wc_reminder_row->device_brand;
			$selected_types 		= $wc_reminder_row->device_type;
			$sms_message 			= $wc_reminder_row->sms_body;
			$email_message 			= $wc_reminder_row->email_body;
			$reminder_description 	= $wc_reminder_row->description;
			$reminder_interval 		= $wc_reminder_row->interval;
			$reminder_name 		 	= $wc_reminder_row->name;
		endif;

		$wc_device_brand_label = ( empty( get_option( 'wc_device_brand_label' ) ) ) ? esc_html__( 'Device Brand', 'computer-repair-shop' ) : get_option( 'wc_device_brand_label' );
		$wc_device_type_label = ( empty( get_option( 'wc_device_type_label' ) ) ) ? esc_html__( 'Device Type', 'computer-repair-shop' ) : get_option( 'wc_device_type_label' );

		$content = '<h2>' . esc_html__( 'Update Maintenance Reminder', 'computer-repair-shop' ) . '</h2>';
		$content .= '<div class="booking_success_msg"></div>';
		
		$content .= '<div class="grid-x grid-margin-x"><div class="cell"><div data-abide-error class="alert callout" style="display: none;">';
		$content .= '<p><i class="fi-alert"></i> ' . esc_html__( 'There are some errors in your form.', 'computer-repair-shop' ) . '</p>';
		$content .= '</div></div></div>';

		$content .= '<div class="grid-x grid-margin-x"><div class="cell medium-6">';
		$content .= '<label>' . esc_html__( 'Reminder Name', 'computer-repair-shop' )  . '*';
		$content .= '<input name="reminder_name" type="text" class="form-control login-field"
						value="' . esc_html( $reminder_name ) . '" required id="reminder_name"/>';
		$content .= '</label></div>';
		
		$content .= '<div class="cell medium-6">';
		$content .= '<label>' . esc_html__( 'Run After', 'computer-repair-shop' ) . '*';
		$content .= '<select name="reminder_interval" class="form-control form-select">';
		
		$reminder_interval_seven 	= ( $reminder_interval == '7' ) ? 'selected' : '';
		$reminder_interval_one_m 	= ( $reminder_interval == '30' ) ? 'selected' : '';
		$reminder_interval_three_m 	= ( $reminder_interval == '90' ) ? 'selected' : '';
		$reminder_interval_six_m 	= ( $reminder_interval == '180' ) ? 'selected' : '';
		$reminder_interval_year 	= ( $reminder_interval == '365' ) ? 'selected' : '';

		$content .= '<option value="">' . esc_html__( 'Select Time Interval', 'computer-repair-shop' ) . '</option>';
		$content .= '<option value="7" ' . esc_html( $reminder_interval_seven ) . '>' . esc_html__( '7 Days', 'computer-repair-shop' ) . '</option>';
		$content .= '<option value="30" ' . esc_html( $reminder_interval_one_m ) . '>' . esc_html__( '30 Days', 'computer-repair-shop' ) . '</option>';
		$content .= '<option value="90" ' . esc_html( $reminder_interval_three_m ) . '>' . esc_html__( '90 Days', 'computer-repair-shop' ) . '</option>';
		$content .= '<option value="180" ' . esc_html( $reminder_interval_six_m ) . '>' . esc_html__( '180 Days', 'computer-repair-shop' ) . '</option>';
		$content .= '<option value="365" ' . esc_html( $reminder_interval_year ) . '>' . esc_html__( '365 Days', 'computer-repair-shop' ) . '</option>';

		$content .= '</select></label></div></div>';

		$content .= '<div class="grid-x grid-margin-x"><div class="cell medium-12">';
		$content .= '<label>' . esc_html__( 'Description', 'computer-repair-shop' );
		$content .= '<input name="reminder_description" type="text" class="form-control login-field"
						value="' . esc_html( $reminder_description ) . '" id="reminder_description" />';
		$content .= '</label></div></div>';


		$content .= '<div class="grid-x grid-margin-x"><div class="cell medium-12">';
		$content .= '<label>' . esc_html__( 'Email Message', 'computer-repair-shop' ) . ' | ';
		$content .= esc_html__( 'Keywords available to use', 'computer-repair-shop' ) . '{{device_name}} {{customer_name}} {{unsubscribe_device}}';
		$content .= '<textarea name="email_message" class="form-control" id="email_message" rows="6">' . html_entity_decode( $email_message ) . '</textarea>';
		$content .= '</label></div><p>&nbsp;</p></div>';

		$content .= '<div class="grid-x grid-margin-x"><div class="cell medium-12">';
		$content .= '<label>' . esc_html__( 'SMS Message', 'computer-repair-shop' ) . ' | ' . esc_html__( 'Keywords available to use', 'computer-repair-shop' ) . ' {{device_name}} {{customer_name}} {{unsubscribe_device}}';
		$content .= '<textarea name="sms_message" class="form-control"
							id="sms_message">' . esc_html( $sms_message ) . '</textarea>';
		$content .= '</label></div></div>';

		$content .= '<div class="grid-x grid-margin-x"><div class="cell medium-6">';
		$content .= '<label>' . esc_html__( 'For ', 'computer-repair-shop' ) . ' ' . esc_html( $wc_device_type_label ) . '*';
		$content .= '<select name="reminder_for_device_types" class="form-control form-select">';

		$allowedHTML = ( function_exists( 'wc_return_allowed_tags' ) ) ? wc_return_allowed_tags() : '';
		$brandsOutput = $WCRB_MANAGE_DEVICES->generate_device_type_options( $selected_types, 'all' );
		$content .= wp_kses( $brandsOutput, $allowedHTML );	
		$content .= '</select></label></div>';

		$content .= '<div class="cell medium-6">';
		$content .= '<label>' . esc_html__( 'For ', 'computer-repair-shop' ) . ' ' . esc_html( $wc_device_brand_label ) . '*';
		$content .= '<select name="reminder_for_device_brand" class="form-control form-select">';

		$allowedHTML = ( function_exists( 'wc_return_allowed_tags' ) ) ? wc_return_allowed_tags() : '';
		$manufactureOutput = $WCRB_MANAGE_DEVICES->generate_manufacture_options( $selected_brand, 'all' );
		$content .= wp_kses( $manufactureOutput, $allowedHTML );
		$content .= '</select></label></div><p>&nbsp;</p></div>';

		$content .= '<div class="grid-x grid-margin-x"><p>&nbsp;</p><div class="cell medium-4">';
		$content .= '<label>' . esc_html__( 'Activate Email Reminder', 'computer-repair-shop' ) . '*';

		$active_email_re 	= ( $email_reminder_status == 'active' ) ? 'selected' : '';
		$inactive_email_re 	= ( $email_reminder_status == 'inactive' ) ? 'selected' : '';

		$content .= '<select name="email_reminder_status" class="form-control form-select">';
		$content .= '<option value="">' . esc_html__( 'Email Reminder Status', 'computer-repair-shop' ) . '</option>';
		$content .= '<option value="active" ' . esc_html( $active_email_re ) . '>' . esc_html__( 'Active', 'computer-repair-shop' ) . '</option>';
		$content .= '<option value="inactive" ' . esc_html( $inactive_email_re ) . '>' . esc_html__( 'Inactive', 'computer-repair-shop' ) . '</option>';
		$content .= '</select></label></div>';

		$content .= '<div class="cell medium-4">';
		$content .= '<label>' . esc_html__( 'Activate SMS Reminder', 'computer-repair-shop' ) . '*';

		$active_sms_re 	 = ( $sms_reminder_status == 'active' ) ? 'selected' : '';
		$inactive_sms_re = ( $sms_reminder_status == 'inactive' ) ? 'selected' : '';

		$content .= '<select name="sms_reminder_status" class="form-control form-select">';
	    $content .= '<option value="">' . esc_html__( 'SMS Reminder Status', 'computer-repair-shop' ) . '</option>';
		$content .= '<option value="active" ' . esc_html( $active_sms_re ) . '>' . esc_html__( 'Active', 'computer-repair-shop' ) . '</option>';
		$content .= '<option value="inactive" ' . esc_html( $inactive_sms_re ) . '>' . esc_html__( 'Inactive', 'computer-repair-shop' ) . '</option>';
		$content .= '</select></label></div>';

		$content .= '<div class="cell medium-3">';
		$content .= '<label>' . esc_html__( 'Reminder Status', 'computer-repair-shop' ) . '*';

		$active_reminder 	= ( $reminder_status == 'active' ) ? 'selected' : '';
		$inactive_reminder 	= ( $reminder_status == 'inactive' ) ? 'selected' : '';

		$content .= '<select name="reminder_status" class="form-control form-select">';
		$content .= '<option value="">' . esc_html__( 'Reminder Status', 'computer-repair-shop' ) . '</option>';
		$content .= '<option value="active" ' . esc_html( $active_reminder ) . '>' . esc_html__( 'Active', 'computer-repair-shop' ) . '</option>';
		$content .= '<option value="inactive" ' . esc_html( $inactive_reminder ) . '>' . esc_html__( 'Inactive', 'computer-repair-shop' ) . '</option>';
		$content .= '</select></label></div><p>&nbsp;</p></div>';
	
		$content .= '<input name="form_type" type="hidden" value="maintenance_reminder_form" />';

		$content .= wp_nonce_field( 'wcrb_nonce_maintenance_reminder', 'wcrb_nonce_maintenance_reminder_field', true, false );

		$content .= '<input name="form_type_status_reminder" type="hidden" value="update" />';
		$content .= '<input name="reminder_id" type="hidden" value="' . esc_html( $thereminder_id ) . '" />';

		$content .= '<div class="grid-x grid-margin-x"><fieldset class="cell medium-6">';
	    $content .= '<button class="button" type="submit">' . esc_html__( 'Update Reminder', 'computer-repair-shop' ) . '</button>';
		$content .= '</fieldset><small>(*) ' . esc_html__( 'fields are required', 'computer-repair-shop' ) . '</small></div>';


		$values['message'] = $content;
		$values['success'] = 'NO';

		wp_send_json( $values );
		wp_die();
	}

	/***
	 * @since 3.2
	 * 
	 * Adds Post Status form in footer.
	*/
	function wc_maintenance_reminder_form() {
		global $WCRB_MANAGE_DEVICES;

		$wc_device_brand_label = ( empty( get_option( 'wc_device_brand_label' ) ) ) ? esc_html__( 'Device Brand', 'computer-repair-shop' ) : get_option( 'wc_device_brand_label' );
		$wc_device_type_label = ( empty( get_option( 'wc_device_type_label' ) ) ) ? esc_html__( 'Device Type', 'computer-repair-shop' ) : get_option( 'wc_device_type_label' );

		$reminder_name = $reminder_description = $email_message = $sms_message = "";
		$button_label = $modal_label = esc_html__( 'Add new', 'computer-repair-shop' );
		?>
		<!-- Modal for Post Entry /-->
		
		<div class="small reveal" id="maintenancereminderReveal" data-reveal>
			<form data-async data-abide class="needs-validation" novalidate method="post" data-success-class=".booking_success_msg">
			<div id="replacement_part_reminder">
			<h2><?php echo esc_html( $modal_label ) . " " . esc_html__( 'Maintenance Reminder', 'computer-repair-shop' ); ?></h2>
			
			<div class="booking_success_msg"></div>
			
				<div class="grid-x grid-margin-x">
					<div class="cell">
						<div data-abide-error class="alert callout" style="display: none;">
							<p><i class="fi-alert"></i> <?php echo esc_html__( 'There are some errors in your form.', 'computer-repair-shop' ); ?></p>
						</div>
					</div>
				</div>

				<!-- Login Form Starts /-->
				<div class="grid-x grid-margin-x">
					<div class="cell medium-6">
						<label><?php echo esc_html__( 'Reminder Name', 'computer-repair-shop' ); ?>*
							<input name="reminder_name" type="text" class="form-control login-field"
									value="<?php echo esc_html( $reminder_name ); ?>" id="reminder_name"/>
						</label>
					</div>

					<div class="cell medium-6">
						<label><?php echo esc_html__( 'Run After', 'computer-repair-shop' ); ?>*
							<select name="reminder_interval" class="form-control form-select">
								<option value=""><?php echo esc_html__( 'Select Time Interval', 'computer-repair-shop' ); ?></option>
								<option value="7"><?php echo esc_html__( '7 Days', 'computer-repair-shop' ); ?></option>
								<option value="30"><?php echo esc_html__( '30 Days', 'computer-repair-shop' ); ?></option>
								<option value="90"><?php echo esc_html__( '90 Days', 'computer-repair-shop' ); ?></option>
								<option value="180"><?php echo esc_html__( '90 Days', 'computer-repair-shop' ); ?></option>
								<option value="365"><?php echo esc_html__( '365 Days', 'computer-repair-shop' ); ?></option>
							</select>
						</label>
					</div>
				</div>
	
				<div class="grid-x grid-margin-x">
					<div class="cell medium-12">
						<label><?php echo esc_html__( 'Description', 'computer-repair-shop' ); ?>
							<input name="reminder_description" type="text" class="form-control login-field"
									value="<?php echo esc_html( $reminder_description ); ?>" id="reminder_description" />
						</label>
					</div>
				</div>

				<div class="grid-x grid-margin-x">
					<div class="cell medium-12">
						<label><?php echo esc_html__( 'Email Message', 'computer-repair-shop' ); ?> | 
						<?php echo esc_html__( 'Keywords available to use', 'computer-repair-shop' );?> {{device_name}} {{customer_name}} {{unsubscribe_device}}
							<?php
								wp_editor( $email_message , 'my_option', array(
									'wpautop'       => true,
									'media_buttons' => false,
									'textarea_name' => 'email_message',
									'editor_class'  => 'my_custom_class',
									'textarea_rows' => 6
								));
							?>
						</label>
					</div>
					<p>&nbsp;</p>
				</div>

				<div class="grid-x grid-margin-x">
					<div class="cell medium-12">
						<label><?php echo esc_html__( 'SMS Message', 'computer-repair-shop' ); ?> | <?php echo esc_html__( 'Keywords available to use', 'computer-repair-shop' );?> {{device_name}} {{customer_name}}
							<textarea name="sms_message" class="form-control"
									 id="sms_message"><?php echo esc_html( $sms_message ); ?></textarea>
						</label>
					</div>
				</div>
				<!-- Login Form Ends /-->

				<div class="grid-x grid-margin-x">
					<div class="cell medium-6">
						<label><?php echo esc_html__( 'For ', 'computer-repair-shop' ); ?> <?php echo esc_html( $wc_device_type_label ); ?>*
							<select name="reminder_for_device_types" class="form-control form-select">
								<?php 
									$allowedHTML = ( function_exists( 'wc_return_allowed_tags' ) ) ? wc_return_allowed_tags() : '';
									$brandsOutput = $WCRB_MANAGE_DEVICES->generate_device_type_options( '', 'all' );
									echo wp_kses( $brandsOutput, $allowedHTML ); ?>	
							</select>
						</label>
					</div>

					<div class="cell medium-6">
						<label><?php echo esc_html__( 'For ', 'computer-repair-shop' ); ?> <?php echo esc_html( $wc_device_brand_label ); ?>*
							<select name="reminder_for_device_brand" class="form-control form-select">
								<?php 
									$allowedHTML = ( function_exists( 'wc_return_allowed_tags' ) ) ? wc_return_allowed_tags() : '';
									$manufactureOutput = $WCRB_MANAGE_DEVICES->generate_manufacture_options( '', 'all' );
									echo wp_kses( $manufactureOutput, $allowedHTML ); ?>
							</select>
						</label>
					</div>
					<p>&nbsp;</p>
				</div>

				<div class="grid-x grid-margin-x">
					<p>&nbsp;</p>	
					<div class="cell medium-4">
						<label><?php echo esc_html__( 'Activate Email Reminder', 'computer-repair-shop' ); ?>*
							<select name="email_reminder_status" class="form-control form-select">
								<option value=""><?php echo esc_html__( 'Email Reminder Status', 'computer-repair-shop' ); ?></option>
								<option value="active"><?php echo esc_html__( 'Active', 'computer-repair-shop' ); ?></option>
								<option value="inactive"><?php echo esc_html__( 'Inactive', 'computer-repair-shop' ); ?></option>
							</select>
						</label>
					</div>

					<div class="cell medium-4">
						<label><?php echo esc_html__( 'Activate SMS Reminder', 'computer-repair-shop' ); ?>*
							<select name="sms_reminder_status" class="form-control form-select">
								<option value=""><?php echo esc_html__( 'SMS Reminder Status', 'computer-repair-shop' ); ?></option>
								<option value="active"><?php echo esc_html__( 'Active', 'computer-repair-shop' ); ?></option>
								<option value="inactive"><?php echo esc_html__( 'Inactive', 'computer-repair-shop' ); ?></option>
							</select>
						</label>
					</div>

					<div class="cell medium-3">
						<label><?php echo esc_html__( 'Reminder Status', 'computer-repair-shop' ); ?>*
							<select name="reminder_status" class="form-control form-select">
								<option value=""><?php echo esc_html__( 'Reminder Status', 'computer-repair-shop' ); ?></option>
								<option value="active"><?php echo esc_html__( 'Active', 'computer-repair-shop' ); ?></option>
								<option value="inactive"><?php echo esc_html__( 'Inactive', 'computer-repair-shop' ); ?></option>
							</select>
						</label>
					</div>
					<p>&nbsp;</p>
				</div>
				
				<!-- Login Form Ends /-->
				<input name="form_type" type="hidden" 
								value="maintenance_reminder_form" />
				<?php wp_nonce_field( 'wcrb_nonce_maintenance_reminder', 'wcrb_nonce_maintenance_reminder_field', true, true ); ?>
				<input name="form_type_status_reminder" type="hidden" value="add" />

				<div class="grid-x grid-margin-x">
					<fieldset class="cell medium-6">
						<button class="button" type="submit"><?php echo esc_html( $button_label ); ?></button>
					</fieldset>
					<small>(*) <?php echo esc_html__( 'fields are required', 'computer-repair-shop' ); ?></small>	
				</div>

			</div></form>
	
			<button class="close-button" data-close aria-label="Close modal" type="button">
				<span aria-hidden="true">&times;</span>
			</button>
		</div>
		<?php
	}

	function wcrb_send_reminder_email( $job_id, $reminder_id ) {
		$menu_name_p 	= get_option( 'menu_name_p' );

		if ( empty( $reminder_id ) || empty( $job_id ) ) {
			return esc_html__( 'Job ID and Reminder ID are required to send email reminder', 'computer-repair-shop' );
		}

		$customer_id = get_post_meta( $job_id, "_customer", true );

		if ( empty( $customer_id ) ) {
			return esc_html__( 'Customer not set for this job', 'computer-repair-shop' );
		}

		$user_info 	= get_userdata( $customer_id );
		$user_name 	= $user_info->first_name . ' ' . $user_info->last_name;
		$user_email = $user_info->user_email;

		if ( empty( $user_email ) ) {
			return esc_html__( 'Could not find the email for customer', 'computer-repair-shop' );
		}

		$email_optout = get_post_meta( $job_id, "_email_optout", true );

		if ( $email_optout == 'YES' ) {
			return esc_html__( 'Customer opted out for this email', 'computer-repair-shop' );
		}

		//Get Email Status
		$email_status = $this->get_field( $reminder_id, 'email_status' );

		if ( $email_status == 'inactive' ) {
			return esc_html__( 'Email is not active to send', 'computer-repair-shop' );
		}

		$email_body = $this->get_field( $reminder_id, 'email_body' );

		if ( empty( $email_body ) ) {
			return esc_html__( 'No message defined to email', 'computer-repair-shop' );
		}
		$email_body = html_entity_decode( $email_body );
		
		$wc_device_label = ( empty( get_option( 'wc_device_label' ) ) ) ? esc_html__( 'Device', 'computer-repair-shop' ) : get_option( 'wc_device_label' );

		//{{device_name}} {{customer_name}} //$user_name
		$to = $user_email;

		$headers = array('Content-Type: text/html; charset=UTF-8');

		$current_devices = get_post_meta( $job_id, '_wc_device_data', true );

		$device_type  = $this->get_field( $reminder_id, 'device_type' );
		$device_brand = $this->get_field( $reminder_id, 'device_brand' );

        if ( ! empty( $current_devices )  && is_array( $current_devices ) ) {
            foreach( $current_devices as $device_data ) {
                $device_post_id = ( isset( $device_data['device_post_id'] ) ) ? $device_data['device_post_id'] : '';
				
				$theTypeId   = wcrb_return_device_terms( $device_post_id, 'device_type' );
				$theBrandId  = wcrb_return_device_terms( $device_post_id, 'device_brand' );

				$sendme = 'YES';
				if ( $device_type == 'All' && $device_brand == 'All' ) {
					//SMS will go
				} elseif ( $device_type == 'All' && $device_brand == $theBrandId ) {
					//SMS will go
				} elseif ( $device_type == $theTypeId && $device_brand == 'All' ) {
					//SMS will go  
				} elseif ( $device_type == $theTypeId && $device_brand == $theBrandId ) {
					//SMS will go
				} else {
					//SMS not going
					$sendme = 'NO';
				}

				if ( $sendme == 'YES' ) {
					//Send Email
					$device_label = return_device_label( $device_post_id );

					$subject = ( isset( $subject ) ) ? $subject : esc_html__( 'Maintenance reminder for your ', 'computer-repair-shop' ) . $wc_device_label . ' ' . $device_label;
					$subject = $subject . ' | ' . esc_html( $menu_name_p );
	
					$email_body = str_replace( '{{customer_name}}', $user_name, $email_body );
					$email_body = str_replace( '{{device_name}}', $device_label, $email_body );

					$siteUrl 	= get_site_url();
					$arr_params = array( 'thejobid' => $job_id, 'theunsub' => 'true' );
					$unsubURL 	= esc_url( add_query_arg( $arr_params, $siteUrl ) );

					$email_body = str_replace( '{{unsubscribe_device}}', $unsubURL, $email_body );
	
					$body = '<div class="repair_box">' . $email_body . '</div>';
	
					$body_output = wc_rs_get_email_head();
					$body_output .= $body;
					$body_output .= wc_rs_get_email_footer();
	
					wp_mail( $to, $subject, $body_output, $headers );
	
					//Let's log the email now
					$arguments = array( 'customer_id' => $customer_id, 'job_id' => $job_id, 'reminder_id' => $reminder_id, 'email_to' => $to, 'sms_to' => '', 'status' => 'sent' );
					$this->wc_rb_add_reminder_log( $arguments );
				}
            }
        }
	}

	function wcrb_send_reminder_sms( $job_id, $reminder_id ) {
		global $OBJ_SMS_SYSTEM;

		if ( empty( $reminder_id ) || empty( $job_id ) ) {
			return esc_html__( 'Job ID and Reminder ID are required to send SMS reminder', 'computer-repair-shop' );
		}
		$customer_id = get_post_meta( $job_id, "_customer", true );

		if ( empty( $customer_id ) ) {
			return esc_html__( 'Customer not set for this job', 'computer-repair-shop' );
		}

		$user_info 	= get_userdata( $customer_id );
		$user_name 	= $user_info->first_name . ' ' . $user_info->last_name;
		$phone_number = get_user_meta( $customer_id, 'billing_phone', true );

		if ( empty( $phone_number ) ) {
			return esc_html__( 'Could not find the phone number of customer', 'computer-repair-shop' );
		}

		$email_optout = get_post_meta( $job_id, "_email_optout", true );

		if ( $email_optout == 'YES' ) {
			return esc_html__( 'Customer opted out for this email', 'computer-repair-shop' );
		}

		//Get Email Status
		$sms_status = $this->get_field( $reminder_id, 'sms_status' );

		if ( $sms_status == 'inactive' ) {
			return esc_html__( 'SMS is not active to send', 'computer-repair-shop' );
		}
		$sms_body = $this->get_field( $reminder_id, 'sms_body' );

		if ( empty( $sms_body ) ) {
			return esc_html__( 'No message defined to sms', 'computer-repair-shop' );
		}
		$wc_device_label = ( empty( get_option( 'wc_device_label' ) ) ) ? esc_html__( 'Device', 'computer-repair-shop' ) : get_option( 'wc_device_label' );

		//{{device_name}} {{customer_name}} {{unsubscribe_device}} //$user_name

		$current_devices = get_post_meta( $job_id, '_wc_device_data', true );

		$device_type  = $this->get_field( $reminder_id, 'device_type' );
		$device_brand = $this->get_field( $reminder_id, 'device_brand' );

        if ( ! empty( $current_devices )  && is_array( $current_devices ) ) {
            foreach( $current_devices as $device_data ) {
                $device_post_id = ( isset( $device_data['device_post_id'] ) ) ? $device_data['device_post_id'] : '';
				
				$theTypeId   = wcrb_return_device_terms( $device_post_id, 'device_type' );
				$theBrandId  = wcrb_return_device_terms( $device_post_id, 'device_brand' );

				$sendme = 'YES';
				if ( $device_type == 'All' && $device_brand == 'All' ) {
					//SMS will go
				} elseif ( $device_type == 'All' && $device_brand == $theBrandId ) {
					//SMS will go
				} elseif ( $device_type == $theTypeId && $device_brand == 'All' ) {
					//SMS will go  
				} elseif ( $device_type == $theTypeId && $device_brand == $theBrandId ) {
					//SMS will go
				} else {
					//SMS not going
					$sendme = 'NO';
				}

				if ( $sendme == 'YES' ) {
					//Send Email
					$device_label = return_device_label( $device_post_id );

					$sms_body = str_replace( '{{customer_name}}', $user_name, $sms_body );
					$sms_body = str_replace( '{{device_name}}', $device_label, $sms_body );

					$siteUrl = get_site_url();
					$arr_params = array( 'thejobid' => $job_id, 'theunsub' => 'true' );
					$unsubURL = esc_url( add_query_arg( $arr_params, $siteUrl ) );

					$sms_body = str_replace( '{{unsubscribe_device}}', $unsubURL, $sms_body );
	
					$OBJ_SMS_SYSTEM->send_sms( $phone_number, $sms_body, $job_id );
	
					//Let's log the email now
					$arguments = array( 'customer_id' => $customer_id, 'job_id' => $job_id, 'reminder_id' => $reminder_id, 'email_to' => '', 'sms_to' => $phone_number, 'status' => 'sent' );
					$this->wc_rb_add_reminder_log( $arguments );
				}
            }
        }
	}

	/**
	 * Accepts array with arguments
	 * 
	 * array( 'customer_id' => , 'job_id' => , 'reminder_id' => , 'email_to' => , 'sms_to' => , 'status' => , ) 
	 */
	function wc_rb_add_reminder_log( $args ) {
		global $wpdb;

		if ( ! is_array( $args ) ) {
			return esc_html__( 'Is not an array', 'computer-repair-shop' );
		}
		if ( ! isset( $args['customer_id'] ) || empty( $args['customer_id'] ) ) {
			return esc_html__( 'Missing customer id', 'computer-repair-shop' );
		}
		if ( ! isset( $args['job_id'] ) || empty( $args['job_id'] ) ) {
			return esc_html__( 'Missing Job id', 'computer-repair-shop' );
		}
		if ( ! isset( $args['reminder_id'] ) || empty( $args['reminder_id'] ) ) {
			return esc_html__( 'Missing reminder id', 'computer-repair-shop' );
		}

		$customer_id = ( isset( $args['customer_id'] ) && ! empty( $args['customer_id'] ) ) ? sanitize_text_field( $args['customer_id'] ) : '';
		$job_id 	 = ( isset( $args['job_id'] ) && ! empty( $args['job_id'] ) ) ? sanitize_text_field( $args['job_id'] ) : '';
		$reminder_id = ( isset( $args['reminder_id'] ) && ! empty( $args['reminder_id'] ) ) ? sanitize_text_field( $args['reminder_id'] ) : '';
		$email_to 	 = ( isset( $args['email_to'] ) && ! empty( $args['email_to'] ) ) ? sanitize_text_field( $args['email_to'] ) : '';
		$sms_to   	 = ( isset( $args['sms_to'] ) && ! empty( $args['sms_to'] ) ) ? sanitize_text_field( $args['sms_to'] ) : '';
		$status   	 = ( isset( $args['status'] ) && ! empty( $args['status'] ) ) ? sanitize_text_field( $args['status'] ) : 'unknown';

		$computer_repair_reminder_logs   = $wpdb->prefix . 'wc_cr_reminder_logs';
		$wcrb_log_dateti = wp_date( 'Y-m-d H:i:s' );

		$insert_query =  "INSERT INTO `{$computer_repair_reminder_logs}` VALUES( NULL, %s, %d, %d, %d, %s, %s, %s )";
	
		$wpdb->query(
				$wpdb->prepare( $insert_query, $wcrb_log_dateti, $customer_id, $job_id, $reminder_id, $email_to, $sms_to, $status )
		);

		$log_id = $wpdb->insert_id;
		return $wpdb->last_error;
	}

	function return_reminder_logs_history() {
		global $wpdb;

		$computer_repair_reminder_logs   = $wpdb->prefix . 'wc_cr_reminder_logs';

		$select_query 	= "SELECT * FROM `" . $computer_repair_reminder_logs . "` ORDER BY `log_id` DESC";
        $select_results = $wpdb->get_results( $select_query );
            
        $output = ( $wpdb->num_rows == 0 ) ? esc_html__( 'There is no record available', 'computer-repair-shop' ) : '';

		$date_format = get_option('date_format');
		$date_format .= ' ' . get_option('time_format');
		//log_id datetime customer_id job_id reminder_id email_to sms_to status
        foreach( $select_results as $result ) {
			$_date = date_i18n( $date_format, strtotime( $result->datetime ) );

			$user 		= get_user_by( 'id', $result->customer_id );
			$first_name	= empty( $user->first_name ) ? "" : $user->first_name;
			$last_name 	= empty( $user->last_name )? "" : $user->last_name;
			$cust_name  =  $first_name. ' ' .$last_name ;

			$email = ( ! empty( $result->email_to ) ) ? $result->email_to : ' - ';
			$sms   = ( ! empty( $result->sms_to ) ) ? $result->sms_to : ' - ';

			$reminder_name = $this->get_field( $result->reminder_id, 'name' );

			$caseNumber = get_the_title( $result->job_id );
			$admin_url  = admin_url( 'post.php?post=' . $result->job_id . '&action=edit' );

			$output .= '<tr>';

			$output .= '<td>' . esc_html( $result->log_id ) . '</td>';
			$output .= '<td>' . esc_html( $_date ) . '</td>';
			$output .= '<td>' . esc_html( $cust_name ) . '</td>';
			$output .= '<td><a href="' . esc_url( $admin_url ) . '">' . esc_html( $caseNumber ) . '</a></td>';
			$output .= '<td>' . esc_html( $reminder_name ) . '</td>';
			$output .= '<td>' . esc_html( $email ) . '</td>';
			$output .= '<td>' . esc_html( $sms ) . '</td>';
			$output .= '</tr>';
		}

		$allowedHTML = wc_return_allowed_tags(); 
		echo wp_kses( $output, $allowedHTML );
	}
}