<?php
	/*
	 * Start Job
	 * 
	 * By Selecting Device
	 * Shortcode for front end
	 * 
	 * @Since 3.53
	*/

	if(!function_exists("wc_start_job_with_device")):
		function wc_start_job_with_device() { 
			if(!is_user_logged_in()) {
				return "";
				exit;
			} 
			wp_enqueue_script("intl-tel-input");
			wp_enqueue_style("intl-tel-input");

			add_action( 'wp_print_footer_scripts', 'wcrb_intl_tel_input_script' );

			$user_role = wc_get_user_roles_by_user_id(get_current_user_id());

			$wc_device_label         = ( empty( get_option( 'wc_device_label' ) ) ) ? esc_html__( 'Device', 'computer-repair-shop' ) : get_option( 'wc_device_label' );
			$wc_device_id_imei_label = ( empty( get_option( 'wc_device_id_imei_label' ) ) ) ? esc_html__( 'ID/IMEI', 'computer-repair-shop' ) : get_option( 'wc_device_id_imei_label' );

			$content = '';

			if(in_array("administrator", $user_role) || in_array("technician", $user_role) || in_array("store_manager", $user_role)) :
				wp_enqueue_script("foundation-js");
				wp_enqueue_script("wc-cr-js");

				wp_enqueue_style("select2");
				wp_enqueue_script("select2");

				$content .= '<button class="button" data-open="WCstartJob">'.esc_html__("Start a Job", "computer-repair-shop").'</button>';

				$content .= '<div class="reveal large" id="WCstartJob" data-reveal><div class="startNewJob">';

				$content .= '<p class="lead">'.esc_html__("Start a New Job", "computer-repair-shop").'</p>';

				$content .= '<div class="form-message"></div><form data-async data-abide class="needs-validation" method="post"><div class="grid-container">';

				$content .= '<div class="grid-x grid-margin-x">';
				$content .= '<div class="medium-6 cell">';
				
				$content .= '<label for="deliveryDate">'.esc_html__("Delivery Date", "computer-repair-shop")." (*)";
				$content .= '<input type="date" name="delivery_date" id="deliveryDate" required class="form-control login-field" placeholder="">';
				$content .= '</label>';

				$content .= '</div><!-- Column /-->';

				$content .= '<div class="medium-6 cell">';

				$content .= '<label for="jobDetail">'.esc_html__("Select Customer", "computer-repair-shop");
				$content .= wp_dropdown_users( array( 'show_option_all' => esc_html__('Select Customer', 'computer-repair-shop'), 'name' => 'customer', 'role' => 'customer', 'echo' => 0, 'selected' => "" ) );
				$content .= '</label>';
				$content .= '<p class="help-text">'.esc_html__("Select customer if does not exist!", 'computer-repair-shop').' <a class="button button-primary button-small" id="customerFormReveal">'.esc_html__("Add New Customer", "computer-repair-shop").'</a></p>';

				$content .= '</div>';
				$content .= '</div><!-- Grid /-->';


				$content .= '<div class="grid-x grid-margin-x">';
				$content .= '<div class="medium-6 cell">';
			
				$content .= '<label for="rep_devices">';
				$content .= $wc_device_label;
				$content .= '</label>';

				$content .= '<select id="rep_devices" name="device_post_id">';
				$content .= wc_generate_device_options("data-list");
				$content .= '</select>';
			
				$content .= '</div><!-- column Ends /-->';
				$content .= '<div class="medium-6 cell">';

				$content .= '<label for="devideID">' . $wc_device_label . ' ' . $wc_device_id_imei_label;
				$content .= '<input type="text" name="devideID" id="devideID" class="form-control login-field" placeholder="">';
				$content .= '</label>';
			
				$content .= '</div><!-- column Ends /-->';  
				$content .= '</div><!-- grid-x ends /-->';

				$content .= '<div class="addNewCustomer" id="addNewCustomer">';	
					$content .= '<div class="grid-x grid-margin-x">';
					$content .= '<div class="medium-6 cell">';
				
					$content .= '<label>'.esc_html__("First Name", "computer-repair-shop")." (*)";
					$content .= '<input type="text" name="firstName" id="firstName" class="form-control login-field" value="" placeholder="">';
					$content .= '</label>';
				 
					$content .= '</div><!-- column Ends /-->';
					$content .= '<div class="medium-6 cell">';
			
					$content .= '<label>'.esc_html__("Last Name", "computer-repair-shop")." (*)";
					$content .= '<input type="text" name="lastName" id="lastName" class="form-control login-field" placeholder="">';
					$content .= '</label>';
				 
					$content .= '</div><!-- column Ends /-->';  
					$content .= '</div><!-- grid-x ends /-->';
			
					$content .= '<div class="grid-x grid-margin-x">';
					$content .= '<div class="medium-6 cell">';
			
					$content .= '<label>'.esc_html__("Email", "computer-repair-shop")." (*)";
					$content .= '<input type="email" name="userEmail" id="userEmail" class="form-control login-field" placeholder="">';
					$content .= '</label>';
				 
					$content .= '</div><!-- column Ends /-->';
					$content .= '<div class="medium-6 cell">';
			
					$content .= '<label>'.esc_html__("Phone number", "computer-repair-shop");
					$content .= '<input type="text" name="phoneNumber_ol" class="form-control login-field" placeholder="">';
					$content .= '</label>';
				 
					$content .= '</div><!-- column Ends /-->';  
					$content .= '</div><!-- grid-x ends /-->';
						
					$content .= '<div class="grid-x grid-margin-x">';
					$content .= '<div class="medium-6 cell">';
			
					$content .= '<label>'.esc_html__("City", "computer-repair-shop");
					$content .= '<input type="text" name="userCity" class="form-control login-field" placeholder="">';
					$content .= '</label>';
				 
					$content .= '</div><!-- column Ends /-->';
					$content .= '<div class="medium-6 cell">';
			
					$content .= '<label>'.esc_html__("Postal Code", "computer-repair-shop");
					$content .= '<input type="text" name="postalCode" class="form-control login-field" placeholder="">';
					$content .= '</label>';
				 
					$content .= '</div><!-- column Ends /-->';  
					$content .= '</div><!-- grid-x ends /-->';
			
					$content .= '<div class="grid-x grid-margin-x">';
					$content .= '<div class="medium-6 cell">';
			
					$content .= '<label>'.esc_html__("Company", "computer-repair-shop");
					$content .= '<input type="text" name="userCompany" class="form-control login-field" placeholder="">';
					$content .= '</label>';
				 
					$content .= '</div><!-- column Ends /-->';
					$content .= '<div class="medium-6 cell">';
			
					$content .= '<label>'.esc_html__("Address", "computer-repair-shop");
					$content .= '<input type="text" name="userAddress" class="form-control login-field" placeholder="">';
					$content .= '</label>';
				 	$content .= '<input type="hidden" name="verify_customer" id="verifyCustomer" value="0" />';
					$content .= '</div><!-- column Ends /-->';  
					$content .= '</div><!-- grid-x ends /-->';
				$content .= '</div>';//Add new customer wrapper

				$content .= '<div class="grid-x grid-margin-x">';
				$content .= '<div class="medium-12 cell">';
		
				$content .= '<label>'.esc_html__("Job Details", "computer-repair-shop")." (*)";
				$content .= '<textarea name="jobDetails" required class="form-control login-field" placeholder=""></textarea>';
				$content .= '</label>';

				$content .= '<input name="form_type" type="hidden" value="wc_create_new_job_form" />';
				$content .=  wp_nonce_field( 'wc_computer_repair_nonce', 'wc_add_job_nonce', $echo = false);

				$content .= '<input type="submit" value="'.esc_html__("Create Job", "computer-repair-shop").'" class="button button-primary" /> ';
				
				$content .= '</div><!-- column Ends /-->';  
				$content .= '</div><!-- grid-x ends /-->';

				$content .= '</div></form></div><button class="close-button" data-close aria-label="Close modal" type="button"><span aria-hidden="true">&times;</span></button></div>';

				return $content;
			endif;
		}//Function Ends.

		add_shortcode('wc_start_job_with_device', 'wc_start_job_with_device');
	endif;


	if(!function_exists("wc_cr_create_new_job")):

		function wc_cr_create_new_job() { 
			global $wpdb;

			if (!isset( $_POST['wc_add_job_nonce'] ) 
				|| ! wp_verify_nonce( $_POST['wc_add_job_nonce'], 'wc_computer_repair_nonce' )) :
					$values['message'] = esc_html__("Something is wrong with your submission!", "computer-repair-shop");
					$values['success'] = "YES";
			else:
				$error = 0;
				//Form processing
				if(!isset($_POST["form_type"]) || $_POST["form_type"] != "wc_create_new_job_form") {
					$error = 1;
					$message = esc_html__("Unknown form.", "computer-repair-shop");
				}

				if(isset($_POST["verify_customer"]) && $_POST["verify_customer"] == '1' && ($_POST["customer"] == "0" || $_POST["customer"] == "")):
					$first_name 	= sanitize_text_field($_POST["firstName"]);
					$last_name 		= sanitize_text_field($_POST["lastName"]);
					$user_email 	= sanitize_email($_POST["userEmail"]);
					$username 		= sanitize_email($_POST["userEmail"]);
					$phone_number 	= sanitize_text_field($_POST["phoneNumber"]);
					$user_city 		= sanitize_text_field($_POST["userCity"]);
					$billing_tax 	= sanitize_text_field($_POST["billing_tax"]);
					$postal_code 	= sanitize_text_field($_POST["postalCode"]);
					$user_company 	= sanitize_text_field($_POST["userCompany"]);
					$user_address 	= sanitize_text_field($_POST["userAddress"]);
					$job_details 	= sanitize_text_field($_POST["jobDetails"]);
					$user_role 		= "customer";

					if(!$user_email) {
						$error = 1;
						$message = esc_html__("Email is not valid.", "computer-repair-shop");	
					} elseif(empty($first_name)) {
						$error = 1;
						$message = esc_html__("First name required.", "computer-repair-shop");
					} elseif(empty($job_details)) {
						$error = 1;
						$message = esc_html__("Please enter job details.", "computer-repair-shop");
					} if(!empty($username) && username_exists($username)) {
						$error = 1;
						$message = esc_html__("Duplicate User. Please login to submit your quote request.", "computer-repair-shop");
					} elseif(!empty($username) && !validate_username($username)) {
						$error = 1;
						$message = esc_html__("Not a valid username", "computer-repair-shop");
					} elseif(!empty($user_email) && !is_email($user_email)) {
						$error = 1;
						$message = esc_html__("Email is not valid", "computer-repair-shop");
					} elseif(email_exists($user_email)) {
						$error = 1;
						$message = esc_html__("Email already exists in customers, please use different email or search customer above.", "computer-repair-shop");
					}

					$password 	= wp_generate_password(8, false );
					
					if($error == 0) :
						if(!empty($username) && !empty($user_email)) {
							//We are all set to Register User.
							$userdata = array(
								'user_login' 	=> $username,
								'user_email' 	=> $user_email,
								'user_pass' 	=> $password,
								'first_name' 	=> $first_name,
								'last_name' 	=> $last_name,
								'role'			=> $user_role
							);
						
							//Insert User Data
							$register_user = wp_insert_user($userdata);
						
							//If Not exists
							if (!is_wp_error($register_user)) {
								//Use user instead of both in case sending notification to only user
								wp_new_user_notification($register_user, null, 'both');
								$message = esc_html__("User account is created logins sent to email.", "computer-repair-shop")." ".$user_email;
								$user_id = $register_user;
								
								global $WCRB_EMAILS;
								$WCRB_EMAILS->send_user_logins_after_register( $user_id, $password );

								if(!empty($user_id)) {
									update_user_meta( $user_id, 'billing_first_name', $first_name );
									update_user_meta( $user_id, 'billing_last_name', $last_name );
									update_user_meta( $user_id, 'billing_company', $user_company );
									update_user_meta( $user_id, 'billing_address_1', $user_address );
									update_user_meta( $user_id, 'billing_city', $user_city );
									update_user_meta( $user_id, 'billing_postcode', $postal_code );
									update_user_meta( $user_id, 'billing_phone', $phone_number );
									update_user_meta( $user_id, 'billing_tax', $billing_tax );

									update_user_meta( $user_id, 'billing_email', $user_email );

									update_user_meta( $user_id, 'shipping_first_name', $first_name );
									update_user_meta( $user_id, 'shipping_last_name', $last_name );
									update_user_meta( $user_id, 'shipping_company', $user_company );
									update_user_meta( $user_id, 'shipping_tax', $billing_tax );
									update_user_meta( $user_id, 'shipping_address_1', $user_address );
									update_user_meta( $user_id, 'shipping_city', $user_city );
									update_user_meta( $user_id, 'shipping_postcode', $postal_code );
									//update_user_meta( $user_id, 'shipping_state', $userState );
									//update_user_meta( $user_id, 'shipping_country', $userCountry );
									update_user_meta( $user_id, 'shipping_phone', $phone_number );
								}
							} else {
								$message = '<strong>' . $register_user->get_error_message() . '</strong>';
							}
						}
					endif;	
				elseif(isset($_POST["customer"]) && $_POST["customer"] == "0" && isset($_POST["verify_customer"]) && $_POST["verify_customer"] != '1'):
					$error = 1;
					$message = esc_html__("Please select a customer or add new customer.", "computer-repair-shop");
				else: 
					//User is logged in
					if($_POST["customer"] != 0) :
						$user_id 	= sanitize_text_field($_POST["customer"]);

						$user = get_userdata( $user_id );

						if ( $user === false ) {
							$error = 1;
							$message = esc_html__("Invalid Customer.", "computer-repair-shop");
						}
					endif;	

					if(!isset($_POST["device_post_id"]) || empty($_POST["device_post_id"])) {
						$wc_device_label = ( empty( get_option( 'wc_device_label' ) ) ) ? esc_html__( 'Device', 'computer-repair-shop' ) : get_option( 'wc_device_label' );

						$error = 1;
						$message = esc_html__("Please Select.", "computer-repair-shop") . ' ' . $wc_device_label;
					}

					if(!isset($_POST["jobDetails"]) || empty($_POST["jobDetails"])) {
						$error = 1;
						$message = esc_html__("Please add job details.", "computer-repair-shop");
					}

					if(!isset($_POST["delivery_date"]) || empty($_POST["delivery_date"])) {
						$error = 1;
						$message = esc_html__("Please add delivery date.", "computer-repair-shop");
					}
				endif;

				//We have user ID here.
				if(isset($user_id) && $error == 0) {
					//Let's insert the Job
					//We have now User ID
					//We have now Job Details. 
					
					$case_number 	= wc_generate_random_case_num();

					$job_details	= empty($_POST["jobDetails"])? "" : sanitize_text_field($_POST["jobDetails"]);

					$delivery_date  = empty($_POST["delivery_date"])? "" : sanitize_text_field($_POST["delivery_date"]);
					$device_post_id	= empty($_POST["device_post_id"])? "" : sanitize_text_field($_POST["device_post_id"]);
					$device_id 		= empty($_POST["devideID"])? "" : sanitize_text_field($_POST["devideID"]);
					

					$order_status 	= "new";
					$customer_id	= $user_id;

					//Let's now prepare our WP Insert post.
					$post_data = array(
						'post_status'   => 'publish',
						'post_type' 	=> wcrb_return_booking_post_type(),
					);
					
					if ( post_exists( $case_number ) == 0 ) {
						$post_id = wp_insert_post( $post_data );
						
						update_post_meta($post_id, '_case_number', $case_number);
						update_post_meta($post_id, '_customer', $customer_id);
						update_post_meta($post_id, '_case_detail', $job_details);
						update_post_meta($post_id, '_wc_order_status', $order_status);
						update_post_meta($post_id, '_delivery_date', $delivery_date);
						update_post_meta($post_id, '_device_post_id', $device_post_id);
						update_post_meta($post_id, '_device_id', $device_id);

						if(isset($case_number)) {
							$title = $case_number;
							$where = array('ID' => $post_id );
							$wpdb->update( $wpdb->posts, array( 'post_title' => $title ), $where );
						}
						$message = esc_html__("A new case have been registered with Case# ".$case_number.".", "computer-repair-shop");
			
					} else {
						$message = esc_html__("Your case is already registered with us.", "computer-repair-shop");
					}
				}

				$values['message'] = $message;
				
				if($error == 0) {
					$values['success'] = "YES";
					$values['reset_select2'] = "YES";
				}

			endif;

			wp_send_json($values);
			wp_die();
		}
		add_action( 'wp_ajax_wc_cr_create_new_job', 'wc_cr_create_new_job' );
		add_action( 'wp_ajax_nopriv_wc_cr_create_new_job', 'wc_cr_create_new_job' );
	endif;