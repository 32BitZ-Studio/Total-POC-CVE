<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit; // Exit if accessed directly
}
/***
 * Request Quote Shortcode
 *
 * Generates a Form which requests Quote
 * Quote is added into Jobs with Status Quote.
 *
 * @package computer repair shop
 */

if ( ! function_exists( 'wc_cr_my_account' ) ) :
	/**
	 * Function wc_cr_my_account
	 * lists my account data
	 */
	function wc_cr_my_account() {
		$object_id = get_queried_object_id();

		wp_enqueue_script("foundation-js");
		wp_enqueue_script("wc-cr-js");
		wp_enqueue_script("select2");
		wp_enqueue_script("intl-tel-input");
		wp_enqueue_style("intl-tel-input");

		add_action( 'wp_print_footer_scripts', 'wcrb_intl_tel_input_script' );

		$content = '';
		if ( ! is_user_logged_in() ) :
			// Content for non logged in users.
			$content .= '<!-- Content section -->';
			$content .= '<div class="content-area cr_content_area">';
			$content .= '<div class="grid-container grid-x grid-margin-x">';

			$wc_rb_turn_registration_on = get_option( 'wc_rb_turn_registration_on' );
			$columns_class 				= ( $wc_rb_turn_registration_on == 'on' ) ? 'large-6 medium-6 small-12 cell' : 'large-12 medium-6 small-12 cell';

			if ( $wc_rb_turn_registration_on == 'on' ) {
				$content .= '<div class="' . esc_attr( $columns_class ) . '">';
				$content .= '<div class="have-meta no_thumb blog-post blog post-1 post type-post status-publish format-standard hentry category-uncategorized">';

				$content .= '<div class="blog-text">';
				$content .= '<h3>';
				$content .= esc_html__( 'Register', 'computer-repair-shop' );
				$content .= '</h3>';
				$content .= '<div class="post-content blog-page-content">';
				
				$content .= '<form data-async data-abide class="needs-validation" novalidate method="post" data-success-class=".resgister_account_form_message">';

				$content .= '<div class="grid-x grid-margin-x">';
				$content .= '<div class="medium-6 cell">';
				$content .= '<label>'.esc_html__("First Name", "computer-repair-shop")." (*)";
				$content .= '<input type="text" name="firstName" value="" id="firstName" required class="form-control login-field" value="" placeholder="">';
				$content .= '</label>';
				$content .= '</div><!-- column Ends /-->';

				$content .= '<div class="medium-6 cell">';
				$content .= '<label>'.esc_html__("Last Name", "computer-repair-shop")." (*)";
				$content .= '<input type="text" name="lastName" value="" id="lastName" required class="form-control login-field" placeholder="">';
				$content .= '</label>';
				$content .= '</div><!-- column Ends /-->';  
				$content .= '</div><!-- grid-x ends /-->';
    
				$content .= '<div class="grid-x grid-margin-x">';
				$content .= '<div class="medium-6 cell">';
				$content .= '<label>'.esc_html__( "Email", "computer-repair-shop" )." (*)";
				$content .= '<input type="email" name="userEmail" id="userEmail" value="" required class="form-control login-field" placeholder="">';
				$content .= '</label>';
				$content .= '</div><!-- column Ends /-->';

				$content .= '<div class="medium-6 cell">';
				$content .= '<label>'.esc_html__("Phone number", "computer-repair-shop");
				$content .= '<input type="text" name="phoneNumber_ol" value="" class="form-control login-field" placeholder="">';
				$content .= '</label>';
				$content .= '</div><!-- column Ends /-->';  
				$content .= '</div><!-- grid-x ends /-->';

				$content .= '<div class="grid-x grid-margin-x">';
				$content .= '<div class="medium-6 cell">';
				$content .= '<label>'.esc_html__("Company", "computer-repair-shop");
				$content .= '<input type="text" name="userCompany" value="" class="form-control login-field" placeholder="">';
				$content .= '</label>';
				$content .= '</div><!-- column Ends /-->';

				$content .= '<div class="medium-6 cell">';
				$content .= '<label>'.esc_html__("Address", "computer-repair-shop");
				$content .= '<input type="text" name="userAddress" value="" class="form-control login-field" placeholder="">';
				$content .= '</label>';
				$content .= '</div><!-- column Ends /-->';  
				$content .= '</div><!-- grid-x ends /-->';
    
				$content .= '<div class="grid-x grid-margin-x">';
				$content .= '<div class="medium-6 cell">';
				$content .= '<label>'.esc_html__("Postal Code", "computer-repair-shop");
				$content .= '<input type="text" name="postalCode" value="" class="form-control login-field" placeholder="">';
				$content .= '</label>';
				$content .= '</div><!-- column Ends /-->';

				$content .= '<div class="medium-6 cell">';
				$content .= '<label>'.esc_html__("City", "computer-repair-shop");
				$content .= '<input type="text" name="userCity" value="" class="form-control login-field" placeholder="">';
				$content .= '</label>';
				$content .= '</div><!-- column Ends /-->';

				$content .= '<div class="medium-6 cell">';
				$content .= '<label>'.esc_html__("State/Province", "computer-repair-shop");
				$content .= '<input type="text" name="userState" value="" class="form-control login-field" placeholder="">';
				$content .= '</label>';
				$content .= '</div><!-- column Ends /-->';

				$content .= '<div class="medium-6 cell">';
				$content .= '<label>'.esc_html__("State/Province", "computer-repair-shop");
				$content .= '<select name="userCountry" class="form-control">';
				$country = ( get_option( "wc_primary_country" ) ) ? get_option( "wc_primary_country" ) : "";
				$content .= wc_cr_countries_dropdown( $country, 'return' );
				$content .= '</select></label>';
				$content .= '</div><!-- column Ends /-->';
				
				$content .= '</div><!-- grid-x ends /-->';

				if ( defined( 'RB_DIAG_DIESEL' ) ) :
				$content .= '<div class="grid-x grid-margin-x">';
				$content .= '<div class="medium-6 cell">';
				$content .= '<label>'.esc_html__( 'Account Number', 'computer-repair-shop' );
				$content .= '<input type="text" name="accountNumber" value="" class="form-control login-field" placeholder="">';
				$content .= '</label>';
				$content .= '</div><!-- column Ends /-->';
				$content .= '</div><!-- grid-x ends /-->';
				endif;

				$content .= '<input type="hidden" name="form_action" value="wcrb_register_account" />';
				$content .=  wp_nonce_field( 'wcrb_register_account_nonce', 'wcrb_register_account_nonce_post', true, false);
				$content .= '<input type="submit" class="button button-primary primary" value="' . esc_html__( 'Register Account!', "computer-repair-shop").'" />';

				$content .= '<div class="resgister_account_form_message"></div>';
			
				$content .= '</form>';
				$content .= '</div><!-- Post Content /-->';	
				$content .= '</div></div><!-- Blog Post /--></div><!-- Column /-->';
			}

			$content .= '<div class="' . esc_attr( $columns_class ) . '">';
			$content .= '<div class="have-meta no_thumb blog-post blog post-1 post type-post status-publish format-standard hentry category-uncategorized">';

			$content .= '<div class="blog-text">';
			$content .= '<h3>';
			$content .= esc_html__( 'Login', 'computer-repair-shop' );
			$content .= '</h3>';
			$content .= '<div class="post-content blog-page-content">';
			$content .= wp_login_form( array( 'echo' => false ) );
			$content .= '<a href="' . esc_url( wp_lostpassword_url( get_permalink() ) ) . '">' . esc_html__( 'Lost Password?', 'computer-repair-shop' ) . '</a>';
			$content .= '</div><!-- Post Content /-->';
			$content .= '</div>';
			$content .= '</div><!-- Blog Post /-->
							</div><!-- Column /-->
							<div class="clearfix"></div>    
						</div><!-- Row / Posts Container /-->
					</div>
			<!-- Content Section Ends /-->';
		else :
			$current_user = wp_get_current_user();

			if ( in_array( 'technician', (array) $current_user->roles ) ) {
				//Technician
				$content = rb_return_my_account_dashboard();
			} elseif ( in_array( 'store_manager', (array) $current_user->roles ) ) {
				//Manager
				$content = rb_return_my_account_dashboard();
			} elseif ( in_array( 'administrator', (array) $current_user->roles ) ) {
				//admin
				$content = rb_return_my_account_dashboard();
			} else {
				//Customer and all other
				$content = rb_return_my_account_dashboard();
			}
		endif;

		return $content;
	}// End wc_list_services.
	add_shortcode( 'wc_cr_my_account', 'wc_cr_my_account' );
endif;

if ( ! function_exists( 'rb_return_my_account_dashboard' ) ) :
function rb_return_my_account_dashboard() {
	$content = '<div class="main-container computer-repair wcrbfd">';
	$content .= '<div class="team-wrap grid-x" data-equalizer data-equalize-on="medium">
					<div class="cell medium-2 thebluebg sidebarmenu">
					<div class="the-brand-logo">';
	$logoUrl = wc_rb_return_logo_url_with_img( 'shoplogo' );

	$content .= ( ! empty( $logoUrl ) ) ? $logoUrl : '<img src="' . esc_url( WC_COMPUTER_REPAIR_DIR_URL . '/assets/admin/images/repair-buddy-logo.png' ) . '" alt="RepairBuddy CRM Logo" />';
	
	$content .= '</div>';
	$content .= '<ul class="vertical tabs thebluebg" data-tabs="82ulyt-tabs" id="example-tabs">';
			
	$rb_ma_menu_items = apply_filters( 'wc_rb_myaccount_tab_menu_item', 'admin' );
	$content .= $rb_ma_menu_items;

	$content .= '</ul></div>';
		
	$content .= '<div class="cell medium-10 thewhitebg contentsideb">';
	$content .= '<div class="tabs-content vertical" data-tabs-content="example-tabs">';
			
	$cl_dashboard = ( isset( $_GET['job_status'] ) && ! empty( $_GET['job_status'] ) ) ? '' : ' is-active';
	$cl_dashboard = ( isset( $_GET['book_device'] ) && ! empty( $_GET['book_device'] ) ) ? '' : $cl_dashboard;
	if ( isset( $_GET['print'] ) && ! empty( $_GET['print'] ) ) {
		$cl_dashboard = '';
	}

	$content .= '<div class="tabs-panel team-wrap ' . esc_attr( $cl_dashboard ) . '" id="main_page" role="tabpanel" aria-hidden="true" aria-labelledby="main_page-label">';
	$MAINPAGEOUTPUT = new WCRB_DASHBOARD;

	$content .= $MAINPAGEOUTPUT->output_main_page( 'front' );
	$content .= '</div>';		

	$rb_ma_page_items = apply_filters( 'wc_rb_myaccount_tab_body', 'admin' );
	$content .= $rb_ma_page_items;

	$content .= '<!-- Main page ends /--></div><!-- tabs content ends --></div></div></div>';

	return $content;
}
endif;

if ( ! function_exists( 'wcrb_register_account' ) ) :
	function wcrb_register_account() {
		if (!isset( $_POST['wcrb_register_account_nonce_post'] ) 
			|| ! wp_verify_nonce( $_POST['wcrb_register_account_nonce_post'], 'wcrb_register_account_nonce' ) ) :
				$values['message'] = esc_html__( "Something is wrong with your submission!", "computer-repair-shop");
				$values['success'] = "NO";
		else:
			//New User Informaiton
            $first_name 	= ( isset( $_POST["firstName"] ) && ! empty( $_POST["firstName"] ) ) ? sanitize_text_field( $_POST["firstName"] ) : '';
            $last_name 		= ( isset( $_POST["lastName"] ) && ! empty( $_POST["lastName"] ) ) ?  sanitize_text_field($_POST["lastName"]) : '';
            $user_email 	= ( isset( $_POST["userEmail"] ) && ! empty( $_POST["userEmail"] ) ) ?  sanitize_email($_POST["userEmail"]) : '';
            $username 		= ( isset( $_POST["userEmail"] ) && ! empty( $_POST["userEmail"] ) ) ?  sanitize_email($_POST["userEmail"]) : '';
            $phone_number 	= ( isset( $_POST["phoneNumber"] ) && ! empty( $_POST["phoneNumber"] ) ) ?  sanitize_text_field($_POST["phoneNumber"]) : '';
            $user_city 		= ( isset( $_POST["userCity"] ) && ! empty( $_POST["userCity"] ) ) ?  sanitize_text_field($_POST["userCity"]) : '';
			$userState 		= ( isset( $_POST["userState"] ) && ! empty( $_POST["userState"] ) ) ?  sanitize_text_field($_POST["userState"]) : '';
			$userCountry 	= ( isset( $_POST["userCountry"] ) && ! empty( $_POST["userCountry"] ) ) ?  sanitize_text_field($_POST["userCountry"]) : '';
            $postal_code 	= ( isset( $_POST["postalCode"] ) && ! empty( $_POST["postalCode"] ) ) ?  sanitize_text_field($_POST["postalCode"]) : '';
            $user_company 	= ( isset( $_POST["userCompany"] ) && ! empty( $_POST["userCompany"] ) ) ?  sanitize_text_field($_POST["userCompany"]) : '';
            $user_address 	= ( isset( $_POST["userAddress"] ) && ! empty( $_POST["userAddress"] ) ) ?  sanitize_text_field($_POST["userAddress"]) : '';
			$accountNumber	= ( isset( $_POST["accountNumber"] ) && ! empty( $_POST["accountNumber"] ) ) ? sanitize_text_field( $_POST["accountNumber"] ) : '';
            
            $user_role = "customer";
			$message   = '';
            if( empty( $user_email ) ) {
                $error = 1;
                $message = esc_html__( "Email is not valid.", "computer-repair-shop");	
            } elseif ( empty( $first_name ) ) {
                $error = 1;
                $message = esc_html__("First name required.", "computer-repair-shop");
            } elseif ( ! empty( $user_email ) && ! is_email( $user_email ) ) {
                $error = 1;
                $message = esc_html__("Email is not valid", "computer-repair-shop");
            } elseif( ! empty( $username ) && ! validate_username( $username ) ) {
				$error = 1;
				$message = esc_html__("Not a valid username", "computer-repair-shop");
			} elseif( ! empty( $username ) && username_exists( $username ) ) {
				$error = 1;
				$message = esc_html__( "A user already exists with same email please try to reset password.", "computer-repair-shop" );
			} elseif ( email_exists( $user_email ) ) {
				$error = 1;
				$message = esc_html__("A user already exists with same email please try to reset password.", "computer-repair-shop");
			}

            $user = get_user_by( 'login', $user_email );
            $theUserId = '';
            if( $user ) {
                $theUserId = $user->ID;
            } else {
                $user = get_user_by( 'email', $user_email );
                $theUserId = $user->ID;
            }
			if ( ! empty( $theUserId ) ) {
				$error = 1;
                $message = esc_html__("A user already exists with same email please try to reset password.", "computer-repair-shop");
			}

            if ( empty( $theUserId ) ) {
                //Let's add user and get ID
                $password 	= wp_generate_password( 8, false );
					
                if($error == 0) :
                    if( ! empty ( $username ) && ! empty ( $user_email ) ) {
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
                        $register_user = wp_insert_user( $userdata );
                    
                        //If Not exists
                        if ( ! is_wp_error( $register_user ) ) {
                            //Use user instead of both in case sending notification to only user
                            wp_new_user_notification( $register_user, null, 'both' );
                            $message = esc_html__("User account is created logins sent to email.", "computer-repair-shop")." ".$user_email;
                            $theUserId = $register_user;
							global $WCRB_EMAILS;
							$WCRB_EMAILS->send_user_logins_after_register( $theUserId, $password );
                        } else {
                            $error = 1;
                            $message = '<strong>' . $register_user->get_error_message() . '</strong>';
                        }
						if ( ! empty( $theUserId ) ) {
							update_user_meta( $theUserId, 'customer_account_number', $accountNumber );
							update_user_meta( $theUserId, 'billing_first_name', $first_name );
							update_user_meta( $theUserId, 'billing_last_name', $last_name );
							update_user_meta( $theUserId, 'billing_company', $user_company );
							update_user_meta( $theUserId, 'billing_address_1', $user_address );
							update_user_meta( $theUserId, 'billing_city', $user_city );
							update_user_meta( $theUserId, 'billing_postcode', $postal_code );
							update_user_meta( $theUserId, 'billing_state', $userState );
							update_user_meta( $theUserId, 'billing_phone', $phone_number );
							update_user_meta( $theUserId, 'billing_country', $userCountry );
							
							update_user_meta( $theUserId, 'billing_email', $user_email );

							update_user_meta( $theUserId, 'shipping_first_name', $first_name );
							update_user_meta( $theUserId, 'shipping_last_name', $last_name );
							update_user_meta( $theUserId, 'shipping_company', $user_company );
							//update_user_meta( $theUserId, 'shipping_tax', $billing_tax );
							update_user_meta( $theUserId, 'shipping_address_1', $user_address );
							update_user_meta( $theUserId, 'shipping_city', $user_city );
							update_user_meta( $theUserId, 'shipping_postcode', $postal_code );
							update_user_meta( $theUserId, 'shipping_state', $userState );
							update_user_meta( $theUserId, 'shipping_country', $userCountry );
							update_user_meta( $theUserId, 'shipping_phone', $phone_number );

							$values['success'] = 'YES';
						}
                    }
                endif; //Add user ends.
            }//If Empty user adds
            $values['message'] = $message;
		endif;

		wp_send_json( $values );
		wp_die();
	}
	add_action( 'wp_ajax_wcrb_register_account', 'wcrb_register_account' );
	add_action( 'wp_ajax_nopriv_wcrb_register_account', 'wcrb_register_account' );
endif;