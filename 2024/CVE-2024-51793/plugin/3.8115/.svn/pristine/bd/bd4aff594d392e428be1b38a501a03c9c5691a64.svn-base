<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit; // Exit if accessed directly
}
/**
 * Short Code
 * WC Book my Service
 *
 * @Since : 3.79
 * @package : RepairBuddy CRM
 */

if ( ! function_exists( 'wc_book_my_service' ) ) :
    /**
     * Function Shortcode
     * To add Booking 
     * Page
     */
    function wc_book_my_service() {
        wp_enqueue_script("foundation-js");
        //wp_enqueue_script("wc-cr-js");
        //wp_enqueue_script("select2");
        wp_enqueue_style("intl-tel-input");
        wp_enqueue_script("intl-tel-input");

        add_action( 'wp_print_footer_scripts', 'wcrb_intl_tel_input_script' );

        $defaultBrand = get_option( 'wc_booking_default_brand' );

        $content = '';
        $content .= '<div class="wc_rb_mb_wrap"><form method="post" action="" name="wc_rb_device_form">';

        //The Manufactures.
        $wc_device_brand_label = ( empty( get_option( 'wc_device_brand_label' ) ) ) ? esc_html__( 'Manufacture', 'computer-repair-shop' ) : get_option( 'wc_device_brand_label' );
        $content .= '<div class="wc_rb_mb_section wc_rb_mb_manufactures">';
        $content .= '<div class="wc_rb_mb_head"><h2>' . esc_html__( 'Select ', 'computer-repair-shop' ) . esc_html( $wc_device_brand_label ) . '</h2></div>';
        
        $content .= '<div class="wc_rb_mb_body">';
        $content .=  wp_nonce_field( 'wc_computer_repair_mb_nonce', 'wc_rb_mb_device_submit', true, false);
        
        $defaultBrand = ( $defaultBrand == 'All' || empty( $defaultBrand ) ) ? '' : $defaultBrand;

        $content .= '<input type="hidden" name="wcrb_thebrand_id" id="wcrb_thebrand_id" value="' . esc_attr( $defaultBrand ) . '">';
        
        $wcrb_type = 'rep_devices';
        $wcrb_tax = 'device_brand';
        if ( wcrb_use_woo_as_devices() == 'YES' ) {
            $wcrb_type = 'product';
            $wcrb_tax = 'product_cat';
        }
        $taxonomies = get_terms( array(
            'taxonomy'   => $wcrb_tax,
            'hide_empty' => true
        ) );
         
        if ( ! empty ( $taxonomies ) ) :
            $output = '<ul class="manufacture_list">';
            foreach( $taxonomies as $category ) {
                $selected = ( $category->term_id == $defaultBrand ) ? 'selected' : '';
                $output .= '<li><a class="' . esc_attr( $selected ) . '" href="#" dt_brand_device="thebrand" dt_brand_id="'. esc_attr( $category->term_id ) .'" title="' . $category->name . '">';
                
                $image_id = esc_html( get_term_meta( $category->term_id, 'image_id', true ) );
				if ( ! empty( $image_id ) ) :
                    $output .= wp_get_attachment_image ( $image_id, 'full' );
                else: 
                    $output .= '<h3>' . esc_html( $category->name ) . '</h3>';
                endif;
                $output .= '</a></li>';
            }

            $wcrb_turn_off_other_device_brands = get_option( 'wcrb_turn_off_other_device_brands' );
            if ( $wcrb_turn_off_other_device_brands != 'on' ) {
                $output .= '<li class="wcrb-other-color"><a class="' . esc_attr( $selected ) . '" href="#" dt_brand_device="thebrand" dt_brand_id="brand_other" title="' . esc_html__( 'Other', 'computer-repair-shop' ) . '">';
                $output .= '<h3>' . esc_html__( 'Other', 'computer-repair-shop' ) . '</h3></a></li>';
            }

            $output.='</ul>';
            $content .= $output;
        endif;

        $content .= '</div><!-- body ends /-->';
        $content .= '</div>';


        //The Devide.
        $wc_device_label = ( empty( get_option( 'wc_device_label' ) ) ) ? esc_html__( 'Device', 'computer-repair-shop' ) : get_option( 'wc_device_label' );
        $content .= '<div class="wc_rb_mb_section wc_rb_mb_device">';

        $content .= '<input name="add_more_device_label" type="hidden" value="' . esc_html__( 'Add another', 'computer-repair-shop' ) . ' ' . esc_html( $wc_device_label ) . '" />';
        $content .= '<input name="select_service_label" type="hidden" value="' . esc_html__( 'Select service', 'computer-repair-shop' ) . '" />';
        $content .= '<input name="enter_device_label_missing_msg" type="hidden" value="' . esc_html__( 'Please enter the name of device or select another device, and remove devices not needed.', 'computer-repair-shop' ) . '" />';

        $content .= '<div class="wc_rb_mb_head"><h2>' . esc_html__( 'Select ', 'computer-repair-shop' ) . esc_html( $wc_device_label ) . '</h2></div>';
        
        $content .= '<input type="hidden" name="wcrb_thedevice_id" id="wcrb_thedevice_id" value="">';

        $content .= '<div class="wc_rb_mb_body text-center device-message">';
        $content .= esc_html__( 'Please select a manufacture to list devices', 'computer-repair-shop' );
        $content .= '<br>' . esc_html__( 'If you have different device or some other query please contact us.', 'computer-repair-shop' );

        $content .= '</div><!-- body ends /-->';

        $content .= '<div class="wc_rb_mb_body selected_devices">';
        $content .= '<div class="selected_devices_message"></div>';
        $content .= '</div><!-- Selected Devices /-->';
        $content .= '</div>';

        //The service.
        $content .= '<div class="wcrb_services_holder"><div class="wcrb_services_holder_message"></div></div>';

        //The Customer Information.
        $content .= '<div class="wc_rb_mb_section wc_rb_mb_customer displayNone">';
        if ( is_single() && 'rep_services' != get_post_type() ) {
            $object_id = get_queried_object_id();
            $content .= '<input type="hidden" id="loadDirectCustomer" name="wc_rb_select_service" value="' . $object_id . '">';
        }
        $content .= '<div class="wc_rb_mb_head"><h2>' . esc_html__( 'Customer Information', 'computer-repair-shop' ) . '</h2></div>';
        
        $content .= '<div class="wc_rb_mb_body final_customer_message grid-container fluid">';

        $user = '';
        $customer_id = '';
        if ( is_user_logged_in() ) {
            $customer_id = get_current_user_id();
            $user = get_user_by( 'id', $customer_id );
        }
        $user_email  =  ( ! empty( $user ) ) ? $user->user_email : '';
        $first_name  =  ( ! empty( $user ) ) ? $user->first_name : '';
        $last_name   =  ( ! empty( $user ) ) ? $user->last_name : '';

        $customer_phone  	= ( ! empty( $customer_id )) ? get_user_meta( $customer_id, 'billing_phone', true) : '';
        $customer_city 		= ( ! empty( $customer_id )) ? get_user_meta( $customer_id, 'billing_city', true) : '';
        $customer_zip		= ( ! empty( $customer_id )) ? get_user_meta( $customer_id, 'billing_postcode', true) : '';
        $customer_address 	= ( ! empty( $customer_id )) ? get_user_meta( $customer_id, 'billing_address_1', true) : '';
        $customer_company	= ( ! empty( $customer_id )) ? get_user_meta( $customer_id, 'billing_company', true) : '';
        $billing_tax	    = ( ! empty( $customer_id )) ? get_user_meta( $customer_id, 'billing_tax', true) : '';

        $content .= '<div class="grid-x grid-margin-x">';
        $content .= '<div class="medium-6 cell">';
        
        $content .= '<label>'.esc_html__("First Name", "computer-repair-shop")." (*)";
        $content .= '<input type="text" name="firstName" value="' . esc_html( $first_name ) . '" id="firstName" required class="form-control login-field" value="" placeholder="">';
        $content .= '</label>';
         
        $content .= '</div><!-- column Ends /-->';
        $content .= '<div class="medium-6 cell">';
    
        $content .= '<label>'.esc_html__("Last Name", "computer-repair-shop")." (*)";
        $content .= '<input type="text" name="lastName" value="' . esc_html( $last_name ) . '" id="lastName" required class="form-control login-field" placeholder="">';
        $content .= '</label>';
         
        $content .= '</div><!-- column Ends /-->';  
        $content .= '</div><!-- grid-x ends /-->';
    
        $content .= '<div class="grid-x grid-margin-x">';
        $content .= '<div class="medium-6 cell">';
    
        $content .= '<label>'.esc_html__("Email", "computer-repair-shop")." (*)";
        $content .= '<input type="email" name="userEmail" id="userEmail" value="' .esc_html( $user_email ). '" required class="form-control login-field" placeholder="">';
        $content .= '</label>';
         
        $content .= '</div><!-- column Ends /-->';
        $content .= '<div class="medium-6 cell">';
    
        $content .= '<label>'.esc_html__("Phone number", "computer-repair-shop");
        $content .= '<input type="text" name="phoneNumber_ol" value="' . esc_html( $customer_phone ) . '" class="form-control login-field" placeholder="">';
        $content .= '</label>';
         
        $content .= '</div><!-- column Ends /-->';  
        $content .= '</div><!-- grid-x ends /-->';
    
        $content .= '<div class="grid-x grid-margin-x">';
        $content .= '<div class="medium-6 cell">';
    
        $content .= '<label>'.esc_html__("City", "computer-repair-shop");
        $content .= '<input type="text" name="userCity" value="' . esc_html( $customer_city ) . '" class="form-control login-field" placeholder="">';
        $content .= '</label>';
         
        $content .= '</div><!-- column Ends /-->';
        $content .= '<div class="medium-6 cell">';

        $content .= '<label>'.esc_html__("Postal Code", "computer-repair-shop");
        $content .= '<input type="text" name="postalCode" value="' . esc_html( $customer_zip ) . '" class="form-control login-field" placeholder="">';
        $content .= '</label>';
         
        $content .= '</div><!-- column Ends /-->';  
        $content .= '</div><!-- grid-x ends /-->';

        $content .= '<div class="grid-x grid-margin-x">';
        $content .= '<div class="medium-6 cell">';

        $content .= '<label>'.esc_html__("Company", "computer-repair-shop");
        $content .= '<input type="text" name="userCompany" value="' . esc_html( $customer_company ) . '" class="form-control login-field" placeholder="">';
        $content .= '</label>';
        
        $content .= '</div><!-- column Ends /-->';

        $content .= '<div class="medium-6 cell">';

        $content .= '<label>'.esc_html__("Tax ID", "computer-repair-shop");
        $content .= '<input type="text" name="billing_tax" value="' . esc_html( $billing_tax ) . '" class="form-control login-field" placeholder="">';
        $content .= '</label>';
        
        $content .= '</div><!-- column Ends /-->';

        $content .= '<div class="medium-12 cell">';

        $content .= '<label>'.esc_html__("Address", "computer-repair-shop");
        $content .= '<input type="text" name="userAddress" value="' . esc_html( $customer_address ) . '" class="form-control login-field" placeholder="">';
        $content .= '</label>';
        
        $content .= '</div><!-- column Ends /-->';  
        $content .= '</div><!-- grid-x ends /-->';
    
        $content .= '<div class="grid-x grid-margin-x">';
        $content .= '<div class="medium-12 cell">';

        $content .= '<label>'.esc_html__("Job Details", "computer-repair-shop")." (*)";
        $content .= '<textarea name="jobDetails" required class="form-control login-field" placeholder=""></textarea>';
        $content .= '</label>';
        $content .= '<input type="hidden" name="form_type" value="wc_rb_booking_form" />';

        $content .= '</div><!-- column Ends /-->';  
        $content .= '</div><!-- grid-x ends /-->';

        $content .= apply_filters( 'rb_ms_store_booking_options', '' );

        $content .= '<div class="jobAttachments displayNone" id="jobAttachments"></div>';
        $content .= '<label for="reciepetAttachment" class="button button-primary">' . esc_html__( 'Attach Files', 'computer-repair-shop' ) . '</label>
                    <input type="file" id="reciepetAttachment" name="reciepetAttachment" class="show-for-sr">';

        $content .= wc_rb_gdpr_acceptance_link_generate();

        $content .= '<input type="submit" class="button button-primary primary" value="' . esc_html__( 'Submit Request!', "computer-repair-shop").'" />';

        $content .= '<div class="booking_message"></div>';
        $content .= '</div><!-- body ends /-->';
        $content .= '</div>';

        $content .= '</div><!-- wc_rb_mb_wrap Ends /--></form>';

        return $content;
    } // wc_list_services
    add_shortcode ( 'wc_book_my_service', 'wc_book_my_service' );
endif;


if( ! function_exists( 'wc_rb_mb_update_devices' ) ):
    function wc_rb_mb_update_devices() { 
        $values = array();
        if (!isset( $_POST['theBrandNonce'] ) 
            || ! wp_verify_nonce( $_POST['theBrandNonce'], 'wc_computer_repair_mb_nonce' )) :
                $values['message'] = esc_html__("Something is wrong with your submission!", "computer-repair-shop");
                $values['success'] = "YES";
        else:
            //Register User
            $theBrandId = sanitize_text_field( $_POST['theBrandId'] );
            $theTypeId = '';

            $dt_device_warranty = 'NO';
            if ( isset( $_POST['typeWarranty'] ) && ! empty( $_POST['typeWarranty'] ) ) {
                $dt_device_warranty = ( $_POST['typeWarranty'] == 'YES' ) ? 'YES' : 'NO';
            }

            $wcrb_type = 'rep_devices';
			$wcrb_tax = 'device_brand';
			if ( wcrb_use_woo_as_devices() == 'YES' ) {
				$wcrb_type = 'product';
				$wcrb_tax = 'product_cat';
			}
            $grouped = 'NO';
            if ( isset( $_POST['theTypeId'] ) && ! empty( $_POST['theTypeId'] ) && $wcrb_type != 'product' ) {
                $theTypeId = sanitize_text_field( $_POST['theTypeId'] );

                $query_devices = array(
                    'posts_per_page' => -1,
                    'post_type'      => $wcrb_type,
                    'orderby'       => 'title',
                    'order'         => 'ASC',
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
                $grouped = 'YES';
            } else {
                $query_devices = array(
                    'posts_per_page' => -1,
                    'post_type'      => $wcrb_type,
                    'orderby'       => 'title',
                    'order'         => 'ASC',
                    'tax_query'      => array(
                        array (
                            'taxonomy'  => $wcrb_tax,
                            'field'     => 'term_id',
                            'terms'     => $theBrandId,
                        ),
                    ),
                );
            }
            $wc_device_query = new WP_Query( $query_devices );

            if( $wc_device_query->have_posts() ) : 
                $post_output = '<ul class="manufacture_list">';
                while( $wc_device_query->have_posts() ): 
                    $wc_device_query->the_post();
                    $device_id = get_the_ID();
                    if ( $grouped == 'NO' ) {
                        $post_output .=  '<li><a href="" dt_device_id="' . $device_id . '">';
                    } else {
                        $dt_warranty_label = ( $dt_device_warranty == 'YES' ) ? ' dt_warranty_device=' . $device_id : 'dt_device_g_id=' . $device_id;
                        $post_output .=  '<li><a ' . esc_attr( $dt_warranty_label ) . ' href="">';
                    }
                    $feat_image =   wp_get_attachment_image_src( get_post_thumbnail_id( $device_id ), 'thumbnail');
                    if ( ! empty( $feat_image ) ) {
                        $post_output .= '<img src="' . $feat_image[0] . '">';
                    }
                    $post_output .=  get_the_title() . '</a></li>';
                endwhile;
                $wcrb_turn_off_other_device_brands = get_option( 'wcrb_turn_off_other_device_brands' );
                if ( $wcrb_turn_off_other_device_brands != 'on' ) {
                    $post_output .= '<li class="wcrb-other-color">';
                    if ( $grouped == 'NO' ) {
                        $post_output .= '<a href="#" dt_device_id="load_other_device" dt_device_brand_id="'. esc_attr( $theBrandId ) .'" dt_device_type_id="'. esc_attr( $theTypeId ) .'" title="' . esc_html__( 'Other', 'computer-repair-shop' ) . '">';
                    } else {
                        $post_output .= '<a href="#" dt_device_g_id="load_other_device" dt_device_brand_id="'. esc_attr( $theBrandId ) .'" dt_device_type_id="'. esc_attr( $theTypeId ) .'" title="' . esc_html__( 'Other', 'computer-repair-shop' ) . '">';
                    }
                    $post_output .= esc_html__( 'Other', 'computer-repair-shop' ) . '</a></li>';
                }
                $post_output .= '</ul>';

                $values['message'] = $post_output;
            else:
                $values['message'] = esc_html__("We haven't found any device with your given brand! please contact us.", "computer-repair-shop");
                if ( isset( $_POST['theBrandId'] ) && $_POST['theBrandId'] == 'brand_other' ) {
                    $values['message'] = 'load_other_device';
                }
            endif;
				 
            wp_reset_postdata();
        endif;

        wp_send_json($values);
        wp_die();
    }
    add_action( 'wp_ajax_wc_rb_mb_update_devices', 'wc_rb_mb_update_devices' );
    add_action( 'wp_ajax_nopriv_wc_rb_mb_update_devices', 'wc_rb_mb_update_devices' );
endif;

if( ! function_exists( 'wc_rb_submit_booking_form' ) ):
    function wc_rb_submit_booking_form() { 
        global $wpdb, $WCRB_EMAILS, $WCRB_DEVICE_SERVICES;

        $computer_repair_items 		= $wpdb->prefix.'wc_cr_order_items';
        $computer_repair_items_meta = $wpdb->prefix.'wc_cr_order_itemmeta';

        if (!isset( $_POST['wc_rb_mb_device_submit'] ) 
            || ! wp_verify_nonce( $_POST['wc_rb_mb_device_submit'], 'wc_computer_repair_mb_nonce' )) :
                $values['message'] = esc_html__("Something is wrong with your submission!", "computer-repair-shop");
                $values['success'] = "YES";
        else:
            //Create Customer and Get its User ID
            $error = 0;
            if ( ! isset ( $_POST['form_type'] ) || $_POST['form_type'] != 'wc_rb_booking_form' ) {
                $error = 1;
                $message = esc_html__( 'Invalid or Unkown form', 'computer-repair-shop' );
            }
            //New User Informaiton
            $first_name 	= ( isset( $_POST["firstName"] ) && ! empty( $_POST["firstName"] ) ) ? sanitize_text_field( $_POST["firstName"] ) : '';
            $last_name 		= ( isset( $_POST["lastName"] ) && ! empty( $_POST["lastName"] ) ) ?  sanitize_text_field($_POST["lastName"]) : '';
            $user_email 	= ( isset( $_POST["userEmail"] ) && ! empty( $_POST["userEmail"] ) ) ?  sanitize_email($_POST["userEmail"]) : '';
            $username 		= ( isset( $_POST["userEmail"] ) && ! empty( $_POST["userEmail"] ) ) ?  sanitize_email($_POST["userEmail"]) : '';
            $phone_number 	= ( isset( $_POST["phoneNumber"] ) && ! empty( $_POST["phoneNumber"] ) ) ?  sanitize_text_field($_POST["phoneNumber"]) : '';
            $billing_tax 	= ( isset( $_POST["billing_tax"] ) && ! empty( $_POST["billing_tax"] ) ) ?  sanitize_text_field($_POST["billing_tax"]) : '';
            $user_city 		= ( isset( $_POST["userCity"] ) && ! empty( $_POST["userCity"] ) ) ?  sanitize_text_field($_POST["userCity"]) : '';
            $postal_code 	= ( isset( $_POST["postalCode"] ) && ! empty( $_POST["postalCode"] ) ) ?  sanitize_text_field($_POST["postalCode"]) : '';
            $user_company 	= ( isset( $_POST["userCompany"] ) && ! empty( $_POST["userCompany"] ) ) ?  sanitize_text_field($_POST["userCompany"]) : '';
            $user_address 	= ( isset( $_POST["userAddress"] ) && ! empty( $_POST["userAddress"] ) ) ?  sanitize_text_field($_POST["userAddress"]) : '';
            $job_details 	= ( isset( $_POST["jobDetails"] ) && ! empty( $_POST["jobDetails"] ) ) ?  sanitize_textarea_field($_POST["jobDetails"]) : '';
            $store_exists   = ( isset( $_POST["store_exists"] ) && ! empty( $_POST["store_exists"] ) ) ? sanitize_text_field( $_POST["store_exists"] ) : '';
            
            $user_role 		= "customer";

            if( empty( $user_email ) ) {
                $error = 1;
                $message = esc_html__("Email is not valid.", "computer-repair-shop");	
            } elseif ( empty( $first_name ) ) {
                $error = 1;
                $message = esc_html__("First name required.", "computer-repair-shop");
            } elseif ( empty( $job_details ) ) {
                $error = 1;
                $message = esc_html__("Please enter job details.", "computer-repair-shop");
            } elseif ( ! empty( $user_email ) && ! is_email( $user_email ) ) {
                $error = 1;
                $message = esc_html__("Email is not valid", "computer-repair-shop");
            } elseif( empty ( $job_details ) ) {
                $error = 1;
                $message = esc_html__("Please enter job details.", "computer-repair-shop");
            } 
            if ( $store_exists == 'yes' ) {
                $wc_rb_ms_select_store   = ( isset( $_POST["wc_rb_ms_select_store"] ) && ! empty( $_POST["wc_rb_ms_select_store"] ) ) ? sanitize_text_field( $_POST["wc_rb_ms_select_store"] ) : '';

                if ( empty( $wc_rb_ms_select_store ) ) {
                    $error = 1;
                    $message = esc_html__( 'Please select store.', 'computer-repair-shop' );
                }
            }

            $user = get_user_by( 'login', $user_email );
            $theUserId = '';
            if( $user ) {
                $theUserId = $user->ID;
            } else {
                $user = get_user_by( 'email', $user_email );
                $theUserId = $user->ID;
            }

            if ( empty( $theUserId ) ) {
                //Let's add user and get ID
                if( ! empty( $username ) && ! validate_username( $username ) ) {
                    $error = 1;
                    $message = esc_html__("Not a valid username", "computer-repair-shop");
                } elseif( ! empty( $username ) && username_exists( $username ) ) {
                    $error = 1;
                    $message = esc_html__("Duplicate User. Please login to submit your quote request.", "computer-repair-shop");
                } elseif ( email_exists( $user_email ) ) {
                    $error = 1;
                    $message = esc_html__("Email already in user. Try resetting password if its your Email. Then login to submit your quote request.", "computer-repair-shop");
                }

                $password 	= wp_generate_password(8, false );
					
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
                    }
                endif; //Add user ends.
            }//If Empty user adds

            if ( ! empty( $theUserId ) ) {
                update_user_meta( $theUserId, 'billing_first_name', $first_name );
				update_user_meta( $theUserId, 'billing_last_name', $last_name );
				update_user_meta( $theUserId, 'billing_company', $user_company );
				update_user_meta( $theUserId, 'billing_address_1', $user_address );
				update_user_meta( $theUserId, 'billing_city', $user_city );
				update_user_meta( $theUserId, 'billing_postcode', $postal_code );
				update_user_meta( $theUserId, 'billing_phone', $phone_number );
                update_user_meta( $theUserId, 'billing_tax', $billing_tax );

                update_user_meta( $theUserId, 'billing_email', $user_email );

				update_user_meta( $theUserId, 'shipping_first_name', $first_name );
				update_user_meta( $theUserId, 'shipping_last_name', $last_name );
				update_user_meta( $theUserId, 'shipping_company', $user_company );
				update_user_meta( $theUserId, 'shipping_tax', $billing_tax );
				update_user_meta( $theUserId, 'shipping_address_1', $user_address );
				update_user_meta( $theUserId, 'shipping_city', $user_city );
				update_user_meta( $theUserId, 'shipping_postcode', $postal_code );
				//update_user_meta( $theUserId, 'shipping_state', $state );
				//update_user_meta( $theUserId, 'shipping_country', $country );
				update_user_meta( $theUserId, 'shipping_phone', $phone_number );
            }
            
            //We have user ID here.
            if ( ! empty ( $theUserId ) && isset( $job_details ) && $error == 0) {
                //Let's insert the Job
                $case_number 	= wc_generate_random_case_num();
                $order_status 	= "quote";
                $customer_id	= $theUserId;

                //Let's now prepare our WP Insert post.
                $post_data = array(
                    'post_status'   => 'draft',
                    'post_type' 	=> wcrb_return_booking_post_type(),
                );
                global $WCRB_MANAGE_DEVICES;
                if ( post_exists( $case_number ) == 0 ) {
                    $post_id = wp_insert_post( $post_data );
                    
                    update_post_meta( $post_id, '_case_number', $case_number );
                    update_post_meta( $post_id, '_customer', $customer_id );
                    update_post_meta( $post_id, '_case_detail', $job_details);
                    update_post_meta( $post_id, '_wc_order_status', $order_status );
                    if ( isset( $wc_rb_ms_select_store ) && ! empty( $wc_rb_ms_select_store ) ) {
                        update_post_meta( $post_id, '_store_id', $wc_rb_ms_select_store );
                    }
                    $order_status = wc_return_status_name( $order_status );		
	                update_post_meta( $post_id, '_wc_order_status_label', $order_status );
                    $insert_user 	= $first_name. ' ' .$last_name ;
                    update_post_meta($post_id, '_customer_label', $insert_user);

                    //OTHEROTHER
                    if ( isset( $_POST['wcrb_thedevice_id'] )  && ! empty ( $_POST['wcrb_thedevice_id'] ) ) :
                        $array_devices = array();
                        $theDeviceID = ( ! empty( $_POST['wcrb_thedevice_id'] ) ) ? sanitize_text_field( $_POST['wcrb_thedevice_id'] ) : '';
                        //You can take input of login, note, and device ID from customer
                        if( isset( $_POST["data_identifier"] ) && !empty( $_POST["data_identifier"] ) ):
                            //Get Services and save to database first.
                            for($i = 0; $i < count( $_POST["data_identifier"] ); $i++) {
                                $device_post_id_h   = ( isset( $_POST["book_deivce_id"][$i] ) || !empty( $_POST["book_deivce_id"][$i] ) ) ? sanitize_text_field($_POST["book_deivce_id"][$i]) : '';
                                $device_serial_id_h = ( isset( $_POST["book_device_serial_num"][$i] ) || !empty( $_POST["book_device_serial_num"][$i] ) ) ? sanitize_text_field($_POST["book_device_serial_num"][$i]) : '';
                                $device_login_h     = ( isset( $_POST["book_device_pincode"][$i] ) || !empty( $_POST["book_device_pincode"][$i] ) ) ? sanitize_text_field($_POST["book_device_pincode"][$i]) : '';
                                $device_note_h      = ( isset( $_POST["book_device_note"][$i] ) || !empty( $_POST["book_device_note"][$i] ) ) ? sanitize_text_field($_POST["book_device_note"][$i]) : '';
                                $device_identifier  = ( isset( $_POST["data_identifier"][$i] ) || !empty( $_POST["data_identifier"][$i] ) ) ? sanitize_text_field($_POST["data_identifier"][$i]) : '';

                                if ( empty( $device_post_id_h ) && isset( $_POST['book_deivce_name_other'][$i] ) && ! empty( $_POST['book_deivce_name_other'][$i] ) && $_POST['book_deivce_name_other'][$i] != 'NOT_TO_USE' ) {
                                    $new_device_name  = ( ! empty( $_POST['book_deivce_name_other'][$i] ) ) ? sanitize_text_field( $_POST['book_deivce_name_other'][$i] ) : '';
                                    $new_device_brand = ( isset( $_POST['book_device_other_brand'][$i] ) && ! empty( $_POST['book_device_other_brand'][$i] ) ) ? sanitize_text_field( $_POST['book_device_other_brand'][$i] ) : '';
                                    $new_device_type  = ( isset( $_POST['book_device_other_type'][$i] ) && ! empty( $_POST['book_device_other_type'][$i] ) ) ? sanitize_text_field( $_POST['book_device_other_type'][$i] ) : '';

                                    $device_post_id_h = wcrb_add_other_device_return_id( $new_device_name, $new_device_brand, $new_device_type );
                                }

                                if ( ! empty( $device_post_id_h ) ) {
                                    $array_devices[] = array(
                                        "device_post_id" => $device_post_id_h, 
                                        "device_id"      => $device_serial_id_h, 
                                        "device_login"   => $device_login_h,
                                        "device_note"	 => $device_note_h,
                                    );
    
                                    $WCRB_MANAGE_DEVICES->add_customer_device( $device_post_id_h, $device_serial_id_h, $device_login_h, $customer_id );
                                }

                                //Add Service 
                                if ( isset( $_POST["wc_rb_select_service_" . esc_attr( $device_identifier )] ) ) :
                                    //Get Services and save to database first.
                                    $wc_service_id			= sanitize_text_field( $_POST["wc_rb_select_service_" . esc_attr( $device_identifier )] );
                                    $wc_service_name 		= get_the_title( $wc_service_id );
                                    $wc_service_price 		= get_post_meta( $wc_service_id, '_cost', true );
                                    if ( ! empty( $device_post_id_h ) ) {
                                        $wc_service_price = $WCRB_DEVICE_SERVICES->get_price_by_device_for_service( $device_post_id_h, $wc_service_id );
                                    }
                                    $wc_service_qty 		= '1';
                                    $wc_service_code 		= get_post_meta( $wc_service_id, '_service_code', true );
                                    
                                    $process_service_array = array(
                                        "wc_service_code"	        => $wc_service_code, 
                                        "wc_service_id"		        => $wc_service_id, 
                                        "wc_service_qty"	        => $wc_service_qty, 
                                        "wc_service_price"	        => $wc_service_price,
                                        "wc_service_device"	        => $device_post_id_h,
                                        "wc_service_device_serial"  => $device_serial_id_h
                                    );
            
                                    $insert_query =  "INSERT INTO `{$computer_repair_items}` VALUES(NULL, %s, 'services', %s)";
                                        $wpdb->query(
                                            $wpdb->prepare($insert_query, $wc_service_name, $post_id)
                                    );
                                    $order_item_id = $wpdb->insert_id;
                                    
                                    foreach($process_service_array as $key => $value) {
                                        $service_insert_query =  "INSERT INTO `{$computer_repair_items_meta}` VALUES(NULL, %s, %s, %s)";
                            
                                        $wpdb->query(
                                            $wpdb->prepare($service_insert_query, $order_item_id, $key, $value)
                                        );
                                    }
                                endif;
                            }
                        else:
                            $array_devices[] = array(
                                "device_post_id" => $theDeviceID, 
                                "device_id"      => '', 
                                "device_login"   => '',
                                "device_note"	 => '',
                            );
                        endif;

                        update_post_meta( $post_id, '_wc_device_data', $array_devices );
                    endif; // Process devices
                    
                    if ( isset( $_POST["repairBuddAttachment_file"] ) && ! empty( $_POST["repairBuddAttachment_file"] ) ) {
                        //[]
                        $attachments = $_POST["repairBuddAttachment_file"];
                        foreach( $attachments as $attachment ) {
                            $attachment = sanitize_url( $attachment );

                            $arguments = array(
                                'label' => esc_html__( 'Attached Receipt', 'computer-repair-shop' ),
                                'details' => $attachment,
                                'visibility' => 'public',
                                'type' => 'file',
                                'description' => esc_html__( 'File attachment by customer', 'computer-repair-shop' ),
                            );
                            wc_job_extra_items_add( $arguments, $post_id );
                        }
                    }
                    if ( isset( $_POST['dateOfPurchase'] ) && ! empty( $_POST['dateOfPurchase'] ) ) {
                        $arguments = array(
                            'label' => esc_html__( 'Purchase Date', 'computer-repair-shop' ),
                            'details' => sanitize_text_field( $_POST['dateOfPurchase'] ),
                            'visibility' => 'public',
                            'type' => 'date_of_purchase',
                            'description' => esc_html__( 'Declared date of purchase', 'computer-repair-shop' ),
                        );
                        wc_job_extra_items_add( $arguments, $post_id );
                    }

                    if ( isset( $case_number ) ) {
                        $title = $case_number;
                        $where = array( 'ID' => $post_id );
                        $wpdb->update( $wpdb->posts, array( 'post_title' => $title ), $where );
                    }
                    $message = esc_html__("We have received your quote request we would get back to you asap! Thanks. Refresh the page to book more devices. ", "computer-repair-shop");
                    $message .= '<br>' . esc_html__("Your case number is ", "computer-repair-shop") . ' { ' . esc_html( $case_number ) . ' } ';
                } else {
                    $message = esc_html__("Your case is already registered with us.", "computer-repair-shop");
                }
                
                $computer_repair_email 	= ( empty( get_option( 'computer_repair_email' ) ) ) ? get_option( 'admin_email' ) : get_option( 'computer_repair_email' );
                
                $to 	 = $computer_repair_email;
                $WCRB_EMAILS->booking_email_to_administrator( $post_id, $to );

                //Process Customer Email
                if ( isset( $user_email ) && ! empty( $user_email ) ) {
                    $WCRB_EMAILS->booking_email_to_customer( $post_id, $user_email );
                } //Customer Email Processing

                $values['success'] = 'YES';
            }
            $values['message'] = $message;
        endif;
        
        wp_send_json($values);
        wp_die();
    }
    add_action( 'wp_ajax_wc_rb_submit_booking_form', 'wc_rb_submit_booking_form' );
    add_action( 'wp_ajax_nopriv_wc_rb_submit_booking_form', 'wc_rb_submit_booking_form' );
endif;

if ( ! function_exists( 'rb_add_booking_device_row' ) ) : 
    function rb_add_booking_device_row() {
        $content = '';

        $wc_device_label         = ( empty( get_option( 'wc_device_label' ) ) ) ? esc_html__( 'Device', 'computer-repair-shop' ) : get_option( 'wc_device_label' );
        $wc_device_id_imei_label = ( empty( get_option( 'wc_device_id_imei_label' ) ) ) ? esc_html__( 'ID/IMEI', 'computer-repair-shop' ) : get_option( 'wc_device_id_imei_label' );

        $theDeviceID = ( isset( $_POST['theDeviceId'] ) && ! empty ( $_POST['theDeviceId'] ) ) 
                       ? sanitize_text_field( $_POST['theDeviceId'] ) 
                       : '';

        if ( empty ( $theDeviceID ) ) {
            return;
        }
        $deviceLabel = ( $theDeviceID == 'load_other_device' ) ? '' : get_the_title( $theDeviceID );

        $uniquerowID = uniqid( rand() );

        $content .= '<div class="device-booking-row SdisplayNone">';

        $content .= '<div class="device-item-b">';
        $content .= '<label>';
        $content .= $wc_device_label;

        if ( $theDeviceID == 'load_other_device' ) {
            $content .= '<input type="hidden" name="book_deivce_id[]" value="" />';
            $content .= '<input type="hidden" name="book_deivce_name[]" value="" />';
            
            $content .= '<input type="text" data-identifier="'. esc_attr( $uniquerowID ) .'" name="book_deivce_name_other[]" value="' . esc_attr( $deviceLabel ) . '" />';
            $content .= ( isset( $_POST['type_id'] ) && ! empty( $_POST['type_id'] ) ) ? '<input type="hidden" name="book_device_other_type[]" value="'. esc_html( sanitize_text_field( $_POST['type_id'] ) ) .'" />' : '<input type="hidden" name="book_device_other_type[]" value="" />';
            $content .= ( isset( $_POST['brand_id'] ) && ! empty( $_POST['brand_id'] ) ) ? '<input type="hidden" name="book_device_other_brand[]" value="'. esc_html( sanitize_text_field( $_POST['brand_id'] ) ) .'" />' : '<input type="hidden" name="book_device_other_brand[]" value="" />';
        } else {
            $content .= '<input type="hidden" name="book_deivce_id[]" value="' . esc_attr( $theDeviceID ) . '" />';
            $content .= '<input type="text" disabled name="book_deivce_name[]" value="' . esc_attr( $deviceLabel ) . '" />';

            $content .= '<input type="hidden" name="book_deivce_name_other[]" value="NOT_TO_USE" />';
            $content .= '<input type="hidden" name="book_device_other_type[]" value="" />';
            $content .= '<input type="hidden" name="book_device_other_brand[]" value="" />';
        }
        $content .= '</label>';
        $content .= '</div>'; //Column Ends

        $content .= '<div class="device-item-b">';
        $content .= '<label>';
        $content .= $wc_device_label . ' ' . $wc_device_id_imei_label;
        $content .= '<input type="text" data-identifier="'. esc_attr( $uniquerowID ) .'" name="book_device_serial_num[]" value="" />';
        $content .= '</label>';
        $content .= '</div>'; //Column Ends
        
        $wc_pin_code_field		= get_option("wc_pin_code_field");

        if($wc_pin_code_field == "on"):
            $content .= '<div class="device-item-b">';
            $content .= '<label>';
            $wc_pin_code_label	  = ( empty( get_option( 'wc_pin_code_label' ) ) ) ? esc_html__( 'Pin Code/Password', 'computer-repair-shop' ) : get_option( 'wc_pin_code_label' );
            $content .= esc_html( $wc_pin_code_label );

            $content .= '<input type="text" name="book_device_pincode[]" value="" />';
            $content .= '</label>';
            $content .= '</div>'; //Column Ends
        endif;

        $content .= '<div class="device-item-b">';
        $content .= '<label>';
        $wc_note_label 	  = ( empty( get_option( 'wc_note_label' ) ) ) ? esc_html__( 'Note', 'computer-repair-shop' ) : get_option( 'wc_note_label' );
        $content .= $wc_device_label . ' ' . $wc_note_label;
        $content .= '<input type="text" name="book_device_note[]" value="" />';
        $content .= '</label>';
        $content .= '</div>'; //Column Ends

        $content .= '<input type="hidden" name="data_identifier[]" value="'. esc_attr( $uniquerowID ) .'" />';
        $content .= '<a href="#" class="delthisdevice wcrb_close" data-identifier="'. esc_attr( $uniquerowID ) .'">X</a>';
        $content .= '</div><!-- Device Booking Row /-->';

        $values['identifier'] = esc_attr( $uniquerowID );
        $values['message'] = $content;
        
        wp_send_json( $values );
        wp_die();
    }
    add_action( 'wp_ajax_rb_add_booking_device_row', 'rb_add_booking_device_row' );
    add_action( 'wp_ajax_nopriv_rb_add_booking_device_row', 'rb_add_booking_device_row' );
endif;

if ( ! function_exists( 'wcrb_return_services_section' ) ) :
    function wcrb_return_services_section() {
        $values = array( 'message' => '', 'success' => 'NO' );

        $theID         = ( isset( $_POST['identifier'] ) && ! empty( $_POST['identifier'] ) ) ? sanitize_text_field( $_POST['identifier'] ) : '';
        $MtheDeviceId  = ( isset( $_POST['theDeviceId'] ) && ! empty( $_POST['theDeviceId'] ) ) ? sanitize_text_field( $_POST['theDeviceId'] ) : '';
        $device_title  = ( $MtheDeviceId == 'load_other_device' ) ? ' <span class="wcrb_booking_device_label">()</span>' : ' <span class="wcrb_booking_device_label">('. esc_html( get_the_title( $MtheDeviceId ) ) .')</span>';
        $displayClass  = ( $MtheDeviceId == 'load_other_device' ) ? ' displayNone' : '';

        if (!isset( $_POST['theBrandNonce'] ) 
            || ! wp_verify_nonce( $_POST['theBrandNonce'], 'wc_computer_repair_mb_nonce' )) :
                $values['message'] = esc_html__("Something is wrong with your submission!", "computer-repair-shop");
                $values['success'] = "YES";
        else:
            $content = '<div id="'. esc_attr( $theID ) .'" class="wc_rb_mb_section wc_rb_mb_services'. esc_attr( $displayClass ) .'">';
            $content .= '<div class="wc_rb_mb_head"><h2>' . esc_html__( 'Select Services', 'computer-repair-shop' ) . $device_title . ' <span class="wcrb_booking_device_serial"></span></h2></div>';
            
            $content .= '<div class="wc_rb_mb_body text-center service-message">';
            $content .= wc_rb_update_services_list( $MtheDeviceId, $theID );
            $content .= '</div><!-- body ends /-->';

            $content .= '</div>';
        endif;

        $values['message'] = $content;

        wp_send_json( $values );
        wp_die();
    }
    add_action( 'wp_ajax_wcrb_return_services_section', 'wcrb_return_services_section' );
    add_action( 'wp_ajax_nopriv_wcrb_return_services_section', 'wcrb_return_services_section' );
endif;

if( ! function_exists( 'wc_rb_update_services_list' ) ):
    function wc_rb_update_services_list( $MtheDeviceId, $identifier ) { 
        $post_output = '';
        
        if ( empty( $MtheDeviceId ) ) {
            return;
        }

        $theTypeId   = ( $MtheDeviceId == 'load_other_device' ) ? '' : wcrb_return_device_terms( $MtheDeviceId, 'device_type' );
        $theBrandId  = ( $MtheDeviceId == 'load_other_device' ) ? '' : wcrb_return_device_terms( $MtheDeviceId, 'device_brand' );

        $post_query = array(
                            'posts_per_page' => -1,
                            'post_status'   => 'publish',
                            'post_type'      => 'rep_services',
        );
        $the_post = new WP_Query( $post_query );

        if( $the_post->have_posts() ) : 
            $post_output = '<ul class="manufacture_list wc_service_radio">';
            while( $the_post->have_posts() ): 
                $the_post->the_post();
                $service_id   = get_the_ID();
                $timeRequired = get_post_meta( $service_id, '_time_required', true );
                $thePrice     = get_post_meta( $service_id, '_cost', true );

                $devicePrice  = get_post_meta( $service_id, 'device_price_'.$MtheDeviceId, true );
                $typePrice    = get_post_meta( $service_id, 'type_price_'.$theTypeId, true );
                $brandPrice   = get_post_meta( $service_id, 'brand_price_'.$theBrandId, true );

                $brand_status  = get_post_meta( $service_id, 'brand_status_'.$theBrandId, true );
                $type_status   = get_post_meta( $service_id, 'type_status_'.$theTypeId, true );
                $device_status = get_post_meta( $service_id, 'device_status_'.$MtheDeviceId, true );

                $thestatus = 'active';
                $thestatus = ( $type_status == 'inactive' ) ? 'inactive' : $thestatus;
                $thestatus = ( $brand_status == 'inactive' ) ? 'inactive' : $thestatus;
                $thestatus = ( $brand_status == 'active' ) ? 'active' : $thestatus;
                $thestatus = ( $device_status == 'inactive' ) ? 'inactive' : $thestatus;
                $thestatus = ( $device_status == 'active' ) ? 'active' : $thestatus;

                if ( $thestatus == 'active' ) :
                    if ( ! empty( $devicePrice ) ) {
                        $thePrice = $devicePrice;
                    } elseif ( ! empty( $brandPrice ) ) {
                        $thePrice = $brandPrice;
                    } elseif ( ! empty( $typePrice ) ) {
                        $thePrice = $typePrice;
                    }

                    $thePrice     = ( ! empty( $thePrice ) ) ? $thePrice : '0.00';
                    $thePrice     = wc_cr_currency_format($thePrice);
                    $post_output .= '<li><label>';
                    $post_output .= '<span class="radioHolder"><input type="radio" class="wcrb_select_service_radio" name="wc_rb_select_service_'. esc_attr( $identifier ) .'" value="' . $service_id . '"></span>';
                    $post_output .= '<span class="theServiceTitle">' . get_the_title() . '<br>';
                    $post_output .= ( ! empty( $timeRequired ) ) ? esc_html__( 'Time Required:', 'computer-repair-shop' ) . ' ' . esc_html( $timeRequired ) . '</span>' : '</span>';
                    $post_output .= '<span class="theServicePrice">' . esc_html( $thePrice ) . '</span>';
                    $post_output .= '</label></li>';
                endif;
            endwhile;
            $post_output .= '</ul>';
        endif;
            
        wp_reset_postdata();

        return $post_output;
    }
endif;