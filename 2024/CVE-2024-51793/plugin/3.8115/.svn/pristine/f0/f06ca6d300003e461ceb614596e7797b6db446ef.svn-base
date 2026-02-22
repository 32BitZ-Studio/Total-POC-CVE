<?php
/**
 * The file contains the functions related to Shortcode Pages
 * wc_book_my_warranty
 * Help setup pages to they can be used in notifications and other items
 *
 * @package computer-repair-shop
 * @version 3.7961
 */

defined( 'ABSPATH' ) || exit;

if ( ! function_exists( 'wc_book_my_warranty' ) ) {
    function wc_book_my_warranty() {
        wp_enqueue_script("foundation-js");
        //wp_enqueue_script("wc-cr-js");
        //wp_enqueue_script("select2");
        wp_enqueue_script("intl-tel-input");
        wp_enqueue_style("intl-tel-input");

        add_action( 'wp_print_footer_scripts', 'wcrb_intl_tel_input_script' );

        $content = '';
        $content .= '<div class="wc_rb_mb_wrap"><form method="post" enctype="multipart/form-data" action="" name="wc_rb_device_form">';

        $wc_device_type_label = ( empty( get_option( 'wc_device_type_label' ) ) ) ? esc_html__( 'Device Type', 'computer-repair-shop' ) : get_option( 'wc_device_type_label' );

        //The Device Type
        $content .= '<div class="wc_rb_mb_section wc_rb_mb_types">';
        $content .= '<div class="wc_rb_mb_head"><h2>' . esc_html__( 'Select ', 'computer-repair-shop' ) . esc_html( $wc_device_type_label ) . '</h2></div>';
        
        $content .= '<div class="wc_rb_mb_body">';
        $content .=  wp_nonce_field( 'wc_computer_repair_mb_nonce', 'wc_rb_mb_device_submit', true, false);
        
        $content .= '<input type="hidden" name="wcrb_thetype_id" id="wcrb_thetype_id" value="">';
        $content .= '<input type="hidden" name="wcrb_booking_type" id="wcrb_booking_type" value="YES" >';
        
        $wcrb_type = 'rep_devices';
        $wcrb_tax = 'device_type';
     
        $taxonomies = get_terms( array(
            'taxonomy'   => $wcrb_tax,
            'hide_empty' => true
        ) );
         
        if ( ! empty ( $taxonomies ) ) :
            $output = '<ul class="dtypes_list">';
            foreach( $taxonomies as $category ) {
                $output .= '<li><a href="#" dt_device_type="thetype" dt_type_id="'. esc_attr( $category->term_id ) .'" title="' . $category->name . '">';
                
                $image_id = esc_html( get_term_meta( $category->term_id, 'image_id', true ) );
				if ( ! empty( $image_id ) ) :
                    $output .= wp_get_attachment_image ( $image_id, 'full' );
                else: 
                    $output .= '<h3>' . esc_html( $category->name ) . '</h3>';
                endif;
                $output .= '</a></li>';
            }
            $output.='</ul>';
            $content .= $output;
        endif;

        $content .= '</div><!-- body ends /-->';
        $content .= '</div>';

        $wc_device_brand_label = ( empty( get_option( 'wc_device_brand_label' ) ) ) ? esc_html__( 'Manufacture', 'computer-repair-shop' ) : get_option( 'wc_device_brand_label' );
        $wc_device_brands_label = ( empty( get_option( 'wc_device_brand_label_plural' ) ) ) ? esc_html__( 'Manufactures', 'computer-repair-shop' ) : get_option( 'wc_device_brand_label_plural' );
        
        //The Manufactures.
        $content .= '<div class="wc_rb_mb_section wc_rb_mb_manufactures" id="wc_rb_mb_manufactures">';
        $content .= '<div class="wc_rb_mb_head"><h2>' . esc_html__( 'Select ', 'computer-repair-shop' ) . esc_html( $wc_device_brand_label ) . '</h2></div>';
        
        $content .= '<input type="hidden" name="wcrb_thebrand_id" id="wcrb_thebrand_id" value="">';

        $content .= '<div class="wc_rb_mb_body manufactures_message"><div class="selectionnotice">';
        $content .= esc_html__( 'Please select a type to list ', 'computer-repair-shop' ) . esc_html( lcfirst( $wc_device_brands_label ) );
        $content .= '<br>' . esc_html__( 'If you have different type or some other query please contact us.', 'computer-repair-shop' ) . '</div>';

        $wcrb_type = 'rep_devices';
        $wcrb_tax = 'device_brand';
     
        $taxonomies = get_terms( array(
            'taxonomy'   => $wcrb_tax,
            'hide_empty' => true
        ) );
         
        if ( ! empty ( $taxonomies ) ) :
            $output = '<ul class="manufacture_list displayNone">';
            foreach( $taxonomies as $category ) {
                $output .= '<li><a href="#" dt_device_type="thebrand" dt_device_warranty="YES" dt_brand_g_id="'. esc_attr( $category->term_id ) .'" title="' . $category->name . '">';
                
                $image_id = esc_html( get_term_meta( $category->term_id, 'image_id', true ) );
				if ( ! empty( $image_id ) ) :
                    $output .= wp_get_attachment_image ( $image_id, 'full' );
                else: 
                    $output .= '<h3>' . esc_html( $category->name ) . '</h3>';
                endif;
                $output .= '</a></li>';
            }
            
            $selected = '';
            $wcrb_turn_off_other_device_brands = get_option( 'wcrb_turn_off_other_device_brands' );
            if ( $wcrb_turn_off_other_device_brands != 'on' ) {
                $output .= '<li class="wcrb-other-color"><a class="' . esc_attr( $selected ) . '" href="#" dt_device_type="thebrand" dt_brand_g_id="brand_other" title="' . esc_html__( 'Other', 'computer-repair-shop' ) . '">';
                $output .= '<h3>' . esc_html__( 'Other', 'computer-repair-shop' ) . '</h3></a></li>';
            }

            $output.='</ul>';
            $content .= $output;
        endif;

        $content .= '</div><!-- body ends /-->';
        $content .= '</div>';

        //The Devide.
        $wc_device_label = ( empty( get_option( 'wc_device_label' ) ) ) ? esc_html__( 'Device', 'computer-repair-shop' ) : get_option( 'wc_device_label' );
        $content .= '<div class="wc_rb_mb_section wc_rb_mb_device displayNone">';
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

        //The Customer Information.
        $content .= '<div class="wc_rb_mb_section wc_rb_mb_customer displayNone">';
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

        $content .= '<label>'.esc_html__("Address", "computer-repair-shop");
        $content .= '<input type="text" name="userAddress" value="' . esc_html( $customer_address ) . '" class="form-control login-field" placeholder="">';
        $content .= '</label>';
        
        $content .= '</div><!-- column Ends /-->';

        $content .= '<div class="medium-6 cell">';

        $content .= '<label>' . esc_html__( 'Date of Purchase', 'computer-repair-shop' );
        $content .= '<input type="date" name="dateOfPurchase" value="" class="form-control login-field">';
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
        $content .= '<label for="reciepetAttachment" class="button button-primary">' . esc_html__( 'Attach Receipt', 'computer-repair-shop' ) . '</label>
                    <input type="file" id="reciepetAttachment" name="reciepetAttachment" class="show-for-sr">';

        $content .= wc_rb_gdpr_acceptance_link_generate();

        $content .= '<input type="submit" class="button button-primary primary" value="' . esc_html__( 'Submit Request!', "computer-repair-shop").'" />';
        $content .= '<div class="booking_message"></div>';
        $content .= '</div><!-- body ends /-->';

        $content .= '</div>';

        $content .= '</div><!-- wc_rb_mb_wrap Ends /--></form>';

        return $content;
    }
    add_shortcode( 'wc_book_my_warranty', 'wc_book_my_warranty' );
} //EndIf Function Exists