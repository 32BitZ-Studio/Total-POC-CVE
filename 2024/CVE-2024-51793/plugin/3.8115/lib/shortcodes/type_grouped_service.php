<?php
/**
 * The file contains the functions related to Shortcode Pages
 * wc_book_type_grouped_service
 * Help setup pages to they can be used in notifications and other items
 *
 * @package computer-repair-shop
 * @version 3.7947
 */

defined( 'ABSPATH' ) || exit;

if ( ! function_exists( 'WCRB_TYPE_GROUPED_SERVICE' ) ) {
    function WCRB_TYPE_GROUPED_SERVICE() {
        wp_enqueue_script("foundation-js");
        //wp_enqueue_script("wc-cr-js");
        //wp_enqueue_script("select2");
        wp_enqueue_script("intl-tel-input");
        wp_enqueue_style("intl-tel-input");

        add_action( 'wp_print_footer_scripts', 'wcrb_intl_tel_input_script' );

        $content = '';
        $content .= '<div class="wc_rb_mb_wrap"><form method="post" action="" name="wc_rb_device_form">';

        $wc_device_type_label = ( empty( get_option( 'wc_device_type_label' ) ) ) ? esc_html__( 'Device Type', 'computer-repair-shop' ) : get_option( 'wc_device_type_label' );

        //The Device Type
        $content .= '<div class="wc_rb_mb_section wc_rb_mb_types">';
        $content .= '<div class="wc_rb_mb_head"><h2>' . esc_html__( 'Select ', 'computer-repair-shop' ) . esc_html( $wc_device_type_label ) . '</h2></div>';
        
        $content .= '<div class="wc_rb_mb_body">';
        $content .=  wp_nonce_field( 'wc_computer_repair_mb_nonce', 'wc_rb_mb_device_submit', true, false);
        $content .=  '<input type="hidden" id="grouped_services_load" value="YES" />';
        
        $content .= '<input type="hidden" name="wcrb_thetype_id" id="wcrb_thetype_id" value="">';
        
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
                $output .= '<li><a href="#" dt_device_type="thebrand" dt_brand_g_id="'. esc_attr( $category->term_id ) .'" title="' . $category->name . '">';
                
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
        
        $content .= '<input name="add_more_device_label" type="hidden" value="' . esc_html__( 'Add another', 'computer-repair-shop' ) . ' ' . esc_html( $wc_device_label ) . '" />';
        $content .= '<input name="select_service_label" type="hidden" value="' . esc_html__( 'Select service', 'computer-repair-shop' ) . '" />';
        $content .= '<input name="enter_device_label_missing_msg" type="hidden" value="' . esc_html__( 'Please enter the name of device or select another device, and remove devices not needed.', 'computer-repair-shop' ) . '" />';

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
        $billing_tax    	= ( ! empty( $customer_id )) ? get_user_meta( $customer_id, 'billing_tax', true) : '';

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
    }
    add_shortcode( 'wc_book_type_grouped_service', 'WCRB_TYPE_GROUPED_SERVICE' );
} //EndIf Function Exists

if ( ! function_exists( 'wc_rb_update_services_list_grouped' ) ) {
    function wc_rb_update_services_list_grouped() {
        $values = array();
        if (!isset( $_POST['theBrandNonce'] ) 
            || ! wp_verify_nonce( $_POST['theBrandNonce'], 'wc_computer_repair_mb_nonce' )) :
                $values['message'] = esc_html__("Something is wrong with your submission!", "computer-repair-shop");
                $values['success'] = "YES";
        else:
            $post_output = '';
            //Register User(  )
            $theID         = ( isset( $_POST['identifier'] ) && ! empty( $_POST['identifier'] ) ) ? sanitize_text_field( $_POST['identifier'] ) : '';
            $MtheDeviceId = sanitize_text_field( $_POST['theDeviceId'] );
            $device_title  = ( $MtheDeviceId == 'load_other_device' ) ? ' <span class="wcrb_booking_device_label">()</span>' : ' <span class="wcrb_booking_device_label">('. esc_html( get_the_title( $MtheDeviceId ) ) .')</span>';
            $displayClass  = ( $MtheDeviceId == 'load_other_device' ) ? ' displayNone' : '';

            $post_output = '<div id="'. esc_attr( $theID ) .'" class="wc_rb_mb_section wc_rb_mb_services'. esc_attr( $displayClass ) .'">';
            $post_output .= '<div class="wc_rb_mb_head"><h2>' . esc_html__( 'Select Services', 'computer-repair-shop' ) . $device_title . ' <span class="wcrb_booking_device_serial"></span></h2></div>';
            
            $post_output .= '<div class="wc_rb_mb_body text-center service-message">';
            $post_output .= '<ul class="accordion" data-accordion data-allow-all-closed="true">';

			$service_group 	= get_terms( 'service_type', array( 'orderby' => 'name', 'order' => 'ASC' ) );
			
			$counter = 1; //counter init
			
			foreach( $service_group as $group ) {
				$group_slug = $group->slug;
				$group_name = $group->name;
                $group_id   = $group->term_id;

                $outputofservices = wcrb_return_services_for_accordion( $MtheDeviceId, $group_id, $theID );

                if ( ! empty( $outputofservices ) ) {
                    $post_output .= '<li class="accordion-item" data-accordion-item>';
                    $post_output .= '<a href="#' . esc_attr( $group_slug ) . '_'. esc_attr( $theID ) .'" class="accordion-title">' . esc_html( $group_name ) . '</a>';
                    $post_output .= '<div class="accordion-content" data-tab-content id="' . esc_attr( $group_slug ) . '_'. esc_attr( $theID ) .'">';
                    $post_output .= $outputofservices;
                    $post_output .= '</div></li>';
                }
            }
            $post_output .= '</ul>';
            $post_output .= '</div><!-- body ends /-->';
            $post_output .= '</div>';

            $values['message'] = $post_output;
        endif;
        
        wp_send_json($values);
        wp_die();
    }
    add_action( 'wp_ajax_wc_rb_update_services_list_grouped', 'wc_rb_update_services_list_grouped' );
    add_action( 'wp_ajax_nopriv_wc_rb_update_services_list_grouped', 'wc_rb_update_services_list_grouped' );
}//End Function Exists


function wcrb_return_services_for_accordion( $MtheDeviceId, $term_id, $identifier ) {

    if ( empty( $MtheDeviceId ) || empty( $term_id ) ) {
        return '';
    }

    $theTypeId   = wcrb_return_device_terms( $MtheDeviceId, 'device_type' );
    $theBrandId  = wcrb_return_device_terms( $MtheDeviceId, 'device_brand' );

    $post_output = '';

    $post_query = array(
            'posts_per_page' => -1,
            'post_type'      => 'rep_services',
            'tax_query' => array(
                array(
                    'taxonomy' => 'service_type',
                    'field'    => 'term_id',
                    'terms'    => $term_id,
                ),
            ),
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

                $returnD = 1;
            endif;
        endwhile;
        $post_output .= '</ul>';
    endif;
    wp_reset_postdata();

    return ( isset( $returnD ) && $returnD == 1 ) ? $post_output : '';
}