<?php
defined( 'ABSPATH' ) || exit;

if ( ! function_exists( 'wc_print_order_invoice' ) ) :
    /***
     * Repair Order Functionality
     * Function Returns repair Order
     *
     * Takes Order ID as an Argument.
     * @package computer repair shop
     */
    function wc_print_order_invoice( $order_id, $post_type ) {
        global $PAYMENT_STATUS_OBJ;

        if ( empty( $order_id ) ) {
            return;
        }
        $system_currency = return_wc_rb_currency_symbol();
        $wc_use_taxes    = get_option( 'wc_use_taxes' );
        //Let's do magic.
        $customer_id     = get_post_meta( $order_id, '_customer', true );
        $user            = get_user_by( 'id', $customer_id );
        $user_email      =  !empty( $user ) ? $user->user_email : '';
        
        $wc_device_label         = ( empty( get_option( 'wc_device_label' ) ) ) ? esc_html__( 'Device', 'computer-repair-shop' ) : get_option( 'wc_device_label' );
        $wc_device_id_imei_label = ( empty( get_option( 'wc_device_id_imei_label' ) ) ) ? esc_html__( 'ID/IMEI', 'computer-repair-shop' ) : get_option( 'wc_device_id_imei_label' );

        $content = '<div id="invoice-box" class="invoice-box">
        <table cellpadding="0" cellspacing="0">
            <tr class="top">
                <td colspan="2">
                    <table>
                        <tr>
                            <td class="title">';
        $content .= wc_rb_return_logo_url_with_img("company_logo");

        $pickup_date = get_post_meta( $order_id, '_pickup_date', true );
        $pickup_date = ( ! empty( $pickup_date ) ) ? $pickup_date : get_the_date( '', $order_id );
        $date_format = get_option( 'date_format' );
		$pickup_date = date_i18n( $date_format, strtotime( $pickup_date ) );

        $postType = get_post_type( $order_id ) ;
        $invoice_html = '';
        if ( $postType != 'rep_estimates' ) {
            $wc_status_slug = get_post_meta( $order_id, '_wc_order_status', true );
            $invoce_label = wc_return_status_invoice_label( $wc_status_slug );
            $invoce_label = ( empty( $invoce_label ) ) ? 'Invoice' : $invoce_label; 
            $invoice_html = '<h2 class="wcrb_invoice_label">' . esc_html( $invoce_label ) . '</h2>';
        }
        $content .= '</td>
                            <td class="invoice_headers">
                                '. $invoice_html .'
                                <strong>'.esc_html__("Order", "computer-repair-shop").' #:</strong> '.$order_id.'<br>
                                <strong>'.esc_html__( 'Case Number', 'computer-repair-shop' ).' :</strong> '.get_post_meta( $order_id, "_case_number", true ).'<br>
                                <strong>'.esc_html__("Created", "computer-repair-shop").' :</strong> ' . esc_html( $pickup_date ) . '<br>
                                <strong>'.esc_html__("Payment Status", "computer-repair-shop").' :</strong> '.get_post_meta( $order_id, "_wc_payment_status_label", true ).'<br>
                                <strong>'.esc_html__("Order Status", "computer-repair-shop").' :</strong> '.get_post_meta( $order_id, "_wc_order_status_label", true ).'
                            </td>
                        </tr>
                    </table>
                </td>
            </tr>
            
            <tr class="information">
                <td colspan="2">
                    '. $PAYMENT_STATUS_OBJ->wc_return_online_payment_link( $order_id ) .'
                    <table class="invoice_headers">
                        <tr>
                            <td>';
                                $wc_rb_business_name	= get_option( 'wc_rb_business_name' );
                                $wc_rb_business_phone	= get_option( 'wc_rb_business_phone' );
                                $wc_rb_business_address	= get_option( 'wc_rb_business_address' );

                                $wc_rb_business_name	= ( empty( $wc_rb_business_name ) ) ? get_bloginfo( 'name' ) : $wc_rb_business_name;

                                $computer_repair_email = get_option( 'computer_repair_email' );

                                $_store_id = get_post_meta( $order_id, '_store_id', true );
                                if ( ! empty( $_store_id ) ) {
                                    $store_address = get_post_meta( $_store_id, '_store_address', true );
                                    $store_email   = get_post_meta( $_store_id, '_store_email', true );

                                    $wc_rb_business_address = ( ! empty( $store_address ) ) ? $store_address : $wc_rb_business_address;
                                    $computer_repair_email = ( ! empty( $store_email ) ) ? $store_email : $computer_repair_email;
                                }

                                if(empty($computer_repair_email)) {
                                    $computer_repair_email	= get_option("admin_email");	
                                }

                                $content .= '<div class="company_info large_invoice">';
                                $content .= "<div class='address-side'>
                                             <h2>".$wc_rb_business_name."</h2>";
                                $content .= ( ! empty( get_bloginfo( 'description' ) ) ) ? get_bloginfo( 'description' ) . '<br>' : '';
                                $content .= "<p>";
                                $content .= $wc_rb_business_address;
                                $content .= (!empty($computer_repair_email)) ? "<br><strong>".esc_html__("Email", "computer-repair-shop")."</strong>: ".$computer_repair_email : "";
                                $content .= (!empty($wc_rb_business_phone)) ? "<br><strong>".esc_html__("Phone", "computer-repair-shop")."</strong>: ".$wc_rb_business_phone : "";
                                $content .= "</p></div>";
                                $content .= '</div>';
                $content .= '</td>
                            <td>';
                                $customerLabel      = get_post_meta( $order_id, "_customer_label", true );

                                $customer_phone  	= get_user_meta( $customer_id, 'billing_phone', true);
                                $customer_address 	= get_user_meta( $customer_id, 'billing_address_1', true);
                                $customer_city 		= get_user_meta( $customer_id, 'billing_city', true);
                                $customer_zip		= get_user_meta( $customer_id, 'billing_postcode', true);
                                $state		        = get_user_meta( $customer_id, 'billing_state', true);
                                $country		    = get_user_meta( $customer_id, 'billing_country', true);
                                $customer_company	= get_user_meta( $customer_id, 'billing_company', true);
                                $billing_tax	    = get_user_meta( $customer_id, 'billing_tax', true);
                                
                                $content .= ( ! empty( $customer_company ) ) ? '<strong>' . esc_html__( 'Company', 'computer-repair-shop' ) . ' : </strong>' . $customer_company . '<br>' : '';
                                $content .= ( ! empty( $billing_tax ) ) ? '<strong>' . esc_html__( 'Tax ID', 'computer-repair-shop' ) . ' : </strong>' . $billing_tax . '<br>' : '';
                                $content .= ( ! empty( $customerLabel ) ) ? $customerLabel : '';


                                if(!empty($customer_zip) || !empty($customer_city) || !empty($customer_address)) {
                                    $content .= "<br><strong>".esc_html__("Address", "computer-repair-shop")." :</strong> ";

                                    $content .= !empty($customer_address) ? $customer_address.", " : " ";
                                    $content .= !empty($customer_city) ? "<br>".$customer_city.", " : " ";
                                    $content .= !empty($customer_zip) ? $customer_zip.", " : " ";
                                    $content .= !empty($state) ? $state.", " : " ";
                                    $content .= !empty($country) ? $country : " ";
                                }
                                if(!empty($customer_phone)) {
                                    $content .= "<br><strong>".esc_html__("Phone", "computer-repair-shop")." :</strong> ".$customer_phone;	
                                }
                                if(!empty($user_email)) {
                                    $content .= "<br><strong>".esc_html__("Email", "computer-repair-shop")." :</strong> ".$user_email;	
                                }
                        $content .= '
                            </td>
                        </tr>
                    </table>
                </td>
            </tr>';	

            if ( isset( $post_type ) && $post_type == 'status_check' ) {
                //Get File option
                $wc_file_attachment_in_job = get_option( 'wc_file_attachment_in_job' );
                $meta_key 	= 'wc_job_file';
                $file_id 	=  get_post_meta( $order_id, '_' . $meta_key, true );
                
                if ( $wc_file_attachment_in_job == 'on' && !empty( $file_id ) ) {
                    $content .= '<tr class="heading">';
                    $content .= '<th>' . esc_html__( 'File Attachment', 'computer-repair-shop' ) . '</th>';
                    $file_url = wp_get_attachment_url( $file_id );
                    $content .= '<td><a href="' . esc_url( $file_url ) . '" target="_blank">' . esc_html__( 'Click to view', 'computer-repair-shop' ) . '</a></td>';
                    $content .= '</tr>';
                }
            }

            /*$device_id 	        = get_post_meta( $order_id, '_device_id', true );
            $device_post_number = get_post_meta( $order_id, '_device_post_id', true );

            if(!empty($device_post_number)):
                $content .= "<br><strong>" .  . " </strong>".return_device_label($device_post_number);
            endif;

            if(!empty($device_id)):
                $content .= "<br><strong>" . $wc_device_id_imei_label . " </strong>".esc_html($device_id);
            endif; */

            $postType = get_post_type( $order_id ) ;

            if ( $postType == 'rep_estimates' ) {
                $wc_order_status = get_post_meta( $order_id, '_wc_estimate_status', true );

                if ( $wc_order_status == 'approved' ) {
                    $label = ' - ' . esc_html__( 'Approved', 'computer-repair-shop' );
                } elseif ( $wc_order_status == 'rejected' ) {
                    $label = ' - ' . esc_html__( 'Rejected', 'computer-repair-shop' );
                } else {
                    $label = '';
                }

                $content .= '<tr class="heading estimate">
                                <td colspan="2">' . esc_html__( 'ESTIMATE', 'computer-repair-shop' ) . $label . '</td>
                            </tr>';
            }

            $wc_case_detail = get_post_meta( $order_id, '_case_detail', true );

            if ( ! empty( $wc_case_detail ) ) :
                $content .= '<tr class="heading">
                    <td colspan="2">
                        ' . esc_html__( 'Order Details', 'computer-repair-shop' ) . '
                    </td>
                </tr>
                
                <tr class="details">
                    <td colspan="2">
                        ' . nl2br( $wc_case_detail ) . '
                    </td>
                </tr>';
            endif;

        $content .= '</table>';

        $current_devices = get_post_meta( $order_id, '_wc_device_data', true );

        if ( ! empty( $current_devices )  && is_array( $current_devices ) ) {
            $wc_pin_code_show_inv = get_option( 'wc_pin_code_show_inv' );

            $content .= '<table class="mb-twenty">';
            
            $content .= '<tr class="heading special_head">';
            $content .= '<td>' . $wc_device_label . '</td>';
            $content .= '<td>' . $wc_device_id_imei_label . '</td>';
            $wc_note_label 	  = ( empty( get_option( 'wc_note_label' ) ) ) ? esc_html__( 'Note', 'computer-repair-shop' ) : get_option( 'wc_note_label' );
            $content .= '<td>' . esc_html( $wc_note_label ) . '</td>';

            if ( $wc_pin_code_show_inv == 'on' ) {
                $wc_pin_code_label = ( empty( get_option( 'wc_pin_code_label' ) ) ) ? esc_html__( 'Pin Code/Password', 'computer-repair-shop' ) : get_option( 'wc_pin_code_label' );
                $content .= '<td>' . esc_html( $wc_pin_code_label ) . '</td>';
            }

            $content .= '</tr>';

            foreach( $current_devices as $device_data ) {
                $deive_note     = ( isset( $device_data['device_note'] ) ) ? $device_data['device_note'] : '';
                $device_post_id = ( isset( $device_data['device_post_id'] ) ) ? $device_data['device_post_id'] : '';
                $device_id      = ( isset( $device_data['device_id'] ) ) ? $device_data['device_id'] : '';

                $content .= '<tr class="item-row">';
                $content .= '<td>' . return_device_label( $device_post_id ) . '</td>';
                $content .= '<td>' . $device_id . '</td>';
                $content .= '<td class="text-left">' . $deive_note . '</td>';
                if ( $wc_pin_code_show_inv == 'on' ) {
                    $device_login = ( isset( $device_data['device_login'] ) ) ? $device_data['device_login'] : '';
                    $content .= '<td>' . esc_html( $device_login ) . '</td>';
                }
                $content .= '</tr>';
            }

            $content .= '</table>';
        }

        $arguments_d = $post_type;

        if ( ! empty( $arguments_d ) ) {
            $arguments_d = array(
                'order_id' => $order_id,
                'display_type' => $post_type
            );
        } else {
            $arguments_d = $order_id;   
        }

        if ( wc_rs_license_state() ) :
            $wb_rb_invoice_type = get_option( 'wb_rb_invoice_type' );
            if ( $wb_rb_invoice_type == 'by_device' ) {
                $content .= rb_return_order_items_by_device( $order_id );
            } else {
                $content .= rb_return_order_items( $order_id, $arguments_d );       
            }
        else: 
            $content .= wc_cr_new_purchase_link("");
        endif;
        
        $content .= '<div class="invoice_totals"><table>';
        $receiving      = $PAYMENT_STATUS_OBJ->wc_return_receivings_total( $order_id );
        $theGrandTotal  = wc_order_grand_total( $order_id, 'grand_total' );
        $theBalance     = $theGrandTotal-$receiving;

        $content .= '<tr><th>'.esc_html__("Grand Total", "computer-repair-shop").'</th><td>' . wc_cr_currency_format( $theGrandTotal ) . '</td></tr>';

        if ( $postType != 'rep_estimates' ) {
            $content .= '<tr><th>'.esc_html__("Received", "computer-repair-shop").'</th><td>' . wc_cr_currency_format( $receiving ) . '</td></tr>';
            $content .= '<tr><th>'.esc_html__("Balance", "computer-repair-shop").'</th><td>' . wc_cr_currency_format( $theBalance ) . '</td></tr>';
        }

        $content .= '</table></div>';
        $content .= "<p class='text-center signatureblock'>";
        $content .= ( ! empty( get_option( 'wc_rb_io_thanks_msg' ) ) ) ? get_option( 'wc_rb_io_thanks_msg' ) : esc_html__( 'Thanks for your business!', 'computer-repair-shop' );
        $content .= "</p>";

        if(isset($post_type) && ( $post_type == "print" || $post_type == 'status_check' ) ){
            $content .= '<button id="btnPrint" class="hidden-print button button-primary">'.esc_html__("Print", "computer-repair-shop").'</button>';
        }
        $content .= '</div>';
        
        return $content;
    }
endif;

if ( ! function_exists( 'rb_return_order_items_by_device' ) ) :
function rb_return_order_items_by_device( $order_id ) {
    global $wpdb;

    if ( empty( $order_id ) ) {
        return;
    }

    if ( ! wc_rs_license_state() ) :
        return wc_cr_new_purchase_link("");
    endif;

    $computer_repair_items 		= $wpdb->prefix . 'wc_cr_order_items';
    $select_items_query = $wpdb->prepare( "SELECT * FROM `{$computer_repair_items}` WHERE `order_id`= %d", $order_id);
    $items_result = $wpdb->get_results( $select_items_query );
	
	$_devices = $_parts = $_services = $_products = $_extras = array();
    foreach( $items_result as $item ) {
        $order_item_id 	 = $item->order_item_id;
        $order_item_name = $item->order_item_name;
        $order_item_type = $item->order_item_type;

        //extras services

        if ( $order_item_type == 'parts' ) {
            $part_array = array();
            
            $part_array['_device_id'] = $_device_id = wcrb_return_order_meta( $order_item_id, 'wc_part_device' );
            $part_array['_device_serial'] = $_device_serial = wcrb_return_order_meta( $order_item_id, 'wc_part_device_serial' );
            $part_array['wc_part_id'] 		= wcrb_return_order_meta( $order_item_id, 'wc_part_id' );
            $part_array['wc_part_code']		= wcrb_return_order_meta( $order_item_id, 'wc_part_code' );
            $part_array['wc_part_capacity']	= wcrb_return_order_meta( $order_item_id, 'wc_part_capacity' );
            $part_array['wc_part_qty']		= wcrb_return_order_meta( $order_item_id, 'wc_part_qty' );
            $part_array['wc_part_price']	= wcrb_return_order_meta( $order_item_id, 'wc_part_price' );
            $part_array['wc_part_tax']		= wcrb_return_order_meta( $order_item_id, 'wc_part_tax' );
            $part_array['item_name']		= $order_item_name;

            $array_key = ( ! empty( $_device_id ) ) ? $_device_id : 'other';
            $array_key .= ( ! empty( $_device_serial ) ) ? '_' . $_device_serial : '';

            $_devices[$array_key]['device_id'] = $_device_id;
            $_devices[$array_key]['device_serial'] = $_device_serial;
            $_devices[$array_key]['parts'][] = $part_array;
        }
        
        if ( $order_item_type == 'products' ) {
            $product_array = array();

            $product_array['_device_id'] = $_device_id = wcrb_return_order_meta( $order_item_id, 'wc_product_device' );
            $product_array['_device_serial'] = $_device_serial = wcrb_return_order_meta( $order_item_id, 'wc_product_device_serial' );
            $product_array['wc_product_id']    = wcrb_return_order_meta( $order_item_id, 'wc_product_id' );
            $product_array['wc_product_sku']   = wcrb_return_order_meta( $order_item_id, 'wc_product_sku' );
            $product_array['wc_product_qty']   = wcrb_return_order_meta( $order_item_id, 'wc_product_qty' );
            $product_array['wc_product_price'] = wcrb_return_order_meta( $order_item_id, 'wc_product_price' );
            $product_array['wc_product_tax']   = wcrb_return_order_meta( $order_item_id, 'wc_product_tax' );
            $product_array['item_name']		   = $order_item_name;

            $array_key = ( ! empty( $_device_id ) ) ? $_device_id : 'other';
            $array_key .= ( ! empty( $_device_serial ) ) ? '_' . $_device_serial : '';

            $_devices[$array_key]['device_id'] = $_device_id;
            $_devices[$array_key]['device_serial'] = $_device_serial;
            $_devices[$array_key]['products'][] = $product_array;
        }
        
        if ( $order_item_type == 'services' ) {
            $services_array = array();

            $services_array['_device_id'] = $_device_id = wcrb_return_order_meta( $order_item_id, 'wc_service_device' );
            $services_array['_device_serial'] = $_device_serial = wcrb_return_order_meta( $order_item_id, 'wc_service_device_serial' );
            $services_array['wc_service_id']    = wcrb_return_order_meta( $order_item_id, 'wc_service_id' );
            $services_array['wc_service_code']  = wcrb_return_order_meta( $order_item_id, 'wc_service_code' );
            $services_array['wc_service_qty']   = wcrb_return_order_meta( $order_item_id, 'wc_service_qty' );
            $services_array['wc_service_price']	= wcrb_return_order_meta( $order_item_id, 'wc_service_price' );
            $services_array['wc_service_tax']	= wcrb_return_order_meta( $order_item_id, 'wc_service_tax' );
            $services_array['item_name']		= $order_item_name;

            $array_key = ( ! empty( $_device_id ) ) ? $_device_id : 'other';
            $array_key .= ( ! empty( $_device_serial ) ) ? '_' . $_device_serial : '';

            $_devices[$array_key]['device_id'] = $_device_id;
            $_devices[$array_key]['device_serial'] = $_device_serial;
            $_devices[$array_key]['services'][] = $services_array;
        }

        if ( $order_item_type == 'extras' ) {
            $extras_array = array();

            $extras_array['_device_id'] = $_device_id = wcrb_return_order_meta( $order_item_id, 'wc_extra_device' );
            $extras_array['_device_serial'] = $_device_serial = wcrb_return_order_meta( $order_item_id, 'wc_extra_device_serial' );
            $extras_array['wc_extra_code']	 = wcrb_return_order_meta( $order_item_id, 'wc_extra_code' );
            $extras_array['wc_extra_qty']	 = wcrb_return_order_meta( $order_item_id, 'wc_extra_qty' );
            $extras_array['wc_extra_price']	 = wcrb_return_order_meta( $order_item_id, 'wc_extra_price' );
            $extras_array['wc_extra_tax']	 = wcrb_return_order_meta( $order_item_id, 'wc_extra_tax' );
            $extras_array['item_name']	     = $order_item_name;

            $array_key = ( ! empty( $_device_id ) ) ? $_device_id : 'other';
            $array_key .= ( ! empty( $_device_serial ) ) ? '_' . $_device_serial : '';

            $_devices[$array_key]['device_id'] = $_device_id;
            $_devices[$array_key]['device_serial'] = $_device_serial;
            $_devices[$array_key]['extras'][] = $extras_array;
        }
    } // End for each creating array

    $wc_pin_code_show_inv = get_option( 'wc_pin_code_show_inv' );
    $wc_use_taxes         = get_option( 'wc_use_taxes' );
    $system_currency      = return_wc_rb_currency_symbol();
    $colspan              = ( $wc_use_taxes == 'on' ) ? 6 : 4;
    $prices_inclu_exclu   = ( isset( $order_id ) && ! empty( $order_id ) ) ? get_post_meta( $order_id, '_wc_prices_inclu_exclu', true ) : 'exclusive';
    $wc_device_label      = ( empty( get_option( 'wc_device_label' ) ) ) ? esc_html__( 'Device', 'computer-repair-shop' ) : get_option( 'wc_device_label' );

    $content = '';
    foreach( $_devices as $thedevice ) {
        $deviceTax = $deviceTotal = 0;

        $thedeviceid = $thedevice['device_id'];
        $thedeviceserial = $thedevice['device_serial'];

        $deviceLabel = ( empty( $thedeviceid ) ) ? esc_html__( 'Other', 'computer-repair-shop' ) : return_device_label( $thedeviceid );
        $deviceLabel .= ( ! empty( $thedeviceserial ) ) ? ' (' . $thedeviceserial . ') ' : '';

        $content .= '<table class="invoice-items">';
        $content .= ( count( $_devices ) > 1 ) ? '<tr class="heading special_head device_head"><td>' . esc_html__( $deviceLabel ) . '</td><td class="emptyhead" colspan="' . esc_attr( $colspan ) . '">&nbsp;</td></tr>' : '';

        //Process Parts
        if ( isset( $thedevice['parts'] ) && ! empty( $thedevice['parts'] ) ) :
        $parts_head = '<tr class="heading special_head">';
        $parts_head .= '<td>' . esc_html__( 'Part Name', 'computer-repair-shop' ) . '</td>';
        $parts_head .= '<td>' . esc_html__( 'Code', 'computer-repair-shop' ).'</td>';
        $parts_head .= '<td width="50">' . esc_html__( 'Qty', 'computer-repair-shop' ).'</td>';
        $parts_head .= '<td width="100">' . esc_html__( 'Price', 'computer-repair-shop' ).'</td>';
        if ($wc_use_taxes == 'on'):
            $parts_head .= '<td>'.esc_html__("Tax (%)", "computer-repair-shop").'</td>';
            $parts_head .= '<td>'.esc_html__("Tax", "computer-repair-shop") . ' (' . $system_currency . ')' . '</td>';	
        endif;
        $parts_head .= '<td>'.esc_html__("Total", "computer-repair-shop").'</td></tr>';

        $part_body = '';
        $parts_yes = 'no';
        foreach( $thedevice['parts'] as $theparts ) {
            $parts_yes = 'yes';
            
            $theQty   = (float)$theparts['wc_part_qty'];
            $thePrice = (float)$theparts['wc_part_price'];
            $theTax   = (float)$theparts['wc_part_tax'];

            if ( ! empty( $theTax ) || $wc_use_taxes == "on" ) {
                $tax_rate = ( ! empty( $theTax ) ) ? $theTax : '0';
               
                $total_price = $theQty*$thePrice;

                if ( $prices_inclu_exclu == 'inclusive' ) {
                    $calculate_tax 	= $total_price*$tax_rate/(100+$tax_rate);
                } else {
                    $calculate_tax 	= ($total_price/100)*$tax_rate;
                }
                $deviceTax += $calculate_tax;
                $calculate_tax_disp = wc_cr_currency_format( $calculate_tax, FALSE, TRUE );
            }

            $partName = $theparts['item_name'];
            $partName .= ( ! empty( $theparts['wc_part_capacity'] ) ) ? ' (' . esc_html( $theparts['wc_part_capacity'] ) . ')' : '';

            $part_body .= '<tr class="item-row wc_part_row">';
            $part_body .= '<td class="wc_part_name">' . esc_html( $partName ) . '</td>';
            $part_body .= '<td class="wc_part_code">' . esc_html( $theparts['wc_part_code'] )  . '</td>';
            $part_body .= '<td class="wc_qty">' . esc_html( $theQty ) . '</td>';
            $part_body .= '<td class="wc_price">' . esc_html( $thePrice ) . '</td>';
            if ( ! empty( $theTax ) || $wc_use_taxes == "on" ) {
                $part_body .= '<td class="wc_tax">' . esc_html( $tax_rate ) . '</td>';
                $part_body .= '<td class="wc_part_tax_price">' . esc_html( $calculate_tax_disp ) . '</td>';
            }
            $total_price_disp = ( $prices_inclu_exclu == 'inclusive' ) ? ( $thePrice * $theQty ) : ( $thePrice * $theQty ) + $calculate_tax;
            $deviceTotal += $total_price_disp;
			$total_price_disp = wc_cr_currency_format( $total_price_disp, FALSE, TRUE );

            $part_body .= '<td class="wc_price_total">' . esc_html( $total_price_disp ) . '</td>';
            $part_body .= '</tr>';
        }
        $content .= ( isset( $parts_yes ) && $parts_yes == 'yes' ) ? $parts_head . $part_body : '';
        endif;

        //Process Products
        if ( isset( $thedevice['products'] ) && ! empty( $thedevice['products'] ) ) :
        $products_head = '<tr class="heading special_head">';
        $products_head .= '<td>' . esc_html__( 'Product Name', 'computer-repair-shop' ) . '</td>';
        $products_head .= '<td>' . esc_html__( 'SKU', 'computer-repair-shop' ).'</td>';
        $products_head .= '<td width="50">' . esc_html__( 'Qty', 'computer-repair-shop' ).'</td>';
        $products_head .= '<td width="100">' . esc_html__( 'Price', 'computer-repair-shop' ).'</td>';
        if ($wc_use_taxes == 'on'):
            $products_head .= '<td>'.esc_html__("Tax (%)", "computer-repair-shop").'</td>';
            $products_head .= '<td>'.esc_html__("Tax", "computer-repair-shop") . ' (' . $system_currency . ')' . '</td>';	
        endif;
        $products_head .= '<td>'.esc_html__("Total", "computer-repair-shop").'</td></tr>';

        $products_body = '';
        $products_yes = 'no';
        foreach( $thedevice['products'] as $theproduct ) {
            $products_yes = 'yes';
            
            $theQty   = $theproduct['wc_product_qty'];
            $thePrice = $theproduct['wc_product_price'];
            $theTax   = $theproduct['wc_product_tax'];

            if ( ! empty( $theTax ) || $wc_use_taxes == "on" ) {
                $tax_rate = ( ! empty( $theTax ) ) ? $theTax : '0';
               
                $total_price = (int)$theQty*(float)$thePrice;

                if ( $prices_inclu_exclu == 'inclusive' ) {
                    $calculate_tax 	= $total_price*$tax_rate/(100+$tax_rate);
                } else {
                    $calculate_tax 	= ($total_price/100)*$tax_rate;
                }
                $deviceTax += $calculate_tax;
                $calculate_tax_disp = wc_cr_currency_format( $calculate_tax, FALSE, TRUE );
            }

            $partName = $theproduct['item_name'];

            $products_body .= '<tr class="item-row wc_part_row">';
            $products_body .= '<td class="wc_part_name">' . esc_html( $partName ) . '</td>';
            $products_body .= '<td class="wc_part_code">' . esc_html( $theproduct['wc_product_sku'] )  . '</td>';
            $products_body .= '<td class="wc_qty">' . esc_html( $theQty ) . '</td>';
            $products_body .= '<td class="wc_price">' . esc_html( $thePrice ) . '</td>';
            if ( ! empty( $theTax ) || $wc_use_taxes == "on" ) {
                $products_body .= '<td class="wc_tax">' . esc_html( $tax_rate ) . '</td>';
                $products_body .= '<td class="wc_part_tax_price">' . esc_html( $calculate_tax_disp ) . '</td>';
            }
            $total_price_disp = ( $prices_inclu_exclu == 'inclusive' ) ? ( (float)$thePrice * (int)$theQty ) : ( (float)$thePrice * (int)$theQty ) + $calculate_tax;
            $deviceTotal += $total_price_disp;
			$total_price_disp = wc_cr_currency_format( $total_price_disp, FALSE, TRUE );

            $products_body .= '<td class="wc_price_total">' . esc_html( $total_price_disp ) . '</td>';
            $products_body .= '</tr>';
        }
        $content .= ( isset( $products_yes ) && $products_yes == 'yes' ) ? $products_head . $products_body : '';
        endif;

        //Process Services
        if ( isset( $thedevice['services'] ) && ! empty( $thedevice['services'] ) ) :        
        $services_head = '<tr class="heading special_head">';
        $services_head .= '<td>' . esc_html__( 'Service Name', 'computer-repair-shop' ) . '</td>';
        $services_head .= '<td>' . esc_html__( 'Code', 'computer-repair-shop' ).'</td>';
        $services_head .= '<td width="50">' . esc_html__( 'Qty', 'computer-repair-shop' ).'</td>';
        $services_head .= '<td width="100">' . esc_html__( 'Price', 'computer-repair-shop' ).'</td>';
        if ($wc_use_taxes == 'on'):
            $services_head .= '<td>'.esc_html__("Tax (%)", "computer-repair-shop").'</td>';
            $services_head .= '<td>'.esc_html__("Tax", "computer-repair-shop") . ' (' . $system_currency . ')' . '</td>';	
        endif;
        $services_head .= '<td>'.esc_html__("Total", "computer-repair-shop").'</td></tr>';

        $services_body = '';
        $services_yes = 'no';
        foreach( $thedevice['services'] as $theservice ) {
            $services_yes = 'yes';

            $theQty   = $theservice['wc_service_qty'];
            $thePrice = $theservice['wc_service_price'];
            $theTax   = $theservice['wc_service_tax'];

            if ( ! empty( $theTax ) || $wc_use_taxes == "on" ) {
                $tax_rate = ( ! empty( $theTax ) ) ? $theTax : '0';
               
                $total_price = (float)$theQty*(float)$thePrice;

                if ( $prices_inclu_exclu == 'inclusive' ) {
                    $calculate_tax 	= $total_price*$tax_rate/(100+$tax_rate);
                } else {
                    $calculate_tax 	= ($total_price/100)*$tax_rate;
                }
                $deviceTax += $calculate_tax;
                $calculate_tax_disp = wc_cr_currency_format( $calculate_tax, FALSE, TRUE );
            }

            $partName = $theservice['item_name'];

            $services_body .= '<tr class="item-row wc_part_row">';
            $services_body .= '<td class="wc_part_name">' . esc_html( $partName ) . '</td>';
            $services_body .= '<td class="wc_part_code">' . esc_html( $theservice['wc_service_code'] )  . '</td>';
            $services_body .= '<td class="wc_qty">' . esc_html( $theQty ) . '</td>';
            $services_body .= '<td class="wc_price">' . esc_html( $thePrice ) . '</td>';
            if ( ! empty( $theTax ) || $wc_use_taxes == "on" ) {
                $services_body .= '<td class="wc_tax">' . esc_html( $tax_rate ) . '</td>';
                $services_body .= '<td class="wc_part_tax_price">' . esc_html( $calculate_tax_disp ) . '</td>';
            }
            $total_price_disp = ( $prices_inclu_exclu == 'inclusive' ) ? ( (float)$thePrice * (float)$theQty ) : ( (float)$thePrice * (float)$theQty ) + $calculate_tax;
            $deviceTotal += $total_price_disp;
			$total_price_disp = wc_cr_currency_format( $total_price_disp, FALSE, TRUE );

            $services_body .= '<td class="wc_price_total">' . esc_html( $total_price_disp ) . '</td>';
            $services_body .= '</tr>';
        }
        $content .= ( isset( $services_yes ) && $services_yes == 'yes' ) ? $services_head . $services_body : '';
        endif;

        //Process Extras
        if ( isset( $thedevice['extras'] ) && ! empty( $thedevice['extras'] ) ) :        
            $extra_head = '<tr class="heading special_head">';
            $extra_head .= '<td>' . esc_html__( 'Extra Name', 'computer-repair-shop' ) . '</td>';
            $extra_head .= '<td>' . esc_html__( 'Code', 'computer-repair-shop' ).'</td>';
            $extra_head .= '<td width="50">' . esc_html__( 'Qty', 'computer-repair-shop' ).'</td>';
            $extra_head .= '<td width="100">' . esc_html__( 'Price', 'computer-repair-shop' ).'</td>';
            if ($wc_use_taxes == 'on'):
                $extra_head .= '<td>'.esc_html__("Tax (%)", "computer-repair-shop").'</td>';
                $extra_head .= '<td>'.esc_html__("Tax", "computer-repair-shop") . ' (' . $system_currency . ')' . '</td>';	
            endif;
            $extra_head .= '<td>'.esc_html__("Total", "computer-repair-shop").'</td></tr>';
    
            $extra_body = '';
            $extra_yes = 'no';
            foreach( $thedevice['extras'] as $theextra ) {
                $extra_yes = 'yes';
    
                $theQty   = $theextra['wc_extra_qty'];
                $thePrice = $theextra['wc_extra_price'];
                $thePrice = (float)$thePrice;
                $theTax   = $theextra['wc_extra_tax'];
    
                if ( ! empty( $theTax ) || $wc_use_taxes == "on" ) {
                    $tax_rate = ( ! empty( $theTax ) ) ? $theTax : '0';
                   
                    $total_price = (int)$theQty*(float)$thePrice;
    
                    if ( $prices_inclu_exclu == 'inclusive' ) {
                        $calculate_tax 	= $total_price*$tax_rate/(100+$tax_rate);
                    } else {
                        $calculate_tax 	= ($total_price/100)*$tax_rate;
                    }
                    $deviceTax += $calculate_tax;
                    $calculate_tax_disp = wc_cr_currency_format( $calculate_tax, FALSE, TRUE );
                }
    
                $partName = $theextra['item_name'];
    
                $extra_body .= '<tr class="item-row wc_part_row">';
                $extra_body .= '<td class="wc_part_name">' . esc_html( $partName ) . '</td>';
                $extra_body .= '<td class="wc_part_code">' . esc_html( $theextra['wc_extra_code'] )  . '</td>';
                $extra_body .= '<td class="wc_qty">' . esc_html( $theQty ) . '</td>';
                $extra_body .= '<td class="wc_price">' . esc_html( $thePrice ) . '</td>';
                if ( ! empty( $theTax ) || $wc_use_taxes == "on" ) {
                    $extra_body .= '<td class="wc_tax">' . esc_html( $tax_rate ) . '</td>';
                    $extra_body .= '<td class="wc_part_tax_price">' . esc_html( $calculate_tax_disp ) . '</td>';
                }
                $total_price_disp = ( $prices_inclu_exclu == 'inclusive' ) ? ( $thePrice * (int)$theQty ) : ( $thePrice * (int)$theQty ) + $calculate_tax;
                $deviceTotal += $total_price_disp;
                $total_price_disp = wc_cr_currency_format( $total_price_disp, FALSE, TRUE );
    
                $extra_body .= '<td class="wc_price_total">' . esc_html( $total_price_disp ) . '</td>';
                $extra_body .= '</tr>';
            }
            $content .= ( isset( $extra_yes ) && $extra_yes == 'yes' ) ? $extra_head . $extra_body : '';
            endif;

                        
        $content .= '</table>';

        $content .= '<div class="invoice_totals"><table><tr>';
        if ( $wc_use_taxes == 'on' || $deviceTax > 0 ):
            $content .= '<th>'.esc_html__("Tax", "computer-repair-shop").'</th><td>' . wc_cr_currency_format( $deviceTax, FALSE ) . '</td>';
        endif;
        $content .= '<th>' . esc_html( $wc_device_label ) . ' ' . esc_html__("Total", "computer-repair-shop") . '</th><td>' . wc_cr_currency_format( $deviceTotal, FALSE ) . '</td>';
        $content .= '</tr></table></div>';
    }
    return $content;
}
endif;

if ( ! function_exists( 'rb_return_order_items' ) ) :
function rb_return_order_items( $order_id, $arguments_d ) {

    if ( empty( $order_id ) ) {
        return;
    }
    $arguments_d = ( empty( $arguments_d ) ) ? $order_id : $arguments_d;

    $system_currency = return_wc_rb_currency_symbol();
    $wc_use_taxes    = get_option( 'wc_use_taxes' );
    
    if ( ! wc_rs_license_state() ) :
        return wc_cr_new_purchase_link("");
    endif;

    $content = '';
    if ( !empty( wc_print_existing_parts( $order_id ) ) ) :
        $content .= '<table class="invoice-items">
                        <tr class="heading special_head">
                            <td>' . esc_html__( 'Part Name', 'computer-repair-shop' ) . '</td>
                            <td>' . esc_html__( 'Code', 'computer-repair-shop' ).'</td>
                            <td>' . esc_html__( 'Capacity', 'computer-repair-shop' ).'</td>
                            <td width="50">' . esc_html__( 'Qty', 'computer-repair-shop' ).'</td>
                            <td width="100">' . esc_html__( 'Price', 'computer-repair-shop' ).'</td>';
        if($wc_use_taxes == 'on'):
            $content .= '<td>'.esc_html__("Tax (%)", "computer-repair-shop").'</td>';
            $content .= '<td>'.esc_html__("Tax", "computer-repair-shop") . ' (' . $system_currency . ')' . '</td>';	
        endif;
        $content	.= '<td>'.esc_html__("Total", "computer-repair-shop").'</td>
                        </tr>
                        ' . wc_print_existing_parts( $arguments_d ) . '
                    </table>';
        $content .= '<div class="invoice_totals"><table><tr>';
        if($wc_use_taxes == 'on'):
            $partsTax = wc_order_grand_total( $order_id, 'parts_tax' );
            $content .= '<th>'.esc_html__("Parts Tax", "computer-repair-shop").'</th><td>' . wc_cr_currency_format( $partsTax, FALSE ) . '</td>';
        endif;
        $partsTotal = wc_order_grand_total( $order_id, 'parts_total' );
        $content .= '<th>'.esc_html__("Parts Total", "computer-repair-shop").'</th><td>' . wc_cr_currency_format( $partsTotal, FALSE ) . '</td>';
        $content .= '</tr></table></div>';
    endif;

    if(!empty(wc_print_existing_products($order_id))):
        $content .= '<table class="invoice-items">
                        <tr class="heading special_head">
                            <td>'.esc_html__("Product Name", "computer-repair-shop").'</td>
                            <td>'.esc_html__("SKU", "computer-repair-shop").'</td>
                            <td width="50">'.esc_html__("Qty", "computer-repair-shop").'</td>
                            <td width="100">'.esc_html__("Price", "computer-repair-shop").'</td>';
        if($wc_use_taxes == 'on'):
            $content .= '<td>'.esc_html__("Tax (%)", "computer-repair-shop").'</td>';
            $content .= '<td>'.esc_html__("Tax", "computer-repair-shop") . ' (' . $system_currency . ')' . '</td>';	
        endif;

        $content	.= '<td>'.esc_html__("Total", "computer-repair-shop").'</td>
                        </tr>
                        '.wc_print_existing_products($arguments_d).'
                    </table>';
        $content .= '<div class="invoice_totals"><table><tr>';
        if($wc_use_taxes == 'on'):
            $productsTax = wc_order_grand_total( $order_id, 'products_tax' );
            $content .= '<th>'.esc_html__("Products Tax", "computer-repair-shop").'</th><td>' . wc_cr_currency_format( $productsTax, FALSE ) . '</td>';
        endif;
        $productsTotal = wc_order_grand_total( $order_id, 'products_total' );
        $content .= '<th>'.esc_html__("Products Total", "computer-repair-shop").'</th><td>' . wc_cr_currency_format( $productsTotal, FALSE) . '</td>';
        $content .= '</tr></table></div>';
    endif;
    
    if ( ! empty( wc_print_existing_services( $order_id ) ) ):
        $content .= '<table class="invoice-items">
                        <tr class="heading special_head">
                            <td>'.esc_html__("Service Name", "computer-repair-shop").'</td>
                            <td>'.esc_html__("Code", "computer-repair-shop").'</td>
                            <td width="50">'.esc_html__("Qty", "computer-repair-shop").'</td>
                            <td width="100">'.esc_html__("Price", "computer-repair-shop").'</td>';
        if($wc_use_taxes == 'on'):
            $content .= '<td>'.esc_html__("Tax (%)", "computer-repair-shop").'</td>';
            $content .= '<td>'.esc_html__("Tax", "computer-repair-shop") . ' (' . $system_currency . ')' . '</td>';	
        endif;

        $content .= '<td>'.esc_html__("Total", "computer-repair-shop").'</td>
                        </tr>
                        ' . wc_print_existing_services( $arguments_d ) . '
                    </table>';
        $content .= '<div class="invoice_totals"><table><tr>';
        if($wc_use_taxes == 'on'):
            $servicesTax = wc_order_grand_total( $order_id, 'services_tax' );
            $content .= '<th>'.esc_html__("Services Tax", "computer-repair-shop").'</th><td>' . wc_cr_currency_format( $servicesTax, FALSE ) . '</td>';
        endif;
        $servicesTotal = wc_order_grand_total( $order_id, 'services_total' );
        $content .= '<th>'.esc_html__("Services Total", "computer-repair-shop").'</th><td>' . wc_cr_currency_format( $servicesTotal, FALSE ) . '</td>';
        $content .= '</tr></table></div>';
    endif;
    
    if(!empty(wc_print_existing_extras($order_id))):
        $content .= '<table class="invoice-items">
                        <tr class="heading special_head">
                            <td>'.esc_html__("Extra Name", "computer-repair-shop").'</td>
                            <td>'.esc_html__("Code", "computer-repair-shop").'</td>
                            <td width="50">'.esc_html__("Qty", "computer-repair-shop").'</td>
                            <td width="100">'.esc_html__("Price", "computer-repair-shop").'</td>';
        if($wc_use_taxes == 'on'):
            $content .= '<td>'.esc_html__("Tax (%)", "computer-repair-shop").'</td>';
            $content .= '<td>'.esc_html__("Tax", "computer-repair-shop") . ' (' . $system_currency . ')' . '</td>';	
        endif;
        $content .= '<td>'.esc_html__("Total", "computer-repair-shop").'</td>
                        </tr>
                        '.wc_print_existing_extras( $arguments_d ).'
                    </table>';
        
        $content .= '<div class="invoice_totals"><table><tr>';
        if($wc_use_taxes == 'on'):
            $extrasTax = wc_order_grand_total( $order_id, 'extras_tax' );
            $content .= '<th>'.esc_html__("Extras Tax", "computer-repair-shop").'</th><td>' . wc_cr_currency_format( $extrasTax, FALSE ) . '</td>';
        endif;
        $extrasTotal = wc_order_grand_total( $order_id, 'extras_total' );
        $content .= '<th>'.esc_html__("Extras Total", "computer-repair-shop").'</th><td>' . wc_cr_currency_format( $extrasTotal, FALSE ) . '</td>';
        $content .= '</tr></table></div>';
    endif;

    return $content;
}
endif;