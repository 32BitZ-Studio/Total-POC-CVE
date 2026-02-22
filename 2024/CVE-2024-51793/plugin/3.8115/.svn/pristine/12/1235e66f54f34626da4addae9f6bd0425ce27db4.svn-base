<?php
    defined( 'ABSPATH' ) || exit;
    
    /**
     * Report Functions
     * 
     * Holds Various functions related to print functionality of reports
     */
    if(!function_exists("print_report_criteria_select_form")): 
        function print_report_criteria_select_form($type, $range) {
            //"date_range", "selected_today"

            if ( empty( $type ) ) {
                return;
            }
            if ( empty( $range ) ) {
                return;
            }
            $content = '<div id="invoice-box" class="invoice-box">';

            if ( $type == "date_range" ) {
                $today = date( "Y-m-d" );

                $content .= "<h2 class='text-center select-head'>".esc_html__("Select options to generate report", "computer-repair-shop")."</h2>";
                $content .= "<form method='get' action=''>";

                $content .= '<div class="grid-container">';
                $content .= '<div class="grid-x grid-margin-x">';
                  
                $content .= '<div class="medium-6 cell">';
                $content .= '<label>'.esc_html__("From Date", "computer-repair-shop");
                $content .= '<input type="date" name="start_date" value="'.$today.'">';
                $content .= '</label>';
                $content .= '</div>';

                $content .= '<div class="medium-6 cell">';
                $content .= '<label>'.esc_html__("To Date", "computer-repair-shop");
                $content .= '<input type="date" name="end_date" value="'.$today.'">';
                $content .= '</label>';
                $content .= '</div>';

                $content .= '</div></div>';

                $content .= '<fieldset class="fieldset">
                            <legend>'.esc_html__("Select job status to include", "computer-repair-shop").'</legend>';
                $content .= wc_generate_status_checkboxes();
                $content .= '</fieldset>';

                $content .= '<fieldset class="fieldset">
                            <legend>'.esc_html__("Select payment status to include", "computer-repair-shop").'</legend>';
                
                $content .= wc_generate_payment_status_checkboxes();

                $content .= '</fieldset>';

                $content .= '<input type="hidden" name="page" value="wc_computer_repair_print" />';
                $content .= '<input type="hidden" name="print_reports" value="YES" />';
                $content .= '<input type="hidden" name="report_type" value="daily_sales_summary" />';

                $content .= '<input type="submit" class="button button-primary" value="'.esc_html__("Generate Report", "computer-repair-shop").'">';

                $content .= "</form>";
            }
            $content .= '</div>';

            $allowedHTML = wc_return_allowed_tags(); 
            echo wp_kses($content, $allowedHTML);
        }
    endif;

    /**
     * Generate Job Status 
     * 
     * CheckBox options
     * Options with labels
     */
    if(!function_exists("wc_generate_status_checkboxes")):
		function wc_generate_status_checkboxes() {
			global $wpdb;

			$field_to_select 	= "status_slug";
			
			//Table
			$computer_repair_job_status 	= $wpdb->prefix.'wc_cr_job_status';

			$select_query 	= "SELECT * FROM `".$computer_repair_job_status."` WHERE `status_status`='active'";
            $select_results = $wpdb->get_results( $select_query );

			$output = '<div class="selectunselect"><a href="#" checkbox-toggle-group="job_status_include" class="unselect">'. esc_html__( 'Select/Unselect All', 'computer-repair-shop' ) .'</a></div>';
			foreach($select_results as $result) {
                $output .= '<input checked name="job_status_include[]" value="'.esc_attr($result->$field_to_select).'" id="'.esc_attr($result->$field_to_select).'" type="checkbox">';
                $output .= '<label for="'.esc_attr($result->$field_to_select).'">'.esc_attr($result->status_name).'</label>';
			} // End Foreach	

			return $output;
		}
	endif;

    /**
     * Generate Payment Options
     * 
     * Checkbox Options
     * Options with labels
     */
    if(!function_exists("wc_generate_payment_status_checkboxes")):
		function wc_generate_payment_status_checkboxes() {
            global $PAYMENT_STATUS_OBJ;

			$payment_status = $PAYMENT_STATUS_OBJ->wc_generate_payment_status_array( 'active' );

			$output = '<div class="selectunselect"><a href="#" checkbox-toggle-group="payment_status_include" class="unselect">'. esc_html__( 'Select/Unselect All', 'computer-repair-shop' ) .'</a></div>';
			foreach($payment_status as $key => $value ) {
                $output .= '<input checked name="payment_status_include[]" value="'.esc_attr($key).'" id="'.esc_attr($key).'" type="checkbox">';
                $output .= '<label for="'.esc_attr($key).'">'.esc_attr($value).'</label>';
			} // End Foreach	

			return $output;
		}
	endif;

    /**
     * Generate Sale Report
     * 
     * List sales by 
     * 
     * $args brings
     * start_date
     * end_date
     * 
     * payment_status_include Array
     * job_status_include Array
     * report_type daily_sales_summary
     */
    if(!function_exists("wc_generate_sale_report")):
        function wc_generate_sale_report($args) {
            if(!isset($args["report_type"]) || empty($args["report_type"])) {
                return esc_html__("Report is not defined", "computer-repair-shop");
            }
            $args['job_status_include']     = ( isset( $_GET['job_status_include'] ) ) ? array_map( 'sanitize_text_field', $_GET['job_status_include'] ) : '';
    		$args['payment_status_include'] = ( isset( $_GET['payment_status_include'] ) ) ? array_map( 'sanitize_text_field', $_GET['payment_status_include'] ) : '';
            $job_status_include             = (!isset($args["job_status_include"]) || empty($args["job_status_include"])) ? "" : $args["job_status_include"];
            $payment_status_include         = (!isset($args["payment_status_include"]) || empty($args["payment_status_include"])) ? "" : $args["payment_status_include"];

            $report_heading     = "unknown";

            if($args["report_type"] == "daily_sales_summary") {
                $report_heading = esc_html__("Daily Sales Summary", "computer-repair-shop");
            }

            $from_date  = (!empty($args["start_date"])) ? $args["start_date"] : "2020-01-01";
            $to_date    = (!empty($args["end_date"])) ? $args["end_date"] : "2025-01-01";

            $content = '<div class="invoice-box report-container">';
            $content .= wc_get_report_head($report_heading);

            $content .= '<div id="table_div">';
            $content .= '<div class="wc-rb-report-title">';
            $content .= '<h2>'.$report_heading.'</h2>';
            $content .= '</div>';

            $date_format = get_option('date_format');
            
            $from_date_fr  = (!empty($from_date)) ? date($date_format, strtotime($from_date)) : "";
            $to_date_fr    = (!empty($to_date)) ? date($date_format, strtotime($to_date)) : "";

            $content .= '<div class="wc-rb-report-period">';
            $content .= '<p><span class="todayDate"><strong>'.esc_html__("Today", "computer-repair-shop").':</strong> '.date($date_format).' </span><span class="statementPeriod"><strong>';
    		$content .= esc_html__("Statement Period", "computer-repair-shop").':</strong> '.$from_date_fr.' - '.$to_date_fr . '</span></p>';

            $wc_device_label = ( empty( get_option( 'wc_device_label' ) ) ) ? esc_html__( 'Device', 'computer-repair-shop' ) : get_option( 'wc_device_label' );

            $content .= '</div><!--account_info -->
            <div class="clearIt"></div>
            <table class="invoice-items">
                <thead>';
            
            $content .= '<tr class="heading special_head">
                            <td>'.esc_html__("Date", "computer-repair-shop").'</td>
                            <td>'.esc_html__("Customer", "computer-repair-shop") . '/' . $wc_device_label . '/' . esc_html__("Tech", "computer-repair-shop") . '</td>
                            <td>'.esc_html__("Delivery", "computer-repair-shop").'</td>
                            <td>'.esc_html__("Status", "computer-repair-shop").'</td>
                            <td>'.esc_html__("Payment", "computer-repair-shop").'</td>
                            <td>'.esc_html__("Parts", "computer-repair-shop").'</td>
                            <td>'.esc_html__("Services", "computer-repair-shop").'</td>
                            <td>'.esc_html__("Extras", "computer-repair-shop").'</td>
                            <td>'.esc_html__("Tax", "computer-repair-shop").'</td>
                            <td>'.esc_html__("Total", "computer-repair-shop").'</td>
                        </tr>
                    </thead>';

            $content .= '<tbody>';

            $arguments = array(
                "job_status_include"        => $job_status_include,
                "payment_status_include"    => $payment_status_include,
                "report_type"               => $args["report_type"],
            );
            $get_job_data = wc_return_job_ids_by_filters( $from_date, $to_date, $arguments );

            $content .= $get_job_data["the_content"];

            $content .= '</tbody>
            </table>';

            $content .= '<div class="invoice_totals">
                            <table style="max-width:100%;">
                                <tbody>
                                    <tr>
                                        <th>' . esc_html__("Parts Total", "computer-repair-shop") . '</th>
                                        <td>' . wc_cr_currency_format( $get_job_data["parts_grand_total"], FALSE, TRUE ) .'</td>
                                    </tr><tr>
                                        <th>' . esc_html__("Services Total", "computer-repair-shop") . '</th>
                                        <td>' . wc_cr_currency_format( $get_job_data["services_grand_total"], FALSE, TRUE ) . '</td>
                                        </tr><tr>
                                        <th>' . esc_html__("Extras Total", "computer-repair-shop") . '</th>
                                        <td>' . wc_cr_currency_format( $get_job_data["extras_grand_total"], FALSE, TRUE ) . '</td>
                                        </tr><tr>
                                        <th>' . esc_html__("Taxes Total", "computer-repair-shop") . '</th>
                                        <td>' . wc_cr_currency_format( $get_job_data["taxes_grand_total"], FALSE, TRUE ) . '</td>
                                        </tr><tr>
                                        <th>' . esc_html__("Grand Total", "computer-repair-shop") . '</th>
                                        <td>' . wc_cr_currency_format( $get_job_data["statement_grand_total"], TRUE, TRUE ) . '</td>
                                    </tr>
                                </tbody>
                            </table>
                        </div>';
            if ( ! wc_rs_license_state() ) :
                $content .= wc_cr_new_purchase_link("");
            endif;
            $content .= '<p align="center">'.esc_html__("This is computer generated statement does not need signature.", "computer-repair-shop").'</p>
            </div>';

            $content .= '<button id="btnPrint" class="hidden-print button button-primary">'.esc_html__("Print", "computer-repair-shop").'</button>';
            $content .= '</div><!-- Invoice Box /-->';

            $allowedHTML = wc_return_allowed_tags();
            echo wp_kses( $content, $allowedHTML );
        }
    endif;

    if(!function_exists("wc_get_report_head")): 
        function wc_get_report_head($heading) {
            $wc_rb_business_name	= get_option("wc_rb_business_name");
            $wc_rb_business_phone	= get_option("wc_rb_business_phone");
            $wc_rb_business_address	= get_option("wc_rb_business_address");

            $wc_rb_business_name	= (empty($wc_rb_business_name)) ? get_bloginfo( 'name' ) : $wc_rb_business_name;

            $computer_repair_email = get_option("computer_repair_email");

            if(empty($computer_repair_email)) {
                $computer_repair_email	= get_option("admin_email");	
            }

            $content = '<div class="company_info"><div class="company_logo_wrap">';
            $content .= wc_rb_return_logo_url_with_img("company_logo");
            $content .= "</div><div class='address-side'><h2>".$wc_rb_business_name."</h2>";
            $content .= "<p>";
            $content .= $wc_rb_business_address;
            $content .= (!empty($computer_repair_email)) ? "<br><strong>".esc_html__("Email", "computer-repair-shop")."</strong>: ".$computer_repair_email : "";
            $content .= (!empty($wc_rb_business_phone)) ? "<br><strong>".esc_html__("Phone", "computer-repair-shop")."</strong>: ".$wc_rb_business_phone : "";
            $content .= "</p></div>";
            $content .= '</div>';

            return $content;
        }
    endif;

    /**
	 * Function Returns Job IDS 
	 * 
	 * Returns job Id's
	 * 
	 * Filter Jobs by various conditions
     * Takes an array of arguments. 
     * array(
         "start_date" => "",
         "end_date" => "",
         "job_status_include" => array()
         "payment_status_include" => array()
         "page" => "",
         "print_reports" => "",
         "report_type" => "",
     );
	 */
	if(!function_exists("wc_return_job_ids_by_filters")):
		function wc_return_job_ids_by_filters( $from_date, $end_date, $arges ) {
			if ( ! is_user_logged_in() ) {
				return esc_html__("You are not logged in.", "computer-repair-shop");
				exit;
			}
            global $wpdb;

            //Get Arguments here. Getting
            //Start working here ATeeq
            // Check Array if not then fix it and work on it.
            $modify_str = $start_date = ( ! empty( $from_date ) ) ? date('Y-m-d H:i:s', strtotime( str_replace( '-', '/', $from_date ) ) ) : "2020-01-01";
            $modify_end = $end_date   = ( ! empty( $end_date ) ) ? date('Y-m-d H:i:s', strtotime( str_replace( '-', '/', $end_date ) ) ) : "2025-01-01";
            
            $job_status     = (!empty($arges["job_status_include"])) ? $arges["job_status_include"] : array(); 
            $payment_status = (!empty($arges["payment_status_include"])) ? $arges["payment_status_include"] : array();
            $technician     = ( isset( $arges["technician"] ) && ! empty( $arges["technician"] ) ) ? $arges["technician"] : array();
            $customer     = ( isset( $arges["customer"] ) && ! empty( $arges["customer"] ) ) ? $arges["customer"] : array();
            $report_type    = (!empty($arges["report_type"])) ? $arges["report_type"] : "daily_sales_summary";

            //Query posts.
            $sql_query = "SELECT 
                            `ID` 
                        FROM 
                            `".$wpdb->prefix."posts` 
                        WHERE 
                            `post_type`='rep_jobs'
                        AND
                            (`post_date` between '%s' and '%s'    
                        OR 
                            `post_modified` between '%s' and '%s')
                        ";
            $query = $wpdb->prepare( $sql_query, $start_date, $end_date, $modify_str, $modify_end );

            $results = $wpdb->get_results( $query, ARRAY_A );
            $posts_discovered_in_date = array();

            if ( ! empty( $results ) ) {
                foreach( $results as $result ) {
                    $posts_discovered_in_date[] = $result['ID'];
                }
            }

            if(empty($posts_discovered_in_date)) {
                $return_array = array(
                    "the_content"           => esc_html__("Couldn't find any post related to given date range.", "computer-repair-shop"),
                    "parts_grand_total"     => "0.00",   
                    "services_grand_total"  => "0.00",
                    "extras_grand_total"    => "0.00",   
                    "taxes_grand_total"     => "0.00",    
                    "statement_grand_total" => "0.00"
                );
                return $return_array;
            }

            $meta_query_arr = array();
            
            if ( ! empty( $job_status ) ) {
                $meta_query_arr[] = array(
                    'key'		=> "_wc_order_status",
                    'value'		=> wc_rb_sanitize_non_index_array( $job_status ),
                    'compare'	=> 'IN',
                );
            }
            if ( ! empty( $payment_status ) ) {
                $meta_query_arr[] = array(
                    'key'		=> "_wc_payment_status",
                    'value'		=> wc_rb_sanitize_non_index_array($payment_status),
                    'compare'	=> 'IN',
                );
            }
            if ( ! empty( $technician ) ) {
                $meta_query_arr[] = array(
                    'key'   => '_technician',
                    'value' => sanitize_text_field( $technician ),
                    'compare' => '=',
                    'type'    => 'NUMERIC',
                );
            }
            if ( ! empty( $customer ) ) {
                $meta_query_arr[] = array(
                    'key'   => '_customer',
                    'value' => sanitize_text_field( $customer ),
                    'compare' => '=',
                    'type'    => 'NUMERIC',
                );
            }
			//WordPress Query for Rep Jobs
			$jobs_args = array(
				'post_type' 		=> "rep_jobs",
				'orderby'			=> 'id',
				'order' 			=> 'DESC',
				'posts_per_page' 	=> -1,
                'post__in'          => wc_rb_sanitize_non_index_array( $posts_discovered_in_date ),
				'post_status'		=> array( 'publish', 'pending', 'future', 'draft', 'private' ),
				'meta_query' 		=> $meta_query_arr,
			);

			$jobs_query         = new WP_Query( $jobs_args );
            
            $content            = "";
            $parts_grand_total      = 0;
            $services_grand_total   = 0;
            $extras_grand_total     = 0;
            $taxes_grand_total      = 0;
            $statement_grand_total  = 0;
            //Generate here.

            if($jobs_query->have_posts()): while($jobs_query->have_posts()):
                $jobs_query->the_post();

                $job_id 		= $jobs_query->post->ID;
                $case_number 	= get_post_meta( $job_id, "_case_number", true ); 
                $order_date 	= get_the_date( 'd/m/Y', $job_id );
                $payment_status = get_post_meta($job_id, "_wc_payment_status_label", true);
                $job_status		= get_post_meta($job_id, "_wc_order_status_label", true);
                $technician 	= get_post_meta($job_id, "_technician", true);
                $customer 	    = get_post_meta($job_id, "_customer", true);

                //Getting Totals
                $order_total 	= filter_var(wc_order_grand_total($job_id, "grand_total"), FILTER_SANITIZE_NUMBER_FLOAT, FILTER_FLAG_ALLOW_FRACTION);
                $parts_total 	= filter_var(wc_order_grand_total($job_id, "parts_total"), FILTER_SANITIZE_NUMBER_FLOAT, FILTER_FLAG_ALLOW_FRACTION);
                $products_total	= filter_var(wc_order_grand_total($job_id, "products_total"), FILTER_SANITIZE_NUMBER_FLOAT, FILTER_FLAG_ALLOW_FRACTION);
                $services_total	= filter_var(wc_order_grand_total($job_id, "services_total"), FILTER_SANITIZE_NUMBER_FLOAT, FILTER_FLAG_ALLOW_FRACTION);
                $extras_total	= filter_var(wc_order_grand_total($job_id, "extras_total"), FILTER_SANITIZE_NUMBER_FLOAT, FILTER_FLAG_ALLOW_FRACTION);

                $parts_tax	    = filter_var(wc_order_grand_total($job_id, "parts_tax"), FILTER_SANITIZE_NUMBER_FLOAT, FILTER_FLAG_ALLOW_FRACTION);
                $products_tax	= filter_var(wc_order_grand_total($job_id, "products_tax"), FILTER_SANITIZE_NUMBER_FLOAT, FILTER_FLAG_ALLOW_FRACTION);
                $services_tax	= filter_var(wc_order_grand_total($job_id, "services_tax"), FILTER_SANITIZE_NUMBER_FLOAT, FILTER_FLAG_ALLOW_FRACTION);
                $extras_tax	    = filter_var(wc_order_grand_total($job_id, "extras_tax"), FILTER_SANITIZE_NUMBER_FLOAT, FILTER_FLAG_ALLOW_FRACTION);

                $parts_grand    = (float)$parts_total+(float)$products_total;
                $parts_grand    = (float)$parts_grand-(float)$parts_tax-(float)$products_tax;
                $extras_total   = (float)$extras_total-(float)$extras_tax;
                $services_total = (float)$services_total-(float)$services_tax;
                
                $tax_total      = (float)$parts_tax+(float)$products_tax+(float)$services_tax+(float)$extras_tax;

                $parts_grand_total      += $parts_grand;
                $services_grand_total   += $services_total;
                $extras_grand_total     += $extras_total;
                $taxes_grand_total      += $tax_total;
                $statement_grand_total  += $order_total;

                $delivery_date = get_post_meta($job_id, '_delivery_date', true);
			
                if(!empty($delivery_date)) {
                    $date_format = "d/m/Y";
                    $delivery_date = date_i18n($date_format, strtotime($delivery_date));
                }

                $tech_name = "";
				if(!empty($technician)) : 
					$tech_user 		= get_user_by('id', $technician);
					$tech_name 		=  $tech_user->first_name . ' ' . $tech_user->last_name;
				endif;

                $content .= "<tr class='item-row wc_extra_row'>";
                $content .= "<td>".esc_html($order_date)."</td>";

                $content .= "<td>";
                
                if(!empty($customer)) {
                    $user 			= get_user_by('id', $customer);
                    $phone_number 	= get_user_meta($customer, "billing_phone", true);
                    $company 		= get_user_meta($customer, "billing_company", true);
    
                    $first_name		= empty($user->first_name)? "" : $user->first_name;
                    $last_name 		= empty($user->last_name)? "" : $user->last_name;
                    $content        .=  $first_name. ' ' .$last_name ;
    
                    if(!empty($phone_number)) {
                        //$content .= "<br>".esc_html__("Phone", "computer-repair-shop").": ".$phone_number;	
                    }
                    if(!empty($company)) {
                        //$content .= "<br>".esc_html__("Company", "computer-repair-shop").": ".$company;	
                    }
                }

                $device_id 		 = get_post_meta($job_id, '_device_id', true);
                $current_devices = get_post_meta( $job_id, '_wc_device_data', true );
                $wc_device_label = ( empty( get_option( 'wc_device_label' ) ) ) ? esc_html__( 'Device', 'computer-repair-shop' ) : get_option( 'wc_device_label' );

                if ( ! empty( $current_devices )  && is_array( $current_devices ) ) {
                    $counter = 0;
                    foreach( $current_devices as $device_data ) {
                        $content .= ( $counter != 0 ) ? '<br>' : '<br><strong>' . $wc_device_label . ' : </strong>';				
                        $device_post_id = ( isset( $device_data['device_post_id'] ) ) ? $device_data['device_post_id'] : '';
        
                        $content .= return_device_label( $device_post_id );
                        $counter++;
                    }
                }

                if(!empty($device_id)) {
                    //$content .= "<br>".esc_html__("ID/IMEI", "computer-repair-shop").": ".esc_html($device_id);	
                }
                $content .= "<br>".esc_html__("Case#", "computer-repair-shop").": ".esc_html($case_number);
                if(!empty($tech_name) && $report_type != 'jobs_by_technician' ):
                    $content .= "<br>".esc_html__("Technician", "computer-repair-shop").": ".esc_html($tech_name);
                endif;
                $content .= "</td>";

                $content .= "<td>".esc_html($delivery_date)."</td>";
                $content .= "<td>".esc_html($job_status)."</td>";
                $content .= "<td>".esc_html($payment_status)."</td>";

                $content .= "<td>" . wc_cr_currency_format( $parts_grand, FALSE ) . "</td>";
                $content .= "<td>" . wc_cr_currency_format( $services_total, FALSE ) . "</td>";
                $content .= "<td>" . wc_cr_currency_format( $extras_total, FALSE ) . "</td>";
                $content .= "<td>" . wc_cr_currency_format( $tax_total, FALSE ) . "</td>";
                $content .= "<td>" . wc_cr_currency_format( $order_total, FALSE ) . "</td>";
                $content .= "</tr>";
            endwhile; endif;
            
			wp_reset_postdata();

            $return_array = array(
                "the_content"           => $content,
                "parts_grand_total"     => $parts_grand_total,   
                "services_grand_total"  => $services_grand_total,
                "extras_grand_total"    => $extras_grand_total,   
                "taxes_grand_total"     => $taxes_grand_total,    
                "statement_grand_total" => $statement_grand_total
            );

            return $return_array;
		}
	endif;

    if(!function_exists("wc_rb_sanitize_non_index_array")): 
        function wc_rb_sanitize_non_index_array($array_given) {
            if(!is_array($array_given)) {
                return "";
            }
            if(empty($array_given)) {
                return "";
            }

            $return_array = array();
            foreach( $array_given as $thevalue ) {
                $return_array[] = sanitize_text_field( $thevalue );
            }

            return $return_array;
        }
    endif;