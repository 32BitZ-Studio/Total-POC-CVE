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

class REPORT_CUSTOMERS {

	function generate_form_output_jobs_by_customer( $type, $range ) {
		if(empty($type)) {
			return;
		}
		if(empty($range)) {
			return;
		}
		$content = '<div id="invoice-box" class="invoice-box">';

		if ( $type == "date_range" || $type == 'customers_summary' ) {
			$today = date("Y-m-d");

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

			if ( $type !== 'customers_summary' ) {
				$content .= '<div class="medium-12 cell">';
				$content .= '<label>' . esc_html__( 'Select Customer', 'computer-repair-shop' );
				$content .= wcrb_return_customer_select_options( '', 'customer', 'updatenone' );
				$content .= '</label>';
				$content .= '</div>';
			}
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
			if ( $type == 'customers_summary' ) {
				$content .= '<input type="hidden" name="report_type" value="customers_summary" />';
			} else {
				$content .= '<input type="hidden" name="report_type" value="jobs_by_customer" />';
			}
			$content .= '<input type="submit" class="button button-primary" value="'.esc_html__("Generate Report", "computer-repair-shop").'">';
			$content .= "</form>";
		}
		$content .= '</div>';

		$allowedHTML = wc_return_allowed_tags(); 
		echo wp_kses($content, $allowedHTML);
	}

	function wc_generate_customer_report( $arges ) {
		if ( ! isset( $arges["report_type"] ) || empty( $arges["report_type"] ) ) {
			return esc_html__( "Report is not defined", "computer-repair-shop" );
		}
		$arges['job_status_include']     = ( isset( $_GET['job_status_include'] ) ) ? array_map( 'sanitize_text_field', $_GET['job_status_include'] ) : '';
		$arges['payment_status_include'] = ( isset( $_GET['payment_status_include'] ) ) ? array_map( 'sanitize_text_field', $_GET['payment_status_include'] ) : '';
		$job_status_include             = (!isset($arges["job_status_include"]) || empty($arges["job_status_include"])) ? "" : $arges["job_status_include"];
		$payment_status_include         = (!isset($arges["payment_status_include"]) || empty($arges["payment_status_include"])) ? "" : $arges["payment_status_include"];

		$report_heading     = "unknown";
		$customer 		= ( isset( $arges['customer'] ) && ! empty( $arges['customer'] ) ) ? $arges['customer'] : '';
		$CusfullName		= esc_html__( 'Customer', 'computer-repair-shop' );

		if ( ! empty( $customer ) ) {
			$customer_obj = get_user_by( 'id', $customer );
			$CusfullName = $customer_obj->first_name . ' ' . $customer_obj->last_name;
		}
		if ( $arges["report_type"] == "jobs_by_customer" ) {
			$report_heading = esc_html__( "Jobs Summary By - ", "computer-repair-shop" ) . esc_html( $CusfullName ) ;
		}

		$from_date  = ( ! empty( $arges["start_date"] ) ) ? $arges["start_date"] : "2020-01-01";
		$to_date    = ( ! empty( $arges["end_date"] ) ) ? $arges["end_date"] : "2025-01-01";

		$content = '<div class="invoice-box report-container">';
		$content .= wc_get_report_head( $report_heading );

		$content .= '<div id="table_div">';
		$content .= '<div class="wc-rb-report-title"><h2>' . esc_html( $report_heading ) . '</h2></div>';

		$date_format = get_option('date_format');
		
		$from_date_fr  = (!empty($from_date)) ? date($date_format, strtotime($from_date)) : "";
		$to_date_fr    = (!empty($to_date)) ? date($date_format, strtotime($to_date)) : "";

		$content .= '<div class="wc-rb-report-period">';
		$content .= '<p><span class="todayDate"><strong>'.esc_html__("Today", "computer-repair-shop").':</strong> '.date($date_format).' </span><span class="statementPeriod"><strong>';
		$content .= esc_html__("Statement Period", "computer-repair-shop").':</strong> '.$from_date_fr.' - '.$to_date_fr . '</span></p>';

		$wc_device_label        = ( empty( get_option( 'wc_device_label' ) ) ) ? esc_html__( 'Device', 'computer-repair-shop' ) : get_option( 'wc_device_label' );

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
			"report_type"               => $arges["report_type"],
			"job_status_include"        => $job_status_include,
			"payment_status_include"    => $payment_status_include,
			"customer"					=> $customer,
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

	function wc_generate_customers_summary( $arges ) {
		if ( ! isset( $arges["report_type"] ) || empty( $arges["report_type"] ) ) {
			return esc_html__( "Report is not defined", "computer-repair-shop" );
		}
		$arges['job_status_include']     = ( isset( $_GET['job_status_include'] ) ) ? array_map( 'sanitize_text_field', $_GET['job_status_include'] ) : '';
		$arges['payment_status_include'] = ( isset( $_GET['payment_status_include'] ) ) ? array_map( 'sanitize_text_field', $_GET['payment_status_include'] ) : '';
		$job_status_include             = (!isset($arges["job_status_include"]) || empty($arges["job_status_include"])) ? "" : $arges["job_status_include"];
		$payment_status_include         = (!isset($arges["payment_status_include"]) || empty($arges["payment_status_include"])) ? "" : $arges["payment_status_include"];

		$report_heading     = "unknown";
		
		if ( $arges["report_type"] == "customers_summary" ) {
			$report_heading = esc_html__( "Customers Job Summary", "computer-repair-shop" );
		}
		$from_date  = ( ! empty( $arges["start_date"] ) ) ? $arges["start_date"] : "2020-01-01";
		$to_date    = ( ! empty( $arges["end_date"] ) ) ? $arges["end_date"] : "2025-01-01";

		$content = '<div class="invoice-box report-container">';
		$content .= wc_get_report_head( $report_heading );

		$content .= '<div id="table_div">';
		$content .= '<div class="wc-rb-report-title"><h2>' . esc_html( $report_heading ) . '</h2></div>';

		$date_format = get_option( 'date_format' );
		
		$from_date_fr  = ( ! empty( $from_date ) ) ? date( $date_format, strtotime( $from_date ) ) : "";
		$to_date_fr    = ( ! empty( $to_date ) ) ? date( $date_format, strtotime( $to_date ) ) : "";

		$content .= '<div class="wc-rb-report-period">';
		$content .= '<p><span class="todayDate"><strong>'.esc_html__("Today", "computer-repair-shop").':</strong> '.date($date_format).' </span><span class="statementPeriod"><strong>';
		$content .= esc_html__("Statement Period", "computer-repair-shop").':</strong> '.$from_date_fr.' - '.$to_date_fr . '</span></p>';

		$wc_device_label        = ( empty( get_option( 'wc_device_label' ) ) ) ? esc_html__( 'Device', 'computer-repair-shop' ) : get_option( 'wc_device_label' );

		$content .= '</div><!--account_info -->
		<div class="clearIt"></div>
		<table class="invoice-items">
			<thead>';
		
		$content .= '<tr class="heading special_head">
						<td>'.esc_html__("Sr#", "computer-repair-shop") . '</td>
						<td>'.esc_html__("Customer", "computer-repair-shop") . '</td>
						<td>'.esc_html__("Jobs", "computer-repair-shop") . '</td>
						<td>'.esc_html__("Parts", "computer-repair-shop").'</td>
						<td>'.esc_html__("Services", "computer-repair-shop").'</td>
						<td>'.esc_html__("Extras", "computer-repair-shop").'</td>
						<td>'.esc_html__("Tax", "computer-repair-shop").'</td>
						<td>'.esc_html__("Total", "computer-repair-shop").'</td>
					</tr>
				</thead>';
		$content .= '<tbody>';

		$arguments = array(
			"report_type"            => $arges["report_type"],
			"job_status_include"     => $job_status_include,
			"payment_status_include" => $payment_status_include,
		);
		$get_job_data = $this->wc_return_customers_job_summary( $from_date, $to_date, $arguments );

		$content .= ( isset( $get_job_data['the_content'] ) && ! empty( $get_job_data['the_content'] ) ) ? $get_job_data['the_content'] : '';

		//Process array here. 
		if ( ! isset( $get_job_data['the_content'] ) && is_array( $get_job_data ) ) {
			$counter = 0;
			foreach( $get_job_data as $techId => $techJobs ) {
				$counter++;
				$content .= "<tr class='item-row wc_extra_row'>";
				$content .= '<td>' . esc_html( $counter ) . '</td>';
				$techName = ( $techId == 'empty' ) ? esc_html__( 'Undefined', 'computer-repair-shop' ) : 'gettechname';
				if ( $techName == 'gettechname' ) {
					$user = get_user_by( 'id', $techId );
                    $first_name = empty($user->first_name)? "" : $user->first_name;
                    $last_name 	= empty($user->last_name)? "" : $user->last_name;
					$techName = $first_name . ' ' . $last_name;
				}
				$content .= '<td>' . esc_html( $techName ) . '</td>';
				$content .= '<td>' . esc_html( count( $techJobs ) ) . '</td>';

				$partsTotal = $servicesTotal = $extrasTotal = $taxTotal = $grandTotal = 0;
				foreach( $techJobs as $theJob ) {
					$partsTotal    += (float)$theJob['parts_grand'];
					$servicesTotal += (float)$theJob['services_total'];
					$extrasTotal   += (float)$theJob['extras_total'];
					$taxTotal 	   += (float)$theJob['tax_total'];
					$grandTotal    += (float)$theJob['order_total'];
				}
				$content .= '<td>' . esc_html( wc_cr_currency_format( $partsTotal, FALSE, TRUE ) ) . '</td>';
				$content .= '<td>' . esc_html( wc_cr_currency_format( $servicesTotal, FALSE, TRUE ) ) . '</td>';
				$content .= '<td>' . esc_html( wc_cr_currency_format( $extrasTotal, FALSE, TRUE ) ) . '</td>';
				$content .= '<td>' . esc_html( wc_cr_currency_format( $taxTotal, FALSE, TRUE ) ) . '</td>';
				$content .= '<td>' . esc_html( wc_cr_currency_format( $grandTotal, TRUE, TRUE ) ) . '</td>';
				$content .= "</tr>";
			}
		}
		$content .= '</tbody>
		</table>';

		$content .= '<div class="invoice_totals">
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

	function wc_return_customers_job_summary( $from_date, $end_date, $arges ) {
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

		if ( empty( $posts_discovered_in_date ) ) {
			$return_array = array(
				"the_content" => esc_html__("Couldn't find any post related to given date range.", "computer-repair-shop"),
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
		if ( isset( $customer ) && ! empty( $customer ) ) {
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
		
		$array_jobs = array();
		if($jobs_query->have_posts()): while($jobs_query->have_posts()):
			$jobs_query->the_post();

			$job_id 		= $jobs_query->post->ID;
			$case_number 	= get_post_meta( $job_id, "_case_number", true ); 
			$order_date 	= get_the_date( 'd/m/Y', $job_id );
			$payment_status = get_post_meta($job_id, "_wc_payment_status_label", true);
			$job_status		= get_post_meta($job_id, "_wc_order_status_label", true);
			$techncuician 	= get_post_meta($job_id, "_technician", true);
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

			$customer = ( ! empty( $customer ) ) ? $customer : 'empty';
			$array_jobs[$customer][] = array(
				'job_id' 		 => $job_id,
				'$case_number' 	 => $case_number,
				'order_date' 	 => $order_date,
				'payment_status' => $payment_status,
				'job_status' 	 => $job_status,
				'customer' 		 => $customer,
				'parts_grand' 	 => $parts_grand,
				'services_total' => $services_total,
				'extras_total' 	 => $extras_total,
				'tax_total' 	 => $tax_total,
				'order_total' 	 => $order_total,
			);			
		endwhile; endif;
	
		wp_reset_postdata();

		$return_array = $array_jobs;
		return $return_array;
	}
}