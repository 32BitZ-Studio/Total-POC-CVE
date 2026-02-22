<?php
defined( 'ABSPATH' ) || exit;
/***
 * Repair Print Functinoality
 * Properly prints the reports
 *
 * @package computer repair shop
 */
function wc_computer_repair_print_functionality( $return = false ) {
	if ( ! current_user_can( 'read' ) ) {
		wp_die( esc_html__( 'You do not have sufficient permissions to access this page.', 'computer-repair-shop' ) );
	}
	if ( ! is_admin() ) {
		wp_enqueue_script("foundation-js");
		wp_enqueue_script("wc-cr-js");
	}

	if ( isset( $_GET["order_id"] ) && ! empty( $_GET["order_id"] ) ) {
		$the_order_id = ( isset( $_GET["order_id"] ) ) ? sanitize_text_field( $_GET["order_id"] ) : '';

		if ( isset( $_GET["email_customer"] ) && !empty( $_GET["email_customer"] ) ) {
			wc_cr_send_customer_update_email( $the_order_id );
			echo '<h2>' . esc_html__( 'Email have been sent to the customer.', 'computer-repair-shop' ) . '</h2>';
		}

		if(isset($_GET["print_type"]) && $_GET["print_type"] == "repair_order") {
			//Repair Order to print.
			$allowedHTML 	= wc_return_allowed_tags();
			$generatedHTML 	= wc_print_repair_order( $the_order_id );
			echo wp_kses( $generatedHTML, $allowedHTML );
		} elseif(isset($_GET["print_type"]) && $_GET["print_type"] == "repair_label") {
			//Repair label to print.
			$allowedHTML 	= wc_return_allowed_tags();
			$generatedHTML 	= wc_print_repair_label($the_order_id);
			echo wp_kses( $generatedHTML, $allowedHTML );
		} else {
			//Let's call or Print our order Invoice Here.
			$allowedHTML 	= wc_return_allowed_tags();
			$generatedHTML 	= wc_print_order_invoice( $the_order_id, 'print' );
			if ( $return == TRUE ) {
				return wp_kses( $generatedHTML, $allowedHTML );
			} else {
				echo wp_kses( $generatedHTML, $allowedHTML );
			}
		}
	}

	/**
	 * Reports of different types
	 */
	if ( isset( $_GET["print_reports"] ) && ! empty( $_GET["print_reports"] ) ) {
		//Daily Sales Summary
		if(isset($_GET["report_type"]) && $_GET["report_type"] == "daily_sales_summary") {
			if(!isset($_GET["start_date"]) && !isset($_GET["end_date"])) {
				print_report_criteria_select_form("date_range", "selected_today");
			} else {
				$argus = array_map( 'sanitize_text_field', $_GET );
				wc_generate_sale_report( $argus );
			}
		}
		//Jobs by Technicians
		if ( isset( $_GET["report_type"] ) && $_GET["report_type"] == "jobs_by_technician" ) {
			$REPORTS_TECHNICIANS = new REPORT_TECHNICIANS;
			if ( ! isset( $_GET["start_date"] ) && ! isset( $_GET["end_date"] ) ) {
				$REPORTS_TECHNICIANS->generate_form_output_jobs_by_technician( "date_range", "selected_today" );
			} else {
				$argus = array_map( 'sanitize_text_field', $_GET );
				$REPORTS_TECHNICIANS->wc_generate_technician_report( $argus );
			}
		}
		//technicians_summary
		if ( isset( $_GET["report_type"] ) && $_GET["report_type"] == "technicians_summary" ) {
			$REPORTS_TECHNICIANS = new REPORT_TECHNICIANS;
			if ( ! isset( $_GET["start_date"] ) && ! isset( $_GET["end_date"] ) ) {
				echo 'yes';
				$REPORTS_TECHNICIANS->generate_form_output_jobs_by_technician( "technicians_summary", "selected_today" );
			} else {
				$argus = array_map( 'sanitize_text_field', $_GET );
				$REPORTS_TECHNICIANS->wc_generate_technicians_summary( $argus );
			}
		}
		//Jobs by Technicians
		if ( isset( $_GET["report_type"] ) && $_GET["report_type"] == "jobs_by_customer" ) {
			$REPORTS_CUSTOMERS = new REPORT_CUSTOMERS;
			if ( ! isset( $_GET["start_date"] ) && ! isset( $_GET["end_date"] ) ) {
				$REPORTS_CUSTOMERS->generate_form_output_jobs_by_customer( "date_range", "selected_today" );
			} else {
				$argus = array_map( 'sanitize_text_field', $_GET );
				$REPORTS_CUSTOMERS->wc_generate_customer_report( $argus );
			}
		}
		//customers_summary
		if ( isset( $_GET["report_type"] ) && $_GET["report_type"] == "customers_summary" ) {
			$REPORTS_CUSTOMERS = new REPORT_CUSTOMERS;
			if ( ! isset( $_GET["start_date"] ) && ! isset( $_GET["end_date"] ) ) {
				$REPORTS_CUSTOMERS->generate_form_output_jobs_by_customer( "customers_summary", "selected_today" );
			} else {
				$argus = array_map( 'sanitize_text_field', $_GET );
				$REPORTS_CUSTOMERS->wc_generate_customers_summary( $argus );
			}
		}
	}
} // add category function ends here.