<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit; // Exit if accessed directly
}
if(!function_exists("wc_rs_get_email_head")):
function wc_rs_get_email_head() {
	$output = '<!DOCTYPE html>';
	$output .= '<html '.get_language_attributes().'>';
	$output .= '<head>';
	$output .= '<meta http-equiv="Content-Type" content="text/html; charset='.get_bloginfo( 'charset' ).'" />';
	$output .= '<title>'.get_bloginfo( 'name', 'display' ).'</title>';
	$output .= '<style type="text/css"> .invoice_totals:after{clear:both;display:table;content:""} .company_info.large_invoice .address-side p{font-size:12px;margin-top:4px;margin-bottom:4px;} .company_info.large_invoice .address-side h2{font-size:14px;font-weight:bold;margin-top:4px;margin-bottom:4px;} p.signatureblock{display:block;width:100%;text-align:center;clear:both;} tr.top td.title img.company_logo {max-height:83px;max-width:200px;width:auto;} .repair_box .invoice_header {text-align:right;} .invoice_totals:after {clear:both;display:table;content:"";width:100%;} 
	.repair_box table tr td, .repair_box table tr th {border:1px solid #f7f7f7;padding:8px;} .repair_box table tr.heading td {
		background: #eee; border-bottom: 1px solid #ddd; font-weight: bold;} .logomain {text-align:left;} td.textallright, td.textallright div, td.textallright p {text-align:right;} .repair_box .invoice_totals table {
			border: 1px solid #ededed; max-width: 350px; text-align: right; float: right; margin-bottom: 15px; } .repair_box p.aligncenter {width:100%;display:block;clear:both;text-align:center;} .repair_box table tr th {font-weight:bold;} .repair_box table {margin-bottom:15px;width:100%;}</style>';
	$output .= '</head>';
	$rightmargin = is_rtl() ? 'rightmargin' : 'leftmargin';
	$direction = is_rtl() ? 'rtl' : 'ltr';
	$output .= '<body '.$rightmargin.'="0" marginwidth="0" topmargin="0" marginheight="0" offset="0">';
	$output .= '<center style="width: 100%; background-color: #f1f1f1;">';
	$output .= '<div id="wrapper" dir="'.$direction.'">';
	$output .= '<table border="0" cellpadding="0" cellspacing="0" height="100%" width="100%">';
	$output .= '<tr><td align="center" valign="top">';
	$output .= '<table border="0" style="background-color:#FFF;margin:30px;max-width:600px;width:100%;" cellpadding="0" cellspacing="0" width="600" id="template_container">';

	$output .= '<table border="0" cellpadding="15" cellspacing="0" height="100%" width="100%" style="background-color:#f8f8f8;">';
	$output .= '<tr class="top"><td align="center" valign="top" class="title logomain">';
	$output .= wc_rb_return_logo_url_with_img("company_logo");
	$output .= '</td><td align="right" valign="top" class="textallright">';

	$wc_rb_business_name	= get_option( 'wc_rb_business_name' );
	$wc_rb_business_phone	= get_option( 'wc_rb_business_phone' );

	$wc_rb_business_name	= ( empty( $wc_rb_business_name ) ) ? get_bloginfo( 'name' ) : $wc_rb_business_name;

	$computer_repair_email = get_option( 'computer_repair_email' );

	if(empty($computer_repair_email)) {
		$computer_repair_email	= get_option("admin_email");	
	}
	$output .= '<div class="company_info large_invoice">';
	$output .= "<div class='address-side'>
					<h2>".$wc_rb_business_name."</h2>";
	$output .= "<p>";
	$output .= (!empty($computer_repair_email)) ? "<strong>".esc_html__("Email", "computer-repair-shop")."</strong>: ".$computer_repair_email : "";
	$output .= (!empty($wc_rb_business_phone)) ? "<br><strong>".esc_html__("Phone", "computer-repair-shop")."</strong>: ".$wc_rb_business_phone : "";
	$output .= "</p></div>";
	$output .= '</div>';

	$output .= '</td></tr></table>';

	$output .= '<tr>
				<td align="center" valign="top">
				<!-- Body -->
				<table border="0" cellpadding="0" cellspacing="0" width="600" style="max-width:600px;width:100%;" id="template_body">
				<tr>
				<td valign="top" id="body_content">
				<!-- Content -->
				<table border="0" cellpadding="20" cellspacing="0" width="100%">
				<tr>
				<td valign="top">
				<div id="body_content_inner">';
	return $output;
}
endif;