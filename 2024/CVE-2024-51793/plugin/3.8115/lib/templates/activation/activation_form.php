<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit; // Exit if accessed directly
}
if(!function_exists("wc_rs_activation_form")):
	function wc_rs_activation_form() {
		$userEmail 		= get_option("wc_cr_purchase_email");
		$purchaseCode 	= get_option("wc_cr_purchase_code");

		$output = '<div class="purchase_verification_alert"></div>';

		$output .= '<form method="post" id="purchaseVerifiction">
					<div class="purchase_form_wrap" id="purchase_box_update">';
		$output .= '<div class="grid-x grid-margin-x">';

		$output .= wc_rs_purchase_details();

		$output .= '<div class="cell medium-offset-3 medium-6">';
		$output .= '<label for="userEmail">'.esc_html__("Purchaser Email", "computer-repair-shop");
		$output .= '<input name="userEmail" type="text" 
		class="form-control login-field" value="'.$userEmail.'" 
		required="" id="userEmail">';
		$output .= '</label>';
		$output .= '</div><!-- Column End /-->';

		$output .= '<div class="cell medium-offset-3 medium-6">';
		$output .= '<label for="purchaseCode">'.esc_html__("Purchase Code", "computer-repair-shop");
		$output .= '<input name="purchaseCode" type="password" 
		class="form-control login-field" value="'.$purchaseCode.'" 
		required="" id="purchaseCode">';
		$output .= '</label>';
		$output .= '</div><!-- Column End /-->';

		$output .= '<div class="cell medium-offset-3 medium-6">';
		$output .= '<input type="submit" class="button button-primary" value="'.esc_html__("Verify Purchase", "computer-repair-shop").'" />';
		$output .= '</div><!-- Column End /-->';

		$output .= wc_cr_new_purchase_link("license");

		$output .= '</div><!-- Row end /-->';
		$output .= '</div><!-- purchase form end /-->';

		$output .= "</form>";

		return $output;
	}
endif;

/**
 * Verify purchase 
 * and save
 */
if(!function_exists("wc_rs_verify_purchase")):
function wc_rs_verify_purchase( $userEmail, $purchaseCode ) {

	if ( empty( $userEmail ) ) {
		$userEmail = get_option( "wc_cr_purchase_email" );
	}
	if ( empty( $purchaseCode ) ) {
		$purchaseCode = get_option("wc_cr_purchase_code");
	}
	if ( ! empty( $purchaseCode ) ) {
		$purchase_code = $purchaseCode;
		update_option("wc_cr_purchase_code", $purchase_code);
	}
	if ( ! empty( $userEmail ) ) {
		$user_email = $userEmail;
		update_option("wc_cr_purchase_email", $user_email);
	}
	if ( ! empty( $user_email ) && ! empty( $purchase_code ) ) {
		$url = 'https://www.webfulcreations.com/members/licensecheck.php';

		$args = array(
			'method'      => 'POST',
			'timeout'     => 45,
			'redirection' => 5,
			'httpversion' => '1.0',
			'blocking'    => true,
			'headers' 	  => array(),
			'body'        => array(
				'user_email'     	=> $user_email,
				'purchase_code' 	=> $purchase_code,
			),
			'cookies'     => array()
		);

		$response = wp_remote_post( $url, $args );

		// error check
		if ( is_wp_error( $response ) ) {
			$error_message = $response->get_error_message();
			return "Something went wrong: " . esc_html($error_message);
		} else {
			$body = wp_remote_retrieve_body( $response );
			$response = json_decode( $body );

			$product_id 	= (empty($response->product_id)) ? "" : $response->product_id;
			$support_until 	= (empty($response->support_until)) ? "" : $response->support_until;
			$license_state 	= (empty($response->license_state)) ? "" : $response->license_state; 

			if($license_state == "valid" && $product_id != "21") {
				$license_state = esc_html__("Invalid Product", "computer-repair-shop");
			}

			$args = array(
				"product_id" 	=> $product_id,
				"support_until" => $support_until,
				"license_state" => $license_state,
				"user_email" 	=> $user_email,
				"purchase_code" => $purchase_code
			);
			update_option("wc_cr_license_details", $args);

			return 'YES';
		}
	}
	//return $output;
}
endif;

/*
	* WC Update Tax or Status 
	* 
	* Helps to update the record
*/
if(!function_exists("wc_check_and_verify_purchase")) {
	function wc_check_and_verify_purchase() {
		global $wpdb;
	
		if(isset($_POST["purchaseCode"]) && isset($_POST["userEmail"])) {
			$userEmail 		= sanitize_email($_POST["userEmail"]);
			$purchaseCode 	= sanitize_text_field($_POST["purchaseCode"]);

			$returned = wc_rs_verify_purchase( $userEmail, $purchaseCode );
			$message = ( $returned == 'YES' ) ? esc_html__("Your purchase details updated.", "computer-repair-shop") : $returned;	
		} else {
			$message = esc_html__("Record updated!", "computer-repair-shop");	
		}
		$values['message'] = $message;
		$values['success'] = "YES";

		wp_send_json($values);
		wp_die();
	}
	add_action( 'wp_ajax_wc_check_and_verify_purchase', 'wc_check_and_verify_purchase');
}

/**
 * Prints purchase details
 * 
 * Support Until, Product ID etc.
 */
if(!function_exists("wc_rs_purchase_details")):
	function wc_rs_purchase_details() {
		//Get purchase data.
		$purchase_arr = get_option("wc_cr_license_details");	

		if(empty($purchase_arr)) {
			return "";
		}

		if(!is_array($purchase_arr)) {
			return "";
		}

		$userEmail 		= (isset($purchase_arr["user_email"]) && !empty($purchase_arr["user_email"])) ? $purchase_arr["user_email"] : "";
		$licenseExpiry 	= (isset($purchase_arr["support_until"]) && !empty($purchase_arr["support_until"])) ? $purchase_arr["support_until"] : "";
		$licenseExpiry 	= (!empty($licenseExpiry)) ? date_i18n(get_option('date_format'), strtotime($licenseExpiry)) : "";
		$licenseState 	= (isset($purchase_arr["license_state"]) && !empty($purchase_arr["license_state"])) ? ucfirst($purchase_arr["license_state"]) : "";

		$output = '<div class="cell medium-offset-3 medium-6"><div class="callout success">';
		$output .= "<table>";
		$output .= "<tr>
						<th>".esc_html__("Licensed to", "computer-repair-shop")."</th>
						<td>".$userEmail."</td>
					</tr>";
		$output .= "<tr>
					<th>".esc_html__("License Expiry", "computer-repair-shop")."</th>
					<td>".$licenseExpiry."</td>
				</tr>";
		$output .= "<tr>
					<th>".esc_html__("License State", "computer-repair-shop")."</th>
					<td>".$licenseState."</td>
				</tr>";
		$output .= "</table>";
		$output .= '</div></div>';

		return $output;
	}
endif;