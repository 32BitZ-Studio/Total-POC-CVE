<?php
defined( 'ABSPATH' ) || exit;
/***
 * Repair Label Functionality
 * Function Returns repair label
 * Takes Order ID as an Argument.
 *
 * @package computer repair shop
 */

if ( ! function_exists( 'wc_print_repair_label' ) ) {
	/***
	 * Generate Repair Label
	 * Returns the label
	 *
	 * parameter $order_id
	 */
	function wc_print_repair_label( $order_id ) {
		if ( empty( $order_id ) ) {
			return;
		}

		$wc_use_taxes    = get_option( 'wc_use_taxes' );

		// Let's do magic.
		$customer_id             = get_post_meta( $order_id, '_customer', true );
		$wc_device_label         = ( empty( get_option( 'wc_device_label' ) ) ) ? esc_html__( 'Device', 'computer-repair-shop' ) : get_option( 'wc_device_label' );
		$wc_device_id_imei_label = ( empty( get_option( 'wc_device_id_imei_label' ) ) ) ? esc_html__( 'ID/IMEI', 'computer-repair-shop' ) : get_option( 'wc_device_id_imei_label' );
		$current_devices         = get_post_meta( $order_id, '_wc_device_data', true );

		$content = '';

		$content .= '<div id="invoice-box" class="invoice-box ticket-box"><div class="ticket">';

		$content .= '<p class="centered label_box">';
		$content .= "<span id='current_date' colspan='2'></span><br>";


		$content .= '<strong>'.esc_html__("Case#", "computer-repair-shop").' :</strong> '.get_post_meta( $order_id, "_case_number", true );

		if ( ! empty( $customer_id ) ):
			$user 		 = get_user_by( 'id', $customer_id );
		
			$first_name	  = empty( $user->first_name ) ? "" : $user->first_name;
			$last_name 	  = empty( $user->last_name ) ? "" : $user->last_name;
			$content .= '<br><strong>' . esc_html__( "Customer", "computer-repair-shop" ) . ' :</strong> ' . $customer_id . ' { ' . $first_name. ' ' .$last_name . ' } ';
		endif;

        if ( ! empty( $current_devices )  && is_array( $current_devices ) ) {
			$counter = 0;
            foreach( $current_devices as $device_data ) {
				$content .= ( $counter != 0 ) ? '<br>' : '<br><strong>' . $wc_device_label . ' ' . $wc_device_id_imei_label . ' :</strong> ';				
                $device_post_id = ( isset( $device_data['device_post_id'] ) ) ? $device_data['device_post_id'] : '';
                $device_id      = ( isset( $device_data['device_id'] ) ) ? $device_data['device_id'] : '';

				$content .= return_device_label( $device_post_id ) . ' (' . esc_html( $device_id ) . ')';
				$counter++;
            }
        }

		$content .= "</p>";

	$content .= '</div>';

	$content .= '<button id="btnPrint" class="hidden-print button button-primary btn-fullwidth">'.esc_html__("Print", "computer-repair-shop").'</button>';
	$content .= '<p class="hidden-print">'.esc_html__("Print label to paste on device or parts for validation of claim.", "computer-repair-shop").'</p>';
	$content .= '</div><!-- Invoice-box Ends /-->';

	return $content;

	}
}