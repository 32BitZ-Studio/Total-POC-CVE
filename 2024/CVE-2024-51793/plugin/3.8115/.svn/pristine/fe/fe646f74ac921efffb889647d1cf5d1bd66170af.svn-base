<?php
/**
 * The file contains the functions related to Shortcode Pages
 *
 * Help setup pages to they can be used in notifications and other items
 *
 * @package computer-repair-shop
 * @version 3.7947
 */

defined( 'ABSPATH' ) || exit;

class WCRB_WOO_FUNCTIONS {
	
	function wc_update_woo_stock_if_enabled( $jobID, $new_job_status ) {
		global $wpdb;

		$status_id = wc_return_status_id( $new_job_status );

		if ( empty( $jobID ) || empty( $status_id ) ) {
			return;
		}

		$cr_status_table 	= $wpdb->prefix.'wc_cr_job_status';

		$wc_curr_job_status	= $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$cr_status_table} WHERE `status_id` = %d", $status_id ) );	
		$curr_status 		= $wc_curr_job_status->inventory_count;

		$curr_status = ( empty( $curr_status ) || $curr_status == "off" ) ? 'off' : 'on';

		//Now we have status either on or off. 
		//If inventory already deducted
		$current_reduction_record = get_post_meta( $jobID, '_wcrb_inventory_managed', true );

		if ( ! empty( $current_reduction_record ) ) {
			//Let's readd stock.
			$state = 'increase';
			$current_reduction_inv = $current_reduction_record; 
			$current_reduction_record = unserialize( $current_reduction_record );

			if ( is_array( $current_reduction_record ) ) {
				foreach( $current_reduction_record as $the_product_arr ) {
					$_qty 	  = $the_product_arr['qty'];
					$_product = $the_product_arr['product_id'];
					update_woo_record( $_product, $_qty, $state );
				}
				//Record History private.
				$argums = array( 'job_id' => $jobID, 'name' => esc_html__( 'Stock added back in Woo inventory.', 'computer-repair-shop' ), 'type' => 'private', "field" => 'stock_management', "change_detail" => $current_reduction_inv );
				$WCRB_JOB_HISTORY_LOGS = WCRB_JOB_HISTORY_LOGS::getInstance();
				$WCRB_JOB_HISTORY_LOGS->wc_record_job_history( $argums );
				
				//Let's remove it from meta table
				update_post_meta( $jobID, '_wcrb_inventory_managed', '' );
			}
		}

		if ( $curr_status == 'on' ) {
			//Reduce Stock
			$state = 'decrease';

			$receive_arr = $this->return_rb_woo_products_qty_array( $jobID );

			if ( ! empty( $receive_arr ) && is_array( $receive_arr ) ) {
				foreach( $receive_arr as $prod_ded ) {
					$_qty 	  = $prod_ded['qty'];
					$_product = $prod_ded['product_id'];
					update_woo_record( $_product, $_qty, $state );
				}
				//Add post meta
				$receive_arr = serialize( $receive_arr );
				update_post_meta( $jobID, '_wcrb_inventory_managed', $receive_arr );
				//Record History
				$argums = array( 'job_id' => $jobID, 'name' => esc_html__( 'Stock reduced from Woo inventory.', 'computer-repair-shop' ), 'type' => 'private', "field" => 'stock_management', "change_detail" => $receive_arr );
				$WCRB_JOB_HISTORY_LOGS = WCRB_JOB_HISTORY_LOGS::getInstance();
				$WCRB_JOB_HISTORY_LOGS->wc_record_job_history( $argums );
			}
		}
	}

	function return_rb_woo_products_qty_array( $job_id ) {
		global $wpdb;

		if ( empty( $job_id ) ) {
			return;
		}
		
		$item_type = 'products';
		$qty_key   = 'wc_product_qty';
	
		$table_items 		= $wpdb->prefix . 'wc_cr_order_items';
		$table_items_meta = $wpdb->prefix . 'wc_cr_order_itemmeta';
			
		$select_items_query = $wpdb->prepare( "SELECT * FROM `{$table_items}` WHERE `order_id`= %d AND `order_item_type`='%s'", $job_id, $item_type );
		$items_result 		= $wpdb->get_results( $select_items_query );
		
		$array_ret = array();
		foreach( $items_result as $item ) {
			$_item_id 	 = $item->order_item_id;
			
			$_product_id	= $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$table_items_meta} WHERE `order_item_id` = %d AND `meta_key` = %s", $_item_id, 'wc_product_id' ) );
			$_qty			= $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$table_items_meta} WHERE `order_item_id` = %d AND `meta_key` = %s", $_item_id, $qty_key ) );

			$array_ret[] = array(
				'qty' => $_qty->meta_value,
				'product_id' => $_product_id->meta_value,
			);
		}
		return $array_ret;
	}
}