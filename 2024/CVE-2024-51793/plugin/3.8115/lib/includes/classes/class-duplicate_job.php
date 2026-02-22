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

add_action( 'plugins_loaded', array( 'WCRB_DUPLICATE_JOB', 'getInstance' ) );

class WCRB_DUPLICATE_JOB {
    private static $instance = NULL;

	static public function getInstance() {
		if ( self::$instance === NULL )
			self::$instance = new WCRB_DUPLICATE_JOB();
		return self::$instance;
	}

    public function __construct() {
		add_action( 'wp_ajax_wcrb_return_duplicate_job_fields', array( $this, 'wcrb_return_duplicate_job_fields' ) );
		add_action( 'wp_ajax_wcrb_duplicate_page_perform', array( $this, 'wcrb_duplicate_page_perform' ) );

        $this->reveal_duplicate_job_admin_footer();
	}

	
	function wcrb_duplicate_page_perform() {
		$redirect_url = 'NO';
		$message = '';

		// Verify that the nonce is valid.
		if ( ! isset( $_POST['wcrb_nonce_duplicate_job_field'] ) || ! wp_verify_nonce( $_POST['wcrb_nonce_duplicate_job_field'], 'wcrb_nonce_duplicate_job' )) {
			$message = esc_html__( 'Something is not right', 'computer-repair-shop' );
		} elseif ( ! isset( $_POST['wcrb_job_id'] ) || empty( $_POST['wcrb_job_id'] ) ) {
			$message = esc_html__( 'Unknown job', 'computer-repair-shop' );
		} else {
			$_old_job_id = sanitize_text_field( $_POST['wcrb_job_id'] );

			//Create a new job first. 
			$new_case_number = wc_generate_random_case_num();
			
			$my_post = array(
							'post_title'    => $new_case_number,
							'post_status'   => 'publish',
							'post_type' 	=> 'rep_jobs'
						);
			// Insert the post into the database
			$new_job_id = wp_insert_post( $my_post );
			
			update_post_meta( $new_job_id, '_case_number', $new_case_number );
			
			if ( isset( $_POST['c_delivery_date'] ) && $_POST['c_delivery_date'] == 'YES' ) {
				//Set Delivery Date
				$delivery_date = get_post_meta( $_old_job_id, '_delivery_date', true );
				update_post_meta( $new_job_id, '_delivery_date', $delivery_date );
			}
			if ( isset( $_POST['c_pickup_date'] ) && $_POST['c_pickup_date'] == 'YES' ) {
				//Set Pickup Date
				$pickup_date = get_post_meta( $_old_job_id, '_pickup_date', true );
				update_post_meta( $new_job_id, '_pickup_date', $pickup_date );
			}
			if ( isset( $_POST['c_technician'] ) && $_POST['c_technician'] == 'YES' ) {
				//Set Technician
				$technician = get_post_meta( $_old_job_id, '_technician', true );
				update_post_meta( $new_job_id, '_technician', $technician );
			}
			if ( isset( $_POST['c_job_details'] ) && $_POST['c_job_details'] == 'YES' ) {
				//Set Job Details
				$case_detail = get_post_meta( $_old_job_id, '_case_detail', true );
				update_post_meta( $new_job_id, '_case_detail', $case_detail );
			}
			if ( isset( $_POST['c_customer'] ) && $_POST['c_customer'] == 'YES' ) {
				//Set Customer
				$customer = get_post_meta( $_old_job_id, '_customer', true );
				update_post_meta( $new_job_id, '_customer', $customer );

				$customer_label = get_post_meta( $_old_job_id, '_customer_label', TRUE );
				update_post_meta( $new_job_id, '_customer_label', $customer_label );
			}

			$store_id = get_post_meta( $_old_job_id, '_store_id', true );
			update_post_meta( $new_job_id, '_store_id', $store_id );

			$wc_order_note = get_post_meta( $_old_job_id, '_wc_order_note', true );
			update_post_meta( $new_job_id, '_wc_order_note', $wc_order_note );

			update_post_meta( $new_job_id, '_wc_order_status', 'neworder' );
			$order_status =  wc_return_status_name( 'neworder' );
			update_post_meta( $new_job_id, '_wc_order_status_label', $order_status );

			update_post_meta( $new_job_id, '_order_id', $new_job_id );

			$wc_prices_inclu_exclu = get_post_meta( $_old_job_id, '_wc_prices_inclu_exclu', true );
			update_post_meta( $new_job_id, '_wc_prices_inclu_exclu', $wc_prices_inclu_exclu );

			if ( isset( $_POST['c_fields_files'] ) && $_POST['c_fields_files'] == 'YES' ) {
				//Set Fields and Files
				$wc_job_extra_items = get_post_meta( $_old_job_id, 'wc_job_extra_items', true );
				update_post_meta( $new_job_id, 'wc_job_extra_items', $wc_job_extra_items );
			}

			if ( isset( $_POST['c_devices'] ) && $_POST['c_devices'] == 'YES' ) {
				//Set Devices
				$wc_device_data = get_post_meta( $_old_job_id, '_wc_device_data', TRUE );
				update_post_meta( $new_job_id, '_wc_device_data', $wc_device_data );
			}
			
			$WCRB_JOB_HISTORY_LOGS = WCRB_JOB_HISTORY_LOGS::getInstance();
			if ( isset( $_POST['c_history_log'] ) && $_POST['c_history_log'] == 'YES' ) {
				//Copy Logs
				$WCRB_JOB_HISTORY_LOGS->copy_history_logs_to_other_job( $_old_job_id, $new_job_id );
			}
			
			if ( isset( $_POST['c_services'] ) && $_POST['c_services'] == 'YES' ) {
				//Set Services
				$this->copy_order_items( $_old_job_id, $new_job_id, 'services' );
			}
			if ( isset( $_POST['c_parts'] ) && $_POST['c_parts'] == 'YES' ) {
				//Set Parts
				$this->copy_order_items( $_old_job_id, $new_job_id, 'parts' );
			}
			if ( isset( $_POST['c_products'] ) && $_POST['c_products'] == 'YES' ) {
				//Set Products
				$this->copy_order_items( $_old_job_id, $new_job_id, 'products' );
			}
			if ( isset( $_POST['c_extras'] ) && $_POST['c_extras'] == 'YES' ) {
				//Set Extras
				$this->copy_order_items( $_old_job_id, $new_job_id, 'extras' );
			}
			
			$args = array(
				"job_id" 		=> $new_job_id, 
				"name" 			=> esc_html__( "Job copied from another job id", "computer-repair-shop" ), 
				"type" 			=> 'public', 
				"field" 		=> '_job_copied_from_id', 
				"change_detail" => $_old_job_id
			);
			$WCRB_JOB_HISTORY_LOGS->wc_record_job_history( $args );

			$redirect_url = admin_url( 'post.php?post=' . $new_job_id . '&action=edit' );;
			$message = esc_html__( 'Record updated!', 'computer-repair-shop' );
		}

		$values['message'] = $message;
		$values['redirect_url'] = esc_url_raw( $redirect_url );

		wp_send_json( $values );
		wp_die();
	}

	function copy_order_items( $old_job_id, $new_job_id, $items ) {
		global $wpdb;
		
		if ( empty( $old_job_id ) || empty( $new_job_id ) || empty( $items ) ) {
			return;
		}
		if ( $items != 'extras' && $items != 'products' && $items != 'parts' && $items != 'services' ) {
			return;
		}

		$computer_repair_items 		= $wpdb->prefix.'wc_cr_order_items';
		$computer_repair_items_meta = $wpdb->prefix.'wc_cr_order_itemmeta';
			
		$select_items_query = $wpdb->prepare( "SELECT * FROM `{$computer_repair_items}` WHERE `order_id`= %d AND `order_item_type`=%s", $old_job_id, $items );
		$items_result 		= $wpdb->get_results( $select_items_query );

		$content = '';
				
		foreach ( $items_result as $item ) {
			$order_item_id 	 = $item->order_item_id;
			$order_item_name = $item->order_item_name;
			$order_item_type = $item->order_item_type;
			$order_id 		 = $new_job_id;
				
			//Now get the ID from Insert
			$insert_query =  "INSERT INTO `{$computer_repair_items}` VALUES(NULL, %s, %s, %d)";
		
			$wpdb->query(
					$wpdb->prepare( $insert_query, $order_item_name, $order_item_type, $order_id )
			);
			$new_order_item_id = $wpdb->insert_id;

			//Now get itemmeta by item id and insert into new table id
			$select_itemmeta_query = $wpdb->prepare( "SELECT * FROM `{$computer_repair_items_meta}` WHERE `order_item_id`= %d", $order_item_id );
			$itemmeta_result = $wpdb->get_results( $select_itemmeta_query );

			foreach( $itemmeta_result as $itemmeta ) {
				$meta_id = $itemmeta->meta_id;
				$order_item_id = $itemmeta->order_item_id;
				$meta_key = $itemmeta->meta_key;
				$meta_value = $itemmeta->meta_value;

				$meta_insert_query =  "INSERT INTO `{$computer_repair_items_meta}` VALUES(NULL, %s, %s, %s)";

				$wpdb->query(
					$wpdb->prepare( $meta_insert_query, $new_order_item_id, $meta_key, $meta_value )
				);
			}
		}
	}

	function reveal_duplicate_job_admin_footer() {
		global $pagenow;

		if ( isset( $_GET['post_type'] ) && 'edit.php' === $pagenow && $_GET['post_type'] == 'rep_jobs' ) {
			add_filter( 'admin_footer', array( $this, 'wcrb_duplicate_job_reveal_box' ) );
		}
	}

    function wcrb_duplicate_job_reveal_box() {
	?>
		<!-- Modal for Post Entry /-->
		<div class="reveal" id="wcrbduplicatejob" data-reveal>
		<h2><?php echo esc_html__( 'Duplicate job', 'computer-repair-shop' ); ?></h2>
			<form class="" method="post" name="wcrb_duplicate_page_return" data-success-class=".duplicate_page_return_message">
			<div id="replacementpart_dp_page_formfields">
				<!-- Replacementpart starts /-->
				<!-- Replacementpart Ends /-->
			</div></form>
			<button class="close-button" data-close aria-label="Close modal" type="button">
				<span aria-hidden="true">&times;</span>
			</button>
		</div>
		<?php
	}

	function wcrb_return_duplicate_job_fields() {

		$customerName = '';

		if ( isset( $_POST['recordID'] ) && ! empty ( $_POST['recordID'] ) ) :
			$curr_job_id = sanitize_text_field( $_POST['recordID'] );

			$_case_number = get_the_title( $curr_job_id );
			$customer 	  = get_post_meta( $curr_job_id, '_customer', true );
			
			if ( ! empty( $customer ) ) {
				$user 		 = get_user_by( 'id', $customer );
				
				$first_name	  = empty( $user->first_name ) ? "" : $user->first_name;
				$last_name 	  = empty( $user->last_name ) ? "" : $user->last_name;
				$customerName =  ' { ' . esc_html__( 'Customer', 'computer-repair-shop' ) . ': ' . $first_name. ' ' .$last_name . ' } ';
			}

			$wc_order_status = get_post_meta( $curr_job_id, '_wc_order_status', true );
			$wc_order_status = ( empty( $wc_order_status ) ) ? 'new' : $wc_order_status;

			$output = '<div class="duplicate_page_return_message"></div>
			<p>{ ' . esc_html__( 'Case number', 'computer-repair-shop' ) . ' - ' . esc_html( $_case_number ) . ' }' . $customerName . ' { ' . esc_html__( 'Job Status', 'computer-repair-shop' ) . ': ' . ucfirst( $wc_order_status ) . ' }</p>';


			$output .= '<div class="wcrb_the_payment_note"><table>';

			//c_delivery_date, c_pickup_date, c_technician, c_customer, c_job_details, c_devices, c_fields_files, c_fields_files, c_services, c_parts, c_products, c_extras, c_history_log

			$wc_device_label_plural = ( empty( get_option( 'wc_device_label_plural' ) ) ) ? esc_html__( 'Devices', 'computer-repair-shop' ) : get_option( 'wc_device_label_plural' );

			$output .= '<tr><td><label for="c_delivery_date">' . esc_html__( 'Copy', 'computer-repair-shop' ) . ' - ' . esc_html__( 'Delivery Date', 'computer-repair-shop' ) . '</label></td><td>';
			$output .= '<input type="checkbox" id="c_delivery_date" name="c_delivery_date" value="YES" /></td></tr>';

			$output .= '<tr><td><label for="c_pickup_date">' . esc_html__( 'Copy', 'computer-repair-shop' ) . ' - ' . esc_html__( 'Pickup Date', 'computer-repair-shop' ) . '</label></td><td>';
			$output .= '<input type="checkbox" id="c_pickup_date" name="c_pickup_date" value="YES" /></td></tr>';

			$output .= '<tr><td><label for="c_technician">' . esc_html__( 'Copy', 'computer-repair-shop' ) . ' - ' . esc_html__( 'Technician', 'computer-repair-shop' ) . '</label></td><td>';
			$output .= '<input type="checkbox" checked id="c_technician" name="c_technician" value="YES" /></td></tr>';

			$output .= '<tr><td><label for="c_customer">' . esc_html__( 'Copy', 'computer-repair-shop' ) . ' - ' . esc_html__( 'Customer', 'computer-repair-shop' ) . '</label></td><td>';
			$output .= '<input type="checkbox" checked id="c_customer" name="c_customer" value="YES" /></td></tr>';

			$output .= '<tr><td><label for="c_job_details">' . esc_html__( 'Copy', 'computer-repair-shop' ) . ' - ' . esc_html__( 'Job Details', 'computer-repair-shop' ) . '</label></td><td>';
			$output .= '<input type="checkbox" checked id="c_job_details" name="c_job_details" value="YES" /></td></tr>';

			$output .= '<tr><td><label for="c_devices">' . esc_html__( 'Copy', 'computer-repair-shop' ) . ' - ' . esc_html( $wc_device_label_plural ) . '</label></td><td>';
			$output .= '<input type="checkbox" checked id="c_devices" name="c_devices" value="YES" /></td></tr>';

			$output .= '<tr><td><label for="c_fields_files">' . esc_html__( 'Copy', 'computer-repair-shop' ) . ' - ' . esc_html__( 'Fields & Files', 'computer-repair-shop' ) . '</label></td><td>';
			$output .= '<input type="checkbox" checked id="c_fields_files" name="c_fields_files" value="YES" /></td></tr>';

			$output .= '<tr><td><label for="c_services">' . esc_html__( 'Copy', 'computer-repair-shop' ) . ' - ' . esc_html__( 'Services', 'computer-repair-shop' ) . '</label></td><td>';
			$output .= '<input type="checkbox" checked id="c_services" name="c_services" value="YES" /></td></tr>';

			if ( is_parts_switch_woo() == true ) {
				$output .= '<tr><td><label for="c_products">' . esc_html__( 'Copy', 'computer-repair-shop' ) . ' - ' . esc_html__( 'Products', 'computer-repair-shop' ) . '</label></td><td>';
				$output .= '<input type="checkbox" checked id="c_products" name="c_products" value="YES" /></td></tr>';
			} else {
				$output .= '<tr><td><label for="c_parts">' . esc_html__( 'Copy', 'computer-repair-shop' ) . ' - ' . esc_html__( 'Parts', 'computer-repair-shop' ) . '</label></td><td>';
				$output .= '<input type="checkbox" checked id="c_parts" name="c_parts" value="YES" /></td></tr>';
			}
			$output .= '<tr><td><label for="c_extras">' . esc_html__( 'Copy', 'computer-repair-shop' ) . ' - ' . esc_html__( 'Extras', 'computer-repair-shop' ) . '</label></td><td>';
			$output .= '<input type="checkbox" checked id="c_extras" name="c_extras" value="YES" /></td></tr>';

			$output .= '<tr><td><label for="c_history_log">' . esc_html__( 'Copy', 'computer-repair-shop' ) . ' - ' . esc_html__( 'History Log', 'computer-repair-shop' ) . '</label></td><td>';
			$output .= '<input type="checkbox" id="c_history_log" name="c_history_log" value="YES" /></td></tr>';

			$output .= '<tr><td><label for="c_reviews">' . esc_html__( 'Copy', 'computer-repair-shop' ) . ' - ' . esc_html__( 'Reviews', 'computer-repair-shop' ) . '</label></td><td>';
			$output .= '<input type="checkbox" id="c_reviews" name="c_reviews" value="YES" /></td></tr>';

			$output .= '</table></div><!-- the_payment_note /-->';

			$output .= wp_nonce_field( 'wcrb_nonce_duplicate_job', 'wcrb_nonce_duplicate_job_field', true, false );
			
			$output .= '<input type="hidden" name="wcrb_job_id" value="' . esc_html( $curr_job_id ) . '" />';
			$output .= '<table class="form-table widthfifty">
							<tr><td>
								<button class="button button-primary expanded" type="submit" value="Submit">' . esc_html__( 'Duplicate Job', 'computer-repair-shop' ) . '</button>
							</td><td>
							</fieldset><small>' . esc_html__( '(*) fields are required', 'computer-repair-shop' ) . '</small>
							</td></tr>
						</table>';

			$allowedHTML = wc_return_allowed_tags(); 
			$message = wp_kses( $output, $allowedHTML );
		else: 
			$message = esc_html__( 'Could not find the job id', 'computer-repair-shop' );
		endif;
					
		$values['message'] = $message;
		$values['success'] = "YES";

		wp_send_json( $values );
		wp_die();
	}
}