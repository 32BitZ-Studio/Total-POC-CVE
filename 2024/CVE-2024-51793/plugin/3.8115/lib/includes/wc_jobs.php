<?php
	/*
		* Function to Register Post Type
		*
		* @ For Jobs or Cases
		*
		* @ Since 2.0.0
	*/
	function wc_repair_shop_jobs_init() {
		$labels = array(
			'add_new_item' 			=> esc_html__('Add new Job', 'computer-repair-shop'),
			'singular_name' 		=> esc_html__('Job', 'computer-repair-shop'), 
			'menu_name' 			=> esc_html__('Jobs', 'computer-repair-shop'),
			'all_items' 			=> esc_html__('Jobs', 'computer-repair-shop'),
			'edit_item' 			=> esc_html__('Edit Job', 'computer-repair-shop'),
			'new_item' 				=> esc_html__('New Job', 'computer-repair-shop'),
			'view_item' 			=> esc_html__('View Job', 'computer-repair-shop'),
			'search_items' 			=> esc_html__('Search Job', 'computer-repair-shop'),
			'not_found' 			=> esc_html__('No Job found', 'computer-repair-shop'),
			'not_found_in_trash' 	=> esc_html__('No Job in trash', 'computer-repair-shop')
		);

		$args = array(
			'labels'             	=> $labels,
			'label'					=> esc_html__('Jobs', 'computer-repair-shop'),
			'description'        	=> esc_html__('Jobs Section', 'computer-repair-shop'),
			'public'             	=> false,
			'publicly_queryable' 	=> false,
			'show_ui'            	=> true,
			'show_in_menu'       	=> false,
			'query_var'          	=> true,
			'rewrite'            	=> array('slug' => 'jobs'),
			'capability_type'    	=> array('rep_job', 'rep_jobs'),
			'has_archive'        	=> true,
			'menu_icon'			 	=> 'dashicons-clipboard',
			'menu_position'      	=> 30,
			'supports'           	=> array(''), 	
			'register_meta_box_cb' 	=> 'wc_job_features',
		);

		register_post_type( 'rep_jobs', $args );
	}
	add_action('init', 'wc_repair_shop_jobs_init');
	//registeration of post type ends here.

function wc_job_features() { 
	global $WCRB_REVIEWS_OBJ;

	add_meta_box( 'wc_order_info_id', esc_html__('Order Information', 'computer-repair-shop' ), 'wc_jobs_features_c', 'rep_jobs', 'side', 'high' );

	//Second Metabox
	add_meta_box( 'wc_job_details_box', esc_html__( 'Job Details', 'computer-repair-shop' ), 'wc_jobs_features_callback', 'rep_jobs', 'advanced', 'high' );

	//Orer Status and Order Total
	add_meta_box( 'wc_order_o_payments', esc_html__( 'Payments', 'computer-repair-shop' ), 'wc_jobs_drive_payments', 'rep_jobs', 'advanced', 'high' );

	//Second Metabox
	add_meta_box( 'wc_job_hisotry_box', esc_html__( 'Job History', 'computer-repair-shop' ), 'wc_jobs_history_callback', 'rep_jobs', 'advanced', 'low' );

	//Second Metabox
	add_meta_box( 'wc_job_feedback', esc_html__( 'Job Feedback', 'computer-repair-shop' ), array( $WCRB_REVIEWS_OBJ, 'wcrb_jobs_feedback_box' ), 'rep_jobs', 'advanced', 'low' );
} //Parts features post.
add_action( 'add_meta_boxes', 'wc_job_features', 15 );

function wc_jobs_features_c( $post ) {
	wp_nonce_field( 'wc_meta_box_nonce', 'wc_jobs_features_sub' );
	settings_errors();
	
	$selected_user 	= get_post_meta($post->ID, "_technician", true);
	$user_value 	= ($selected_user == '') ? '': $selected_user;
	$current_user = wp_get_current_user();

	if (in_array('technician', (array) $current_user->roles)) {
		if($user_value != $current_user->ID) {
			echo esc_html__("You have no access to this job!", "computer-repair-shop");
			exit();
		}
	}

	$wc_use_taxes 	= get_option("wc_use_taxes");
	$parts_returned = wc_print_existing_parts($post->ID);

	$content = '';
	$content .= '<div class="wcrb_order_ID"><span class="wcrb_label">' . esc_html__( 'Order ID', 'computer-repair-shop' ) . '</span><span class="wcrb_id">' . esc_attr( $post->ID ) . '</span></div>';
	$content .= '<div class="order_calculations">';
	
	$content .= '<table class="order_totals_calculations">';
	
	if(is_parts_switch_woo() == true) {
		//Product To Display!
		//WooCommerce Products Active
		$content .= '<tr>
						<th>'.esc_html__("Products Total", "computer-repair-shop").'</th>
						<td class="wc_products_grandtotal"><span class="amount">0.00</span></td>
					</tr>';
	}

	if(is_parts_switch_woo() == false || !empty($parts_returned)):
		$content .= '<tr>
						<th>'.esc_html__("Parts Total", "computer-repair-shop").'</th>
						<td class="wc_parts_grandtotal"><span class="amount">0.00</span></td>
					</tr>';
	endif;				
	
	$content .= '<tr>
				 	<th>'.esc_html__("Services Total", "computer-repair-shop").'</th>
				 	<td class="wc_services_grandtotal"><span class="amount">0.00</span></td>
				 </tr>';
	
	$content .= '<tr>
				 	<th>'.esc_html__("Extras Total", "computer-repair-shop").'</th>
				 	<td class="wc_extras_grandtotal"><span class="amount">0.00</span></td>
				 </tr>';

	if(is_parts_switch_woo() == true) {
		if($wc_use_taxes == "on"):
			$content .= '<tr>
						<th>'.esc_html__("Products Tax", "computer-repair-shop").'</th>
						<td class="wc_products_tax_total"><span class="amount">0.00</span></td>
					</tr>';	
		endif;	
	}

	if ( $wc_use_taxes == "on" ) :
		if ( is_parts_switch_woo() == false || ! empty( $parts_returned ) ):
			$content .= '<tr>
						<th>'.esc_html__("Parts Tax", "computer-repair-shop").'</th>
						<td class="wc_parts_tax_total"><span class="amount">0.00</span></td>
					</tr>';
		endif;			

		$content .= '<tr>
					<th>'.esc_html__("Services Tax", "computer-repair-shop").'</th>
					<td class="wc_services_tax_total"><span class="amount">0.00</span></td>
				</tr>';

		$content .= '<tr>
					<th>'.esc_html__("Extras Tax", "computer-repair-shop").'</th>
					<td class="wc_extras_tax_total"><span class="amount">0.00</span></td>
				</tr>';
	endif;

	$content .= '<tr class="grand_total_row color-blue">
				 	<th>'.esc_html__("Grand Total", "computer-repair-shop").'</th>
				 	<td class="wc_grandtotal"><span class="amount">0.00</span></td>
				 </tr>';
	
	$content .= '<tr class="color-orange">
				 <th>' . esc_html__( 'Received', 'computer-repair-shop' ) . '</th>
				 <td class="wc_jobs_payments_total">(<span class="amount">0.00</span>)</td>
			 </tr>';	
	
	$content .= '<tr class="balance_total_row color-orange">
			 <th>'.esc_html__("Balance", "computer-repair-shop").'</th>
			 <td class="wc_grandtotal_balance"><span class="amount">0.00</span></td>
		 </tr>';
	$content .= '</table>';
	
	$content .= '<div class="two-equal-buttons">';
	$content .= '<a class="button expanded button-primary button-small" style="width:100%;margin-top:10px" recordid="' . $post->ID . '" target="wcrb_add_discount">';
	$content .= esc_html__( 'Add Discount', 'computer-repair-shop' );
	$content .= '</a></div>';

	$content .= '<div class="wc_order_status_wrap"><h3>';
	
	$wc_order_status = get_post_meta($post->ID, "_wc_order_status", true);
	$selected = " selected='selected'";
	
	$content .= esc_html__( 'Order Status', 'computer-repair-shop' );
	$content .= '</h3><select name="wc_order_status">';

	if ( empty ( $wc_order_status ) ) {
		$wc_order_status = 'new';
	}
	$content .= wc_generate_status_options( $wc_order_status );
	$content .= '</select></div>';
	
	$wc_payment_status = get_post_meta( $post->ID, '_wc_payment_status', true );
	
	$content .= '<div class="wc_order_status_wrap"><h3>';
	$content .= esc_html__( 'Payment Status', 'computer-repair-shop' );
	$content .= '</h3><select name="wc_payment_status">';

	if ( empty ( $wc_payment_status ) ) {
		$wc_payment_status = 'nostatus';
	}
	global $PAYMENT_STATUS_OBJ;
	$content .= $PAYMENT_STATUS_OBJ->wc_generate_payment_status_options( $wc_payment_status );

	$content .= '</select></div>';
	
	$wc_file_attachment_in_job = get_option( 'wc_file_attachment_in_job' );

	if($wc_file_attachment_in_job == "on"):
		$content .= '<div class="wc_order_file_wrap"><h3>';
		$content .= esc_html__( 'Upload Files', 'computer-repair-shop' );
		$content .= "</h3>";
		$meta_key = 'wc_job_file';
		$content .=  wc_image_uploader_field( $meta_key, get_post_meta($post->ID, "_".$meta_key, true) );
		$content .= "</div>";
	endif; //File uploading ends.	

	$content .= '<div class="wc_order_note_wrap"><h3>';
	
	$order_notes = get_post_meta( $post->ID, '_wc_order_note', true );
	$content .= esc_html__( 'Order Notes:', 'computer-repair-shop' );
	$content .= '</h3><textarea name="wc_order_note">';
	$content .= $order_notes;
	$content .= '</textarea></div>';

	$content .= "</div>";
	$content .= '<div class="order_action_messages"></div>';
	$content .= '<div class="the-wc-rb-job-actions">';
	$content .= ( defined( 'RB_QB_VERSION' ) ) ? apply_filters( 'rb_qb_send_invoice', $post->ID ) : '';
	$content .= apply_filters( 'wc_rb_jobs_action_payments', $post->ID );

	//Print Repair Order!
	$content .= '<div class="two-equal-buttons">';
	$content .= '<a target="_blank" href="admin.php?page=wc_computer_repair_print&print_type=repair_order&order_id='.$post->ID.'" class="button button-primary button-large" id="printRepairOrder">'.esc_html__("Print Repair Order", "computer-repair-shop").'</a>';
	$content .= '<a target="_blank" style="color:#FFF;margin-left:6px;" href="admin.php?page=wc_computer_repair_print&print_type=repair_label&order_id='.$post->ID.'" class="button success button-primary button-large" id="printRepairLabel">'.esc_html__("Print Repair Label", "computer-repair-shop").'</a>';
	$content .= '</div>';

	$content .= '<div class="two-equal-buttons">';
	$content .= '<a id="printorder" class="button button-primary button-large" target="_blank" href="admin.php?page=wc_computer_repair_print&order_id='.$post->ID.'">'.esc_html__("Print Order", "computer-repair-shop").'</a>';
	$content .= ' <a id="emailcustomer" style="color:#FFF;" class="button success button-primary button-large" target="_blank" href="admin.php?page=wc_computer_repair_print&order_id='.$post->ID.'&email_customer=yes">'.esc_html__("Email Customer", "computer-repair-shop").'</a>';

	$content .= "</div></div>";

	$allowedHTML = wc_return_allowed_tags(); 
	echo wp_kses($content, $allowedHTML);
}

function wc_jobs_features_callback( $post ) {
	wp_nonce_field( 'wc_meta_box_nonce', 'wc_jobs_features_call_sub' );
	settings_errors();
	
	$selected_user 	= get_post_meta($post->ID, "_technician", true);
	$user_value 	= ($selected_user == '') ? '': $selected_user;
	$current_user = wp_get_current_user();

	if (in_array('technician', (array) $current_user->roles)) {
		if($user_value != $current_user->ID) {
			echo esc_html__("You have no access to this job!", "computer-repair-shop");
			exit();
		}
	}
	
	$system_currency 	= return_wc_rb_currency_symbol();

	$content = '';
	
	$content .= wc_cr_add_js_fields_for_currency_formating();

	$content .= '<div class="grid-x grid-margin-x">';
	$content .= '<div class="cell small-12 medium-4 large-3">';
	$content .= '<label>';
	$content .= esc_html__('Case Number', 'computer-repair-shop');
	
	$random_string 	= wc_generate_random_case_num();
	$case_number 	= get_post_meta( $post->ID, "_case_number", true );
	
	$case_number 	= ($case_number == '') ? $random_string: $case_number;
	
	$content .= '<input type="text" name="case_number" value="'.$case_number.'" />';
	$content .= '</label>';
	$content .= '</div>'; //Column Ends
	
	$content .= '<input type="hidden" name="can_review_it" value="YES" />';
	$content .= '<div class="cell medium-4 large-3">';
	$content .= '<label>';
	$content .= esc_html__( 'Delivery Date', 'computer-repair-shop' );
	
	$delivery_date 	= get_post_meta( $post->ID, '_delivery_date', true );

	$content .= '<input type="date" name="delivery_date" value="'.$delivery_date.'" />';
	$content .= '</label>';
	$content .= '</div>'; //Column Ends

	$content .= '<div class="cell medium-4 large-3">';
	$content .= '<label>';
	$content .= esc_html__( 'Pickup Date', 'computer-repair-shop' );
	
	$pickup_date 	= get_post_meta( $post->ID, '_pickup_date', true );

	$pickup_date = ( ! empty( $pickup_date ) ) ? $pickup_date : get_the_date( 'Y-m-d', $post->ID );

	$content .= '<input type="date" name="pickup_date" value="'.$pickup_date.'" />';
	$content .= '</label>';
	$content .= '</div>'; //Column Ends
	
	$content .= '<div class="cell medium-4 large-3">';
	$content .= '<label class="have-addition">';
	$content .= esc_html__('Select Technician', 'computer-repair-shop');
	$selected_user 	= get_post_meta( $post->ID, "_technician", true );
	$user_value 	= ( $selected_user == '' ) ? '': $selected_user;
	
	/*$wc_add_admin_to_technician = get_option("wc_add_admin_to_technician");

	if($wc_add_admin_to_technician == "on") {
		$technician_role = '';	
	} else {
		$technician_role = array('technician');
	}*/
	$content .= wp_dropdown_users( array( 'show_option_all' => esc_html__('Select Technician', 'computer-repair-shop'), 'name' => 'technician', 'role' => 'technician', 'echo' => 0, 'selected' => $user_value ));

	$content .= '<a class="button button-primary button-small" title="' . esc_html__( 'Add New Technician', 'computer-repair-shop' ) . '" data-open="technicianFormReveal"><span class="dashicons dashicons-plus"></span></a>';
	$content .= '</label>';
	$content .= '</div>'; //Column Ends
	//Add Reveal Form
	add_filter( 'admin_footer','wc_add_technician_form' );

	$content .= '</div>'; //Row Ends

	$content .= '<div class="grid-x grid-margin-x">';

	$content .= '<div class="cell small-12 medium-6 large-6 wcRbJob_background_wrap" id="customerSelectHolder">';
	$content .= '<label id="reloadCustomerData" class="have-addition">';
	
	$selected_user 	= get_post_meta( $post->ID, "_customer", true );
	$user_value 	= ($selected_user == '') ? '': $selected_user;
	
	//$content .= esc_html__('Select Customer', 'computer-repair-shop');
	$content .= wcrb_return_customer_select_options( $user_value, 'customer', 'updatecustomer' );
	
	$content .= '<a class="button button-primary button-small" title="' . esc_html__( 'Add New Customer', 'computer-repair-shop' ) . '" data-open="customerFormReveal"><span class="dashicons dashicons-plus"></span></a>';
	$content .= '</label>';
	$content .= '<div class="wcrb_customer_info">';
	if ( ! empty( $user_value ) ) :
		$user 			= get_user_by( 'id', $user_value );
		$phone_number 	= get_user_meta( $user_value, "billing_phone", true );
		$company 		= get_user_meta( $user_value, "billing_company", true );
		$tax 			= get_user_meta( $user_value, "billing_tax", true );
		$first_name		= empty($user->first_name)? "" : $user->first_name;
		$last_name 		= empty($user->last_name)? "" : $user->last_name;
		$theFullName 	= $first_name. ' ' .$last_name;
		$email 			= empty( $user->user_email ) ? "" : $user->user_email;

		$customer_address 	= get_user_meta( $user_value, 'billing_address_1', true );
		$customer_city 		= get_user_meta( $user_value, 'billing_city', true );
		$customer_zip		= get_user_meta( $user_value, 'billing_postcode', true );
		$state		        = get_user_meta( $user_value, 'billing_state', true );
		$country		    = get_user_meta( $user_value, 'billing_country', true );

		$content .= ( ! empty( $theFullName ) ) ? $theFullName . '<br>' : '';
		
		$eprow = ( ! empty( $email ) ) ? '<strong>E :</strong> ' . $email . ' ' : '';
		$eprow .= ( ! empty( $phone_number ) ) ? '<strong>P :</strong> ' . $phone_number . '' : '';
		$content .= ( ! empty( $eprow ) ) ? $eprow . '<br>' : '';

		$ctrow = ( ! empty( $company ) ) ? '<strong>' . esc_html__( 'Company', 'computer-repair-shop' ) . ' :</strong> ' . $company . ' ' : '';
		$ctrow .= ( ! empty( $tax ) ) ? '<strong> ' . esc_html__( 'Tax ID', 'computer-repair-shop' ) . ' :</strong> ' . $tax . '' : '';
		$content .= ( ! empty( $ctrow ) ) ? $ctrow . '<br>' : '';

		if(!empty($customer_zip) || !empty($customer_city) || !empty($customer_address)) {
			$content .= "<strong>".esc_html__("Address", "computer-repair-shop")." :</strong> ";

			$content .= ! empty( $customer_address ) ? $customer_address.", " : " ";
			$content .= ! empty( $customer_city ) ? " ".$customer_city.", " : " ";
			$content .= ! empty( $customer_zip ) ? $customer_zip.", " : " ";
			$content .= ! empty( $state ) ? $state.", " : " ";
			$content .= ! empty( $country ) ? $country : " ";
		}
	endif;
	$content .= '</div>';
	$content .= '</div>'; //Column Ends
	//Add Reveal Form
	add_filter( 'admin_footer', 'wc_add_user_form' );

	$content .= '<div class="cell small-12 medium-6 large-6">'; //Column Ends
	
	$content .= '<label>' . esc_html__('Job Details', 'computer-repair-shop');
	
	$job_details = get_post_meta($post->ID, "_case_detail", true);
	
	$content .= '<textarea name="case_detail" rows="4" placeholder="'.esc_html__("Enter details about job.", "computer-repair-shop").'">'.$job_details.'</textarea>';
	$content .= '</label>';

	$content .= '</div></div>'; //End column and row

	/*
		Device Integration
	*/
	$wc_device_label         = ( empty( get_option( 'wc_device_label' ) ) ) ? esc_html__( 'Device', 'computer-repair-shop' ) : get_option( 'wc_device_label' );
	$wc_device_id_imei_label = ( empty( get_option( 'wc_device_id_imei_label' ) ) ) ? esc_html__( 'ID/IMEI', 'computer-repair-shop' ) : get_option( 'wc_device_id_imei_label' );
	$content .= '<div class="the-device-wrapper">';
	$content .= apply_filters( 'rb_carregistration_inside_device_wrap_jobs', '' );
	$content .= '<div class="device_body_message"></div>';
	$content .= '<div class="grid-x grid-margin-x" id="deviceselectrow" data-type="device_row">';
	$content .= '<div class="medium-3 small-6">';
	$content .= '<label id="rep_devices_head" class="have-addition">';
	$content .= $wc_device_label;

	if ( wcrb_use_woo_as_devices() == 'YES' ) {
		$theSearchClass = ( ! empty( get_option('wcrb_special_PR_Search_class') ) ) ? get_option('wcrb_special_PR_Search_class') : 'bc-product-search';

		$content .= '<select name="device_post_id_html" id="rep_devices" 
		data-display_stock="true" 
		data-exclude_type="variable" 
		data-placeholder="'.esc_html__( "Select ", "computer-repair-shop" ) . $wc_device_label . ' ...'. '" 
		data-security="'.wp_create_nonce( 'search-products' ).'" class="' . esc_attr( $theSearchClass ) . '"></select>';
	} else {
		$content .= '<select id="rep_devices" name="device_post_id_html">';
		$content .= wc_generate_device_options("");
		$content .= '</select>';
	}
	
	if ( wcrb_use_woo_as_devices() != 'YES' ) {
		$content .= '<a class="button button-primary button-small" title="' . esc_html__( 'Add New Device', 'computer-repair-shop' ) . '" data-open="deviceFormReveal"><span class="dashicons dashicons-plus"></span></a>';
	
		global $WCRB_MANAGE_DEVICES;
		add_filter( 'admin_footer', array( $WCRB_MANAGE_DEVICES, 'add_device_reveal_form' ) );
	}
	
	$content .= '</label>';

	$content .= '</div>'; //Column Ends
	
	$content .= '<div class="cell medium-3 small-6">';
	$content .= '<label>';
	$content .= $wc_device_label . ' ' . $wc_device_id_imei_label;
	
	$content .= '<input type="text" name="device_serial_id_html" value="" />';
	$content .= '</label>';
	$content .= '</div>'; //Column Ends
	
	$wc_pin_code_field		= get_option("wc_pin_code_field");

	if($wc_pin_code_field == "on"):
		$content .= '<div class="cell medium-2 small-6">';
		$content .= '<label>';
		$wc_pin_code_label	  = ( empty( get_option( 'wc_pin_code_label' ) ) ) ? esc_html__( 'Pin Code/Password', 'computer-repair-shop' ) : get_option( 'wc_pin_code_label' );
		$content .= esc_html( $wc_pin_code_label );

		$content .= '<input type="text" name="device_login_html" value="" />';
		$content .= '</label>';
		$content .= '</div>'; //Column Ends
	endif;

	$content .= '<div class="cell medium-3 small-6">';
	$content .= '<label>';
	$wc_note_label 	  = ( empty( get_option( 'wc_note_label' ) ) ) ? esc_html__( 'Note', 'computer-repair-shop' ) : get_option( 'wc_note_label' );
	$content .= $wc_device_label . ' ' . $wc_note_label;
	
	$content .= '<input type="text" name="device_note_html" value="" />';
	$content .= '</label>';
	$content .= '</div>'; //Column Ends

	$content .= '<div class="cell small-12 medium-1">';
	$content .= '<label><br><a class="button button-primary button-small" id="addtheDevice">';
	$content .= esc_html__( 'Add', 'computer-repair-shop' ) . ' ' . $wc_device_label;
	$content .= '</a></label>';
	$content .= '<div class="device-body-message"></div>';
	$content .= '</div>';

	$content .= '</div>'; //Row Ends 

	//List Devices Attached.
	$content .= '<div id="wc_devices_holder" class="table-scroll">';
	$content .= wc_return_job_devices( $post->ID, 'job_html');
	$content .= '</div>';
	$content .= '</div><!-- the-device-wrapper -->';
	/*
		Device Integration ends.
	*/

	/**
	 * Extra Items in Jobs
	 */
	$wc_job_extra_items = get_post_meta( $post->ID, 'wc_job_extra_items', true );
	$wc_job_extra_items = unserialize( $wc_job_extra_items );

	$content .= '<div class="wcRbJob_services_wrap"><h3>';
	$content .= esc_html__( 'Attach Fields & Files', 'computer-repair-shop' );
	$content .= '<a class="button button-primary button-small float-right" data-open="extraFieldAddition">' . esc_html__( 'Add Extra Field', 'computer-repair-shop' ) . '</a></h3>';
	add_filter( 'admin_footer','wc_add_extra_field_to_job_modal' );

	$content .= '<div class="grid-x grid-margin-x" id="reloadTheExtraFields">';
	$content .= '<div class="cell small-12">';
	$content .= '<div class="attachment_body_message"></div>';
	$counter = 0;
	if ( is_array( $wc_job_extra_items ) && ! empty( $wc_job_extra_items ) ) {
		$content .= '<table class="grey-bg wc_table extrafieldstable"><thead><tr>';
		$content .= '<th>' . esc_html__( 'Date Time', 'computer-repair-shop' ) . '</th>';
		$content .= '<th>' . esc_html__( 'Label', 'computer-repair-shop' ) . '</th>';
		$content .= '<th>' . esc_html__( 'Description', 'computer-repair-shop' ) . '</th>';
		$content .= '<th>' . esc_html__( 'Detail', 'computer-repair-shop' ) . '</th>';
		$content .= '<th>' . esc_html__( 'Visibility', 'computer-repair-shop' ) . '</th>';
		$content .= '</tr></thead><tbody>'; 
		
		foreach( $wc_job_extra_items as $wc_job_extra_item ) {
			$dateTime   = ( isset( $wc_job_extra_item['date'] ) ) ? $wc_job_extra_item['date'] : '';
			$label      = ( isset( $wc_job_extra_item['label'] ) ) ? $wc_job_extra_item['label'] : '';
			$detail     = ( isset( $wc_job_extra_item['detail'] ) ) ? $wc_job_extra_item['detail'] : '';
			$type       = ( isset( $wc_job_extra_item['type'] ) ) ? $wc_job_extra_item['type'] : '';
			$visibility = ( isset( $wc_job_extra_item['visibility'] ) && $wc_job_extra_item['visibility'] == 'public' ) ? 'Customer' : 'Staff';
			$description = ( isset( $wc_job_extra_item['description'] ) ) ? $wc_job_extra_item['description'] : '';

			$date_format = get_option( 'date_format' );
			$dateTime    = date_i18n( $date_format, strtotime( $dateTime ) );

			$content .= '<tr>';
			$content .= '<td class="deleteextrafield">
						 <a class="delme delmeextrafield" data-value="'. esc_attr( $post->ID ) .'" recordid="'. esc_attr( $counter ) .'" href="#" title="Remove row">
						 <span class="dashicons dashicons-trash"></span></a>' . $dateTime . '</td>';
			$content .= '<td>' . $label . '</td>';
			if ( $type == 'file' ) {
				$detail = '<a href="' . esc_url( $detail ) . '" target="_blank">' . $detail . '</a>';
			}
			$content .= '<td>' . $description . '</td>';
			$content .= '<td>' . $detail . '</td>';
			$content .= '<td>' . $visibility . '</td>';
			$content .= '</tr>';

			$counter++;
		}
		
		$content .= '</tbody></table>';
	}
	$content .= '</div></div></div>'; //Row Ends
	 //Ends extra items

	//Options for tax Inclusive Exclusive
	$wc_use_taxes = get_option( 'wc_use_taxes' );

	if ( $wc_use_taxes == 'on' ) :
	$content .= '<div class="wcrbJob_tax_inclusive_exclusive">';
	$content .= '<div class="grid-x grid-margin-x">';

	$wc_prices_inclu_exclu  = get_option( 'wc_prices_inclu_exclu' );
	$wc_prices_tax_type 	= get_post_meta( $post->ID, '_wc_prices_inclu_exclu', true );

	$wc_prices_inclu_exclu = ( $wc_prices_tax_type == 'inclusive' || $wc_prices_tax_type == 'exclusive' ) ? $wc_prices_tax_type : $wc_prices_inclu_exclu;

	$inclusive = ( $wc_prices_inclu_exclu == 'inclusive' ) ? ' selected' : '';
	$exclusive = ( $wc_prices_inclu_exclu == 'exclusive' ) ? ' selected' : '';

	$content .= '<div class="small-offset-6 small-3 cell">
					<label for="wc_prices_inclu_exclu" class="text-right middle pb-0"><strong>' . esc_html__( 'Amounts are', 'computer-repair-shop' ) . '</strong></label>
				</div>
				<div class="small-3 cell">
				<select name="wc_prices_inclu_exclu" id="wc_prices_inclu_exclu" class="form-control">';
	$content .= '<option value="exclusive" ' . $exclusive . '>' . esc_html__( 'Tax Exclusive', 'computer-repair-shop' ) . '</option>';
	$content .= '<option value="inclusive" ' . $inclusive . '>' . esc_html__( 'Tax Inclusive', 'computer-repair-shop' ) . '</option>';
	$content .= '</select>';
	$content .= '</div>';

	$content .= '</div></div>'; //Row Ends
	endif;
	//End of tax inclusive and exclusive

	$parts_returned 		= wc_print_existing_parts( $post->ID );
	$wc_use_taxes 			= get_option( 'wc_use_taxes' );
	$wc_primary_tax			= get_option( 'wc_primary_tax' );

	if ( is_parts_switch_woo() == true ) {
		// Add Products by WooCommerce if on from Plugin options.
		$content .= "<div class='wcRbJob_parts_wrap'><h3>";
		$content .= esc_html__('Select Products', 'computer-repair-shop').'</h3>';

		$content .= '<div class="grid-x grid-margin-x">';
		$content .= '<div class="cell small-6">';
		$theSearchClass = ( ! empty( get_option('wcrb_special_PR_Search_class') ) ) ? get_option('wcrb_special_PR_Search_class') : 'bc-product-search';
		
		$content .= '<select name="product" id="select_product" 
		data-display_stock="true" 
		data-exclude_type="variable" 
		data-placeholder="'.esc_html__("Search product ...", "computer-repair-shop").'" 
		data-security="'.wp_create_nonce( 'search-products' ).'" class="' . esc_attr( $theSearchClass ) . '"></select>';
		$content .= '</div>'; //Column Ends
		$content .= '<div class="cell small-2">';
		$theID 	  = ( ! empty( get_option('wcrb_special_ADDPRODUCT_ID') ) ) ? get_option('wcrb_special_ADDPRODUCT_ID') : 'addProduct';
		$content .= '<a class="button button-primary button-small" id="' . esc_attr( $theID ) . '">'.esc_html__("Add Product", "computer-repair-shop").'</a>';
		$content .= '</div>'; //Column Ends
		$content .= '</div>'; //Row Ends

		$content .= '<div class="grid-x grid-margin-x">';
		$content .= '<div class="cell small-12">';
		$content .= '<div class="products_body_message"></div>';
		$content .= '<table class="grey-bg wc_table"><thead><tr>';
		$content .= '<th>'.esc_html__('Name', 'computer-repair-shop').'</th>';
		$content .= '<th>'.esc_html__('SKU', 'computer-repair-shop').'</th>';
		$content .= '<th>' . esc_html( $wc_device_label ) . '</th>';
		$content .= '<th>'.esc_html__('Qty', 'computer-repair-shop').'</th>';
		$content .= '<th>'.esc_html__('Price', 'computer-repair-shop').'</th>';
	
		if($wc_use_taxes == "on"):
			$content .= '<th>'.esc_html__('Tax', 'computer-repair-shop').' (%)</th>';
			$content .= '<th>'.esc_html__('Tax', 'computer-repair-shop').' (' . $system_currency . ')</th>';
		endif;

		$content .= '<th>'.esc_html__('Total', 'computer-repair-shop').'</th>';
		$content .= '</tr></thead><tbody class="products_body">'; 
		
		$content .= wc_print_existing_products( $post->ID );
		
		$content .= '</tbody></table></div>'; //Column Ends
		
		$content .= '</div></div>'; //Row Ends
	}

	if ( is_parts_switch_woo() == false || ! empty( $parts_returned ) ) :
		// Add parts section if turned off Woo and its products
		$content .= '<div class="wcRbJob_Nativeparts_wrap"><h3>';

		if(is_parts_switch_woo() == true) {
			$content .= esc_html__('Selected Parts', 'computer-repair-shop').'</h3>';
		} else {
			$content .= esc_html__('Select Parts', 'computer-repair-shop').'</h3>';

			$content .= '<div class="grid-x grid-margin-x">';
			$content .= '<div class="cell small-6">';

			$content .= '<label id="reloadPartsData" class="have-addition">';
			$content .= wc_post_select_options( "rep_products" );
			//Add part button
			$content .= '<a class="button button-primary button-small" title="' . esc_html__( 'Add New Part', 'computer-repair-shop' ) . '" data-open="partFormReveal">
			<span class="dashicons dashicons-plus"></span></a>';
			$content .= '</label>';
			$content .= '</div>'; //Column Ends

			global $WCRB_PARTS;
			add_filter( 'admin_footer', array( $WCRB_PARTS, 'add_parts_reveal_form' ) );

			$content .= '<div class="cell small-2">';
			$content .= '<a class="button button-primary button-small" id="addPart">'.esc_html__("Add Part", "computer-repair-shop").'</a>';
			$content .= '</div>'; //Column Ends
			$content .= '</div>'; //Row Ends
		}
	
		$content .= '<div class="grid-x grid-margin-x">';
		$content .= '<div class="cell table-scroll">';
		$content .= '<div class="parts_body_message"></div>';
		$content .= '<table class="grey-bg wc_table"><thead><tr>';
		$content .= '<th>' . esc_html__( 'Name', 'computer-repair-shop' ) . '</th>';
		$content .= '<th>' . esc_html__( 'Code', 'computer-repair-shop' ) . '</th>';
		$content .= '<th>' . esc_html__( 'Capacity', 'computer-repair-shop' ) . '</th>';
		$content .= '<th>' . esc_html( $wc_device_label ) . '</th>';
		$content .= '<th>' . esc_html__( 'Qty', 'computer-repair-shop' ) . '</th>';
		$content .= '<th>' . esc_html__( 'Price', 'computer-repair-shop' ) . '</th>';
	
		if($wc_use_taxes == "on"):
			$content .= '<th>' . esc_html__( 'Tax', 'computer-repair-shop' ) . ' (%)</th>';
			$content .= '<th>' . esc_html__( 'Tax', 'computer-repair-shop' ) . ' (' . $system_currency . ')</th>';
		endif;

		$content .= '<th>' . esc_html__( 'Total', 'computer-repair-shop' ) . '</th>';
		$content .= '</tr></thead><tbody class="parts_body">'; 
		
		$content .= wc_print_existing_parts( $post->ID );
		
		$content .= '</tbody></table></div>'; //Column Ends
		
		$content .= '</div></div>'; //Row Ends

	endif; // Enable WooCommerce Taxes	
	
	$content .= '<div class="wcRbJob_services_wrap"><h3>';
	$content .= esc_html__('Select Services', 'computer-repair-shop').'</h3>';

	
	$content .= '<div class="grid-x grid-margin-x">';
	
	$content .= '<div class="cell small-6">';
	$content .= '<label id="reloadServicesData" class="have-addition">';
	$content .= wc_post_select_options( 'rep_services' );
	//Add part button
	$content .= '<a class="button button-primary button-small" title="' . esc_html__( 'Add New Service', 'computer-repair-shop' ) . '" data-open="serviceFormReveal">
	<span class="dashicons dashicons-plus"></span></a>';
	$content .= '</label>';
	$content .= '</div>'; //Column Ends

	global $WCRB_SERVICES;
	add_filter( 'admin_footer', array( $WCRB_SERVICES, 'add_services_reveal_form' ) );

	$content .= '<div class="cell small-2">';
	$content .= '<a class="button button-primary button-small" id="addService">'.esc_html__("Add Service", "computer-repair-shop").'</a>';
	$content .= '</div>'; //Column Ends
	
	$content .= '</div>'; //Row Ends
	
	$content .= '<div class="grid-x grid-margin-x">';
	
	$content .= '<div class="cell table-scroll">';
	$content .= '<div class="services_body_message"></div>';
	$content .= '<table class="grey-bg wc_table"><thead><tr>';
    $content .= '<th>' . esc_html__( 'Name', 'computer-repair-shop' ) . '</th>';
    $content .= '<th>' . esc_html__( 'Service Code', 'computer-repair-shop' ) . '</th>';
	$content .= '<th>' . esc_html( $wc_device_label ) . '</th>';
	$content .= '<th>' . esc_html__( 'Qty', 'computer-repair-shop' ) . '</th>';
	$content .= '<th>' . esc_html__( 'Price', 'computer-repair-shop' ) . '</th>';
	
	if($wc_use_taxes == "on"):
		$content .= '<th>' . esc_html__( 'Tax', 'computer-repair-shop' ) . ' (%)</th>';
		$content .= '<th>' . esc_html__( 'Tax', 'computer-repair-shop' ) . ' (' . $system_currency . ')</th>';
	endif;

	$content .= '<th>'.esc_html__('Total', 'computer-repair-shop').'</th>';
	$content .= '</tr></thead><tbody class="services_body">'; 
  
    $content .= wc_print_existing_services( $post->ID );
	
	$content .= '</tbody></table></div>'; //Column Ends
	
	$content .= '</div></div>'; //Row Ends
	
	$content .= '<div class="wcRbJob_extras_wrap"><h3>';
	$content .= esc_html__('Other Items ', 'computer-repair-shop').'<small>' . esc_html__( 'e.g Rent Or Used Cable Or Used Transistor etc', 'computer-repair-shop' ) . '</small> &nbsp;&nbsp;';
	$content .= '<a class="button button-primary button-small" id="addExtra">'.esc_html__("Add Inline Item", "computer-repair-shop").'</a></h3>';
	$content .= '<div class="grid-x grid-margin-x">';
	
	$content .= '<div class="cell small-12">';
	
	$content .= '</div>'; //Column Ends
	
	$content .= '</div>'; //Row Ends
	
	$content .= '<div class="grid-x grid-margin-x">';
	
	$content .= '<div class="cell table-scroll">';
	$content .= '<div class="extra_body_message"></div>';
	$content .= '<table class="grey-bg wc_table"><thead><tr>';
    $content .= '<th>'.esc_html__('Name', 'computer-repair-shop').'</th>';
    $content .= '<th>'.esc_html__('Code', 'computer-repair-shop').'</th>';
	$content .= '<th>' . esc_html( $wc_device_label ) . '</th>';
	$content .= '<th>'.esc_html__('Qty', 'computer-repair-shop').'</th>';
	$content .= '<th>'.esc_html__('Price', 'computer-repair-shop').'</th>';
	
	if($wc_use_taxes == "on"):
		$content .= '<th>'.esc_html__('Tax', 'computer-repair-shop').' (%)</th>';
		$content .= '<th>'.esc_html__('Tax', 'computer-repair-shop').' ('.$system_currency.')</th>';
	endif;

	$content .= '<th>'.esc_html__('Total', 'computer-repair-shop').'</th>';
	$content .= '</tr></thead><tbody class="extra_body">'; 
  
  	$content .= wc_print_existing_extras( $post->ID );
	
	$content .= '</tbody></table></div>'; //Column Ends
	$content .= '</div></div>'; //Row Ends
	
	$allowedHTML = wc_return_allowed_tags(); 
	echo wp_kses( $content, $allowedHTML );
}

function wc_jobs_history_callback($post) {
	wp_nonce_field( 'wc_meta_history_box_nonce', 'wc_jobs_history_sub' );
	settings_errors();

	$selected_user 	= get_post_meta($post->ID, "_technician", true);
	$user_value 	= ($selected_user == '') ? '': $selected_user;
	$current_user = wp_get_current_user();

	if (in_array('technician', (array) $current_user->roles)) {
		if($user_value != $current_user->ID) {
			echo esc_html__("You have no access to this job!", "computer-repair-shop");
			exit();
		}
	}

	$WCRB_JOB_HISTORY_LOGS = WCRB_JOB_HISTORY_LOGS::getInstance();
	$content = '<div id="wc_order_notes"><ul class="order_notes">';
	$content .= $WCRB_JOB_HISTORY_LOGS->wc_list_job_history( $post->ID, "all" );
	$content .= '</ul>';

	if ( ! isset( $post->ID ) || empty( $post->ID ) ): 
		$content .= "<h2>".esc_html__("Please publish post before adding history", "computer-repair-shop")."</h2>";
	else:
	$content .= '<hr><div class="add_note"><div class="add_history_log"></div>
				<p>
					<label for="add_history_note">'.esc_html__("Add manual log", "computer-repair-shop").' <span class="woocommerce-help-tip"></span></label>
					<textarea type="text" name="add_history_note" id="add_history_note" class="input-text" cols="20" rows="2"></textarea>
				</p>
				<p>
					<label for="wc_history_type" class="screen-reader-text">Note type</label>
					<select name="wc_history_type" id="wc_history_type">
						<option value="private">'.esc_html__( 'Only staff can see', 'computer-repair-shop' ) . '</option>
						<option value="public">'.esc_html__( 'Customer can see', 'computer-repair-shop' ).'</option>
					</select>
				</p>
				<p>
					<label for="wc_email_customer_manual_msg">' . esc_html__( 'Email customer on public message?', 'computer-repair-shop' ) . '
					<input type="checkbox" id="wc_email_customer_manual_msg" name="wc_email_customer_manual_msg" value="YES" checked />
					</label>
					<button data-job-id="'.$post->ID.'" 
					data-type="submit-wc-cr-history" type="button" 
					class="button button-primary button-small">'.esc_html__("Add log", "computer-repair-shop").'</button>
				</p></div></div>';
	endif;

	$allowedHTML = wc_return_allowed_tags(); 
	echo wp_kses($content, $allowedHTML);
}

function wc_jobs_drive_payments( $post ) {
	global $PAYMENT_STATUS_OBJ;
	
	$args = array(
		'job_id' => $post->ID,
		'print_head' => 'YES',
	);
	$return_payment_rows = '<div class="wrapperfor_payments table-scroll" id="payments_received_INjob"><div id="paymentstatusmessage"></div>' . $PAYMENT_STATUS_OBJ->list_the_payments( $args ) . '</div>';

	$allowedHTML = wc_return_allowed_tags(); 
	echo wp_kses( $return_payment_rows, $allowedHTML );
}

/**
 * Save infor.
 *
 * @param int $post_id The ID of the post being saved.
 */
function wc_jobs_features_save_box( $post_id ) {
	global $post;

	// Verify that the nonce is valid.
	if ( ! isset( $_POST['wc_jobs_features_sub'] ) || ! wp_verify_nonce( $_POST['wc_jobs_features_sub'], 'wc_meta_box_nonce' )) {
		return;
	}

	// If this is an autosave, our form has not been submitted, so we don't want to do anything.
	if ( defined('DOING_AUTOSAVE') && DOING_AUTOSAVE ) {
		return;
	}

	// bail out if this is not an event item
	if ( 'rep_jobs' !== $post->post_type ) {
		return;
	}

	// Check the user's permissions.
	if ( isset( $_POST['post_type'] )) {
		if ( ! current_user_can( 'edit_post', $post_id ) ) {
			return;
		}
	}
	
	global $wpdb;
	
	$old_job_status          = get_post_meta( $post_id, '_wc_order_status', true );
	$new_job_status          = sanitize_text_field( $_POST['wc_order_status'] );
	$wc_device_label         = ( empty( get_option( 'wc_device_label' ) ) ) ? esc_html__( 'Device', 'computer-repair-shop' ) : get_option( 'wc_device_label' );
	$wc_device_id_imei_label = ( empty( get_option( 'wc_device_id_imei_label' ) ) ) ? esc_html__( 'ID/IMEI', 'computer-repair-shop' ) : get_option( 'wc_device_id_imei_label' );

	//Form PRocessing
	$submission_values = array (
							'case_number',
							'customer',
							'technician',
							'pickup_date',
							'delivery_date',
							'case_detail',
							'wc_order_status',
							'store_id',
							'wc_order_note',
							'wc_prices_inclu_exclu',
							'wc_job_file',
							'wc_payment_status',
							'can_review_it'
						);

	foreach($submission_values as $submit_value) {
		if ( $_POST[$submit_value] == 'case_detail' ) {
			$my_value 	= ( isset( $_POST[$submit_value] ) ) ? sanitize_textarea_field( $_POST[$submit_value] ) : '';
		} else {
			$my_value 	= ( isset( $_POST[$submit_value] ) ) ? sanitize_text_field( $_POST[$submit_value] ) : '';
		}
		$current_value 	= get_post_meta( $post_id, '_'.$submit_value, true );

		update_post_meta( $post_id, '_'.$submit_value, $my_value );
		
		if($my_value != $current_value) {
			$type = "public";
			$error = 0;
			//Record History
			if($submit_value == "customer") {
				$name 			= esc_html__( 'Customer modified to', 'computer-repair-shop' );
				$change_detail 	= '';

				if ( ! empty ( $my_value ) ) :
					$new_user_info 		= get_userdata( $my_value );
					$new_first_name 	= $new_user_info->first_name;
					$new_last_name 		= $new_user_info->last_name;

					$change_detail 	= $new_first_name.' '.$new_last_name;
				endif;

				$error = ($my_value == "0") ? 1 : 0;
			} elseif($submit_value == "technician") {
				$name 			= esc_html__("Technician Modified to", "computer-repair-shop");
				$change_detail 	= '';
				if(!empty($my_value)):
					$new_user_info 		= get_userdata($my_value);
					$new_first_name 	= $new_user_info->first_name;
					$new_last_name 		= $new_user_info->last_name;

					$change_detail 	= $new_first_name.' '.$new_last_name;
				endif;

				$error = ($my_value == "0") ? 1 : 0;
			} elseif($submit_value == "delivery_date") {
				$name 			= esc_html__("Delivery date modified to", "computer-repair-shop");
				$change_detail 	= $my_value;
			} elseif($submit_value == "pickup_date") {
				$name 			= esc_html__("Pickup date modified to", "computer-repair-shop");
				$change_detail 	= $my_value;
			}  elseif($submit_value == "case_number") {
				$name 			= esc_html__("Case number modified to", "computer-repair-shop");
				$change_detail 	= $my_value;
			} elseif($submit_value == "case_detail") {
				$name 			= esc_html__("Job details modified to", "computer-repair-shop");
				$change_detail 	= $my_value;
			} elseif($submit_value == "wc_order_note") {
				$name 			= esc_html__("Order note modified to", "computer-repair-shop");
				$change_detail 	= $my_value;
			} elseif($submit_value == "wc_job_file") {
				$name 			= esc_html__("File attachment", "computer-repair-shop");
				$file_url 		= wp_get_attachment_url($my_value);
				$change_detail 	= $file_url;
			} elseif($submit_value == "wc_order_status") {
				$name 			= esc_html__("Order status modified to", "computer-repair-shop");
				$change_detail 	= wc_return_status_name($my_value);
			} elseif ( $submit_value == 'wc_prices_inclu_exclu' ) {
				$name		= esc_html__( 'Invoice Amounts are set to', 'computer-repair-shop' );
				$change_detail = ( $my_value == 'inclusive' ) ? esc_html__( 'Tax inclusive', 'computer-repair-shop' ) : esc_html__( 'Tax exclusive', 'computer-repair-shop' );
			} elseif($submit_value == "wc_payment_status") {
				$name 			= esc_html__("Payment status modified to", "computer-repair-shop");
				$change_detail 	= wc_return_payment_status($my_value);
			} else {
				$name			= $submit_value;
				$change_detail	= $my_value;
			}
			$args = array(
							"job_id" 		=> $post_id, 
							"name" 			=> $name, 
							"type" 			=> $type, 
							"field" 		=> '_'.$submit_value, 
							"change_detail" => $change_detail
						);
			if ( $error != 1 ) {
				$WCRB_JOB_HISTORY_LOGS = WCRB_JOB_HISTORY_LOGS::getInstance();
				$WCRB_JOB_HISTORY_LOGS->wc_record_job_history($args);
			}
		}

		if($submit_value == "case_number") {
			$title = $my_value;
			$where = array( 'ID' => $post_id );
			$wpdb->update( $wpdb->posts, array( 'post_title' => $title ), $where );
		}
	}
	/**
	 * Update Job Devices
	 * Takes Multiple Values
	 * 
	 * Add sanitized data
	 */
	$array_devices = array();
	$customer_id = ( isset( $_POST['customer'] ) && ! empty( $_POST['customer'] ) ) ? sanitize_text_field( $_POST['customer'] ) : '';
	global $WCRB_MANAGE_DEVICES;

	if( isset( $_POST["device_post_id_html"] ) && !empty( $_POST["device_post_id_html"] ) && is_array( $_POST["device_post_id_html"] ) ):
		//Get Services and save to database first.
		for($i = 0; $i < count( $_POST["device_post_id_html"] ); $i++) {
			$device_post_id_h   = ( isset( $_POST["device_post_id_html"][$i] ) || !empty( $_POST["device_post_id_html"][$i] ) ) ? sanitize_text_field($_POST["device_post_id_html"][$i]) : '';
			$device_serial_id_h = ( isset( $_POST["device_serial_id_html"][$i] ) || !empty( $_POST["device_serial_id_html"][$i] ) ) ? sanitize_text_field($_POST["device_serial_id_html"][$i]) : '';
			$device_login_h     = ( isset( $_POST["device_login_html"][$i] ) || !empty( $_POST["device_login_html"][$i] ) ) ? sanitize_text_field($_POST["device_login_html"][$i]) : '';
			$device_note_h      = ( isset( $_POST["device_note_html"][$i] ) || !empty( $_POST["device_note_html"][$i] ) ) ? sanitize_text_field($_POST["device_note_html"][$i]) : '';

			$array_devices[] = array(
				"device_post_id" => $device_post_id_h, 
				"device_id"      => $device_serial_id_h, 
				"device_login"   => $device_login_h,
				"device_note"	 => $device_note_h,
			);
			$WCRB_MANAGE_DEVICES->add_customer_device( $device_post_id_h, $device_serial_id_h, $device_login_h, $customer_id );
		}
	endif;

	$current_devices = get_post_meta($post_id, '_wc_device_data', TRUE);

	update_post_meta( $post_id, '_wc_device_data', $array_devices );

	$new_devices     = get_post_meta($post_id, '_wc_device_data', TRUE);
	$new_devices     = ( is_array( $new_devices ) && !empty( $new_devices ) ) ? serialize($new_devices) : '';
	$current_devices = ( is_array( $current_devices ) && !empty( $current_devices ) ) ? serialize($current_devices) : '';

	if ( $current_devices != $new_devices ) {
		$devices_args = array(
			"job_id" 		=> $post_id, 
			"name" 			=> $wc_device_label . ' ' . esc_html__( 'updated', 'computer-repair-shop' ), 
			"type" 			=> 'public', 
			"field" 		=> '_wc_device_data', 
			"change_detail" => $new_devices
		);
		$WCRB_JOB_HISTORY_LOGS = WCRB_JOB_HISTORY_LOGS::getInstance();
		$WCRB_JOB_HISTORY_LOGS->wc_record_job_history($devices_args);
	}

	$user 			= get_user_by('id', sanitize_text_field($_POST["customer"]));

	$first_name		= empty($user->first_name)? "" : $user->first_name;
	$last_name 		= empty($user->last_name)? "" : $user->last_name;

	$insert_user 	= $first_name. ' ' .$last_name ;

	update_post_meta( $post_id, '_customer_label', $insert_user );
	
	update_post_meta( $post_id, '_order_id', $post_id );
	
	$order_status = wc_return_status_name(sanitize_text_field($_POST["wc_order_status"]));		
	update_post_meta($post_id, '_wc_order_status_label', $order_status);
	
	update_post_meta($post_id, '_wc_payment_status_label', wc_return_payment_status(sanitize_text_field($_POST["wc_payment_status"])));
	
	//Let's save the data
	
	//Let's delete the data if that already exists. 
	$computer_repair_items 		= $wpdb->prefix.'wc_cr_order_items';
	$computer_repair_items_meta = $wpdb->prefix.'wc_cr_order_itemmeta';
	
	$select_query 	= "SELECT * FROM `".$computer_repair_items."` WHERE order_id = %d";
	
	$select_results = $wpdb->get_results( $wpdb->prepare( $select_query, $post_id ) );

	foreach($select_results as $result) {
		$order_item_id = $result->order_item_id;
		
		$delete_itemmeta_query = "DELETE  FROM `".$computer_repair_items_meta."` WHERE order_item_id = %d";
		
		$wpdb->query($wpdb->prepare( $delete_itemmeta_query, $order_item_id ));
	}
	$delete_items = "DELETE FROM `".$computer_repair_items."` WHERE order_id = %d";

	$wpdb->query($wpdb->prepare( $delete_items, $post_id ));
	
	//Now we can save the values into DAtabase 
	
	//Get Parts and save to database first.
	if(isset($_POST["wc_part_id"])):
	for($i = 0; $i < count($_POST["wc_part_id"]); $i++) {
		$wc_part_name 		= ( isset( $_POST["wc_part_name"][$i] ) ) ? sanitize_text_field( $_POST["wc_part_name"][$i] ) : '';
		$wc_part_id 		= ( isset( $_POST["wc_part_id"][$i] ) ) ? sanitize_text_field( $_POST["wc_part_id"][$i] ) : '';
		$wc_part_code 		= ( isset( $_POST["wc_part_code"][$i] ) ) ? sanitize_text_field( $_POST["wc_part_code"][$i] ) : '';
		$wc_part_capacity 	= ( isset( $_POST["wc_part_capacity"][$i] ) ) ? sanitize_text_field( $_POST["wc_part_capacity"][$i] ) : '';
		$wc_part_qty 		= ( isset( $_POST["wc_part_qty"][$i] ) ) ? sanitize_text_field( $_POST["wc_part_qty"][$i] ) : '';
		$wc_part_price 		= ( isset( $_POST["wc_part_price"][$i] ) ) ? sanitize_text_field( $_POST["wc_part_price"][$i] ) : '';
		$wc_part_device		= ( isset( $_POST["wc_part_device"][$i] ) ) ? sanitize_text_field( $_POST["wc_part_device"][$i] ) : '';

		$wc_part_device_arr = explode( '_', $wc_part_device );
		$wc_part_device = ( isset( $wc_part_device_arr[0] ) ) ? $wc_part_device_arr[0] : '';
		$wc_part_device_serial = ( isset( $wc_part_device_arr[1] ) ) ? $wc_part_device_arr[1] : '';

		$process_part_array = array(
									"wc_part_id"		=> $wc_part_id, 
									"wc_part_code"		=> $wc_part_code, 
									"wc_part_capacity"	=> $wc_part_capacity, 
									"wc_part_qty"		=> $wc_part_qty, 
									"wc_part_price"		=> $wc_part_price,
									"wc_part_device"	=> $wc_part_device,
									"wc_part_device_serial" => $wc_part_device_serial
								);

		if(isset($_POST["wc_part_tax"][$i])) {
			$wc_part_tax = sanitize_text_field($_POST["wc_part_tax"][$i]);

			$process_part_array["wc_part_tax"] = $wc_part_tax;	
		}

		$insert_query =  "INSERT INTO `{$computer_repair_items}` VALUES(NULL, %s, 'parts', %s)";
		
		$wpdb->query(
				$wpdb->prepare($insert_query, $wc_part_name, $post_id)
		);
		$order_item_id = $wpdb->insert_id;
		
		foreach($process_part_array as $key => $value) {
			$part_insert_query =  "INSERT INTO `{$computer_repair_items_meta}` VALUES(NULL, %s, %s, %s)";

			$wpdb->query(
				$wpdb->prepare($part_insert_query, $order_item_id, $key, $value)
			);
		}
	}//Parts Processed nicely
	endif;
	
	//Get Products and Save into Database
	if(isset($_POST["wc_product_id"])):
		for($i = 0; $i < count($_POST["wc_product_id"]); $i++) {
			$wc_product_name 	= ( isset( $_POST['wc_product_name'][$i] ) ) ? sanitize_text_field($_POST["wc_product_name"][$i]) : '';
			$wc_product_id 		= ( isset( $_POST['wc_product_id'][$i] ) ) ? sanitize_text_field($_POST["wc_product_id"][$i]) : '';
			$wc_product_sku 	= ( isset( $_POST['wc_product_sku'][$i] ) ) ? sanitize_text_field($_POST["wc_product_sku"][$i]) : '';
			$wc_product_qty 	= ( isset( $_POST['wc_product_qty'][$i] ) ) ? sanitize_text_field($_POST["wc_product_qty"][$i]) : '';
			$wc_product_price 	= ( isset( $_POST['wc_product_price'][$i] ) ) ? sanitize_text_field($_POST["wc_product_price"][$i]) : '';
			$wc_product_device = ( isset( $_POST['wc_product_device'][$i] ) ) ? sanitize_text_field( $_POST['wc_product_device'][$i] ) : '';

			$wc_product_device_arr = explode( '_', $wc_product_device );
			$wc_product_device = ( isset( $wc_product_device_arr[0] ) ) ? $wc_product_device_arr[0] : '';
			$wc_product_device_serial = ( isset( $wc_product_device_arr[1] ) ) ? $wc_product_device_arr[1] : '';

			$process_products_array = array(
										"wc_product_id"		=> $wc_product_id, 
										"wc_product_sku"	=> $wc_product_sku, 
										"wc_product_qty"	=> $wc_product_qty, 
										"wc_product_price"	=> $wc_product_price,
										"wc_product_device" => $wc_product_device,
										"wc_product_device_serial" => $wc_product_device_serial
									);
	
			if(isset($_POST["wc_product_tax"][$i])) {
				$wc_part_tax = sanitize_text_field($_POST["wc_product_tax"][$i]);
	
				$process_products_array["wc_product_tax"] = $wc_part_tax;
			}
	
			$insert_query =  "INSERT INTO `{$computer_repair_items}` VALUES(NULL, %s, 'products', %s)";
			
			$wpdb->query(
					$wpdb->prepare($insert_query, $wc_product_name, $post_id)
			);
			$order_item_id = $wpdb->insert_id;
			
			foreach($process_products_array as $key => $value) {
				$part_insert_query =  "INSERT INTO `{$computer_repair_items_meta}` VALUES(NULL, %s, %s, %s)";
	
				$wpdb->query(
					$wpdb->prepare($part_insert_query, $order_item_id, $key, $value)
				);
			}
		}//Parts Processed nicely
	endif;
	
	if(isset($_POST["wc_service_id"])):
	//Get Services and save to database first.
	for($i = 0; $i < count($_POST["wc_service_id"]); $i++) {
		$wc_service_id			= ( isset( $_POST['wc_service_id'][$i] ) ) ? sanitize_text_field($_POST["wc_service_id"][$i]) : '';
		$wc_service_name 		= ( isset( $_POST['wc_service_name'][$i] ) ) ? sanitize_text_field($_POST["wc_service_name"][$i]) : '';
		$wc_service_code 		= ( isset( $_POST['wc_service_code'][$i] ) ) ? sanitize_text_field($_POST["wc_service_code"][$i]) : '';
		$wc_service_qty 		= ( isset( $_POST['wc_service_qty'][$i] ) ) ? sanitize_text_field($_POST["wc_service_qty"][$i]) : '';
		$wc_service_price 		= ( isset( $_POST['wc_service_price'][$i] ) ) ? sanitize_text_field($_POST["wc_service_price"][$i]) : '';
		$wc_service_device		= ( isset( $_POST['wc_service_device'][$i] ) ) ? sanitize_text_field( $_POST['wc_service_device'][$i] ) : '';

		$wc_service_device_arr = explode( '_', $wc_service_device );
		$wc_service_device = ( isset( $wc_service_device_arr[0] ) ) ? $wc_service_device_arr[0] : '';
		$wc_service_device_serial = ( isset( $wc_service_device_arr[1] ) ) ? $wc_service_device_arr[1] : '';

		$process_service_array = array(
			"wc_service_code"	=> $wc_service_code, 
			"wc_service_id"		=> $wc_service_id, 
			"wc_service_qty"	=> $wc_service_qty, 
			"wc_service_price"	=> $wc_service_price,
			"wc_service_device"	=> $wc_service_device,
			"wc_service_device_serial" => $wc_service_device_serial
		);

		if(isset($_POST["wc_service_tax"][$i])) {
			$wc_service_tax = sanitize_text_field($_POST["wc_service_tax"][$i]);

			$process_service_array["wc_service_tax"] = $wc_service_tax;	
		}

		$insert_query =  "INSERT INTO `{$computer_repair_items}` VALUES(NULL, %s, 'services', %s)";
		 $wpdb->query(
				$wpdb->prepare($insert_query, $wc_service_name, $post_id)
		);
		$order_item_id = $wpdb->insert_id;
		
		foreach($process_service_array as $key => $value) {
			$service_insert_query =  "INSERT INTO `{$computer_repair_items_meta}` VALUES(NULL, %s, %s, %s)";

			$wpdb->query(
				$wpdb->prepare($service_insert_query, $order_item_id, $key, $value)
			);
		}
	}//Services Processed nicely
	endif;

	if(isset($_POST["wc_extra_name"])):
	//Get Services and save to database first.
	for($i = 0; $i < count($_POST["wc_extra_name"]); $i++) {
		$wc_extra_name 		= ( isset( $_POST['wc_extra_name'][$i] ) ) ? sanitize_text_field($_POST["wc_extra_name"][$i]) : '';
		
		$wc_extra_code 		= ( isset( $_POST['wc_extra_code'][$i] ) ) ? sanitize_text_field($_POST["wc_extra_code"][$i]) : '';
		$wc_extra_qty 		= ( isset( $_POST['wc_extra_qty'][$i] ) ) ? sanitize_text_field($_POST["wc_extra_qty"][$i]) : '';
		$wc_extra_price 	= ( isset( $_POST['wc_extra_price'][$i] ) ) ? sanitize_text_field($_POST["wc_extra_price"][$i]) : '';
		$wc_extra_device	= ( isset( $_POST['wc_extra_device'][$i] ) ) ? sanitize_text_field( $_POST['wc_extra_device'][$i] ) : '';

		$wc_extra_device_arr = explode( '_', $wc_extra_device );
		$wc_extra_device = ( isset( $wc_extra_device_arr[0] ) ) ? $wc_extra_device_arr[0] : '';
		$wc_extra_device_serial = ( isset( $wc_extra_device_arr[1] ) ) ? $wc_extra_device_arr[1] : '';

		$process_extra_array = array(
			"wc_extra_code"		=> $wc_extra_code, 
			"wc_extra_qty"		=> $wc_extra_qty, 
			"wc_extra_price"	=> $wc_extra_price,
			"wc_extra_name"		=> $wc_extra_name,
			"wc_extra_device"	=> $wc_extra_device,
			"wc_extra_device_serial" => $wc_extra_device_serial
		);

		if(isset($_POST["wc_extra_tax"][$i])) {
			$wc_extra_tax = sanitize_text_field($_POST["wc_extra_tax"][$i]);

			$process_extra_array["wc_extra_tax"] = $wc_extra_tax;	
		}

		$insert_query =  "INSERT INTO `{$computer_repair_items}` VALUES(NULL, %s, 'extras', %s)";
		 $wpdb->query(
				$wpdb->prepare($insert_query, $wc_extra_name, $post_id)
		);
		$order_item_id = $wpdb->insert_id;
		
		foreach($process_extra_array as $key => $value) {
			$extra_insert_query =  "INSERT INTO `{$computer_repair_items_meta}` VALUES(NULL, %s, %s, %s)";

			$wpdb->query(
				$wpdb->prepare($extra_insert_query, $order_item_id, $key, $value)
			);
		}

	}//Services Processed nicely
	endif;
	global $WCRB_WOO_FUNCTIONS_OBJ;
	
	$WCRB_WOO_FUNCTIONS_OBJ->wc_update_woo_stock_if_enabled( $post_id, $new_job_status );

	if ( ( $old_job_status != $new_job_status ) || empty ( $old_job_status ) ) {
		global $OBJ_SMS_SYSTEM;
		$wc_send_cr_notice 	= get_option( 'wc_job_status_cr_notice' );

		$is_sms_active = get_option( 'wc_rb_sms_active' );
		if ( $is_sms_active == 'YES' ) {
			$OBJ_SMS_SYSTEM->wc_rb_status_send_the_sms( $post_id, $new_job_status );
		}

		if ( function_exists( 'rb_qb_update_invoice_status' ) ) {
			rb_qb_update_invoice_status( $old_job_status, $new_job_status, $post_id );
		}

		if ( $wc_send_cr_notice == 'on' ) {
			$_GET['wc_case_number'] = sanitize_text_field( $_POST['case_number'] );
			
			wc_cr_send_customer_update_email( $post_id );
		}
	}
}
add_action( 'save_post', 'wc_jobs_features_save_box' );
//Add filter to show Meta Data in front end of post!


/*
*Add meta data to table fields post list.. 
*/
add_filter('manage_edit-rep_jobs_columns', 'wc_table_list_jobs_type_columns') ;

function wc_table_list_jobs_type_columns( $columns ) {
	$wc_device_label = ( empty( get_option( 'wc_device_label' ) ) ) ? esc_html__( 'Device', 'computer-repair-shop' ) : get_option( 'wc_device_label' );

	$columns = array(
		'cb' => '<input type="checkbox" />',
		'order_id' 			=> __( 'Order ID', 'computer-repair-shop' ),
		'title' 			=> __( 'Case Number', 'computer-repair-shop' ),
		'customers' 		=> __( 'Customer', 'computer-repair-shop' ),
		'device' 			=> $wc_device_label,
		'assigned_to' 		=> __( 'Assigned To', 'computer-repair-shop' ),
		'delivery_date' 	=> __( 'Delivery Date', 'computer-repair-shop' ),
		'invoice_total' 	=> __( 'Order Total', 'computer-repair-shop' ),
		'invoice_balance' 	=> __( 'Balance', 'computer-repair-shop' ),
		'wc_order_status' 	=> __( 'Order Status', 'computer-repair-shop' ),
		'wc_payment_status' => __( 'Payment Status', 'computer-repair-shop' ),
		'wc_job_actions' => __( 'Actions', 'computer-repair-shop' )
	);
	return $columns;
}
add_action( 'manage_rep_jobs_posts_custom_column', 'wc_table_jobs_list_meta_data', 10, 2 );

function wc_table_jobs_list_meta_data( $column, $post_id ) {
	global $post, $PAYMENT_STATUS_OBJ;

	$allowedHTML = wc_return_allowed_tags(); 

	$theGrandTotal  = wc_order_grand_total( $post_id, 'grand_total' );
	$theBalance     = wc_order_grand_total( $post_id, 'balance' );

	$wc_device_id_imei_label = ( empty( get_option( 'wc_device_id_imei_label' ) ) ) ? esc_html__( 'ID/IMEI', 'computer-repair-shop' ) : get_option( 'wc_device_id_imei_label' );

	switch( $column ) {
		case 'order_id' :
			$theOrderId = "# ".$post_id; 
			echo esc_html( $theOrderId );
		break;
		case 'customers' :
			$customer 		= get_post_meta( $post_id, '_customer', true );
			
			if(!empty($customer)) {
				$user 			= get_user_by( 'id', $customer );
				$phone_number 	= get_user_meta( $customer, "billing_phone", true );
				$billing_tax 	= get_user_meta( $customer, "billing_tax", true );
				$company 		= get_user_meta( $customer, "billing_company", true );
				
				$first_name		= empty($user->first_name)? "" : $user->first_name;
				$last_name 		= empty($user->last_name)? "" : $user->last_name;
				$theFullName 	= $first_name. ' ' .$last_name;
				$email 			= empty( $user->user_email ) ? "" : $user->user_email;
				echo esc_html( $theFullName );

				if(!empty($phone_number)) {
					echo "<br>".esc_html__("P", "computer-repair-shop").": ".esc_html( $phone_number );
				}
				if ( ! empty( $email ) ) {
					echo "<br>" . esc_html__( "E", "computer-repair-shop").": ".esc_html( $email );	
				}
				if ( ! empty( $company ) ) {
					echo "<br>" . esc_html__( "Company", "computer-repair-shop" ) . ": " . esc_html( $company );	
				}
				if ( ! empty( $billing_tax ) ) {
					echo "<br>" . esc_html__( "Tax ID", "computer-repair-shop" ) . ": " . esc_html( $billing_tax );	
				}
			}	
		break;
		case 'device' :
			$device_post_id	 = get_post_meta( $post_id, '_device_post_id', true );
			$current_devices = get_post_meta( $post_id, '_wc_device_data', true );

			$setup_new_type = ( ! empty ( $device_post_id ) ) ? wc_set_new_device_format( $post_id ) : '';

			if ( ! empty( $current_devices )  && is_array( $current_devices ) ) {
				$counter = 0;
				$content = '';
				foreach( $current_devices as $device_data ) {
					$content .= ( $counter != 0 ) ? '<br>' : '';				
					$device_post_id = ( isset( $device_data['device_post_id'] ) ) ? $device_data['device_post_id'] : '';
					$device_id      = ( isset( $device_data['device_id'] ) ) ? $device_data['device_id'] : '';
	
					$content .= return_device_label( $device_post_id );
					$content .= ( ! empty ( $device_id ) ) ? ' (' . esc_html( $device_id ) . ')' : '';
					$counter++;
				}
				echo wp_kses_post( $content );
			}
		break;
		case 'assigned_to' :
			$technician 	= get_post_meta($post_id, '_technician', true);
			if(!empty($technician)) {
				$tech_user 		= get_user_by('id', $technician);

				$techName = $tech_user->first_name . ' ' . $tech_user->last_name;
				echo esc_html( $techName );
			}	
		break;	
		case 'delivery_date':
			$delivery_date = get_post_meta( $post_id, '_delivery_date', true );
			
			if(!empty($delivery_date)) {
				$date_format = get_option( 'date_format' );
				$delivery_date = date_i18n( $date_format, strtotime( $delivery_date ) );
				echo esc_html( $delivery_date );
			}
		break;
		case 'invoice_total':
			$thePrice = wc_cr_currency_format( $theGrandTotal );
			echo esc_html( $thePrice );
		break;
		case 'invoice_balance':
			$theClass = ( $theBalance > 0 ) ? 'abovezero' : 'isequalzero';

			$thePrice = '<span class="' . esc_attr( $theClass ) . '">' . wc_cr_currency_format( $theBalance ) . '</span>';
			echo wp_kses( $thePrice, $allowedHTML );
		break;
		case 'wc_order_status' :
			$wc_order_status = get_post_meta( $post_id, '_wc_order_status', true );

			$order_statuses = '<select name="wc_update_order_status" style="max-width:100%;" class="update_status" data-post="'.$post_id.'">';

			if ( empty( $wc_order_status ) ) {
				$wc_order_status = "new";
			}
			$order_statuses .= wc_generate_status_options($wc_order_status);
			$order_statuses .= '</select>';

            echo wp_kses( $order_statuses, $allowedHTML );
		break;
		case 'wc_payment_status' :
			$wc_payment_status = get_post_meta( $post_id, '_wc_payment_status', true );
			
			$payment_status = $PAYMENT_STATUS_OBJ->wc_generate_payment_status_array( 'all' );

			$wc_payment_status = empty ( $wc_payment_status ) ? "nostatus" : $wc_payment_status;
			
			echo esc_html( $payment_status[ $wc_payment_status ] );
		break;
		case 'wc_job_actions' :
			$actions_output = '<div class="actionswrapperjobs">';
			
			$actions_output .= '<a class="cursorpointer" title="' . esc_html__( 'Take Payment', 'computer-repair-shop' ) . '" data-open="addjoblistpaymentreveal" recordid="' . esc_attr( $post_id ) . '"><span class="dashicons dashicons-money-alt"></span></a>';

			$actions_output .= '<a title="' . esc_html__( 'Print invoice', 'computer-repair-shop' ) . '" target="_blank" href="admin.php?page=wc_computer_repair_print&order_id=' . $post_id . '"><span class="dashicons dashicons-printer"></span></a>';
			$actions_output .= '<a title="' . esc_html__( 'Email details to customer', 'computer-repair-shop' ) . '" target="_blank" href="admin.php?page=wc_computer_repair_print&order_id=' . $post_id . '&email_customer=yes"><span class="dashicons dashicons-email-alt"></span></a>';
			$actions_output .= '<a class="cursorpointer" title="' . esc_html__( 'Duplicate job', 'computer-repair-shop' ) . '" data-open="wcrbduplicatejob" recordid="' . esc_attr( $post_id ) . '"><span class="dashicons dashicons-tickets-alt"></span></a>';
			$actions_output .= '<a title="' . esc_html__( 'View or Edit', 'computer-repair-shop' ) . '" href="' . get_edit_post_link( $post_id ) . '" target="_blank"/><span class="dashicons dashicons-edit-page"></span></a>';
			$actions_output .= '</div>';

			echo wp_kses( $actions_output, $allowedHTML );
		break;
		//Break for everything else to show default things.
		default :
			break;
	}
}


if(!function_exists("wc_extend_jobs_admin_search")):
	function wc_extend_jobs_admin_search( $query ) {

		// Extend search for document post type
		$post_type = 'rep_jobs';
		$estimate_type = 'rep_estimates';
		// Custom fields to search for
		$custom_fields = array(
			"_order_id",
			"_customer_label",
			"_wc_order_status_label",
			"_wc_payment_status_label",
			"_device_id",
			"_wc_device_data"
		);
		
		if( ! is_admin() )
			return;

		if ( $query->query_vars['post_type'] != $post_type && $query->query_vars['post_type'] != $estimate_type )
			return;

		$search_term = $query->query_vars['s'];

		// Set to empty, otherwise it won't find anything
		$query->query_vars['s'] = '';

		$query->set('_meta_or_title', $search_term);

		if ( $search_term != '' ) {
			$meta_query = array( 'relation' => 'OR' );

			foreach( $custom_fields as $custom_field ) {
				array_push( $meta_query, array(
					'key' => $custom_field,
					'value' => $search_term,
					'compare' => 'LIKE'
				));
			}
			$query->set( 'meta_query', $meta_query );
		};
	}
	add_action( 'pre_get_posts', 'wc_extend_jobs_admin_search', 6, 2);

	add_action( 'pre_get_posts', function( $q ) {
		if( $title = $q->get( '_meta_or_title' ) ) {
			add_filter( 'get_meta_sql', function( $sql ) use ( $title ) {
				global $wpdb;

				// Only run once:
				static $nr = 0; 
				if( 0 != $nr++ ) return $sql;

				// Modified WHERE
				$sql['where'] = sprintf(
					" AND ( %s OR %s ) ",
					$wpdb->prepare( "{$wpdb->posts}.post_title like '%%%s%%'", $title),
					mb_substr( $sql['where'], 5, mb_strlen( $sql['where'] ) )
				);

				return $sql;
			}, 12, 1);
		}
	}, 12, 1);
endif;


/**
 * Job Status Filter
 * @since 3.0
 * @return void
 */
if(!function_exists("wc_filter_jobs_by_status")):
	function wc_filter_jobs_by_status() {
		global $typenow, $PAYMENT_STATUS_OBJ, $wp_query;

		if ( $typenow == 'rep_jobs' || $typenow == 'rep_estimates' ) { // Your custom post type slug
			
			if ( $typenow == 'rep_jobs' ) :
			$current_status = '';
			if( isset( $_GET['wc_job_status'] ) ) {
				$current_status = sanitize_text_field( $_GET['wc_job_status'] ); // Check if option has been selected
			} ?>
			<select name="wc_job_status" id="wc_job_status">
				<option value="all" <?php selected( 'all', $current_status); ?>><?php _e( 'Job Status (All)', 'computer-repair-shop' ); ?></option>
			<?php
				$allowed_html = wc_return_allowed_tags();
				$optionsGenerated = wc_generate_status_options($current_status);
				echo wp_kses($optionsGenerated, $allowed_html);
			?>
			</select>
			
			<?php 
				endif;

				if ( function_exists( 'wc_store_select_options' ) ) : ?>
			<select name="wc_store" id="wc_store">
				<option value="all"><?php echo esc_html__( 'Store (All)', 'computer-repair-shop' ); ?></option>
				<?php
					$selected_store = '';
					if ( isset( $_GET['wc_store'] ) ) {
						$selected_store = sanitize_text_field( $_GET['wc_store'] );
					}
					echo wp_kses( wc_store_select_options( $selected_store ), $allowed_html );
				?>
			</select>
			<?php endif; ?>
			
			<?php if ( wcrb_use_woo_as_devices() == 'YES' ) {
				$wc_device_label = ( empty( get_option( 'wc_device_label' ) ) ) ? esc_html__( 'Device', 'computer-repair-shop' ) : get_option( 'wc_device_label' );

				$theSearchClass = ( ! empty( get_option('wcrb_special_PR_Search_class') ) ) ? get_option('wcrb_special_PR_Search_class') : 'bc-product-search';

				$contentSel = '<select name="device_post_id" id="rep_devices" 
				data-display_stock="true" 
				data-exclude_type="variable" 
				data-security="' . wp_create_nonce( 'search-products' ) . '" class="' . esc_attr( $theSearchClass ) . ' form-control"><option value="">' . $wc_device_label . ' ...'. '</option></select>';
				$allowed_html = wc_return_allowed_tags();
				echo wp_kses( $contentSel, $allowed_html );
			} else { ?>
			<select id="rep_devices" name="device_post_id">
			<?php
				$device_post_id = (isset($_GET["device_post_id"])) ? sanitize_text_field($_GET["device_post_id"]): "";
				$allowed_html = wc_return_allowed_tags();
				$optionsGenerated = wc_generate_device_options( $device_post_id );
				echo wp_kses($optionsGenerated, $allowed_html);
			?>	
			</select>
			<?php }

			if ( $typenow == 'rep_jobs' ) :
			//Payment Status Processing
			$payment_status = $PAYMENT_STATUS_OBJ->wc_generate_payment_status_array( 'active' );

			$current_payment_status = '';
			if( isset( $_GET['wc_payment_status'] ) ) {
				$current_payment_status = sanitize_text_field( $_GET['wc_payment_status'] ); // Check if option has been selected
			} ?>
			<select name="wc_payment_status" id="wc_payment_status">
				<option value="all" <?php selected( 'all', $current_payment_status); ?>><?php _e( 'Payment Status (All)', 'computer-repair-shop' ); ?></option>
			<?php foreach( $payment_status as $key=>$value ) { ?>
				<option value="<?php echo esc_attr( $key ); ?>" <?php selected( $key, $current_payment_status); ?>><?php echo esc_attr( $value ); ?></option>
			<?php } ?>
			</select>	
		<?php
			endif;

			//By Customer
			$current_job_customer = '';
			if( isset( $_GET['job_customer'] ) ) {
				$current_job_customer = sanitize_text_field( $_GET['job_customer'] ); // Check if option has been selected
			} 
			
			$allowed_html = wc_return_allowed_tags();
			$optionsGenerated = wcrb_return_customer_select_options( $current_job_customer, 'job_customer', 'updatenone' );
			echo wp_kses( $optionsGenerated, $allowed_html);

			//By Technician
			$current_job_technician = '';
			if( isset( $_GET['job_technician'] ) ) {
				$current_job_technician = sanitize_text_field( $_GET['job_technician'] ); // Check if option has been selected
			} 

			wp_dropdown_users( array( 'show_option_all' => esc_html__('Technician (All)', 'computer-repair-shop'), 'name' => 'job_technician', 'role' => 'technician', 'echo' => 1, 'selected' => $current_job_technician));
		}
	}
	add_action( 'restrict_manage_posts', 'wc_filter_jobs_by_status');
endif;	

/**
 * Update job status query
 * @since 3.0
 * @return void
 */
if(!function_exists("wc_filter_jobs_by_status_query")):
	function wc_filter_jobs_by_status_query( $query ) {
		global $pagenow;
		$type = 'rep_jobs';
		
		if (isset($_GET['post_type']) && 
		( $query->query["post_type"] == $type || $query->query["post_type"] == 'rep_estimates' ) && 
		( $_GET["post_type"] == $type || $query->query["post_type"] == 'rep_estimates' ) &&
		$pagenow=='edit.php') {

			$queryParamsCounter = 0;
			if (isset( $_GET['wc_job_status']) && $_GET['wc_job_status'] !='all') {
				$wc_job_status = sanitize_text_field( $_GET['wc_job_status'] );
				$queryParamsCounter++;
			}

			if ( isset( $_GET["device_post_id"] ) && ! empty( $_GET["device_post_id"] ) && $_GET["device_post_id"] != 'All' ) {
				$queryParamsCounter++;
				$device_post_id = (int)sanitize_text_field( $_GET['device_post_id'] );
			}

			if (isset( $_GET['wc_payment_status'] ) && $_GET['wc_payment_status'] != 'all') {
				$queryParamsCounter++;
				$wc_payment_status = sanitize_text_field( $_GET['wc_payment_status'] );
			}

			if (isset( $_GET['wc_store'] ) && $_GET['wc_store'] !='all') {
				$queryParamsCounter++;
				$wc_store = (int)sanitize_text_field( $_GET['wc_store'] );
			}

			if (isset( $_GET['job_customer'] ) && $_GET['job_customer'] !='0' && ! empty( $_GET['job_customer'] ) ) {
				$queryParamsCounter++;
				$wc_job_customer = (int)sanitize_text_field( $_GET['job_customer'] );
			}

			if (isset( $_GET['job_technician'] ) && $_GET['job_technician'] != '0' ) {
				$queryParamsCounter++;
				$wc_job_technician = (int)sanitize_text_field( $_GET['job_technician'] );
			}

			$meta_query = array();

			if ($queryParamsCounter > 1) {
				$meta_query['relation'] = 'AND';
			}

			if (isset($wc_job_status)) {
				$meta_query[] =	array(
					'key' 		=> '_wc_order_status',
					'value'    	=> $wc_job_status,
					'compare' 	=> '=',
					'type'    	=> 'CHAR',  
				);
			}
			if (isset($wc_store)) {
				$meta_query[] =	array(
					'key' 		=> '_store_id',
					'value'    	=> $wc_store,
					'compare' 	=> '=',
					'type'    	=> 'NUMERIC',  
				);
			}
			if ( isset( $device_post_id ) ) {
				$meta_query[] =	array(
					'key' 		=> '_wc_device_data',
					'value' 	=> sprintf( ':"%s";', $device_post_id ),
		            'compare' 	=> 'LIKE',
					'type'    	=> 'CHAR',  
				);
			}
			if (isset($wc_payment_status)) {
				$meta_query[] =	array(
					'key' 		=> '_wc_payment_status',
					'value'    	=> $wc_payment_status,
					'compare' 	=> '=',
					'type'    	=> 'CHAR',  
				);
			}
			if(isset($wc_job_customer)) {
				$meta_query[] =	array(
					'key' 		=> '_customer',
					'value'    	=> $wc_job_customer,
					'compare' 	=> '=',
					'type'    	=> 'NUMERIC',  
				);
			}
			if(isset($wc_job_technician)) {
				$meta_query[] =	array(
					'key' 		=> '_technician',
					'value'    	=> $wc_job_technician,
					'compare' 	=> '=',
					'type'    	=> 'NUMERIC',  
				);
			}
			$query->set( 'meta_query', $meta_query );
		}
	}
	add_filter( 'parse_query', 'wc_filter_jobs_by_status_query');
endif;	