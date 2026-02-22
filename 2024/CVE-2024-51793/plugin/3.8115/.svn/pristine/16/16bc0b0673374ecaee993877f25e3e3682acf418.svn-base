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

class WCRB_ESTIMATES {

	private $TABID = "wcrb_estimates_tab";

	function __construct() {
        add_action( 'wc_rb_settings_tab_menu_item', array( $this, 'add_estimate_tab_in_settings_menu' ), 10, 2 );
        add_action( 'wc_rb_settings_tab_body', array( $this, 'add_estimate_tab_in_settings_body' ), 10, 2 );
		add_action( 'wp_ajax_wc_rb_update_estimate_settings', array( $this, 'wc_rb_update_estimate_settings' ) );
		add_action( 'wp_ajax_wcrb_generate_repair_order_from_estimate', array( $this, 'wcrb_generate_repair_order_from_estimate' ) );
		add_action( 'wp_ajax_wcrb_send_estimate_to_customer', array( $this, 'wcrb_send_estimate_to_customer' ) );

		$wcrb_turn_estimates_on = get_option( 'wcrb_turn_estimates_on' );

		if ( $wcrb_turn_estimates_on != 'on' ) {
			//Register Estimate Post type.
			add_action( 'init', array( $this, 'wcrb_estimates_post_type' ) );

			add_action( 'admin_menu', array( $this, 'wcrb_estimate_admin_menu' ), 99 );

			add_action( 'add_meta_boxes', array( $this, 'wcrb_estimate_features' ), 15 );

			add_action( 'save_post', array( $this, 'wcrb_save_estimate_post' ) );

			add_action( 'manage_rep_estimates_posts_custom_column', array( $this, 'wcrb_estimate_table_meta_data' ), 10, 2 );
			
			add_filter('manage_edit-rep_estimates_columns', array( $this, 'wcrb_estimate_columns' ) ) ;
		}
    }

	function add_estimate_tab_in_settings_menu() {
        $active = '';

        $menu_output = '<li class="tabs-title' . esc_attr($active) . '" role="presentation">';
        $menu_output .= '<a href="#' . esc_attr( $this->TABID ) . '" role="tab" aria-controls="' . esc_attr( $this->TABID ) . '" aria-selected="true" id="' . esc_attr( $this->TABID ) . '-label">';
        $menu_output .= '<h2>' . esc_html__( 'Estimates', 'computer-repair-shop' ) . '</h2>';
        $menu_output .=	'</a>';
        $menu_output .= '</li>';

        echo wp_kses_post( $menu_output );
    }
	
	function add_estimate_tab_in_settings_body() {
        global $wpdb, $WCRB_MANAGE_DEVICES;

        $active = '';
		
		$setting_body = '<div class="tabs-panel team-wrap' . esc_attr( $active ) . '" 
        id="' . esc_attr( $this->TABID ) . '" 
        role="tabpanel" 
        aria-hidden="true" 
        aria-labelledby="' . esc_attr( $this->TABID ) . '-label">';

		$setting_body .= '<div class="wc-rb-manage-devices">';
		$setting_body .= '<h2>' . esc_html__( 'Estimate Settings', 'computer-repair-shop' ) . '</h2>';
		$setting_body .= '<div class="estimate_success_msg"></div>';
		
		$setting_body .= '<form data-async data-abide class="needs-validation" novalidate method="post" data-success-class=".estimate_success_msg">';

		$setting_body .= '<div class="wc-rb-grey-bg-box">';
		$setting_body .= '<h2>' . esc_html__( 'Estimate Email To Customer', 'computer-repair-shop' ) . '</h2>';
		$setting_body .= '<div class="grid-container"><div class="grid-x grid-padding-x">';

		$menu_name_p 	= get_option( 'blogname' );
		$value 		  = ( ! empty ( get_option( 'estimate_email_subject_to_customer' ) ) ) ? get_option( 'estimate_email_subject_to_customer' ) : 'You have received an estimate! | ' . $menu_name_p;

		$setting_body .= '<div class="medium-12 cell"><label for="estimate_email_subject_to_customer">
							' . esc_html__( 'Email subject', 'computer-repair-shop' ) . '
								<input type="text" id="estimate_email_subject_to_customer" name="estimate_email_subject_to_customer" value="' . esc_html( $value ) . '" />
							</label></div>';

		$saved_message = ( empty( get_option( 'estimate_email_body_to_customer' ) ) ) ? '' : get_option( 'estimate_email_body_to_customer' );

$message = 'Hello {{customer_full_name}},

We have prepared an estimate for you. If you have further questions please contact us.

Your estimate details are listed below. You can approve or reject estimate as per your choice. If you have questions please get in touch.

Approve/Reject the Estimate

{{start_approve_estimate_link}}Approve Estimate{{end_approve_estimate_link}}

{{start_reject_estimate_link}}Reject Estimate {{end_reject_estimate_link}}


{{order_invoice_details}}

Thank you again for your business!';
							
		$saved_message = ( empty( $saved_message ) ) ? $message : $saved_message;						

		$setting_body .= '<div class="medium-12 cell"><label for="estimate_email_body_to_customer">
							'. esc_html__( 'Email body', 'computer-repair-shop' ) .'<br>
							'. esc_html__( 'Available Keywords', 'computer-repair-shop' ) .' {{customer_full_name}} {{customer_device_label}} {{order_invoice_details}} {{job_id}} {{case_number}} <br> {{start_approve_estimate_link}}Approve Estimate{{end_approve_estimate_link}}
								{{start_reject_estimate_link}}Reject Estimate {{end_reject_estimate_link}}
							<textarea id="estimate_email_body_to_customer" name="estimate_email_body_to_customer" rows="4">'. esc_textarea( $saved_message ) .'</textarea>
						</label></div>';
		
		//Estimate email template Ends to Customer ...						
		$setting_body .= '</div></div><!-- End of grid Container and Grid X /-->';
		$setting_body .= '</div>';

		$setting_body .= '<table class="form-table border"><tbody>';

		$setting_body .= '<tr>
							<th scope="row">
								<label for="wcrb_turn_estimates_on">
									' . esc_html__( 'Disable Estimates', 'computer-repair-shop' ) . '
								</label>
							</th>';
		$setting_body .= '<td>';

		$wcrb_turn_estimates_on = get_option( 'wcrb_turn_estimates_on' );
		$wcrb_turn_estimates_on = ( $wcrb_turn_estimates_on == 'on' ) ? 'checked="checked"' : '';
		
		$setting_body .= '<input type="checkbox" ' . esc_html( $wcrb_turn_estimates_on ) . ' name="wcrb_turn_estimates_on" id="wcrb_turn_estimates_on" />';
		
		$setting_body .= '<label for="wcrb_turn_estimates_on">';
		$setting_body .= esc_html__( 'Disable estimates and reload page ', 'computer-repair-shop' );
		$setting_body .= '</label></td></tr>';

		$setting_body .= '<tr>
							<th scope="row">
								<label for="wcrb_turn_booking_forms_to_jobs">
									' . esc_html__( 'Booking & Quote Forms', 'computer-repair-shop' ) . '
								</label>
							</th>';
		$setting_body .= '<td>';

		$wcrb_turn_booking_forms_to_jobs = get_option( 'wcrb_turn_booking_forms_to_jobs' );
		$wcrb_turn_booking_forms_to_jobs = ( $wcrb_turn_booking_forms_to_jobs == 'on' ) ? 'checked="checked"' : '';
		
		$setting_body .= '<input type="checkbox" ' . esc_html( $wcrb_turn_booking_forms_to_jobs ) . ' name="wcrb_turn_booking_forms_to_jobs" id="wcrb_turn_booking_forms_to_jobs" />';
		
		$setting_body .= '<label for="wcrb_turn_booking_forms_to_jobs">';
		$setting_body .= esc_html__( 'Send booking forms & quote forms to jobs instead of estimates ', 'computer-repair-shop' );
		$setting_body .= '</label></td></tr>';

		$setting_body .= '<tr><td colspan="2">'. esc_html__( 'You should have set the page with status check shortcode in Pages Setup menu for Select Status Check Page, for estimate approval and rejection links to be sent in email and work.', 'computer-repair-shop' ) .'</td></tr>';

		$setting_body .= '</tbody></table>';

		//Estimate approve email
		$setting_body .= '<div class="wc-rb-grey-bg-box">';
		$setting_body .= '<h2>' . esc_html__( 'Estimate approve email to admin', 'computer-repair-shop' ) . '</h2>';
		$setting_body .= '<div class="grid-container"><div class="grid-x grid-padding-x">';

		$menu_name_p 	= get_option( 'blogname' );
		$value 		  = ( ! empty ( get_option( 'estimate_approve_email_subject_to_admin' ) ) ) ? get_option( 'estimate_approve_email_subject_to_admin' ) : 'Congratulations! Customer have approved your estimate! | ' . $menu_name_p;

		$setting_body .= '<div class="medium-12 cell"><label for="estimate_approve_email_subject_to_admin">
							' . esc_html__( 'Email subject', 'computer-repair-shop' ) . '
								<input type="text" id="estimate_approve_email_subject_to_admin" name="estimate_approve_email_subject_to_admin" value="' . esc_html( $value ) . '" />
							</label></div>';

		$saved_message = ( empty( get_option( 'estimate_approve_email_body_to_admin' ) ) ) ? '' : get_option( 'estimate_approve_email_body_to_admin' );

$message = 'Hello,

Estimate you sent to {{customer_full_name}} have been approved by customer and converted to job.

Job ID : {{job_id}} created from Estimate ID : {{estimate_id}}

Thank you!';
							
		$saved_message = ( empty( $saved_message ) ) ? $message : $saved_message;						

		$setting_body .= '<div class="medium-12 cell"><label for="estimate_approve_email_body_to_admin">
							'. esc_html__( 'Email body', 'computer-repair-shop' ) .'<br>
							'. esc_html__( 'Available Keywords', 'computer-repair-shop' ) .' {{customer_full_name}} {{customer_device_label}} {{order_invoice_details}} {{job_id}} {{estimate_id}} {{case_number}}
							<textarea id="estimate_approve_email_body_to_admin" name="estimate_approve_email_body_to_admin" rows="4">'. esc_textarea( $saved_message ) .'</textarea>
						</label></div>';
		
		//Estimate email template Ends to Customer ...						
		$setting_body .= '</div></div><!-- End of grid Container and Grid X /-->';
		$setting_body .= '</div>';
		//Estimate approve email ends

		//Estimate reject email
		$setting_body .= '<div class="wc-rb-grey-bg-box">';
		$setting_body .= '<h2>' . esc_html__( 'Estimate reject email to admin', 'computer-repair-shop' ) . '</h2>';
		$setting_body .= '<div class="grid-container"><div class="grid-x grid-padding-x">';

		$menu_name_p 	= get_option( 'blogname' );
		$value 		  = ( ! empty ( get_option( 'estimate_reject_email_subject_to_admin' ) ) ) ? get_option( 'estimate_reject_email_subject_to_admin' ) : 'Estimate have been rejected! | ' . $menu_name_p;

		$setting_body .= '<div class="medium-12 cell"><label for="estimate_reject_email_subject_to_admin">
							' . esc_html__( 'Email subject', 'computer-repair-shop' ) . '
								<input type="text" id="estimate_reject_email_subject_to_admin" name="estimate_reject_email_subject_to_admin" value="' . esc_html( $value ) . '" />
							</label></div>';

		$saved_message = ( empty( get_option( 'estimate_reject_email_body_to_admin' ) ) ) ? '' : get_option( 'estimate_reject_email_body_to_admin' );

$message = 'Hello,

Estimate you sent to {{customer_full_name}} have been rejected by customer.

Estimate ID : {{estimate_id}}

Thank you!';
							
		$saved_message = ( empty( $saved_message ) ) ? $message : $saved_message;					

		$setting_body .= '<div class="medium-12 cell"><label for="estimate_reject_email_body_to_admin">
							'. esc_html__( 'Email body', 'computer-repair-shop' ) .'<br>
							'. esc_html__( 'Available Keywords', 'computer-repair-shop' ) .' {{customer_full_name}} {{customer_device_label}} {{order_invoice_details}} {{estimate_id}} {{case_number}}
							<textarea id="estimate_reject_email_body_to_admin" name="estimate_reject_email_body_to_admin" rows="4">'. esc_textarea( $saved_message ) .'</textarea>
						</label></div>';
		
		//Estimate email template Ends to Customer ...						
		$setting_body .= '</div></div><!-- End of grid Container and Grid X /-->';
		$setting_body .= '</div>';
		//Estimate reject email ends

		$setting_body .= '<input type="hidden" name="form_type" value="wcrb_update_settings_form" />';
		$setting_body .= '<input type="hidden" name="form_action" value="wc_rb_update_estimate_settings" />';
		
		$setting_body .= wp_nonce_field( 'wcrb_nonce_estimates', 'wcrb_nonce_estimates_field', true, false );

		$setting_body .= '<button type="submit" class="button button-primary" data-type="rbssubmitdevices">' . esc_html__( 'Update Options', 'computer-repair-shop' ) . '</button></form>';

		$setting_body .= '</div><!-- wc rb Devices /-->';
		$setting_body .= '</div><!-- Tabs Panel /-->';

		$allowedHTML = ( function_exists( 'wc_return_allowed_tags' ) ) ? wc_return_allowed_tags() : '';
		echo wp_kses( $setting_body, $allowedHTML );
	}

	function wc_rb_update_estimate_settings() {
		$message = '';
		$success = 'NO';

		if ( ! isset( $_POST['wcrb_nonce_estimates_field'] ) || ! wp_verify_nonce( $_POST['wcrb_nonce_estimates_field'], 'wcrb_nonce_estimates' ) ) {
			$message = esc_html__( 'Couldn\'t verify nonce please reload page.', 'computer-repair-shop' );
		} else {
			// process form data
			$wcrb_turn_estimates_on = ( ! isset( $_POST['wcrb_turn_estimates_on'] ) ) ? '' : sanitize_text_field( $_POST['wcrb_turn_estimates_on'] );
			$wcrb_turn_booking_forms_to_jobs = ( ! isset( $_POST['wcrb_turn_booking_forms_to_jobs'] ) ) ? '' : sanitize_text_field( $_POST['wcrb_turn_booking_forms_to_jobs'] );

			$estimate_email_subject_to_customer = ( ! isset( $_POST['estimate_email_subject_to_customer'] ) || empty( $_POST['estimate_email_subject_to_customer'] ) ) ? '' : sanitize_text_field( $_POST['estimate_email_subject_to_customer'] );
			$estimate_email_body_to_customer	= ( ! isset( $_POST['estimate_email_body_to_customer'] ) || empty( $_POST['estimate_email_body_to_customer'] ) ) ? '' : sanitize_textarea_field( $_POST['estimate_email_body_to_customer'] );

			$estimate_approve_email_subject_to_admin = ( ! isset( $_POST['estimate_approve_email_subject_to_admin'] ) || empty( $_POST['estimate_approve_email_subject_to_admin'] ) ) ? '' : sanitize_text_field( $_POST['estimate_approve_email_subject_to_admin'] );
			$estimate_approve_email_body_to_admin = ( ! isset( $_POST['estimate_approve_email_body_to_admin'] ) || empty( $_POST['estimate_approve_email_body_to_admin'] ) ) ? '' : sanitize_textarea_field( $_POST['estimate_approve_email_body_to_admin'] );

			update_option( 'estimate_approve_email_subject_to_admin', $estimate_approve_email_subject_to_admin );
			update_option( 'estimate_approve_email_body_to_admin', $estimate_approve_email_body_to_admin );

			$estimate_reject_email_subject_to_admin = ( ! isset( $_POST['estimate_reject_email_subject_to_admin'] ) || empty( $_POST['estimate_reject_email_subject_to_admin'] ) ) ? '' : sanitize_text_field( $_POST['estimate_reject_email_subject_to_admin'] );
			$estimate_reject_email_body_to_admin = ( ! isset( $_POST['estimate_reject_email_body_to_admin'] ) || empty( $_POST['estimate_reject_email_body_to_admin'] ) ) ? '' : sanitize_textarea_field( $_POST['estimate_reject_email_body_to_admin'] );

			update_option( 'estimate_reject_email_subject_to_admin', $estimate_reject_email_subject_to_admin );
			update_option( 'estimate_reject_email_body_to_admin', $estimate_reject_email_body_to_admin );

			update_option( 'wcrb_turn_estimates_on', 			 $wcrb_turn_estimates_on );
			update_option( 'estimate_email_subject_to_customer', $estimate_email_subject_to_customer );
			update_option( 'estimate_email_body_to_customer', 	 $estimate_email_body_to_customer );
			update_option( 'wcrb_turn_booking_forms_to_jobs', 	 $wcrb_turn_booking_forms_to_jobs );

			$message = esc_html__( 'Settings updated!', 'computer-repair-shop' );
		}

		$values['message'] = $message;
		$values['success'] = $success;

		wp_send_json( $values );
		wp_die();
	}

	//Estimate admin menu
	function wcrb_estimate_admin_menu() {
		add_submenu_page( 'wc-computer-rep-shop-handle', __( 'Repair Estimates', 'computer-repair-shop' ), __( 'Estimates', 'computer-repair-shop' ), 
		'edit_rep_job', 'edit.php?post_type=rep_estimates', '', 1099 );
	}

	//Estimate job post
	function wcrb_estimates_post_type() {
		$labels = array(
			'add_new_item' 			=> esc_html__( 'Add New Estimate', 'computer-repair-shop'),
			'singular_name' 		=> esc_html__( 'Estimate', 'computer-repair-shop'), 
			'menu_name' 			=> esc_html__( 'Estimates', 'computer-repair-shop'),
			'all_items' 			=> esc_html__( 'Estimates', 'computer-repair-shop'),
			'edit_item' 			=> esc_html__( 'Edit Estimate', 'computer-repair-shop'),
			'new_item' 				=> esc_html__( 'New Estimate', 'computer-repair-shop'),
			'view_item' 			=> esc_html__( 'View Estimate', 'computer-repair-shop'),
			'search_items' 			=> esc_html__( 'Search Estimate', 'computer-repair-shop'),
			'not_found' 			=> esc_html__( 'No Estimate found', 'computer-repair-shop'),
			'not_found_in_trash' 	=> esc_html__( 'No Estimate in trash', 'computer-repair-shop')
		);

		$args = array(
			'labels'             	=> $labels,
			'label'					=> esc_html__( 'Estimates', 'computer-repair-shop' ),
			'description'        	=> esc_html__( 'Estimates Section', 'computer-repair-shop' ),
			'public'             	=> false,
			'publicly_queryable' 	=> false,
			'show_ui'            	=> true,
			'show_in_menu'       	=> false,
			'query_var'          	=> true,
			'rewrite'            	=> array('slug' => 'estimate'),
			'capability_type'    	=> array('rep_job', 'rep_jobs'),
			'has_archive'        	=> true,
			'menu_icon'			 	=> 'dashicons-clipboard',
			'menu_position'      	=> 30,
			'supports'           	=> array(''), 	
			'register_meta_box_cb' 	=> array( $this, 'wcrb_estimate_features' ),
		);
		register_post_type( 'rep_estimates', $args );
	}

	function wcrb_estimate_features() { 
		add_meta_box( 'wc_order_info_id', esc_html__('Order Information', 'computer-repair-shop' ), array( $this, 'wcrb_estimate_information' ), 'rep_estimates', 'side', 'high' );
	
		//Second Metabox
		add_meta_box( 'wc_job_details_box', esc_html__( 'Job Details', 'computer-repair-shop' ), array( $this, 'wcrb_estimate_details' ), 'rep_estimates', 'advanced', 'high' );
	} //Parts features post.
	
	function wcrb_estimate_information( $post ) {
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
	
		$wc_use_taxes 		= get_option("wc_use_taxes");
		$parts_returned 	= wc_print_existing_parts( $post->ID );
	
		$content = '<div class="order_calculations">';
	
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
	
		if($wc_use_taxes == "on"):
			if(is_parts_switch_woo() == false || !empty($parts_returned)):
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
		
		
		$content .= '<div class="wc_order_note_wrap"><h3>';
		
		$order_notes = get_post_meta( $post->ID, '_wc_order_note', true );
		$content .= esc_html__( 'Order Notes:', 'computer-repair-shop' );
		$content .= '</h3><textarea name="wc_order_note">';
		$content .= $order_notes;
		$content .= '</textarea></div>';
	
		$content .= "</div>";
		$content .= '<div class="order_action_messages"></div>';
		$content .= '<div class="the-wc-rb-job-actions">';
	
		//Print Repair Order!
		$content .= '<div class="two-equal-buttons">';
		$wc_order_status 	= get_post_meta( $post->ID, '_wc_estimate_status', true );
		$wc_estimate_ticket = get_post_meta( $post->ID, '_wc_estimate_ticket_id', true );

		if ( $wc_order_status != 'approved' && $wc_order_status != 'rejected' ) {
			$content .= '<div class="two-equal-buttons">
							<a class="button expanded button-primary button-large" style="width:100%;margin-top:10px" recordid="'. esc_html( $post->ID ) .'" target="wcrb_generate_estimate_to_order">
							'. esc_html__( 'Convert to Repair Job', 'computer-repair-shop' ) .'
							</a>
						</div>';
		} else {
			$job_link = ( ! empty( $wc_estimate_ticket ) ) ? ' <a href="'. get_edit_post_link( $wc_estimate_ticket ) .'">' . esc_html__( 'View Repair Order', 'computer-repair-shop' ) . '</a>' : '';
			$estimate_case = ( $wc_order_status == 'approved' ) ? esc_html__( 'Estimate already have been converted to repair job. ', 'computer-repair-shop' ) . $job_link : esc_html__( 'This estimate was rejected and cannot be converted back.', 'computer-repair-shop' );

			$content .= '<div class="two-equal-buttons">' . $estimate_case . '</div>';
		}

		$content .= '<a id="printorder" class="button button-primary button-large" target="_blank" href="admin.php?page=wc_computer_repair_print&order_id='.$post->ID.'">'.esc_html__("Print Estimate", "computer-repair-shop").'</a>';
		$content .= ' <a id="emailcustomer" style="color:#FFF;width:100%;margin-top:10px;" class="button success expanded button-primary button-large" recordid="'. esc_html( $post->ID ) .'" target="wcrb_send_estimate_to_customer">'.esc_html__("Send Estimate Email", "computer-repair-shop").'</a>';
		$content .= '<p>' . esc_html__( 'If you have set job status page, estimate email will include links for approve or reject estimate by customer.', 'computer-repair-shop' ) . '</p>';
		$content .= "</div></div>";
	
		$allowedHTML = wc_return_allowed_tags(); 
		echo wp_kses($content, $allowedHTML);
	}
	
	function wcrb_estimate_details( $post ) {
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
		$wc_order_status 	= get_post_meta( $post->ID, '_wc_estimate_status', true );
		$wc_estimate_ticket = get_post_meta( $post->ID, '_wc_estimate_ticket_id', true );

		$content .= wc_cr_add_js_fields_for_currency_formating();
	
		if ( $wc_order_status != 'approved' && $wc_order_status != 'rejected' ) {
		} else {
			$job_link = ( ! empty( $wc_estimate_ticket ) ) ? ' <a href="'. get_edit_post_link( $wc_estimate_ticket ) .'">' . esc_html__( 'View Repair Order', 'computer-repair-shop' ) . '</a>' : '';
			$estimate_case = ( $wc_order_status == 'approved' ) ? esc_html__( 'Estimate already have been converted to repair job. ', 'computer-repair-shop' ) . $job_link : esc_html__( 'This estimate was rejected and cannot be converted back.', 'computer-repair-shop' );

			$content .= '<div class="grid-x grid-margin-x">';
			$content .= '<div class="cell small-12 medium-12 large-12">';

			$content .= '<div class="callout alert">';
			$content .= '<h3>'. $estimate_case .'</h3>';
			if ( $wc_order_status == 'approved' ) {
				$content .= '<p>' . esc_html__( 'Making any changes here will not reflect in related job', 'computer-repair-shop' ) . '</p>';
				$content .= $job_link;
			} else {
				$content .= '<p>' . esc_html__( 'You can create a new estimate as this one have been rejecte.', 'computer-repair-shop' ) . '</p>';
			}
			
			$content .= '</div>';

			$content .= '</div></div>';
		}
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

	if ( is_array( $wc_job_extra_items ) && ! empty( $wc_job_extra_items ) ) {
		$content .= '<table class="grey-bg wc_table"><thead><tr>';
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
			$content .= '<td>' . $dateTime . '</td>';
			$content .= '<td>' . $label . '</td>';
			if ( $type == 'file' ) {
				$detail = '<a href="' . esc_url( $detail ) . '" target="_blank">' . $detail . '</a>';
			}
			$content .= '<td>' . $description . '</td>';
			$content .= '<td>' . $detail . '</td>';
			$content .= '<td>' . $visibility . '</td>';
			$content .= '</tr>';
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
	
		if(is_parts_switch_woo() == true) {
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

	/**
	 * Save infor.
	 *
	 * @param int $post_id The ID of the post being saved.
	 */
	function wcrb_save_estimate_post( $post_id ) {
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
		if ( 'rep_estimates' !== $post->post_type ) {
			return;
		}

		// Check the user's permissions.
		if ( isset( $_POST['post_type'] )) {
			if ( ! current_user_can( 'edit_post', $post_id ) ) {
				return;
			}
		}
		
		global $wpdb;
		
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
								'wc_payment_status'
							);

		foreach( $submission_values as $submit_value ) {
			if ( $_POST[$submit_value] == 'case_detail' ) {
				$my_value 	= ( isset( $_POST[$submit_value] ) ) ? sanitize_textarea_field( $_POST[$submit_value] ) : '';
			} else {
				$my_value 	= ( isset( $_POST[$submit_value] ) ) ? sanitize_text_field( $_POST[$submit_value] ) : '';
			}
			$current_value 	= get_post_meta( $post_id, '_'.$submit_value, true );

			update_post_meta( $post_id, '_'.$submit_value, $my_value );
			
			if ( $submit_value == "case_number" ) {
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

		$user 			= get_user_by('id', sanitize_text_field($_POST["customer"]));

		$first_name		= empty($user->first_name)? "" : $user->first_name;
		$last_name 		= empty($user->last_name)? "" : $user->last_name;

		$insert_user 	= $first_name. ' ' .$last_name ;

		update_post_meta( $post_id, '_customer_label', $insert_user );
		
		update_post_meta( $post_id, '_order_id', $post_id );
		
		$order_status = wc_return_status_name(sanitize_text_field($_POST["wc_order_status"]));		
		update_post_meta( $post_id, '_wc_order_status_label', $order_status );
		
	
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
	}

	/*
	*Add meta data to table fields post list.. 
	*/

	function wcrb_estimate_columns( $columns ) {
		$wc_device_label = ( empty( get_option( 'wc_device_label' ) ) ) ? esc_html__( 'Device', 'computer-repair-shop' ) : get_option( 'wc_device_label' );

		$columns = array(
			'cb' => '<input type="checkbox" />',
			'order_id' 			=> __( 'Order ID', 'computer-repair-shop' ),
			'title' 			=> __( 'Case Number', 'computer-repair-shop' ),
			'customers' 		=> __( 'Customer', 'computer-repair-shop' ),
			'device' 			=> $wc_device_label,
			'invoice_total' 	=> __( 'Estimate Total', 'computer-repair-shop' ),
			'wc_order_status' 	=> __( 'Estimate Status', 'computer-repair-shop' ),
			'wc_job_actions' => __( 'Actions', 'computer-repair-shop' )
		);
		return $columns;
	}

	function wcrb_estimate_table_meta_data( $column, $post_id ) {
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
						echo "<br>".esc_html__("P", "computer-repair-shop").": ".esc_html($phone_number);	
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
			case 'invoice_total':
				$thePrice = wc_cr_currency_format( $theGrandTotal );
				echo esc_html( $thePrice );
			break;
			case 'wc_order_status' :
				$wc_order_status = get_post_meta($post_id, '_wc_estimate_status', true);

				if ( empty( $wc_order_status ) ) {
					$wc_order_status = esc_html__( 'Pending', 'computer-repair-shop' );
				} elseif ( $wc_order_status == 'rejected' ) {
					$wc_order_status = esc_html__( 'Rejected', 'computer-repair-shop' );
				} elseif ( $wc_order_status == 'approved' ) {
					$wc_order_status = esc_html__( 'Approved', 'computer-repair-shop' );
				}

				echo wp_kses( $wc_order_status, $allowedHTML );
			break;
			case 'wc_job_actions' :
				$actions_output = '<div class="actionswrapperjobs">';
				$actions_output .= '<a title="' . esc_html__( 'Print Estimate', 'computer-repair-shop' ) . '" target="_blank" href="admin.php?page=wc_computer_repair_print&order_id=' . $post_id . '"><span class="dashicons dashicons-printer"></span></a>';
				$actions_output .= '<a title="' . esc_html__( 'Email estimate to customer', 'computer-repair-shop' ) . '" target="_blank" href="admin.php?page=wc_computer_repair_print&order_id=' . $post_id . '&email_customer=yes"><span class="dashicons dashicons-email-alt"></span></a>';
				$actions_output .= '<a title="' . esc_html__( 'View or Edit', 'computer-repair-shop' ) . '" href="' . get_edit_post_link( $post_id ) . '" target="_blank"/><span class="dashicons dashicons-edit-page"></span></a>';
				$actions_output .= '</div>';

				echo wp_kses( $actions_output, $allowedHTML );
			break;
			//Break for everything else to show default things.
			default :
				break;
		}
	}

	function wcrb_generate_repair_order_from_estimate() {
		if ( ! isset( $_POST['wcrb_estimate_id'] ) || empty( $_POST['wcrb_estimate_id'] ) ) {
			$message = esc_html__( 'Something is not right', 'computer-repair-shop' );
		} else {
			$estimate_id = sanitize_text_field( $_POST['wcrb_estimate_id'] );

			$repair_id = $this->wcrb_generate_repair_order_return_id( $estimate_id );

			$message = ( empty( $repair_id ) ) ? esc_html__( 'Something did not go right', 'computer-repair-shop' ) : esc_html__( 'Repair Job is generated with ID : ', 'computer-repair-shop' ) . ' ' . $repair_id;
		}

		$values['message'] = $message;
		$values['success'] = "YES";

		wp_send_json( $values );
		wp_die();
	}

	function wcrb_send_estimate_to_customer() {
		global $WCRB_EMAILS;
		
		if ( ! isset( $_POST['wcrb_submit_type'] ) || $_POST['wcrb_submit_type'] != 'send_the_email' ) {
			return;
		}
		if ( ! isset( $_POST['wcrb_estimate_id'] ) || empty( $_POST['wcrb_estimate_id'] ) ) {
			return;
		}

		//Estimate id to bring details.
		$_est_id = sanitize_text_field( $_POST['wcrb_estimate_id'] );

		$saved_message = ( empty( get_option( 'estimate_email_body_to_customer' ) ) ) ? '' : get_option( 'estimate_email_body_to_customer' );

$message = 'Hello {{customer_full_name}},

We have prepared an estimate for you. If you have further questions please contact us.

Your estimate details are listed below. You can approve or reject estimate as per your choice. If you have questions please get in touch.

Approve/Reject the Estimate

{{start_approve_estimate_link}}Approve Estimate{{end_approve_estimate_link}}

{{start_reject_estimate_link}}Reject Estimate {{end_reject_estimate_link}}


{{order_invoice_details}}

Thank you again for your business!';
							
		$email_body = ( empty( $saved_message ) ) ? $message : $saved_message;		

		$args = array( 'job_id' => $_est_id, 'email_message' => $email_body );

		$email_body = $WCRB_EMAILS->return_body_replacing_keywords( $args );
	
		$customer_id = get_post_meta( $_est_id, "_customer", true );

		if ( ! empty( $customer_id ) ) {
			$user_info 	= get_userdata( $customer_id );
			$user_email = $user_info->user_email;

			if ( ! empty( $user_email ) ) {
				if ( ! empty( $email_body ) ) {
					$to = $user_email;
					$menu_name_p 	= get_option( 'blogname' );
					$subject 		= ( ! empty ( get_option( 'estimate_email_subject_to_customer' ) ) ) ? get_option( 'estimate_email_subject_to_customer' ) : 'You have received an estimate! | ' . $menu_name_p;
					
					$WCRB_EMAILS->send_email( $to, $subject, $email_body );
				}
			}
			$message = esc_html__( 'Email have been sent to the customer.', 'computer-repair-shop' );
		} else {
			$message = esc_html__( 'Customer not set for this job', 'computer-repair-shop' );
		}

		$values['message'] = $message;
		$values['success'] = "YES";

		wp_send_json( $values );
		wp_die();
	}

	function wcrb_generate_repair_order_return_id( $estimate_id ) {
		global $wpdb;

		if ( empty( $estimate_id ) ) {
			return;
		}
		$wc_estimate_ticket = get_post_meta( $estimate_id, '_wc_estimate_ticket_id', true);
		if ( ! empty( $wc_estimate_ticket ) ) {
			return;
		}

		//Let's get the existing variables first. 
		$case_number 		   = get_post_meta( $estimate_id, '_case_number', true );
		$customer 			   = get_post_meta( $estimate_id, '_customer', true );
		$technician 		   = get_post_meta( $estimate_id, '_technician', true );
		$pickup_date 		   = get_post_meta( $estimate_id, '_pickup_date', true );
		$delivery_date 		   = get_post_meta( $estimate_id, '_delivery_date', true );
		$case_detail 		   = get_post_meta( $estimate_id, '_case_detail', true );
		$wc_order_status 	   = get_post_meta( $estimate_id, '_wc_order_status', true );
		$store_id 			   = get_post_meta( $estimate_id, '_store_id', true );
		$wc_order_note 		   = get_post_meta( $estimate_id, '_wc_order_note', true );
		$wc_prices_inclu_exclu = get_post_meta( $estimate_id, '_wc_prices_inclu_exclu', true );
		$wc_device_data 	   = get_post_meta( $estimate_id, '_wc_device_data', TRUE );
		$wc_job_extra_items    = get_post_meta( $estimate_id, 'wc_job_extra_items', true );
		$customer_label 	   = get_post_meta( $estimate_id, '_customer_label', TRUE );
		
		$my_post = array(
			'post_title'    => $case_number,
			'post_status'   => 'publish',
			'post_type' 	=> 'rep_jobs'
			);
		// Insert the post into the database
		$rep_job_id = wp_insert_post( $my_post );

		$order_status =  wc_return_status_name( 'neworder' );

		//let's get estimate parts and insert into db. 
		if ( ! empty( $rep_job_id ) ) :
			update_post_meta( $rep_job_id, '_case_number', $case_number );
			update_post_meta( $rep_job_id, '_customer', $customer );
			update_post_meta( $rep_job_id, '_technician', $technician );
			update_post_meta( $rep_job_id, '_pickup_date', $pickup_date );
			update_post_meta( $rep_job_id, '_delivery_date', $delivery_date );
			update_post_meta( $rep_job_id, '_case_detail', $case_detail );
			update_post_meta( $rep_job_id, '_wc_order_status', $wc_order_status );
			update_post_meta( $rep_job_id, '_store_id', $store_id );
			update_post_meta( $rep_job_id, '_wc_order_note', $wc_order_note );
			update_post_meta( $rep_job_id, 'wc_job_extra_items', $wc_job_extra_items );
			update_post_meta( $rep_job_id, '_wc_prices_inclu_exclu', $wc_prices_inclu_exclu );
			update_post_meta( $rep_job_id, '_wc_device_data', $wc_device_data );
			update_post_meta( $rep_job_id, '_customer_label', $customer_label );
			update_post_meta( $rep_job_id, '_wc_order_status_label', $order_status );
			update_post_meta( $rep_job_id, '_order_id', $rep_job_id );

			$computer_repair_items 		= $wpdb->prefix.'wc_cr_order_items';
			$computer_repair_items_meta = $wpdb->prefix.'wc_cr_order_itemmeta';
			
			$select_items_query = $wpdb->prepare( "SELECT * FROM `{$computer_repair_items}` WHERE `order_id`= %d", $estimate_id );
			$items_result = $wpdb->get_results( $select_items_query );

			$content = '';
				
			foreach ( $items_result as $item ) {
				$order_item_id 	 = $item->order_item_id;
				$order_item_name = $item->order_item_name;
				$order_item_type = $item->order_item_type;
				$order_id 		 = $rep_job_id;
				
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

			//
			update_post_meta( $estimate_id, '_wc_estimate_ticket_id', $rep_job_id );
			update_post_meta( $rep_job_id, '_wc_estimate_ticket_id', $estimate_id );
			update_post_meta( $estimate_id, '_wc_estimate_status', 'approved' );

			//Copy Logs
			$WCRB_JOB_HISTORY_LOGS = WCRB_JOB_HISTORY_LOGS::getInstance();
			$WCRB_JOB_HISTORY_LOGS->copy_history_logs_to_other_job( $estimate_id, $rep_job_id );

			$args = array(
				"job_id" 		=> $rep_job_id, 
				"name" 			=> esc_html__("Job Converted through estimate", "computer-repair-shop" ), 
				"type" 			=> 'public', 
				"field" 		=> '_wc_estimate_ticket_id', 
				"change_detail" => $estimate_id
			);
			$WCRB_JOB_HISTORY_LOGS->wc_record_job_history( $args );

			return $rep_job_id;
		endif;
	}

	function admin_email_on_estimate_reject_or_approve( $estimate_id, $choice ) {
		global $WCRB_EMAILS;

		if ( empty( $estimate_id ) || empty( $choice ) ) {
			return;
		}
		$subject = '';
		$email_body = '';
		$menu_name_p = get_option( 'blogname' );

		if ( $choice == 'rejected' ) {
			$subject = ( ! empty ( get_option( 'estimate_reject_email_subject_to_admin' ) ) ) ? get_option( 'estimate_reject_email_subject_to_admin' ) : 'Estimate have been rejected! | ' . $menu_name_p;
			$saved_message = ( empty( get_option( 'estimate_reject_email_body_to_admin' ) ) ) ? '' : get_option( 'estimate_reject_email_body_to_admin' );

$message = 'Hello,

Estimate you sent to {{customer_full_name}} have been rejected by customer.

Estimate ID : {{estimate_id}}

Thank you!';
							
			$email_body = ( empty( $saved_message ) ) ? $message : $saved_message;
		}

		if ( $choice == 'approved' ) {
			$subject = ( ! empty ( get_option( 'estimate_approve_email_subject_to_admin' ) ) ) ? get_option( 'estimate_approve_email_subject_to_admin' ) : 'Congratulations! Customer have approved your estimate! | ' . $menu_name_p;

			$saved_message = ( empty( get_option( 'estimate_approve_email_body_to_admin' ) ) ) ? '' : get_option( 'estimate_approve_email_body_to_admin' );

$message = 'Hello,

Estimate you sent to {{customer_full_name}} have been approved by customer and converted to job.

Job ID : {{job_id}} created from Estimate ID : {{estimate_id}}

Thank you!';
			$email_body = ( empty( $saved_message ) ) ? $message : $saved_message;
		}

		$admin_email = ( ! empty( get_option( 'admin_email' ) ) ) ? get_option( 'admin_email' ) : '';

		if ( ! empty( $subject ) || ! empty( $email_body ) || ! empty( $admin_email ) ) {
			$args = array( 'job_id' => $estimate_id, 'email_message' => $email_body );
			$email_body = $WCRB_EMAILS->return_body_replacing_keywords( $args );

			$WCRB_EMAILS->send_email( $admin_email, $subject, $email_body );
		}
	}

	function process_estimate_choice( $estimate_id, $case_number, $choice ) {
	
		if ( empty( $estimate_id ) || empty( $case_number ) || empty( $choice ) ) {
			return esc_html__( 'Incomplete submission', 'computer-repair-shop' );
		}

		if ( $choice != 'approved' && $choice != 'rejected' ) {
			return esc_html__( 'Unknown choice', 'computer-repair-shop' );
		}

		$wc_estimate_status = get_post_meta( $estimate_id, '_wc_estimate_status', true );

		if ( ! empty( $wc_estimate_status ) ) {
			return esc_html__( 'Already accepted or rejected.', 'computer-repair-shop' );
		}

		$db_case_number = get_post_meta( $estimate_id, '_case_number', true );

		if ( $db_case_number != $case_number  ) {
			return esc_html__( 'Incomplete submission', 'computer-repair-shop' );
		}

		if ( $choice == 'rejected' ) {
			update_post_meta( $estimate_id, '_wc_estimate_status', 'rejected' );

			$this->admin_email_on_estimate_reject_or_approve( $estimate_id, $choice );

			return esc_html__( 'We are sorry to know you have rejected our estimate. Please get in touch to find a better way.', 'computer-repair-shop' );
		}
		if ( $choice == 'approved' ) {
			$this->wcrb_generate_repair_order_return_id( $estimate_id );

			$this->admin_email_on_estimate_reject_or_approve( $estimate_id, $choice );

			return esc_html__( 'Thank you for approving the estimate your job have been started. Please check status of your job below using Case#.', 'computer-repair-shop' ) . ' {' . $case_number . '}';
		}
	}
}