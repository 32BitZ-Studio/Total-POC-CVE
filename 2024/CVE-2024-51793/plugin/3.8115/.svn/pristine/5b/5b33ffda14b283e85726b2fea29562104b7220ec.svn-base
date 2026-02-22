<?php
	//List Services shortcode
	//Used to display Services on a page.
	//Linked to single service pages. 

	if ( ! function_exists( 'wc_order_status_form' ) ) :
		function wc_order_status_form() { 
			global $WCRB_ESTIMATES_OBJ;

			wp_enqueue_script("foundation-js");
			wp_enqueue_script("wc-cr-js");
			wp_enqueue_script("select2");

			$content = '';

			if ( isset( $_GET['choice'] ) && ! empty( $_GET['choice'] ) ) {
				$choice 	 = sanitize_text_field( $_GET['choice'] );
				$estimate_id = ( isset( $_GET['estimate_id'] ) ) ? sanitize_text_field( $_GET['estimate_id'] ) : '';
				$case_number = ( isset( $_GET['case_number'] ) ) ? sanitize_text_field( $_GET['case_number'] ) : '';

				$estMsg = $WCRB_ESTIMATES_OBJ->process_estimate_choice( $estimate_id, $case_number, $choice );
				$content .= '<div class="callout success">' . esc_html( $estMsg ) . ' </div>';
			}
			
			$content .= '<div class="wc_order_status_form">';
			$content .= '<h2>'.esc_html__("Check your job status!", "computer-repair-shop").'</h2>';
			$content .= '<p>'.esc_html__("Please enter your case# which you may received in email or from our outlet.", "computer-repair-shop").'</p>';
			
			$the_case_id = '';
			if ( isset( $_GET['case_id'] ) && ! empty( $_GET['case_id'] ) ) {
				$the_case_id = sanitize_text_field( $_GET['case_id'] );
				$content .= '<div id="auto_submit_status"></div>';
			}

			$content .= '<form data-async="" method="post">';
			$content .= '<input type="text" required autofocus placeholder="'.esc_html__("Your Case Number...", "computer-repair-shop").'" value="' . $the_case_id . '" name="wc_case_number" />';
			$content .=  wp_nonce_field( 'wc_computer_repair_nonce', 'wc_job_status_nonce', $echo = false);
			$content .= '<input type="submit" class="button button-primary primary" value="'.esc_html__("Check Now!", "computer-repair-shop").'" />';
			$content .= '</form>';

			$content .= '</div>';
			
			$content .= '<div class="form-message orderstatusholder"></div>';

			return $content;
		}//wc_list_services.
		add_shortcode('wc_order_status_form', 'wc_order_status_form');
	endif;


	if(!function_exists("wc_cmp_rep_check_order_status")):

		function wc_cmp_rep_check_order_status() { 
			if (!isset( $_POST['wc_job_status_nonce'] ) 
				|| ! wp_verify_nonce( $_POST['wc_job_status_nonce'], 'wc_computer_repair_nonce' )) :
					$values['message'] = esc_html__("Something is wrong with your submission!", "computer-repair-shop");
					$values['success'] = "YES";
			else:
				//Register User
				$wcCasaeNumber 		= sanitize_text_field($_POST["wc_case_number"]);

				$available_action = do_action( 'wc_rb_before_status_check_result' );

				if(!empty($wcCasaeNumber)) {
					$wc_cr_args = array(
						'posts_per_page'   => 1,
						'post_type'        => 'rep_jobs',
						'meta_key'         => '_case_number',
						'meta_value'       => $wcCasaeNumber
					);
					$wc_cr_query = new WP_Query($wc_cr_args);

					if($wc_cr_query->have_posts()): 

						while($wc_cr_query->have_posts()): 
							$wc_cr_query->the_post();

							$order_id = get_the_ID();
							$post_output = "<a href='#' class='wcCrJobHistoryHideShowBtn'>";
							$post_output .= '<span class="text-left">' . esc_html__("Add a message", "computer-repair-shop") . '</span>';
							$post_output .= '<span class="text-right">' . esc_html__("Job history show/hide", "computer-repair-shop") . '</span>';
							$post_output .= "</a>";

							$post_output .= '<div class="wcCrShowHideHistory">';
							
							$post_output .= '<div class="wcrb_post_message_by_customer_status row"><div class="grid-x grid-padding-x"><div class="medium-12 cell">';
							$post_output .= '<h2>' . esc_html__( 'Add a message', 'computer-repair-shop' ) . '</h2>';
							$post_output .= '<form id="wcrb_post_customer_msg" class="needs-validation" method="post">
											<label><textarea name="wcrb_message_on_status" required="" class="form-control login-field" 
											placeholder="' . esc_html__( 'Add a message for technician or owner', 'computer-repair-shop' ) . '"></textarea></label>';
							
							$post_output .= wp_nonce_field( 'wcrb_customer_msg_post_action', 'wcrb_customer_msg_post_action_field', true, false );

							$post_output .=	'<input type="hidden" name="order_id" value="' . esc_html( $order_id ) . '" />';
							$post_output .=	'<input type="submit" class="button button-primary primary" value="' . esc_html__( 'Post message', 'computer-repair-shop' ) . '">
								<div class="client_msg_post_reply"></div><!-- AjaX Return /-->
							</form></div></div></div>';

							$post_output .= '<ul class="order_notes">';

							$WCRB_JOB_HISTORY_LOGS = WCRB_JOB_HISTORY_LOGS::getInstance();
							$post_output .= $WCRB_JOB_HISTORY_LOGS->wc_list_job_history( $order_id, "public" );
							$post_output .= '</ul></div>';

							$post_output .= wc_print_order_invoice($order_id, "status_check");
						endwhile;

						$values['message'] = $available_action . $post_output;
					else: 
						$values['message'] = esc_html__("We haven't found any job with your given case number!", "computer-repair-shop");
					endif; 	
					wp_reset_postdata();
				}
				$values['success'] = "YES";
			endif;
			
			wp_send_json($values);
			wp_die();
		}
		add_action( 'wp_ajax_wc_cmp_rep_check_order_status', 'wc_cmp_rep_check_order_status' );
		add_action( 'wp_ajax_nopriv_wc_cmp_rep_check_order_status', 'wc_cmp_rep_check_order_status' );
	endif;

	if ( ! function_exists( 'wcrb_post_customer_message_status' ) ) :
		function wcrb_post_customer_message_status() {
			global $WCRB_EMAILS;

			$values = array();

			if (!isset( $_POST['wcrb_customer_msg_post_action_field'] ) 
				|| ! wp_verify_nonce( $_POST['wcrb_customer_msg_post_action_field'], 'wcrb_customer_msg_post_action' )) :
					$values['message'] = esc_html__( "Something is wrong with your submission!", "computer-repair-shop" );
					$values['success'] = "YES";
			else:
				//Register User
				if ( empty( $_POST['order_id'] ) || empty( $_POST['wcrb_message_on_status'] ) ) {
					$message = esc_html__( 'Something is not right', 'computer-repair-shop' );
				} else {
					$job_id 				= sanitize_text_field( $_POST['order_id'] );
					$wcrb_message_on_status = sanitize_textarea_field( $_POST['wcrb_message_on_status'] );
					$customer_id 			= get_post_meta( $job_id, "_customer", true );

					if ( empty( $customer_id ) ) {
						$message = esc_html__( 'Customer not set for this job', 'computer-repair-shop' );
					} else {
						$WCRB_JOB_HISTORY_LOGS = WCRB_JOB_HISTORY_LOGS::getInstance();

						//Let's add msg to db.
						$args = array(
							"job_id" 		=> $job_id, 
							"name" 			=> esc_html__( 'Customer posted message: ', 'computer-repair-shop' ), 
							"type" 			=> 'public', 
							"field" 		=> '_customer_message', 
							"change_detail" => $wcrb_message_on_status,
							"user_id"		=> $customer_id
						);
						$WCRB_JOB_HISTORY_LOGS->wc_record_job_history( $args );

						//Now needs to send mail to admin.
						$admin_email = ( ! empty( get_option( 'admin_email' ) ) ) ? get_option( 'admin_email' ) : '';

						if ( ! empty( $admin_email ) ) {
							$subject = esc_html__( 'Customer posted message: ', 'computer-repair-shop' ) . esc_html__( 'Job ID', 'computer-repair-shop' ) . ' | ' . esc_html( $job_id );
							$email_body = wp_kses_post( $wcrb_message_on_status );
							$WCRB_EMAILS->send_email( $admin_email, $subject, $email_body );
						}
						$values['redirect_url'] = wc_rb_return_status_check_link( $job_id );
					}
					$message = esc_html__( 'Message posted', 'computer-repair-shop' );
				}

				$values['message'] = $message;
				$values['success'] = "YES";
			endif;
			
			wp_send_json( $values );
			wp_die();
		}
		add_action( 'wp_ajax_wcrb_post_customer_message_status', 'wcrb_post_customer_message_status' );
		add_action( 'wp_ajax_nopriv_wcrb_post_customer_message_status', 'wcrb_post_customer_message_status' );
	endif;