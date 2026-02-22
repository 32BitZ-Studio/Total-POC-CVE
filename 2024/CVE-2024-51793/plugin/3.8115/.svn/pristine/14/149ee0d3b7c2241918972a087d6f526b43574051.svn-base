<?php
function wc_comp_repair_shop_main() {
    if ( ! current_user_can('manage_options') ) {
      wp_die( __( 'You do not have sufficient permissions to access this page.', 'computer-repair-shop' ) );
	}
?>
	<div class="main-container computer-repair">
		<div class="grid-x grid-container grid-margin-x grid-padding-y fluid" style="width:100%;">
			<div class="small-12 cell">
				<div class="form-update-message"></div>
			</div>

			<div class="large-12 medium-12 small-12 cell">
				
				<div class="team-wrap grid-x" data-equalizer data-equalize-on="medium">
					<?php
						if(isset($_GET["update_status"]) && !empty($_GET["update_status"])):
							$class_settings = "";
							$class_activation = '';
							$class_status 	= " is-active";
						else: 
							$class_settings = " is-active";
							$class_status 	= "";
							$class_activation = '';
						endif;

						$class_general_settings = ( isset( $_POST['wc_rep_settings'] ) && $_POST['wc_rep_settings'] == '1' ) ? ' is-active' : '';
						$class_settings 		= ( empty( $class_general_settings ) ) ? $class_settings : '';

						$class_invoices_settings = ( isset( $_POST['wc_rep_labels_submit'] ) && $_POST['wc_rep_labels_submit'] == '1' ) ? ' is-active' : '';
						$class_settings 		= ( empty( $class_invoices_settings ) ) ? $class_settings : '';

						$class_currency_settings = ( isset( $_POST['wc_rep_currency_submit'] ) && $_POST['wc_rep_currency_submit'] == '1' ) ? ' is-active' : '';
						$class_settings 		= ( empty( $class_currency_settings ) ) ? $class_settings : '';

						if ( isset( $_GET['update_payment_status'] ) && ! empty ( $_GET['update_payment_status'] ) ) {
							$class_settings = "";
							$class_status 	= "";
						}
						if ( isset( $_GET['unselect'] ) && ! empty ( $_GET['unselect'] ) ) {
							$class_settings = "";
							$class_status 	= "";
						}
					?>
					<div class="cell medium-2 thebluebg sidebarmenu">
						<div class="the-brand-logo">
							<a href="https://www.webfulcreations.com/products/crm-wordpress-plugin-repairbuddy/" target="_blank">
								<img src="<?php echo esc_url( WC_COMPUTER_REPAIR_DIR_URL . '/assets/admin/images/repair-buddy-logo.png' ); ?>" alt="RepairBuddy CRM Logo" />
							</a>
						</div>
						<ul class="vertical tabs thebluebg" data-tabs="82ulyt-tabs" id="example-tabs">
							<li class="tabs-title<?php echo esc_attr( $class_settings ); ?>" role="presentation">
								<a href="#main_page" role="tab" aria-controls="main_page" aria-selected="false" id="main_page-label">
									<h2><?php echo esc_html__( 'Dashboard', 'computer-repair-shop' ); ?></h2>
								</a>
							</li>
							<li class="tabs-title<?php echo esc_attr( $class_general_settings ); ?>" role="presentation">
								<a href="#panel1" role="tab" aria-controls="panel1" aria-selected="false" id="panel1-label">
									<h2><?php echo esc_html__( 'General Settings', 'computer-repair-shop' ); ?></h2>
								</a>
							</li>
							<li class="tabs-title<?php echo esc_attr( $class_currency_settings ); ?>" role="presentation">
								<a href="#currencyFormatting" role="tab" aria-controls="currencyFormatting" aria-selected="true" id="currencyFormatting-label">
									<h2><?php echo esc_html__( 'Currency', 'computer-repair-shop' ); ?></h2>
								</a>
							</li>
							<li class="tabs-title<?php echo esc_attr( $class_invoices_settings ); ?>" role="presentation">
								<a href="#reportsAInvoices" role="tab" aria-controls="reportsAInvoices" aria-selected="true" id="reportsAInvoices-label">
									<h2><?php echo esc_html__( 'Reports & Invoices', 'computer-repair-shop' ); ?></h2>
								</a>
							</li>
							<li class="tabs-title<?php echo esc_attr($class_status); ?>" role="presentation">
								<a href="#panel3" role="tab" aria-controls="panel3" aria-selected="true" id="panel3-label">
									<h2><?php echo esc_html__("Job Status", "computer-repair-shop"); ?></h2>
								</a>
							</li>
							<?php
								do_action( 'wc_rb_settings_tab_menu_item' );
							?>
							<li class="tabs-title<?php echo esc_attr($class_activation); ?>" role="presentation">
								<a href="#panel4" role="tab" aria-controls="panel4" aria-selected="true" id="panel4-label">
									<h2><?php echo esc_html__("Activation", "computer-repair-shop"); ?></h2>
								</a>
							</li>
							<li class="thespacer"><hr></li>
							<li class="tabs-title" role="presentation">
								<a href="#documentation" role="tab" aria-controls="documentation" aria-selected="true" id="documentation-label">
									<h2><?php echo esc_html__( 'Shortcodes & Support', 'computer-repair-shop' ); ?></h2>
								</a>
							</li>
							<li class="tabs-title" role="presentation">
								<a href="#addons" role="tab" aria-controls="addons" aria-selected="true" id="addons-label">
									<h2><?php echo esc_html__( 'Addons', 'computer-repair-shop' ); ?></h2>
								</a>
							</li>
							<li class="thespacer"><hr></li>
							<li class="external-title">
								<a href="https://www.webfulcreations.com/contact-us/" target="_blank">
									<h2><span class="dashicons dashicons-buddicons-pm"></span> <?php echo esc_html__( 'Contact Us', 'computer-repair-shop' ); ?></h2>
								</a>
							</li>
							<li class="external-title">
								<a href="https://www.facebook.com/WebfulCreations" target="_blank">
									<h2><span class="dashicons dashicons-facebook"></span> <?php echo esc_html__( 'Chat With Us', 'computer-repair-shop' ); ?></h2>
								</a>
							</li>
						</ul>
					</div>
                    
					<div class="cell medium-10 thewhitebg contentsideb">
						<div class="tabs-content vertical" data-tabs-content="example-tabs">
						
							<div class="tabs-panel team-wrap<?php echo esc_attr($class_settings); ?>" id="main_page" role="tabpanel" aria-hidden="true" aria-labelledby="main_page-label">
							<?php 
								$MAINPAGEOUTPUT = new WCRB_DASHBOARD;
								$dashoutput = $MAINPAGEOUTPUT->output_main_page( 'admin' ); 
								$allowedHTML = wc_return_allowed_tags();
								echo wp_kses( $dashoutput, $allowedHTML );
							?>
							</div>
							<!-- Main page ends /-->

							<div class="tabs-panel team-wrap<?php echo esc_attr($class_general_settings); ?>" id="panel1" role="tabpanel" aria-hidden="true" aria-labelledby="panel1-label">
							<?php
								//must check that the user has the required capability 
								$menu_name_p 			= get_option( 'menu_name_p' );
								$wc_rb_business_name	= get_option( 'wc_rb_business_name' );
								$wc_rb_business_phone	= get_option( 'wc_rb_business_phone' );
								$wc_rb_business_address	= get_option( 'wc_rb_business_address' );
								
								$wc_rb_business_name	= (empty($wc_rb_business_name)) ? get_bloginfo( 'name' ) : $wc_rb_business_name; 

								//Processing Logo
								$computer_repair_logo = get_option("computer_repair_logo");

								if(empty($computer_repair_logo)) {
									$custom_logo_id 		= get_theme_mod( 'custom_logo' );
									if(!empty($custom_logo_id)) : 
										$image 					= wp_get_attachment_image_src( $custom_logo_id , 'full' );

										$computer_repair_logo	= $image[0];	
									endif;
								}

								$computer_repair_email = get_option( 'computer_repair_email' );
								$computer_repair_email = ( empty( $computer_repair_email ) ) ? get_option( 'admin_email' ) : $computer_repair_email;

								$wc_rb_gdpr_acceptance_link   = ( empty( get_option( 'wc_rb_gdpr_acceptance_link' ) ) ) ? '' : get_option( 'wc_rb_gdpr_acceptance_link' );
								$wc_rb_gdpr_acceptance 		  = ( empty( get_option( 'wc_rb_gdpr_acceptance' ) ) ) ? esc_html__( 'I understand that I will be contacted by a representative regarding this request and I agree to the privacy policy.', 'computer-repair-shop' ) : get_option( 'wc_rb_gdpr_acceptance' );
								
								$case_number_length = empty( get_option( 'case_number_length' ) ) ? 6 : get_option( 'case_number_length' );
								$case_number_prefix = empty( get_option( 'case_number_prefix' ) ) ? 'WC_' : get_option( 'case_number_prefix' );

								$wc_primary_country			= get_option("wc_primary_country");

								//Use Woo Products
								$wc_enable_woo_products = get_option( 'wc_enable_woo_products' );
								$useWooProducts 		= ( $wc_enable_woo_products == 'on' ) ? 'checked="checked"' : '';

								//File Attachment
								$wc_file_attachment_in_job 	= get_option( 'wc_file_attachment_in_job' );
								$use_file_attachment 		= ( $wc_file_attachment_in_job == 'on' ) ? 'checked="checked"' : '';

								//Email Notice
								$wc_send_cr_notice 	= get_option( 'wc_job_status_cr_notice' );
								$send_notice 		= ( $wc_send_cr_notice == 'on' ) ? 'checked="checked"' : '';

								//New User notification
								$wc_add_user_notification = get_option( 'wc_add_user_notification' );
								$wc_add_user_notification = ( $wc_add_user_notification == 'on' ) ? 'checked="checked"' : '';

								/*//Use admin as Technicians 
								$wc_add_admin_to_technician = get_option( 'wc_add_admin_to_technician' );
								$adminrole 					= ( $wc_add_admin_to_technician == 'on' ) ? 'checked="checked"' : '';
								<tr>
									<th scope="row">
										<label for="add_admin_to_technician">'.esc_html__("Add admin Role to Technicians Dropdown", 'computer-repair-shop').'</label>
									</th>
									<td>
										<input type="checkbox" '.$adminrole.' name="add_admin_to_technician" id="add_admin_to_technician" />
									</td>
								</tr>*/
								?>
		
								<div class="wrap">
									<h2><?php esc_html_e( 'Settings', 'computer-repair-shop' ); ?></h2>

									<form action="" method="post">
										<table cellpadding="5" cellspacing="5" class="form-table">

											<tr>
												<th scope="row">
													<label for="menu_name"><?php esc_html_e("Menu Name e.g Computer Repair", "computer-repair-shop"); ?></label>
												</th>
												<td>
													<input 
														name="menu_name" 
														id="menu_name" 
														class="regular-text" 
														value="<?php echo esc_html($menu_name_p); ?>" 
														type="text" 
														placeholder="<?php esc_html_e("Enter Menu Name Default Computer Repair", "computer-repair-shop"); ?>"/>
												</td>
											</tr>

											<tr>
												<th scope="row">
													<label for="wc_rb_business_name">
														<?php esc_html_e("Business Name", "computer-repair-shop"); ?>
														<small><?php echo esc_html__("Name will be used in reports/invoices", "computer-repair-shop"); ?></small>
													</label>
												</th>
												<td>
													<input 
														name="wc_rb_business_name" 
														id="wc_rb_business_name" 
														class="regular-text" 
														value="<?php echo esc_html($wc_rb_business_name); ?>" 
														type="text" />
												</td>
											</tr>
											<tr>
												<th scope="row">
													<label for="wc_rb_business_phone">
														<?php esc_html_e("Business Phone", "computer-repair-shop"); ?>
														<small><?php echo esc_html__("Phone will be used in reports/invoices", "computer-repair-shop"); ?></small>
													</label>
												</th>
												<td>
													<input 
														name="wc_rb_business_phone" 
														id="wc_rb_business_phone" 
														class="regular-text" 
														value="<?php echo esc_html($wc_rb_business_phone); ?>" 
														type="text" />
												</td>
											</tr>

											<tr>
												<th scope="row">
													<label for="wc_rb_business_address">
														<?php esc_html_e("Business Address", "computer-repair-shop"); ?>
														<small><?php echo esc_html__("Address will be used in reports/invoices", "computer-repair-shop"); ?></small>
													</label>
												</th>
												<td>
													<input 
														name="wc_rb_business_address" 
														id="wc_rb_business_address" 
														class="regular-text" 
														value="<?php echo esc_html($wc_rb_business_address); ?>" 
														type="text" />
												</td>
											</tr>

											<tr>
												<th scope="row">
													<label for="menu_name"><?php esc_html_e("Logo to use", "computer-repair-shop"); ?></label>
												</th>
												<td>
													<input 
														name="computer_repair_logo" 
														id="computer_repair_logo" 
														class="regular-text" 
														value="<?php echo esc_url($computer_repair_logo); ?>" 
														type="text" 
														placeholder="<?php esc_html_e("Enter url of logo", "computer-repair-shop"); ?>"/>
												</td>
											</tr>

											<tr>
												<th scope="row">
													<label for="menu_name"><?php esc_html_e("Email", "computer-repair-shop"); ?><small> <?php esc_html_e("Where quote forms and other admin emails would be sent.", "computer-repair-shop"); ?></small></label>
												</th>
												<td>
													<input 
														name="computer_repair_email" 
														id="computer_repair_email" 
														class="regular-text" 
														value="<?php echo esc_html($computer_repair_email); ?>" 
														type="text" 
														placeholder="<?php esc_html_e("Where to send emails like Quote and other stuff.", "computer-repair-shop"); ?>"/>
												</td>
											</tr>

											<tr>
												<th scope="row">
													<label for="wc_job_status_cr_notice"><?php echo esc_html__( 'Email Customer', 'computer-repair-shop' ); ?></label>
												</th>
												<td>
													<input type="checkbox" <?php echo esc_html__( $send_notice ); ?> name="wc_job_status_cr_notice" id="wc_job_status_cr_notice" />
													<p class="description"><?php echo esc_html__( 'Email customer everytime job status is changed.', 'computer-repair-shop' ); ?></p>
												</td>
											</tr>
											<!-- Work here. -->
											<tr>
												<th scope="row">
													<label for="wc_add_user_notification"><?php echo esc_html__( 'New User Notification', 'computer-repair-shop' ); ?></label>
												</th>
												<td>
													<input type="checkbox" <?php echo esc_html__( $wc_add_user_notification ); ?> name="wc_add_user_notification" id="wc_add_user_notification" />
													<p class="description"><?php echo esc_html__( 'Send email notificaiton to admin and customer on adding new user.', 'computer-repair-shop' ); ?></p>
												</td>
											</tr>

											<tr>
												<th scope="row">
													<label for="wc_rb_gdpr_acceptance"><?php esc_html_e( 'GDPR Acceptance on Book and Quote forms', 'computer-repair-shop' ); ?></label>
												</th>
												<td>
													<table class="form-table no-padding-table">
														<tr>
															<td>
															<input 
																name="wc_rb_gdpr_acceptance" 
																id="wc_rb_gdpr_acceptance" 
																class="regular-text" 
																value="<?php echo esc_html( $wc_rb_gdpr_acceptance ); ?>" 
																type="text" 
																placeholder="<?php esc_html_e( 'GDPR Acceptance text label for booking and quote', 'computer-repair-shop' ); ?>" />
															</td>
															<td>
															<input 
																name="wc_rb_gdpr_acceptance_link" 
																id="wc_rb_gdpr_acceptance_link" 
																class="regular-text" 
																value="<?php echo esc_html( $wc_rb_gdpr_acceptance_link ); ?>" 
																type="text" 
																placeholder="<?php esc_html_e( 'Privacy policy or terms link', 'computer-repair-shop' ); ?>" />
															</td>
														</tr>
													</table>	
												</td>
											</tr>

											<tr>
												<th scope="row">
													<label for="case_number_prefix"><?php echo esc_html__("Case # Prefix", "computer-repair-shop"); ?></label>
												</th>
												<td>
													<input 
														name="case_number_prefix" 
														id="case_number_prefix" 
														class="regular-text" 
														value="<?php echo esc_html($case_number_prefix); ?>" 
														type="text" 
														placeholder="<?php echo esc_html__("Case number prefix e.g CHM_ or WC_", "computer-repair-shop"); ?>"/>
												</td>
											</tr>

											<tr>
												<th scope="row">
													<label for="case_number_length"><?php echo esc_html__("Case # Length for string in Case# before timestamp", "computer-repair-shop"); ?></label>
												</th>
												<td>
													<input 
														name="case_number_length" 
														id="case_number_length" 
														class="regular-text" 
														value="<?php echo esc_html($case_number_length); ?>" 
														type="number" 
														value="6" 
														min="1" 
														/>
												</td>
											</tr>

											<tr>
												<th scope="row">
													<label for="wc_primary_country"><?php echo esc_html__("Default Country", 'computer-repair-shop'); ?></label>
												</th>
												<td>
													<select name="wc_primary_country" id="wc_primary_country" class="form-control">
														<?php 
															$allowed_html = wc_return_allowed_tags();
															$optionsGenerated = wc_cr_countries_dropdown( $wc_primary_country, 'return' );
															echo wp_kses($optionsGenerated, $allowed_html);
														?>
													</select>
												</td>
											</tr>

											<tr>
												<th scope="row">
													<label for="wc_enable_woo_products">
														<?php echo esc_html__("Disable Parts and Use WooCommerce Products", 'computer-repair-shop'); ?>
													</label>
												</th>
												<td>
													<?php
														if( rb_is_woocommerce_activated() == false ) {
															echo esc_html__("Please install and activate WooCommerce to use it. Otherwise you can rely on parts by our plugin.", "computer-repair-shop");
														} else { ?>
															<input type="checkbox" <?php echo esc_html__( $useWooProducts ); ?> name="wc_enable_woo_products" id="wc_enable_woo_products" />
													<?php	}
													?>
												</td>
											</tr>

											<tr>
												<th scope="row">
													<label for="wc_file_attachment_in_job">
														<?php echo esc_html__("Enable File Attachment in Job", 'computer-repair-shop'); ?>
													</label>
												</th>
												<td>
													<input type="checkbox" <?php echo esc_html( $use_file_attachment ); ?> name="wc_file_attachment_in_job" id="wc_file_attachment_in_job" />
												</td>
											</tr>

											<tr>
												<td>
													<input 
														class="button button-primary" 
														type="Submit"  
														value="<?php echo esc_html__("Save Changes", "computer-repair-shop"); ?>"/>
												</td>
												<td>
													<input type="hidden" name="wc_rep_settings" value="1" />
													&nbsp;
												</td>
											</tr>
										</table>
									</form>
								</div>
							</div><!-- tab 1 ends -->
						
							<div class="tabs-panel team-wrap<?php echo esc_attr( $class_currency_settings ); ?>" id="currencyFormatting" 
							role="tabpanel" aria-hidden="true" aria-labelledby="panel1-label">
								<?php
									$wc_cr_selected_currency = get_option( 'wc_cr_selected_currency' );
									$wc_cr_currency_position = get_option( 'wc_cr_currency_position' );
									$wc_cr_thousand_separator = get_option( 'wc_cr_thousand_separator' );
									$wc_cr_thousand_separator = ( empty ( $wc_cr_thousand_separator ) ) ? ',' : $wc_cr_thousand_separator;

									$wc_cr_decimal_separator = get_option( 'wc_cr_decimal_separator' );
									$wc_cr_decimal_separator = ( empty ( $wc_cr_decimal_separator ) ) ? '.' : $wc_cr_decimal_separator;

									$wc_cr_number_of_decimals = get_option( 'wc_cr_number_of_decimals' );
									$wc_cr_number_of_decimals = ( empty ( $wc_cr_number_of_decimals ) ) ? '0' : $wc_cr_number_of_decimals;
								?>
								<div class="wrap">
									<h2>
										<?php echo esc_html__( 'Currency Settings', 'computer-repair-shop' ); ?>
									</h2>

									<form action="" method="post">
									<table class="form-table">
									<tbody>
										<tr valign="top">
											<th scope="row" class="titledesc">
												<label for="wc_cr_selected_currency"><?php echo esc_html__( 'Currency', 'computer-repair-shop'); ?></label>
											</th>
											<td class="forminp forminp-select">
												<select name="wc_cr_selected_currency" id="wc_cr_selected_currency">
												<?php 
													$allowed_html = wc_return_allowed_tags();
													$optionsGenerated = wc_cr_return_currency_options( $wc_cr_selected_currency );
													echo wp_kses( $optionsGenerated, $allowed_html );
												?>
												</select>
											</td>
										</tr>
										<tr valign="top">
											<th scope="row" class="titledesc">
												<label for="wc_cr_currency_position">
													<?php echo esc_html__( 'Currency position', 'computer-repair-shop' ); ?>
												</label>
											</th>
											<td class="forminp forminp-select">
												<select name="wc_cr_currency_position" id="wc_cr_currency_position">
													<?php
														$position_currency_arr = array(
															'left' 			=> __( 'Left', 'computer-repair-shop' ),
															'right' 		=> __( 'Right', 'computer-repair-shop' ),
															'left_space' 	=> __( 'Left with space', 'computer-repair-shop' ),
															'right_space' 	=> __( 'Right with space', 'computer-repair-shop' ),
														);

														$output_postion = '';

														foreach( $position_currency_arr as $curr_po_key => $curr_po_label ) {
															$selected_position = ( ! empty( $wc_cr_currency_position ) && $wc_cr_currency_position == $curr_po_key ) ? 'selected' : '';
															$output_postion .= '<option value="' . $curr_po_key . '" ' . $selected_position . '>' . $curr_po_label . '</option>';
														}
														echo wp_kses( $output_postion, $allowed_html );
													?>
												</select>
											</td>
										</tr>
										<tr valign="top">
											<th scope="row" class="titledesc">
												<label for="wc_cr_thousand_separator">
													<?php echo esc_html__( 'Thousand separator', 'computer-repair-shop' ); ?>
												</label>
											</th>
											<td class="forminp forminp-text">
												<input name="wc_cr_thousand_separator" id="wc_cr_thousand_separator" type="text" 
												style="width:50px;" value="<?php echo esc_html__( $wc_cr_thousand_separator ); ?>"> 							
											</td>
										</tr>
										<tr valign="top">
											<th scope="row" class="titledesc">
												<label for="wc_cr_decimal_separator">
													<?php echo esc_html__( 'Decimal separator', 'computer-repair-shop' ); ?>
												</label>
											</th>
											<td class="forminp forminp-text">
												<input name="wc_cr_decimal_separator" id="wc_cr_decimal_separator" type="text" style="width:50px;" 
												value="<?php echo esc_html__( $wc_cr_decimal_separator ); ?>"> 							
											</td>
										</tr>
										<tr valign="top">
											<th scope="row" class="titledesc">
												<label for="wc_cr_number_of_decimals">
													<?php echo esc_html__( 'Number of decimals', 'computer-repair-shop' ); ?>
												</label>
											</th>
											<td class="forminp forminp-number">
												<input name="wc_cr_number_of_decimals" id="wc_cr_number_of_decimals" type="number" style="width:50px;" 
												value="<?php echo esc_html__( $wc_cr_number_of_decimals ); ?>" min="0" step="1"> 							
											</td>
										</tr>
										<tr>
											<td>
												<input 
													class="button button-primary" 
													type="Submit"  
													value="<?php echo esc_html__( 'Save Changes', 'computer-repair-shop' ); ?>"/>
											</td>
											<td>
												<input type="hidden" name="wc_rep_currency_submit" value="1" />
											</td>
										</tr>
									</tbody>
									</table>
									</form>
								</div>
							</div><!-- tab CurrencyFormatting -->

							<div class="tabs-panel team-wrap<?php echo esc_attr( $class_invoices_settings ); ?>" id="reportsAInvoices" role="tabpanel" aria-hidden="true" aria-labelledby="panel1-label">
								<?php
									$wc_repair_order_print_size = get_option( 'wc_repair_order_print_size' );
									$wb_rb_invoice_type 		= get_option( 'wb_rb_invoice_type' );

									$business_terms 			= get_option( 'wc_business_terms' );
									$wc_rb_ro_thanks_msg 		= get_option( 'wc_rb_ro_thanks_msg' );
									$wc_rb_io_thanks_msg 		= get_option( 'wc_rb_io_thanks_msg' );
									
									$wc_rb_cr_display_add_on_ro 	= ( get_option("wc_rb_cr_display_add_on_ro") == "on" ) ? 'checked="checked"' : '';
									$wc_rb_cr_display_add_on_ro_cu  = ( get_option("wc_rb_cr_display_add_on_ro_cu") == "on" ) ? 'checked="checked"' : '';
								?>
								<div class="wrap">
									<h2><?php esc_html_e("Reports & Invoices Settings", "computer-repair-shop"); ?></h2>

									<form action="" method="post">
										<table cellpadding="5" cellspacing="5" class="form-table">
											<tr>
												<th scrope="row" colspan="2">
													<h3><?php esc_html_e( 'Print Invoice Settings', 'computer-repair-shop' ); ?></h3>
												</th>
											</tr>
											
											<tr>
												<th scope="row">
													<label for="wc_rb_io_thanks_msg"><?php echo esc_html__("Footer message on Print Invoice", "computer-repair-shop"); ?></label>
												</th>
												<td>
													<input 
														name="wc_rb_io_thanks_msg" 
														id="wc_rb_io_thanks_msg" 
														class="regular-text" 
														value="<?php echo esc_html($wc_rb_io_thanks_msg); ?>" 
														type="text" 
														placeholder="<?php esc_html_e( 'Thanks for your business!', 'computer-repair-shop' ); ?>"
														/>
												</td>
											</tr>
											<tr>
												<th scope="row">
													<label for="wb_rb_invoice_type">
														<?php echo esc_html__("Invoice Print By", 'computer-repair-shop'); ?>
													</label>
												</th>
												<td>
													<select name="wb_rb_invoice_type" id="wb_rb_invoice_type" class="form-control">
														<option <?php echo ( isset( $wb_rb_invoice_type ) && $wb_rb_invoice_type == 'default' ) ? 'selected' : ''; ?> value="default"><?php echo esc_html__( 'Default (By Items)', 'computer-repair-shop' ); ?></option>
														<option <?php echo ( isset( $wb_rb_invoice_type ) && $wb_rb_invoice_type == 'by_device' ) ? 'selected' : ''; ?> value="by_device"><?php echo esc_html__( 'By Devices', 'computer-repair-shop' ); ?></option>
														<option <?php echo ( isset( $wb_rb_invoice_type ) && $wb_rb_invoice_type == 'by_items' ) ? 'selected' : ''; ?> value="by_items"><?php echo esc_html__( 'By Items', 'computer-repair-shop' ); ?></option>
													</select>
												</td>
											</tr>


											<tr>
												<th scrope="row" colspan="2">
													<h3><?php esc_html_e( 'Repair Order Settings', 'computer-repair-shop' ); ?></h3>
												</th>
											</tr>

											<tr>
												<th scope="row">
													<label for="business_terms"><?php echo esc_html__("Terms & Conditions for Repair Order", "computer-repair-shop"); ?></label>
												</th>
												<td>
													<input 
														name="business_terms" 
														id="business_terms" 
														class="regular-text" 
														value="<?php echo esc_html($business_terms); ?>" 
														type="text" 
														placeholder="<?php echo esc_html__("On Repair Order QR Code would be generated with this link.", "computer-repair-shop"); ?>"/>
												</td>
											</tr>

											<tr>
												<th scope="row">
													<label for="repair_order_print_size">
														<?php echo esc_html__("Repair Order Print Size", 'computer-repair-shop'); ?>
													</label>
												</th>
												<td>
													<select name="wc_repair_order_print_size" id="repair_order_print_size" class="form-control">
														<option <?php echo ( isset( $wc_repair_order_print_size ) && $wc_repair_order_print_size == 'default' ) ? 'selected' : ''; ?> value="default"><?php echo esc_html__( 'Default (POS Size)', 'computer-repair-shop' ); ?></option>
														<option <?php echo ( isset( $wc_repair_order_print_size ) && $wc_repair_order_print_size == 'a4' ) ? 'selected' : ''; ?> value="a4"><?php echo esc_html__( 'A4', 'computer-repair-shop' ); ?></option>
														<option <?php echo ( isset( $wc_repair_order_print_size ) && $wc_repair_order_print_size == 'a5' ) ? 'selected' : ''; ?> value="a5"><?php echo esc_html__( 'A5', 'computer-repair-shop' ); ?></option>
													</select>
												</td>
											</tr>

											<tr>
												<th scope="row">
													<label for="wc_rb_cr_display_add_on_ro"><?php echo esc_html__("Display Business Address Details", 'computer-repair-shop'); ?></label>
												</th>
												<td>
													<input type="checkbox" <?php echo esc_html__( $wc_rb_cr_display_add_on_ro ); ?> name="wc_rb_cr_display_add_on_ro" id="wc_rb_cr_display_add_on_ro" />
													<p class="description"><?php echo esc_html__("Show business address, email and phone details on repair order.", "computer-repair-shop"); ?></p>
												</td>
											</tr>

											<tr>
												<th scope="row">
													<label for="wc_rb_cr_display_add_on_ro_cu"><?php echo esc_html__("Display Customer Email & Address Details", 'computer-repair-shop'); ?></label>
												</th>
												<td>
													<input type="checkbox" <?php echo esc_html__( $wc_rb_cr_display_add_on_ro_cu ); ?> name="wc_rb_cr_display_add_on_ro_cu" id="wc_rb_cr_display_add_on_ro_cu" />
													<p class="description"><?php echo esc_html__("Show customer address, email and phone details on repair order.", "computer-repair-shop"); ?></p>
												</td>
											</tr>

											<tr>
												<th scope="row">
													<label for="wc_rb_ro_thanks_msg"><?php echo esc_html__("Footer message on Repair Order", "computer-repair-shop"); ?></label>
												</th>
												<td>
													<input 
														name="wc_rb_ro_thanks_msg" 
														id="wc_rb_ro_thanks_msg" 
														class="regular-text" 
														value="<?php echo esc_html($wc_rb_ro_thanks_msg); ?>" 
														type="text" 
														placeholder="<?php esc_html_e( 'Thanks for your business!', 'computer-repair-shop' ); ?>"
														/>
												</td>
											</tr>

											<tr>
												<td>
													<input 
														class="button button-primary" 
														type="Submit"  
														value="<?php echo esc_html__("Save Changes", "computer-repair-shop"); ?>"/>
												</td>
												<td>
													<input type="hidden" name="wc_rep_labels_submit" value="1" />
												</td>
											</tr>
										</table>
									</form>
								</div>
							</div><!-- tab reportsAInvoices -->
							
							<div class="tabs-panel team-wrap<?php echo esc_attr($class_status); ?>" id="panel3" role="tabpanel" aria-hidden="false" aria-labelledby="panel3-label">
								
								<p class="help-text">
									<a class="button button-primary button-small" data-open="statusFormReveal">
										<?php echo esc_html__("Add New Status", "computer-repair-shop") ?>
									</a>
								</p>
								<?php add_filter( 'admin_footer','wc_add_status_form' ); ?>

								<div id="job_status_wrapper">
									<table id="status_poststuff" class="wp-list-table widefat fixed striped posts">
										<thead>
											<tr>
												<th  class="column-id"><?php echo esc_html__("ID", "computer-repair-shop"); ?></th>
												<th><?php echo esc_html__("Name", "computer-repair-shop"); ?></th>
												<th><?php echo esc_html__("Slug", "computer-repair-shop"); ?></th>
												<th><?php echo esc_html__("Description", "computer-repair-shop"); ?></th>
												<th><?php echo esc_html__("Invoice Label", "computer-repair-shop"); ?></th>

												<?php
													if(wc_inventory_management_status() == true) :
												?>
												<th><?php echo esc_html__("Manage Woo Stock", "computer-repair-shop"); ?></th>
												<?php 
													endif;
												?>
												<th class="column-id"><?php echo esc_html__("Status", "computer-repair-shop"); ?></th>
												<th class="column-id"><?php echo esc_html__("Actions", "computer-repair-shop"); ?></th>
											</tr>
										</thead>

										<tbody>
											<?php
												global $wpdb;
												
												$computer_repair_job_status = $wpdb->prefix.'wc_cr_job_status';

												$select_query 	= "SELECT * FROM `".$computer_repair_job_status."`";
												$select_results = $wpdb->get_results($select_query);
												
												$output = '';
												foreach($select_results as $result) {
																								
													$output .= '<tr><td>'.$result->status_id.'</td>';

													$output .= '<td><strong>'.$result->status_name.'</strong></td>';
													$output .= '<td>'.$result->status_slug.'</td>';
													$output .= '<td>'.$result->status_description.'</td>';

													$invoice_label = ( empty( $result->invoice_label ) ) ? 'Invoice' : $result->invoice_label;
													$output .= '<td>' . esc_html( $invoice_label ) . '</td>';
													
													if(wc_inventory_management_status() == true) :
														if(empty($result->inventory_count) || $result->inventory_count == "off"): 
															$labelCount = "OFF";
														else:
															$labelCount = "ON";	
														endif;

														$output .= '<td><a href="#" class="change_tax_status" data-type="inventory_count" data-value="'.esc_attr($result->status_id).'">'.$labelCount.'</a></td>';
													endif;
													
													$output .= '<td><a href="#" title="'.esc_html__("Change Status", "computer-repair-shop").'" class="change_tax_status" data-type="status" data-value="'.esc_attr($result->status_id).'">'.$result->status_status.'</a></td>';
													$output .= '<td><a href="'.esc_url( add_query_arg( 'update_status', $result->status_id, remove_query_arg( 'update_payment_status' ) ) ).'" class="update_tax_status" data-type="status" data-value="'.esc_attr($result->status_id).'">'.esc_html__("Edit", "computer-repair-shop").'</a>';
													$output .= '</td></tr>';
												}

												echo wp_kses_post($output);
											?>	
										</tbody>
									</table>
								</div><!-- Post Stuff/-->

							</div><!-- tab 3 Ends -->

							<?php do_action( 'wc_rb_settings_tab_body' ); ?>

							<div class="tabs-panel team-wrap<?php echo esc_attr($class_activation); ?>" id="panel4" role="tabpanel" aria-hidden="false" 
							aria-labelledby="panel4-label">
								
								<div id="license_activation">
									<?php 
										$theOutPut = wc_rs_activation_form();
										$allowedHTML = wc_return_allowed_tags();
										echo wp_kses($theOutPut, $allowedHTML);
									?>
								</div><!-- Post Stuff/-->

							</div><!-- tab 4 Ends -->

							<div class="tabs-panel team-wrap" id="documentation" role="tabpanel" aria-hidden="false" 
							aria-labelledby="documentation-label">
								<h1><?php esc_html_e("Shortcodes", "computer-repair-shop"); ?></h1>
								<p><?php echo esc_html__( 'RepairBuddy WordPress Plugin provides various shortcodes to use in different pages. Just copy a shortcode you need and paste in a page to use it. Please check Page Setup for some default created pages.', 'computer-repair-shop' ); ?></p>
								
								<div class="documentation-section">
									<h2><?php echo esc_html__( 'Check Repair Status', 'computer-repair-shop' ); ?></h2>
								<p><?php echo esc_html__("To add check case status form create a page and insert shortcode", "computer-repair-shop"); ?></p>
								<pre>[wc_order_status_form]</pre></div>
									
								<div class="documentation-section">
									<h2><?php esc_html_e( 'Book Device / Book Service', 'computer-repair-shop'); ?></h2>
									<p><?php echo esc_html__("Book the service with brand, device, and service selection.", "computer-repair-shop"); ?></p>
									<p><?php echo esc_html__("Doesn't include device type or grouped services.", "computer-repair-shop"); ?></p>
									<pre>[wc_book_my_service]</pre>

									<p><?php echo esc_html__("Grouped services with device type, brands, devices.", "computer-repair-shop"); ?></p>
									<pre>[wc_book_type_grouped_service]</pre>

									<p><?php echo esc_html__("To add start new job by device on front end for loged in users only", "computer-repair-shop"); ?></p> 
									<pre>[wc_start_job_with_device]</pre></div>

								<div class="documentation-section">
									<h2><?php esc_html_e( 'Get Feedback on Job Page', 'computer-repair-shop'); ?></h2>
									<p><?php echo esc_html__( 'Using this shortcode you can get the feedback from customers on jobs you performed for them. For auto feedback request check reviews settings.', 'computer-repair-shop' ); ?> </p>
									<pre>[wc_get_order_feedback]</pre>
								</div>

								<div class="documentation-section">
									<h2><?php esc_html_e( 'My Account Page', 'computer-repair-shop'); ?></h2>
									<p><?php echo esc_html__( 'Note: If you are using WooCommerce then WooCommerce My Account page can list Repair Orders and Request quote section, You do not need to add separate account page in that case.', 'computer-repair-shop' ); ?> </p>
									<p><?php echo esc_html__("To add user account page into front end create a page and use", "computer-repair-shop"); ?></p>
									<pre>[wc_cr_my_account]</pre>
								</div>	

								<div class="documentation-section">
									<h2><?php esc_html_e( 'For Warranty Claim', 'computer-repair-shop'); ?></h2>
									<p><?php echo esc_html__( "Warranty claim can be done for WooCommerce products or Devices.", "computer-repair-shop"); ?></p>
									<p><?php echo esc_html__("Following Shortcode let customers book their device for warranty claim. Doesn't require services to be included.", "computer-repair-shop"); ?></p>
									<pre>[wc_book_my_warranty]</pre>
								</div>	
								
								<div class="documentation-section">
									<h2><?php esc_html_e( 'Simple Quote Form', 'computer-repair-shop'); ?></h2>
								<p><?php echo esc_html__("To add simple request quote form into front end use", "computer-repair-shop"); ?></p> 
								<pre>[wc_request_quote_form]</pre></div>

								<div class="documentation-section">
									<h2><?php esc_html_e( 'Services Page', 'computer-repair-shop'); ?></h2>
								<p><?php echo esc_html__("To populate services create a page and insert shortcode", "computer-repair-shop"); ?></p>
								<pre>[wc_list_services]</pre></div>

								<div class="documentation-section"><h2><?php esc_html_e( 'Parts Page', 'computer-repair-shop'); ?></h2>
								<p><?php echo esc_html__("To populate parts/products create a page and insert shortcode", "computer-repair-shop"); ?></p> 
								<pre>[wc_list_products]</pre></div>
							</div><!-- tab Documentation Ends -->

							<div class="tabs-panel team-wrap" id="addons" role="tabpanel" aria-hidden="false" 
							aria-labelledby="addons-label">
								<h1><?php esc_html_e("Addons", "computer-repair-shop"); ?></h1>
								<p><?php echo esc_html__( 'We have some addons which you can use to extend the features of your RepairBuddy WordPress Plugin.', 'computer-repair-shop' ); ?></p>
								
								<div class="theaddons-container grid-x grid-margin-x grid-container fluid">
									<?php if ( ! defined( 'RB_MS_VERSION' ) ) : ?>
									<div class="large-4 medium-4 medium-6 cell">
										<div class="documentation-section theaddon">
												<h2><?php echo esc_html__( 'MultiStore - RepairBuddy', 'computer-repair-shop' ); ?></h2>
											<p><?php echo esc_html__( "Multistore RepairBuddy addon extends your CRM with features to have more than one stores, filter jobs based on stores. Technicians can access jobs only they have access to, Managers can access only store they have access to. Invoices can also have address of selected store on that job and much more ...", "computer-repair-shop" ); ?></p>
											<a href="https://www.webfulcreations.com/products/multi-store-addon-repairbuddy/" class="button button-primary" target="_blank"><?php echo esc_html__( 'Learn More', 'computer-repair-shop' ); ?></a>
										</div>
									</div> <!-- Column Ends /-->
									<?php endif; ?>

									<?php if ( ! defined( 'RB_QB_VERSION' ) ) : ?>
									<div class="large-4 medium-4 medium-6 cell">
										<div class="documentation-section theaddon">
												<h2><?php echo esc_html__( 'QuickBooks Addon – RepairBuddy', 'computer-repair-shop' ); ?></h2>
											<p><?php echo esc_html__( "QuickBooks Addon – RepairBuddy is another great addon to expand features of your RepairBuddy supported website. Using QuickBooks addon you can easily fetch your customers from QuickBooks and also send invoices to QuickBooks from RepairBuddy. While you can manually send invoices to QuickBooks clicking button but also on status change automatically job can be sent to QuickBooks as invoice. ", "computer-repair-shop" ); ?></p>
											<a href="https://www.webfulcreations.com/products/quickbooks-addon-repairbuddy/" class="button button-primary" target="_blank"><?php echo esc_html__( 'Learn More', 'computer-repair-shop' ); ?></a>
										</div>
									</div> <!-- Column Ends /-->
									<?php endif; ?>

								</div><!-- End container /-->
									
							</div><!-- Addons Ends -->

						</div><!-- tabs content ends -->
					</div>

                </div>
			
			</div><!-- Main Content Div Ends /-->
		</div><!-- Row Ends /-->
	</div>
<?php
}
	//Checking if form is submitted or not.
	if(isset($_POST['wc_rep_settings']) && $_POST['wc_rep_settings'] == '1') { 
		wc_rep_shop_settings_submission(); //running this function on form submission.
	}

	if ( isset( $_POST['wc_rep_labels_submit'] ) && $_POST['wc_rep_labels_submit'] == '1' ) {
		wc_rep_shop_report_labels_submission();
	}

	if ( isset( $_POST['wc_rep_currency_submit'] ) && $_POST['wc_rep_currency_submit'] == '1' ) {
		wc_cr_submit_currency_options();
	}

	function wc_cr_submit_currency_options() {
		global $wpdb;

		$wc_cr_selected_currency 	= ( ! isset( $_POST['wc_cr_selected_currency'] ) ) ? 'USD' : sanitize_text_field( $_POST['wc_cr_selected_currency'] );
		$wc_cr_currency_position 	= ( ! isset( $_POST['wc_cr_currency_position'] ) ) ? 'left' : sanitize_text_field( $_POST['wc_cr_currency_position'] );
		$wc_cr_thousand_separator 	= ( ! isset( $_POST['wc_cr_thousand_separator'] ) ) ? ',' : wp_filter_nohtml_kses( $_POST['wc_cr_thousand_separator'] );
		$wc_cr_decimal_separator 	= ( ! isset( $_POST['wc_cr_decimal_separator'] ) ) ? '.' : wp_filter_nohtml_kses( $_POST['wc_cr_decimal_separator'] );
		$wc_cr_number_of_decimals	= ( ! isset( $_POST['wc_cr_number_of_decimals'] ) ) ? '0' : sanitize_text_field( $_POST['wc_cr_number_of_decimals'] );

		update_option( 'wc_cr_selected_currency', $wc_cr_selected_currency );
		update_option( 'wc_cr_currency_position', $wc_cr_currency_position );
		update_option( 'wc_cr_thousand_separator', $wc_cr_thousand_separator );
		update_option( 'wc_cr_decimal_separator', $wc_cr_decimal_separator );
		update_option( 'wc_cr_number_of_decimals', $wc_cr_number_of_decimals );
	
		//Show message.
		add_action( "admin_notices", "wc_main_settings_saved" );
	}

	function wc_rep_shop_report_labels_submission() {
		global $wpdb;

		$wc_repair_order_print_size = ( ! isset( $_POST['wc_repair_order_print_size'] ) ) ? '' : sanitize_text_field( $_POST['wc_repair_order_print_size'] );
		$wb_rb_invoice_type			= ( ! isset( $_POST['wb_rb_invoice_type'] ) ) ? '' : sanitize_text_field( $_POST['wb_rb_invoice_type'] );

		$business_terms				= ( ! isset( $_POST['business_terms'] ) ) ? "" : sanitize_text_field($_POST['business_terms']);
		$wc_rb_cr_display_add_on_ro = ( ! isset( $_POST['wc_rb_cr_display_add_on_ro'] ) ) ? '' : sanitize_text_field( $_POST['wc_rb_cr_display_add_on_ro'] );
		$wc_rb_cr_display_add_on_ro_cu = ( ! isset( $_POST['wc_rb_cr_display_add_on_ro_cu'] ) ) ? '' : sanitize_text_field( $_POST['wc_rb_cr_display_add_on_ro_cu'] );
		$wc_rb_ro_thanks_msg		= ( ! isset( $_POST['wc_rb_ro_thanks_msg'] ) ) ? '' : sanitize_text_field( $_POST['wc_rb_ro_thanks_msg'] );
		$wc_rb_io_thanks_msg		= ( ! isset( $_POST['wc_rb_io_thanks_msg'] ) ) ? '' : sanitize_text_field( $_POST['wc_rb_io_thanks_msg'] );
		
		update_option( 'wb_rb_invoice_type', $wb_rb_invoice_type );
		update_option( 'wc_repair_order_print_size', $wc_repair_order_print_size);
		update_option( 'wc_business_terms', 			$business_terms);
		update_option( 'wc_rb_ro_thanks_msg', $wc_rb_ro_thanks_msg );
		update_option( 'wc_rb_io_thanks_msg', $wc_rb_io_thanks_msg );
		update_option( 'wc_rb_cr_display_add_on_ro', $wc_rb_cr_display_add_on_ro);
		update_option( 'wc_rb_cr_display_add_on_ro_cu', $wc_rb_cr_display_add_on_ro_cu);
		
		//Show message.
		add_action("admin_notices", "wc_main_settings_saved");
	}

	//Function to save data. 
	function wc_rep_shop_settings_submission() { 
		global $wpdb; //to use database functions inside function.

		$wc_enable_woo_products 	 = ! isset( $_POST['wc_enable_woo_products'] ) ? "" : 	sanitize_text_field($_POST['wc_enable_woo_products']);
		$wc_file_attachment_in_job 	 = ! isset($_POST['wc_file_attachment_in_job'])? "" : sanitize_text_field($_POST['wc_file_attachment_in_job']);
		$wc_job_status_cr_notice 	 = ! isset($_POST['wc_job_status_cr_notice'])? "" : 	sanitize_text_field($_POST['wc_job_status_cr_notice']);
		$wc_add_user_notification    = ! isset( $_POST['wc_add_user_notification']) ? '' : sanitize_text_field( $_POST['wc_add_user_notification'] );
		$menu_name					 = ( ! isset($_POST['menu_name'])) ? "" : sanitize_text_field($_POST['menu_name']);
		$wc_rb_business_name		 = ( ! isset($_POST['wc_rb_business_name'])) ? "" : 	sanitize_text_field($_POST['wc_rb_business_name']);
		$wc_rb_business_phone		 = ( ! isset($_POST['wc_rb_business_phone'])) ? "" : 	sanitize_text_field($_POST['wc_rb_business_phone']);
		$wc_rb_business_address		 = ( ! isset($_POST['wc_rb_business_address'])) ? "" : sanitize_text_field($_POST['wc_rb_business_address']);
		$computer_repair_logo		 = ( ! isset($_POST['computer_repair_logo'])) ? "" : 	esc_url_raw($_POST['computer_repair_logo']);
		$computer_repair_email		 = ( ! isset($_POST['computer_repair_email'])) ? "" :  sanitize_email($_POST['computer_repair_email']);
		$wc_rb_gdpr_acceptance 	 	 = ( !isset( $_POST['wc_rb_gdpr_acceptance'] ) ) ? "" : sanitize_text_field( $_POST['wc_rb_gdpr_acceptance'] );
		$wc_rb_gdpr_acceptance_link  = ( ! isset($_POST['wc_rb_gdpr_acceptance_link'])) ? "" : 	esc_url_raw($_POST['wc_rb_gdpr_acceptance_link']);
		$wc_primary_country			= ( ! isset($_POST['wc_primary_country'])) ? "" : 	sanitize_text_field($_POST['wc_primary_country']);
		$case_number_prefix 		= ( ! isset($_POST['case_number_prefix'])) ? "" : 	sanitize_text_field($_POST['case_number_prefix']);
		$case_number_length			= ( ! isset($_POST['case_number_length'])) ? "" : 	sanitize_text_field($_POST['case_number_length']);

		update_option('wc_enable_woo_products', 	$wc_enable_woo_products);// Enable Woo Prouducts Replace Parts
		update_option('wc_file_attachment_in_job', 	$wc_file_attachment_in_job);// Enable Woo Prouducts Replace Parts
		update_option('menu_name_p', 				$menu_name);
		update_option('wc_rb_business_name', 		$wc_rb_business_name);
		update_option('wc_rb_business_phone', 		$wc_rb_business_phone);
		update_option('wc_rb_business_address', 	$wc_rb_business_address);
		update_option("computer_repair_logo", 		$computer_repair_logo);
		update_option( 'wc_rb_gdpr_acceptance', 	 $wc_rb_gdpr_acceptance );
		update_option( 'wc_rb_gdpr_acceptance_link', $wc_rb_gdpr_acceptance_link );
		update_option("computer_repair_email", 		$computer_repair_email);
		update_option ( 'wc_add_user_notification', $wc_add_user_notification );
		
		//update_option('wc_add_admin_to_technician', strip_tags($_POST['add_admin_to_technician']));
		update_option("wc_job_status_cr_notice", 	$wc_job_status_cr_notice);
		update_option('wc_primary_country', 		$wc_primary_country);
		update_option('case_number_prefix', 		$case_number_prefix);
		update_option('case_number_length', 		$case_number_length);

		add_action( 'admin_notices', 'wc_main_settings_saved' );
	}//End of wc_rep_shop_settings_submission()

	if(!function_exists("wc_main_settings_saved")):
		function wc_main_settings_saved() {
			$content = '<div class="updated">';
			$content .= '<p>' . esc_html__( 'Settings saved!', 'computer-repair-shop' ) . '</p>';
			$content .= '</div>';

			echo wp_kses_post( $content );	
		}
	endif;