<?php
	function wc_comp_rep_shop_technicians() {
		if (!current_user_can('delete_posts')) {
			wp_die( esc_html__('You do not have sufficient permissions to access this page.', "computer-repair-shop") );
		}
		
		if ( ! current_user_can( 'delete_posts' ) ) {
			wp_die(
				'<h1>' . esc_html__( 'You need a higher level of permission.', "computer-repair-shop" ) . '</h1>' .
				'<p>' . esc_html__( 'Sorry, you are not allowed to list users.', "computer-repair-shop" ) . '</p>',
				403
			);
		}

		// Pagination vars
		$current_page 	= isset($_GET['paged']) ? sanitize_text_field( $_GET['paged'] ) : 1; //get_query_var('paged') ? (int) get_query_var('paged') : 1;
		$users_per_page = 20;

		$current_page = (int)$current_page;
		$users_per_page = (int)$users_per_page;

		$args 			= array( 
								'role' 		=> 'technician', 
								'echo' 		=> 0,
								'orderby'	=> 'ID',
								'order'		=> 'DESC',
								'number' 	=> $users_per_page,
								'paged' 	=> $current_page
						);
		//$users_array 	= get_users($args);

		$users_obj 		= new WP_User_Query( $args );

		$total_users 	= $users_obj->get_total();
		$num_pages 		= ceil($total_users / $users_per_page);
?>		
		<div class="wrap" id="poststuff">
				<h1 class="wp-heading-inline">
					<?php 
						echo esc_html__( "Manage Technicians", "computer-repair-shop" );
					?>
				</h1>
				<a data-open="technicianFormReveal" class="page-title-action"><?php echo esc_html__("Add New", "computer-repair-shop"); ?></a>
				<br class="clear" />
				<?php
					$display_from 	= (($current_page*$users_per_page)-$users_per_page);
					$display_to 	= ($current_page*$users_per_page);

					$display_to 	= ($display_to >= $total_users) ? $total_users : $display_to;
				?>
				<p><?php echo esc_html__( 'Display', 'computer-repair-shop' ) . ' ' . esc_html( $display_from ) . ' - ' . esc_html( $display_to ) . ' ' . esc_html__( 'From Total', 'computer-repair-shop' ) . '  ' . esc_html( $total_users ) . ' ' . esc_html__( 'Technicians.', 'computer-repair-shop' ); ?></p>

			<table class="wp-list-table widefat fixed striped users">
				<thead>
				<tr>
						<th class="manage-column column-id">
							<span><?php echo esc_html__("ID", "computer-repair-shop"); ?></span>
						</th>
						<th class="manage-column column-name">
							<span><?php echo esc_html__("Name", "computer-repair-shop"); ?></span>
						</th>
						<th class="manage-column column-email">
							<span><?php echo esc_html__("Email", "computer-repair-shop"); ?></span>
						</th>
						<th class="manage-column column-phone">
							<?php echo esc_html__("Phone", "computer-repair-shop"); ?>
						</th>
						<th class="manage-column column-address">
							<?php echo esc_html__("Address", "computer-repair-shop"); ?>
						</th>
						<th class="manage-column column-company">
							<?php echo esc_html__("Company", "computer-repair-shop"); ?>
						</th>
						<th class="manage-column column-jobs">
							<?php echo esc_html__("Jobs", "computer-repair-shop"); ?>
						</th>
					</tr>
				</thead>

				<tbody data-wp-lists="list:user">

					<?php 
						$content = '';

						foreach($users_obj->get_results() as $userdata) {
							$user 			= get_user_by('id', $userdata->ID);
							$phone_number 	= get_user_meta($userdata->ID, "billing_phone", true);
							$company 		= get_user_meta($userdata->ID, "billing_company", true);
							$address 		= get_user_meta($userdata->ID, "billing_address_1", true);
							$city 			= get_user_meta($userdata->ID, "billing_city", true);
							$zip_code 		= get_user_meta($userdata->ID, "billing_postcode", true);

							$content .= '<tr>';
							$content .= '<td class="id column-id num" data-colname="ID">';
							$content .= $userdata->ID;
							$content .= '</td>';	

							$content .= '<td class="username column-username has-row-actions column-primary" data-colname="Username">
											<strong>
												<a href="edit.php?post_type=rep_jobs&job_technician='.$userdata->ID.'">
													'.$user->first_name . ' ' . $user->last_name.'
												</a>
											</strong><br>
											<div class="row-actions">
												<span class="edit">
													<a href="'.add_query_arg(array('update_user' => $userdata->ID)).'" class="update_user_form">
														'.esc_html__("Edit", "computer-repair-shop").'
													</a> | 
												</span>
												<span class="remove">
													<a href="edit.php?post_type=rep_jobs&job_technician='.$userdata->ID.'">
														'.esc_html__("View Jobs", "computer-repair-shop").'
													</a> 
												</span>
											</div>
											<button type="button" class="toggle-row"><span class="screen-reader-text">'.esc_html__("Show more details", "computer-repair-shop").'</span></button>
										</td>';
						
							$content .= '<td class="email column-email" data-colname="Email">
											<a href="mailto:'.$userdata->user_email.'">
											'.$userdata->user_email.'
											</a>
										</td>';

							$content .= '<td class="phone column-phone" data-colname="phone">';
											if(!empty($phone_number)):
												$content .= '<a href="tel:'.$phone_number.'">'.$phone_number.'</a>';
											endif;
							$content .= '</td>';			
							
							$content .= '<td class="address column-address" data-colname="Address">';
											if(!empty($address)) {
												$content .= $address.", ";
											}
											if(!empty($city)) {
												$content .= $city.", ";	
											}
											if(!empty($zip_code)) {
												$content .= $zip_code;
											}
							$content .= '</td>';

							$content .= '<td class="company column-company" data-colname="Company">';
							$content .= $company;
							$content .= '</td>';
			
							$content .= '<td class="jobs column-jobs num" data-colname="Jobs">';
							$content .= wc_return_jobs_by_user($userdata->ID, "technician");
							$content .= '</td></tr>';
						}
						$allowedHTML = wc_return_allowed_tags(); 
						echo wp_kses($content, $allowedHTML);
					?>
				</tbody>

				<tfoot>
					<tr>
						<th class="manage-column column-id">
							<span><?php echo esc_html__("ID", "computer-repair-shop"); ?></span>
						</th>
						<th class="manage-column column-name">
							<span><?php echo esc_html__("Name", "computer-repair-shop"); ?></span>
						</th>
						<th class="manage-column column-email">
							<span><?php echo esc_html__("Email", "computer-repair-shop"); ?></span>
						</th>
						<th class="manage-column column-phone">
							<?php echo esc_html__("Phone", "computer-repair-shop"); ?>
						</th>
						<th class="manage-column column-address">
							<?php echo esc_html__("Address", "computer-repair-shop"); ?>
						</th>
						<th class="manage-column column-company">
							<?php echo esc_html__("Company", "computer-repair-shop"); ?>
						</th>
						<th class="manage-column column-jobs">
							<?php echo esc_html__("Jobs", "computer-repair-shop"); ?>
						</th>
					</tr>
				</tfoot>
			</table>


			<div class="tablenav-pages" style="float:right;margin-top:20px;">
				<span class="displaying-num">
					<?php 
						echo esc_html($total_users)." ".esc_html__("items", "computer-repair-shop"); 
					?>
				</span>

				<span class="pagination-links">
			
					<?php
						// Previous page
						if ( $current_page > 1 ) {
						?>
							<a class="first-page button" href="<?php echo esc_url(add_query_arg(array('paged' => 1))); ?>">
								<span aria-hidden="true">«</span>
							</a>
							<a class="prev-page button" href="<?php echo esc_url(add_query_arg(array('paged' => $current_page-1))); ?>">
								<span aria-hidden="true">‹</span>
							</a>
						<?php } ?>

					<span id="table-paging" class="paging-input">
						<span class="tablenav-paging-text"><?php echo esc_html($current_page); ?> <?php echo esc_html__("of", "computer-repair-shop"); ?> <span class="total-pages"><?php echo esc_html($num_pages); ?></span></span></span>
				
					<?php
					// Next page
					if ( $current_page < $num_pages ) {
					?>
						<a class="next-page button" href="<?php echo esc_url(add_query_arg(array('paged' => $current_page+1))); ?>"><span aria-hidden="true">›</span></a>
						<a class="last-page button" href="<?php echo esc_url(add_query_arg(array('paged' => $num_pages))); ?>"><span aria-hidden="true">»</span></a></span>
					<?php } ?>
			</div>
			</div> <!-- Wrap Ends /-->
		<?php
		if ( ! isset( $_GET['update_user'] ) ) {
			add_filter('admin_footer','wc_add_technician_form');
		} else {
			add_filter('admin_footer','wc_update_user_form');
		}
	}//add category function ends here.