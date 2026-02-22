<?php
defined( 'ABSPATH' ) || exit;

if ( ! function_exists( 'wc_comp_rep_shop_payments' ) ) :
	function wc_comp_rep_shop_payments() {
		global $wpdb, $PAYMENT_STATUS_OBJ;

		if ( ! current_user_can( 'delete_posts' ) ) {
			wp_die( esc_html__( 'You do not have sufficient permissions to access this page.', "computer-repair-shop" ) );
		}
		
		$computer_repair_payments = $wpdb->prefix.'wc_cr_payments';
		
		$current_page 	= isset($_GET['paged']) ? sanitize_text_field( $_GET['paged'] ) : 1; //get_query_var('paged') ? (int) get_query_var('paged') : 1;
		$_per_page_rec 	= 15;

		$current_page 	= (int)$current_page;
		$_per_page_rec 	= (int)$_per_page_rec;

		$recordscount   = $wpdb->get_var( "SELECT COUNT(*) FROM $computer_repair_payments WHERE `discount` = 0" );

		$num_pages 		= ceil( $recordscount / $_per_page_rec );

		$display_from 	= ( ( $current_page*$_per_page_rec ) - $_per_page_rec );
		$display_to 	= ( $current_page*$_per_page_rec );
		$display_to 	= ( $display_to >= $recordscount ) ? $recordscount : $display_to;

		?>
		<div class="wrap" id="poststuff">
			<h1 class="wp-heading-inline"><?php echo esc_html__( "Manage Payments", "computer-repair-shop" ); ?></h1>
			<br class="clear" />
			<p><?php echo esc_html__("Display", "computer-repair-shop")." ".esc_html( $display_from )." - ".esc_html( $display_to )." ".esc_html__("From Total", "computer-repair-shop")." ".esc_html( $recordscount ); ?></p>
			<div id="paymentstatusmessage"></div>

			<table class="wp-list-table widefat fixed striped users" id="thepaymentstable">
				<thead>
					<tr>
						<th class="manage-column column-id">
							<span><?php echo esc_html__("ID", "computer-repair-shop"); ?></span>
						</th>
						<th class="manage-column column-name">
							<span><?php echo esc_html__("ON", "computer-repair-shop"); ?></span>
						</th>
						<th class="manage-column column-name">
							<span><?php echo esc_html__("Job", "computer-repair-shop"); ?></span>
						</th>
						<th class="manage-column column-email">
							<span><?php echo esc_html__("Receiver", "computer-repair-shop"); ?></span>
						</th>
						<th class="manage-column column-phone">
							<?php echo esc_html__("Method", "computer-repair-shop"); ?>
						</th>
						<th class="manage-column column-address">
							<?php echo esc_html__("Status", "computer-repair-shop"); ?>
						</th>
						<th class="manage-column column-company">
							<?php echo esc_html__("Note", "computer-repair-shop"); ?>
						</th>
						<th class="manage-column column-tax">
							<?php echo esc_html__("Validity", "computer-repair-shop"); ?>
						</th>
						<th class="manage-column column-jobs">
							<?php echo esc_html__("Amount", "computer-repair-shop"); ?>
						</th>
					</tr>
				</thead>

				<tbody data-wp-lists="list:user">
					<?php
						$args = array( 'print_head' => 'NO', 'include_job' => 'YES', 'limit' => $_per_page_rec, 'offset' => $display_from, 'discounts' => 'nodiscounts' );

						$returned = $PAYMENT_STATUS_OBJ->list_the_payments( $args );
						$allowedHTML = wc_return_allowed_tags(); 
						echo wp_kses( $returned, $allowedHTML );
					?>

				</tbody>

				<tfoot>
					<tr>
						<th class="manage-column column-id">
							<span><?php echo esc_html__("ID", "computer-repair-shop"); ?></span>
						</th>
						<th class="manage-column column-name">
							<span><?php echo esc_html__("ON", "computer-repair-shop"); ?></span>
						</th>
						<th class="manage-column column-name">
							<span><?php echo esc_html__("Job", "computer-repair-shop"); ?></span>
						</th>
						<th class="manage-column column-email">
							<span><?php echo esc_html__("Receiver", "computer-repair-shop"); ?></span>
						</th>
						<th class="manage-column column-phone">
							<?php echo esc_html__("Method", "computer-repair-shop"); ?>
						</th>
						<th class="manage-column column-address">
							<?php echo esc_html__("Status", "computer-repair-shop"); ?>
						</th>
						<th class="manage-column column-company">
							<?php echo esc_html__("Note", "computer-repair-shop"); ?>
						</th>
						<th class="manage-column column-tax">
							<?php echo esc_html__("Validity", "computer-repair-shop"); ?>
						</th>
						<th class="manage-column column-jobs">
							<?php echo esc_html__("Amount", "computer-repair-shop"); ?>
						</th>
					</tr>
				</tfoot>
			</table>

			<div class="tablenav-pages" style="float:right;margin-top:20px;">
				<span class="displaying-num">
					<?php 
						echo esc_html( $recordscount ) . " " . esc_html__( "items", "computer-repair-shop" ); 
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
						<span class="tablenav-paging-text"><?php echo esc_html( $current_page ); ?> <?php echo esc_html__("of", "computer-repair-shop"); ?> <span class="total-pages"><?php echo esc_html( $num_pages ); ?></span></span></span>
				
					<?php if ( $current_page < $num_pages ) { ?>
						<a class="next-page button" href="<?php echo esc_url(add_query_arg(array('paged' => $current_page+1))); ?>"><span aria-hidden="true">›</span></a>
						<a class="last-page button" href="<?php echo esc_url(add_query_arg(array('paged' => $num_pages))); ?>"><span aria-hidden="true">»</span></a></span>
					<?php } ?>
			</div>
		</div> <!-- Wrap Ends /-->
		<?php
	}
endif;