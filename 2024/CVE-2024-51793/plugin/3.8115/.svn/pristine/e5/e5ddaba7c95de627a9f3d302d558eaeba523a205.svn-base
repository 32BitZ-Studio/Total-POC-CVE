<?php
defined( 'ABSPATH' ) || exit;

	if(!function_exists("wc_computer_rep_reports")):
	function wc_computer_rep_reports() { 
		if (!current_user_can('manage_options')) {
			wp_die( __('You do not have sufficient permissions to access this page.', "computer-repair-shop") );
		}
	?>
	<div class='wc-rb-reports-container'>
		<div class="wc-rb-head">
			<h2><?php 
					$menu_name_p = get_option("menu_name_p");
					echo esc_html($menu_name_p)." - ".esc_html__("RepairBuddy Reports", "computer-repair-shop"); ?></h2>
		</div>

		<div class="grid-container grid-x grid-margin-x grid-padding-y">
			
			<div class="large-4 medium-6 small-12 cell">
				<div class="wc-rb-panel wc-rb-panel-info">
					<div class="wc-rb-panel-heading">
						<strong><?php echo esc_html__("Sales Reports", "computer-repair-shop"); ?></strong>
					</div>
					<div class="wc-rb-panel-body wc-rb-list-group">
						<div class="wc-rb-list-group-item">
							<a href="admin.php?page=wc_computer_repair_print&print_reports=YES&report_type=daily_sales_summary" target="_blank">
								<?php echo esc_html__("Daily Sales", "computer-repair-shop"); ?>
							</a>
						</div>
					</div>
				</div>
			</div>
			<!--customers and receiveables-->

			<div class="large-4 medium-6 small-12 cell">
				<div class="wc-rb-panel wc-rb-panel-info">
					<div class="wc-rb-panel-heading">
						<strong><?php echo esc_html__( "Technicians Reports", "computer-repair-shop" ); ?></strong>
					</div>
					<div class="wc-rb-panel-body wc-rb-list-group">
						<div class="wc-rb-list-group-item">
							<a href="admin.php?page=wc_computer_repair_print&print_reports=YES&report_type=jobs_by_technician" target="_blank">
								<?php echo esc_html__( "Jobs By Technician", "computer-repair-shop" ); ?>
							</a>
						</div>
						<div class="wc-rb-list-group-item">
							<a href="admin.php?page=wc_computer_repair_print&print_reports=YES&report_type=technicians_summary" target="_blank">
								<?php echo esc_html__( "Technicians Summary", "computer-repair-shop" ); ?>
							</a>
						</div>
					</div>
				</div>
			</div>
			<!--Technicians Reports-->

			<div class="large-4 medium-6 small-12 cell">
				<div class="wc-rb-panel wc-rb-panel-info">
					<div class="wc-rb-panel-heading">
						<strong><?php echo esc_html__( "Customers Reports", "computer-repair-shop" ); ?></strong>
					</div>
					<div class="wc-rb-panel-body wc-rb-list-group">
						<div class="wc-rb-list-group-item">
							<a href="admin.php?page=wc_computer_repair_print&print_reports=YES&report_type=jobs_by_customer" target="_blank">
								<?php echo esc_html__( "Jobs By Customer", "computer-repair-shop" ); ?>
							</a>
						</div>
						<div class="wc-rb-list-group-item">
							<a href="admin.php?page=wc_computer_repair_print&print_reports=YES&report_type=customers_summary" target="_blank">
								<?php echo esc_html__( "Customers Summary", "computer-repair-shop" ); ?>
							</a>
						</div>
					</div>
				</div>
			</div>
			<!--Customers Reports-->

		</div>
	</div><!-- End of reports container /-->
	<?php 
	}
	endif; 