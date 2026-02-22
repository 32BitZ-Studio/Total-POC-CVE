<?php
defined( 'ABSPATH' ) || exit;

if ( ! function_exists( 'wcrb_display_reminder_logs' ) ) :
	function wcrb_display_reminder_logs() {
		global $OBJ_MAINTENANCE_REMINDER;

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have sufficient permissions to access this page.', 'computer-repair-shop' ) );
		}
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die(
				'<h1>' . esc_html__( 'You need a higher level of permission.', "computer-repair-shop" ) . '</h1>' .
				'<p>' . esc_html__( 'Sorry, you are not allowed to list users.', "computer-repair-shop" ) . '</p>',
				403
			);
		}

		?>
		<div class="wrap" id="poststuff">
			<h1 class="wp-heading-inline">
				<?php 
					echo esc_html__( "Reminder Logs", "computer-repair-shop" );
				?>
			</h1>
	
			<table class="wp-list-table widefat fixed striped users">
			<thead><tr>
				<th class="manage-column column-id">
					<span><?php echo esc_html__( 'ID', 'computer-repair-shop' ); ?></span>
				</th>
				<th class="manage-column column-name">
					<span><?php echo esc_html__( 'Date', 'computer-repair-shop' ); ?></span>
				</th>
				<th class="manage-column column-email">
					<span><?php echo esc_html__( 'Customer', 'computer-repair-shop' ); ?></span>
				</th>
				<th class="manage-column column-phone">
					<?php echo esc_html__( 'Job', 'computer-repair-shop' ); ?>
				</th>
				<th class="manage-column column-address">
					<?php echo esc_html__( 'Reminder', 'computer-repair-shop' ); ?>
				</th>
				<th class="manage-column column-company">
					<?php echo esc_html__( 'Email', 'computer-repair-shop' ); ?>
				</th>
				<th class="manage-column column-jobs">
					<?php echo esc_html__( 'SMS', 'computer-repair-shop' ); ?>
				</th>
			</tr></thead>
			<tbody data-wp-lists="list:user">
				<?php $OBJ_MAINTENANCE_REMINDER->return_reminder_logs_history(); ?>
			</tbody>
			<tfoot><tr>
				<th class="manage-column column-id">
					<span><?php echo esc_html__( 'ID', 'computer-repair-shop' ); ?></span>
				</th>
				<th class="manage-column column-name">
					<span><?php echo esc_html__( 'Date', 'computer-repair-shop' ); ?></span>
				</th>
				<th class="manage-column column-email">
					<span><?php echo esc_html__( 'Customer', 'computer-repair-shop' ); ?></span>
				</th>
				<th class="manage-column column-phone">
					<?php echo esc_html__( 'Job', 'computer-repair-shop' ); ?>
				</th>
				<th class="manage-column column-address">
					<?php echo esc_html__( 'Reminder', 'computer-repair-shop' ); ?>
				</th>
				<th class="manage-column column-company">
					<?php echo esc_html__( 'Email', 'computer-repair-shop' ); ?>
				</th>
				<th class="manage-column column-jobs">
					<?php echo esc_html__( 'SMS', 'computer-repair-shop' ); ?>
				</th>
			</tr></tfoot>
			</table>
		</div> <!-- Wrap Ends /-->
		<?php
	}
endif;