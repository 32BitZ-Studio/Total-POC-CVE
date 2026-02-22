<?php
defined( 'ABSPATH' ) || exit;
/**
 * RepairBuddy Admin Pages
 * Adds pages to backend
 *
 * @Since 1.0.0
 */
function wc_add_comp_rep_pages() {
	global $OBJ_MAINTENANCE_REMINDER;

	// main_sub Menu Page.
	$menu_name_p = get_option( 'menu_name_p' );

	if ( empty( $menu_name_p ) ) {
		$menu_name_p = esc_html__( 'Computer Repair', 'computer-repair-shop' );
	}

	add_menu_page( $menu_name_p, $menu_name_p, 'read', 'wc-computer-rep-shop-handle', 'wc_comp_repair_shop_main', plugins_url( 'assets/admin/images/computer-repair.png', __FILE__ ), '50' );

	//add_submenu_page( 'wc-computer-rep-shop-handle', __( 'Stores', 'computer-repair-shop' ), __( 'Stores', 'computer-repair-shop' ), 'manage_options' , 'edit.php?post_type=store' );

	add_submenu_page( 'wc-computer-rep-shop-handle', __( 'Repair Services', 'computer-repair-shop' ), __( 'Services', 'computer-repair-shop' ), 'edit_rep_job', 'edit.php?post_type=rep_services' );

	if ( is_parts_switch_woo() === true ) {
		add_submenu_page( 'wc-computer-rep-shop-handle', __( 'Products', 'computer-repair-shop' ), __( 'Products', 'computer-repair-shop' ), 'edit_posts', 'edit.php?post_type=product' );
	} else {
		add_submenu_page( 'wc-computer-rep-shop-handle', __( 'Parts', 'computer-repair-shop' ), __( 'Parts', 'computer-repair-shop' ), 'edit_rep_job', 'edit.php?post_type=rep_products' );
	}
	add_submenu_page( 'wc-computer-rep-shop-handle', __( 'Repair Jobs', 'computer-repair-shop' ), __( 'Jobs', 'computer-repair-shop' ), 'edit_rep_job', 'edit.php?post_type=rep_jobs' );

	add_submenu_page( 'edit.php?post_type=rep_jobs', __( 'Print Screen', 'computer-repair-shop' ), __( 'Print Screen', 'computer-repair-shop' ), 'edit_rep_job', 'wc_computer_repair_print', 'wc_computer_repair_print_functionality' );

	$wc_device_label              = ( empty( get_option( 'wc_device_label' ) ) ) ? esc_html__( 'Device', 'computer-repair-shop' ) : get_option( 'wc_device_label' );
	$wc_device_label_plural       = ( empty( get_option( 'wc_device_label_plural' ) ) ) ? esc_html__( 'Devices', 'computer-repair-shop' ) : get_option( 'wc_device_label_plural' );
	$wc_device_brand_label        = ( empty( get_option( 'wc_device_brand_label' ) ) ) ? esc_html__( 'Device Brand', 'computer-repair-shop' ) : get_option( 'wc_device_brand_label' );
	$wc_device_brand_label_plural = ( empty( get_option( 'wc_device_brand_label_plural' ) ) ) ? esc_html__( 'Device Brands', 'computer-repair-shop' ) : get_option( 'wc_device_brand_label_plural' );
	$wc_device_type_label_plural = ( empty( get_option( 'wc_device_type_label_plural' ) ) ) ? esc_html__( 'Device Types', 'computer-repair-shop' ) : get_option( 'wc_device_type_label_plural' );

	if ( wcrb_use_woo_as_devices() == 'NO' ) {
		add_submenu_page( 'wc-computer-rep-shop-handle', $wc_device_label_plural, $wc_device_label_plural, 'edit_rep_job', 'edit.php?post_type=rep_devices' );

		add_submenu_page( 'wc-computer-rep-shop-handle', $wc_device_brand_label_plural, $wc_device_brand_label_plural, 'manage_options', 'edit-tags.php?taxonomy=device_brand&post_type=rep_devices' );
		add_submenu_page( 'wc-computer-rep-shop-handle', $wc_device_type_label_plural, $wc_device_type_label_plural, 'manage_options', 'edit-tags.php?taxonomy=device_type&post_type=rep_devices' );
	}

	add_submenu_page( 'wc-computer-rep-shop-handle', __( 'Clients', 'computer-repair-shop' ), __( 'Clients', 'computer-repair-shop' ), 'delete_posts', 'wc-computer-rep-shop-clients', 'wc_comp_rep_shop_clients' );

	add_submenu_page( 'wc-computer-rep-shop-handle', __( 'Technicians', 'computer-repair-shop' ), __( 'Technicians', 'computer-repair-shop' ), 'delete_posts', 'wc-computer-rep-shop-technicians', 'wc_comp_rep_shop_technicians' );

	add_submenu_page( 'wc-computer-rep-shop-handle', __( 'Managers', 'computer-repair-shop' ), __( 'Managers', 'computer-repair-shop' ), 'manage_options', 'wc-computer-rep-shop-managers', 'wc_comp_rep_shop_store_manager' );

	add_submenu_page( 'wc-computer-rep-shop-handle', __( 'Reports', 'computer-repair-shop' ), __( 'Reports', 'computer-repair-shop' ), 'manage_options', 'wc-computer-rep-reports', 'wc_computer_rep_reports' );

	add_submenu_page( 'wc-computer-rep-shop-handle', __( 'Reminder Logs', 'computer-repair-shop' ), __( 'Reminder Logs', 'computer-repair-shop' ), 'manage_options', 'wcrb_reminder_logs', 'wcrb_display_reminder_logs' );

	global $WCRB_MANAGE_DEVICES;
	add_submenu_page( 'wc-computer-rep-shop-handle', __( 'Customer ', 'computer-repair-shop' ) . $wc_device_label_plural, __( 'Customer ', 'computer-repair-shop' ) . $wc_device_label_plural, 'manage_options', 'wcrb_customer_devices', array( $WCRB_MANAGE_DEVICES, 'backend_customer_devices_output' ) );
	
	add_submenu_page( 'wc-computer-rep-shop-handle', __( 'Payments', 'computer-repair-shop' ), __( 'Payments', 'computer-repair-shop' ), 'delete_posts', 'wc-computer-rep-shop-payments', 'wc_comp_rep_shop_payments' );
}
add_action( 'admin_menu', 'wc_add_comp_rep_pages' );
