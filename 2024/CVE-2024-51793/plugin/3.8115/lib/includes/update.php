<?php
if ( ! defined( 'ABSPATH' ) ) { 
	exit;
}

	$current_plugin_version = get_option( 'wc_cr_shop_version' );

	$pages_setup_status = get_option( 'wc_rb_setup_pages_once' );

	if ( $pages_setup_status != 'YES' ) {
		wc_rb_create_default_pages();
	}

	//Installation of plugin starts here.
	if ( ! function_exists( "wc_computer_repair_shop_update" ) ) :
		function wc_computer_repair_shop_update() {
			//Installs default values on activation.
			global $wpdb;
			require_once( ABSPATH .'wp-admin/includes/upgrade.php' );
			
			$charset_collate = $wpdb->get_charset_collate();

			$computer_repair_items 			 = $wpdb->prefix.'wc_cr_order_items';
			$computer_repair_items_meta 	 = $wpdb->prefix.'wc_cr_order_itemmeta';
			$computer_repair_taxes 			 = $wpdb->prefix.'wc_cr_taxes';
			$computer_repair_job_status 	 = $wpdb->prefix.'wc_cr_job_status';
			$computer_repair_payment_status  = $wpdb->prefix.'wc_cr_payment_status';
			$computer_repair_history 		 = $wpdb->prefix.'wc_cr_job_history';
			$computer_repair_payments 		 = $wpdb->prefix.'wc_cr_payments';
			$computer_repair_maint_reminders = $wpdb->prefix.'wc_cr_maint_reminders';
			$computer_repair_reminder_logs   = $wpdb->prefix.'wc_cr_reminder_logs';
			$computer_repair_customer_devices = $wpdb->prefix.'wc_cr_customer_devices';
			$computer_repair_feedback_log 	  = $wpdb->prefix.'wc_cr_feedback_log';
						
			$sql = 'CREATE TABLE IF NOT EXISTS '.$computer_repair_customer_devices.'(
				`device_id` bigint(20) NOT NULL AUTO_INCREMENT,
				`device_post_id` bigint(20) NULL,
				`device_label` varchar(600) NOT NULL,
				`serial_nuumber` varchar(200) NOT NULL,
				`pint_code` varchar(200) NOT NULL,
				`customer_id` bigint(20) NULL,
				PRIMARY KEY (`device_id`)
			) '.$charset_collate.';';	
			dbDelta($sql);
	
			$sql = 'CREATE TABLE IF NOT EXISTS '.$computer_repair_reminder_logs.'(
				`log_id` bigint(20) NOT NULL AUTO_INCREMENT,
				`datetime` datetime NULL,
				  `customer_id` bigint(20) NULL,
				`job_id` bigint(20) NULL,
				`reminder_id` bigint(20) NULL,
				`email_to` varchar(200) NOT NULL,
				`sms_to` varchar(200) NOT NULL,
				`status` varchar(200) NOT NULL,
				  PRIMARY KEY (`log_id`)
			) '.$charset_collate.';';	
			dbDelta($sql);

			$sql = 'CREATE TABLE IF NOT EXISTS '.$computer_repair_feedback_log.'(
				`log_id` bigint(20) NOT NULL AUTO_INCREMENT,
				`datetime` datetime NULL,
				`job_id` bigint(20) NULL,
				`email_to` varchar(200) NOT NULL,
				`sms_to` varchar(200) NOT NULL,
				`type` varchar(200) NOT NULL,
				`action` varchar(200) NOT NULL,
				  PRIMARY KEY (`log_id`)
			) '.$charset_collate.';';	
			dbDelta($sql);
	
			$sql = 'CREATE TABLE IF NOT EXISTS '.$computer_repair_maint_reminders.'(
				`reminder_id` bigint(20) NOT NULL AUTO_INCREMENT,
				`datetime` datetime NULL,
				  `name` varchar(500) NULL,
				`description` longtext NULL,
				`interval` varchar(200) NOT NULL,
				`email_body` longtext NULL,
				`sms_body` longtext NULL,
				`device_type` varchar(200) NOT NULL,
				`device_brand` varchar(200) NOT NULL,
				`email_status` varchar(200) NOT NULL,
				`sms_status` varchar(200) NOT NULL,
				`reminder_status` varchar(200) NOT NULL,
				`last_execution` datetime NULL,
				  PRIMARY KEY (`reminder_id`)
			) '.$charset_collate.';';	
			dbDelta($sql);
	
			$sql = 'CREATE TABLE IF NOT EXISTS '.$computer_repair_payments.'(
				`payment_id` bigint(20) NOT NULL AUTO_INCREMENT,
				`date` datetime NULL,
				  `order_id` bigint(20) NOT NULL,
				`receiver_id` bigint(20) NULL,
				`method` varchar(50) NULL,
				`identifier` longtext NULL,
				`payment_status` varchar(50) NOT NULL,
				`note` longtext NULL,
				`amount` double NULL,
				`discount` double NULL,
				`status` varchar(50) NULL,
				`woo_orders` longtext NULL,
				  PRIMARY KEY (`payment_id`)
			) '.$charset_collate.';';	
			dbDelta($sql);
			
			$sql = 'CREATE TABLE IF NOT EXISTS '.$computer_repair_items.'(
				`order_item_id` bigint(20) NOT NULL AUTO_INCREMENT,
				`order_item_name` varchar(100) NOT NULL,
				  `order_item_type` varchar(50) NOT NULL,
				`order_id` bigint(20) NOT NULL,
				  PRIMARY KEY (`order_item_id`)
			) '.$charset_collate.';';	
			dbDelta($sql);
			
			
			$sql = 'CREATE TABLE IF NOT EXISTS '.$computer_repair_items_meta.'(
				`meta_id` bigint(20) NOT NULL AUTO_INCREMENT,
				`order_item_id` bigint(20) NOT NULL,
				  `meta_key` varchar(250) NOT NULL,
				`meta_value` longtext NOT NULL,
				  PRIMARY KEY (`meta_id`),
				FOREIGN KEY (order_item_id) REFERENCES '.$computer_repair_items.'(order_item_id)
			) '.$charset_collate.';';	
			dbDelta($sql);
	
			/*
				@Since 2.5
	
				Reactivate the Plugin required
			*/
			$sql = 'CREATE TABLE IF NOT EXISTS '.$computer_repair_taxes.'(
				`tax_id` bigint(20) NOT NULL AUTO_INCREMENT,
				`tax_name` varchar(250) NOT NULL,
				`tax_description` varchar(250) NOT NULL,
				`tax_rate` varchar(50) NOT NULL,
				`tax_status` varchar(20) NOT NULL,
				PRIMARY KEY (`tax_id`)
			) '.$charset_collate.';';	
			dbDelta($sql);
	
	
			/*
				@Since 3.1
	
				Reactivate the Plugin required
			*/
			$sql = 'CREATE TABLE IF NOT EXISTS '.$computer_repair_job_status.'(
				`status_id` bigint(20) NOT NULL AUTO_INCREMENT,
				`status_name` varchar(250) NOT NULL,
				`status_slug` varchar(250) NOT NULL,
				`status_description` varchar(250) NOT NULL,
				`status_email_message` varchar(600) NOT NULL,
				`invoice_label` varchar(100) NOT NULL,
				`inventory_count` varchar(20) NOT NULL,
				`status_status` varchar(20) NOT NULL,
				PRIMARY KEY (`status_id`)
			) '.$charset_collate.';';	
			dbDelta($sql);
	
			/*
				@Since 3.7946
	
				Reactivate the Plugin required
			*/
			$sql = 'CREATE TABLE IF NOT EXISTS '.$computer_repair_payment_status.'(
				`status_id` bigint(20) NOT NULL AUTO_INCREMENT,
				`status_name` varchar(250) NOT NULL,
				`status_slug` varchar(250) NOT NULL,
				`status_description` varchar(250) NOT NULL,
				`status_email_message` varchar(600) NOT NULL,
				`status_status` varchar(20) NOT NULL,
				PRIMARY KEY (`status_id`)
			) '.$charset_collate.';';	
			dbDelta($sql);
			
			/*
				@Since 3.59
	
				Reactivate the Plugin
			*/
			$sql = 'CREATE TABLE IF NOT EXISTS '.$computer_repair_history.'(
				`history_id` 	bigint(20) NOT NULL AUTO_INCREMENT,
				`datetime`		datetime NULL,
				`job_id`		bigint(20) NULL,
				`name`			varchar(600) NULL,
				`type`			varchar(50) NULL,
				`field`			varchar(50) NULL,
				`change_detail`	longtext NULL,
				`user_id`		bigint(20) NULL,
				PRIMARY KEY (`history_id`)
			) '.$charset_collate.';';	
			dbDelta($sql);



			$row = $wpdb->get_results(  "SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS
				WHERE `TABLE_NAME` = '".$computer_repair_job_status."' AND `COLUMN_NAME` = 'inventory_count'" );

			if(empty($row)){
				$wpdb->query("ALTER TABLE `".$computer_repair_job_status."` ADD `inventory_count` varchar(20) NOT NULL AFTER `status_description`");
			}

			$row = $wpdb->get_results(  "SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS
				WHERE `TABLE_NAME` = '".$computer_repair_job_status."' AND `COLUMN_NAME` = 'status_email_message'" );

			if(empty($row)){
				$wpdb->query("ALTER TABLE `".$computer_repair_job_status."` ADD `status_email_message` varchar(600) NOT NULL AFTER `status_description`");
			}

			$row = $wpdb->get_results(  "SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS
				WHERE `TABLE_NAME` = '".$computer_repair_job_status."' AND `COLUMN_NAME` = 'invoice_label'" );

			if(empty($row)){
				$wpdb->query("ALTER TABLE `".$computer_repair_job_status."` ADD `invoice_label` varchar(100) NOT NULL AFTER `status_email_message`");
			}

			$payment_methods = get_option( 'wc_rb_payment_methods_active' );
			if ( empty ( $payment_methods ) ) {
				$default_methods = array( 'cash', 'bank-transfer', 'check', 'card-swipe', 'mobile-payment' );
				update_option( 'wc_rb_payment_methods_active', serialize( $default_methods ) );
			}

			//Declared in active.php
			wc_computer_repair_shop_default_status_data();
			wc_computer_repair_shop_default_payment_data();
			wcrb_update_customers_meta();
			wc_rs_verify_purchase( '', '' );
			wcrb_update_shipping_address_customers();
			
			update_option( "wc_cr_shop_version", WC_CR_SHOP_VERSION );
		}//end of function wc_restaurant_install()
	endif;	

	if ( ! function_exists( 'wcrb_update_customers_meta' ) ) :
		function wcrb_update_customers_meta() {
			$customersUpdated 	= get_option( 'customersUpdated' );

			if ( $customersUpdated != 'YES' ) {
				//Let's update customers data.
				$role_query = new WP_User_Query( array( 'role__in' => array( 'customer', 'technician', 'store_manager' ) ) );

				foreach ( $role_query->get_results() as $userdata ) {
					$phone_number 	= get_user_meta( $userdata->ID, "customer_phone", true );
					update_user_meta( $userdata->ID, 'billing_phone', $phone_number );

					$company 		= get_user_meta( $userdata->ID, "company", true );
					update_user_meta( $userdata->ID, 'billing_company', $company );

					$address 		= get_user_meta( $userdata->ID, "customer_address", true );
					update_user_meta( $userdata->ID, 'billing_address_1', $address );

					$city 			= get_user_meta( $userdata->ID, "customer_city", true );
					update_user_meta( $userdata->ID, 'billing_city', $city );

					$zip_code 		= get_user_meta( $userdata->ID, "zip_code", true );
					update_user_meta( $userdata->ID, 'billing_postcode', $zip_code );

					$state_province = get_user_meta( $userdata->ID, "state_province", true );
					update_user_meta( $userdata->ID, 'billing_state', $state_province );

					$country 		= get_user_meta( $userdata->ID, "country", true );
					update_user_meta( $userdata->ID, 'billing_country', $country );
				}//EndForeach.
				update_option( 'customersUpdated', 'YES' );
			}
		}
	endif;

	if ( ! function_exists( 'wcrb_update_shipping_address_customers' ) ) :
		function wcrb_update_shipping_address_customers() {
			$shippingUpdated 	= get_option( 'shippingupdated' );
			$customersUpdated 	= get_option( 'customersUpdated' );

			if ( $customersUpdated == 'YES' && $shippingUpdated != 'YES' ) {
				//Let's update customers data.
				$role_query = new WP_User_Query( array( 'role__in' => array( 'customer', 'technician', 'store_manager' ) ) );

				foreach ( $role_query->get_results() as $userdata ) {
					$first_name   = get_user_meta( $userdata->ID, 'billing_first_name', true );
					$last_name    = get_user_meta( $userdata->ID, 'billing_last_name', true );
					$user_company = get_user_meta( $userdata->ID, 'billing_company', true );
					$user_address = get_user_meta( $userdata->ID, 'billing_address_1', true );
					$user_city    = get_user_meta( $userdata->ID, 'billing_city', true );
					$postal_code  = get_user_meta( $userdata->ID, 'billing_postcode', true );
					$phone_number = get_user_meta( $userdata->ID, 'billing_phone', true );
					$billing_tax  = get_user_meta( $userdata->ID, 'billing_tax', true );
					$userState    = get_user_meta( $userdata->ID, 'billing_state', true );
					$userCountry  = get_user_meta( $userdata->ID, 'billing_country', true );

					update_user_meta( $userdata->ID, 'billing_email', $userdata->email );

					update_user_meta( $userdata->ID, 'shipping_first_name', $first_name );
					update_user_meta( $userdata->ID, 'shipping_last_name', $last_name );
					update_user_meta( $userdata->ID, 'shipping_company', $user_company );
					update_user_meta( $userdata->ID, 'shipping_tax', $billing_tax );
					update_user_meta( $userdata->ID, 'shipping_address_1', $user_address );
					update_user_meta( $userdata->ID, 'shipping_city', $user_city );
					update_user_meta( $userdata->ID, 'shipping_postcode', $postal_code );
					update_user_meta( $userdata->ID, 'shipping_state', $userState );
					update_user_meta( $userdata->ID, 'shipping_country', $userCountry );
					update_user_meta( $userdata->ID, 'shipping_phone', $phone_number );


				}//EndForeach.
				update_option( 'shippingupdated', 'YES' ); 
			}
		}
	endif;

	/*
		check Update status and run functions
	*/
	if ( ! empty( $current_plugin_version ) && $current_plugin_version != WC_CR_SHOP_VERSION ) {
		add_action( 'plugins_loaded', 'wc_computer_repair_shop_update' );
	}