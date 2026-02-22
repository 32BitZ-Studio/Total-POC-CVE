<?php
if ( ! defined( 'ABSPATH' ) ) { 
	exit;
}
if ( ! function_exists( 'wc_computer_repair_shop_default_status_data' ) ):
	/***
	 * Default Status Data
	 * Being used in both updated.php and active.php
	 */
	function wc_computer_repair_shop_default_status_data() {
		global $wpdb;

		/**
		 * Job Default Status Feature
		 * Default Data
		 *
		 * @Since 3.1
		 */
		$computer_repair_job_status = $wpdb->prefix . 'wc_cr_job_status';

		$result = $wpdb->get_results("SELECT `status_id` from `".$computer_repair_job_status."` WHERE `status_id` IS NOT NULL");
		
		if(count($result) == 0) {
			$order_status = array(
				"new" 				=> esc_html__("New Order", "computer-repair-shop"),
				"quote" 			=> esc_html__("Quote", "computer-repair-shop"),
				"cancelled" 		=> esc_html__("Cancelled", "computer-repair-shop"),
				"inprocess" 		=> esc_html__("In Process", "computer-repair-shop"),
				"inservice" 		=> esc_html__("In Service", "computer-repair-shop"),
				"ready_complete" 	=> esc_html__("Ready/Complete", "computer-repair-shop"),
				"delivered"			=> esc_html__("Delivered", "computer-repair-shop")	
			);

			foreach( $order_status as $key=>$value ) {
				$wpdb->insert( 
					$computer_repair_job_status, 
					array( 
						'status_id' 			=> "", 
						'status_name' 			=> $value, 
						'status_slug' 			=> $key,
						'status_description' 	=> "",
						'invoice_label' 		=> "Invoice",
						'inventory_count'		=> "",
						'status_status' 		=> "active",
					)
				);
			}
		}
	}
endif;

if ( ! function_exists( 'wc_rb_create_default_pages' ) ) {
	function wc_rb_create_default_pages() {
		//Check if pages are setup
		$pages_setup_status = get_option( 'wc_rb_setup_pages_once' );

		if ( $pages_setup_status == 'YES' ) {
			return '';
		}

		if ( empty( get_option( 'wc_rb_status_check_page_id' ) ) ) {
			//Setup Status Check page.
			$theReturnId = $page_args = '';
			$page_args = array(
				'post_title'    => esc_html__( 'Job Status', 'computer-repair-shop' ),
				'post_content'  => '[wc_order_status_form]',
				'post_status'   => 'publish',
				'post_author'   => 1,
				'post_type'     => 'page',
			);
			// Insert the post into the database
			$theReturnId = wp_insert_post( $page_args );

			update_option( 'wc_rb_status_check_page_id', $theReturnId );
		}

		if ( empty( get_option( 'wc_rb_get_feedback_page_id' ) ) ) {
			//Setup Status Check page.
			$theReturnId = $page_args = '';
			$page_args = array(
				'post_title'    => esc_html__( 'Review Your Job', 'computer-repair-shop' ),
				'post_content'  => '[wc_get_order_feedback]',
				'post_status'   => 'publish',
				'post_author'   => 1,
				'post_type'     => 'page',
			);
			// Insert the post into the database
			$theReturnId = wp_insert_post( $page_args );

			update_option( 'wc_rb_get_feedback_page_id', $theReturnId );
		}

		if ( empty( get_option( 'wc_rb_device_booking_page_id' ) ) ) {
			//Setup booking page.
			$theReturnId = $page_args = '';
			$page_args = array(
				'post_title'    => esc_html__( 'Book Device', 'computer-repair-shop' ),
				'post_content'  => '[wc_book_my_service]',
				'post_status'   => 'publish',
				'post_author'   => 1,
				'post_type'     => 'page',
			);
			// Insert the post into the database
			$theReturnId = wp_insert_post( $page_args );

			update_option( 'wc_rb_device_booking_page_id', $theReturnId );

		}

		if ( empty( get_option( 'wc_rb_my_account_page_id' ) ) ) {
			//Setup my account page.
			$theReturnId = $page_args = '';
			$page_args = array(
				'post_title'    => esc_html__( 'My Account', 'computer-repair-shop' ),
				'post_content'  => '[wc_cr_my_account]',
				'post_status'   => 'publish',
				'post_author'   => 1,
				'post_type'     => 'page',
			);
			// Insert the post into the database
			$theReturnId = wp_insert_post( $page_args );

			update_option( 'wc_rb_my_account_page_id', $theReturnId );
			update_option( 'wc_rb_customer_login_page', $theReturnId );
		}

		if ( empty( get_option( 'wc_rb_list_services_page_id' ) ) ) {
			//Setup services.
			$theReturnId = $page_args = '';
			$page_args = array(
				'post_title'    => esc_html__( 'Our Services', 'computer-repair-shop' ),
				'post_content'  => '[wc_list_services]',
				'post_status'   => 'publish',
				'post_author'   => 1,
				'post_type'     => 'page',
			);
			// Insert the post into the database
			$theReturnId = wp_insert_post( $page_args );

			update_option( 'wc_rb_list_services_page_id', $theReturnId );
		}

		if ( empty( get_option( 'wc_rb_list_parts_page_id' ) ) ) {
			//Products setp.
			$theReturnId = $page_args = '';
			$page_args = array(
				'post_title'    => esc_html__( 'Parts', 'computer-repair-shop' ),
				'post_content'  => '[wc_list_products]',
				'post_status'   => 'publish',
				'post_author'   => 1,
				'post_type'     => 'page',
			);
			// Insert the post into the database
			$theReturnId = wp_insert_post( $page_args );

			update_option( 'wc_rb_list_parts_page_id', $theReturnId );
		}

		update_option( 'wc_rb_setup_pages_once', 'YES' );
	}
}

if ( ! function_exists( 'wc_computer_repair_shop_default_payment_data' ) ):
	/***
	 * Default Payment Methods
	 * Being used in both updated.php and active.php
	 */
	function wc_computer_repair_shop_default_payment_data() {
		global $wpdb;

		/**
		 * Job Default Payment Statuses
		 * Default Data
		 *
		 * @Since 3.7946
		 */
		$computer_repair_payment_status = $wpdb->prefix.'wc_cr_payment_status';

		$result = $wpdb->get_results("SELECT `status_id` from `".$computer_repair_payment_status."` WHERE `status_id` IS NOT NULL");

		if(count($result) == 0) {
			$payment_status = array(
				'nostatus' 	    => esc_html__( 'No Status', 'computer-repair-shop' ),
				'credit' 	    => esc_html__( 'Credit', 'computer-repair-shop' ),
				'paid' 		    => esc_html__( 'Paid', 'computer-repair-shop' ),
				'partial' 	    => esc_html__( 'Partially Paid', 'computer-repair-shop' ),
			);

			foreach( $payment_status as $key=>$value ) {
				$wpdb->insert( 
					$computer_repair_payment_status, 
					array( 
						'status_id' 			=> "", 
						'status_name' 			=> $value, 
						'status_slug' 			=> $key,
						'status_description' 	=> "",
						'status_status' 		=> "active",
					)
				);
			}
		}
	}
endif;



	//Installation of plugin starts here.
	function wc_computer_repair_shop_install() {
		//Installs default values on activation.
		global $wpdb;
		require_once( ABSPATH .'wp-admin/includes/upgrade.php' );
		
		$charset_collate = $wpdb->get_charset_collate();

		update_option('offer_pic_de', 'on');
		
		update_option("wc_cr_shop_version", WC_CR_SHOP_VERSION);
		
		$payment_methods = get_option( 'wc_rb_payment_methods_active' );
		if ( empty ( $payment_methods ) ) {
			$default_methods = array( 'cash', 'bank-transfer', 'check', 'card-swipe', 'mobile-payment' );
			update_option( 'wc_rb_payment_methods_active', serialize( $default_methods ) );
		}

		/*
			Add User Role
			
			@Role Customer
			
			@Since 1.0.0
		*/
		$wc_role_existance = wc_get_role("customer");
		
		if($wc_role_existance == null) {
			add_role(
				'customer', 
				esc_html__('Customer', 'computer-repair-shop'), 
				array( 'read' => true, 'edit_posts' => false ) 
			);
		}

		$wc_role_existance = wc_get_role("technician");
		
		if($wc_role_existance == null) {
			add_role(
				'technician', 
				esc_html__('Technician', 'computer-repair-shop'), 
				array( 'read' => true, 'edit_posts' => true, 'delete_posts' => false ) 
			);
		}

		$wc_role_existance = wc_get_role("store_manager");
		
		if($wc_role_existance == null) {
			add_role(
				'store_manager', 
				esc_html__('Store Manager', 'computer-repair-shop'), 
				array( 'read' => true, 'edit_posts' => true, 'delete_posts' => true ) 
			);
		}
	
		
		/**
		 * Add Tables required
		 *
		 * @Since 2.0
		 */
		$computer_repair_items 			  = $wpdb->prefix.'wc_cr_order_items';
		$computer_repair_items_meta 	  = $wpdb->prefix.'wc_cr_order_itemmeta';
		$computer_repair_taxes 			  = $wpdb->prefix.'wc_cr_taxes';
		$computer_repair_job_status 	  = $wpdb->prefix.'wc_cr_job_status';
		$computer_repair_payment_status   = $wpdb->prefix.'wc_cr_payment_status';
		$computer_repair_history 		  = $wpdb->prefix.'wc_cr_job_history';
		$computer_repair_payments 		  = $wpdb->prefix.'wc_cr_payments';
		$computer_repair_maint_reminders  = $wpdb->prefix.'wc_cr_maint_reminders';
		$computer_repair_reminder_logs    = $wpdb->prefix.'wc_cr_reminder_logs';
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
			`invoice_label` varchar(20) NOT NULL,
			`inventory_count` varchar(100) NOT NULL,
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


		wc_capability_store_manager();

		wc_computer_repair_shop_default_status_data();
		wc_computer_repair_shop_default_payment_data();
	}//end of function wc_restaurant_install()
	//'rep_devices', 'rep_device'
	//'rep_services', 'rep_service'
	//'rep_products', 'rep_product'
	if(!function_exists("wc_capability_store_manager")):
		function wc_capability_store_manager() {
	
			// Add the roles you'd like to administer the custom post types
			$roles = array('store_manager','editor','administrator', 'technician', 'customer');
			
			// Loop through each role and assign capabilities
			foreach($roles as $the_role) { 
	
				$role = get_role($the_role);

				$role->add_cap( 'read' );

				if($the_role == "store_manager") {
					//Repair Jobs
					$role->add_cap("show_service_menu");
					$rep_jobs_cap = wc_store_manager_capabilities("rep_job", "rep_jobs");
					
					foreach($rep_jobs_cap as $capability_type) {
						$role->add_cap( $capability_type );	
					}

					//Devices
					$rep_devices_cap = wc_store_manager_capabilities("rep_device", "rep_devices");
					
					foreach($rep_devices_cap as $capability_type) {
						$role->add_cap( $capability_type );	
					}

					//Services
					$rep_services_cap = wc_store_manager_capabilities("repair_service", "repair_services");

					foreach($rep_services_cap as $capability_type) {
						$role->add_cap( $capability_type );	
					}

					//Parts
					$rep_parts_cap = wc_store_manager_capabilities("rep_product", "rep_products");

					foreach($rep_parts_cap as $capability_type) {
						$role->add_cap( $capability_type );	
					}
				}

				if($the_role == "technician") {
					$role->add_cap("show_service_menu");
					//Repair Jobs
					$rep_jobs_cap = wc_technician_capabilities("rep_job", "rep_jobs");
					
					foreach($rep_jobs_cap as $capability_type) {
						$role->add_cap( $capability_type );	
					}

					//Devices
					$rep_devices_cap = wc_technician_capabilities("rep_device", "rep_devices");
					
					foreach($rep_devices_cap as $capability_type) {
						$role->add_cap( $capability_type );	
					}

					//Services
					$rep_services_cap = wc_technician_capabilities("repair_service", "repair_services");

					foreach($rep_services_cap as $capability_type) {
						$role->add_cap( $capability_type );	
					}

					//Parts
					$rep_parts_cap = wc_technician_capabilities("rep_product", "rep_products");

					foreach($rep_parts_cap as $capability_type) {
						$role->add_cap( $capability_type );	
					}
				}

				if($the_role == "customer") {
					//Repair Jobs
					$rep_jobs_cap = wc_customer_capabilities("rep_job", "rep_jobs");
					
					foreach($rep_jobs_cap as $capability_type) {
						$role->add_cap( $capability_type );	
					}

					//Devices
					$rep_devices_cap = wc_customer_capabilities("rep_device", "rep_devices");
					
					foreach($rep_devices_cap as $capability_type) {
						$role->add_cap( $capability_type );	
					}

					//Services
					$rep_services_cap = wc_customer_capabilities("repair_service", "repair_services");

					foreach($rep_services_cap as $capability_type) {
						$role->add_cap( $capability_type );	
					}

					//Parts
					$rep_parts_cap = wc_customer_capabilities("rep_product", "rep_products");

					foreach($rep_parts_cap as $capability_type) {
						$role->add_cap( $capability_type );	
					}
				}

				if($the_role == "administrator" || $the_role == "editor"):
					$role->add_cap("show_service_menu");
					//Repair Jobs
					$rep_jobs_cap = wc_admin_capabilities("rep_job", "rep_jobs");
					
					foreach($rep_jobs_cap as $capability_type) {
						$role->add_cap( $capability_type );	
					}

					//Devices
					$rep_devices_cap = wc_admin_capabilities("rep_device", "rep_devices");
					
					foreach($rep_devices_cap as $capability_type) {
						$role->add_cap( $capability_type );	
					}

					//Services
					$rep_services_cap = wc_admin_capabilities("repair_service", "repair_services");

					foreach($rep_services_cap as $capability_type) {
						$role->add_cap( $capability_type );	
					}

					//Parts
					$rep_parts_cap = wc_admin_capabilities("rep_product", "rep_products");

					foreach($rep_parts_cap as $capability_type) {
						$role->add_cap( $capability_type );	
					}
				endif;
			}
		}
	endif;	

	if(!function_exists("wc_admin_capabilities")): 
		function wc_admin_capabilities($singular = 'post', $plural = 'posts') {
			return [
				'edit_post'      		=> "edit_$singular",
				'read_post'      		=> "read_$singular",
				'delete_post'        	=> "delete_$singular",
				'edit_posts'         	=> "edit_$plural",
				'edit_others_posts'  	=> "edit_others_$plural",
				'publish_posts'      	=> "publish_$plural",
				'read_private_posts'     => "read_private_$plural",
				'delete_posts'           => "delete_$plural",
				'delete_private_posts'   => "delete_private_$plural",
				'delete_published_posts' => "delete_published_$plural",
				'delete_others_posts'    => "delete_others_$plural",
				'edit_private_posts'     => "edit_private_$plural",
				'edit_published_posts'   => "edit_published_$plural",
				'create_posts'           => "edit_$plural",
			];
		}
	endif;	

	if(!function_exists("wc_technician_capabilities")):
		function wc_technician_capabilities($singular = 'post', $plural = 'posts') {
			return [
				'edit_post'      		=> "edit_$singular",
				'read_post'      		=> "read_$singular",
				'edit_posts'         	=> "edit_$plural",
				'edit_others_posts'  	=> "edit_others_$plural",
				'publish_posts'      	=> "publish_$plural",
				'read_private_posts'     => "read_private_$plural",
				'edit_private_posts'     => "edit_private_$plural",
				'edit_published_posts'   => "edit_published_$plural",
				'create_posts'           => "edit_$plural",
			];
		}
	endif;

	if(!function_exists("wc_store_manager_capabilities")):
		function wc_store_manager_capabilities($singular = 'post', $plural = 'posts') {
			return [
				'edit_post'      		=> "edit_$singular",
				'read_post'      		=> "read_$singular",
				'edit_posts'         	=> "edit_$plural",
				'edit_others_posts'  	=> "edit_others_$plural",
				'publish_posts'      	=> "publish_$plural",
				'read_private_posts'     => "read_private_$plural",
				'edit_private_posts'     => "edit_private_$plural",
				'edit_published_posts'   => "edit_published_$plural",
				'create_posts'           => "edit_$plural",
			];
		}
	endif;

	if ( ! function_exists( 'wc_customer_capabilities' ) ) :
		function wc_customer_capabilities( $singular = 'post', $plural = 'posts' ) {
			return [
				'read_post' => "read_$singular"
			];
		}
	endif;