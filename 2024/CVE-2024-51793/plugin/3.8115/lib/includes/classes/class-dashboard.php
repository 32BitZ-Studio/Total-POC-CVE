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

class WCRB_DASHBOARD {
	
	function output_main_page( $theSide ) {
		$output = '';
		if ( isset( $theSide ) && $theSide == 'front' ) {
			$output .= $this->section_front_navigation();
			$output .= $this->section_jobs_by_status( 'frontend' );
		} else {
			$output .= $this->section_navigation();
			$output .= $this->section_jobs_by_status( 'backend' );
		}

		return $output;
	} //Function prints the output

	function section_jobs_by_status( $state ) {
		global $wpdb;

		$stateCol = ( isset( $state ) && $state == 'frontend' ) ? 'large-4 medium-4 small-6' : 'large-3 medium-4 small-6';

		$image_output = '<img src="'. esc_url( WC_COMPUTER_REPAIR_DIR_URL . '/assets/admin/images/icons/jobs.png' ) .'" />';

		$output = '<div class="wcrb_dashboard_jobs_status wcrb_dashboard_section grid-x grid-margin-x grid-container fluid">';

		//Table
		$computer_repair_job_status = $wpdb->prefix.'wc_cr_job_status';

		$select_query 	= "SELECT * FROM `".$computer_repair_job_status."` WHERE `status_status`='active' ORDER BY `status_name` ASC";
		$select_results = $wpdb->get_results( $select_query );
		
		foreach($select_results as $result) {
			$status_label = $result->status_name;

			if ( $state == 'frontend' ) {
				//&job_status=planning
				$link = add_query_arg( 'job_status', $result->status_slug, get_permalink() );
				//$link = 'edit.php?s&post_status=all&post_type=rep_jobs&wc_job_status=' . $result->status_slug;
			} else {
				$link = 'edit.php?s&post_status=all&post_type=rep_jobs&wc_job_status=' . $result->status_slug;
			}
			$number_jobs  = wcrb_count_jobs_by_status( $result->status_slug, $state ) . ' ' . esc_html__( 'Jobs', 'computer-repair-shop' );

			$output .= '<div class="' . esc_attr( $stateCol ) . ' cell">';
			$output .= '<div class="wcrb_widget wcrb_widget-12 wcrb_has-shadow"><a href="' . esc_url( $link ) . '">';
			$output .= '<div class="wcrb_widget-body"><div class="wcrb_media"><div class="wcrb_align-self-center wcrb_ml-5 wcrb_mr-5">';
			$output .= $image_output;
			$output .= '</div>';
			$output .= '<div class="wcrb_media-body wcrb_align-self-center">';
			$output .= '<div class="wcrb_title">' . esc_html( $status_label ) . '</div>';
			$output .= '<div class="wcrb_number">' .esc_html( $number_jobs ) . '</div>';
			$output .= '</div></div></div></a></div></div>';
		} //End Foreach

		$output .= '</div>';

		return $output;		
	}

	function section_navigation() {
		$nav_items = array();

		$nav_items[] = array(
			'label' => esc_html__( 'Tickets', 'computer-repair-shop' ),
			'image' => 'jobs.png',
			'link'  => 'edit.php?post_type=rep_jobs',
		);
		$nav_items[] = array(
			'label' => esc_html__( 'Services', 'computer-repair-shop' ),
			'image' => 'services.png',
			'link'  => 'edit.php?post_type=rep_services',
		);
		if ( is_parts_switch_woo() === true ) {
			$nav_items[] = array(
				'label' => esc_html__( 'Products', 'computer-repair-shop' ),
				'image' => 'parts.png',
				'link'  => 'edit.php?post_type=product',
			);
		} else {
			$nav_items[] = array(
				'label' => esc_html__( 'Parts', 'computer-repair-shop' ),
				'image' => 'parts.png',
				'link'  => 'edit.php?post_type=rep_products',
			);
		}
		
		$wc_device_label = ( empty( get_option( 'wc_device_label_plural' ) ) ) ? esc_html__( 'Device', 'computer-repair-shop' ) : get_option( 'wc_device_label_plural' );
		$nav_items[] = array(
			'label' => $wc_device_label,
			'image' => 'devices.png',
			'link'  => 'edit.php?post_type=rep_devices',
		);

		$wc_manufactu_label = ( empty( get_option( 'wc_device_brand_label_plural' ) ) ) ? esc_html__( 'Brands', 'computer-repair-shop' ) : get_option( 'wc_device_brand_label_plural' );
		$nav_items[] = array(
			'label' => $wc_manufactu_label,
			'image' => 'manufacture.png',
			'link'  => 'edit-tags.php?taxonomy=device_brand&post_type=rep_devices',
		);
		$wc_type_label = ( empty( get_option( 'wc_device_type_label_plural' ) ) ) ? esc_html__( 'Types', 'computer-repair-shop' ) : get_option( 'wc_device_type_label_plural' );
		$nav_items[] = array(
			'label' => $wc_type_label,
			'image' => 'types.png',
			'link'  => 'edit-tags.php?taxonomy=device_type&post_type=rep_devices',
		);
		$nav_items[] = array(
			'label' => esc_html__( 'Customers', 'computer-repair-shop' ),
			'image' => 'clients.png',
			'link'  => 'admin.php?page=wc-computer-rep-shop-clients',
		);
		$nav_items[] = array(
			'label' => esc_html__( 'Technicians', 'computer-repair-shop' ),
			'image' => 'technicians.png',
			'link'  => 'admin.php?page=wc-computer-rep-shop-technicians',
		);
		$nav_items[] = array(
			'label' => esc_html__( 'Managers', 'computer-repair-shop' ),
			'image' => 'manager.png',
			'link'  => 'admin.php?page=wc-computer-rep-shop-managers',
		);
		$nav_items[] = array(
			'label' => esc_html__( 'Reports', 'computer-repair-shop' ),
			'image' => 'report.png',
			'link'  => 'admin.php?page=wc-computer-rep-reports',
		);

		$output = '<div class="wcrb_dashboard_nav wcrb_dashboard_section">';

		foreach( $nav_items as $nav_item ) {
			$output .= '<div class="wcrb_dan_item">';
			$output .= '<a href="'. esc_url( $nav_item['link'] ) .'">';
			$output .= '<img src="'. esc_url( WC_COMPUTER_REPAIR_DIR_URL . '/assets/admin/images/icons/' . $nav_item['image'] ) .'" />';
			$output .= '<h3>' . esc_html( $nav_item['label'] ) . '</h3>';
			$output .= '</a>';
			$output .= '</div>';
		}

		$output .= '</div>';

		return $output;
	}

	function section_front_navigation() {
		$nav_items = array();

		$nav_items[] = array(
			'label' => esc_html__( 'Tickets', 'computer-repair-shop' ),
			'image' => 'jobs.png',
			'link'  => add_query_arg( 'job_status', 'all', get_the_permalink() ),
		);
		
		$wc_device_label = ( empty( get_option( 'wc_device_label' ) ) ) ? esc_html__( 'Devices', 'computer-repair-shop' ) : get_option( 'wc_device_label' );
		$wc_device_label = esc_html__( 'Book', 'computer-repair-shop' ) . ' ' . $wc_device_label;

		if ( ! defined( 'RB_DIAG_DIESEL' ) ) :
		$nav_items[] = array(
			'label' => $wc_device_label,
			'image' => 'devices.png',
			'link'  => add_query_arg( 'book_device', 'yes', get_the_permalink() ),
		);
		endif;

		$output = '<div class="wcrb_dashboard_nav wcrb_dashboard_section">';

		foreach( $nav_items as $nav_item ) {
			$output .= '<div class="wcrb_dan_item">';
			$output .= '<a href="'. esc_url( $nav_item['link'] ) .'">';
			$output .= '<img src="'. esc_url( WC_COMPUTER_REPAIR_DIR_URL . '/assets/admin/images/icons/' . $nav_item['image'] ) .'" />';
			$output .= '<h3>' . esc_html( $nav_item['label'] ) . '</h3>';
			$output .= '</a>';
			$output .= '</div>';
		}

		$output .= '</div>';

		return $output;
	}
}