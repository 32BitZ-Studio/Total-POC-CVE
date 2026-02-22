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

class WCRB_SERVICES {

	function __construct() {
		add_action( 'wp_ajax_wc_add_service_for_fly', array( $this, 'wc_add_service_for_fly' ) );
    }

	function wc_add_service_for_fly() {
		$message = '';
		$service_id = '';
		$success = 'NO';

		$service_serviceName = ( isset( $_POST['service_serviceName'] ) ) ? sanitize_text_field( $_POST['service_serviceName'] ) : '';
		$service_serviceType = ( isset( $_POST['service_serviceType'] ) ) ? sanitize_text_field( $_POST['service_serviceType'] ) : '';
		$service_ServiceCode = ( isset( $_POST['service_ServiceCode'] ) ) ? sanitize_text_field( $_POST['service_ServiceCode'] ) : '';
		$service_cost 		 = ( isset( $_POST['service_cost'] ) ) ? sanitize_text_field( $_POST['service_cost'] ) : '';

		if ( empty ( $service_serviceName ) || empty( $service_cost ) ) {
			$message = esc_html__( 'Service name and service cost are required fields.', 'computer-repair-shop' );
		} else {
			//Check device status
			$curr = post_exists( $service_serviceName,'','','rep_services' );

			if ( $curr == '0' ) {
				//Post didn't exist let's add 
				$post_data = array(
					'post_title'    => $service_serviceName,
					'post_status'   => 'publish',
					'post_type' 	=> 'rep_services',
				);
				$post_id = wp_insert_post( $post_data );

				if ( ! empty( $service_serviceType ) ) {
					$tag = array( $service_serviceType );
					wp_set_post_terms( $post_id, $tag, 'service_type' );
				}
				update_post_meta( $post_id, '_service_code', $service_ServiceCode );
				update_post_meta( $post_id, '_cost', $service_cost );

				$service_id = $post_id;
				$message = esc_html__( 'Service Added to add featured image, warranty and other information go to services.', 'computer-repair-shop' );
			} else {
				$service_id = $curr;
				$message = esc_html__( 'Service with same name already exists', 'computer-repair-shop' );
			}
		}
		$values['message'] = $message;
		$values['service_id'] = $service_id;
		$values['success'] = $success;

		wp_send_json( $values );
		wp_die();
	}

	/**
	 * Parts Brands Options
	 * Return options
	 * Outputs selected options
	 */
	function generate_servicetype_select_options( $selected_type ) {
		$selected_type = ( ! empty( $selected_type ) ) ? $selected_type : '';

		$wcrb_type = 'rep_services';
		$wcrb_tax  = 'service_type';

		$cat_terms = get_terms(
			array(
					'taxonomy'		=> $wcrb_tax,
					'hide_empty'    => false,
					'orderby'       => 'name',
					'order'         => 'ASC',
					'number'        => 0
				)
		);

		$output = "<option value='All'>" . esc_html__( 'Select Service Type', 'computer-repair-shop' ) . "</option>";

		if( $cat_terms ) :
			foreach( $cat_terms as $term ) :
				$selected = ( $term->term_id == $selected_type ) ? ' selected' : '';
				$output .= '<option ' . $selected . ' value="' . esc_html( $term->term_id ) . '">';
				$output .= $term->name;
				$output .= '</option>';

			endforeach;
		endif;

		return $output;
	}

	function add_services_reveal_form() {
		$output = '<div class="small reveal" id="serviceFormReveal" data-reveal>';

		$output .= '<h2>' . esc_html__( 'Add a new service', 'computer-repair-shop' ) . '</h2>';
		$output .= '<div class="service-form-message"></div>';

		$output .= '<form data-async data-abide data-success-class=".service-form-message" class="needs-validation" novalidate method="post">';
		
		$output .= '<div class="grid-x grid-margin-x">';
		
		$output .= '<div class="cell medium-6">
						<label>' . esc_html__( 'Service Name', 'computer-repair-shop' ) . '*
							<input name="service_serviceName" type="text" class="form-control login-field"
								   value="" required id="service_serviceName"/>
						</label>
					</div>';
	
		$output .= '<div class="cell medium-6">
					<label class="have-addition">' . esc_html__( 'Select Type', 'computer-repair-shop' );
		$output .= '<select name="service_serviceType">';
		$output .= $this->generate_servicetype_select_options( '' );
		$output .= '</select>';
		$output .= '<a href="edit-tags.php?taxonomy=service_type&post_type=rep_services" target="_blank" class="button button-primary button-small" title="' . esc_html__( 'Add Service Type', 'computer-repair-shop' ) . '"><span class="dashicons dashicons-plus"></span></a>';
		$output .= '</label>
					</div>';			

		$output .= '</div>';

		$output .= '<div class="grid-x grid-margin-x">';
		$output .= '<div class="cell medium-6">
						<label>' . esc_html__( 'Service Code', 'computer-repair-shop' ) . '
							<input name="service_ServiceCode" type="text" class="form-control login-field"
								   value="" id="service_ServiceCode"/>
						</label></div>';
	
		$output .= '<div class="cell medium-6">
					<label>' . esc_html__( 'Service Cost', 'computer-repair-shop' ) . '*
						<input name="service_cost" type="number" class="form-control login-field"
								value="" required id="service_cost"/>
					</label></div>';
		$output .= '</div>';

		$output .= '<input name="form_type" type="hidden" value="add_service_fly_form" />';

		$output .= '<div class="grid-x grid-margin-x">';
		$output .= '<fieldset class="cell medium-6">';
		$output .= '<button class="button" type="submit" value="Submit">';
		$output .= esc_html__( 'Add Service', 'computer-repair-shop' );
		$output .= '</button></fieldset>';
					
		$output .= '<small>' . esc_html__( '(*) fields are required', 'computer-repair-shop' ) . '</small>';	
		$output .= '</div></form>';
	
		$output .= '<button class="close-button" data-close aria-label="Close modal" type="button"><span aria-hidden="true">&times;</span></button></div>';

		$allowedHTML = ( function_exists( 'wc_return_allowed_tags' ) ) ? wc_return_allowed_tags() : '';
		echo wp_kses( $output, $allowedHTML );
	}
}