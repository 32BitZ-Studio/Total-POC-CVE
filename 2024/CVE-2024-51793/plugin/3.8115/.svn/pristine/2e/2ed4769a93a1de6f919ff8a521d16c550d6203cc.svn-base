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

class WCRB_PARTS {

	function __construct() {
		add_action( 'wp_ajax_wc_add_part_for_fly', array( $this, 'wc_add_part_for_fly' ) );
    }

	function wc_add_part_for_fly() {
		$message = '';
		$part_id = '';
		$success = 'NO';

		$part_partName 	  	    = ( isset( $_POST['part_partName'] ) ) ? sanitize_text_field( $_POST['part_partName'] ) : '';
		$part_partBrand 	    = ( isset( $_POST['part_partBrand'] ) ) ? sanitize_text_field( $_POST['part_partBrand'] ) : '';
		$part_manufacturingCode = ( isset( $_POST['part_manufacturingCode'] ) ) ? sanitize_text_field( $_POST['part_manufacturingCode'] ) : '';
		$part_StockCode 		= ( isset( $_POST['part_StockCode'] ) ) ? sanitize_text_field( $_POST['part_StockCode'] ) : '';
		$part_price 			= ( isset( $_POST['part_price'] ) ) ? sanitize_text_field( $_POST['part_price'] ) : '';

		if ( empty ( $part_partName ) || empty( $part_manufacturingCode ) || empty( $part_price ) ) {
			$message = esc_html__( 'Part name, manufacturing code and price are required fields.', 'computer-repair-shop' );
		} else {
			//Check device status
			$curr = post_exists( $part_partName,'','','rep_products' );

			if ( $curr == '0' ) {
				//Post didn't exist let's add 
				$post_data = array(
					'post_title'    => $part_partName,
					'post_status'   => 'publish',
					'post_type' 	=> 'rep_products',
				);
				$post_id = wp_insert_post( $post_data );

				if ( ! empty( $part_partBrand ) ) {
					$tag = array( $part_partBrand );
					wp_set_post_terms( $post_id, $tag, 'brand_type' );
				}

				update_post_meta($post_id, '_manufacturing_code', $part_manufacturingCode);
				update_post_meta($post_id, '_stock_code', $part_StockCode);
				update_post_meta($post_id, '_price', $part_price);

				$part_id = $post_id;
				$message = esc_html__( 'Part Added to add featured image, features and other information go to parts.', 'computer-repair-shop' );
			} else {
				$part_id = $curr;
				$message = esc_html__( 'Part with same name already exists', 'computer-repair-shop' );
			}
		}

		$values['message'] = $message;
		$values['part_id'] = $part_id;
		$values['success'] = $success;

		wp_send_json( $values );
		wp_die();
	}

	/**
	 * Parts Brands Options
	 * Return options
	 * Outputs selected options
	 */
	function generate_brands_select_options( $selected_brand ) {
		$selected_brand = ( ! empty( $selected_brand ) ) ? $selected_brand : '';

		$wcrb_type = 'rep_products';
		$wcrb_tax  = 'brand_type';

		$cat_terms = get_terms(
			array(
					'taxonomy'		=> $wcrb_tax,
					'hide_empty'    => false,
					'orderby'       => 'name',
					'order'         => 'ASC',
					'number'        => 0
				)
		);

		$output = "<option value='All'>" . esc_html__( 'Select Brand', 'computer-repair-shop' ) . "</option>";

		if( $cat_terms ) :
			foreach( $cat_terms as $term ) :
				$selected = ( $term->term_id == $selected_brand ) ? ' selected' : '';
				$output .= '<option ' . $selected . ' value="' . esc_html( $term->term_id ) . '">';
				$output .= $term->name;
				$output .= '</option>';

			endforeach;
		endif;

		return $output;
	}

	function add_parts_reveal_form() {
		$output = '<div class="small reveal" id="partFormReveal" data-reveal>';

		$output .= '<h2>' . esc_html__( 'Add a new part', 'computer-repair-shop' ) . '</h2>';
		$output .= '<div class="part-form-message"></div>';

		$output .= '<form data-async data-abide data-success-class=".part-form-message" class="needs-validation" novalidate method="post">';
		
		$output .= '<div class="grid-x grid-margin-x">';
		
		$output .= '<div class="cell medium-6">
						<label>' . esc_html__( 'Part Name', 'computer-repair-shop' ) . '*
							<input name="part_partName" type="text" class="form-control login-field"
								   value="" required id="part_partName"/>
						</label>
					</div>';
	
		$output .= '<div class="cell medium-6">
					<label class="have-addition">' . esc_html__( 'Select Brand', 'computer-repair-shop' ) . '*';
		$output .= '<select name="part_partBrand">';
		$output .= $this->generate_brands_select_options( '' );
		$output .= '</select>';
		$output .= '<a href="edit-tags.php?taxonomy=brand_type&post_type=rep_products" target="_blank" class="button button-primary button-small" title="' . esc_html__( 'Add Brand', 'computer-repair-shop' ) . '"><span class="dashicons dashicons-plus"></span></a>';
		$output .= '</label>
					</div>';			

		$output .= '</div>';

		$output .= '<div class="grid-x grid-margin-x">';
		$output .= '<div class="cell medium-6">
						<label>' . esc_html__( 'Manufacturing Code', 'computer-repair-shop' ) . '*
							<input name="part_manufacturingCode" type="text" class="form-control login-field"
								   value="" required id="part_manufacturingCode"/>
						</label></div>';
	
		$output .= '<div class="cell medium-6">
						<label>' . esc_html__( 'Stock Code', 'computer-repair-shop' ) . '
							<input name="part_StockCode" type="text" class="form-control login-field"
								   value="" id="part_StockCode"/>
						</label></div>';
		$output .= '</div>';

		$output .= '<div class="grid-x grid-margin-x">';
		$output .= '<div class="cell medium-6">
						<label>' . esc_html__( 'Part Price', 'computer-repair-shop' ) . '*
							<input name="part_price" type="number" class="form-control login-field"
								   value="" required id="part_price"/>
						</label></div>';
		$output .= '</div>';

		$output .= '<input name="form_type" type="hidden" value="add_part_fly_form" />';

		$output .= '<div class="grid-x grid-margin-x">';
		$output .= '<fieldset class="cell medium-6">';
		$output .= '<button class="button" type="submit" value="Submit">';
		$output .= esc_html__( 'Add Part', 'computer-repair-shop' );
		$output .= '</button></fieldset>';
					
		$output .= '<small>' . esc_html__( '(*) fields are required', 'computer-repair-shop' ) . '</small>';	
		$output .= '</div></form>';
	
		$output .= '<button class="close-button" data-close aria-label="Close modal" type="button"><span aria-hidden="true">&times;</span></button></div>';

		$allowedHTML = ( function_exists( 'wc_return_allowed_tags' ) ) ? wc_return_allowed_tags() : '';
		echo wp_kses( $output, $allowedHTML );
	}
}