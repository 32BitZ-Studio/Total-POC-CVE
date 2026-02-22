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

class WCRB_MANAGE_DEVICES {

	function __construct() {
        add_action( 'wc_rb_settings_tab_menu_item', array( $this, 'add_devices_tab_in_settings_menu' ), 10, 2 );
        add_action( 'wc_rb_settings_tab_body', array( $this, 'add_devices_tab_in_settings_body' ), 10, 2 );
		add_action( 'wp_ajax_wc_rb_update_device_settings', array( $this, 'wc_rb_update_device_settings' ) );
		add_action( 'wp_ajax_wc_add_device_for_manufacture', array( $this, 'wc_add_device_for_manufacture' ) );
    }

	function add_devices_tab_in_settings_menu() {
        $active = '';

        $menu_output = '<li class="tabs-title' . esc_attr($active) . '" role="presentation">';
        $menu_output .= '<a href="#wc_rb_manage_devices" role="tab" aria-controls="wc_rb_manage_devices" aria-selected="true" id="wc_rb_manage_devices-label">';
        $menu_output .= '<h2>' . esc_html__( 'Devices & Brands', 'computer-repair-shop' ) . '</h2>';
        $menu_output .=	'</a>';
        $menu_output .= '</li>';

        echo wp_kses_post( $menu_output );
    }
	
	function add_devices_tab_in_settings_body() {
        global $wpdb;

        $active = '';

		$wc_note_label 				  = ( empty( get_option( 'wc_note_label' ) ) ) ? esc_html__( 'Note', 'computer-repair-shop' ) : get_option( 'wc_note_label' );
		$wc_pin_code_label			  = ( empty( get_option( 'wc_pin_code_label' ) ) ) ? esc_html__( 'Pin Code/Password', 'computer-repair-shop' ) : get_option( 'wc_pin_code_label' );
		$wc_device_label 			  = ( empty( get_option( 'wc_device_label' ) ) ) ? esc_html__( 'Device', 'computer-repair-shop' ) : get_option( 'wc_device_label' );
		$wc_device_brand_label        = ( empty( get_option( 'wc_device_brand_label' ) ) ) ? esc_html__( 'Device Brand', 'computer-repair-shop' ) : get_option( 'wc_device_brand_label' );
		$wc_device_label_plural       = ( empty( get_option( 'wc_device_label_plural' ) ) ) ? esc_html__( 'Devices', 'computer-repair-shop' ) : get_option( 'wc_device_label_plural' );

		$wc_device_type_label        = ( empty( get_option( 'wc_device_type_label' ) ) ) ? esc_html__( 'Device Type', 'computer-repair-shop' ) : get_option( 'wc_device_type_label' );
		$wc_device_type_label_plural = ( empty( get_option( 'wc_device_type_label_plural' ) ) ) ? esc_html__( 'Device Type', 'computer-repair-shop' ) : get_option( 'wc_device_type_label_plural' );

		$wc_device_brand_label_plural = ( empty( get_option( 'wc_device_brand_label_plural' ) ) ) ? esc_html__( 'Device Brands', 'computer-repair-shop' ) : get_option( 'wc_device_brand_label_plural' );
		$wc_device_id_imei_label      = ( empty( get_option( 'wc_device_id_imei_label' ) ) ) ? esc_html__( 'ID/IMEI', 'computer-repair-shop' ) : get_option( 'wc_device_id_imei_label' );
		$wc_pin_code_field			  = get_option( 'wc_pin_code_field' );
		$wcpincodefield 			  = ( $wc_pin_code_field == 'on' ) ? 'checked="checked"' : '';

		$wc_pin_code_show_inv		  = get_option( 'wc_pin_code_show_inv' );
		$wcpincodeshowinvoice 		  = ( $wc_pin_code_show_inv == 'on' ) ? 'checked="checked"' : '';

		//If offer Pick and Delivery.
		$wc_offer_pick_deli = get_option( 'wc_offer_pick_deli' );
		$instruct 			= ( $wc_offer_pick_deli == 'on' ) ? 'checked="checked"' : '';
		
		$offer_laptop_one	= get_option( 'wc_one_day' );
		$offer_laptop_week 	= get_option( 'wc_one_week' );

		$wc_offer_laptop = get_option( 'wc_offer_laptop' );
		$offer_laptop    = ( $wc_offer_laptop == 'on' ) ? 'checked="checked"' : '';

		$pick_deliver_charg = get_option('wc_pick_delivery_charges');

		$setting_body = '<div class="tabs-panel team-wrap' . esc_attr($active) . '" 
        id="wc_rb_manage_devices" 
        role="tabpanel" 
        aria-hidden="true" 
        aria-labelledby="wc_rb_manage_devices-label">';

		$setting_body .= '<div class="wc-rb-manage-devices">';
		$setting_body .= '<h2>' . esc_html__( 'Brands & Devices', 'computer-repair-shop' ) . '</h2>';
		$setting_body .= '<div class="devices_success_msg"></div>';
		
		$setting_body .= '<form data-async data-abide class="needs-validation" novalidate method="post" data-success-class=".devices_success_msg">';

		$setting_body .= '<table class="form-table border"><tbody>';

		$setting_body .= '<tr><th scope="row"><label for="wc_pin_code_field">' . esc_html__( 'Enable Pin Code Field in Jobs page', 'computer-repair-shop' ) . '</label></th>';
		$setting_body .= '<td><input type="checkbox"  ' . esc_html( $wcpincodefield ) . ' name="wc_pin_code_field" id="wc_pin_code_field" /></td></tr>';

		$setting_body .= '<tr><th scope="row"><label for="wc_pin_code_show_inv">' . esc_html__( 'Show Pin Code in Invoices/Emails/Status Check', 'computer-repair-shop' ) . '</label></th>';
		$setting_body .= '<td><input type="checkbox"  ' . esc_html( $wcpincodeshowinvoice ) . ' name="wc_pin_code_show_inv" id="wc_pin_code_show_inv" /></td></tr>';

		if ( rb_is_woocommerce_activated() == TRUE ) {
			$wcrbreplacedevices_f	= get_option( 'wc_enable_devices_as_woo_products' );
			$wcrbreplacedevices     = ( $wcrbreplacedevices_f == 'on' ) ? 'checked="checked"' : '';
		
			$setting_body .= '<tr>
								<th scope="row">
								<label for="wc_enable_devices_as_woo_products">' . esc_html__( 'Replace devices & brands with WooCommerce products', 'computer-repair-shop' ) . '</label></th>';
			$setting_body .= '<td><input type="checkbox"  ' . esc_html( $wcrbreplacedevices ) . ' name="wc_enable_devices_as_woo_products" id="wc_enable_devices_as_woo_products" /></td></tr>';
		}

		$setting_body .= '<tr>';
		$setting_body .= '<th scope="row"><label for="wc_note_label">' . esc_html__( 'Other Labels', 'computer-repair-shop' ) . '</label></th>';

		$setting_body .= '<td><table class="form-table no-padding-table"><tr>';
		$setting_body .= '<td><label>' . esc_html__( 'Note label like Device Note', 'computer-repair-shop' );
		$setting_body .= '<input name="wc_note_label" id="wc_note_label" class="regular-text" value="' . esc_html( $wc_note_label ) . '" type="text" 
		placeholder="' . esc_html__( 'Note', 'computer-repair-shop' ) . '" /></label></td>';

		$setting_body .= '<td><label>' . esc_html__( 'Pin Code/Password Label', 'computer-repair-shop' ) . '<input name="wc_pin_code_label" id="wc_pin_code_label" class="regular-text" 
						value="' . esc_html( $wc_pin_code_label ) . '" type="text" placeholder="' . esc_html__( 'Pin Code/Password', 'computer-repair-shop' ) . '" /></label></td>';
		$setting_body .= '</tr></table></td></tr>';
		
		$setting_body .= '<tr>';
		$setting_body .= '<th scope="row"><label for="wc_device_label">' . esc_html__( 'Device Label', 'computer-repair-shop' ) . '</label></th>';

		$setting_body .= '<td><table class="form-table no-padding-table"><tr>';
		$setting_body .= '<td><label>' . esc_html__( 'Singular device label', 'computer-repair-shop' );
		$setting_body .= '<input name="wc_device_label" id="wc_device_label" class="regular-text" value="' . esc_html( $wc_device_label ) . '" type="text" 
		placeholder="' . esc_html__( 'Device', 'computer-repair-shop' ) . '" /></label></td>';

		$setting_body .= '<td><label>' . esc_html__( 'Plural device label', 'computer-repair-shop' ) . '<input name="wc_device_label_plural" id="wc_device_label_plural" class="regular-text" 
						value="' . esc_html( $wc_device_label_plural ) . '" type="text" placeholder="' . esc_html__( 'Devices', 'computer-repair-shop' ) . '" /></label></td>';
		$setting_body .= '</tr></table></td></tr>';

		$setting_body .= '<tr><th scope="row"><label for="wc_device_brand_label">' . esc_html__( 'Device Brand Label', 'computer-repair-shop' ) . '</label></th>';
		$setting_body .= '<td><table class="form-table no-padding-table"><tr><td><label>' . esc_html__( 'Singular device brand label', 'computer-repair-shop' );
		$setting_body .= '<input name="wc_device_brand_label" id="wc_device_brand_label" class="regular-text" value="' . esc_html( $wc_device_brand_label ) . '" type="text" 
						placeholder="' . esc_html__( 'Device Brand', 'computer-repair-shop' ) . '" /></label></td>';
					
		$setting_body .= '<td><label>' . esc_html__( 'Plural device brand label', 'computer-repair-shop' );
		$setting_body .= '<input name="wc_device_brand_label_plural" id="wc_device_brand_label_plural" class="regular-text" value="' . esc_html( $wc_device_brand_label_plural ) . '" 
						type="text" placeholder="' . esc_html__( 'Device Brands', 'computer-repair-shop' ) . '" /></label></td>';
		$setting_body .= '</tr></table></td></tr>';

		$setting_body .= '<tr><th scope="row"><label for="wc_device_type_label">' . esc_html__( 'Device Type Label', 'computer-repair-shop' ) . '</label></th>';
		$setting_body .= '<td><table class="form-table no-padding-table"><tr><td><label>' . esc_html__( 'Singular device type label', 'computer-repair-shop' );
		$setting_body .= '<input name="wc_device_type_label" id="wc_device_type_label" class="regular-text" value="' . esc_html( $wc_device_type_label ) . '" type="text" 
						placeholder="' . esc_html__( 'Device Type', 'computer-repair-shop' ) . '" /></label></td>';
					
		$setting_body .= '<td><label>' . esc_html__( 'Plural device type label', 'computer-repair-shop' );
		$setting_body .= '<input name="wc_device_type_label_plural" id="wc_device_type_label_plural" class="regular-text" value="' . esc_html( $wc_device_type_label_plural ) . '" 
						type="text" placeholder="' . esc_html__( 'Device Types', 'computer-repair-shop' ) . '" /></label></td>';
		$setting_body .= '</tr></table></td></tr>';

		$setting_body .= '<tr><th scope="row"><label for="wc_device_id_imei_label">' . esc_html__( 'ID/IMEI Label', 'computer-repair-shop' ) . '</label></th>';
		$setting_body .= '<td><input name="wc_device_id_imei_label" id="wc_device_id_imei_label" class="regular-text" value="' . esc_html( $wc_device_id_imei_label ) . '" type="text" 
			placeholder="' . esc_html__( 'ID/IMEI', 'computer-repair-shop' ) . '" /></td></tr>';

		$setting_body .= '<tr><th scope="row"><label for="offer_pic_de">' . esc_html__( 'Offer pickup and delivery?', 'computer-repair-shop' ) . '</label></th>';
		$setting_body .= '<td><input type="checkbox"  ' . esc_html( $instruct ) . ' name="offer_pic_de" id="offer_pic_de" /></td></tr>';

		$setting_body .= '<tr><th scope="row"><label for="pick_deliver">' . esc_html__( 'Pick up and delivery charges', 'computer-repair-shop' ) . '</label></th>';
		$setting_body .= '<td><input name="pick_deliver" id="pick_deliver" class="regular-text wc_validate_number" value="' . esc_html( $pick_deliver_charg ) . '" type="text" 
					placeholder="' . esc_html__( 'Enter the Pick up and delivery charges here', 'computer-repair-shop' ) . '"/></td></tr>';

		$setting_body .= '<tr><th scope="row"><label for="offer_laptop">' . esc_html__( 'Offer device rental?', 'computer-repair-shop' ) . '</label></th>';
		$setting_body .= '<td><input type="checkbox"  ' . esc_html( $offer_laptop ) . ' name="offer_laptop" id="offer_laptop" /></td></tr>';

		$setting_body .= '<tr><th scope="row"><label for="offer_laptop_one">' . esc_html__( 'Device rent', 'computer-repair-shop' ) . '</label></th>';
		$setting_body .= '<td><table class="form-table no-padding-table"><tr><td><label>' . esc_html__( 'Device rent per day', 'computer-repair-shop' );
		$setting_body .= '<input name="offer_laptop_one" id="offer_laptop_one" class="regular-text wc_validate_number" value="' . esc_html( $offer_laptop_one ) . '" type="text" 
							placeholder="' . esc_html__( 'Enter the device rent for one day', 'computer-repair-shop' ) . '"/></label></td>';
		$setting_body .= '<td><label>' . esc_html__( 'Device rent per week', 'computer-repair-shop' );
		$setting_body .= '<input name="offer_laptop_week" id="offer_laptop_week" class="regular-text wc_validate_number" value="' . esc_html( $offer_laptop_week ) . '" type="text" 
							placeholder="' . esc_html__( 'Enter the Device rent for one week', 'computer-repair-shop' ) . '"/></label></td></tr></table></td></tr>';

		$setting_body .= '</tbody></table>';

		$setting_body .= '<input type="hidden" name="form_type" value="wc_rb_update_sett_devices_brands" />';
		$setting_body .= wp_nonce_field( 'wcrb_nonce_setting_payment', 'wcrb_nonce_setting_payment_field', true, false );

		$setting_body .= '<button type="submit" class="button button-primary" data-type="rbssubmitdevices">' . esc_html__( 'Update Options', 'computer-repair-shop' ) . '</button></form>';

		$setting_body .= '</div><!-- wc rb Devices /-->';

		$setting_body .= '</div><!-- Tabs Panel /-->';

		$allowedHTML = ( function_exists( 'wc_return_allowed_tags' ) ) ? wc_return_allowed_tags() : '';
		echo wp_kses( $setting_body, $allowedHTML );
	}

	function wc_rb_update_device_settings() {
		$message = '';
		$success = 'NO';

		if ( ! isset( $_POST['wcrb_nonce_setting_payment_field'] ) || ! wp_verify_nonce( $_POST['wcrb_nonce_setting_payment_field'], 'wcrb_nonce_setting_payment' ) ) {
			$message = esc_html__( 'Couldn\'t verify nonce please reload page.', 'computer-repair-shop' );
		} else {
			// process form data
			if ( rb_is_woocommerce_activated() ) {
				$wc_enable_devices_as_woo_products = ( ! isset( $_POST['wc_enable_devices_as_woo_products'] ) ) ? '' : sanitize_text_field( $_POST['wc_enable_devices_as_woo_products'] );
				update_option( 'wc_enable_devices_as_woo_products', $wc_enable_devices_as_woo_products );
			}

			$wc_note_label 				  = ( ! isset( $_POST['wc_note_label'] ) ) ? '' : sanitize_text_field( $_POST['wc_note_label'] );
			$wc_pin_code_label			  = ( ! isset( $_POST['wc_pin_code_label'] ) ) ? '' : sanitize_text_field( $_POST['wc_pin_code_label'] );
			$wc_device_label			  = ( ! isset( $_POST['wc_device_label'] ) ) ? '' : sanitize_text_field( $_POST['wc_device_label'] );
			$wc_device_brand_label		  = ( ! isset( $_POST['wc_device_brand_label'] ) ) ? '' : sanitize_text_field( $_POST['wc_device_brand_label'] );
			$wc_device_id_imei_label	  = ( ! isset( $_POST['wc_device_id_imei_label'] ) ) ? '' : sanitize_text_field( $_POST['wc_device_id_imei_label'] );
			$wc_device_label_plural		  = ( ! isset( $_POST['wc_device_label_plural'] ) ) ? '' : sanitize_text_field( $_POST['wc_device_label_plural'] );
			$wc_device_brand_label_plural = ( ! isset( $_POST['wc_device_brand_label_plural'] ) ) ? '' : sanitize_text_field( $_POST['wc_device_brand_label_plural'] );

			$wc_device_type_label		  = ( ! isset( $_POST['wc_device_type_label'] ) ) ? '' : sanitize_text_field( $_POST['wc_device_type_label'] );
			$wc_device_type_label_plural = ( ! isset( $_POST['wc_device_type_label_plural'] ) ) ? '' : sanitize_text_field( $_POST['wc_device_type_label_plural'] );

			$wc_pin_code_field 			  = ( ! isset( $_POST['wc_pin_code_field'] ) ) ? '' : sanitize_text_field( $_POST['wc_pin_code_field'] );
			$wc_pin_code_show_inv 		  = ( ! isset( $_POST['wc_pin_code_show_inv'] ) ) ? '' : sanitize_text_field( $_POST['wc_pin_code_show_inv'] );
			
			$pick_deliver				  = (!isset($_POST['pick_deliver'])) ? "" : 			sanitize_text_field($_POST['pick_deliver']);
			$offer_laptop				  = (!isset($_POST['offer_laptop'])) ? "" : 			sanitize_text_field($_POST['offer_laptop']);
			$offer_laptop_one			  = (!isset($_POST['offer_laptop_one'])) ? "" : 		sanitize_text_field($_POST['offer_laptop_one']);
			$offer_laptop_week			  = (!isset($_POST['offer_laptop_week'])) ? "" : 		sanitize_text_field($_POST['offer_laptop_week']);
			$offer_pic_de 				  = (!isset($_POST['offer_pic_de'])) ? "" : sanitize_text_field($_POST['offer_pic_de']);
		
		
			update_option('wc_offer_pick_deli', $offer_pic_de);//Processing offer_pic_de checkbox.
			update_option('wc_one_day', $offer_laptop_one);//Processing offer_laptop for one day input box.
			update_option('wc_one_week', $offer_laptop_week);//Processing offer_laptop for one week input box.
			update_option('wc_offer_laptop', $offer_laptop);//Processing offer_laptop checkbox.
			update_option('wc_pick_delivery_charges', $pick_deliver); //Processing pickup and delivery charges.
			update_option( 'wc_device_label', $wc_device_label );
			update_option( 'wc_device_brand_label', $wc_device_brand_label );
			update_option( 'wc_device_label_plural', $wc_device_label_plural );
			update_option( 'wc_device_brand_label_plural', $wc_device_brand_label_plural );

			update_option( 'wc_device_type_label', $wc_device_type_label );
			update_option( 'wc_device_type_label_plural', $wc_device_type_label_plural );

			update_option( 'wc_note_label', $wc_note_label );
			update_option( 'wc_pin_code_label', $wc_pin_code_label );

			update_option( 'wc_device_id_imei_label', $wc_device_id_imei_label );
			update_option( 'wc_pin_code_field', $wc_pin_code_field );
			update_option( 'wc_pin_code_show_inv', $wc_pin_code_show_inv );

			$message = esc_html__( 'Settings updated!', 'computer-repair-shop' );
		}

		$values['message'] = $message;
		$values['success'] = $success;

		wp_send_json( $values );
		wp_die();
	}

	function wc_add_device_for_manufacture() {
		$message = '';
		$device_id = '';
		$success = 'NO';

		$manufacture = ( isset( $_POST['manufacture'] ) ) ? sanitize_text_field( $_POST['manufacture'] ) : '';
		$devicetype  = ( isset( $_POST['devicetype'] ) ) ? sanitize_text_field( $_POST['devicetype'] ) : '';
		$device_name = ( isset( $_POST['device_name'] ) ) ? sanitize_text_field( $_POST['device_name'] ) : '';

		if ( empty ( $manufacture ) || empty( $device_name ) || $manufacture == 'All' ) {
			$message = esc_html__( 'Brand and device names cannot be empty.', 'computer-repair-shop' );
		} else {
			//Check device status
			$curr = post_exists( $device_name,'','','rep_devices' );

			if ( $curr == '0' ) {
				//Post didn't exist let's add 
				$post_data = array(
					'post_title'    => $device_name,
					'post_status'   => 'publish',
					'post_type' 	=> 'rep_devices',
				);
				$post_id = wp_insert_post( $post_data );

				$tag = array( $manufacture );
				wp_set_post_terms( $post_id, $tag, 'device_brand' );

				if ( ! empty( $devicetype ) ) {
					$type = array( $devicetype );
					wp_set_post_terms( $post_id, $type, 'device_type' );
				}

				$device_id = $post_id;
				$message = esc_html__( 'Device Added', 'computer-repair-shop' );
			} else {
				$device_id = $curr;
				$message = esc_html__( 'Device with same name already exists', 'computer-repair-shop' );
			}
		}

		$values['message'] = $message;
		$values['device_id'] = $device_id;
		$values['success'] = $success;

		wp_send_json( $values );
		wp_die();
	}

	/**
	 * Device Manufacture Options
	 * Return options
	 * Outputs selected options
	 */
	function generate_manufacture_options( $selected_manufacture, $select_all ) {

		$selected_manufacture = ( ! empty( $selected_manufacture ) ) ? $selected_manufacture : '';

		$wcrb_type = 'rep_devices';
		$wcrb_tax  = 'device_brand';

		$cat_terms = get_terms(
			array(
					'taxonomy'		=> $wcrb_tax,
					'hide_empty'    => false,
					'orderby'       => 'name',
					'order'         => 'ASC',
					'number'        => 0
				)
		);

		$wc_device_label = ( empty( get_option( 'wc_device_brand_label' ) ) ) ? esc_html__( 'Brand', 'computer-repair-shop' ) : get_option( 'wc_device_brand_label' );
		$wc_device_labels = ( empty( get_option( 'wc_device_brand_label_plural' ) ) ) ? esc_html__( 'Brands', 'computer-repair-shop' ) : get_option( 'wc_device_brand_label_plural' );

		$output = "<option value='All'>" . esc_html__("Select", "computer-repair-shop") . ' ' . $wc_device_label . "</option>";

		$output = ( isset( $select_all ) && ! empty( $select_all ) ) ? "<option value='All'>" . esc_html__("For All ", "computer-repair-shop") . ' ' . $wc_device_labels . "</option>" : $output;

		if( $cat_terms ) :
			foreach( $cat_terms as $term ) :
				$selected = ( $term->term_id == $selected_manufacture ) ? ' selected' : '';
				$output .= '<option ' . $selected . ' value="' . esc_html( $term->term_id ) . '">';
				$output .= $term->name;
				$output .= '</option>';

			endforeach;
		endif;

		return $output;
	}

	function generate_device_type_options( $selected_type, $extra_field ) {
		$selected_type = ( ! empty( $selected_type ) ) ? $selected_type : '';

		$wcrb_type = 'rep_devices';
		$wcrb_tax  = 'device_type';

		$cat_terms = get_terms(
			array(
					'taxonomy'		=> $wcrb_tax,
					'hide_empty'    => false,
					'orderby'       => 'name',
					'order'         => 'ASC',
					'number'        => 0
				)
		);

		$wc_device_label = ( empty( get_option( 'wc_device_type_label' ) ) ) ? esc_html__( 'Type', 'computer-repair-shop' ) : get_option( 'wc_device_type_label' );
		$wc_device_labels = ( empty( get_option( 'wc_device_type_label_plural' ) ) ) ? esc_html__( 'Types', 'computer-repair-shop' ) : get_option( 'wc_device_type_label_plural' );

		$output = "<option value='All'>" . esc_html__("Select", "computer-repair-shop") . ' ' . $wc_device_label . "</option>";

		$output = ( isset( $extra_field ) && ! empty( $extra_field ) ) ? "<option value='All'>" . esc_html__("For All ", "computer-repair-shop") . ' ' . $wc_device_labels . "</option>" : $output;

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

	/**
	 * Add Device Reveal Form
	 * Needs to load in footer first
	 */
	function add_device_reveal_form() {
		$output = '';

		$wc_device_label 	   = ( empty( get_option( 'wc_device_label' ) ) ) ? esc_html__( 'Device', 'computer-repair-shop' ) : get_option( 'wc_device_label' );
		$wc_device_brand_label = ( empty( get_option( 'wc_device_brand_label' ) ) ) ? esc_html__( 'Device Brand', 'computer-repair-shop' ) : get_option( 'wc_device_brand_label' );
		$wc_device_type_label = ( empty( get_option( 'wc_device_type_label' ) ) ) ? esc_html__( 'Device Type', 'computer-repair-shop' ) : get_option( 'wc_device_type_label' );

		$output .= '<div class="small reveal" id="deviceFormReveal" data-reveal>';
		$output .= '<h2>' . esc_html__( 'Add New ', 'computer-repair-shop' ) . $wc_device_label . '</h2>';
	
		$output .= '<div class="form-message"></div>';
	
		$output .= '<form data-async data-abide class="needs-validation" novalidate method="post">';
		
		$output .= '<div class="grid-x grid-margin-x">';
		$output .= '<div class="cell">
						<div data-abide-error class="alert callout hidden">
							<p>' . esc_html__( 'There are some errors in your form.', 'computer-repair-shop' ) . '</p>
						</div>
					</div></div>';
	
		$output .= '<div class="grid-x grid-margin-x">';
	
		$output .= '<div class="cell medium-6">
						<label class="have-addition">' . esc_html__( 'Select ', 'computer-repair-shop' ) . $wc_device_brand_label . '*';
		$output .= '<select name="manufacture">';
		$output .= $this->generate_manufacture_options( '', '' );
		$output .= '</select>';
		$output .= '<a href="edit-tags.php?taxonomy=device_brand&post_type=rep_devices" target="_blank" class="button button-primary button-small" title="' . esc_html__( 'Add ', 'computer-repair-shop' ) . $wc_device_brand_label . '"><span class="dashicons dashicons-plus"></span></a>';
		$output .= '</label>
					</div>';

		$output .= '<div class="cell medium-6"><label class="have-addition">' . esc_html__( 'Select ', 'computer-repair-shop' ) . $wc_device_type_label . '*';
		$output .= '<select name="devicetype">';
		$output .= $this->generate_device_type_options( '', '' );
		$output .= '</select>';
		$output .= '<a href="edit-tags.php?taxonomy=device_type&post_type=rep_devices" target="_blank" class="button button-primary button-small" title="' . esc_html__( 'Add ', 'computer-repair-shop' ) . $wc_device_brand_label . '"><span class="dashicons dashicons-plus"></span></a>';
		$output .= '</label></div>';
	
		$output .= '<div class="cell medium-6">
						<label>' . $wc_device_label . esc_html__( ' Name', 'computer-repair-shop' ) . '
							<input name="device_name" type="text" class="form-control login-field"
								   value="" id="device_name"/>
						</label>';
		$output .= '</div>';
					
		$output .= '</div>';
		
		$output .= '<input name="form_type" type="hidden" value="add_device_form" />';
	
		$output .= '<div class="grid-x grid-margin-x">
					<fieldset class="cell medium-6">
						<button class="button" type="submit">' . esc_html__( "Add ", "computer-repair-shop" ) . $wc_device_label . '</button>
					</fieldset>
				</div>
			</form>
	
			<button class="close-button" data-close aria-label="Close modal" type="button">
				<span aria-hidden="true">&times;</span>
			</button>
		</div>';

		$allowedHTML = ( function_exists( 'wc_return_allowed_tags' ) ) ? wc_return_allowed_tags() : '';
		echo wp_kses( $output, $allowedHTML );
	}

	function list_customer_devices( $view ) {
		global $wpdb;

		if ( ! is_user_logged_in() ) {
			return;
		}
		$computer_repair_customer_devices = $wpdb->prefix . 'wc_cr_customer_devices';

		$current_user = wp_get_current_user();
		$customer_id = $current_user->ID;

		if ( in_array( 'administrator', (array) $current_user->roles ) && is_admin() ) {
			$select_query = "SELECT * FROM `{$computer_repair_customer_devices}` ORDER BY `device_id` DESC";
			$view = ( empty( $view ) ) ? 'customer' : $view;
		} else {
			$select_query = $wpdb->prepare( "SELECT * FROM `{$computer_repair_customer_devices}` WHERE `customer_id`= %d ORDER BY `device_id` DESC", $customer_id );			
			$view = ( empty( $view ) ) ? $view : 'admin';
		}
        $select_results = $wpdb->get_results( $select_query );
            
        $output = ( $wpdb->num_rows == 0 ) ? esc_html__( 'There is no record available', 'computer-repair-shop' ) : '';

        foreach( $select_results as $item ) {
			$device_id 		= $item->device_id;
			$device_post_id = $item->device_post_id;
			$device_label 	= $item->device_label;
			$serial_nuumber = $item->serial_nuumber;
			$pint_code 		= $item->pint_code;
			$customerId 	= $item->customer_id;

			$output .= '<tr>';
			$output .= '<td>' . esc_html( $device_id ) . '</td>';
			$output .= '<td>' . esc_html( $device_label ) . '</td>';
			$output .= '<td>' . esc_html( $serial_nuumber ) . '</td>';
			$output .= '<td>' . esc_html( $pint_code ) . '</td>';
			if ( is_admin() ) {
				$user 		= get_user_by( 'id', $customerId );
				$first_name	= empty( $user->first_name ) ? "" : $user->first_name;
				$last_name 	= empty( $user->last_name )? "" : $user->last_name;
				$cust_name  =  $first_name. ' ' .$last_name ;

				$output .= '<td>' . esc_html( $cust_name ) . '</td>';
			}
			$output .= '</tr>';
		}
		return $output;
	}

	function backend_customer_devices_output() {
		global $wpdb;

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have sufficient permissions to access this page.', 'computer-repair-shop' ) );
		}

		$wc_device_label 		 = ( empty( get_option( 'wc_device_label_plural' ) ) ) ? esc_html__( 'Devices', 'computer-repair-shop' ) : get_option( 'wc_device_label_plural' );
		$sing_device_label  	 = ( empty( get_option( 'wc_device_label' ) ) ) ? esc_html__( 'Device', 'computer-repair-shop' ) : get_option( 'wc_device_label' );
		$wc_device_id_imei_label = ( empty( get_option( 'wc_device_id_imei_label' ) ) ) ? esc_html__( 'ID/IMEI', 'computer-repair-shop' ) : get_option( 'wc_device_id_imei_label' );
		$wc_pin_code_label 		 = ( empty( get_option( 'wc_pin_code_label' ) ) ) ? esc_html__( 'Pin Code/Password', 'computer-repair-shop' ) : get_option( 'wc_pin_code_label' );
	?>
		<div class="wrap" id="poststuff">
			<h1 class="wp-heading-inline"><?php echo esc_html__( "Customer", "computer-repair-shop" ) . ' ' . esc_html( $wc_device_label ); ?></h1>
			
			<table class="wp-list-table widefat fixed striped users">
			<thead><tr>
				<th class="manage-column column-id">
					<span><?php echo esc_html__( 'ID', 'computer-repair-shop' ); ?></span>
				</th>
				<th class="manage-column column-name">
					<span><?php echo esc_html( $sing_device_label ); ?></span>
				</th>
				<th class="manage-column column-email">
					<span><?php echo esc_html( $wc_device_id_imei_label ); ?></span>
				</th>
				<th class="manage-column column-phone">
					<?php echo esc_html( $wc_pin_code_label ); ?>
				</th>
				<th class="manage-column column-address">
					<?php echo esc_html__( 'Customer', 'computer-repair-shop' ); ?>
				</th>
			</tr></thead>
			<tbody data-wp-lists="list:user">
				<?php 
					$output = $this->list_customer_devices( 'admin' ); 
					$allowedHTML = wc_return_allowed_tags();
					echo wp_kses( $output, $allowedHTML );
				?>
			</tbody>
			<tfoot><tr>
				<th class="manage-column column-id">
					<span><?php echo esc_html__( 'ID', 'computer-repair-shop' ); ?></span>
				</th>
				<th class="manage-column column-name">
					<span><?php echo esc_html( $sing_device_label ); ?></span>
				</th>
				<th class="manage-column column-email">
					<span><?php echo esc_html( $wc_device_id_imei_label ); ?></span>
				</th>
				<th class="manage-column column-phone">
					<?php echo esc_html( $wc_pin_code_label ); ?>
				</th>
				<th class="manage-column column-address">
					<?php echo esc_html__( 'Customer', 'computer-repair-shop' ); ?>
				</th>
			</tr></tfoot>
			</table>
		</div> <!-- Wrap Ends /-->
		<?php
	}

	function add_customer_device( $device_post_id, $imei_serial, $device_pincode, $customer_id ) {
		global $wpdb;

		if ( empty( $device_post_id ) || empty( $customer_id ) ) {
			return;
		}

		$computer_repair_customer_devices = $wpdb->prefix.'wc_cr_customer_devices';
		$wc_meta_value	 = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$computer_repair_customer_devices} WHERE `customer_id` = %d AND `device_post_id` = %s AND `serial_nuumber` = %s", $customer_id, $device_post_id, $imei_serial ) );
		if ( ! empty( $wc_meta_value ) ) {
			return;
		}
		$device_label = return_device_label( $device_post_id );
		$insert_query = "INSERT INTO 
						`" . $computer_repair_customer_devices . "` 
					VALUES
						(NULL, %d, %s, %s, %s, %d)";
		$wpdb->query(
				$wpdb->prepare($insert_query, array( $device_post_id, $device_label, $imei_serial, $device_pincode, $customer_id ))
		);
		$history_id = $wpdb->insert_id;
	}
}