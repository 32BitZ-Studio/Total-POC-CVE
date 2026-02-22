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

class WCRB_DEVICE_SERVICES extends WCRB_MANAGE_DEVICES {

	function __construct() {
		add_action( 'add_meta_boxes', array( $this, 'wc_service_price_features' ) );
		add_action( 'wp_ajax_wc_rb_update_the_prices', array( $this, 'wc_rb_update_the_prices' ) );
	}

	function wc_service_price_features() { 
		$screens = array( 'rep_services' );
	
		foreach ( $screens as $screen ) {
			add_meta_box(
				'wcrb_service_price_device',
				esc_html__( 'Set Prices for Devices', 'computer-repair-shop' ),
				array( $this, 'wc_service_price_by_device' ),
				$screen,
				'advanced',
				'high'
			);
		}
	} //Parts features post.
	
	function wc_service_price_by_device( $post ) {
		$thePostID = $post->ID;
		settings_errors();
		
		$output = '';

		if ( empty( $thePostID ) ) :
			$output = esc_html__( 'Service ID couldn not be found, please publish or update serviceto get price settings', 'computer-repair-shop' );
		else :
			$output .= esc_html__( 'Please note If set deivce price that will override manufacture price, if set manufacture price that will override type price. And if only type price is set that will apply to all devices related to that type or manufacture', 'computer-repair-shop' );

			$output .= '<div class="prices_message"></div>';

			$output .= wp_nonce_field( 'wcrb_nonce_setting_device', 'wcrb_nonce_setting_device_field', true, false );

			$output .= '<ul class="accordion" data-accordion data-allow-all-closed="true">';
			$output .= $this->return_device_type_accordion_price( $thePostID );
			$output .= $this->return_device_brand_accordion_price( $thePostID );
			$output .= $this->return_device_accordion_price( $thePostID );
			$output .= '</ul>';
		endif;

		$allowedHTML = ( function_exists( 'wc_return_allowed_tags' ) ) ? wc_return_allowed_tags() : '';
		echo wp_kses( $output, $allowedHTML );
	}

	function return_device_type_accordion_price( $thePostID ) {
		if ( empty( $thePostID ) ) {
			return '';
		}

		$wc_device_type_label_plural = ( empty( get_option( 'wc_device_type_label_plural' ) ) ) ? esc_html__( 'Device Type', 'computer-repair-shop' ) : get_option( 'wc_device_type_label_plural' );
		$thePrice = get_post_meta( $thePostID, '_cost', true );
		
		$output = '<li class="accordion-item" data-accordion-item>';
		$output .= '<a href="#" class="accordion-title">';
		$output .= esc_html__( 'Set price by ', 'computer-repair-shop' ) . ' ' . $wc_device_type_label_plural;		
		$output .= '</a>';

		$output .= '<div class="accordion-content" data-tab-content>';
		
		$output .= esc_html__( 'Update prices to apply to related devices', 'computer-repair-shop' );
		
		$output .= '<div class="button-right"><button id="WCRB_submit_type_prices" data-job-id="' . esc_html( $thePostID ) . '" class="button button-primary button-large preview">' . esc_html__( 'Update Prices', 'computer-repair-shop' ) . '</button></div>';

		$table_head = '<table class="wp-list-table widefat fixed striped posts"><thead>';
		$table_head .= '<tr>';
		$table_head .= '<th class="id_head">' . esc_html__( 'ID', 'computer-repair-shop' ) . '</th>';
		$table_head .= '<th>' . esc_html__( 'Name', 'computer-repair-shop' ) . '</th>';
		$table_head .= '<th class="price_head">' . esc_html__( 'Price', 'computer-repair-shop' ) . '</th>';
		$table_head .= '<th class="action_head">' . esc_html__( 'Active', 'computer-repair-shop' ) . '</th>';
		$table_head .= '</th>';
		$table_head .= '</thead>';

		$table_foot = '</table>';

		$wcrb_type = 'rep_devices';
		$wcrb_tax  = 'device_type';

		$cat_terms = get_terms(
			array(
					'taxonomy'	 => $wcrb_tax,
					'hide_empty' => false,
					'orderby'    => 'name',
					'order'      => 'ASC',
					'number'     => 0, //Returns all
				)
		);

		if( $cat_terms ) :
			$table_body = '<tbody>';
			foreach( $cat_terms as $term ) :
				$termPriceSet 	 = get_post_meta( $thePostID, 'type_price_' . esc_html( $term->term_id ), true );
				$termPriceStatus = get_post_meta( $thePostID, 'type_status_' . esc_html( $term->term_id ), true );

				$checked = ( $termPriceStatus == 'inactive' ) ? '' : 'checked';

				$thePrice = ( empty( $termPriceSet ) ) ? $thePrice : $termPriceSet;
				$thePrice = ( empty( $thePrice ) ) ? '0.00' : $thePrice;

				$table_body .= '<tr>';
				$table_body .= '<td><input type="hidden" name="type_id[]" value="' . esc_html( $term->term_id ) . '" /> ' . esc_html( $term->term_id ) . '</td>';
				$table_body .= '<td> ' . $term->name . '</td>';
				$table_body .= '<td><input type="number" class="regular-text" name="type_price[]" step="any" value="'.esc_attr( $thePrice ). '" /></td>';
				$table_body .= '<td><input type="checkbox" name="type_status[]" value="' . esc_html( $term->term_id ) . '" ' . esc_attr( $checked ) . ' /></td>';
				$table_body .= '</tr>';
			endforeach;
			$table_body .= '<tbody>';
		endif;

		if ( isset( $table_body ) ) {
			$output .= $table_head;
			$output .= $table_body;
			$output .= $table_foot;
		} else {
			$output .= esc_html__( 'Add some', 'computer-repair-shop' ) .' ' . $wc_device_type_label_plural . esc_html__( 'to set prices', 'computer-repair-shop' )  . '<a target="_blank" href="edit-tags.php?taxonomy=device_type&post_type=rep_devices">'. esc_html__( 'Add some', 'computer-repair-shop' ) . ' ' . $wc_device_type_label_plural .'</a>';
		}

		$output .= '</div></li>';
			
		return $output;
	}

	function return_device_brand_accordion_price( $thePostID ) {
		if ( empty( $thePostID ) ) {
			return '';
		}

		$wc_device_brand_label_plural = ( empty( get_option( 'wc_device_brand_label_plural' ) ) ) ? esc_html__( 'Device Brand', 'computer-repair-shop' ) : get_option( 'wc_device_brand_label_plural' );
		$thePrice = get_post_meta( $thePostID, '_cost', true );
		
		$output = '<li class="accordion-item" data-accordion-item>';
		$output .= '<a href="#" class="accordion-title">';
		$output .= esc_html__( 'Set price by ', 'computer-repair-shop' ) . ' ' . $wc_device_brand_label_plural;		
		$output .= '</a>';

		$output .= '<div class="accordion-content" data-tab-content>';
		
		$output .= esc_html__( 'Update prices to apply to related devices', 'computer-repair-shop' );
		
		$output .= '<div class="button-right"><button id="WCRB_submit_brand_prices" data-job-id="' . esc_html( $thePostID ) . '" 
		class="button button-primary button-large preview">' . esc_html__( 'Update Prices', 'computer-repair-shop' ) . '</button></div>';

		$table_head = '<table class="wp-list-table widefat fixed striped posts"><thead>';
		$table_head .= '<tr>';
		$table_head .= '<th class="id_head">' . esc_html__( 'ID', 'computer-repair-shop' ) . '</th>';
		$table_head .= '<th>' . esc_html__( 'Name', 'computer-repair-shop' ) . '</th>';
		$table_head .= '<th class="price_head">' . esc_html__( 'Price', 'computer-repair-shop' ) . '</th>';
		$table_head .= '<th class="action_head">' . esc_html__( 'Active', 'computer-repair-shop' ) . '</th>';
		$table_head .= '</th>';
		$table_head .= '</thead>';

		$table_foot = '</table>';

		$wcrb_type = 'rep_devices';
		$wcrb_tax  = 'device_brand';

		$cat_terms = get_terms(
			array(
					'taxonomy'	 => $wcrb_tax,
					'hide_empty' => false,
					'orderby'    => 'name',
					'order'      => 'ASC',
					'number'     => 0, //Returns all
				)
		);

		if( $cat_terms ) :
			$table_body = '<tbody>';
			foreach( $cat_terms as $term ) :
				$termPriceSet 	 = get_post_meta( $thePostID, 'brand_price_' . esc_html( $term->term_id ), true );
				$termPriceStatus = get_post_meta( $thePostID, 'brand_status_' . esc_html( $term->term_id ), true );

				$checked = ( $termPriceStatus == 'inactive' ) ? '' : 'checked';

				$thePrice = ( empty( $termPriceSet ) ) ? $thePrice : $termPriceSet;
				$thePrice = ( empty( $thePrice ) ) ? '0.00' : $thePrice;

				$table_body .= '<tr>';
				$table_body .= '<td><input type="hidden" name="brand_id[]" value="' . esc_html( $term->term_id ) . '" /> ' . esc_html( $term->term_id ) . '</td>';
				$table_body .= '<td> ' . $term->name . '</td>';
				$table_body .= '<td><input type="number" class="regular-text" name="brand_price[]" step="any" value="'.esc_attr( $thePrice ). '" /></td>';
				$table_body .= '<td><input type="checkbox" name="brand_status[]" value="' . esc_html( $term->term_id ) . '" ' . esc_attr( $checked ) . ' /></td>';
				$table_body .= '</tr>';
			endforeach;
			$table_body .= '<tbody>';
		endif;

		if ( isset( $table_body ) ) {
			$output .= $table_head;
			$output .= $table_body;
			$output .= $table_foot;
		} else {
			$output .= esc_html__( 'Add some', 'computer-repair-shop' ) .' ' . $wc_device_brand_label_plural . esc_html__( 'to set prices', 'computer-repair-shop' )  . 
			'<a target="_blank" href="edit-tags.php?taxonomy=device_brand&post_type=rep_devices">'. esc_html__( 'Add some', 'computer-repair-shop' ) . ' ' . $wc_device_brand_label_plural .'</a>';
		}

		$output .= '</div></li>';
			
		return $output;
	}
	
	function return_device_accordion_price( $thePostID ) {
		if ( empty( $thePostID ) ) {
			return '';
		}

		$wc_device_label_plural = ( empty( get_option( 'wc_device_label_plural' ) ) ) ? esc_html__( 'Device', 'computer-repair-shop' ) : get_option( 'wc_device_label_plural' );
		$thePrice = get_post_meta( $thePostID, '_cost', true );
		
		$output = '<li class="accordion-item" data-accordion-item>';
		$output .= '<a href="#" class="accordion-title">';
		$output .= esc_html__( 'Set price by ', 'computer-repair-shop' ) . ' ' . $wc_device_label_plural;		
		$output .= '</a>';

		$output .= '<div class="accordion-content" data-tab-content>';
		
		$output .= esc_html__( 'You may update manufacutre or type prices to apply to related devices as well.', 'computer-repair-shop' );
		
		$output .= '<div class="button-right"><button id="WCRB_submit_device_prices" data-job-id="' . esc_html( $thePostID ) . '" 
		class="button button-primary button-large preview">' . esc_html__( 'Update Prices', 'computer-repair-shop' ) . '</button></div>';

		$table_head = '<table class="wp-list-table widefat fixed striped posts reloadthedevices"><thead>';
		$table_head .= '<tr>';
		$table_head .= '<th class="id_head">' . esc_html__( 'ID', 'computer-repair-shop' ) . '</th>';
		$table_head .= '<th>' . esc_html__( 'Name', 'computer-repair-shop' ) . '</th>';
		$table_head .= '<th class="price_head">' . esc_html__( 'Price', 'computer-repair-shop' ) . '</th>';
		$table_head .= '<th class="action_head">' . esc_html__( 'Active', 'computer-repair-shop' ) . '</th>';
		$table_head .= '</th>';
		$table_head .= '</thead>';

		$table_foot = '</table>';

		$wcrb_type = 'rep_devices';
		$wcrb_tax  = 'device_brand';

		$device_args = array(
			'post_type' 		=> $wcrb_type,
			'orderby'			=> 'title',
			'order' 			=> 'ASC',
			'posts_per_page' 	=> -1,
		);

		$device_query = new WP_Query( $device_args );

		if ( $device_query->have_posts() ) { 
			$table_body = '<tbody>';
			while( $device_query->have_posts() ) {
				$device_query->the_post();

				$device_id 	  = $device_query->post->ID;
				$device_title  = get_the_title();

				$termPriceSet = $this->get_price_by_device_for_service( $device_id, $thePostID );
				$termPriceStatus = get_post_meta( $thePostID, 'device_status_' . esc_html( $device_id ), true );

				$checked = ( $termPriceStatus == 'inactive' ) ? '' : 'checked';

				$thePrice = ( empty( $termPriceSet ) ) ? '0.00' : $termPriceSet;

				$table_body .= '<tr>';
				$table_body .= '<td><input type="hidden" name="device_id[]" value="' . esc_html( $device_id ) . '" /> ' . esc_html( $device_id ) . '</td>';
				$table_body .= '<td> ' . esc_html( $device_title ) . '</td>';
				$table_body .= '<td><input type="number" class="regular-text" name="device_price[]" step="any" value="'.esc_attr( $thePrice ). '" /></td>';
				$table_body .= '<td><input type="checkbox" name="device_status[]" value="' . esc_html( $device_id ) . '" ' . esc_attr( $checked ) . ' /></td>';
				$table_body .= '</tr>';
			}
			$table_body .= '<tbody>';
		}
		if ( isset( $table_body ) ) {
			$output .= $table_head;
			$output .= $table_body;
			$output .= $table_foot;
		} else {
			$output .= esc_html__( 'Add some', 'computer-repair-shop' ) .' ' . $wc_device_label_plural . esc_html__( 'to set prices', 'computer-repair-shop' )  . 
			'<a target="_blank" href="edit.php?post_type=rep_devices">'. esc_html__( 'Add some', 'computer-repair-shop' ) . ' ' . $wc_device_label_plural .'</a>';
		}
		$output .= '</div></li>';
			
		return $output;
	}

	function get_price_by_device_for_service( $device_id, $service_id ) {
		if ( empty( $device_id ) || empty( $service_id ) ) {
			return '';
		}
		$_default_price = get_post_meta( $service_id, '_cost', true );

		//Get Types if not manufactures
		$type_list = wp_get_post_terms( $device_id, 'device_type', array( 'fields' => 'ids' ) );

		if ( ! empty( $type_list ) ) {
			if ( is_array( $type_list ) ) {
				foreach( $type_list as $type_id ) {
					$termPriceSet = get_post_meta( $service_id, 'type_price_' . esc_html( $type_id ), true );
				}
			}
		}
		if ( ! empty( $termPriceSet ) ) {
			$_default_price = $termPriceSet;
		}

		//Get Manufactures
		$manufactures_list = wp_get_post_terms( $device_id, 'device_brand', array( 'fields' => 'ids' ) );

		if ( ! empty( $manufactures_list ) ) {
			if ( is_array( $manufactures_list ) ) {
				foreach( $manufactures_list as $manufacture_id ) {
					$termPriceSet = get_post_meta( $service_id, 'brand_price_' . esc_html( $manufacture_id ), true );
				}
			}
		}
		if ( ! empty( $termPriceSet ) ) {
			$_default_price = $termPriceSet;
		}

		//Get Device price
		$termPriceSet = get_post_meta( $service_id, 'device_price_' . esc_html( $device_id ), true );

		if ( ! empty( $termPriceSet ) ) {
			$_default_price = $termPriceSet;
		}

		return $_default_price;
	}

	function wc_rb_update_the_prices() {
		$message = '';
		$success = 'NO';

		if ( ! isset( $_POST['wcrb_nonce_setting_device_field'] ) || ! wp_verify_nonce( $_POST['wcrb_nonce_setting_device_field'], 'wcrb_nonce_setting_device' ) ) {
			if( count($_POST, COUNT_RECURSIVE) >= ini_get("max_input_vars") ) {
				$message = esc_html__( 'You are trying to post ', 'computer-repair-shop' ) . count($_POST, COUNT_RECURSIVE) . ' ' . esc_html__( 'while your server allows max_input_vars ', 'computer-repair-shop' ) . ini_get("max_input_vars");
			} else {
				$message = esc_html__( 'Couldn\'t verify nonce please reload pages.', 'computer-repair-shop' );				
			}
		} else {
			$service_id = ( isset( $_POST['wcrb_job_id'] ) && ! empty( $_POST['wcrb_job_id'] ) ) ? sanitize_text_field( $_POST['wcrb_job_id'] ) : '';

			if ( empty( $service_id ) ) {
				$message = esc_html__( 'Service could not identified', 'computer-repair-shop' );
			} else {
				$preparedArray = array();

				if ( isset( $_POST['type_id'] ) ) {
					for ( $i = 0; $i < count( $_POST['type_id'] ); $i++) {
						$preparedArray[$i]['typeid'] = $type_id = ( ! empty( $_POST['type_id'][$i] ) ) ? sanitize_text_field( $_POST['type_id'][$i]['value'] ) : '';
						$preparedArray[$i]['typeprice'] = ( ! empty( $_POST['type_price'][$i] ) ) ? sanitize_text_field( $_POST['type_price'][$i]['value'] ) : '';

						$preparedArray[$i]['typestatus'] = 'inactive';
						foreach( $_POST['type_status'] as $typeStatus  ) {
							if ( $typeStatus['value'] == $type_id ) {
								$preparedArray[$i]['typestatus'] = 'active';
							}
						}//EndForEach
					}//EndFor

					if ( ! empty( $preparedArray ) ) {
						if ( is_array( $preparedArray ) ) {
							foreach( $preparedArray as $prepared ) {
								$ARtypeid     = $prepared['typeid'];
								$ARtypeprice  = $prepared['typeprice'];
								$ARtypestatus = $prepared['typestatus'];

								update_post_meta( $service_id, 'type_price_' . $ARtypeid, $ARtypeprice );
								update_post_meta( $service_id, 'type_status_' . $ARtypeid, $ARtypestatus );
							}
						}
					}
				} elseif ( isset( $_POST['brand_id'] ) ) {
					for ( $i = 0; $i < count( $_POST['brand_id'] ); $i++) {
						$preparedArray[$i]['brandid'] = $brand_id = ( ! empty( $_POST['brand_id'][$i] ) ) ? sanitize_text_field( $_POST['brand_id'][$i]['value'] ) : '';
						$preparedArray[$i]['brandprice'] = ( ! empty( $_POST['brand_price'][$i] ) ) ? sanitize_text_field( $_POST['brand_price'][$i]['value'] ) : '';
	
						$preparedArray[$i]['brandstatus'] = 'inactive';
						foreach( $_POST['brand_status'] as $brandStatus  ) {
							if ( $brandStatus['value'] == $brand_id ) {
								$preparedArray[$i]['brandstatus'] = 'active';
							}
						}//EndForEach
					}//EndFor
	
					if ( ! empty( $preparedArray ) ) {
						if ( is_array( $preparedArray ) ) {
							foreach( $preparedArray as $prepared ) {
								$ARbrandid     = $prepared['brandid'];
								$ARbrandprice  = $prepared['brandprice'];
								$ARbrandstatus = $prepared['brandstatus'];
	
								update_post_meta( $service_id, 'brand_price_' . $ARbrandid, $ARbrandprice );
								update_post_meta( $service_id, 'brand_status_' . $ARbrandid, $ARbrandstatus );
							}
						}
					}
				} elseif ( isset( $_POST['device_id'] ) ) {
					for ( $i = 0; $i < count( $_POST['device_id'] ); $i++) {
						$preparedArray[$i]['deviceid'] = $device_id = ( ! empty( $_POST['device_id'][$i] ) ) ? sanitize_text_field( $_POST['device_id'][$i]['value'] ) : '';
						$preparedArray[$i]['deviceprice'] = ( ! empty( $_POST['device_price'][$i] ) ) ? sanitize_text_field( $_POST['device_price'][$i]['value'] ) : '';
	
						$preparedArray[$i]['devicestatus'] = 'inactive';
						foreach( $_POST['device_status'] as $deviceStatus  ) {
							if ( $deviceStatus['value'] == $device_id ) {
								$preparedArray[$i]['devicestatus'] = 'active';
							}
						}//EndForEach
					}//EndFor
	
					if ( ! empty( $preparedArray ) ) {
						if ( is_array( $preparedArray ) ) {
							foreach( $preparedArray as $prepared ) {
								$ARdeviceid     = $prepared['deviceid'];
								$ARdeviceprice  = $prepared['deviceprice'];
								$ARdevicestatus = $prepared['devicestatus'];
	
								update_post_meta( $service_id, 'device_price_' . $ARdeviceid, $ARdeviceprice );
								update_post_meta( $service_id, 'device_status_' . $ARdeviceid, $ARdevicestatus );
							}
						}
					}
				}
				$message = esc_html__( 'Settings updated!', 'computer-repair-shop' );
			}
		}

		$values['message'] = $message;
		$values['success'] = $success;

		wp_send_json( $values );
		wp_die();
	}

	function return_device_type_accordion_price_front( $thePostID ) {
		if ( empty( $thePostID ) ) {
			return '';
		}
		$status = '';

		$wc_device_type_label_plural = ( empty( get_option( 'wc_device_type_label_plural' ) ) ) ? esc_html__( 'Device Type', 'computer-repair-shop' ) : get_option( 'wc_device_type_label_plural' );
		$thePrice = get_post_meta( $thePostID, '_cost', true );
		
		$output = '<li class="accordion-item" data-accordion-item>';
		$output .= '<a href="#" class="accordion-title">';
		$output .= esc_html__( 'Price by ', 'computer-repair-shop' ) . ' ' . $wc_device_type_label_plural;		
		$output .= '</a>';

		$output .= '<div class="accordion-content" data-tab-content>';
		
		$table_head = '<table class="wp-list-table widefat fixed striped posts"><thead>';
		$table_head .= '<tr>';
		$table_head .= '<th>' . esc_html__( 'Name', 'computer-repair-shop' ) . '</th>';
		$table_head .= '<th class="price_head textright">' . esc_html__( 'Price', 'computer-repair-shop' ) . '</th>';
		$table_head .= '</th>';
		$table_head .= '</thead>';

		$table_foot = '</table>';

		$wcrb_type = 'rep_devices';
		$wcrb_tax  = 'device_type';

		$cat_terms = get_terms(
			array(
					'taxonomy'	 => $wcrb_tax,
					'hide_empty' => false,
					'orderby'    => 'name',
					'order'      => 'ASC',
					'number'     => 0, //Returns all
				)
		);

		if( $cat_terms ) :
			$table_body = '<tbody>';
			foreach( $cat_terms as $term ) :
				$termPriceSet 	 = get_post_meta( $thePostID, 'type_price_' . esc_html( $term->term_id ), true );
				$termPriceStatus = get_post_meta( $thePostID, 'type_status_' . esc_html( $term->term_id ), true );

				$checked = ( $termPriceStatus == 'inactive' ) ? '' : 'checked';

				$thePrice = ( empty( $termPriceSet ) ) ? $thePrice : $termPriceSet;
				$thePrice = ( empty( $thePrice ) ) ? '0.00' : $thePrice;

				if ( $checked == 'checked' ) :
					$status = 'YES';
					$table_body .= '<tr>';
					$table_body .= '<td> ' . esc_html( $term->name ) . '</td>';
					$table_body .= '<td class="textright">' . wc_cr_currency_format( $thePrice, TRUE ) . '</td>';
					$table_body .= '</tr>';
				endif;
			endforeach;
			$table_body .= '<tbody>';
		endif;

		if ( isset( $table_body ) ) {
			$output .= $table_head;
			$output .= $table_body;
			$output .= $table_foot;
		}
		$output .= '</div></li>';

		return ( $status == 'YES' ) ? $output : '';
	}

	function return_device_brand_accordion_price_front( $thePostID ) {
		if ( empty( $thePostID ) ) {
			return '';
		}

		$status = '';

		$wc_device_brand_label_plural = ( empty( get_option( 'wc_device_brand_label_plural' ) ) ) ? esc_html__( 'Device Brand', 'computer-repair-shop' ) : get_option( 'wc_device_brand_label_plural' );
		$thePrice = get_post_meta( $thePostID, '_cost', true );
		
		$output = '<li class="accordion-item" data-accordion-item>';
		$output .= '<a href="#" class="accordion-title">';
		$output .= esc_html__( 'Price by ', 'computer-repair-shop' ) . ' ' . $wc_device_brand_label_plural;		
		$output .= '</a>';

		$output .= '<div class="accordion-content" data-tab-content>';

		$table_head = '<table class="wp-list-table widefat fixed striped posts"><thead>';
		$table_head .= '<tr>';
		$table_head .= '<th>' . esc_html__( 'Name', 'computer-repair-shop' ) . '</th>';
		$table_head .= '<th class="price_head textright">' . esc_html__( 'Price', 'computer-repair-shop' ) . '</th>';
		$table_head .= '</th>';
		$table_head .= '</thead>';

		$table_foot = '</table>';

		$wcrb_type = 'rep_devices';
		$wcrb_tax  = 'device_brand';

		$cat_terms = get_terms(
			array(
					'taxonomy'	 => $wcrb_tax,
					'hide_empty' => false,
					'orderby'    => 'name',
					'order'      => 'ASC',
					'number'     => 0, //Returns all
				)
		);

		if( $cat_terms ) :
			$table_body = '<tbody>';
			foreach( $cat_terms as $term ) :
				$termPriceSet 	 = get_post_meta( $thePostID, 'brand_price_' . esc_html( $term->term_id ), true );
				$termPriceStatus = get_post_meta( $thePostID, 'brand_status_' . esc_html( $term->term_id ), true );

				$checked = ( $termPriceStatus == 'inactive' ) ? '' : 'checked';

				$thePrice = ( empty( $termPriceSet ) ) ? $thePrice : $termPriceSet;
				$thePrice = ( empty( $thePrice ) ) ? '0.00' : $thePrice;

				if ( $checked == 'checked' ) :
					$status = 'YES';
					$table_body .= '<tr>';
					$table_body .= '<td> ' . $term->name . '</td>';
					$table_body .= '<td class="textright">'.wc_cr_currency_format( $thePrice ). '</td>';
					$table_body .= '</tr>';
				endif;
			endforeach;
			$table_body .= '<tbody>';
		endif;

		if ( isset( $table_body ) ) {
			$output .= $table_head;
			$output .= $table_body;
			$output .= $table_foot;
		}
		$output .= '</div></li>';
		
		return ( $status == 'YES' ) ? $output : '';
	}
	
	function return_device_accordion_price_front( $thePostID ) {
		if ( empty( $thePostID ) ) {
			return '';
		}
		$status = '';

		$wc_device_label_plural = ( empty( get_option( 'wc_device_label_plural' ) ) ) ? esc_html__( 'Device', 'computer-repair-shop' ) : get_option( 'wc_device_label_plural' );
		$thePrice = get_post_meta( $thePostID, '_cost', true );
		
		$output = '<li class="accordion-item" data-accordion-item>';
		$output .= '<a href="#" class="accordion-title">';
		$output .= esc_html__( 'Set price by ', 'computer-repair-shop' ) . ' ' . $wc_device_label_plural;		
		$output .= '</a>';

		$output .= '<div class="accordion-content" data-tab-content>';
		
		$table_head = '<table class="wp-list-table widefat fixed striped posts reloadthedevices"><thead>';
		$table_head .= '<tr>';
		$table_head .= '<th>' . esc_html__( 'Name', 'computer-repair-shop' ) . '</th>';
		$table_head .= '<th class="price_head textright">' . esc_html__( 'Price', 'computer-repair-shop' ) . '</th>';
		$table_head .= '</th>';
		$table_head .= '</thead>';

		$table_foot = '</table>';

		$wcrb_type = 'rep_devices';
		$wcrb_tax  = 'device_brand';

		$device_args = array(
			'post_type' 		=> $wcrb_type,
			'orderby'			=> 'title',
			'order' 			=> 'ASC',
			'posts_per_page' 	=> -1,
		);

		$device_query = new WP_Query( $device_args );

		if ( $device_query->have_posts() ) { 
			$table_body = '<tbody>';
			while( $device_query->have_posts() ) {
				$device_query->the_post();

				$device_id 	  = $device_query->post->ID;
				$device_title  = get_the_title();

				$termPriceSet = $this->get_price_by_device_for_service( $device_id, $thePostID );
				$termPriceStatus = get_post_meta( $thePostID, 'device_status_' . esc_html( $device_id ), true );

				$checked = ( $termPriceStatus == 'inactive' ) ? '' : 'checked';

				$thePrice = ( empty( $termPriceSet ) ) ? '0.00' : $termPriceSet;
				if ( $checked == 'checked' ) :
					$status = 'YES';
					$table_body .= '<tr>';
					$table_body .= '<td> ' . esc_html( $device_title ) . '</td>';
					$table_body .= '<td class="textright">' . wc_cr_currency_format( $thePrice ) . '</td>';
					$table_body .= '</tr>';
				endif;
			}
			$table_body .= '<tbody>';
		}
		if ( isset( $table_body ) ) {
			$output .= $table_head;
			$output .= $table_body;
			$output .= $table_foot;
		}
		$output .= '</div></li>';
		
		return ( $status == 'YES' ) ? $output : '';
	}

	function return_price_range_of_service( $service_id ) {
		if ( empty( $service_id ) ) {
			return '';
		}

		$highPrice = $lowPrice = get_post_meta( $service_id, '_cost', true );

		//Get prices by types.
		$wcrb_tax  = 'device_type';

		$cat_terms = get_terms(
			array(
					'taxonomy'	 => $wcrb_tax,
					'hide_empty' => false,
					'orderby'    => 'name',
					'order'      => 'ASC',
					'number'     => 0, //Returns all
				)
		);

		if( $cat_terms ) :
			foreach( $cat_terms as $term ) :
				$termPriceSet 	 = get_post_meta( $service_id, 'type_price_' . esc_html( $term->term_id ), true );
				$termPriceStatus = get_post_meta( $service_id, 'type_status_' . esc_html( $term->term_id ), true );

				$checked = ( $termPriceStatus == 'inactive' ) ? '' : 'checked';

				$thePrice = ( empty( $termPriceSet ) ) ? '0.00' : $termPriceSet;

				if ( $checked == 'checked' ) :
					if ( $thePrice < $lowPrice ) {
						$lowPrice = ( $thePrice > 0 ) ? $thePrice : $lowPrice;
					}
					if ( $thePrice > $highPrice ) {
						$highPrice = ( $thePrice > 0 ) ? $thePrice : $highPrice;
					}
				endif;
			endforeach;
		endif;

		//Get prices by brands.
		$wcrb_type = 'rep_devices';
		$wcrb_tax  = 'device_brand';

		$cat_terms = get_terms(
			array(
					'taxonomy'	 => $wcrb_tax,
					'hide_empty' => false,
					'orderby'    => 'name',
					'order'      => 'ASC',
					'number'     => 0, //Returns all
				)
		);

		if( $cat_terms ) :
			foreach( $cat_terms as $term ) :
				$termPriceSet 	 = get_post_meta( $service_id, 'brand_price_' . esc_html( $term->term_id ), true );
				$termPriceStatus = get_post_meta( $service_id, 'brand_status_' . esc_html( $term->term_id ), true );

				$checked = ( $termPriceStatus == 'inactive' ) ? '' : 'checked';

				$thePrice = ( empty( $termPriceSet ) ) ? '0.00' : $termPriceSet;

				if ( $checked == 'checked' ) :
					if ( $thePrice < $lowPrice ) {
						$lowPrice = ( $thePrice > 0 ) ? $thePrice : $lowPrice;
					}
					if ( $thePrice > $highPrice ) {
						$highPrice = ( $thePrice > 0 ) ? $thePrice : $highPrice;
					}
				endif;
			endforeach;
		endif;


		//Get prices by device. 
		$wcrb_type = 'rep_devices';
		$wcrb_tax  = 'device_brand';

		$device_args = array(
			'post_type' 		=> $wcrb_type,
			'orderby'			=> 'title',
			'order' 			=> 'ASC',
			'posts_per_page' 	=> -1,
		);

		$device_query = new WP_Query( $device_args );

		if ( $device_query->have_posts() ) { 
			while( $device_query->have_posts() ) {
				$device_query->the_post();
				$device_id 	  = $device_query->post->ID;

				$termPriceSet = $this->get_price_by_device_for_service( $device_id, $service_id );
				$termPriceStatus = get_post_meta( $service_id, 'device_status_' . esc_html( $device_id ), true );

				$checked = ( $termPriceStatus == 'inactive' ) ? '' : 'checked';

				$thePrice = ( empty( $termPriceSet ) ) ? '0.00' : $termPriceSet;
				if ( $checked == 'checked' ) :
					if ( $thePrice < $lowPrice ) {
						$lowPrice = ( $thePrice > 0 ) ? $thePrice : $lowPrice;
					}
					if ( $thePrice > $highPrice ) {
						$highPrice = ( $thePrice > 0 ) ? $thePrice : $highPrice;
					}
				endif;
			}
		}
		
		wp_reset_postdata();

		if ( $highPrice == $lowPrice ) {
			return wc_cr_currency_format( $highPrice );
		} else {
			if ( $highPrice > $lowPrice ) {
				return wc_cr_currency_format( $lowPrice ) . ' - ' . wc_cr_currency_format( $highPrice );
			} else {
				return wc_cr_currency_format( $lowPrice );
			}
		}
	}

	function return_service_html_by_device( $device_id ) {
		if ( empty( $device_id ) ) {
			return '';
		}
		$service_block = '<div class="grid-x grid-margin-x grid-margin-y margintopthirty">';

		$service_arg = array(
			'post_type' 		=> 'rep_services',
			'orderby'			=> 'title',
			'order' 			=> 'ASC',
			'posts_per_page' 	=> -1,
		);

		$service_query = new WP_Query( $service_arg );

		if ( $service_query->have_posts() ) { 
			while ( $service_query->have_posts() ) {
				$service_query->the_post();
				$service_id = $service_query->post->ID;

				$termPriceStatus = get_post_meta( $service_id, 'device_status_' . esc_html( $device_id ), true );

				$device_status = ( $termPriceStatus == 'inactive' ) ? '' : 'checked';

				//Get Types if not manufactures
				$type_list = wp_get_post_terms( $device_id, 'device_type', array( 'fields' => 'ids' ) );

				$type_status = '';
				if ( ! empty( $type_list ) ) {
					if ( is_array( $type_list ) ) {
						foreach( $type_list as $type_id ) {
							$termTypeStatus = get_post_meta( $service_id, 'type_status_' . esc_html( $type_id ), true );

							$type_status = ( $termTypeStatus == 'inactive' ) ? '' : 'checked';
						}
					}
				}

				//Get brand if not manufactures
				$brand_list = wp_get_post_terms( $device_id, 'device_brand', array( 'fields' => 'ids' ) );

				$brand_status = '';
				if ( ! empty( $brand_list ) ) {
					if ( is_array( $brand_list ) ) {
						foreach( $brand_list as $brand_id ) {
							$termBrandStatus = get_post_meta( $service_id, 'brand_status_' . esc_html( $brand_id ), true );

							$brand_status = ( $termBrandStatus == 'inactive' ) ? '' : 'checked';
						}
					}
				}
				//pass device id and service id

				if ( $type_status != 'checked' ) :
					$device_status = $brand_status = '';
				endif;
				if ( $brand_status != 'checked' ) :
					$device_status = '';
				endif;
				if ( $device_status == 'checked' ) :
					$deviceprice = $this->get_price_by_device_for_service( $device_id, $service_id );
					
					$linkForbooking = esc_url( add_query_arg( 'device_id', $device_id, get_permalink($service_id) ) );;

					$service_block .= '<div class="cell large-4 medium-4 small-12">';

					$service_block .= '<div class="wcrb_dev_service_wrap">';

					$service_block .= '<div class="wcrb_dev_service_head">';
					$service_block .= '<div class="imageWrap">';
					$thumbnail = get_the_post_thumbnail_url( $service_id );
					$service_block .= ( ! empty( $thumbnail ) ) ? '<a href="' . $linkForbooking . '"><img src="' . $thumbnail . '" /></a>' : '';
					$service_block .= '</div>';
					$service_block .= '<h3><a href="' . $linkForbooking . '">' . get_the_title( $service_id ) . '</a></h3>';
					$service_block .= '</div><!-- Head ends /-->';

					$service_block .= '<div class="wcrb_dev_price_tag">';
					$service_block .= '<a href="' . $linkForbooking . '">';
					$service_block .= wc_cr_currency_format( $deviceprice, TRUE );
					$service_block .= '</a>';
					$service_block .= '</div><!-- Price Tag ends /-->';

					$service_block .= '</div><!-- Service wrap ends /-->';

					$service_block .= '</div><!-- End column /-->';
				endif;
			}//Endwhile
		}//Endif

		$service_block .= '</div><!-- End grid x /-->';

		return $service_block;
	}
}