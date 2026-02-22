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

class WCRB_TAXES {

	private $TABID = "wc_rb_manage_taxes";

	function __construct() {
        add_action( 'wc_rb_settings_tab_menu_item', array( $this, 'add_tax_tab_in_settings_menu' ), 10, 2 );
        add_action( 'wc_rb_settings_tab_body', array( $this, 'add_tax_tab_in_settings_body' ), 10, 2 );
		add_action( 'wp_ajax_wc_post_taxes', array( $this, 'wc_post_taxes' ) );

		add_action( 'wp_ajax_wc_rb_update_tax_settings', array( $this, 'wc_rb_update_tax_settings' ) );

		add_action( 'admin_init', array( $this, 'wc_rb_update_existing_tax_states' ) );
    }

	function add_tax_tab_in_settings_menu() {
        $active = '';

        $menu_output = '<li class="tabs-title' . esc_attr( $active ) . '" role="presentation">';
        $menu_output .= '<a href="#' . esc_attr( $this->TABID ) . '" role="tab" aria-controls="' . esc_attr( $this->TABID ) . '" aria-selected="true" id="' . esc_attr( $this->TABID ) . '-label">';
        $menu_output .= '<h2>' . esc_html__( 'Manage Taxes', 'computer-repair-shop' ) . '</h2>';
        $menu_output .=	'</a>';
        $menu_output .= '</li>';

        echo wp_kses_post( $menu_output );
    }
	
	function add_tax_tab_in_settings_body() {
		global $wpdb;

		$computer_repair_taxes 	= $wpdb->prefix.'wc_cr_taxes';

		//Use Taxes
		$wc_use_taxes = get_option( 'wc_use_taxes' );
		$usetaxes 	  = ( $wc_use_taxes == 'on' ) ? 'checked="checked"' : '';

		$wc_primary_tax			= get_option( 'wc_primary_tax' );
		$wc_prices_inclu_exclu  = get_option( 'wc_prices_inclu_exclu' );

        $active = '';
		
		$setting_body = '<div class="tabs-panel team-wrap' . esc_attr( $active ) . '" 
        id="' . esc_attr( $this->TABID ) . '" 
        role="tabpanel" 
        aria-hidden="true" 
        aria-labelledby="' . esc_attr( $this->TABID ) . '-label">';


		$setting_body .= '<p class="help-text"><a class="button button-primary button-small" data-open="taxFormReveal">';
		$setting_body .= esc_html__( 'Add New Tax', 'computer-repair-shop' );
		$setting_body .= '</a></p>';

		add_filter( 'admin_footer', array( $this, 'wc_add_tax_form' ) );

		$setting_body .= '<div id="poststuff_wrapper">';
		$setting_body .= '<table id="poststuff" class="wp-list-table widefat fixed striped posts">';
		$setting_body .= '<thead><tr>';
		$setting_body .= '<th class="column-id">' . esc_html__( 'ID', 'computer-repair-shop' ) . '</th>';
		$setting_body .= '<th>' . esc_html__( 'Name', 'computer-repair-shop' ) . '</th>';
		$setting_body .= '<th>' . esc_html__( 'Description', 'computer-repair-shop' ) . '</th>';
		$setting_body .= '<th>' . esc_html__( 'Rate (%)', 'computer-repair-shop' ) . '</th>';
		$setting_body .= '<th class="column-id">' . esc_html__( 'Status', 'computer-repair-shop' ) . '</th>';
		$setting_body .= '<th class="column-action">' . esc_html__( 'Actions', 'computer-repair-shop' ) . '</th>';
		$setting_body .= '</tr></thead><tbody>';

		$select_query 	= "SELECT * FROM `".$computer_repair_taxes."`";
		$select_results = $wpdb->get_results($select_query);
												
		$output = '';
		foreach($select_results as $result) {
												
			$output .= '<tr><td>'.$result->tax_id.'</td>';

			$output .= '<td><strong>'.$result->tax_name.'</strong></td>';
			$output .= '<td>'.$result->tax_description.'</td>';
			$output .= '<td>'.$result->tax_rate.'</td>';
			$output .= '<td>'.$result->tax_status.'</td>';
			$output .= '<td><a href="#" class="change_tax_status" data-type="tax" data-value="'.esc_attr($result->tax_id).'">'.esc_html__("Change Status", "computer-repair-shop").'</a></td></tr>';
		}
		$setting_body .= $output;
		$setting_body .= '</tbody></table></div><!-- Post Stuff/-->';

		$setting_body .= '<div class="wc-rb-grey-bg-box">';
		$setting_body .= '<h2>' . esc_html__( 'Tax Settings', 'computer-repair-shop' ) . '</h2>';
		$setting_body .= '<div class="' . esc_attr( $this->TABID ) . '"></div>';

		$setting_body .= '<form data-async data-abide class="needs-validation" novalidate method="post" data-success-class=".' . esc_attr( $this->TABID ) . '">';

		$setting_body .= '<table class="form-table border"><tbody>';

		$setting_body .= '<tr><th scope="row"><label for="wc_add_taxes">' . esc_html__( 'Enable Taxes', 'computer-repair-shop' ) . '</label></th>';
		$setting_body .= '<td><input type="checkbox" ' . esc_html__( $usetaxes ) . ' name="wc_use_taxes" id="wc_add_taxes" /></td></tr>';

		$setting_body .= '<tr><th scope="row"><label for="wc_primary_tax">' . esc_html__( 'Default Tax', 'computer-repair-shop' ) . '</label></th>';
		$setting_body .= '<td><select name="wc_primary_tax" id="wc_primary_tax" class="form-control">';
		$setting_body .= '<option value="">' . esc_html__( 'Select tax', 'computer-repair-shop' ) . '</option>';
		
		$theOptions = wc_generate_tax_options( $wc_primary_tax ); 
		$allowedHTML = array(
			"option" => array(
				"value" => array(),
				"selected" => array()
			),
		);

		$setting_body .= wp_kses( $theOptions, $allowedHTML );
		$setting_body .= '</select></td></tr>';

		$inclusive = ( $wc_prices_inclu_exclu == 'inclusive' ) ? ' selected' : '';
		$exclusive = ( $wc_prices_inclu_exclu == 'exclusive' ) ? ' selected' : '';

		$setting_body .= '<tr><th scope="row"><label for="wc_prices_inclu_exclu">' . esc_html__( 'Invoice Amounts Are', 'computer-repair-shop' ) . '</label></th>';
		$setting_body .= '<td><select name="wc_prices_inclu_exclu" id="wc_prices_inclu_exclu" class="form-control">';
		$setting_body .= '<option value="exclusive" ' . $exclusive . '>' . esc_html__( 'Exclusive of Tax', 'computer-repair-shop' ) . '</option>';
		$setting_body .= '<option value="inclusive" ' . $inclusive . '>' . esc_html__( 'Inclusive of Tax', 'computer-repair-shop' ) . '</option>';
		$setting_body .= '</select></td></tr>';

		$setting_body .= '</tbody></table>';

		$setting_body .= '<input type="hidden" name="form_type" value="wc_rb_update_sett_taxes" />';
		$setting_body .= wp_nonce_field( 'wcrb_nonce_setting_taxes', 'wcrb_nonce_setting_taxes_field', true, false );

		$setting_body .= '<button type="submit" class="button button-primary" data-type="rbssubmitdevices">' . esc_html__( 'Update Options', 'computer-repair-shop' ) . '</button></form>';

		$setting_body .= '</div><!-- wc rb Devices /-->';
		$setting_body .= '</div><!-- Tabs Panel /-->';

		$allowedHTML = ( function_exists( 'wc_return_allowed_tags' ) ) ? wc_return_allowed_tags() : '';
		echo wp_kses( $setting_body, $allowedHTML );
	}

	/***
	 * @since 2.5
	 * 
	 * Adds Tax form in footer.
	*/
	function wc_add_tax_form() { ?>
		<!-- Modal for Post Entry /-->
		<div class="small reveal" id="taxFormReveal" data-reveal>
			<h2><?php echo esc_html__("Add new tax", "computer-repair-shop"); ?></h2>
			<div class="form-message"></div>
		
			<form data-async data-abide class="needs-validation" name="tax_form_sync" novalidate method="post">
				<div class="grid-x grid-margin-x">
					<div class="cell">
						<div data-abide-error class="alert callout" style="display: none;">
							<p><i class="fi-alert"></i> There are some errors in your form.</p>
						</div>
					</div>
				</div>
		
				<!-- Login Form Starts /-->
				<div class="grid-x grid-margin-x">
					<div class="cell medium-6">
						<label><?php echo esc_html__("Tax Name", "computer-repair-shop"); ?>*
							<input name="tax_name" type="text" class="form-control login-field"
									value="" required id="tax_name"/>
							<span class="form-error">
								<?php echo esc_html__("Name of tax to recognize.", "computer-repair-shop"); ?>
							</span>
						</label>
					</div>
	
					<div class="cell medium-6">
						<label><?php echo esc_html__("Tax Description", "computer-repair-shop"); ?>
							<input name="tax_description" type="text" class="form-control login-field"
									value="" id="tax_description"/>
						</label>
					</div>
				</div>
		
				<div class="grid-x grid-margin-x">
					<div class="cell medium-6">
						<label><?php echo esc_html__("Tax Rate", "computer-repair-shop"); ?>*
							<input name="tax_rate" type="number" step="any" class="form-control login-field"
									value="" id="tax_rate" required/>
							<span class="form-error" style="display:block;">
								<?php echo esc_html__("Only numbers like 15 for 15% , 0 for 0%, 25 for 25%.", "computer-repair-shop"); ?>
							</span>
						</label>
					</div>
	
					<div class="cell medium-6">
						<label><?php echo esc_html__("Tax Status", "computer-repair-shop"); ?>
							<select class="form-control" name="tax_status">
								<option value="active"><?php echo esc_html__("Active", "computer-repair-shop"); ?>
								<option value="inactive"><?php echo esc_html__("Inactive", "computer-repair-shop"); ?>
							</select>
						</label>
					</div>
				</div>
				<!-- Login Form Ends /-->
		
				<!-- Login Form Ends /-->
				<input name="form_type" type="hidden" 
								value="tax_form" />
	
				<div class="grid-x grid-margin-x">
					<fieldset class="cell medium-6">
						<button class="button" type="submit"><?php echo esc_html__("Add Tax", "computer-repair-shop"); ?></button>
					</fieldset>
					<small>
						<?php echo esc_html__("(*) fields are required", "computer-repair-shop"); ?>
					</small>	
				</div>
			</form>
			<button class="close-button" data-close aria-label="Close modal" type="button"><span aria-hidden="true">&times;</span></button>
		</div>
	<?php
	}

	function wc_post_taxes() { 
		global $wpdb;

		$computer_repair_taxes 		= $wpdb->prefix.'wc_cr_taxes';

		$form_type 			= ( isset( $_POST["form_type"] ) && ! empty( $_POST["form_type"] ) ) ? sanitize_text_field( $_POST["form_type"] ) : '';
		$tax_name 			= ( isset( $_POST["tax_name"] ) && ! empty( $_POST["tax_name"] ) ) ? sanitize_text_field( $_POST["tax_name"] ) : '';
		$tax_description 	= ( isset( $_POST["tax_description"] ) && ! empty( $_POST["tax_description"] ) ) ? sanitize_text_field( $_POST["tax_description"] ) : '';
		$tax_rate 			= ( isset( $_POST["tax_rate"] ) && ! empty( $_POST["tax_rate"] ) ) ? sanitize_text_field( $_POST["tax_rate"] ) : '';
		$tax_status 		= ( isset( $_POST["tax_status"] ) && ! empty( $_POST["tax_status"] ) ) ? sanitize_text_field( $_POST["tax_status"] ) : '';

		if ( $form_type == 'tax_form' ) {
			//Process form
			if ( empty( $tax_name ) ) {
				$message = esc_html__( 'Tax name required', 'computer-repair-shop' );
			} elseif ( ! is_numeric( $tax_rate ) ) {
				$message = esc_html__( 'Tax rate is empty or not number', 'computer-repair-shop' );
			} else {
				$insert_query =  "INSERT INTO `{$computer_repair_taxes}` VALUES( NULL, %s, %s, %s, %s )";
					$wpdb->query(
						$wpdb->prepare( $insert_query,  $tax_name, $tax_description, $tax_rate, $tax_status)
				);
				$tax_id = $wpdb->insert_id;
				$message = esc_html__( 'You have added tax rate.', 'computer-repair-shop' );
			}
		} else {
			$message = esc_html__( 'Invalid Form', 'computer-repair-shop' );	
		}

		$values['message'] = $message;
		$values['success'] = "YES";

		wp_send_json($values);
		wp_die();
	}

	function wc_rb_update_tax_settings() {
		$message = '';
		$success = 'NO';

		if ( ! isset( $_POST['wcrb_nonce_setting_taxes_field'] ) || ! wp_verify_nonce( sanitize_key( $_POST['wcrb_nonce_setting_taxes_field'] ), 'wcrb_nonce_setting_taxes' ) ) {
			$message = esc_html__( 'Couldn\'t verify nonce please reload page.', 'computer-repair-shop' );
		} else {
			// process form data
			$wc_primary_tax	= ( ! isset( $_POST['wc_primary_tax'] ) ) ? "" : sanitize_text_field( $_POST['wc_primary_tax'] );
			$wc_use_taxes 	= ( ! isset( $_POST['wc_use_taxes'] ) ) ? "" : sanitize_text_field( $_POST['wc_use_taxes'] );
			$wc_prices_inclu_exclu = ( ! isset( $_POST['wc_prices_inclu_exclu'] ) ) ? "" : sanitize_text_field( $_POST['wc_prices_inclu_exclu'] );

			update_option( 'wc_primary_tax', $wc_primary_tax );
			update_option( 'wc_use_taxes', $wc_use_taxes );
			update_option( 'wc_prices_inclu_exclu', $wc_prices_inclu_exclu );

			$message = esc_html__( 'Settings updated!', 'computer-repair-shop' );
		}

		$values['message'] = $message;
		$values['success'] = $success;

		wp_send_json( $values );
		wp_die();
	}

	function wc_rb_update_existing_tax_states() {
		$current_state = get_option( 'update_tax_states' );

		if ( $current_state != 'YES' ) : 
			$post_query = array(
					'posts_per_page' => -1,
					'post_type'      => 'rep_jobs',
			);
			$jobs_query = new WP_Query( $post_query );
		
			if ( $jobs_query->have_posts() ): 
				while( $jobs_query->have_posts() ): 
					$jobs_query->the_post();
					$job_id 		= $jobs_query->post->ID;

					$current_tax_type = get_post_meta( $job_id, '_wc_prices_inclu_exclu', TRUE );

					if ( $current_tax_type != 'exclusive' || $current_tax_type != 'inclusive' ) {
						update_post_meta( $job_id, '_wc_prices_inclu_exclu', 'exclusive' );

						$name		   = esc_html__( 'Invoice Amounts are set to', 'computer-repair-shop' );
						$change_detail = esc_html__( 'Tax exclusive', 'computer-repair-shop' );
						//Update job history
						$args = array(
							"job_id" 		=> $job_id, 
							"name" 			=> $name, 
							"type" 			=> 'public', 
							"field" 		=> '_wc_prices_inclu_exclu', 
							"change_detail" => $change_detail
						);
						$WCRB_JOB_HISTORY_LOGS = WCRB_JOB_HISTORY_LOGS::getInstance();
						$WCRB_JOB_HISTORY_LOGS->wc_record_job_history( $args );
					}
				endwhile;
			endif;

			update_option( 'update_tax_states', 'YES' );
		endif;
	}
}