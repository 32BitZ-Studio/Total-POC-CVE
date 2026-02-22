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

class WCRB_STYLING {
	private $TABID = "wcrb_styling";

	function __construct() {
        add_action( 'wc_rb_settings_tab_menu_item', array( $this, 'add_wcrb_stylings_menu' ), 10, 2 );
        add_action( 'wc_rb_settings_tab_body', array( $this, 'add_wcrb_styling_body' ), 10, 2 );
		add_action( 'wp_ajax_wcrb_submit_styling_settings', array( $this, 'wcrb_submit_styling_settings' ) );

		add_action( 'admin_head', array( $this, 'wcrb_enque_admin_custom_styles' ) );
		add_action( 'wp_head', array( $this, 'wcrb_enque_front_custom_styles' ) );
    }

	function add_wcrb_stylings_menu() {
        $active = '';

        $menu_output = '<li class="tabs-title' . esc_attr( $active ) . '" role="presentation">';
        $menu_output .= '<a href="#' . esc_attr( $this->TABID ) . '" role="tab" aria-controls="' . esc_attr( $this->TABID ) . '" aria-selected="true" id="' . esc_attr( $this->TABID ) . '-label">';
        $menu_output .= '<h2>' . esc_html__( 'Styling', 'computer-repair-shop' ) . '</h2>';
        $menu_output .=	'</a>';
        $menu_output .= '</li>';

        echo wp_kses_post( $menu_output );
    }
	
	function add_wcrb_styling_body() {
        $active = '';

		$setting_body = '<div class="tabs-panel team-wrap' . esc_attr( $active ) . '" 
        id="' . esc_attr( $this->TABID ) . '" 
        role="tabpanel" 
        aria-hidden="true" 
        aria-labelledby="' . esc_attr( $this->TABID ) . '-label">';

		$setting_body .= '<div class="wc-rb-manage-devices">';
		$setting_body .= '<h2>' . esc_html__( 'Styling', 'computer-repair-shop' ) . '</h2>';
		$setting_body .= '<div class="' . esc_attr( $this->TABID ) . '"></div>';
		$setting_body .= '<form data-async data-abide class="needs-validation" novalidate method="post" data-success-class=".' . esc_attr( $this->TABID ) . '">';

		$setting_body .= '<table class="form-table border"><tbody>';

		//Primary Color
		$wcrb_primary_color = get_option( 'wcrb_primary_color' );
		$wcrb_primary_color = ( empty( $wcrb_primary_color ) ) ? '#063e70' : $wcrb_primary_color;
		$setting_body .= '<tr><th scope="row"><label for="wcrb_primary_color">' . esc_html__( 'Primary Color ', 'computer-repair-shop' ) . '</label></th><td>';
		$setting_body .= '<input type="color" value="' . $wcrb_primary_color . '" id="wcrb_primary_color" class="form-control" name="wcrb_primary_color" />';
		$setting_body .= '</td></tr>';

		//Secondary Color
		$wcrb_secondary_color = get_option( 'wcrb_secondary_color' );
		$wcrb_secondary_color = ( empty( $wcrb_secondary_color ) ) ? '#fd6742' : $wcrb_secondary_color;
		$setting_body .= '<tr><th scope="row"><label for="wcrb_secondary_color">' . esc_html__( 'Secondary Color ', 'computer-repair-shop' ) . '</label></th><td>';
		$setting_body .= '<input type="color" value="' . $wcrb_secondary_color . '" id="wcrb_secondary_color" class="form-control" name="wcrb_secondary_color" />';
		$setting_body .= '</td></tr>';

		$setting_body .= '</tbody></table>';

		$setting_body .= '<input type="hidden" name="form_type" value="wcrb_update_settings" />';
		$setting_body .= '<input type="hidden" name="form_action" value="wcrb_submit_styling_settings" />';
		$setting_body .= wp_nonce_field( 'rbqb_nonce_styling', 'rbqb_nonce_styling_field', true, false );

		$setting_body .= '<button type="submit" class="button button-primary" data-type="rbssubmitdevices">' . esc_html__( 'Update Options', 'computer-repair-shop' ) . '</button></form>';

		$setting_body .= '</div><!-- wc rb Devices /-->';
		$setting_body .= '</div><!-- Tabs Panel /-->';

		$allowedHTML = ( function_exists( 'wc_return_allowed_tags' ) ) ? wc_return_allowed_tags() : '';
		echo wp_kses( $setting_body, $allowedHTML );
	}

	function wcrb_submit_styling_settings() {
		$message = '';
		$success = 'NO';

		if ( ! isset( $_POST['rbqb_nonce_styling_field'] ) || ! wp_verify_nonce( $_POST['rbqb_nonce_styling_field'], 'rbqb_nonce_styling' ) ) {
			$message = esc_html__( 'Couldn\'t verify nonce please reload page.', 'computer-repair-shop' );
		} else {
			// process form data
			$wcrb_secondary_color = ( ! isset( $_POST['wcrb_secondary_color'] ) ) ? '' : sanitize_text_field( $_POST['wcrb_secondary_color'] );
			$wcrb_primary_color = ( ! isset( $_POST['wcrb_primary_color'] ) ) ? '' : sanitize_text_field( $_POST['wcrb_primary_color'] );

			update_option( 'wcrb_primary_color', $wcrb_primary_color );
			update_option( 'wcrb_secondary_color', $wcrb_secondary_color );

			$message = esc_html__( 'Settings updated!', 'computer-repair-shop' );
		}
		$values['message'] = $message;
		$values['success'] = $success;

		wp_send_json( $values );
		wp_die();
	}

	public function wcrb_enque_front_custom_styles() {
		$wcrb_secondary_color = get_option( 'wcrb_secondary_color' );
		$wcrb_primary_color   = get_option( 'wcrb_primary_color' );

		?>
		<style type="text/css">
			<?php if ( ! empty( $wcrb_secondary_color ) ) : ?>
				.button.button-secondary,
				.wcCrJobHistoryHideShowBtn:hover,
				.wcCrJobHistoryHideShowBtn:focus {
					background-color:<?php echo esc_attr( $wcrb_secondary_color ); ?>;
				}
				.wc_rb_mb_head {
					background-color:<?php echo esc_attr( $wcrb_secondary_color ); ?>;
				}
				ul.dtypes_list li a.selected,
				ul.manufacture_list li a.selected,
				ul.manufacture_list li a.selected h3 {
					background-color:<?php echo esc_attr( $wcrb_secondary_color ); ?>;
				}
				.wcrbfd .wcrb_dashboard_section .wcrb_dan_item h3 {
					background-color:<?php echo esc_attr( $wcrb_secondary_color ); ?>;
				}
				.wcrbfd.computer-repair li.external-title > a:hover,
				.wcrbfd.computer-repair .tabs-title > a:hover,
				.wcrbfd.computer-repair .tabs-title > a:focus, 
				.wcrbfd.computer-repair .tabs-title > a[aria-selected='true'] {
					background-color:<?php echo esc_attr( $wcrb_secondary_color ); ?>;
				}
				.wcrb_widget_content .accordion-title {
					background-color:<?php echo esc_attr( $wcrb_secondary_color ); ?>;
				}
				.wcrb_dev_service_head .imageWrap {
					background-color:<?php echo esc_attr( $wcrb_secondary_color ); ?>;
				}
				.wcrb_close {
					background-color: <?php echo esc_attr( $wcrb_secondary_color ); ?>;
				}
			<?php endif; ?>

			<?php if ( ! empty( $wcrb_primary_color ) ) : ?>
				.button.button-primary,
				.note .typelabel {
					background-color: <?php echo esc_attr( $wcrb_primary_color ); ?>;
				}
				.wcCrJobHistoryHideShowBtn {
					background-color: <?php echo esc_attr( $wcrb_primary_color ); ?>;
				}
				.wcrbfd .wcrb_dashboard_section .wcrb_dan_item a:hover > h3 {
					background-color:<?php echo esc_attr( $wcrb_primary_color ); ?>;
				}
				.wcrbfd .wcrb_widget-12 .wcrb_title {
					color: <?php echo esc_attr( $wcrb_primary_color ); ?>;
				}
				.wcrbfd .thebluebg {
					background-color:<?php echo esc_attr( $wcrb_primary_color ); ?>;
				}
				.wcrb_widget_title h2 {
					background: <?php echo esc_attr( $wcrb_primary_color ); ?>;
				}
				.wcrb_widget_content .accordion-title:hover,
				.wcrb_widget_content .is-active>.accordion-title {
					background-color:<?php echo esc_attr( $wcrb_primary_color ); ?>;
				}
				h2.wc_service_booking_heading {
					background-color:<?php echo esc_attr( $wcrb_primary_color ); ?>;
				}
				.wcrb_service_thumb_price {
					background-color: <?php echo esc_attr( $wcrb_primary_color ); ?>;
				}
				.priceRangeWCRB {
					background-color: <?php echo esc_attr( $wcrb_primary_color ); ?>;
				}
				.wcrb_dev_service_head {
					background-color: <?php echo esc_attr( $wcrb_primary_color ); ?>;
				}
				.wcrb_close:hover {
					background-color: <?php echo esc_attr( $wcrb_primary_color ); ?>;
				}
			<?php endif; ?>
		</style>
		<?php
	}

	public function wcrb_enque_admin_custom_styles() {
		global $pagenow;

		$current_page = get_current_screen();
		$wc_the_page  = ( isset( $_GET['page'] ) ) ? sanitize_text_field( $_GET['page'] ) : "";

		if ( ( 'rep_jobs' === $current_page->post_type && ( 'post-new.php' === $pagenow || 'post.php' === $pagenow || 'edit.php' === $pagenow ) ) ||
			( 'rep_products' === $current_page->post_type && ( 'post-new.php' === $pagenow || 'post.php' === $pagenow ) ) ||
			( 'rep_services' === $current_page->post_type && ( 'post-new.php' === $pagenow || 'post.php' === $pagenow ) ) ||
			( isset( $wc_the_page ) &&
			( 'wc-computer-rep-shop-handle' === $wc_the_page ||
			'wc_computer_repair_print' === $wc_the_page ||
			'wc-computer-rep-shop-technicians' === $wc_the_page ||
			'wc-computer-rep-shop-managers' === $wc_the_page ||
			'wc-computer-rep-shop-reports' === $wc_the_page ||
			'wc-computer-rep-reports' === $wc_the_page ||
			'wc-computer-rep-shop-clients' === $wc_the_page ) ) ) {
			$wcrb_secondary_color = get_option( 'wcrb_secondary_color' );
			$wcrb_primary_color   = get_option( 'wcrb_primary_color' );
			?>
			<style type="text/css">
				<?php if ( ! empty( $wcrb_secondary_color ) ) : ?>
				.button.button-secondary,
				.wcrb_dashboard_section .wcrb_dan_item h3 {
					background-color:<?php echo esc_attr( $wcrb_secondary_color ); ?>;
				}
				.is-active>.accordion-title {
					background-color: <?php echo esc_attr( $wcrb_secondary_color ); ?>;
				}
				a.accordion-title:hover {
					background-color: <?php echo esc_attr( $wcrb_secondary_color ); ?>;	
				}
				.button.success,
				.orange-bg {
					background-color:<?php echo esc_attr( $wcrb_secondary_color ); ?> !important;
				}
				.color-orange, 
				.color-orange th,
				.color-orange td {
					color:<?php echo esc_attr( $wcrb_secondary_color ); ?> !important;
				}
				.computer-repair li.external-title > a:hover,
				.computer-repair .tabs-title > a:hover,
				.computer-repair .tabs-title > a:focus, 
				.computer-repair .tabs-title > a[aria-selected='true'] {
					background-color:<?php echo esc_attr( $wcrb_secondary_color ); ?>;
				}
				.abovezero {
					background-color: <?php echo esc_attr( $wcrb_secondary_color ); ?>;
				}
				.orange-bg {
					background-color: <?php echo esc_attr( $wcrb_secondary_color ); ?> !important;
				}
				.button.btn-secondary {
					background-color:<?php echo esc_attr( $wcrb_secondary_color ); ?>;
				}
				<?php endif; ?>
				<?php if ( ! empty( $wcrb_primary_color ) ) : ?>
				.button.button-primary,
				.wcrb_order_ID,
				.wp-core-ui .button-primary {
					background-color: <?php echo esc_attr( $wcrb_primary_color ); ?>;
					border-color: <?php echo esc_attr( $wcrb_primary_color ); ?>;
				}
				.wc-rb-panel-heading {
					background-color: <?php echo esc_attr( $wcrb_primary_color ); ?>;
				}
				.purchase_banner_wc {
					background: <?php echo esc_attr( $wcrb_primary_color ); ?>;
				}
				.isequalzero {
					background-color: <?php echo esc_attr( $wcrb_primary_color ); ?>;
				}
				.blue-bg {
					background-color: <?php echo esc_attr( $wcrb_primary_color ); ?> !important;
				}
				.blue-bg {
					background-color:<?php echo esc_attr( $wcrb_primary_color ); ?> !important;
				}
				.close-button, .close-button.medium {
					background-color: <?php echo esc_attr( $wcrb_primary_color ); ?>;
				}
				.color-blue,
				.color-blue th,
				.color-blue td {
					color:<?php echo esc_attr( $wcrb_primary_color ); ?> !important;
				}
				.thebluebg {
					background-color:<?php echo esc_attr( $wcrb_primary_color ); ?>;
				}
				.wcrb_dashboard_section .wcrb_dan_item a:hover > h3 {
					background-color:<?php echo esc_attr( $wcrb_primary_color ); ?>;
				}
				a.accordion-title {
					background-color: <?php echo esc_attr( $wcrb_primary_color ); ?>;
				}
				<?php endif; ?>
			</style>
			<?php
		}
	}
}