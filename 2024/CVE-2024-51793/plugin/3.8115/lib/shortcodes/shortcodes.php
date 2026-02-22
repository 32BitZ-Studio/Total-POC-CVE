<?php
    //Include Shortcode Files.

    require_once WC_COMPUTER_REPAIR_SHOP_DIR . 'lib' . DS . 'shortcodes' . DS . 'list_products.php';
    require_once WC_COMPUTER_REPAIR_SHOP_DIR . 'lib' . DS . 'shortcodes' . DS . 'list_services.php';
    require_once WC_COMPUTER_REPAIR_SHOP_DIR . 'lib' . DS . 'shortcodes' . DS . 'order_status.php';
    require_once WC_COMPUTER_REPAIR_SHOP_DIR . 'lib' . DS . 'shortcodes' . DS . 'request_quote.php';
    require_once WC_COMPUTER_REPAIR_SHOP_DIR . 'lib' . DS . 'shortcodes' . DS . 'my_account.php';
    require_once WC_COMPUTER_REPAIR_SHOP_DIR . 'lib' . DS . 'shortcodes' . DS . 'book_my_service.php';
    require_once WC_COMPUTER_REPAIR_SHOP_DIR . 'lib' . DS . 'shortcodes' . DS . 'type_grouped_service.php';
    require_once WC_COMPUTER_REPAIR_SHOP_DIR . 'lib' . DS . 'shortcodes' . DS . 'book_device_and_services.php';
    require_once WC_COMPUTER_REPAIR_SHOP_DIR . 'lib' . DS . 'shortcodes' . DS . 'wc_book_my_warranty.php';

/**
 * Start Job
 * Front End
 *
 * Selecting Device
 * @popup
 * @Since 3.53
 */
require_once WC_COMPUTER_REPAIR_SHOP_DIR . 'lib' . DS . 'shortcodes' . DS . 'start_job_by_device.php';


if ( ! function_exists( 'wc_comp_rep_register_foundation' ) ) :
    /**
     * Register Scripts
     * Register Styles
     * 
     * To Enque within Shortcodes 
     */
    function wc_comp_rep_register_foundation() {
        wp_register_script( 'foundation-js', WC_COMPUTER_REPAIR_DIR_URL . '/assets/admin/js/foundation.min.js', array( 'jquery' ), '6.5.3', true );
        wp_register_script( 'wc-cr-js', WC_COMPUTER_REPAIR_DIR_URL . '/assets/js/wc_cr_scripts.js', array( 'jquery' ), WC_CR_SHOP_VERSION, true );

        wp_register_style( 'select2', WC_COMPUTER_REPAIR_DIR_URL . '/assets/admin/css/select2.min.css', array(),'4.0.13','all' );
        wp_register_script( 'select2', WC_COMPUTER_REPAIR_DIR_URL . '/assets/admin/js/select2.min.js', array( 'jquery' ),  '4.0.13', true );

        //intl-tel-input
        wp_register_script( 'intl-tel-input', WC_COMPUTER_REPAIR_DIR_URL . '/assets/vendors/intl-tel-input/js/intlTelInputWithUtils.min.js', array( 'jquery' ), '23.1.0', true );
        wp_register_style( 'intl-tel-input', WC_COMPUTER_REPAIR_DIR_URL . '/assets/vendors/intl-tel-input/css/intlTelInput.min.css', array(),'23.1.0','all' );
    }// adding styles and scripts for wordpress admin.
    add_action( 'init', 'wc_comp_rep_register_foundation' );
endif;

if ( ! function_exists( 'wcrb_intl_tel_input_script' ) ) : 
    function wcrb_intl_tel_input_script() { ?>
        <script defer type="text/javascript">
			jQuery(document).ready(function(){
            const input = document.querySelector('input[name="phoneNumber_ol"]');

            const iti = window.intlTelInput(input, {
                <?php 
                    $_country = ( ! empty( get_option( 'wc_primary_country' ) ) ) ? strtolower( get_option( 'wc_primary_country' ) ) : "us";

                    $_lang = explode( '-', get_bloginfo( 'language' ) );
                    $_lang = $_lang[0];
                ?>
                i18n: "<?php echo esc_attr( $_lang ); ?>",
                initialCountry: "<?php echo esc_attr( $_country ); ?>",
                hiddenInput: () => ({ phone: "phoneNumber", country: "country_code" }),
                separateDialCode: true,
                utilsScript: "<?php echo esc_url( WC_COMPUTER_REPAIR_DIR_URL ); ?>/assets/vendors/intl-tel-input/js/utils.js?1716383386062"
            });

            input.onchange = () => {
                if (!iti.isValidNumber()) {
                    alert( '<?php echo esc_html__( 'Invalid phone number', 'computer-repair-shop' ); ?>' );
                    return false;
                }
            };
			});
        </script>
    <?php }
endif;

if ( ! function_exists( 'wcrb_intl_tel_input_script_admin' ) ) : 
    function wcrb_intl_tel_input_script_admin() { ?>
        <script type="text/javascript">
            jQuery(document).ready(function(){
                const input  = document.querySelector('input[name="customer_phone_ol"]');
                const output = document.querySelector('input[name="customer_phone"]');
                
                const iti = window.intlTelInput(input, {
                    <?php 
                        $_country = ( ! empty( get_option( 'wc_primary_country' ) ) ) ? strtolower( get_option( 'wc_primary_country' ) ) : "us";

                        $_lang = explode( '-', get_bloginfo( 'language' ) );
                        $_lang = $_lang[0];
                    ?>
                    i18n: "<?php echo esc_attr( $_lang ); ?>",
                    initialCountry: "<?php echo esc_attr( $_country ); ?>",
                    hiddenInput: () => ({ phone: "customer_phone", country: "country_code" }),
                    separateDialCode: true,
                    utilsScript: "<?php echo esc_url( WC_COMPUTER_REPAIR_DIR_URL ); ?>/assets/vendors/intl-tel-input/js/utils.js?1716383386062"
                });
                input.addEventListener('blur', function() {
                    jQuery('input[name="customer_phone"]').val(iti.getNumber());
                });

                input.onchange = () => {
                    if (!iti.isValidNumber()) {
                        alert( '<?php echo esc_html__( 'Invalid phone number', 'computer-repair-shop' ); ?>' );
                        return false;
                    }
                };
            });
        </script>
    <?php }
endif;