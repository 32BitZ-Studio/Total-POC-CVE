<?php
/**
 * JOB History Logs
 *
 * Help setup pages to they can be used in notifications and other items
 *
 * @package computer-repair-shop
 * @version 3.7947
 */

defined( 'ABSPATH' ) || exit;

add_action( 'plugins_loaded', array( 'WCRB_JOB_HISTORY_LOGS', 'getInstance' ) );

class WCRB_JOB_HISTORY_LOGS {

    private static $instance = NULL;

	static public function getInstance() {
		if ( self::$instance === NULL )
			self::$instance = new WCRB_JOB_HISTORY_LOGS();
		return self::$instance;
	}

    public function __construct() {
        add_action( 'wp_ajax_wc_add_job_history_manually', array( $this, 'wc_add_job_history_manually' ) );
	}

    function wc_add_job_history_manually() {
        global $wpdb;

        if(isset($_POST["recordID"])) {	
            $args = array(
                "job_id" 		=> sanitize_text_field( $_POST["recordID"] ), 
                "name" 			=> sanitize_textarea_field( $_POST["recordName"] ), 
                "type" 			=> sanitize_text_field( $_POST["recordType"] ), 
                "emailCustomer" => sanitize_text_field( $_POST["emailCustomer"] ),
                "field" 		=> "", 
                "change_detail" => ""
            );
            $message = $this->wc_record_job_history( $args );

            $values['success'] = "YES";
        } else {
            $message = esc_html__("Order Id missing, make sure post exists or published.", "computer-repair-shop");
            $values['success'] = "NO";
        }
        $values['message'] = $message;

        wp_send_json($values);
        wp_die();
    }

    function wc_list_job_history( $job_id, $type ) {
        global $wpdb;

        $computer_repair_history = $wpdb->prefix.'wc_cr_job_history';

        if ( empty( $job_id ) ) {
            return;
        }
        $type = ( ! empty( $type ) ) ? $type : "all";
        
        $type_display = ( $type == "public" ) ? "hide" : "show";

        if($type == "all") {
            $select_items_query = "SELECT * FROM `{$computer_repair_history}` WHERE `job_id`= %s ORDER BY `history_id` DESC";
            $items_result = $wpdb->get_results( $wpdb->prepare( $select_items_query, $job_id ) );
        } elseif($type == "private" || $type == "public") {
            $select_items_query = "SELECT * FROM `{$computer_repair_history}` WHERE `job_id`= %d AND `type`= %s ORDER BY `history_id` DESC";
            $items_result = $wpdb->get_results( $wpdb->prepare( $select_items_query, $job_id, $type ) );
        }
        
        $content = '';
        
        foreach( $items_result as $item ) {
            $history_id 	= $item->history_id;
            $datetime 		= $item->datetime;
            $job_id 		= $item->job_id;
            $name 			= $item->name;
            $type 			= ( ! empty( $item->type ) ) ? $item->type : 'public';
            $field 			= $item->field;
            $change_detail 	= $item->change_detail;
            $user_id 		= $item->user_id;

            $user_info 		= get_userdata( $user_id );
            $first_name 	= $user_info->first_name;
            $last_name 		= $user_info->last_name;

            $date_format	= get_option( 'date_format' );
            $time_format	= get_option( 'time_format' );

            $formated_date =  date( $date_format, strtotime( $datetime ) );
            $formated_time =  date( $time_format, strtotime( $datetime ) );

            $content .= '<li data-history-id="'.$history_id.'" class="note note_'.$type.'">
                        <div class="note_content">
                            <p> ' . $name;

            if ( $field == '_wc_device_data' ) {
                if ( !empty( $change_detail ) ) {
                    $change_detail = unserialize($change_detail);

                    $counter = 0;
                    foreach ( $change_detail as $device_detail ) {
                        $content .= ( $counter != 0 ) ? '<br>' : '';

                        $content .= '<strong> ';
                        $content .= ( isset( $device_detail['device_post_id'] ) ) ? return_device_label( $device_detail['device_post_id'] ) . ' | ' : '';
                        $content .= ( isset( $device_detail['device_id'] ) ) ? $device_detail['device_id'] . ' | ' : '';
                        if ( $type_display != 'hide' ) {
                            $content .= ( isset( $device_detail['device_login'] ) ) ? $device_detail['device_login'] . ' | ' : '';
                        }
                        $content .= ( isset( $device_detail['device_note'] ) ) ? $device_detail['device_note'] : '';
                        $content .= '</strong>';

                        $counter++;
                    }
                }
            } elseif ( $field == 'payment_table' ) {
                if ( ! empty( $change_detail ) ) {
                    global $PAYMENT_STATUS_OBJ;
                    $change_detail = unserialize( $change_detail );

                    $Hformated_date =  date( $date_format, strtotime( $change_detail['date'] ) );
                    $Hformated_time =  date( $time_format, strtotime( $change_detail['date'] ) );

                    $receiv_info 	= get_userdata( $change_detail['receiver_id'] );
                    $theName 		= $receiv_info->first_name;
                    $theName 		.= ' ' . $receiv_info->last_name;

                    $theName		= ( empty( $theName ) ) ? $receiv_info->user_login : $theName;

                    $content .= ' { <strong>' . esc_html__( 'Date', 'computer-repair-shop' ) . '</strong> : ' . $Hformated_date . ' ' . $Hformated_time . ' } ';
                    $content .= ' { <strong>' . esc_html__( 'Receiver', 'computer-repair-shop' ) . '</strong> : ' . $theName . ' } ';
                    $content .= ' { <strong>' . esc_html__( 'Method', 'computer-repair-shop' ) . '</strong> : ' . $PAYMENT_STATUS_OBJ->wc_payment_method_label( $change_detail['method'] ) . ' } ';
                    $content .= ' { <strong>' . esc_html__( 'Payment Status', 'computer-repair-shop' ) . '</strong> : ' . wc_return_payment_status( $change_detail['payment_status'] ) . ' } ';
                    $wc_note_label = ( empty( get_option( 'wc_note_label' ) ) ) ? esc_html__( 'Note', 'computer-repair-shop' ) : get_option( 'wc_note_label' );
                    $content .= ' { <strong>' . esc_html( $wc_note_label ) . '</strong> : ' . stripslashes( $change_detail['note'] ) . ' } ';
                    $content .= ' { <strong>' . esc_html__( 'Amount', 'computer-repair-shop' ) . '</strong> : ' . wc_cr_currency_format( $change_detail['amount'] ) . ' } ';
                }
            } elseif( $field == 'stock_management' ) {
                if ( ! empty( $change_detail ) ) {
                    $change_detail = unserialize( $change_detail );

                    if ( is_array( $change_detail ) ) {
                        foreach( $change_detail as $change_arr ) {
                            $productID = ( isset( $change_arr['product_id'] ) ) ? $change_arr['product_id'] : '';
                            $qty 	   = ( isset( $change_arr['qty'] ) ) ? $change_arr['qty'] : '';
                            $content .= ' { <strong>' . esc_html__( 'Product Id', 'computer-repair-shop' ) . ' </strong> : ' . $productID . ', ';
                            $content .= ' <strong>' . esc_html__( 'Qty', 'computer-repair-shop' ) . ' </strong> : ' . $qty . '}, ';
                        }
                    }
                }
            } else {
                $content .= '<strong> '.$change_detail.'</strong>';
            }

            if($type_display != 'hide'): 
                $content .= '<span class="typelabel">'.$type.'</span>';
            endif;

            $content .= '</p>
                        </div>
                        <p class="meta">
                            <abbr class="exact-date" title="'.$datetime.'">
                                '.$formated_date." ".$formated_time.'					
                            </abbr>
                            by '.$first_name.' '.$last_name.'
                        </p></li>';
        }//EndForEach
        return (!empty($content)) ? $content : esc_html__("No history found.", "computer-repair-shop");
    }

    /**
     * Send History log to Customer email
     * takes argument History ID
     * 
     * @Since 3.72
     */
    function wc_send_history_log_to_customer( $history_id ) {
        global $wpdb;

        if ( empty( $history_id ) ) {
            return;
        }

        $computer_repair_history 	= $wpdb->prefix.'wc_cr_job_history';

        $wc_history_status	= $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$computer_repair_history} WHERE `history_id` = %d", $history_id ) );
        
        $history_id			= $wc_history_status->history_id;
        $datetime 			= $wc_history_status->datetime;
        $job_id 			= $wc_history_status->job_id;
        $name 				= $wc_history_status->name;
        $type 				= $wc_history_status->type;
        $field 				= $wc_history_status->field;
        $change_detail 		= $wc_history_status->change_detail;
        $user_id 			= $wc_history_status->user_id;

        if ( $type != 'public' ) {
            return; // Anything else public needs to return.
        }
        if ( empty( $name ) ) {
            return;
        }

        // Let's get customer details now.
        if( empty( $job_id ) ) {
            return;
        }

        $customer_id 		= get_post_meta( $job_id, '_customer', true );
        $status_label 		= get_post_meta( $job_id, '_wc_order_status_label', true );
        $wc_order_status 	= get_post_meta( $job_id, '_wc_order_status', true );

        $ext_message = "";
        
        if ( empty( $customer_id ) ) {
            return;
        }
        $user_info 		= get_userdata( $customer_id );
        $user_name 		= $user_info->first_name . " " . $user_info->last_name;
        $user_email 	= $user_info->user_email;

        if ( empty( $user_email ) ) {
            return;
        }
        $menu_name_p 	= get_option( "menu_name_p" );

        $to 			= $user_email;
        $subject 		= esc_html__("Manual message added to your job!", "computer-repair-shop") . " | " . esc_html($menu_name_p);
        $headers 		= array('Content-Type: text/html; charset=UTF-8');

        $body	 		= "<h2>" . esc_html__( "A manual message added to your job by staff.", "computer-repair-shop" ) . "</h2>";
        
        $body 			.= ( ! empty( $name ) ) ? '<p>' . nl2br( $name ) . '</p>' : '';

        $the_site_url 	 = get_option( 'siteurl' );

        $body 			.= '<p>' . esc_html__( 'To view all details please visit our site.', 'computer-repair-shop' ) . $the_site_url . '<br><br>' . esc_html__( ' Your case# is: ') . get_the_title( $job_id ) . '</p>';

        $status_check_link = wc_rb_return_status_check_link( $job_id );

        if ( ! empty ( $status_check_link ) ) {
            $body .= '<h3>' . esc_html__( 'Check job status online', 'computer-repair-shop' ) . '</h3>';
            $body .= '<p><a href="' . $status_check_link . '">' . esc_html__( 'Click to open in browser' ) . '</a></p>'; 
        }

        $args = array(
            "job_id" 		=> $job_id, 
            "name" 			=> esc_html__( 'Manual log email sent', 'computer-repair-shop' ), 
            "type" 			=> 'public', 
            "field" 		=> '_history_log_email_to_customer', 
            "change_detail" => 'To : ' . $to
        );
        $message = $this->wc_record_job_history( $args );

        $body_output  = wc_rs_get_email_head();
        $body_output .= $body;
        $body_output .= wc_rs_get_email_footer();

        wp_mail( $to, $subject, $body_output, $headers );
    }

    /**
	 * Record Job History
	 * 
	 * Inserts data into History Table. 
	 * PreFix following >> wc_cr_job_history 
	 * Example wp_ >> wp_wc_cr_job_history
	 * 
	 * $args = array("job_id" => , "name" => , "type" => , "field" => , "change_detail" => , "user_id" => )
	 */
    function wc_record_job_history( $args ) {
        global $wpdb;

        if(!is_array($args)) {
            return;
        }

        $computer_repair_history 	= $wpdb->prefix.'wc_cr_job_history';

        $datetimest     = wp_date( 'Y-m-d H:i:s' );
        $user_id 		= ( isset( $args['user_id'] ) && ! empty( $args['user_id'] ) ) ? $args['user_id'] : get_current_user_id();
        $job_id 		= (isset($args["job_id"])) ? $args["job_id"] : "";
        $name 			= (isset($args["name"])) ? $args["name"] : "";
        $type 			= (isset($args["type"])) ? $args["type"] : "private";
        $field 			= (isset($args["field"])) ? $args["field"] : "";
        $change_detail 	= (isset($args["change_detail"])) ? $args["change_detail"] : "";
        $emailCustomer 	= ( isset( $args['emailCustomer'] ) ) ? $args['emailCustomer'] : 'NO';

        if ( empty( $user_id ) || empty( $job_id ) ) {
            return esc_html__( "Missing id or Job ID", "computer-repair-shop" );
        }
        //job_id	name	type	field	change_detail
        $insert_query = "INSERT INTO 
                            `".$computer_repair_history."` 
                        VALUES
                            (NULL, %s, %d, %s, %s, %s, %s, %d)";
        $wpdb->query(
                $wpdb->prepare($insert_query, array( $datetimest, $job_id, $name, $type, $field, $change_detail, $user_id))
        );
        $history_id = $wpdb->insert_id;

        if ( $emailCustomer == 'YES' ) {
            $this->wc_send_history_log_to_customer( $history_id );
        }
        return esc_html__("You have added manual log.", "computer-repair-shop");
    } //EndFunction

    function copy_history_logs_to_other_job( $old_job_id, $new_job_id ) {
        global $wpdb;

        if ( empty( $old_job_id ) || empty( $new_job_id ) ) {
            return;
        }
        $computer_repair_history = $wpdb->prefix.'wc_cr_job_history';

        $select_items_query = "SELECT * FROM `{$computer_repair_history}` WHERE `job_id`= %s ORDER BY `history_id` DESC";
        $items_result = $wpdb->get_results( $wpdb->prepare( $select_items_query, $old_job_id ) );
        
        foreach( $items_result as $item ) {
            $datetime 		= $item->datetime;
            $name 			= $item->name;
            $type 			= ( ! empty( $item->type ) ) ? $item->type : 'public';
            $field 			= $item->field;
            $change_detail 	= $item->change_detail;
            $user_id 		= $item->user_id;

            $insert_query = "INSERT INTO `".$computer_repair_history."` VALUES (NULL, %s, %d, %s, %s, %s, %s, %d)";

            $wpdb->query(
                $wpdb->prepare($insert_query, array( $datetime, $new_job_id, $name, $type, $field, $change_detail, $user_id))
            );
        }
    }
}