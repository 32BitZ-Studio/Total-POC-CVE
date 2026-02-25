<?php

if (!defined('ABSPATH')) {
    die('Don\'t hack please!');
}

class WP01
{

    /**
     * Initialize plugin
     */
    public static function init()
    {
        add_action('init', array('WP01', 'admin_init'));
        add_action( 'plugins_loaded', array('WP01', 'load_plugin_textdomain') );
        register_activation_hook(WP01__PLUGIN_FILE, array('WP01', 'activation_hook_callback'));
    }

    /**
     * Admin initialize
     */
    public static function admin_init()
    {
        self::ajax();
        self::admin_notice();
        self::add_menu_page();
        self::plugin_action_links();
        self::plugin_activation_notice();
    }

    /**
     * Load localization files
     */
    public static function load_plugin_textdomain() {
        load_plugin_textdomain( 'WP01', false, 'wp01/languages/' );
    }

    /**
     * Add action to print notice when plugin be activated
     */
    public static function activation_hook_callback()
    {
        setcookie( "WP01_activated", "true", time() + 300, "/");
    }

    /**
     * Plugin activation notice
     */
    public static function plugin_activation_notice()
    {
        setcookie( "WP01_activated", "true", time() - 1, "/");
        add_action('all_admin_notices', array('WP01', 'print_plugin_activation_notice'));
    }

    /**
     * Print activation notice
     */
    public static function print_plugin_activation_notice()
    {

        if (!isset($_COOKIE['WP01_activated'])) return;

        $text = __('Спасибо за установку плагина “Улучшения от WP01”. Нажмите <a href="%s">здесь</a>, чтобы произвести его настройку.', 'WP01');
        ?>
        <div class="notice notice-info is-dismissible">
            <p><?php printf($text, admin_url('admin.php?page=wp01')) ?></p>
            <button type="button" class="notice-dismiss"><span class="screen-reader-text">Скрыть это уведомление.</span></button>
        </div>
        <?php
    }

    /**
     * Register ajax callbacks
     */
    public static function ajax()
    {
        add_action('wp_ajax_wp01_dismiss_notice_forever', array('WP01', 'dismiss_notice_forever'));
        add_action('wp_ajax_wp01_dismiss_notice_for_week', array('WP01', 'dismiss_notice_for_week'));
        add_action('wp_ajax_wp01_change_language', array('WP01', 'change_language'));
        add_action('wp_ajax_wp01_callback_form', array('WP01', 'callback_form'));
        add_action('wp_ajax_wp01_save_settings', array('WP01', 'save_settings'));
/* start new */		
        add_action('wp_ajax_wp01_generate_zip_archive', array('WP01', 'make_archive'));
        add_action('wp_ajax_nopriv_wp01_generate_zip_archive', array('WP01', 'make_archive'));
/* end new	*/
    }

    /**
     * Dismiss notice forever
     */
    public static function dismiss_notice_forever()
    {
        update_user_meta(get_current_user_id(), 'wp01_notice_dismiss', 'forever');
    }

    /**
     * Dismiss notice for week
     */
    public static function dismiss_notice_for_week()
    {
        update_user_meta(get_current_user_id(), 'wp01_notice_dismiss', time());
    }

/** start new	*/
  /**
     * Create WP backups
     */
    public static function make_archive()
    {
        $zip = new ZipArchive(); // Load zip library
       
        $filename = 'wp-01-'. $_POST['target'];
        $filepath = $_POST['path'];

        if (!file_exists(WP_CONTENT_DIR .'/wp01-backup')) {
            mkdir(WP_CONTENT_DIR .'/wp01-backup', 0755, true);
        }

        $tmp_file = WP_CONTENT_DIR .'/wp01-backup/'. $filename .'.zip';

        if ($zip->open($tmp_file,  ZipArchive::CREATE)) {
            
            $zip->addFile($filepath . $_POST['target'], $_POST['target']);
            $zip->close();
            header('Content-Type: application/zip');
            header('Content-Disposition: attachment; filename="'.$tmp_file.'"');
            header('Content-Transfer-Encoding: binary');

            $return = array(
                'url'   => '/wp-content/wp01-backup/' .$filename.'.zip',
            );

            wp_send_json($return);
        }
    }
/** end new	*/
	
    /**
     * Change WP language
     */
    public static function change_language()
    {
        $locale = 'en_US';
        $lang = self::get_language_dir();
        $current_user = wp_get_current_user();

        if ($lang === 'ru') $locale = 'ru_RU';
        if ($lang === 'en') $locale = 'en_US';

        update_user_meta($current_user->ID, 'locale', $locale);

        wp_die('1');
    }

    /**
     * Callback Form
     */
    public static function callback_form()
    {
		// Email, who will receive the message
		$admin_email = array('info@wp01.ru');

		// Parse post data
		parse_str($_POST['data'], $data);

		// Required fields
		foreach (['name', 'email', 'message'] as $key)
			if ( !isset( $data[$key] ) || empty( $data[$key] ) )
				die('0');

		// Message text
		$mail_mes = [];

		$mail_mes[] = 'Name: ';
		$mail_mes[] = $data['name'];
		$mail_mes[] = '';
		$mail_mes[] = 'Email: ';
		$mail_mes[] = $data['email'];
		$mail_mes[] = '';
		$mail_mes[] = 'Message: ';
		$mail_mes[] = $data['message'];
		$mail_mes[] = '';
		$mail_mes[] = 'Сайт: ' . home_url();

		$mail_mes = implode("\n", $mail_mes);

		wp_mail($admin_email, 'New email from WP01 plugin', $mail_mes);

		wp_die('1');
    }

    /**
     * Register hook to print notice if needed
     */
    public static function admin_notice()
    {
        $dismiss = get_user_meta(get_current_user_id(), 'wp01_notice_dismiss', true);

        if (!$dismiss) {
            self::dismiss_notice_for_week();
            return;
        }

        if ($dismiss === 'forever') return;

        $timestamp = time();
        $week = (7 * 24 * 60 * 60); // week

        if (+$dismiss + $week < $timestamp) {
            add_action('admin_notices', array('WP01', 'print_admin_notice'));
            wp_enqueue_script('wp01JavaScriptNotice', plugins_url('assets/js/notice.js', WP01__PLUGIN_FILE), array('jquery'));
        }
    }

    /**
     * Print notice
     */
    public static function print_admin_notice()
    {
        $lang = self::get_language_dir();
        $dir = WP01__PLUGIN_DIR . "content/" . $lang;
        $path = $dir . '/notice.php';

        if (file_exists($path)) {
            include $path;
        }
    }

    /**
     * Added menu page registration callback
     */
    public static function add_menu_page()
    {
        add_action('admin_menu', array('WP01', 'add_menu_page_callback'));
    }

    /**
     * Returns menu page position (top or sub)
     */
    public static function get_menu_page_position()
    {
        $pos = get_user_meta(get_current_user_id(), 'wp01_menu_position', true);
        return $pos ? $pos : 'top';
    }

    /**
     * Callback Form
     */
    public static function save_settings()
    {
        // Parse post data
        parse_str($_POST['data'], $data);

        $res = update_user_meta(get_current_user_id(), 'wp01_menu_position', $data['menu_position']);

        wp_die('1');
    }

    /**
     * Add menu page and styles hook
     */
    public static function add_menu_page_callback()
    {
        $title = __('Улучшения от WP01', 'WP01');
        $capability = 'manage_options';
        $slug = 'wp01';
        $function = array('WP01', 'menu_callback');

        if (self::get_menu_page_position() === 'top') {
            $page = add_menu_page($title, $title, $capability, $slug, $function, '', 120);
        } else {
            $page = add_submenu_page('options-general.php', $title, $title, $capability, $slug, $function);
        }

        add_action('load-' . $page, array('WP01', 'admin_styles'));
    }

    /**
     * Register styles and scripts for admin page
     */
    public static function admin_styles()
    {
        wp_enqueue_style( 'wp01Stylesheet', plugins_url('assets/css/style.css', WP01__PLUGIN_FILE));

        wp_register_script( 'wp01JavaScript', plugins_url('assets/js/main.js', WP01__PLUGIN_FILE), array('jquery') );
	    wp_localize_script(
		    'wp01JavaScript',
		    'WPO1',
		    array(
			    'activate' => esc_html__( 'Активировать ', 'WP01' ),
			    'activating' => esc_html__( 'Активация ', 'WP01' ),
			    'deactivating' => esc_html__( 'Деактивация ', 'WP01' ),
		    )
	    );

	    wp_enqueue_script( 'plugin-install' );
	    wp_enqueue_script( 'updates' );
        wp_enqueue_script( 'wp01JavaScript');
	    add_thickbox();

    }

    /**
     * Include admin page file
     */
    public static function menu_callback()
    {
        include WP01__PLUGIN_DIR . 'content/admin-page.php';
    }

    /**
     * Register hook for add setting link in plugins page
     */
    public static function plugin_action_links()
    {
        // Add a link to the plugin's settings and/or network admin settings in the plugins list table.
        add_filter('plugin_action_links', array('WP01', 'add_settings_link'), 10, 2);
    }

    /**
     * Add setting link in plugins page
     *
     * @param $links array Links array
     * @param $file string Plugin file
     * @return array Links array
     */
    public static function add_settings_link($links, $file)
    {
        if ($file === 'wp01/wp01.php' && current_user_can('manage_options')) {
            $url_1 = admin_url('admin.php?page=wp01');
            $url_2 = 'https://plagin.wp01.ru/coffee-for-developers.php';

            // Prevent warnings in PHP 7.0+ when a plugin uses this filter incorrectly.
            array_unshift($links, sprintf('<a href="%s">%s</a>', $url_1, __('Настройки', 'WP01')));
            array_unshift($links, sprintf('<a href="%s" style="font-weight: bold;" target="_blank">%s</a>', $url_2, __('Кофе разработчикам', 'WP01')));
        }

        return $links;
    }

    /**
     * Return language dir name
     *
     * @return string Language dir name
     */
    public static function get_language_dir()
    {
        static $lang_dir;
        if (!$lang_dir) {

            if ( isset($_COOKIE['wp01-lang']) && $_COOKIE['wp01-lang'] ) {
	            $lang = $_COOKIE['wp01-lang'];
            } else {
	            $lang = substr(get_bloginfo('language'), 0, 2);
            }

            $lang_dir = 'en';

            $d = dir(WP01__PLUGIN_DIR . "content");
            while (false !== ($entry = $d->read())) {
                if ($lang === $entry) {
                    $lang_dir = $entry;
                }
            }
            $d->close();
        }
        return $lang_dir;
    }

    /**
     * Return steps array
     *
     * @return array Steps array
     */
    public static function get_steps()
    {
        static $steps;
        if (!$steps) {
            $lang_dir = self::get_language_dir();
            $dir = WP01__PLUGIN_DIR . "content/" . $lang_dir;
            $entries = array();
            $steps = array();

            $d = dir($dir);
            while (false !== ($entry = $d->read())) {
                if (substr($entry, -4) === '.php' && ! in_array($entry, array('notice.php', 'head.php'))) {
                    $entries[] = $entry;
                }
            }
            $d->close();

            natcasesort($entries);

            foreach ($entries as $entry) {
                $steps[] = array(
                    'name' => str_replace('.php', '', $entry),
                    'path' => $dir . '/' . $entry
                );
            }
        }
        return $steps;
    }
}
