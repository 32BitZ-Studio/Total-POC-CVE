<?php

if ( ! defined( 'ABSPATH' ) ) {
	die( 'Don\'t hack please!' );
}

class WP01_Content {

	/**
	 * Return plugin status
	 * (Active | Installed, disabled | Not installed)
	 *
	 * @param $plugin array Plugin data.
	 *
	 * @return array Plugin status
	 */
	public static function get_plugin_status( $plugin ) {
		$plugins      = get_plugins();
		$plugin_path  = $plugin['path'];
		$is_installed = isset( $plugins[ $plugin_path ] );
		$is_active    = is_plugin_active( $plugin_path );

		if ( $is_active ) {
			if ( !empty( $plugin['settings_link'] ) ) {
				$active_txt = __( 'Активен', 'WP01' );
				$text = str_replace($active_txt .', ', '', $plugin['settings_text']);

				$status = sprintf(
					'%s, <a href="%s" target="_blank">%s</a>',
					$active_txt,
					admin_url($plugin['settings_link']),
					$text
				);
			} else {
				$status = $plugin['settings_text'];
			}
			$status = '<span style="color: #00c751">' . $status . '</span>';
		} elseif ( $is_installed ) {
			$status = sprintf('<span style="color: #ffa518">%s</span>', __( 'Установлен, не активирован', 'WP01' ));
		} else {
            $status = sprintf('<span style="color: #f92b2b">%s</span>', __( 'Не установлен', 'WP01' ));
		}
		
		return array(
			'text'         => $status,
			'is_installed' => $is_installed,
			'is_active'    => $is_active
		);
	}

	/**
	 * Return analog plugin status
	 * (Active | Installed, disabled | Not installed)
	 *
	 * @param $plugin string Plugin data.
	 *
	 * @return array Plugin status
	 */
	public static function get_analog_status( $analog ) {
		$plugins      = get_plugins();
		$plugin_path  = $analog['path'];
		$is_installed = isset( $plugins[ $plugin_path ] );
		$is_active    = is_plugin_active( $plugin_path );

		return array(
			'is_installed' => $is_installed,
			'is_active'    => $is_active
		);
	}

	/**
	 * Return plugin priority
	 * (High | Medium | Low)
	 *
	 * @param $level int Priority
	 *
	 * @return string Plugin spriority
	 */
	public static function get_plugin_priority( $level ) {
		$strings = array( __( 'Низкая', 'WP01'  ), __( 'Средняя', 'WP01' ), __( 'Высокая', 'WP01' ) );
		$colors  = array( '#e1e607', '#ffa518', '#f92b2b' );
		$format  = '<span style="color: %s">%s</span>';

		return sprintf( $format, $colors[ $level - 1 ], $strings[ $level - 1 ] );
	}

	/**
	 * Return WordPress version
	 *
	 * @return string WP version
	 */
	public static function get_wp_version() {
		return get_bloginfo( 'version', 'display' );
	}

	/**
	 * Return PHP version
	 *
	 * @return string PHP version
	 */
	public static function get_php_version() {
		return preg_replace( '/([0-9]+\.[0-9]+\.[0-9]+).*/', '$1', phpversion() );
	}

	/**
	 * @return null|string|string[] DB version
	 */
	public static function get_db_version() {
		global $wpdb;

		return preg_replace( '/[^0-9.].*/', '', $wpdb->db_version() );
	}

	/**
	 * @return string Memory limit
	 */
	public static function get_memory_limit() {
		return ini_get( 'memory_limit' );
	}


	/**
	 *  Print WordPress version
	 */
	public static function the_wp_version() {
		echo self::get_wp_version();
	}

	/**
	 *  Print PHP version
	 */
	public static function the_php_version() {
		echo self::get_php_version();
	}

	/**
	 *  Print DB version
	 */
	public static function the_db_version() {
		echo self::get_db_version();
	}

	/**
	 *  Print memory limit
	 */
	public static function the_memory_limit() {
		echo self::get_memory_limit();
	}

    /**
     * Return memory limit
     *
     * @param $name string Image name
     *
     * @return string Image url
     */
    public static function get_image_src($name) {
        return plugin_dir_url(WP01__PLUGIN_FILE) . 'assets/img/' . $name;
    }

    /**
     * Print memory limit
     *
     * @param $name string Image name
     */
    public static function the_image_src($name) {
        echo self::get_image_src($name);
    }
}