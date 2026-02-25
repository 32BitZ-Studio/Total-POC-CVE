<?php


class WP01_Installer {

	/**
	 * Generate action button html.
	 *
	 * @param array $analog     analog data.
	 * @param boolean $activate_status     is activated.
	 *
	 * @return string
	 */
    public static function get_button_analog( $analog, $activate_status ) {
		
		
        $button     = '';

        $plugin_link_suffix = $analog['path'];
        list($slug) = explode('/', $plugin_link_suffix);

        if ( empty( $slug ) ) {
            return '';
        }

        $button .= '<div class=" plugin-card-' . esc_attr( $slug ) . '" style="padding: 8px 0 5px;">';

        $plugin_link_suffix = $analog['path'];
        list($slug) = explode('/', $plugin_link_suffix);
        
        $analog_status = WP01_Content::get_analog_status( $analog );
		
        $slug = ucfirst($slug);
        
		$analog_class = $analog_status['is_active'] == 1 ? 'text-purple ' : '' ;
		
        $button .= "<img class='analog-icon' src=$analog[icon]>";
        $button .= sprintf(
            '<span class="analog-name-piece-wrapper"><a href="%s" class="'. $analog_class .'thickbox open-plugin-details-modal analog-name-piece" target="_blank">%s</a></span>',
            self_admin_url(
                'plugin-install.php?' .
                build_query(array(
                    'tab' => 'plugin-information',
                    'plugin' => $slug,
                    'TB_iframe' => true,
                    'width' => 600,
                    'height' => 550
                ))
            ),
            $analog['name']
        );
        
        
        if ($analog_status['is_installed'] == 1 ) {
			$installed_check_status = true;
            if ($analog_status['is_active'] != 1 ) {
                $button .= sprintf(
                    '<a href="%s" class="analog-activate analog-btn '. ($activate_status ? 'modal-activate' : 'activate-now loader-btn') .'" target="_blank">%s<span class="analog-popup"><span class="analog-popup-text">'. __('Активировать аналог', 'WP01') .'</span></span></a>',
                    self_admin_url(
                        'plugins.php?' .
                        build_query( array(
                            'action'        => 'activate',
                            'plugin'        => rawurlencode( $plugin_link_suffix ),
                            'plugin_status' => 'all',
                            'paged'         => '1',
                            '_wpnonce'      => wp_create_nonce( 'activate-plugin_' . $plugin_link_suffix ),
                        ))
                    ),
                    __( "Активировать", 'WP01' )
                );
            } else {
                $button .= sprintf(
                    '<a href="%s" class="deactivate-now analog-off analog-btn loader-btn" target="_blank">%s<span class="analog-popup"><span class="analog-popup-text">'. __('Деактивировать аналог', 'WP01') .'</span></span></a>',
                    self_admin_url(
                        'plugins.php?' .
                        build_query( array(
                            'action' =>  'deactivate',
                            'plugin'        => rawurlencode( $plugin_link_suffix ),
                            'plugin_status' => 'all',
                            'paged'         => '1',
                            '_wpnonce'      => wp_create_nonce( 'deactivate-plugin_' . $plugin_link_suffix ),
                        ))
                    ),
                    __( 'Деактивировать', 'WP01' )
                );
            }
            if ( !empty( $analog['settings_link'] ) && $analog_status['is_active'] == 1 ) {
                $button .= sprintf("<a target='_blank' class='analog-options analog-btn loader-btn' href='%s'>Options
				<span class='analog-popup'>
					<span class='analog-popup-text'>". __('Опции аналога', 'WP01') ."</span>
				</span>
									</a>",
                    admin_url($analog['settings_link'])
                );
            }
            
        } else {
            $button .= sprintf(
                '<a href="%s" class="analog-download thickbox open-plugin-details-modal analog-btn" target="_blank">%s<span class="analog-popup"><span class="analog-popup-text">'. __('Скачать аналог', 'WP01') .'</span></span></a>',
                self_admin_url(
                    'plugin-install.php?' .
                    build_query(array(
                        'tab' => 'plugin-information',
                        'plugin' => $slug,
                        'TB_iframe' => true,
                        'width' => 600,
                        'height' => 550
                    ))
                ),
                __( "$slug", 'WP01' )
            );
            
        }
        $button .= '</div>';
        
        return $button;

    }
	public static function get_button( $plugin, $activate_status ) {
        $button     = '';

        $plugin_link_suffix = $plugin['path'];
        list($slug) = explode('/', $plugin_link_suffix);

        if ( empty( $slug ) ) {
            return '';
        }

        $button .= '<div class=" plugin-card-' . esc_attr( $slug ) . '" style="padding: 8px 0 5px;">';

        $plugin_link_suffix = $plugin['path'];
        list($slug) = explode('/', $plugin_link_suffix);

        $plug_status = WP01_Content::get_plugin_status( $plugin );


        if ($plug_status['is_installed'] != 1 ) {

            $button .= sprintf(
                '<a href="%s" class="thickbox button button-primary open-plugin-details-modal" target="_blank">%s</a>',
                self_admin_url(
                    'plugin-install.php?' .
                    build_query(array(
                        'tab' => 'plugin-information',
                        'plugin' => $slug,
                        'TB_iframe' => true,
                        'width' => 600,
                        'height' => 550
                    ))
                ),
                __( 'Открыть', 'WP01' )
            );

        } else {

            if ($plug_status['is_active'] == 1) {
                $button .= sprintf(
                    '<a href="%s" class="button deactivate-now loader-btn" target="_blank">%s</a>',
                    self_admin_url(
                        'plugins.php?' .
                        build_query( array(
                            'action' =>  'deactivate',
                            'plugin'        => rawurlencode( $plugin_link_suffix ),
                            'plugin_status' => 'all',
                            'paged'         => '1',
                            '_wpnonce'      => wp_create_nonce( 'deactivate-plugin_' . $plugin_link_suffix ),
                        ))
                    ),
                    __( 'Деактивировать', 'WP01' )
                );
            } else {
                $button .= sprintf(
                    '<a href="%s" class="button button-green button-primary '. ($activate_status ? 'modal-activate' : 'activate-now loader-btn') .'" target="_blank">%s</a>',
                    self_admin_url(
                        'plugins.php?' .
                        build_query( array(
                            'action'        => 'activate',
                            'plugin'        => rawurlencode( $plugin_link_suffix ),
                            'plugin_status' => 'all',
                            'paged'         => '1',
                            '_wpnonce'      => wp_create_nonce( 'activate-plugin_' . $plugin_link_suffix ),
                        ))
                    ),
                    __( "Активировать", 'WP01' )
                );
            }

        }

        $button .= '</div>';

        return $button;
	}


	public static function get_info($plugin) {

		$plugin_link_suffix = $plugin['path'];
		list($slug) = explode('/', $plugin_link_suffix);

        $details_link = self_admin_url(
            'plugin-install.php?' .
            build_query(array(
                'tab' => 'plugin-information',
                'plugin' => $slug,
                'TB_iframe' => true,
                'width' => 600,
                'height' => 550
            ))
        );

		$link = sprintf('<a href="%s" class="thickbox open-plugin-details-modal" target="_blank">%s</a>', $details_link, $plugin['name']);

		return $link;
	}


	/**
	 * Check plugin state.
	 *
	 * @param string $path - plugin path.
	 *
	 * @return bool
	 */
	public static function check_plugin_state( $path ) {

		if ( file_exists( ABSPATH . 'wp-content/plugins/' . $path ) ) {
			return is_plugin_active( $path ) ? 'deactivate' : 'activate';
		} else {
			return 'install';
		}

	}


}




