<?php

use IlluminateAgnostic\Arr\Support\Arr;

function kubio_get_started_page_tabs() {
	$default_tabs = array(
		'get-started'     => array(
			'type'        => 'core_page',
			'label'       => __( 'Get started with Kubio', 'kubio' ),
			'tab-partial' => 'get-started.php',
			'subtitle'    => __( 'The supercharged block-based WordPress builder', 'kubio' ),
		),
		'website-starter' => array(
			'type'        => 'hidden',
			'tab-partial' => 'website-starter.php',
		),
	);

	if ( apply_filters( 'kubio/starter-sites/enabled', true ) ) {
		$default_tabs = array_merge(
			$default_tabs,
			array(
				'demo-sites' => array(
					'type'        => 'core_page',
					'label'       => __( 'Starter sites', 'kubio' ),
					'tab-partial' => 'demo-sites.php',
					'subtitle'    => __( 'Beautiful starter sites with 1-click import', 'kubio' ),
				),
			)
		);
	}

	$tabs = apply_filters(
		'kubio/admin-page/info_page_tabs',
		$default_tabs
	);

	if ( apply_filters( 'kubio/admin-page/upgrade_to_pro_tab', true ) ) {
		$tabs = array_merge(
			$tabs,
			array(
				'pro-upgrade' => array(
					'type'        => 'page',
					'label'       => __( 'Upgrade to PRO', 'kubio' ),
					'tab-partial' => 'upgrade-pro.php',
					'subtitle'    => __( 'The first block-based WordPress builder', 'kubio' ),
					'class'       => 'tab_get_pro',
				),
			)
		);
	}

	return $tabs;
}


/**
 * Renders the kubio Welcome Page
 */

function kubio_get_started_page() {
	kubio_print_admin_page_start();
	$kubio_get_started_page_tabs = kubio_get_started_page_tabs();

	// phpcs:ignore WordPress.Security.NonceVerification.Recommended
	$current_tab      = sanitize_key( Arr::get( $_REQUEST, 'tab', 'get-started' ) );
	$current_tab_data = Arr::get( $kubio_get_started_page_tabs, $current_tab, null );

	if ( ! $current_tab_data ) {
		$current_tab = 'get-started';
	}

	$subtitle = Arr::get( $current_tab_data, 'subtitle', '' );

	kubio_print_admin_page_header(
		$subtitle,
		$kubio_get_started_page_tabs
	);

	$tab_partial = Arr::get( $current_tab_data, 'tab-partial', null );

	if ( is_callable( $tab_partial ) ) {
		call_user_func( $tab_partial );
		kubio_print_admin_page_end();
		kubio_enqueue_editor_page_assets();
		return;
	}

	if ( file_exists( $tab_partial ) ) {
		$tab_partial_file = $tab_partial;
	} else {
		$tab_partial_file = __DIR__ . "/main-page/$tab_partial";

	}

	//content
	if ( $tab_partial && file_exists( $tab_partial_file ) ) {
		require_once $tab_partial_file;
	} else {
		wp_die( esc_html__( 'Unknown tab partial', 'kubio' ) );
	}

	kubio_print_admin_page_end();
	kubio_enqueue_editor_page_assets();
}

/**
 * Registers the new WP Admin Menu
 *
 * @return void
 */
function kubio_get_started_add_menu_page() {
	add_submenu_page(
		'kubio',
		__( 'Kubio - Get Started', 'kubio' ),
		__( 'Get Started', 'kubio' ),
		'edit_posts',
		'kubio-get-started',
		'kubio_get_started_page',
		20
	);

	if ( apply_filters( 'kubio/starter-sites/enabled', true ) ) {
		add_submenu_page(
			'kubio',
			__( 'Kubio - Starter Sites', 'kubio' ),
			__( 'Starter Sites', 'kubio' ),
			'edit_posts',
			'kubio-get-started-starter-sites',
			'kubio_get_started_page__starter_sites',
			20
		);
	}

	$tabs = kubio_get_started_page_tabs();

	foreach ( $tabs as $slug => $tab ) {
		if ( Arr::get( $tab, 'type' ) === 'page' ) {
			add_submenu_page(
				'kubio',
				Arr::get( $tab, 'label' ),
				Arr::get( $tab, 'label' ),
				'edit_posts',
				"kubio-admin-page-tab:{$slug}",
				"kubio_get_started_page__{$slug}",
				20
			);
		}
	}

	global $submenu;
	if ( isset( $submenu['kubio'] ) ) {
		foreach ( $submenu['kubio'] as $index => $submenu_item ) {
			if ( $submenu_item[2] === 'kubio-get-started-starter-sites' ) {
				$submenu['kubio'][ $index ][2] = add_query_arg(
					array(
						'tab'  => 'demo-sites',
						'page' => 'kubio-get-started',
					),
					admin_url( 'admin.php' )
				);
			}
			if ( $submenu_item[2] === 'kubio-get-started-pro-upgrade' ) {
				$submenu['kubio'][ $index ][2] = add_query_arg(
					array(
						'tab'  => 'pro-upgrade',
						'page' => 'kubio-get-started',
					),
					admin_url( 'admin.php' )
				);
			}

			if ( str_starts_with( $submenu_item[2], 'kubio-admin-page-tab:' ) ) {
				$page_tab = str_replace( 'kubio-admin-page-tab:', '', $submenu_item[2] );

				$submenu['kubio'][ $index ][2] = add_query_arg(
					array(
						'tab'  => $page_tab,
						'page' => 'kubio-get-started',
					),
					admin_url( 'admin.php' )
				);
			}
		}
	}
}

add_action( 'admin_menu', 'kubio_get_started_add_menu_page', 20 );
