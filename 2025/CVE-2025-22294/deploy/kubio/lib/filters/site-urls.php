<?php

use IlluminateAgnostic\Str\Support\Arr;
use Kubio\Flags;

function kubio_get_site_urls() {

	$base_url = 'https://kubiobuilder.com/go/';

	$args = array(
		'utm_theme'            => get_template(),
		'utm_childtheme'       => get_stylesheet(),
		'utm_install_source'   => Flags::get( 'start_source', 'other' ),
		'utm_activated_on'     => Flags::get( 'kubio_activation_time', '' ),
		'utm_pro_activated_on' => Flags::get( 'kubio_pro_activation_time', '' ),
	);

	$urls = apply_filters(
		'kubio/kubio_go_link_paths',
		array(
			'features'         => 'features',
			'upgrade'          => '/upgrade-to-pro',
			'try'              => 'try-demo',
			'theme_try_online' => 'try-online',
			'documentation'    => 'documentation',
			'contact'          => 'contact',
		)
	);

	foreach ( $urls as $key => $path ) {
		$urls[ $key ] = $base_url . trim( $path, '/' );
	}

	return array(
		'homepage_url'      => 'https://kubiobuilder.com',
		'features_url'      => $urls['features'],
		'upgrade_url'       => add_query_arg( $args, $urls['upgrade'] ),
		'try_starter_site'  => add_query_arg( $args, $urls['try'] ),
		'theme_try_online'  => apply_filters( 'kubio/editor-try-online/url', add_query_arg( $args, $urls['theme_try_online'] ), $urls['theme_try_online'], $base_url, $args ),
		'documentation_url' => add_query_arg( $args, $urls['documentation'] ),
		'contact_url'       => add_query_arg( $args, $urls['contact'] ),
		'facebook_url'      => 'https://www.facebook.com/kubiobuilder',
	);
}


function kubio_get_site_url_for( $key, $utms = array() ) {
	$urls = kubio_get_site_urls();
	$url  = Arr::get(
		$urls,
		$key,
		Arr::get( $urls, "{$key}_url", 'https://kubiobuilder.com' )
	);

	$utms = array_merge(
		array(
			'medium' => 'wp',
		),
		$utms
	);

	if ( ! empty( $utms ) ) {
		$formatted_utms = array();
		foreach ( array_keys( $utms ) as $key ) {
			$formatted_utms[ "utm_{$key}" ] = $utms[ $key ];
		}
		$url = add_query_arg( $formatted_utms, $url );
	}

	return $url;
}

function kubio_try_demo_url( $template_slug ) {
	list($url, $args) = explode( '?', kubio_get_site_url_for( 'try_starter_site' ) );

	$url = untrailingslashit( $url ) . "/{$template_slug}";

	if ( $args ) {
		$url = "{$url}?{$args}";
	}

	return $url;
}
