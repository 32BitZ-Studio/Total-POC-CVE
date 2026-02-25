<?php

use Kubio\Core\Utils;
use Kubio\Flags;


require_once __DIR__ . '/meta-fields.php';
require_once __DIR__ . '/add-block-support.php';

function kubio_ai_remove_start_with_ai_hash() {
	if ( Utils::isRestRequest() && Flags::get( 'start_with_ai_hash' ) ) {
		Flags::delete( 'start_with_ai_hash' );
	}
}
function kubio_ai_remove_black_wizard_onboarding_hash() {
	if( !Utils::isRestRequest()) {
		return;
	}
	if ( Flags::get( 'black_wizard_onboarding_hash' ) ) {
		Flags::delete( 'black_wizard_onboarding_hash' );
	}
	if ( Flags::get( 'auto_start_black_wizard_onboarding' ) ) {
		Flags::delete( 'auto_start_black_wizard_onboarding' );
	}
}

add_action( 'wp_after_insert_post', 'kubio_ai_remove_start_with_ai_hash' );
add_action( 'wp_after_insert_post', 'kubio_ai_remove_black_wizard_onboarding_hash' );

function kubio_ai_upgrade_key( $upgrade_key ) {
	$license = kubio_ai_get_key();
	if ( ! $upgrade_key && $license ) {
		$upgrade_key = sprintf( 'ai:%s', apply_filters( 'kubio/ai/upgrade-key', base64_encode( kubio_ai_get_key() ) ) );
	}

	return $upgrade_key;
}

add_action( 'kubio/upgrade-key', 'kubio_ai_upgrade_key' );
