<?php

namespace Kubio\CLI;

use Kubio\DemoSites\DemoSites;
use WP_CLI;

class ExportDemoSiteCommand {
	/**
	 * Export website as a Kubio design.
	 *
	 * ## OPTIONS
	 *
	 * <file>
	 * : The design output file. It should have the .kds extension.
	 *
	 *
	 * ## EXAMPLES
	 *
	 *     wp kubio:export-design /home/user/my-site.kds
	 *
	 * @when after_wp_load
	 * @param $args
	 * @param $assoc_args
	 * @throws \WP_CLI\ExitException
	 */
	public function __invoke( $args, $assoc_args ) {

		$file = empty( $args[0] ) ? null : $args[0];

		if ( is_null( $file ) ) {
			WP_CLI::error( 'Output file name cannot be empty' );
			return;
		}

		if ( substr( $file, -4 ) !== '.kds' ) {
			WP_CLI::line( "File: '{$file}' does not have the kds extension! It will be automatically added" );
			$file = "{$file}.kds";
		}

		if ( file_exists( $file ) ) {
			WP_CLI::error( "File: '{$file}' already exists. Please use another name!" );
			return;
		}

		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_is_writable
		if ( ! is_writable( dirname( $file ) ) ) {
			WP_CLI::error( "File: '{$file}' is not writable. Please use another location!" );
			return;
		}

		$content = serialize( DemoSites::exportDemoSiteContent() );

		file_put_contents( $file, $content );

		WP_CLI::success( "Demo site successfully exported to '{$file}'." );
	}
}
