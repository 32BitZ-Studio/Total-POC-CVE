<?php

namespace Kubio\CLI;

use IlluminateAgnostic\Arr\Support\Arr;
use Kubio\DemoSites\DemoSitesImporter;
use Kubio\DemoSites\DemoSitesRepository;
use WP_CLI;

class ImportDemoSiteCommand {
	/**
	 * Import a Kubio design.
	 *
	 * ## OPTIONS
	 *
	 * <design>
	 * : The slug, file path, or the url of the design to import.
	 *
	 * [--verify-ssl=<bool>]
	 * : Whatever or not to enforce SSL on requests.
	 * Default: true
	 *
	 * [--scope=<string>]
	 * : The scope the starter site falls in.
	 * Default: null
	 *
	 * [--fetch-attachments=<bool>]
	 * : The scope the starter site falls in.
	 * Default: true
	 *
	 * ## EXAMPLES
	 *
	 *     wp kubio:import-design accounting-free
	 *     wp kubio:import-design https://static-assets.kubiobuilder.com/demo-sites/production/accounting-free/content.kds
	 *     wp kubio:import-design /home/user/my-site.kds
	 *
	 * @when after_wp_load
	 * @param $args
	 * @param $assoc_args
	 * @throws \WP_CLI\ExitException
	 */
	public function __invoke( $args, $assoc_args ) {

		// phpcs:ignore Squiz.PHP.DiscouragedFunctions.Discouraged
		@ini_set( 'max_execution_time', 0 );
		// phpcs:ignore Squiz.PHP.DiscouragedFunctions.Discouraged
		set_time_limit( 0 );

		if ( ! defined( 'KUBIO_IS_STARTER_SITES_IMPORT' ) ) {
			define( 'KUBIO_IS_STARTER_SITES_IMPORT', true );
		}

		$importer_args = $this->build_importer_args( $args, $assoc_args );
		$source        = $importer_args['__source'];

		if ( is_null( $importer_args ) || empty( $importer_args ) ) {
			return;
		}

		$importer = new DemoSitesImporter( 'cli', $importer_args );

		// run importer initial cleanups
		foreach ( $importer->getBeforeImportActions() as $key => $step ) {
			$importer_args['before_import_action'] = $step;
			$importer_args['first_call']           = $key === 0;
			$importer->executeBeforeImportAction( $step, false );
		}

		\WP_CLI::line( "Content to be imported: {$source}" );
		\WP_CLI::line( 'Start importing content' );
		$importer->cliImportDemoData( $importer_args );

		\WP_CLI::line( 'Finishing import' );

		WP_CLI::success( "Design {$source}  was successfully imported!" );

		// remove scoped transient
		delete_transient( 'kubio-demo-sites-repository' );
	}


	private function normalize_source( $args ) {
		if ( empty( $args[0] ) || ! is_string( $args[0] ) ) {
			\WP_CLI::error( 'This command expects the first argument to be an importable design slug, file path or url.' );
			return null;
		}

		$design = $args[0];
		$type   = 'slug';

		if ( filter_var( $design, FILTER_VALIDATE_URL ) ) {
			$type = 'url';
		} else {
			$has_extension = substr( $design, -4 ) === '.kds' || substr( $design, -8 ) === '.kds.wxr';

			if ( $has_extension ) {
				if ( ! file_exists( $design ) ) {
					\WP_CLI::error( "The design path '{$design}' does not exists" );
					return null;
				}

				$type = 'file';
			}
		}

		return array(
			'source' => $design,
			'type'   => $type,
		);
	}

	private function normalize_assoc_args( $assoc_args ) {
		// Normalize  associative arguments.
		foreach ( $assoc_args as $assoc_arg_key => $assoc_arg_value ) {
			switch ( $assoc_arg_key ) {
				case 'verify-ssl':
					$assoc_args[ $assoc_arg_key ] =
						boolval( json_decode( $assoc_arg_value ) );
					break;
				case 'fetch-attachments':
					$assoc_args[ $assoc_arg_key ] =
						boolval( json_decode( $assoc_arg_value ) );
					break;
			}
		}

		$defaults = array(
			'verify-ssl'        => true,
			'fetch-attachments' => true,
		);

		$assoc_args = wp_parse_args( $assoc_args, $defaults );

		return $assoc_args;
	}

	private function build_importer_args( $args, $assoc_args ) {
		$assoc_args  = $this->normalize_assoc_args( $assoc_args );
		$design_info = $this->normalize_source( $args );

		if ( is_null( $design_info ) ) {
			return null;
		}

		$importer_args = array(
			'__source' => $design_info['source'],
		);

		switch ( $design_info['type'] ) {
			case 'file':
			case 'url':
				$importer_args = array_merge(
					$importer_args,
					array(
						'is_custom' => true,
						'kds_url'   => $design_info['source'],
					)
				);
				break;
			case 'slug':
				$repo   = new DemoSitesRepository();
				$design = $design_info['source'];

				$repo->retrieveDemoSites( false, $assoc_args['verify-ssl'], Arr::get( $assoc_args, 'scope', null ) );

				$data = get_transient( 'kubio-demo-sites-repository' );

				if ( ! Arr::get( (array) $data, "demos.{$design}" ) ) {
					\WP_CLI::error( '"' . $design . '" is not a valid design slug.' );
					return null;
				}

				$importer_args = array_merge(
					$importer_args,
					array(
						'is_custom' => false,
						'slug'      => $design,
					)
				);

				if ( ! empty( $assoc_args['non-ssl'] ) ) {
					$importer_args['allow--non-ssl'] = $assoc_args['non-ssl'];
				}
				break;
		}

		$importer_args['fetch_attachments'] = $assoc_args['fetch-attachments'];

		if ( ! $importer_args['fetch_attachments'] ) {
			add_filter( 'kubio/importer/disabled-import-remote-file', '__return_true' );
		}

		return $importer_args;
	}
}
