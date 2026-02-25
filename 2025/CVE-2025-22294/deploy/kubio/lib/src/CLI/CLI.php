<?php

namespace Kubio\CLI;

use WP_CLI;

class CLI {

	public static function load() {
		if ( defined( 'WP_CLI' ) && WP_CLI ) {
			WP_CLI::add_command( 'kubio:import-design', ImportDemoSiteCommand::class );
			WP_CLI::add_command( 'kubio:export-design', ExportDemoSiteCommand::class );
		}
	}
}
