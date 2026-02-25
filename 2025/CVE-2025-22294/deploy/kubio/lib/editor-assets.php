<?php

use IlluminateAgnostic\Arr\Support\Arr;
use Kubio\AssetsDependencyInjector;
use Kubio\Core\Utils;
use Kubio\DemoSites\DemoSitesRepository;
use Kubio\Flags;
use Kubio\Core\KubioFrontPageRevertNotice;

function kubio_override_script( $scripts, $handle, $src, $deps = array(), $ver = false, $in_footer = false ) {
	$script = $scripts->query( $handle, 'registered' );
	if ( $script ) {

		$script->src  = $src;
		$script->deps = $deps;
		$script->ver  = $ver;
		$script->args = $in_footer;

		unset( $script->extra['group'] );
		if ( $in_footer ) {
			$script->add_data( 'group', 1 );
		}
	} else {
		$scripts->add( $handle, $src, $deps, $ver, $in_footer );
	}

	if ( in_array( 'wp-i18n', $deps, true ) ) {
		$translation_path = wp_normalize_path( KUBIO_ROOT_DIR . '/languages' );
		$scripts->set_translations( $handle, 'kubio', $translation_path );
	}
}

function kubio_override_style( $styles, $handle, $src, $deps = array(), $ver = false, $media = 'all' ) {
	$style = $styles->query( $handle, 'registered' );
	if ( $style ) {
		$styles->remove( $handle );
	}
	$styles->add( $handle, $src, $deps, $ver, $media );
}

function kubio_register_kubio_scripts_scripts_dependencies( $version ) {
	$scripts = array(
		array(
			'handle' => 'fancybox',
			'deps'   => array( 'jquery' ),
			'src'    => 'fancybox/jquery.fancybox.min.js',
		)
	);

	$scripts  = apply_filters("kubio/register_kubio_scripts_dependencies", $scripts );

	foreach ( $scripts as $script ) {
		AssetsDependencyInjector::registerKubioScriptsDependency(
			$script['handle'],
			kubio_url( "/static/{$script['src']}" ),
			$script['deps'],
			$version
		);
	}
}

function kubio_register_frontend_script( $handle ) {
	add_filter(
		'kubio/frontend/scripts',
		function ( $scripts ) use ( $handle ) {

			if ( ! in_array( $handle, $scripts ) ) {
				$scripts[] = $handle;
			}

			return $scripts;
		}
	);
}

function kubio_get_frontend_scripts() {
	return apply_filters( 'kubio/frontend/scripts', array() );
}

function kubio_enqueue_frontend_scripts() {
	$scripts = apply_filters( 'kubio/frontend/scripts', array() );
	foreach ( $scripts as $handle ) {
		wp_enqueue_script( $handle );
	}
}

function kubio_register_packages_scripts() {

	$registered = array();

	$translation_path = wp_normalize_path( KUBIO_ROOT_DIR . '/languages' );

	$paths = glob( KUBIO_ROOT_DIR . 'build/*/index.js' );
	foreach ( $paths as $path ) {
		$handle       = 'kubio-' . basename( dirname( $path ) );
		$asset_file   = substr( $path, 0, - 3 ) . '.asset.php';
		$asset        = file_exists( $asset_file )
				? require $asset_file
				: null;
		$dependencies = isset( $asset['dependencies'] ) ? $asset['dependencies'] : array();

		if ( Utils::isDebug() ) {
			$version = uniqid( time() . '-' );
		} else {
			$version = isset( $asset['version'] ) ? $asset['version'] : filemtime( $path );
		}

		switch ( $handle ) {
			case 'kubio-editor':
				array_push( $dependencies, 'wp-dom-ready', 'editor', 'wp-editor' );

				if ( kubio_is_kubio_editor_page() ) {
					array_push( $dependencies, 'kubio-interface-store' );
				}

				break;

			case 'kubio-format-library':
				array_push( $dependencies, 'wp-format-library' );
				break;

			case 'kubio-scripts':
				kubio_register_kubio_scripts_scripts_dependencies( $version );
				$dependencies = array_merge( $dependencies, array( 'jquery' ) );
				$dependencies = array_diff( $dependencies, array( 'wp-polyfill' ) );
				break;

			case 'kubio-frontend':
				$dependencies = array( 'kubio-scripts' );
				kubio_register_frontend_script( 'kubio-frontend' );
				break;

			case 'kubio-block-library':
				array_push( $dependencies, 'kubio-format-library' );
				break;

			case 'kubio-block-editor':
				if ( wp_script_is( 'wp-private-apis', 'registered' ) ) {
					$dependencies[] = 'wp-private-apis';
				}

				if ( wp_script_is( 'wp-experiments', 'registered' ) ) {
					$dependencies[] = 'wp-experiments';
				}

				//For backward compatability to 6.1
				if ( Utils::wpVersionCompare( '6.4', '<' ) ) {
					if ( ( $key = array_search( 'wp-commands', $dependencies ) ) !== false ) {
						unset( $dependencies[ $key ] );
					}
				}
				array_push( $dependencies, 'wp-block-directory' );
				break;

		}

		$kubio_path = substr( $path, strlen( KUBIO_ROOT_DIR ) );

		$registered[] = array(
			$handle,
			kubio_url( $kubio_path ),
			$dependencies,
			$version,
			true,
		);
	}

	foreach ( $registered as $script ) {

		if ( is_array( $script ) && count( $script ) >= 2 ) {
			$handle = $script[0];
			$deps   = $script[2];
			if ( in_array( 'wp-i18n', $deps, true ) ) {
				wp_set_script_translations( $handle, 'kubio' );
			}

			call_user_func_array( 'wp_register_script', $script );
			\wp_set_script_translations( $script[0], 'kubio', $translation_path );
			do_action( 'kubio_registered_script', $script[0], $script[3] );
		}
	}

	do_action( 'kubio_scripts_registered', $registered );
}


function kubio_replace_default_scripts( $scripts ) {

	if ( ! kubio_is_kubio_editor_page() ) {
		return;
	}

	$to_replace = array(
		'wp-block-editor' => 'block-editor',
	);

	foreach ( $to_replace as $old => $new ) {
		$script_path = KUBIO_ROOT_DIR . "/build/{$new}/index.js";
		$asset_file  = KUBIO_ROOT_DIR . "/build/{$new}/index.asset.php";

		$asset        = file_exists( $asset_file )
				? require $asset_file
				: null;
		$dependencies = isset( $asset['dependencies'] ) ? $asset['dependencies'] : array();
		$version      = isset( $asset['version'] ) ? $asset['version'] : filemtime( $script_path );

		//For backward compatability to 6.1
		if ( Utils::wpVersionCompare( '6.4', '<' ) ) {
			if ( ( $key = array_search( 'wp-commands', $dependencies ) ) !== false ) {
				unset( $dependencies[ $key ] );
			}
		}
		kubio_override_script(
			$scripts,
			$old,
			kubio_url( "/build/{$new}/index.js" ),
			$dependencies,
			$version,
			true
		);
	}
}


function kubio_register_kubio_block_library_style_dependencies( $version ) {
	$styles = array(
		array(
			'handle' => 'fancybox',
			'src'    => 'fancybox/jquery.fancybox.min.css',
		)
	);

	$styles  = apply_filters("kubio/register_block_library_style_dependencies", $styles );

	foreach ( $styles as $style ) {
		AssetsDependencyInjector::registerKubioFrontendStyleDependency(
			$style['handle'],
			kubio_url( "/static/{$style['src']}" ),
			isset( $style['deps'] ) ? $style['deps'] : array(),
			$version
		);
	}
}


function kubio_register_packages_styles() {

	$registered = array();

	foreach ( glob( KUBIO_ROOT_DIR . 'build/*/style.css' ) as $path ) {
		$handle       = 'kubio-' . basename( dirname( $path ) );
		$kubio_path   = substr( $path, strlen( KUBIO_ROOT_DIR ) );
		$version      = filemtime( $path );
		$dependencies = array();

		switch ( $handle ) {
			case 'kubio-editor':
				$dependencies = array( 'wp-edit-blocks' );
				break;

			case 'kubio-format-library':
				array_push( $dependencies, 'wp-format-library' );
				break;

			case 'kubio-admin-panel':
				array_push( $dependencies, 'kubio-utils' );
				break;

			case 'kubio-ai':
				array_push( $dependencies, 'wp-components' );
				break;

			case 'kubio-block-library':
				kubio_register_kubio_block_library_style_dependencies( $version );
				break;
		}

		$registered[] = array(
			$handle,
			kubio_url( $kubio_path ),
			$dependencies,
			$version,
		);
	}

	foreach ( glob( KUBIO_ROOT_DIR . 'build/*/editor.css' ) as $path ) {
		$handle       = 'kubio-' . basename( dirname( $path ) );
		$kubio_path   = substr( $path, strlen( KUBIO_ROOT_DIR ) );
		$version      = filemtime( $path );
		$dependencies = array();

		switch ( $handle ) {
			case 'kubio-editor':
				$dependencies = array( 'wp-edit-blocks' );
				break;

			case 'kubio-block-library':
				$dependencies = array( /* 'wp-block-library' */ );
				break;
		}

		$registered[] = array(
			"{$handle}-editor",
			kubio_url( $kubio_path ),
			$dependencies,
			$version,
		);
	}

	foreach ( $registered as $style ) {

		if ( is_array( $style ) && count( $style ) >= 2 ) {

			call_user_func_array( 'wp_register_style', $style );

		}
	}
}


function kubio_replace_default_styles( $styles ) {

	if ( ! kubio_is_kubio_editor_page() ) {
		return;
	}

	// Editor Styles .
	kubio_override_style(
		$styles,
		'wp-block-editor',
		kubio_url( 'build/block-editor/style.css' ),
		array( 'wp-components', 'wp-editor-font' ),
		filemtime( KUBIO_ROOT_DIR . 'build/editor/style.css' )
	);
	$styles->add_data( 'wp-block-editor', 'rtl', 'replace' );
}

add_action( 'init', 'kubio_register_packages_scripts' );
add_action( 'init', 'kubio_register_packages_styles' );

add_action( 'wp_default_styles', 'kubio_replace_default_styles' );
add_action( 'wp_default_scripts', 'kubio_replace_default_scripts' );


add_action(
	'kubio_registered_script',
	function ( $handle, $version ) {
		global $wp_version;
		if ( $handle === 'kubio-utils' || $handle === 'kubio-admin-panel' ) {
			$include_test_templates = defined( 'KUBIO_INCLUDE_TEST_TEMPLATES' ) && KUBIO_INCLUDE_TEST_TEMPLATES === true;
			$is_wpml_active         = kubio_wpml_is_active();
			$is_polylang_active     = kubio_polylang_is_active();

			$data = 'window.kubioUtilsData=' . wp_json_encode(
				array_merge(
					kubio_get_site_urls(),
					array(
						'defaultAssetsURL'               => kubio_url( 'static/default-assets' ),
						'staticAssetsURL'                => kubio_url( 'static' ),
						'patternsAssetsUrl'              => kubio_url( 'static/patterns' ),
						'kubioRemoteContentFile'         => 'https://static-assets.kubiobuilder.com/content-2022-05-17.json',
						'kubioCloudPresetsUrl'           => Utils::getGlobalSnippetsURL(),
						'kubioCloudPresetCategoriesUrl'  => Utils::getGlobalSnippetsCategoriesURL(),
						'kubioCloudPresetTagsUrl'        => Utils::getGlobalSnippetsTagsURL(),
						'kubioCloudUrl'                  => Utils::getCloudURL(),
						'kubioRemoteContent'             => Utils::getSnippetsURL( '/globals' ),
						'kubioLocalContentFile'          => kubio_url( 'static/patterns/content-converted.json' ),
						'kubioEditorURL'                 => add_query_arg( 'page', 'kubio', admin_url( 'admin.php' ) ),
						'patternsOnTheFly'               => ( defined( 'KUBIO_PATTERNS_ON_THE_FLY' ) && KUBIO_PATTERNS_ON_THE_FLY ) ? KUBIO_PATTERNS_ON_THE_FLY : '',
						'base_url'                       => site_url(),
						'admin_url'                      => admin_url(),
						'admin_plugins_url'              => admin_url( 'plugins.php' ),
						'demo_sites_url'                 => Utils::getStarterSitesURL(),
						'demo_parts_url'                 => Utils::getStarterPartsURL(),
						'plugins_states'                 => DemoSitesRepository::getInstance()->getPluginsStates(),
						'last_imported_starter'          => Flags::get( 'last_imported_starter' ),
						'demo_site_ajax_nonce'           => wp_create_nonce( 'kubio-ajax-demo-site-verification' ),
						'ajax_url'                       => admin_url( 'admin-ajax.php' ),
						'kubio_ajax_nonce'               => wp_create_nonce( 'kubio_ajax_nonce' ),
						'enable_starter_sites'           => apply_filters( 'kubio/starter-sites/enabled', true ),
						'wpVersion'                      => preg_replace( '/([0-9]+).([0-9]+).*/', '$1.$2', $wp_version ),
						'enable_try_online'              => Utils::isTryOnlineEnabled(),
						'supplementary_upgrade_to_pro'   => apply_filters( 'kubio/show-supplementary-upgrade-to-pro', false ),
						'kubioAIPricingURL'              => Utils::getCloudURL( '/ui-route/my-plans?purchase_ai=1' ),
						'kubioAIParallelCalls'           => apply_filters( 'kubio/ai/parallel-calls', 5 ),
						'showInternalFeatures'           => defined( '\KUBIO_INTERNAL' ) && \KUBIO_INTERNAL,
						'sectionStylesTags'              => array( 'shadow', 'flat', 'outlined', 'rounded', 'minimal' ),
						'activatedOnStage2'              => Flags::getSetting( 'activatedOnStage2', false ),
						'aiStage2'                       => Flags::getSetting( 'aiStage2', false ),
						'advancedMode'                   => Flags::getSetting( 'advancedMode', true ),
						'featuresVersion'                => Flags::getSetting( 'featuresVersion', 1 ),
						'wpAdminUpgradePage'             => add_query_arg(
							array(
								'tab'  => 'pro-upgrade',
								'page' => 'kubio-get-started',
							),
							admin_url( 'admin.php' )
						),
						'adminLanguage'                  => get_user_locale(),
						'autoStartBlackWizardOnboarding' =>  Flags::get( 'auto_start_black_wizard_onboarding', false ),
						'importDesignIndex'              => Flags::get( 'import_design_index', null ),
						'importDesignAiStructure'        => Flags::get( 'import_design_ai_structure', null ),
						'aiWizardDescriptionOptional'    => Flags::getSetting( 'aiWizardDescriptionOptional', false ),
						'showFrontPageRevertNotice'		 => KubioFrontPageRevertNotice::getShowNoticeInEditor(),
						'frontPageRevertBackupData'		 => KubioFrontPageRevertNotice::getInstance()->getFrontPageBackupData(),
						'frontPageRevertNoticeNonce' 	 =>  wp_create_nonce(KubioFrontPageRevertNotice::$nonceKey),
						'allow3rdPartyBlogOverride'      => apply_filters( 'kubio/allow_3rd_party_blog_override', true ),
						'multilanguage'                  => array(
							'hasTranslator'    => $is_wpml_active || $is_polylang_active,
							'isWpmlActive'     => $is_wpml_active,
							'isPolylangActive' => $is_polylang_active,
							'polylang_add_page_translation_nonce' => wp_create_nonce( 'kubio_api_polylang_add_page_translation' ),
						),
					),
					apply_filters( 'kubio/kubio-utils-data/extras', array() )
				)
			);

			wp_add_inline_script( $handle, $data, 'before' );
		}

		if ( $handle === 'kubio-style-manager' ) {

			$url = add_query_arg(
				array(
					'action'   => 'kubio_style_manager_web_worker',
					'_wpnonce' => wp_create_nonce( 'kubio_style_manager_web_worker_nonce' ),
					'v'        => filemtime( KUBIO_ROOT_DIR . '/defaults/style-manager-web-worker-template.js' ) . '-' . ( Utils::isDebug() ? time() : KUBIO_VERSION . '-' . $wp_version ),
				),
				admin_url( 'admin-ajax.php' )
			);

			wp_add_inline_script(
				$handle,
				'var _kubioStyleManagerWorkerURL=' . wp_json_encode( $url ),
				'before'
			);
		}
	},
	10,
	2
);

function kubio_print_style_manager_web_worker() {
	check_ajax_referer( 'kubio_style_manager_web_worker_nonce' );
	header( 'content-type: application/javascript' );

	$script = '';
	$done   = wp_scripts()->done;
	ob_start();
	wp_scripts()->done = array( 'wp-inert-polyfill', 'wp-polyfill' );
	wp_scripts()->do_items( 'kubio-style-manager' );
	wp_scripts()->done = $done;
	$script            = ob_get_clean();

	$script = preg_replace_callback(
		'#<script(.*?)>(.*?)</script>#s',
		function ( $matches ) {
			$script_attrs = Arr::get( $matches, 1, '' );
			preg_match( "#src=(\"|')(.*?)(\"|')#", $script_attrs, $attrs_match );
			$url     = Arr::get( $attrs_match, 2, '' );
			$content = trim( Arr::get( $matches, 2, '' ) );

			$result = array();

			if ( ! empty( $url ) ) {
				$result[] = sprintf( "importScripts('%s');", $url );
			}

			if ( ! empty( $content ) ) {
				$result[] = $content;
			}

			return trim( implode( "\n", $result ) ) . "\n\n";
		},
		$script
	);

	$content = file_get_contents( KUBIO_ROOT_DIR . '/defaults/style-manager-web-worker-template.js' );
	$content = str_replace( '// {{{importScriptsPlaceholder}}}', $script, $content );

	if ( ! Utils::isDebug() ) {
		header( 'Cache-control: public' );
		header( 'Last-Modified: ' . gmdate( 'D, d M Y H:i:s', time() ) . ' GMT' );
		header( 'Expires: ' . gmdate( 'D, d M Y H:i:s', time() + YEAR_IN_SECONDS ) . ' GMT' );
		header( 'Etag: ' . md5( $content ) );
	}

	// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
	die( $content );
}

add_action( 'wp_ajax_kubio_style_manager_web_worker', 'kubio_print_style_manager_web_worker' );

// quick test for safari
add_action(
	'admin_init',
	function () {
		ob_start();
		?>
	<script>
		window.requestIdleCallback =
			window.requestIdleCallback ||
			function (cb) {
				var start = Date.now();
				return setTimeout(function () {
					cb({
						didTimeout: false,
						timeRemaining: function () {
							return Math.max(0, 50 - (Date.now() - start));
						},
					});
				}, 1);
			};

		window.cancelIdleCallback =
			window.cancelIdleCallback ||
			function (id) {
				clearTimeout(id);
			};
	</script>
		<?php

		$content = wp_strip_all_tags( ob_get_clean() );

		wp_add_inline_script( 'wp-polyfill', $content, 'after' );
	}
);

function kubio_defer_kubio_scripts( $tag, $handle, $src ) {

	if ( is_admin() ) {
		return $tag;
	}

	if ( strpos( $src, kubio_url() ) === 0 ) {
		$tag = str_replace( 'src=', 'defer src=', $tag );
	}

	return $tag;
}

add_filter( 'script_loader_tag', 'kubio_defer_kubio_scripts', 10, 3 );

function kubio_defer_kubio_styles( $tag, $handle, $href, $media ) {

	if ( is_admin() ) {
		return $tag;
	}

	$deferrable_handles = array( 'kubio-google-fonts', 'kubio-third-party-blocks' );

	if ( in_array( $handle, $deferrable_handles ) ) {
		$tag = preg_replace( "#rel='(.*?)'#", 'rel="preload" as="style" onload="this.onload=null;this.rel=\'$1\'"', $tag );
		// phpcs:ignore WordPress.WP.EnqueuedResources.NonEnqueuedStylesheet
		$tag .= "<noscript><link rel='stylesheet' href='{$href}' media='{$media}'></noscript>";
	}

	return $tag;
}

add_filter( 'style_loader_tag', 'kubio_defer_kubio_styles', 10, 4 );
