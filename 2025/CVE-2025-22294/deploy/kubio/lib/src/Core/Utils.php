<?php


namespace Kubio\Core;

use IlluminateAgnostic\Arr\Support\Arr;
use Kubio\Config;
use Kubio\Flags;
use WP_Error;

class Utils {


	private static $execute_start_time;
	protected static $wooIsActive              = null;
	protected static $kubioShopIsActive        = null;
	protected static $currentPageIsWooPage     = null;
	protected static $currentPageIsWooTemplate = null;
	public static $kubioShopSupportedThemes    = array( 'elevate-wp', 'pathway', 'pixy', 'ketos', 'consus', 'zeka', 'niveau', 'rainbow' );
	public static $themeIsSupportedForShop     = null;

	public static function mapHideClassesByMedia(
		$hiddenByMedia,
		$negateValue = false
	) {
		$mapHideClassesByMedia = array();
		foreach ( $hiddenByMedia as $media => $isHidden ) {
			if ( $negateValue ) {
				$isHidden = ! $isHidden;
			}
			if ( $isHidden ) {
				array_push( $mapHideClassesByMedia, "kubio-hide-on-$media" );
			}
		}

		return $mapHideClassesByMedia;
	}

	public static function useJSComponentProps( $name, $settings = array() ) {
		$prefix = Config::$name;

		return array(
			"data-{$prefix}-component" => $name,
			"data-{$prefix}-settings"  => wp_json_encode( $settings ),
		);
	}

	public static function getLinkAttributes( $linkObject ) {
		$defaultValue     = array(
			'value'         => '',
			'typeOpenLink'  => 'sameWindow',
			'noFollow'      => false,
			'lightboxMedia' => '',
		);
		$mergedLinkObject = LodashBasic::merge( array(), $defaultValue, $linkObject );
		$linkAttributes   = array(
			'href'                 => null,
			'target'               => null,
			'rel'                  => null,
			'data-kubio-component' => null,
		);

		if ( $mergedLinkObject ) {
			if ( $mergedLinkObject['value'] ) {
				$linkAttributes['href'] = esc_url( $mergedLinkObject['value'] );
			}
			$linkType = LodashBasic::get( $mergedLinkObject, 'typeOpenLink', '' );
			if ( $linkType === 'newWindow' ) {
				$linkAttributes['target'] = '_blank';
			}

			if ( $linkType === 'lightbox' ) {
				$lightboxType = $mergedLinkObject['lightboxMedia'];
				if ( $lightboxType === '' ) {
					$lightboxType = null;
				}
				$linkAttributes['data-default-type'] = esc_attr( $lightboxType );
				$linkAttributes['data-fancybox']     = wp_rand() . '';
			}
			if ( $mergedLinkObject['noFollow'] ) {
				$linkAttributes['rel'] = 'nofollow';
			}
		}

		return $linkAttributes;
	}

	public static function shortcodeDecode( $data ) {
		return urldecode( base64_decode( $data ) );
	}

	public static function getDefaultAssetsURL( $url ) {
		$staticUrl = kubio_url( 'static/default-assets' );

		return $staticUrl . '/' . ltrim( $url, '/' );
	}

	public static function canEdit() {
		return current_user_can( 'edit_theme_options' ) && current_user_can( 'edit_posts' );
	}

	public static function getEmptyShortcodePlaceholder() {
		if ( is_user_logged_in() ) {
			return static::getFrontendPlaceHolder(
				sprintf(
					'%s<br/><div class="kubio-frontent-placeholder--small">%s</div>',
					__( 'Shortcode is empty.', 'kubio' ),
					__( 'Edit this page to insert a shortcode or delete this block.', 'kubio' )
				)
			);
		} else {
			return '';
		}
	}

	public static function getEmptyPlaceholder( $block_name, $items_type ) {
		if ( is_user_logged_in() ) {
			return static::getFrontendPlaceHolder(
				sprintf(
					'%s<br/><div class="kubio-frontent-placeholder--small">%s</div>',
					// translators: %1$s: block name, %2$s: items type
					sprintf( __( '%1$s has no %2$s.', 'kubio' ), $block_name, $items_type ),
					// translators: %s: items type
					sprintf( __( 'Edit this page to insert %s or delete this block.', 'kubio' ), $items_type )
				)
			);
		}

		return '';
	}

	//the production build does not include the patterns' folder, we can use this to determine if the build is dev or prod
	public static function isProduction() {
		$isProd = ! file_exists( KUBIO_ROOT_DIR . '/static/patterns/content-converted.json' );

		return $isProd;
	}

	public static function getFrontendPlaceHolder( $message, $options = array() ) {

		$options = array_merge(
			array(
				'info'      => true,
				'title'     => __( 'Kubio info', 'kubio' ),
				'if_logged' => true,
			),
			$options
		);

		if ( $options['if_logged'] ) {
			if ( ! is_user_logged_in() ) {
				return;
			}
		}

		if ( is_callable( $message ) ) {
			$message = call_user_func( $message );
		}

		$info = '';
		if ( $options['info'] ) {
			$info = sprintf(
				'<div class="kubio-frontent-placeholder--info">' .
				'	<div class="kubio-frontent-placeholder--logo">%s</div>' .
				'   <div class="kubio-frontent-placeholder--title">%s</div>' .
				'</div>',
				wp_kses_post( KUBIO_LOGO_SVG ),
				$options['title']
			);
		}

		return sprintf( '<div class="kubio-frontent-placeholder"><div>%s</div><div>%s</div></div>', $info, $message );
	}

	public static function kubioCacheGet( $name, $default = null ) {

		$kubio_cache = isset( $GLOBALS['__kubio_plugin_cache__'] ) ? $GLOBALS['__kubio_plugin_cache__'] : array();
		$value       = $default;

		if ( self::kubioCacheHas( $name ) ) {
			$value = $kubio_cache[ $name ];
		}

		return $value;
	}

	public static function kubioCacheHas( $name ) {
		$kubio_cache = isset( $GLOBALS['__kubio_plugin_cache__'] ) ? $GLOBALS['__kubio_plugin_cache__'] : array();

		return array_key_exists( $name, $kubio_cache );
	}

	public static function kubioCacheSet( $name, $value ) {
		$kubio_cache          = isset( $GLOBALS['__kubio_plugin_cache__'] ) ? $GLOBALS['__kubio_plugin_cache__'] : array();
		$kubio_cache[ $name ] = $value;

		$GLOBALS['__kubio_plugin_cache__'] = $kubio_cache;
	}

	/**
	 * Remove empty branches from array
	 *
	 * @param array $array the array to walk
	 *
	 * @return array
	 */
	public static function arrayRecursiveRemoveEmptyBranches( array &$array ) {
		foreach ( $array as $key => &$value ) {
			if ( is_array( $value ) ) {
				$array[ $key ] = static::arrayRecursiveRemoveEmptyBranches( $value );

				if ( empty( $value ) ) {
					unset( $array[ $key ] );
				}
			}
		}

		return $array;
	}

	public static function walkBlocks( &$blocks, $callback ) {
		array_walk(
			$blocks,
			function ( &$block ) use ( $callback ) {
				if ( isset( $block['blockName'] ) ) {
					$callback( $block );
				}
				if ( isset( $block['innerBlocks'] ) ) {
					static::walkBlocks( $block['innerBlocks'], $callback );
				}
			}
		);
	}

	public static function kses( $text, $allowed_protocols = array() ) {

		static $allowed_html;

		if ( ! $allowed_html ) {
			$allowed_html = wp_kses_allowed_html( 'post' );
		}

		// fix the issue with rgb / rgba colors in style atts

		$rgbRegex = '#rgb\(((?:\s*\d+\s*,){2}\s*[\d]+)\)#i';
		$text     = preg_replace( $rgbRegex, 'rgb__$1__rgb', $text );

		$rgbaRegex = '#rgba\(((\s*\d+\s*,){3}[\d\.]+)\)#i';
		$text      = preg_replace( $rgbaRegex, 'rgba__$1__rgb', $text );

		$text = wp_kses( $text, $allowed_html, $allowed_protocols );

		$text = str_replace( 'rgba__', 'rgba(', $text );
		$text = str_replace( 'rgb__', 'rgb(', $text );
		$text = str_replace( '__rgb', ')', $text );

		return $text;
	}

	/**
	 * Compares version string to WP base version ( e.g. X.Y.Z without looking for -beta* -RC* suffixes )
	 *
	 * @param string $compare_to - semver version number
	 * @param string $operator - version_compare operator
	 * @return void
	 */
	public static function wpVersionCompare( $compare_to, $operator ) {
		global $wp_version;
		$version_parts = sscanf( $wp_version, '%d.%d.%d' );
		$version       = array();

		foreach ( $version_parts as $version_part ) {
			if ( $version_part !== null ) {
				$version[] = $version_part;
			}
		}

		$version = implode( '.', $version );
		return version_compare( $version, $compare_to, $operator );
	}

	public static function ksesSVG( $svg_content ) {
		$allowed_html = wp_kses_allowed_html( 'post' );
		return wp_kses( $svg_content, $allowed_html );
	}

	/**
	 * Check if the execution time has enough remaining seconds
	 *
	 * @param integer $compare_to_time - necessary time in seconds
	 * @return boolean
	 */
	public static function hasEnoughRemainingTime( $compare_to_time = 10 ) {

		if ( ! static::$execute_start_time ) {
			static::$execute_start_time = intval( Arr::get( $_SERVER, 'REQUEST_TIME_FLOAT', time() ) );
		}

		$diff = time() - static::$execute_start_time;

		$max_exec_time = @ini_get( 'max_execution_time' );

		// assume 30 seconds if not available
		if ( ! $max_exec_time ) {
			$max_exec_time = 30;
		}

		return ( intval( $max_exec_time ) - $diff >= $compare_to_time );
	}

	/**
	 * Check if current WordPress installation validates plugin requirements
	 *
	 * @return boolean|\WP_Error
	 */
	public static function validateRequirements() {
		include_once ABSPATH . 'wp-admin/includes/plugin.php';
		$plugin_headers = get_plugin_data( KUBIO_ENTRY_FILE );
		$required_wp    = ! empty( $plugin_headers['RequiresWP'] ) ? $plugin_headers['RequiresWP'] : false;
		$required_php   = ! empty( $plugin_headers['RequiresPHP'] ) ? $plugin_headers['RequiresPHP'] : false;

		if ( defined( 'KUBIO_MINIMUM_WP_VERSION' ) && KUBIO_MINIMUM_WP_VERSION ) {
			$required_wp = KUBIO_MINIMUM_WP_VERSION;
		}

		$compatible_wp  = $required_wp ? Utils::wpVersionCompare( $required_wp, '>=' ) : true;
		$compatible_php = version_compare( phpversion(), $required_php, '>=' );

		$php_update_message = '</p><p>' . sprintf(
			/* translators: %s: URL to Update PHP page. */
			__( '<a href="%s">Learn more about updating PHP</a>', 'kubio' ),
			esc_url( wp_get_update_php_url() )
		);

		$update_wp_core = sprintf(
			/* translators: %s: URL to Update PHP page. */
			__( '<a href="%s">Update WordPress now!</a>', 'kubio' ),
			esc_url( admin_url( 'update-core.php' ) )
		);

		if ( ! $compatible_wp && ! $compatible_php ) {
			return new WP_Error(
				'plugin_wp_php_incompatible',
				'<p>' . sprintf(
					/* translators: 1: Current WordPress version, 2: Current PHP version, 3: Plugin name, 4: Required WordPress version, 5: Required PHP version. */
					__( '<strong>Error:</strong> Current versions of WordPress (%1$s) and PHP (%2$s) do not meet minimum requirements for %3$s. The plugin requires WordPress %4$s and PHP %5$s.', 'kubio' ),
					get_bloginfo( 'version' ),
					phpversion(),
					$plugin_headers['Name'],
					$required_wp,
					$required_php
				) . $php_update_message . '<br/>' . $update_wp_core . '</p>'
			);
		} elseif ( ! $compatible_php ) {
			return new WP_Error(
				'plugin_php_incompatible',
				'<p>' . sprintf(
					/* translators: 1: Current PHP version, 2: Plugin name, 3: Required PHP version. */
					__( '<strong>Error:</strong> Current PHP version (%1$s) does not meet minimum requirements for %2$s. The plugin requires PHP %3$s.', 'kubio' ),
					phpversion(),
					$plugin_headers['Name'],
					$required_php
				) . $php_update_message . '</p>'
			);
		} elseif ( ! $compatible_wp ) {
			return new WP_Error(
				'plugin_wp_incompatible',
				'<p>' . sprintf(
					/* translators: 1: Current WordPress version, 2: Plugin name, 3: Required WordPress version. */
					__( '<strong>Error:</strong> Current WordPress version (%1$s) does not meet minimum requirements for %2$s. The plugin requires WordPress %3$s.', 'kubio' ),
					get_bloginfo( 'version' ),
					$plugin_headers['Name'],
					$required_wp
				) . '&nbsp;' . $update_wp_core . '</p>'
			);
		}
	}

	public static function getPluginVersions( $skip_current = false ) {
		include_once ABSPATH . 'wp-admin/includes/plugin.php';
		$plugin_headers = get_plugin_data( KUBIO_ENTRY_FILE );
		$version        = ! empty( $plugin_headers['Version'] ) ? $plugin_headers['Version'] : false;
		$name           = ! empty( $plugin_headers['Name'] ) ? $plugin_headers['Name'] : false;
		$url            = apply_filters(
			'kubio/previous-versions/url',
			sprintf( 'https://api.wordpress.org/plugins/info/1.0/%s.json', KUBIO_SLUG )
		);

		$response = wp_remote_get( $url );

		if ( is_wp_error( $response ) ) {
			return null;
		}

		$response = wp_remote_retrieve_body( $response );

		if ( is_serialized( $response ) ) {
			$response = maybe_unserialize( $response );
		} else {
			$response = json_decode( $response );
		}

		if ( ! is_object( $response ) ) {
			return null;
		}
		if ( ! isset( $response->versions ) ) {
			return null;
		}

		$versions = array();
		foreach ( $response->versions as $key => $value ) {

			$version = is_object( $value ) ? $value->version : $key;

			if ( $version === 'trunk' ) {
				continue;
			}

			if ( $skip_current && $version === \KUBIO_VERSION ) {
				continue;
			}

			$versions[ $version ] = array(
				'version'       => $version,
				'named_version' => sprintf( '%s v%s', $name, $version ),
				'url'           => is_object( $value ) ? $value->file : $value,
			);
		}

		return $versions;
	}

	public static function getCloudURL( $url = '', $cloud_root_url = KUBIO_CLOUD_URL ) {
		$url = trim( $url, '/' );

		$args = array(
			'kubio_version' => KUBIO_VERSION,
			'kubio_build'   => KUBIO_BUILD_NUMBER,
			'activated_on'  => Flags::get( 'kubio_activation_time', '' ),
		);

		$is_skip_cache_flag_on = defined( 'KUBIO_SKIP_CLOUD_CACHE' ) && KUBIO_SKIP_CLOUD_CACHE;

		if ( Utils::isDebug() || $is_skip_cache_flag_on ) {
			$args[ 'kbp_' . time() ] = time();
		}

		$url = add_query_arg( $args, rtrim( "$cloud_root_url/$url", '/' ) );

		return $url;
	}

	public static function getStarterSitesURL() {
		$base_url = KUBIO_CLOUD_URL;
		if ( defined( 'KUBIO_STARTER_SITES_BASE_URL' ) && KUBIO_STARTER_SITES_BASE_URL ) {
			$base_url = KUBIO_STARTER_SITES_BASE_URL;
		}
		$relative_url = '/api/project/demo-sites';
		if ( defined( 'KUBIO_INCLUDE_TEST_TEMPLATES' ) && KUBIO_INCLUDE_TEST_TEMPLATES ) {
			$relative_url = "$relative_url/?testing=true";
		}
		return Utils::getCloudURL( $relative_url, $base_url );
	}

	public static function getStarterPartsURL() {
		$base_url = KUBIO_CLOUD_URL;
		if ( defined( 'KUBIO_STARTER_SITES_BASE_URL' ) && KUBIO_STARTER_SITES_BASE_URL ) {
			$base_url = KUBIO_STARTER_SITES_BASE_URL;
		}
		$relative_url = '/api/demo-sites/get-demo-content';
		if ( defined( 'KUBIO_INCLUDE_TEST_TEMPLATES' ) && KUBIO_INCLUDE_TEST_TEMPLATES ) {
			$relative_url = "$relative_url/?testing=true";
		}
		return self::getCloudURL( $relative_url, $base_url );
	}

	public static function getSnippetsURL( $path = '' ) {
		$base_url      = KUBIO_CLOUD_URL;
		$path          = trim( $path, '/' );
		$relative_path = "/api/snippets/$path";
		if ( defined( 'KUBIO_SNIPPETS_BASE_URL' ) ) {
			$base_url = KUBIO_SNIPPETS_BASE_URL;
		}

		return self::getCloudURL( $relative_path, $base_url );
	}

	public static function getGlobalSnippetsURL() {
		if ( defined( 'KUBIO_INCLUDE_TEST_SNIPPETS' ) && KUBIO_INCLUDE_TEST_SNIPPETS ) {
			return self::getSnippetsURL( '/globals?testing=true' );
		}

		return self::getSnippetsURL( '/globals' );
	}

	public static function getGlobalSnippetsCategoriesURL() {
		if ( defined( 'KUBIO_INCLUDE_TEST_SNIPPETS' ) && KUBIO_INCLUDE_TEST_SNIPPETS ) {
			return self::getSnippetsURL( '/categories?testing=true' );
		}

		return self::getSnippetsURL( '/categories' );
	}
	public static function getGlobalSnippetsTagsURL() {

		return self::getSnippetsURL( '/tags' );
	}

	public static function isDebug() {
		return defined( 'KUBIO_DEBUG' ) && KUBIO_DEBUG;
	}

	public static function isCLI() {
		return defined( 'WP_CLI' ) && WP_CLI;
	}


	/**
	 * return and unique autoinc id based on prefix
	 *
	 * @param  string $prefix
	 * @return string
	 */
	public static function uniqueId( $prefix = '' ) {
		static $state;

		if ( ! is_array( $state ) ) {
			$state = array();
		}

		if ( ! isset( $state[ $prefix ] ) ) {
			$state[ $prefix ] = 0;
		}

		$id = $state[ $prefix ]++;

		return $id;
	}

	public static function getFilePath( $path ) {
		return KUBIO_ROOT_DIR . "/$path";
	}

	public static function getURL( $path ) {
		return KUBIO_ROOT_URL . "/$path";
	}
	public static function getWooIsActive() {
		if ( static::$wooIsActive !== null ) {
			return static::$wooIsActive;
		}
		$wooPluginName       = 'woocommerce/woocommerce.php';
		$activePlugins       = get_option( 'active_plugins', array() );
		static::$wooIsActive = in_array( $wooPluginName, $activePlugins );

		return static::$wooIsActive;
	}

	//For the demo we only show shop content and features if the shop plugin was already activated.
	//When shop will be released this function will always return true. This is so we can lunch kubio with the shop features
	//But only enale them to a select few.
	public static function getKubioShopFeatureIsActivated() {
		return static::getKubioShopIsActive();
	}

	public static function getKubioShopIsActive() {
		if ( static::$kubioShopIsActive !== null ) {
			return static::$kubioShopIsActive;
		}
		$is_kubio_shop_active = false;
		$activePlugins        = get_option( 'active_plugins', array() );
		$kubioShopPluginsName = array( 'kubio-shop/plugin.php', 'kubio-shop-pro/plugin.php' );
		foreach ( $kubioShopPluginsName as $pluginName ) {
			if ( in_array( $pluginName, $activePlugins ) ) {
				$is_kubio_shop_active = true;
			}
		}

		static::$kubioShopIsActive = apply_filters( 'kubio_shop/is_kubio_shop_active', $is_kubio_shop_active );

		return static::$kubioShopIsActive;
	}

	public static function getThemeIsSupportedForShop() {
		if ( static::$themeIsSupportedForShop !== null ) {
			return static::$themeIsSupportedForShop;
		}

		//The filter is not good enough because theme code gets called after plugin code so if we want to stop some logic
		//when files are loading we can't with the filter.
		//return apply_filters( 'kubio/has_block_templates_support', false );

		$theme_is_supported = true;

		if ( ! in_array( get_option( 'template' ), static::$kubioShopSupportedThemes ) ) {

			$theme_is_supported = false;
		} else {
			// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.MissingUnslash, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
			$is_customize_page = ( is_admin() && isset( $_SERVER['PHP_SELF'] ) && 'customize.php' === basename( $_SERVER['PHP_SELF'] ) );
			$theme             = get_template();
			// phpcs:ignore WordPress.Security.NonceVerification.Recommended
			if ( isset( $_GET['theme'] ) && $_GET['theme'] !== get_stylesheet() ) {
				// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.MissingUnslash,WordPress.Security.NonceVerification.Recommended
				$theme = sanitize_text_field( $_GET['theme'] );
			}

			//if is theme preview
			if ( $is_customize_page && ! in_array( $theme, static::$kubioShopSupportedThemes, true ) ) {
				$theme_is_supported = false;
			}
		}

		static::$themeIsSupportedForShop = $theme_is_supported;
		return static::$themeIsSupportedForShop;
	}
	public static function getShowShopContent() {
		return static::getKubioShopFeatureIsActivated() && static::getWooIsActive() && static::getKubioShopIsActive() && static::getThemeIsSupportedForShop();
	}

	public static function getCurrentPageIsWooPage() {
		if ( static::$currentPageIsWooPage !== null ) {
			return static::$currentPageIsWooPage;
		}

		if ( ! static::getWooIsActive() ) {
			static::$currentPageIsWooPage = false;
			return static::$currentPageIsWooPage;
		}

		$is_woo_page = is_cart() || is_checkout() || is_account_page();

		static::$currentPageIsWooPage = $is_woo_page;
		return static::$currentPageIsWooPage;
	}
	public static function getCurrentPageIsWooTemplate() {
		if ( static::$currentPageIsWooTemplate !== null ) {
			return static::$currentPageIsWooTemplate;
		}

		if ( ! static::getWooIsActive() ) {
			static::$currentPageIsWooTemplate = false;
			return static::$currentPageIsWooTemplate;
		}

		$is_shop_page                     = \kubio_woocommerce_is_product_archive_page();
		$is_woo_template                  = is_product() || $is_shop_page;
		static::$currentPageIsWooTemplate = $is_woo_template;
		return static::$currentPageIsWooTemplate;
	}

	public static function getCurrentPageIsWoo() {
		return static::getCurrentPageIsWooPage() || static::getCurrentPageIsWooTemplate();
	}

	public static function getWooIsUpgradedToShopBlocks() {
		return static::getKubioShopFeatureIsActivated() &&
			static::getWooIsActive() &&
			static::getKubioShopIsActive() &&
			static::getWooIsUpgradedToShopBlocksSetting();
	}
	public static function getWooIsUpgradedToShopBlocksSetting() {
		return Flags::getSetting( 'kubioShop.convertedShortcodesToBlocks', false );
	}
	/**
	 * Check if the referer is the Kubio editor page
	 *
	 * @return boolean
	 */
	public static function hasKubioEditorReferer() {
		$referer = wp_get_referer();

		if ( ! $referer ) {
			return false;
		}

		if ( strpos( $referer, admin_url( 'admin.php' ) ) !== 0 ) {
			return false;
		}

		parse_str( wp_parse_url( $referer, PHP_URL_QUERY ), $args );

		return Arr::get( $args, 'page', null ) === 'kubio';
	}

	public static function kubioGetEditorURL( $args = array() ) {
		return add_query_arg(
			array_merge( array( 'page' => 'kubio' ), $args ),
			admin_url( 'admin.php' )
		);
	}

	public static function isTrue( $value ) {

		if ( empty( $value ) ) {
			return false;
		}

		return in_array( $value, array( 'on', 'true', '1', 1, true ), true );
	}

	public static function isFalse( $value ) {
		return ! static::isTrue( $value );
	}


	public static function isRestRequest() {
		return defined( 'REST_REQUEST' ) && REST_REQUEST;
	}

	public static function maybeJSONDecode( $data ) {
		if ( ! is_string( $data ) ) {
			return $data;
		}

		$decoded = json_decode( $data, true );

		if ( json_last_error() === JSON_ERROR_NONE ) {
			return $decoded;
		}

		$decoded = json_decode( urldecode( $data ), true );

		if ( json_last_error() === JSON_ERROR_NONE ) {
			return $decoded;
		}

		return $data;
	}

	public static function isTryOnlineEnabled() {
		return apply_filters( 'kubio/enable_try_online', false );
	}

	public static function humanizeArray( $array, $spacer = "\t", $prefix = '', $level = 0 ) {

		if ( ! is_array( $array ) ) {
			return $array;
		}

		$decorators           = array( '-', '*', '#' );
		$decorator            = $decorators[ $level % count( $decorators ) ];
		$structure_text_lines = array();
		$indent               = str_repeat( $spacer, $level );

		foreach ( $array as $index => $value ) {

			$index = is_numeric( $index ) ? intval( $index ) + 1 : $index;

			list($label, $desc) = array_replace( array( '', '' ), explode( '#', $prefix . strval( $index ) ) );

			if ( $desc ) {
				$desc = " ( {$desc} ),";
			}

			if ( is_array( $value ) ) {
				$structure_text_lines[] = rtrim( "{$indent}{$decorator} {$label}: {$desc}", ', ' );
				$structure_text_lines[] = static::humanizeArray( $value, $spacer, $prefix, $level + 1 );
			} else {

				if ( is_string( $value ) ) {
					$lines = explode( "\n", $value );
					if ( count( $lines ) > 1 ) {
						$line_prefix = str_repeat( $spacer, $level + 1 );
						foreach ( $lines as $l_index => $line ) {
							$lines[ $l_index ] = "{$line_prefix}{$line}";
						}

						$value = "\n" . implode( "\n", $lines );
					}
				}

				$structure_text_lines[] = rtrim( "{$indent}{$decorator} {$label}: {$desc}{$value}", ', ' );
			}
		}

		if ( $level === 0 ) {
			return trim( implode( "\n", $structure_text_lines ) );
		}

		return implode( "\n", $structure_text_lines ) . "\n";
	}

	public static function pageHasCustomTemplate( $post_id = null ): bool {
		if ( ! $post_id ) {
			$post_id = get_the_ID();
		}

		$template_slug = get_post_meta( $post_id, '_wp_page_template', true );
		if ( $template_slug && $template_slug !== 'default' ) {
			return true;
		}

		return false;
	}

	public static function getThemeTemplateParts() {
		$default_language = apply_filters( 'wpml_default_language', null );
		$query            = new \WP_Query(
			array(
				'post_type'      => 'wp_template_part',
				'post_status'    => array( 'publish' ),
				'posts_per_page' => - 1,
				// phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_tax_query
				'tax_query'      => array(
					array(
						'taxonomy' => 'wp_theme',
						'field'    => 'name',
						'terms'    => get_stylesheet(),
					),
				),
				'kubio_filter'   => array(
					'language_code' => $default_language,
				),
			)
		);

		if ( $query->have_posts() ) {
			return array_map(
				function ( $post ) {
					return $post->post_name;
				},
				$query->posts
			);
		}

		return null;
	}

	public static function getPageTemplate( $post_id ) {
		if ( ! $post_id ) {
			return null;
		}

		$permalink = get_permalink( $post_id );
		$url       = add_query_arg( '_wp-find-template', 'true', $permalink );
		$res       = wp_remote_get( $url );
		$data      = wp_remote_retrieve_body( $res );
		$body      = json_decode( $data );

		if ( $body ) {
			// FSE theme
			return $body->data;
		}

		// Non FSE theme
		return null;
	}
}
