<?php

use IlluminateAgnostic\Arr\Support\Arr;
use Kubio\Core\LodashBasic;
use Kubio\Core\Utils;
use Kubio\Flags;

add_filter(
	'kubio/preview/template_part_blocks',
	function ( $parts = array() ) {
		return array_merge(
			(array) $parts,
			array(
				'core/template-part',
				'kubio/header',
				'kubio/footer',
				'kubio/sidebar',
			)
		);
	},
	5,
	1
);

function kubio_blocks_update_template_parts_theme( $parsed_blocks, $theme ) {
	$parts_block_names = apply_filters(
		'kubio/preview/template_part_blocks',
		array()
	);

	Utils::walkBlocks(
		$parsed_blocks,
		function ( &$block ) use (
			$theme,
			$parts_block_names
		) {
			$block_name       = Arr::get( $block, 'blockName' );
			$current_theme    = Arr::get( $block, 'attrs.theme' );
			$is_template_part = in_array( $block_name, $parts_block_names );

			if ( $block_name && ( $current_theme || $is_template_part ) ) {
				Arr::set( $block, 'attrs.theme', $theme );
			}
		}
	);

	return $parsed_blocks;
}

//this code is not required for the attributes to work. But it could be a problem in the future if we don't register the
//anchor attribute
function kubio_register_anchor_attribute( $metaData ) {
	$supportsAnchor = LodashBasic::get(
		$metaData,
		array( 'supports', 'anchor' ),
		false
	);
	if ( $supportsAnchor ) {
		$hasAnchorAttribute = LodashBasic::get(
			$metaData,
			array( 'attributes', 'anchor' ),
			false
		);
		if ( ! $hasAnchorAttribute ) {
			$anchorData = array(
				'type' => 'string',
			);
			LodashBasic::set( $metaData, array( 'attributes', 'anchor' ), $anchorData );
		}
	}

	return $metaData;
}

add_filter(
	'kubio/blocks/register_block_type',
	'kubio_register_anchor_attribute'
);

function kubio_add_full_hd_image_size() {
	add_image_size( 'kubio-fullhd', 1920, 1080 );
}

add_filter( 'after_setup_theme', 'kubio_add_full_hd_image_size' );

function kubio_url_import_cdn_files( $url ) {
	if ( strpos( $url, 'wp-content/uploads' ) !== false ) {
		if ( \_\startsWith( $url, site_url() ) ) {
			return $url;
		}

		return str_replace(
			'https://demos.kubiobuilder.com',
			'https://static-assets.kubiobuilder.com/demos',
			$url
		);
	}

	return $url;
}

add_filter( 'kubio/importer/kubio-source-url', 'kubio_url_import_cdn_files' );

//load full width template if the page is empty
add_action(
	'wp',
	function () {
		/** @var WP_Query $wp_query */

		$is_kubio_theme = kubio_theme_has_kubio_block_support();

		//only apply to pages
		if ( is_page() && ! is_front_page() && $is_kubio_theme ) {
			/** @var \WP_Post $post */
			global $post;

			if ( ! $post ) {
				return;
			}

			$saved_in_kubio = get_post_meta( $post->ID, 'saved_in_kubio', true );
			if ( Utils::isTrue( $saved_in_kubio ) ) {
				return;
			}

			$template      = get_page_template_slug( $post->ID );
			$is_from_kubio = Utils::hasKubioEditorReferer();
			if (
				empty( trim( $post->post_content ) ) &&
				// phpcs:ignore WordPress.Security.NonceVerification.Recommended
				isset( $_GET['_wp-find-template'] ) &&
				$is_from_kubio &&
				empty( $template )
			) {
				/**
				 * The locate_block_template function has a check if the get parameter the _wp-find-template is set it
				 * returns wp_send_json_success( $block_template ) with the template provided;
				 * the  wp_send_json_success( $block_template );
				 *
				 * If the full width template is found the wp_send_json_success will return the full width tempalte then die
				 * the request. If the full width template is not found then the function will return the 'full-width' text
				 * and we do nothing with it. But the code will run normally and return the normal template that should be
				 * Page.
				 */
				locate_block_template( 'full-width', 'page', array( 'full-width.php' ) );
				locate_block_template(
					'kubio-full-width',
					'page',
					array(
						'kubio-full-width.php',
					)
				);
			}
		}
	},
	5
);

//show index when on latest posts page. It's weird but 2022 theme also shows front page when you click edit and latest
//posts is your homepage which is wrong.
add_action(
	'wp',
	function () {
		/** @var WP_Query $wp_query */

		//when the front page is the latest posts load the home or index template
		if ( is_front_page() && is_home() ) {
			// phpcs:ignore WordPress.Security.NonceVerification.Recommended
			$referer       = Arr::get( $_SERVER, 'HTTP_REFERER', '' );
			$callFromKubio =
				strpos( $referer, 'page=kubio' ) !== false &&
				strpos( $referer, admin_url() ) !== false;
				// phpcs:ignore WordPress.Security.NonceVerification.Recommended
			if ( isset( $_GET['_wp-find-template'] ) && $callFromKubio ) {
				locate_block_template( 'home', 'page', array( 'home.php' ) );
				locate_block_template( 'index', 'page', array( 'index.php' ) );
			}
		}
	},
	5
);
function kubio_change_customize_link_to_open_kubio_editor() {
	$kubio_url = Utils::kubioGetEditorURL(); ?>
	<script>
		(function () {
			var button = document.querySelector('.button.load-customize,#welcome-panel .load-customize');

			if (button) {
				button.href = "<?php echo esc_url( $kubio_url ); ?>";
			}
		})();
	</script>
	<?php
}

add_action(
	'welcome_panel',
	'kubio_change_customize_link_to_open_kubio_editor',
	20
);

function kubio_plugin_meta( $plugin_meta, $plugin_file ) {
	$plugins_dir = trailingslashit(
		wp_normalize_path( WP_CONTENT_DIR . '/plugins/' )
	);
	$kubio_file  = str_replace(
		$plugins_dir,
		'',
		wp_normalize_path( KUBIO_ENTRY_FILE )
	);
	if ( $plugin_file === $kubio_file ) {
		$plugin_meta[0] =
			"{$plugin_meta[0]} (build: " . KUBIO_BUILD_NUMBER . ')';
	}

	return $plugin_meta;
}

add_filter( 'plugin_row_meta', 'kubio_plugin_meta', 10, 4 );

add_filter(
	'kubio/importer/kubio-url-placeholder-replacement',
	function () {
		$stylesheet = get_stylesheet();

		return "https://static-assets.kubiobuilder.com/themes/{$stylesheet}/assets/";
	},
	5
);

add_action(
	'plugins_loaded',
	function () {
		// init the hasEnoughRemainingTime static variable
		Utils::hasEnoughRemainingTime();
	}
);

/**
 * This filter checks the attributes for every imported block and replaces the link values stored on the demo site like
 * `https://support-work.kubiobuilder.com` with the site url.
 *
 * @param $parsed_blocks
 * @param $demo_url
 * @return mixed
 */
function kubio_blocks_update_block_links( $parsed_blocks, $demo_url ) {
	$replace = site_url();

	Utils::walkBlocks(
		$parsed_blocks,
		function ( &$block ) use (
			$demo_url,
			$replace
		) {
			$old_url = Arr::get( $block, 'attrs.link.value' );

			if ( $old_url !== null && ! empty( $old_url ) ) {
				$next_url = $old_url;

				if ( strpos( $old_url, 'http://wpsites.' ) === 0 ) {
					// replace internal ( extendstudio links )
					$next_url = preg_replace(
						'#^http://wpsites\.(.*?)\.(.*?)/(.*?)/(.*?)/([a-zA-Z0-9-]+)#',
						$replace,
						$old_url
					);
				} else {
					$next_url = str_replace( $demo_url, $replace, $old_url );
				}

				if ( $old_url !== $next_url ) {
					Arr::set( $block, 'attrs.link.value', $next_url );
				}
			}
		}
	);

	return $parsed_blocks;
}

//This is added for woocomerce but it fixes a general issue. If the page that we preview is being redirected we need to
//add our flag to the redirected page or the editor will not work.
function kubio_add_flags_to_redirects( $location ) {
	$flags = array(
		'_wp-find-template',
		'__kubio-rendered-content',
		'__kubio-rendered-styles',
		'__kubio-site-edit-iframe-preview',
		'__kubio-site-edit-iframe-classic-template',
		'__kubio-body-class',
		'__kubio-page-title',
		'__kubio-page-query',
	);

	foreach ( $flags as $flag ) {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( isset( $_GET[ $flag ] ) && ! empty( $_GET[ $flag ] ) ) {
			// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.MissingUnslash, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized, WordPress.Security.NonceVerification.Recommended
			$location = add_query_arg( $flag, $_GET[ $flag ], $location );
		}
	}

	return $location;
}
add_filter( 'wp_redirect', 'kubio_add_flags_to_redirects' );

function kubio_is_black_wizard_onboarding_enabled() {
	return apply_filters( 'kubio/is_black_wizard_onboarding_enabled', false );
}

// deactivate new block editor
function kubio_remove_widget_block_editor() {
	remove_theme_support( 'widgets-block-editor' );
}
add_action( 'after_setup_theme', 'kubio_remove_widget_block_editor' );


//when blog as homepage disable the front page template in the function used to determine the page template
add_filter('pre_get_block_templates', function( $template, $query, $template_type) {
	$is_front_page = LodashBasic::get($query, 'slug__in.0') === 'front-page';
	if(!$is_front_page) {
		return $template;
	}

	$blog_as_homepage = get_option('show_on_front') === 'posts';
	if(!$blog_as_homepage) {
		return $template;
	}


	//only allow the option to use index as blog for new sites to not have the frontpage change for exsiting users
	if(	!Flags::getSetting( 'enableBlogAsFrontPageFromGeneralSettings' )){
		return $template;
	}

	$blog_query = [
		'slug__in' => [
			//can't have two templates as it will cause errors if the site has both home and index templates
		//	'home',
			'index',
		]
	];
	$result = get_block_templates($blog_query, 'wp_template');
	if(!empty($result)) {
		return $result;
	}

	return $template;
}, 9999, 3);


require_once __DIR__ . '/filters/kubio-fresh-site.php';
require_once __DIR__ . '/filters/dismissable-notice.php';
require_once __DIR__ . '/filters/svg-kses.php';
require_once __DIR__ . '/filters/post-insert.php';
require_once __DIR__ . '/filters/gutenerg-plugin-check.php';
require_once __DIR__ . '/filters/default-editor-overlay.php';
require_once __DIR__ . '/filters/requirements-notices.php';
require_once __DIR__ . '/filters/site-urls.php';
require_once __DIR__ . '/filters/after-kubio-activation.php';
require_once __DIR__ . '/filters/wp-import.php';
require_once __DIR__ . '/filters/starter-sites-feature.php';
require_once __DIR__ . '/filters/register-meta-fields.php';
require_once __DIR__ . '/filters/allow-kubio-blog-override.php';
require_once __DIR__ . '/filters/image-size-auto-fix.php';
