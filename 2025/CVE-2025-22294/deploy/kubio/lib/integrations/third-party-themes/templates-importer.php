<?php

use Kubio\Core\Activation;
use Kubio\Core\Importer;
use Kubio\Core\Utils;
use Kubio\Flags;

class KubioThirdPartyThemeBlockImporter {

	public static function mapBlocksTemplateParts( $content ) {

		$blocks         = parse_blocks( $content );
		$updated_blocks = kubio_blocks_update_template_parts_theme(
			$blocks,
			get_stylesheet()
		);

		return kubio_serialize_blocks( $updated_blocks );

		return $content;
	}

	private static function importTemplates( $mapped_templates, $is_fresh_site = false ) {
		$files     = glob(
			KUBIO_3RD_PARTY_DEFAULT_TEMPLATES_PATH .
				'/default-blog/templates/*.html'
		);
		$templates = array();

		foreach ( $files as $template ) {
			$slug               = preg_replace(
				'#(.*)/templates/(.*).html#',
				'$2',
				wp_normalize_path( $template )
			);
			$templates[ $slug ] = $template;
		}

		if ( $is_fresh_site ) {
			$files = glob(
				KUBIO_3RD_PARTY_DEFAULT_TEMPLATES_PATH .
					'/fresh-site/templates/*.html'
			);

			foreach ( $files as $template ) {
				$slug                      = preg_replace(
					'#(.*)/fresh-site/templates/(.*).html#',
					'$2',
					wp_normalize_path( $template )
				);
				$templates[ $slug ]        = $template;
				$mapped_templates[ $slug ] = $slug;
			}
		}

		foreach ( $mapped_templates as $slug => $template_key ) {
			$content = file_get_contents( $templates[ $template_key ] );
			$result  = Importer::createTemplate(
				$slug,
				static::mapBlocksTemplateParts( $content ),
				true,
				'kubio'
			);

			if ( is_wp_error( $result ) ) {
				break;
				return $result;
			}
		}

		return true;
	}

	private static function importTemplateParts( $is_fresh_site = false ) {
		$files     = glob(
			KUBIO_3RD_PARTY_DEFAULT_TEMPLATES_PATH .
				'/default-blog/parts/*.html'
		);
		$templates = array();

		foreach ( $files as $template ) {
			$slug               = preg_replace(
				'#(.*)/parts/(.*).html#',
				'$2',
				wp_normalize_path( $template )
			);
			$templates[ $slug ] = $template;
		}

		if ( $is_fresh_site ) {
			$files = glob(
				KUBIO_3RD_PARTY_DEFAULT_TEMPLATES_PATH .
					'/fresh-site/parts/*.html'
			);

			foreach ( $files as $template ) {
				$slug               = preg_replace(
					'#(.*)/fresh-site/parts/(.*).html#',
					'$2',
					wp_normalize_path( $template )
				);
				$templates[ $slug ] = $template;
			}
		}

		foreach ( $templates as $slug => $file ) {
			$content = file_get_contents( $file );
			$result  = Importer::createTemplatePart(
				$slug,
				static::mapBlocksTemplateParts( $content ),
				false,
				'kubio'
			);

			if ( is_wp_error( $result ) ) {
				break;
				return $result;
			}
		}

		return true;
	}

	private static function importContent( $templates, $is_fresh_site = false ) {
		$mapped_templates = static::mapTemplatesToImportSlug( $templates );

		$result = static::importTemplates( $mapped_templates, $is_fresh_site );

		if ( is_wp_error( $result ) ) {
			return $result;
		}

		$result = static::importTemplateParts( $is_fresh_site );

		if ( is_wp_error( $result ) ) {
			return $result;
		}

		return true;
	}

	private static function importFSETheme( $is_fresh_site = false ) {
		$block_templates            = get_block_templates( array(), 'wp_template' );
		$block_templates_to_replace = array();
		$blog_templates_slugs       = array(
			'home',
			'index',
			'single',
			'search',
			'archive',
			'singular',
		);

		foreach ( $block_templates as $template ) {
			if ( in_array( $template->slug, $blog_templates_slugs, true ) ) {
				$block_templates_to_replace[] = $template->slug;
			}
		}

		return static::importContent( $block_templates_to_replace, $is_fresh_site );
	}

	private static function importClassicTheme( $is_fresh_site = false ) {
		$theme     = wp_get_theme();
		$files     = (array) $theme->get_files( 'php', 0, true );
		$templates = array_keys( $files );

		$block_templates_to_install   = array(
			'index',
			'single',
			'search',
			'archive',
		);
		$other_blog_related_templates = array(
			'home',
			'singular',
		);

		foreach ( $templates as $template ) {
			$template_slug = preg_replace(
				'#(.*).php#',
				'$1',
				wp_normalize_path( $template )
			);

			if ( in_array( $template_slug, $other_blog_related_templates ) ) {
				$block_templates_to_install[] = $template_slug;
			}
		}

		return static::importContent( $block_templates_to_install, $is_fresh_site );
	}

	public static function mapTemplatesToImportSlug( $templates ) {
		$result                    = array();
		$index_fallback_templates  = array( 'home', 'index', 'archive' );
		$single_fallback_templates = array( 'singular' );

		foreach ( $templates as $template ) {
			$result[ $template ] = $template;
			if ( in_array( $template, $index_fallback_templates, true ) ) {
				$result[ $template ] = 'index';
			}

			if ( in_array( $template, $single_fallback_templates, true ) ) {
				$result[ $template ] = 'single';
			}
		}

		return $result;
	}

	private static function is_fse() {
		$is_fse = is_readable( get_template_directory() . '/templates/index.html' ) ||
		is_readable( get_stylesheet_directory() . '/templates/index.html' );

		return $is_fse;
	}

	public static function import() {

		$result = null;

		if ( static::is_fse() ) {
			$result = static::importFSETheme();
		} else {
			$result = static::importClassicTheme();
		}

		if ( is_wp_error( $result ) ) {
			return $result;
		}

		return array( 'success' => true );
	}

	public static function importFreshSite( \WP_REST_Request $req ) {

		$response             = array(
			'success'  => true,
			'redirect' => Utils::kubioGetEditorURL(),
		);
		$start_with_frontpage = Utils::isTrue( $req->get_param( 'start_with_frontpage' ) );

		// for a kubio supported theme, treat it as a normal import
		if ( kubio_theme_has_kubio_block_support() ) {
			add_filter( 'kubio/activation/activate_with_frontpage', $start_with_frontpage ? '__return_true' : '__return_false' );
			add_filter( 'kubio/activation/override_front_page_content', $start_with_frontpage ? '__return_true' : '__return_false' );

			$activation = new Activation();
			$activation->addCommonFilters();
			$activation->prepareRemoteData();

			$activation->importDesign();
			$activation->importTemplates();
			$activation->importTemplateParts();

			add_filter( 'kubio/importer/page_path', array( $activation, 'getDesignPagePath' ), 10, 2 );

		} else {
			$fp_content = '';

			if ( static::is_fse() ) {
				$result = static::importFSETheme( true );
			} else {
				$result = static::importClassicTheme( true );
			}

			if ( is_wp_error( $result ) ) {
				return $result;
			}

			if ( $start_with_frontpage ) {
				$fp_content = file_get_contents( KUBIO_ROOT_DIR . '/lib/integrations/third-party-themes/front-page.html' );
			}

			$posts_page_id = intval( get_option( 'page_for_posts' ) );

			if ( ! $posts_page_id ) {
				$posts_page_id = wp_insert_post(
					array(
						'comment_status' => 'closed',
						'ping_status'    => 'closed',
						'post_name'      => 'blog',
						'post_title'     => __( 'Blog', 'kubio' ),
						'post_status'    => 'publish',
						'post_type'      => 'page',
						'page_template'  => apply_filters(
							'kubio/front_page_template',
							'page-templates/homepage.php'
						),
						'post_content'   => '',
						'meta_input'     => array(
							'_kubio_created_at_activation' => 1,
						),
					)
				);

				if ( ! is_wp_error( $posts_page_id ) ) {
					update_option( 'page_for_posts', $posts_page_id );
				} else {
					return $posts_page_id;
				}
			}

			$page_on_front = get_option( 'page_on_front' );

			$query = new \WP_Query(
				array(
					'post__in'    => array( $page_on_front ),
					'post_status' => array( 'publish' ),
					'fields'      => 'ids',
					'post_type'   => 'page',
				)
			);

			if ( ! $query->have_posts() ) {
				$page_on_front = wp_insert_post(
					array(
						'comment_status' => 'closed',
						'ping_status'    => 'closed',
						'post_name'      => 'front_page',
						'post_title'     => __( 'Home', 'kubio' ),
						'post_status'    => 'publish',
						'post_type'      => 'page',
						'page_template'  => 'kubio-full-width',
						'post_content'   => wp_slash( kubio_serialize_blocks( parse_blocks( $fp_content ) ) ),
						'meta_input'     => array(
							'_kubio_created_at_activation' => 1,
						),
					)
				);

				if ( ! is_wp_error( $page_on_front ) ) {
					update_option( 'page_on_front', $page_on_front );
				} else {
					return $page_on_front;
				}
			}

			update_option( 'show_on_front', 'page' );

			Activation::preparePrimaryMenu();

		}

		if ( ! is_wp_error( $response ) ) {
			Flags::set( 'kubio_installed_via_fresh_site', true );
			Flags::set( 'start_source', 'fresh-site' );
		}

		return $response;
	}

	public static function registerRestRoute() {
		$namespace = 'kubio/v1';
		register_rest_route(
			$namespace,
			'/3rd_party_themes/import_blog',
			array(
				'methods'             => 'GET',
				'callback'            => array( KubioThirdPartyThemeBlockImporter::class, 'import' ),
				'permission_callback' => function () {
					return current_user_can( 'edit_theme_options' );
				},
			)
		);

		register_rest_route(
			$namespace,
			'/3rd_party_themes/import_fresh_site',
			array(
				'methods'             => 'GET',
				'callback'            => array( KubioThirdPartyThemeBlockImporter::class, 'importFreshSite' ),
				'permission_callback' => function () {
					return current_user_can( 'edit_theme_options' );
				},
			)
		);
	}
}

add_action(
	'rest_api_init',
	array(
		KubioThirdPartyThemeBlockImporter::class,
		'registerRestRoute',
	)
);



function kubio_new_template_get_appropriate_content( $data ) {
	if ( $data['post_type'] !== 'wp_template' ) {
		return $data;
	}

	if ( $data['post_status'] !== 'publish' ) {
		return $data;
	}

	if ( $data['post_content'] === '__KUBIO_REPLACE_WITH_APPROPRIATE_CONTENT__' ) {
		$template         = $data['post_name'];
		$mapped_templates = KubioThirdPartyThemeBlockImporter::mapTemplatesToImportSlug( array( $template ) );
		$template         = $mapped_templates[ $template ];

		$data['post_content'] = '';

		$file = null;

		if ( file_exists( KUBIO_3RD_PARTY_DEFAULT_TEMPLATES_PATH . "/default-blog/templates/{$template}.html" ) ) {
			$file = KUBIO_3RD_PARTY_DEFAULT_TEMPLATES_PATH . "/default-blog/templates/{$template}.html";
		}

		if ( file_exists( KUBIO_3RD_PARTY_DEFAULT_TEMPLATES_PATH . "/primary/templates/{$template}.html" ) ) {
			$file = KUBIO_3RD_PARTY_DEFAULT_TEMPLATES_PATH . "/primary/templates/{$template}.html";
		}

		if ( $file ) {
			$data['post_content'] = KubioThirdPartyThemeBlockImporter::mapBlocksTemplateParts( file_get_contents( $file ) );
		}

		// import parts if needed

		// header
		if ( $template === 'front-page' ) {
			$file   = KUBIO_3RD_PARTY_DEFAULT_TEMPLATES_PATH . '/primary/parts/kubio-front-header.html';
			$header = file_get_contents( $file );
			Importer::createTemplatePart(
				'kubio-front-header',
				KubioThirdPartyThemeBlockImporter::mapBlocksTemplateParts( $header ),
				false,
				'kubio'
			);
		} else {
			$header = file_get_contents( KUBIO_3RD_PARTY_DEFAULT_TEMPLATES_PATH . '/parts/kubio-header.html' );
			Importer::createTemplatePart(
				'kubio-header',
				KubioThirdPartyThemeBlockImporter::mapBlocksTemplateParts( $header ),
				false,
				'kubio'
			);

		}

		// header
		$footer = file_get_contents( KUBIO_3RD_PARTY_DEFAULT_TEMPLATES_PATH . '/parts/kubio-footer.html' );
			Importer::createTemplatePart(
				'kubio-header',
				KubioThirdPartyThemeBlockImporter::mapBlocksTemplateParts( $footer ),
				false,
				'kubio'
			);

		// sidebar
		if ( in_array( $template, array( 'index', 'single', 'search' ), true ) ) {
			$sidebar = file_get_contents( KUBIO_3RD_PARTY_DEFAULT_TEMPLATES_PATH . '/default-blog/parts/kubio-blog-sidebar.html' );
			Importer::createTemplatePart(
				'kubio-blog-sidebar',
				KubioThirdPartyThemeBlockImporter::mapBlocksTemplateParts( $sidebar ),
				false,
				'kubio'
			);
		}
	}

	return $data;
}

add_filter(
	'wp_insert_post_data',
	'kubio_new_template_get_appropriate_content',
	10,
	1
);


function kubio_add_installed_via_fresh_site_to_utils_data( $data ) {
	$data['installedViaFreshSite'] = Flags::get( 'kubio_installed_via_fresh_site', false );
	return $data;
}

add_filter( 'kubio/kubio-utils-data/extras', 'kubio_add_installed_via_fresh_site_to_utils_data' );
