<?php

namespace Kubio\Core;

use IlluminateAgnostic\Arr\Support\Arr;
use Kubio\Flags;

class Activation {


	private static $instance = null;

	private $remote_content = array();


	public function __construct() {


		add_action(
			'activated_plugin',
			function ( $plugin ) {

				if ( $plugin === plugin_basename( KUBIO_ENTRY_FILE ) ) {

					$hash = uniqid( 'activate-' );
					Flags::set( 'activation-hash', $hash );

					$url = add_query_arg(
						array(
							'page'                  => 'kubio-get-started',
							'kubio-activation-hash' => $hash,
						),
						admin_url( 'admin.php' )
					);

					// phpcs:ignore WordPress.Security.NonceVerification.Recommended
					if ( ! $this->isCLI() && ! Arr::has( $_REQUEST, 'tgmpa-activate' ) && ! $this->isAJAX() ) {
						wp_redirect( $url );
						exit();
					} else {

						// phpcs:ignore WordPress.Security.NonceVerification.Recommended
						if ( Arr::has( $_REQUEST, 'tgmpa-activate' ) || $this->isAJAX() ) {
							Flags::set( 'activated_from_tgmpa_or_ajax', true );
						}

						Flags::set( 'import_design', false );
						Flags::set( 'start_with_ai', false );

						if ( $this->isCLI() ) {
							add_filter( 'user_has_cap', array( Importer::class, 'allowImportCaps' ), 10, 2 );
							$this->activate();
						}
					}
				}
			}
		);

		$self = $this;

		// handle direct tgmpa activation
		add_action(
			'init',
			function () {

				if ( ! is_admin() ) {
					return;
				}

				if ( Flags::get( 'activated_from_tgmpa_or_ajax' ) ) {
					Flags::delete( 'activated_from_tgmpa_or_ajax' );

					$hash = uniqid( 'activate-' );
					Flags::set( 'activation-hash', $hash );
					$url = add_query_arg(
						array(
							'page'                  => 'kubio-get-started',
							'kubio-activation-hash' => $hash,
						),
						admin_url( 'admin.php' )
					);

					wp_redirect( $url );
					exit();
				}
			},
			5
		);

		add_action(
			'init',
			function () use ( $self ) {

				if ( ! is_admin() ) {
					return;
				}

				// phpcs:ignore WordPress.Security.NonceVerification.Recommended
				$hash       = sanitize_text_field( Arr::get( $_REQUEST, 'kubio-activation-hash', null ) );
				$saved_hash = Flags::get( 'activation-hash', false );
				if ( $saved_hash === $hash ) {
					Flags::delete( 'activation-hash' );
					$self->activate();
				}
			},
			500
		);

		add_action( 'after_switch_theme', array( $this, 'afterSwitchTheme' ) );
	}

	public function isCLI() {
		return defined( 'WP_CLI' ) && WP_CLI;
	}

	public function isAJAX() {
		return defined( 'DOING_AJAX' ) && DOING_AJAX;
	}

	public function startWithAI() {
		return Flags::get( 'start_with_ai', false ) !== false;
	}

	public function activatedFromCustomizerOnboardingWizard() {
		return Flags::get( 'auto_start_black_wizard_onboarding', false );
	}

	public function startWithBlackWizardOnboarding() {
		//return false;
		$onboarding_is_supported = kubio_is_black_wizard_onboarding_enabled() && Flags::get( 'import_design_ai_structure', false );
		if(!$onboarding_is_supported) {
			return false;
		}

		$activated_from_notice = 	$this->activeWithFrontpage() &&  Flags::get( 'start_source', false ) == 'notice-homepage';
		$activated_from_theme_customizer =  $this->activatedFromCustomizerOnboardingWizard();
		return $activated_from_notice || $activated_from_theme_customizer;
	}

	public function activeWithFrontpage() {

		if ( $this->startWithAI() ) {
			return true;
		}
		$import_design = Flags::get( 'import_design', false );
		return apply_filters( 'kubio/activation/activate_with_frontpage',  $import_design !== false );
	}

	public function importUnmodifiedTemplates() {
		return ! CustomizerImporter::themeHasModifiedOptions();
	}

	public function importCustomizedTemplates() {
		return CustomizerImporter::themeHasModifiedOptions();
	}


	private function shouldRestoreDeactivationBackup( Backup $backup ) {
		$template   = get_stylesheet();
		$identifier = Flags::getSetting( "deactivation_backup_key.{$template}", null );
		return $identifier && $backup->hasBackup( $identifier );
	}

	private function restoreDeactivationBackup( Backup $backup ) {
		$template   = get_stylesheet();
		$identifier = Flags::getSetting( "deactivation_backup_key.{$template}", null );
		$status     = $backup->restoreBackup( $identifier );

		if ( ! is_wp_error( $status ) ) {
			$backup->deleteBackup( $identifier );
		}
		Flags::delete( $identifier );
	}


	public function activate() {
		$backup = new Backup();

		if ( $this->shouldRestoreDeactivationBackup( $backup ) ) {
			$this->restoreDeactivationBackup( $backup );
			return;
		}

		do_action( 'kubio/before_activation' );

		// if free previously activated return
		if ( Flags::get( 'kubio_activation_time', false ) ) {
			$stylesheet = Flags::get( 'stylesheet', null );
			if ( $stylesheet === get_stylesheet() ) {
				return;
			}
		}

		Flags::set( 'kubio_f', get_option( 'fresh_site' ) );
		Flags::set( 'kubio_activation_time', time() );
		Flags::set( 'stylesheet', get_stylesheet() );

		$this->addCommonFilters();
		$this->prepareRemoteData();

		//set site uuid on activation
		Flags::getSiteUUID();

		add_filter( 'kubio/importer/page_path', array( $this, 'getDesignPagePath' ), 10, 2 );

		if ( $this->importCustomizedTemplates() ) {
			add_filter( 'kubio/importer/content', array( $this, 'importCustomizerOptions' ), 20, 3 );
		}

		if ( $this->activeWithFrontpage() ) {
			add_filter( 'kubio/activation/force_front_page_creation', '__return_true' );
		}

		wp_cache_flush();


		//store current data to restore if user wants it
		KubioFrontPageRevertNotice::getInstance()->backupUserData();


		$this->importDesign();
		$this->importTemplates();
		$this->importTemplateParts();

		wp_cache_flush();
		do_action( 'kubio/after_activation' );
		//we wait for the template parts to import so we can backup them
		KubioFrontPageRevertNotice::getInstance()->backupTemplateParts();
		KubioFrontPageRevertNotice::getInstance()->backupGlobalData();
		if ( ! $this->isCLI() ) {

			// make an educated guess about the start source if not set
			if ( ! Flags::get( 'start_source', false ) ) {
				$start_source = 'other';
				if ( $this->startWithAI() ) {
					$start_source = 'notice-ai';
				} elseif ( $this->activeWithFrontpage() ) {
					$start_source = 'notice-homepage';
				}
				Flags::set( 'start_source', $start_source );
			}


			if ( $this->startWithAI() ) {
				Flags::set( 'start_with_ai', false );
				$ai_hash = md5( uniqid( 'start-with-ai' ) );
				Flags::set( 'start_with_ai_hash', $ai_hash );
				wp_redirect(
					Utils::kubioGetEditorURL(
						array(
							'ai' => $ai_hash,
						)
					)
				);
				exit();
			}
			if( $this->startWithBlackWizardOnboarding()) {
					$black_wizard_onboarding_hash = md5( uniqid( 'black-wizard-onboarding' ) );
					Flags::set( 'black_wizard_onboarding_hash', $black_wizard_onboarding_hash );
					$url = Utils::kubioGetEditorURL(
						array(
							'black-wizard-onboarding' => $black_wizard_onboarding_hash,
						)
					);
					wp_redirect( $url );
					exit();
			}

			if ( $this->activeWithFrontpage() ) {
				if ( Flags::get( 'start_source', false ) == 'notice-homepage' ) {

					$url = add_query_arg(
						array(
							'page'                    => 'kubio-get-started',
							'kubio-designed-imported' => intval( ! ! Flags::get( 'import_design', false ) ),
						),
						admin_url( 'admin.php' )
					);

					wp_redirect( $url );

				} else {
					wp_redirect(
						Utils::kubioGetEditorURL()
					);
				}
				exit();
			}

			$is_unmodified_supported_theme = kubio_theme_has_kubio_block_support() && ! CustomizerImporter::themeHasModifiedOptions();
			if ( get_option( 'fresh_site' ) || $is_unmodified_supported_theme ) {
				$url = add_query_arg(
					array(
						'page' => 'kubio-get-started',
						'tab'  => 'website-starter',
					),
					admin_url( 'admin.php' )
				);
				wp_redirect( $url );
				exit();
			}
		}
	}

	public function addCommonFilters() {
		add_filter( 'kubio/importer/skip-remote-file-import', '__return_true' );
		add_filter( 'kubio/importer/content', array( $this, 'getFileContent' ), 1, 3 );
		add_filter( 'kubio/importer/content', array( $this, 'templateMapPartsTheme' ), 10, 2 );
		add_filter( 'kubio/importer/content', array( $this, 'updateBlocks' ), 10, 3 );
		remove_filter( 'theme_mod_nav_menu_locations', 'kubio_nav_menu_locations_from_global_data' );
		remove_filter( 'wp_insert_post_data', 'kubio_on_post_update', 10, 3 );
		remove_action( 'wp_insert_post', 'kubio_update_meta', 10, 3 );

		add_filter( 'kubio/importer/available_templates', array( $this, 'getAvailableTemplates' ), 10 );
		add_filter( 'kubio/importer/available_template_parts', array( $this, 'getAvailableTemplateParts' ), 10 );
	}

	public function prepareRemoteData() {
		if ( ! \kubio_theme_has_kubio_block_support() ) {
			return;
		}

		$with_front_page = apply_filters( 'kubio/importer/with_front_page', $this->importUnmodifiedTemplates() );

		$base_url  = 'https://themes.kubiobuilder.com';
		$file_name = get_stylesheet() . '__' . get_template() . '__' . ( $with_front_page ? 'with-front' : 'default' ) . '.data';

		$url      = apply_filters( 'kubio/remote_data_url', "{$base_url}/{$file_name}" );
		$response = wp_safe_remote_get( $url );

		if ( ! is_wp_error( $response ) && wp_remote_retrieve_response_code( $response ) === 200 /* && Utils::isProduction()  */ ) {
			$content = wp_remote_retrieve_body( $response );
			$data    = unserialize( $content );

			if ( ! is_array( $data ) || Arr::get( $data, 'error' ) ) {
				return;
			}

			$ai_structure = isset( $data['ai-structure'] ) ? $data['ai-structure'] : null;
			if ( $ai_structure ) {
				Flags::set( 'import_design_ai_structure', $ai_structure );
			}
			$this->remote_content = $data;
		} else {
			$content              = file_get_contents( KUBIO_ROOT_DIR . '/defaults/default-site.dat' );
			$this->remote_content = unserialize( $content );
		}

		$global_data = Arr::get( $this->remote_content, 'global-data' );
		if ( $global_data ) {
			$global_data = json_decode( $global_data, true );

			if ( json_last_error() === JSON_ERROR_NONE ) {
				Arr::forget( $global_data, 'menuLocations' );
				kubio_replace_global_data_content( $global_data );
			}
		}

		$theme = Arr::get( $this->remote_content, 'theme' );

		// if the child theme does not exists use the theme name for assets
		if ( $theme && $theme !== get_stylesheet() ) {
			add_filter(
				'kubio/importer/kubio-url-placeholder-replacement',
				function () use ( $theme ) {

					return "https://static-assets.kubiobuilder.com/themes/{$theme}/assets/";
				},
				10
			);
		}
	}

	public function importDesign() {
		if ( $this->isCLI() ) {
			return;
		}


		$result = $this->setPages();

		// try to set the blog page and menu
		if ( ! is_wp_error( $result ) ) {
			static::preparePrimaryMenu();
		} else {
			// only set menu location
			static::preparePrimaryMenu( false );
		}

	}

	private function setPages( $data = array() ) {

		if ( ! kubio_theme_has_kubio_block_support() ) {
			return new \WP_Error( 'not_supported_themes' );
		}


		$data = array_merge(
			array(
				'front_content'  => null,
				'with_blog_page' => true,
			),
			$data
		);

		$front_page_id = $this->importFrontPage();

		if ( is_wp_error( $front_page_id ) ) {
			return $front_page_id;
		}

		update_option( 'show_on_front', 'page' );
		update_option( 'page_on_front', $front_page_id );

		$posts_page_id = intval( get_option( 'page_for_posts' ) );

		if ( ! $posts_page_id && $data['with_blog_page'] ) {
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
			}
		}

		return $posts_page_id;
	}

	/**
	 *
	 * @return int|WP_Error
	 */
	private function importFrontPage() {
		$page_on_front = get_option( 'page_on_front' );
		$query         = new \WP_Query(
			array(
				'post__in'    => array( $page_on_front ),
				'post_status' => array( 'publish' ),
				'fields'      => 'ids',
				'post_type'   => 'page',
			)
		);

		$content = '';

		if ( $this->activeWithFrontpage()) {
			$content = Importer::getTemplateContent( 'page', 'front-page' );
		}

		if ( $query->have_posts() && ! apply_filters( 'kubio/activation/force_front_page_creation', false ) ) {
			if ( apply_filters( 'kubio/activation/override_front_page_content', false ) ) {
				KubioFrontPageRevertNotice::getInstance()->backupUserUsedStarterContentFrontpage($page_on_front);
				wp_update_post(
					array(
						'ID'           => intval( $page_on_front ),
						'post_content' => wp_slash( kubio_serialize_blocks( parse_blocks( $content ) ) ),
					)
				);
				update_post_meta($page_on_front, '_wp_page_template', '');
			}

			return intval( $page_on_front );
		}

		if ( ! is_string( $content ) ) {
			$content = '';
		}

		return wp_insert_post(
			array(
				'comment_status' => 'closed',
				'ping_status'    => 'closed',
				'post_name'      => 'front_page',
				'post_title'     => __( 'Home', 'kubio' ),
				'post_status'    => 'publish',
				'post_type'      => 'page',
				'page_template'  => apply_filters(
					'kubio/front_page_template',
					'kubio-full-width'
				),
				'post_content'   => wp_slash( kubio_serialize_blocks( parse_blocks( $content ) ) ),
				'meta_input'     => array(
					'_kubio_created_at_activation' => 1,
				),
			)
		);
	}

	public static function preparePrimaryMenu( $create_menu_items = true ) {
		$theme_menu_locations    = array_keys( get_registered_nav_menus() );
		$common_header_locations = array(
			'header-menu',
			'header',
			'primary',
			'main',
			'menu-1',
		);

		$selected_location = null;
		/**
		 *  Try to make an educated guess and primary menu location
		 */
		foreach ( $theme_menu_locations as $location ) {
			foreach ( $common_header_locations as $common_header_location ) {
				if ( stripos( $location, $common_header_location ) !== false ) {
					$selected_location = $location;
					break;
				}
			}

			if ( $selected_location ) {
				break;
			}
		}

		$selected_location = apply_filters( 'kubio/primary_menu_location', $selected_location );

		if ( $selected_location ) {

			$current_set_locations = get_nav_menu_locations();

			$primary_menu_id = Arr::get( $current_set_locations, $selected_location, null );

			if ( $create_menu_items ) {

				if ( ! $primary_menu_id ) {
					$primary_menu_id = wp_create_nav_menu( __( 'Primary menu', 'kubio' ) );
				}

				if ( is_wp_error( $primary_menu_id ) ) {
					return;
				}

				$menu_items     = wp_get_nav_menu_items( $primary_menu_id );
				$has_front_page = false;
				$has_blog_page  = false;

				foreach ( $menu_items as $menu_item ) {

					if ( ! $has_front_page ) {
						$menu_item_object_is_front_page = $menu_item->type === 'post_type' && $menu_item->object === 'page' && intval( $menu_item->object_id ) === intval( get_option( 'page_on_front' ) );
						$custom_url                     = $menu_item->type === 'custom' ? $menu_item->url : '';
						$menu_item_link_is_front_page   = false;
						$parsed_url                     = wp_parse_url( $custom_url );

						if ( $parsed_url && $custom_url ) {
							$site_url = site_url();

							$parsed_url = array_merge(
								array(
									'scheme' => '',
									'host'   => '',
									'path'   => '',
								),
								$parsed_url
							);

							$menu_item_url                = "{$parsed_url['scheme']}://{$parsed_url['host']}{$parsed_url['path']}";
							$menu_item_link_is_front_page = untrailingslashit( $menu_item_url ) === untrailingslashit( $site_url );
						}

						if ( $menu_item_object_is_front_page || $menu_item_link_is_front_page ) {
							$has_front_page = true;
						}
					}

					if ( $menu_item->type === 'post_type' && $menu_item->object === 'page' && intval( $menu_item->object_id ) === intval( get_option( 'page_for_posts' ) ) ) {
						$has_blog_page = true;
					}
				}

				if ( ! $has_front_page ) {
					wp_update_nav_menu_item(
						$primary_menu_id,
						0,
						array(
							'menu-item-title'     => __( 'Home', 'kubio' ),
							'menu-item-object'    => 'page',
							'menu-item-object-id' => get_option( 'page_on_front' ),
							'menu-item-type'      => 'post_type',
							'menu-item-status'    => 'publish',
						)
					);
				}

				if ( ! $has_blog_page && get_option( 'page_for_posts', 0 ) ) {
					wp_update_nav_menu_item(
						$primary_menu_id,
						0,
						array(
							'menu-item-title'     => __( 'Blog', 'kubio' ),
							'menu-item-object'    => 'page',
							'menu-item-object-id' => get_option( 'page_for_posts' ),
							'menu-item-type'      => 'post_type',
							'menu-item-status'    => 'publish',
						)
					);
				}
			}

			if ( ! $primary_menu_id ) {
				return;
			}

			$next_nav_menu_locations = array_merge(
				$current_set_locations,
				array(
					$selected_location => $primary_menu_id,
				)
			);

			if ( ! isset( $next_nav_menu_locations['header-menu'] ) ) {
				$next_nav_menu_locations['header-menu'] = $primary_menu_id;
			}

			set_theme_mod( 'nav_menu_locations', $next_nav_menu_locations );
		}
	}

	public function importTemplates() {
		$entities = array_keys( Importer::getAvailableTemplates() );

		foreach ( $entities as $slug ) {
			$is_current_kubio_template = apply_filters( 'kubio/template/is_importing_kubio_template', kubio_theme_has_kubio_block_support(), $slug );
			Importer::createTemplate( $slug, Importer::getTemplateContent( 'wp_template', $slug ), false, $is_current_kubio_template ? 'kubio' : 'theme' );
		}

		Flags::set( 'kubio_templates_imported', time() );
	}

	public function importTemplateParts() {
		$entities = array_keys( Importer::getAvailableTemplateParts() );

		foreach ( $entities as $slug ) {
			$is_current_kubio_template = apply_filters( 'kubio/template/is_importing_kubio_template', kubio_theme_has_kubio_block_support(), $slug );
			Importer::createTemplatePart( $slug, Importer::getTemplateContent( 'wp_template_part', $slug ), false, $is_current_kubio_template ? 'kubio' : 'theme' );
		}

		Flags::set( 'kubio_template_parts_imported', time() );
	}

	public static function load() {
		if ( ! self::$instance ) {
			self::$instance = new self();
		}

		return self::$instance;
	}

	public static function skipAfterSwitchTheme() {
		set_transient( 'kubio_skip_after_theme_switch', true );
	}

	public function afterSwitchTheme() {
		$skip = get_transient( 'kubio_skip_after_theme_switch' );

		if ( $skip ) {
			delete_transient( 'kubio_skip_after_theme_switch' );
			return;
		}

		$this->addCommonFilters();

		add_filter( 'kubio/importer/page_path', array( $this, 'getDesignPagePath' ), 10, 2 );
		$this->prepareRemoteData( true );

		$this->importDesign();

		$this->importTemplates();
		$this->importTemplateParts();

		do_action( 'kubio/after_switch_theme' );
	}

	public function getAvailableTemplates( $current_templates = array() ) {

		$templates = $current_templates;

		if ( kubio_theme_has_kubio_block_support() ) {
			$templates = Arr::get( $this->remote_content, 'block-templates', array() );

			foreach ( array_keys( $templates ) as $template ) {
				$templates[ $template ] = null;
			}

			$templates = array_replace( $templates, $templates );
		}

		return $templates;
	}

	public function getAvailableTemplateParts( $current_parts = array() ) {

		$templates = $current_parts;

		if ( kubio_theme_has_kubio_block_support() ) {
			$templates = Arr::get( $this->remote_content, 'block-template-parts', array() );

			foreach ( array_keys( $templates ) as $template ) {
				$templates[ $template ] = null;
			}

			$templates = array_replace( $templates, $templates );
		}

		return $templates;
	}

	public function getDesignPagePath( $path, $slug ) {
		if ( $slug === 'front-page' ) {
			return null;
		}

		return $path;
	}

	public function updateBlocks( $content, $type, $slug ) {
		$blocks = parse_blocks( $content );
		$blocks = Importer::maybeImportBlockAssets( $blocks );

		if ( $type === 'wp_template_part' && strpos( $slug, 'footer' ) !== false ) {
			$blocks = Importer::setBlocksLocks( $blocks, null );
		}

		return kubio_serialize_blocks( $blocks );
	}



	public function getFileContent( $content, $type, $slug ) {

		if ( $content !== null ) {
			return $content;
		}

		$category = '';
		switch ( $type ) {
			case 'wp_template':
				$category = 'block-templates';
				break;
			case 'wp_template_part':
				$category = 'block-template-parts';
				break;
			case 'page':
				$category = 'pages';
				break;
		}

		return Arr::get( $this->remote_content, "{$category}.{$slug}", '' );
	}

	public function templateMapPartsTheme( $content, $type ) {

		if ( $type === 'wp_template' || $type === 'wp_template_part' ) {
			$blocks         = parse_blocks( $content );
			$updated_blocks = kubio_blocks_update_template_parts_theme( $blocks, get_stylesheet() );

			return kubio_serialize_blocks( $updated_blocks );
		}

		return $content;
	}

	public function importCustomizerOptions( $content, $type, $slug ) {

		if ( ! kubio_theme_has_kubio_block_support() ) {
			return $content;
		}

		$customizer_importer = new CustomizerImporter( $content, $type, $slug );

		return $customizer_importer->process();
	}
}
