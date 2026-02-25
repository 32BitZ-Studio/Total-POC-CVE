<?php

use Kubio\Core\Utils;


function kubio_edit_post_row_style() {
	?>
	<style>

		span.kubio_edit_post * {
			fill: currentColor;
		}
		span.kubio-edit svg {
			width: 12px;
			height: 12px;
			margin-right: 2px;
			fill: currentColor;
		}

		span.kubio-edit {
			display: inline !important;
			vertical-align: middle;
		}
	</style>
	<?php
}
function kubio_add_edit_post_row_actions( $actions, $post ) {

	if ( ! current_user_can( 'edit_theme_options' ) ) {
		return $actions;
	}

	$supported_post_type = array( 'page', 'wp_template', 'wp_template_part' );
	if ( ! in_array( $post->post_type, $supported_post_type ) ) {
		return $actions;
	}

	$post_id               = $post->ID;
	$is_translate_redirect = false;
	//when you try to edit the translated page redirect to the original language
	if ( kubio_wpml_is_active() ) {
		$translated_id = kubio_wpml_get_original_language_post_id( $post_id, $post->post_type );
		if ( $translated_id !== $post_id ) {
			$is_translate_redirect = true;
			$post_id               = $translated_id;
			if ( in_array( $post->post_type, array( 'wp_template', 'wp_template_part' ) ) ) {
				$post = get_post( $translated_id );
			}
		}
	}
	if ( in_array( $post->post_type, array( 'wp_template', 'wp_template_part' ) ) ) {
		$template = _kubio_build_template_result_from_post( $post );

		if ( is_wp_error( $template ) ) {
			return $actions;
		}

		$post_id = $template->id;
	}

	$args = array(
		'page'     => 'kubio',
		'postId'   => $post_id,
		'postType' => $post->post_type,
	);
	if ( $is_translate_redirect ) {
		$args['isTranslateRedirect'] = 1;
	}
	$edit_url = add_query_arg(
		$args,
		admin_url( 'admin.php' )
	);

	$status     = get_post_status( $post_id );
	$is_trashed = strpos( $post_id, '__trashed' );

	if ( $status === 'draft' || $status === 'auto-draft' ) {
		$edit_url = add_query_arg(
			array(
				'action'              => 'edit',
				'post'                => $post_id,
				'kubio-publish-draft' => 1,
			),
			admin_url( 'post.php' )
		);
	}

	if ( $status !== 'trash' && $is_trashed === false ) {
		$link = sprintf(
			'<a href="%s"><span style="display:none" class="kubio-edit">%s</span>%s</a>',
			esc_url( $edit_url ),
			wp_kses_post( KUBIO_LOGO_SVG ),
			esc_html__( 'Edit with Kubio', 'kubio' )
		);

		$actions = array_merge(
			array(
				'kubio_edit_post' => $link,
			),
			$actions
		);

		if ( ! has_action( 'admin_footer', 'kubio_edit_post_row_style' ) ) {
			add_action( 'admin_footer', 'kubio_edit_post_row_style' );
		}
	}

	return $actions;
}

function kubio_post_edit_add_button() {

	global $post;

	if ( ! $post ) {
		return;
	}

	if ( ! current_user_can( 'edit_theme_options' ) ) {
		return;
	}

	if ( ! in_array( $post->post_type, array( 'wp_template', 'wp_template_part', 'page' ) ) ) {
		return;
	}

	if ( kubio_is_kubio_editor_page() ) {
		return;
	}

	$post_id               = $post->ID;
	$is_translate_redirect = false;
	$translated_id         = kubio_wpml_get_original_language_post_id( $post_id, $post->post_type );
	if ( $translated_id !== $post_id ) {
		$is_translate_redirect = true;
		$post_id               = $translated_id;
		if ( in_array( $post->post_type, array( 'wp_template', 'wp_template_part' ), true ) ) {
			$post = get_post( $translated_id );
		}
	}
	if ( in_array( $post->post_type, array( 'wp_template', 'wp_template_part' ), true ) ) {
		$template = _kubio_build_template_result_from_post( $post );

		if ( is_wp_error( $template ) ) {
			esc_html_e( 'Unknown', 'kubio' );
		}

		$post_id = $template->id;
	}
	$args = array(
		'page'     => 'kubio',
		'postId'   => $post_id,
		'postType' => $post->post_type,
	);
	if ( $is_translate_redirect ) {
		$args['isTranslateRedirect'] = 1;
	}
	$edit_url = add_query_arg(
		$args,
		admin_url( 'admin.php' )
	);

	add_action(
		'admin_head',
		function () {
			?>
			<style>
				a.components-button.edit-in-kubio.is-primary svg {
					width: 1em;
					height: 1em;
					margin-right: 0.5em;
					fill: currentColor;
				}
			</style>
			<?php

			if ( Utils::wpVersionCompare( '6.3', '>=' ) ) {
				?>
			<style>
					a.components-button.edit-in-kubio.is-primary {

						margin-right: 30px;
					}
				</style>
				<?php
			}
		}
	);

	ob_start();
	?>

	<script>
		(function () {
			const url = <?php echo wp_json_encode( $edit_url ); ?>;
			const icon = <?php echo wp_json_encode( base64_encode( KUBIO_LOGO_SVG ) ); ?>;
			const label = <?php echo wp_json_encode( '<span>' . esc_html__( 'Edit with Kubio', 'kubio' ) . '</span>' ); ?>;
			let unsubscribe = null;

			const createButton = () => {


				if (unsubscribe) {
						unsubscribe();
						unsubscribe = null;
				}

				setInterval(() => {
					const toolbar = document.querySelector('.edit-post-header-toolbar');
					if (toolbar) {
						if (
							!toolbar.querySelector('.components-button.edit-in-kubio')
						) {
							const link = document.createElement('a');
							link.href = url;
							link.innerHTML = atob(icon) + label;
							link.setAttribute(
								'class',
								'components-button edit-in-kubio is-primary'
							);
							toolbar.appendChild(link);
							link.addEventListener('click', function (event) {
								const editorSelect = wp.data.select('core/editor');
								if (editorSelect) {
									if (
										'draft' ===
											editorSelect.getEditedPostAttribute(
												'status'
											) ||
										'auto-draft' ===
											editorSelect.getEditedPostAttribute(
												'status'
											)
									) {
										event.preventDefault();
										event.stopPropagation();
										wp.hooks.doAction(
											'kubio.post-edit.open-draft-page',
											{ target: event.currentTarget, url }
										);
									}
								}
							});
							wp.hooks.doAction('kubio.post-edit.button-created', {
								target: link,
								url,
							});
						}
					}
				}, 2000);
			};

			unsubscribe = wp.data.subscribe(createButton);
		})();
	</script>
	<?php

	$script = str_replace( "\n\t\t", "\n", ob_get_clean() );

	// phpcs:ignore WordPress.WP.AlternativeFunctions.strip_tags_strip_tags
	wp_add_inline_script( 'wp-block-editor', strip_tags( $script ), 'after' );
}


add_filter( 'page_row_actions', 'kubio_add_edit_post_row_actions', 0, 2 );
add_filter( 'post_row_actions', 'kubio_add_edit_post_row_actions', 0, 2 );


add_action( 'enqueue_block_editor_assets', 'kubio_post_edit_add_button', 0, 2 );

function kubio_frontend_get_editor_url() {
	global $post;
	if ( gettype( $post ) === 'integer' ) {
		$post = get_post( $post );
	}

	// Add site-editor link.
	$url = null;
	if ( ! is_admin() && current_user_can( 'edit_theme_options' ) ) {

		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotValidated, WordPress.Security.ValidatedSanitizedInput.MissingUnslash, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
		$current_url = ( is_ssl() ? 'https://' : 'http://' ) . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];

		$args = array();
		if ( is_singular() || is_single() ) {
			$post_id               = $post->ID;
			$is_translate_redirect = false;
			//when you try to edit the translated page redirect to the original language
			$translated_post_id = kubio_wpml_get_original_language_post_id( $post_id, $post->post_type );
			if ( $translated_post_id !== $post_id ) {
				$post_id               = $translated_post_id;
				$is_translate_redirect = true;
			}
			$args = array(
				'postId'   => $post_id,
				'postType' => $post->post_type,
			);
			if ( $is_translate_redirect ) {
				$args['isTranslateRedirect'] = 1;
			}
		} else {

			$block_template = null;

			if ( is_front_page() && is_home() ) {
				$stylesheet = get_stylesheet();
				$query      = new WP_Query(
					array(
						'post_type'      => 'wp_template',
						'post_status'    => array( 'publish' ),
						'post_name__in'  => array( 'index', 'home' ),
						'posts_per_page' => 1,
						'no_found_rows'  => true,
						// phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_tax_query
						'tax_query'      => array(
							array(
								'taxonomy' => 'wp_theme',
								'field'    => 'name',
								'terms'    => array( $stylesheet ),
							),
						),
					)
				);

				$block_template = $query->have_posts() ? _kubio_build_template_result_from_post( $query->next_post() ) : null;
			}

			//for 404 if you try to use the current_url it crashes the editor so we have a special case for it
			if ( is_404() ) {
				$block_template = resolve_block_template( '404', array( '404.php' ), null );
			}

			if ( $block_template ) {
				$args = array(
					'postId'   => urlencode( $block_template->id ),
					'postType' => 'wp_template',
				);
			} else {
				$args['pageURL'] = $current_url;

			}
		}

		$args = apply_filters( 'kubio/frontend/edit-in-kubio-args', $args );

		$url = Utils::kubioGetEditorURL( $args );
	}

	return $url;
}

function kubio_frontend_adminbar_items( $wp_admin_bar ) {

	if ( ! current_user_can( 'edit_theme_options' ) ) {
		return;
	}

	$url = kubio_frontend_get_editor_url();

	if ( $url ) {
		$wp_admin_bar->add_menu(
			array(
				'id'    => 'kubio-site-editor',
				'title' => sprintf( '<span class="kubio-admin-bar-menu-item">%s<span>%s</span></span>', wp_kses_post( KUBIO_LOGO_SVG ), __( 'Edit with Kubio', 'kubio' ) ),
				'href'  => $url,
			)
		);
	}
}

add_action( 'admin_bar_menu', 'kubio_frontend_adminbar_items', 80 );


function kubio_frontend_adminbar_items_style() {
	?>
		<style>
		.kubio-admin-bar-menu-item {
			display: flex;
			align-items:center;
		}

		.kubio-admin-bar-menu-item span {
			display: block;
			white-space: nowrap;
		}
		.kubio-admin-bar-menu-item svg {
			max-height: 14px;
			fill: #09f;
			flex-grow: 0;
			min-width: 20px;
			margin-right: 0.4em !important;
		}

		a:focus .kubio-admin-tbar-menu-item,
		a:hover .kubio-admin-tbar-menu-item {
			background: rgba(0, 153 ,255 , 0.6);
			color: #fff;

		}

		</style>
	<?php
}

add_action( 'wp_after_admin_bar_render', 'kubio_frontend_adminbar_items_style' );

