<?php

use Kubio\Core\Utils;

function kubio_set_admin_bar_menu_customize_to_kubio_editor( WP_Admin_Bar &$admin_bar ) {

	if ( ! is_user_logged_in() || ! kubio_theme_has_kubio_block_support() ) {
		return;
	}

	$url             = kubio_frontend_get_editor_url();
	$appearance_node = $admin_bar->get_node( 'customize' );
	if ( ! $appearance_node ) {
		return;
	}
	$appearance_node->href = $url;
	$admin_bar->add_node( $appearance_node );
}

function kubio_set_admin_bar_customize_to_kubio_editor() {
	if ( ! kubio_theme_has_kubio_block_support() ) {
		return;
	}
	global $submenu;
	if ( ! isset( $submenu['themes.php'] ) ) {
		return;
	}

	foreach ( $submenu['themes.php'] as $key => $theme_submenu ) {
		$slug = $theme_submenu[1];
		if ( $slug !== 'customize' ) {
			continue;
		}
		$submenu['themes.php'][ $key ][2] = 'admin.php?page=kubio';
	}
}

function kubio_update_theme_page_customize_url( $prepared_themes ) {
	if ( ! kubio_theme_has_kubio_block_support() ) {
		return $prepared_themes;
	}
	foreach ( $prepared_themes as $key => $theme ) {
		if ( $theme['active'] === true ) {
			$prepared_themes[ $key ]['actions']['customize'] = Utils::kubioGetEditorURL();
		}
	}

	return $prepared_themes;
}

function kubio_update_dashboard_customizer_url() {

	// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotValidated, WordPress.Security.ValidatedSanitizedInput.MissingUnslash, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
	$request_uri                 = isset( $_SERVER['REQUEST_URI'] ) ? $_SERVER['REQUEST_URI'] : '';
	$is_dashboard_admin_or_theme = str_contains( $request_uri, 'wp-admin/index.php' ) || str_contains( $request_uri, 'wp-admin/themes.php' );

	//Dashboard page or theme page
	if ( ! $is_dashboard_admin_or_theme ) {
		return;
	}

	$kubio_url = Utils::kubioGetEditorURL();
	ob_start();
	?>
	<script>
		(function($) {
			$(document).ready(function(){

				<?php if ( kubio_theme_has_kubio_block_support() ) : ?>
					var customizeLink = document.querySelector('a.load-customize');
					if(customizeLink) {
						customizeLink.setAttribute('href', <?php echo wp_json_encode( $kubio_url ); ?>);
					}
				<?php endif; ?>

			
				//in the active theme page replace the edit with kubio link
				var themeSingleTemplate = document.querySelector('#tmpl-theme-single')
				if(themeSingleTemplate) {
					let innerHtml = themeSingleTemplate.innerHTML;
					let newInnerHtml = innerHtml.replace(/href='([^']*page=kubio)'/, "href='" +  <?php echo wp_json_encode( $kubio_url ); ?> + "'");
					themeSingleTemplate.innerHTML = newInnerHtml;
				}
			})
		})(jQuery)
	</script>
	<?php

	// phpcs:ignore WordPress.WP.AlternativeFunctions.strip_tags_strip_tags
	$script = strip_tags( ob_get_clean() );
	wp_add_inline_script( 'jquery', $script );
	return;
}

add_filter( 'admin_init', 'kubio_update_dashboard_customizer_url' );
add_action( 'wp_prepare_themes_for_js', 'kubio_update_theme_page_customize_url', 1000 );
add_action( 'admin_bar_menu', 'kubio_set_admin_bar_menu_customize_to_kubio_editor', 1000 );
add_action( 'admin_menu', 'kubio_set_admin_bar_customize_to_kubio_editor', 1000 );

