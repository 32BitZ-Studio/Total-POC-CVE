<?php

class KubioWPTemplateListTable extends \WP_Posts_List_Table {


	protected function handle_row_actions( $item, $column_name, $primary ) {

		if ( $primary !== $column_name ) {
			return '';
		}

		$post          = $item;
		$can_edit_post = current_user_can( 'edit_post', $post->ID );
		$actions       = array();
		$title         = _draft_or_post_title();

		if ( $can_edit_post && 'trash' !== $post->post_status ) {
			$actions['edit'] = sprintf(
				'<a href="%s" aria-label="%s">%s</a>',
				$this->kubio_get_edit_post_link( $post ),
				// phpcs:ignore WordPress.WP.I18n.MissingArgDomain, WordPress.WP.I18n.MissingTranslatorsComment
				esc_attr( sprintf( __( 'Edit &#8220;%s&#8221;' ), $title ) ),
				// phpcs:ignore WordPress.WP.I18n.MissingArgDomain, WordPress.WP.I18n.MissingTranslatorsComment
				__( 'Edit' )
			);

			if ( 'wp_block' !== $post->post_type ) {
				$actions['inline hide-if-no-js'] = sprintf(
					'<button type="button" class="button-link editinline" aria-label="%s" aria-expanded="false">%s</button>',
					// phpcs:ignore WordPress.WP.I18n.MissingArgDomain, WordPress.WP.I18n.MissingTranslatorsComment
					esc_attr( sprintf( __( 'Quick edit &#8220;%s&#8221; inline' ), $title ) ),
					// phpcs:ignore WordPress.WP.I18n.MissingArgDomain, WordPress.WP.I18n.MissingTranslatorsComment
					__( 'Quick&nbsp;Edit' )
				);
			}
		}

		if ( current_user_can( 'delete_post', $post->ID ) ) {
			if ( 'trash' === $post->post_status ) {
				$actions['untrash'] = sprintf(
					'<a href="%s" aria-label="%s">%s</a>',
					wp_nonce_url( admin_url( sprintf( 'post.php?post=%d' . '&amp;action=untrash', $post->ID ) ), 'untrash-post_' . $post->ID ),
					// phpcs:ignore WordPress.WP.I18n.MissingArgDomain, WordPress.WP.I18n.MissingTranslatorsComment
					esc_attr( sprintf( __( 'Restore &#8220;%s&#8221; from the Trash' ), $title ) ),
					// phpcs:ignore WordPress.WP.I18n.MissingArgDomain, WordPress.WP.I18n.MissingTranslatorsComment
					__( 'Restore' )
				);
			} elseif ( EMPTY_TRASH_DAYS ) {
				$actions['trash'] = sprintf(
					'<a href="%s" class="submitdelete" aria-label="%s">%s</a>',
					$this->kubio_get_delete_post_link( $post->ID ),
				// phpcs:ignore WordPress.WP.I18n.MissingArgDomain, WordPress.WP.I18n.MissingTranslatorsComment
					esc_attr( sprintf( __( 'Move &#8220;%s&#8221; to the Trash' ), $title ) ),
					// phpcs:ignore WordPress.WP.I18n.MissingArgDomain, WordPress.WP.I18n.MissingTranslatorsComment
					_x( 'Trash', 'verb' )
				);
			}

			if ( 'trash' === $post->post_status || ! EMPTY_TRASH_DAYS ) {
				$actions['delete'] = sprintf(
					'<a href="%s" class="submitdelete" aria-label="%s">%s</a>',
					$this->kubio_get_delete_post_link( $post->ID, '', true ),
				// phpcs:ignore WordPress.WP.I18n.MissingArgDomain, WordPress.WP.I18n.MissingTranslatorsComment
					esc_attr( sprintf( __( 'Delete &#8220;%s&#8221; permanently' ), $title ) ),
					// phpcs:ignore WordPress.WP.I18n.MissingArgDomain, WordPress.WP.I18n.MissingTranslatorsComment
					__( 'Delete Permanently' )
				);
			}
		}

		if ( is_post_type_hierarchical( $post->post_type ) ) {

			/**
			 * Filters the array of row action links on the Pages list table.
			 *
			 * The filter is evaluated only for hierarchical post types.
			 *
			 * @since 2.8.0
			 *
			 * @param string[] $actions An array of row action links. Defaults are
			 *                          'Edit', 'Quick Edit', 'Restore', 'Trash',
			 *                          'Delete Permanently', 'Preview', and 'View'.
			 * @param WP_Post  $post    The post object.
			 */
			$actions = apply_filters( 'page_row_actions', $actions, $post );
		} else {

			/**
			 * Filters the array of row action links on the Posts list table.
			 *
			 * The filter is evaluated only for non-hierarchical post types.
			 *
			 * @since 2.8.0
			 *
			 * @param string[] $actions An array of row action links. Defaults are
			 *                          'Edit', 'Quick Edit', 'Restore', 'Trash',
			 *                          'Delete Permanently', 'Preview', and 'View'.
			 * @param WP_Post  $post    The post object.
			 */
			$actions = apply_filters( 'post_row_actions', $actions, $post );
		}

		return $this->row_actions( $actions );
	}


	private function kubio_get_delete_post_link( $post = 0, $deprecated = '', $force_delete = false ) {
		if ( ! empty( $deprecated ) ) {
			_deprecated_argument( __FUNCTION__, '3.0.0' );
		}

		$post = get_post( $post );

		if ( ! $post ) {
			return;
		}

		$post_type_object = get_post_type_object( $post->post_type );

		if ( ! $post_type_object ) {
			return;
		}

		if ( ! current_user_can( 'delete_post', $post->ID ) ) {
			return;
		}

		$action = ( $force_delete || ! EMPTY_TRASH_DAYS ) ? 'delete' : 'trash';

		$delete_link = add_query_arg( 'action', $action, admin_url( sprintf( 'post.php?post=%d', $post->ID ) ) );

		/**
		 * Filters the post delete link.
		 *
		 * @since 2.9.0
		 *
		 * @param string $link         The delete link.
		 * @param int    $post_id      Post ID.
		 * @param bool   $force_delete Whether to bypass the Trash and force deletion. Default false.
		 */
		return apply_filters( 'get_delete_post_link', wp_nonce_url( $delete_link, "$action-post_{$post->ID}" ), $post->ID, $force_delete );
	}

	private function kubio_get_edit_post_link( $post ) {
		if ( ! wp_is_block_theme() ) {
			$action = '&action=edit';
			return admin_url( sprintf( 'post.php?post=%d' . $action, $post->ID ) );
		}

		return get_edit_post_link( $post->ID );
	}
}
