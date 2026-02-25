<?php

namespace Kubio\Blocks;

use Kubio\Core\Blocks\BlockBase;
use Kubio\Core\Registry;
use Kubio_Walker_Comment;

class PostCommentsBlock extends BlockBase {

	const CONTAINER = 'commentsContainer';



	static function getPostCommentsTemplate() {
		return KUBIO_ROOT_DIR . '/lib/blog/comments.php';
	}

	public function serverSideRender() {
		global $withcomments;
		$withcomments = true;

		return $this->getPostComments(
			array(
				'none'        => $this->getAttribute( 'noCommentsTitle' ),
				'one'         => $this->getAttribute( 'oneCommentTitle' ),
				'multiple'    => $this->getAttribute( 'multipleComments' ),
				'disabled'    => $this->getAttribute( 'commentsDisabled' ),
				'avatar_size' => $this->getAttribute( 'avatarSize' ),
			)
		);
	}

	function getPostComments( $attrs = array() ) {

		if ( apply_filters( 'kubio/sandboxed_render', false ) ) {
			return '';
		}

		$atts = array_merge(
			array(
				'none'        => __( 'No responses yet', 'kubio' ),
				'one'         => __( 'One response', 'kubio' ),
				'multiple'    => __( '{COMMENTS-COUNT} Responses', 'kubio' ),
				'disabled'    => __( 'Comments are closed', 'kubio' ),
				'avatar_size' => 32,
			),
			$attrs
		);

		if ( kubio_wpml_is_active() ) {
			foreach ( $atts as $key => $value ) {
				$atts[ $key ] = kubio_wpml_get_translated_string( $value );
			}
		}

		global $kubio_comments_data;
		$kubio_comments_data = $atts;

		ob_start();
		add_filter( 'kubio/walker-comment', array( $this, 'getCommentWalker' ) );

		add_filter( 'comments_template', array( PostCommentsBlock::class, 'getPostCommentsTemplate' ) );
		if ( comments_open( get_the_ID() ) ) {
			comments_template();
		} else {
			return sprintf( '<p class="comments-disabled">%s</p>', esc_attr( $atts['disabled'] ) );
		}
		$content = ob_get_clean();

		remove_filter( 'comments_template', array( PostCommentsBlock::class, 'getPostCommentsTemplate' ) );
		remove_filter( 'kubio/walker-comment', array( $this, 'getCommentWalker' ) );

		return $content;
	}

	public function getCommentWalker( $walker ) {
		$migrations = $this->getAppliedMigrations();
		if ( in_array( 1, $migrations ) || in_array( '1', $migrations ) ) {
			require_once KUBIO_ROOT_DIR . '/lib/blog/walker-comment.php';
			return new Kubio_Walker_Comment();
		}

		return $walker;
	}

	public function mapPropsToElements() {
		return array(
			self::CONTAINER => array(
				'innerHTML' => $this->getPostComments(
					array(
						'none'        => wp_kses_post( $this->getAttribute( 'noCommentsTitle' ) ),
						'one'         => wp_kses_post( $this->getAttribute( 'oneCommentTitle' ) ),
						'multiple'    => wp_kses_post( $this->getAttribute( 'multipleComments' ) ),
						'disabled'    => wp_kses_post( $this->getAttribute( 'commentsDisabled' ) ),
						'avatar_size' => wp_kses_post( $this->getAttribute( 'avatarSize' ) ),
						'html5'       => true,
					)
				),
			),
		);
	}
}

Registry::registerBlock( __DIR__, PostCommentsBlock::class );
