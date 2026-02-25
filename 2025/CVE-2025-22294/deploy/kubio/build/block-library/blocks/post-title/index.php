<?php

namespace Kubio\Blocks;

use Kubio\Core\Blocks\BlockBase;
use Kubio\Core\Registry;
use IlluminateAgnostic\Arr\Support\Arr;

class PostTitleBlock extends BlockBase {


	const CONTAINER = 'container';
	const LINK      = 'link';




	public function computed() {
		$iconEnabled    = $this->getProp( 'showIcon', false );
		$iconPosition   = $this->getProp( 'iconPosition', 'before' );
		$showBeforeIcon = $iconEnabled && $iconPosition == 'before';
		$showAfterIcon  = $iconEnabled && $iconPosition == 'after';
		return array(
			'showBeforeIcon' => $showBeforeIcon,
			'showAfterIcon'  => $showAfterIcon,
		);
	}

	public function mapPropsToElements() {
		$headingType = esc_attr( $this->getAttribute( 'headingType' ) );
		$post_id     = Arr::get( $this->block_context, 'postId', null );
		$title       = get_the_title( $post_id );
		return array(
			self::CONTAINER => array(
				'innerHTML' => $title !== '' ? wp_kses_post( $title ) : __( '(Post Title)', 'kubio' ),
				'tag'       => $headingType,
			),
			self::LINK      => array(
				'href' => esc_url( get_the_permalink( $post_id ) ),
			),
		);
	}
}

Registry::registerBlock( __DIR__, PostTitleBlock::class );
