<?php

namespace Kubio\Blocks;

use IlluminateAgnostic\Arr\Support\Arr;
use Kubio\Core\Blocks\BlockBase;
use Kubio\Core\Registry;
use Kubio\Core\Utils;


class SocialIconsBlock extends BlockBase {
	const OUTER = 'outer';

	public function __construct( $block, $autoload = true ) {
		parent::__construct( $block, $autoload );
	}

	public function mapPropsToElements() {
		return array(
			self::OUTER => array(),
		);
	}
}

Registry::registerBlock( __DIR__, SocialIconsBlock::class );

class SocialIconBlock extends BlockBase {
	const LINK = 'link';
	const ICON = 'icon';

	public function mapPropsToElements() {
		$link            = $this->getAttribute( 'link' );
		$link_attributes = Utils::getLinkAttributes( $link );

		$icon_name = $this->getAttribute( 'icon.name' );

		return array(
			self::LINK => array_merge(
				$link_attributes,
				array(
					'aria-label' => esc_attr(
						sprintf(
						// translators: %s: social link value
							__( 'Social link: %s', 'kubio' ),
							Arr::get( $link, 'value', '' )
						)
					),
				)
			),

			self::ICON => array(
				'name' => $icon_name,
			),
		);
	}
}

Registry::registerBlock(
	__DIR__,
	SocialIconBlock::class,
	array(
		'metadata' => './blocks/social-icon/block.json',
	)
);
