<?php

namespace Kubio\Blocks;

use Kubio\AssetsDependencyInjector;
use Kubio\Core\Blocks\BlockBase;
use Kubio\Core\Registry;
use Kubio\Core\Utils;

class LinkBlock extends BlockBase {
	const OUTER = 'outer';
	const LINK  = 'link';
	const TEXT  = 'text';
	const ICON  = 'icon';

	public function computed() {
		$show_icon     = $this->getProp( 'showIcon', false );
		$icon_position = $this->getProp( 'iconPosition', 'before' );
		$show_before   = $show_icon && $icon_position === 'before';
		$show_after    = $show_icon && $icon_position === 'after';
		return array(
			'showBeforeIcon' => $show_before,
			'showAfterIcon'  => $show_after,
		);
	}

	public function mapPropsToElements() {
		$link = $this->getAttribute( 'link' );
		$type = $this->getAttribute( 'link.typeOpenLink' );

		$attributes = Utils::getLinkAttributes( $link );

		if ( $type === 'lightbox' ) {
			$attributes['data-type'] = $this->getAttribute( 'link.lightboxMedia' );
			AssetsDependencyInjector::injectKubioFrontendStyleDependencies( 'fancybox' );
			AssetsDependencyInjector::injectKubioScriptDependencies( 'fancybox' );

		}

		$icon_name = $this->getAttribute( 'icon.name' );
		$text      = $this->getBlockInnerHtml();
		return array(
			self::LINK => $attributes,

			self::ICON => array(
				'name' => $icon_name,
			),

			self::TEXT => array(
				'innerHTML' => wp_kses_post( $text ),
			),
		);
	}
}

Registry::registerBlock( __DIR__, LinkBlock::class );
