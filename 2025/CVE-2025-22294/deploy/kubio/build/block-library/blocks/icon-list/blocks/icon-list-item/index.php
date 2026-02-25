<?php

namespace Kubio\Blocks;

use Kubio\Core\LodashBasic;
use Kubio\Core\Blocks\BlockBase;
use Kubio\Core\Registry;


class IconListItemBlock extends BlockBase {
	const ITEM        = 'item';
	const ICON        = 'icon';
	const LINK        = 'link';
	const TEXT        = 'text';
	const TEXTWRAPPER = 'text-wrapper';

	private $parent_block = null;

	public function __construct( $block, $autoload = true ) {

		parent::__construct( $block, $autoload );
	}

	public function mapPropsToElements() {
		$text         = $this->getBlockInnerHtml();
		$text         = preg_replace( '/\r?\n/', '<br/>', $text );
		$iconName     = $this->getAttribute( 'icon' );
		$disabledItem = $this->getAttribute( 'disabledItem' );
		$parent_block = Registry::getInstance()->getLastBlockOfName( 'kubio/iconlist' );
		$wrapper      = new IconListBlock( $parent_block->block_data );

		// @TO DO - disabled default color won't be needed when default state style will be fixed for frontend elements
		$iconDisabledDefaultColor = LodashBasic::get( $wrapper->block_type->supports, array( 'kubio', 'default', 'style', 'descendants', 'icon', 'states', 'customDisabled', 'fill' ) );
		$textDisabledDefaultColor = LodashBasic::get( $wrapper->block_type->supports, array( 'kubio', 'default', 'style', 'descendants', 'text', 'states', 'customDisabled', 'typography', 'color' ) );

		$iconDisabledStyle = array(
			'fill' => $disabledItem ? $wrapper->getStyle( 'states.customDisabled.fill', $iconDisabledDefaultColor, array( 'styledComponent' => self::ICON ) ) : '',
		);
		$textDisabledStyle = array(
			'color' => $disabledItem ? $wrapper->getStyle( 'states.customDisabled.typography.color', $textDisabledDefaultColor, array( 'styledComponent' => self::TEXT ) ) : '',
		);

		return array(
			self::ITEM        => array(
				'className' => $disabledItem === true ? 'kubio-is-disabled' : '',
			),
			self::ICON        => array(
				'name'  => $iconName,
				'style' => $iconDisabledStyle,
			),
			self::TEXT        => array(
				'innerHTML' => $text,
				'style'     => $textDisabledStyle,
			),
			self::TEXTWRAPPER => array(),
		);
	}

	public function computed() {
		$iconListBlock       = Registry::getInstance()->getLastBlockOfName( 'kubio/iconlist' );
		$divider             = $iconListBlock->getProp( 'divider' );
		$listItems           = LodashBasic::get( $iconListBlock->block_data, 'innerBlocks', array() );
		$currentItemPosition = 0;
		foreach ( $listItems as $index => $item ) {
			$itemId    = LodashBasic::get( $item, array( 'attrs', 'kubio', 'hash' ) );
			$currentId = LodashBasic::get( $this->block_data, array( 'attrs', 'kubio', 'hash' ) );
			if ( $itemId && $currentId && $itemId === $currentId ) {
				$currentItemPosition = $index;
			}
		}

		$isFirstChild = $currentItemPosition === 0;
		$isLastChild  = $currentItemPosition === count( $listItems ) - 1;
		return array(
			'isFirstChild'   => $isFirstChild,
			'isLastChild'    => $isLastChild,
			'dividerEnabled' => $divider['enabled'],
		);
	}

	public function getLinkAttribute() {
		$disabledItem = $this->getAttribute( 'disabledItem' );
		return ! $disabledItem ? $this->getAttribute( 'link', null ) : null;
	}
}


Registry::registerBlock(
	__DIR__,
	IconListItemBlock::class
);
