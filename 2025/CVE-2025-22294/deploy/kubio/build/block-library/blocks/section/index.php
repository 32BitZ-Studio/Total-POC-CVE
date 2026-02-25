<?php

namespace Kubio\Blocks;

use Kubio\Core\Blocks\BlockContainerBase;
use Kubio\Core\Registry;
use Kubio\Core\Styles\FlexAlign;

class SectionBlock extends BlockContainerBase {


	// move to json
	static $WidthTypesClasses = array(
		'full-width' => 'h-section-fluid-container',
		'boxed'      => 'h-section-boxed-container',
	);


	public function mapPropsToElements() {
		$verticalAlignByMedia = $this->getPropByMedia( 'verticalAlign' );
		$verticalAlignClasses = FlexAlign::getVAlignClasses( $verticalAlignByMedia );
		$width                = $this->getProp( 'width', 'boxed' );
		$map                  = array();
		$map['outer']         = array(
			'className' => $verticalAlignClasses,
		);
		$map['inner']         = array( 'className' => isset( self::$WidthTypesClasses[ $width ] ) ? self::$WidthTypesClasses[ $width ] : '' );
		return $map;
	}
}

Registry::registerBlock( __DIR__, SectionBlock::class );
