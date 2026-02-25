<?php

namespace Kubio\Blocks;

use Kubio\Core\Blocks\BlockBase;
use Kubio\Core\Registry;

class CopyrightBlock extends BlockBase {

	const CONTAINER = 'container';
	const OUTER     = 'outer';

	public function mapPropsToElements() {

		$template = $this->getTemplateValue();
		return array(
			self::OUTER => array( 'innerHTML' => $this->render_template( $template ) ),
		);
	}

	function getTemplateValue() {
		$template = $this->getBlockInnerHtml();
		return $template;
	}

	function render_template( $content = '' ) {
		$default = '&copy; {year} {site-name}.';
		$msg     = $content ? $content : $default;

		// replace placeholders with actual values
		$msg = str_replace( '{year}', gmdate( 'Y' ), $msg );
		$msg = str_replace( '{site-name}', get_bloginfo( 'name' ), $msg );

		// sanitize the message to allow only post like content
		$msg = wp_kses_post( $msg );

		$msg = sprintf( '<p>%s</p>', $msg );
		return html_entity_decode( $msg );
	}
}

Registry::registerBlock(
	__DIR__,
	CopyrightBlock::class
);
