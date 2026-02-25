<?php

namespace Kubio\Blocks;

use Kubio\Core\Blocks\TemplatePartBlockBase;
use Kubio\Core\Registry;
use Kubio\Core\Utils;

class FooterTemplatePart extends TemplatePartBlockBase {


	public function mapPropsToElements() {
		$html_tag   = esc_attr( $this->getAttribute( 'tagName', 'div' ) );
		$scriptData = Utils::useJSComponentProps(
			'footer-parallax',
			array(
				'isEnabled' => $this->getProp( 'useFooterParallax', false ),
			)
		);
		return array(
			self::CONTAINER => array_merge(
				array(
					'tag'       => $html_tag,
					'innerHTML' => $this->getContent(),
				),
				$scriptData
			),
		);
	}
}

Registry::registerBlock( __DIR__, FooterTemplatePart::class );
