<?php

namespace Kubio\Blocks;

use Kubio\Core\Blocks\BlockBase;
use Kubio\Core\Registry;

class SearchForm extends BlockBase {

	const OUTER      = 'outer';
	const FORM       = 'form';
	const INPUT      = 'input';
	const BUTTON     = 'button';
	const ICON       = 'icon';
	const BUTTONTEXT = 'buttonText';

	public function computed() {
		$computedProps = array(
			'showInput'      => true,
			'showButton'     => 'inputAndButton' === $this->getProp( 'layout' ),
			'showButtonIcon' => 'icon' === $this->getProp( 'buttonType' ),
			'showButtonText' => 'text' === $this->getProp( 'buttonType' ),
			'iconButton'     => $this->getAttribute( 'iconName' ),
		);

		return $computedProps;
	}
	public function mapPropsToElements() {
		$inputPlaceholder = kubio_wpml_get_translated_string( $this->getAttribute( 'placeholderText' ) );
		$buttonText       = kubio_wpml_get_translated_string( $this->getProp( 'buttonText' ) );
		$button           = array( 'className' => array( 'search-button' ) );
		$iconButton       = $this->getAttribute( 'iconName' );

		return array(
			self::FORM       => array(
				'className' => array( 'd-flex', 'search-form' ),
				'action'    => esc_url( home_url() ),
				'role'      => 'search',
				'method'    => 'GET',
			),
			self::BUTTON     => $button,
			self::INPUT      => array(
				'className'   => array( 'search-input' ),
				'placeholder' => esc_attr( $inputPlaceholder ),
				'value'       => esc_attr( get_search_query() ),
				'name'        => 's',
			),
			self::ICON       => array(
				'name' => $iconButton,
			),
			self::BUTTONTEXT => array(
				'innerHTML' => wp_kses_post( $buttonText ),
			),
		);
	}
}


Registry::registerBlock(
	__DIR__,
	SearchForm::class
);
