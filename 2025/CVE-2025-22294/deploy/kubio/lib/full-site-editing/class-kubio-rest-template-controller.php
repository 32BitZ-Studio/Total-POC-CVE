<?php

use Kubio\Core\Utils;

if ( class_exists( '\Gutenberg_REST_Templates_Controller' ) ) {
	class KubioRestTemplateController extends \Gutenberg_REST_Templates_Controller {
		public function get_item( $request ) {

			if ( Utils::wpVersionCompare( '6.5', '>=' ) && is_numeric( $request['id'] ) ) {
				$controller = new \WP_REST_Posts_Controller( 'wp_template' );
				return $controller->get_item( $request );
			}

			return parent::get_item( $request );
		}

		public function update_item( $request ) {
			if ( Utils::wpVersionCompare( '6.5', '>=' ) && is_numeric( $request['id'] ) ) {
				$controller = new \WP_REST_Posts_Controller( 'wp_template' );
				return $controller->update_item( $request );
			}

			return parent::update_item( $request );
		}
	}

} else {
	class KubioRestTemplateController extends \WP_REST_Templates_Controller {
		public function get_item( $request ) {

			if ( Utils::wpVersionCompare( '6.5', '>=' ) && is_numeric( $request['id'] ) ) {
				$controller = new \WP_REST_Posts_Controller( 'wp_template' );
				return $controller->get_item( $request );
			}

			return parent::get_item( $request );
		}

		public function update_item( $request ) {
			if ( Utils::wpVersionCompare( '6.5', '>=' ) && is_numeric( $request['id'] ) ) {
				$controller = new \WP_REST_Posts_Controller( 'wp_template' );
				return $controller->update_item( $request );
			}

			return parent::update_item( $request );
		}
	}
}
