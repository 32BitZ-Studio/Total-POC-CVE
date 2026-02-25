<?php

use Kubio\Blocks\PageTitleBlock;
use Kubio\Core\Utils;
use IlluminateAgnostic\Arr\Support\Arr;

add_action(
	'template_redirect',
	function () {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( Arr::has( $_REQUEST, '__kubio-page-title' ) && Utils::canEdit() ) {
			return wp_send_json_success(
				PageTitleBlock::getTitle( true )
			);
		}
	},
	PHP_INT_MAX
);
