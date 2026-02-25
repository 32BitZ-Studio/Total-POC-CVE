<?php


function kubio_polylang_is_active(): bool {
	//disable polylang detection until it's ready for release
	return false;
	return function_exists( 'pll_the_languages' );
}
