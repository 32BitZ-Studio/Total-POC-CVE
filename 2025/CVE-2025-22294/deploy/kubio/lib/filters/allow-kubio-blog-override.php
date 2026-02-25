<?php

function kubio_allow_3rd_party_override_by_theme( $allow ) {
	$template           = get_template();
	$skip_for_templates = array( 'twentytwentyfour' );

	if ( in_array( $template, $skip_for_templates, true ) ) {
		return false;

	}

	return $allow;
}

add_filter( 'kubio/allow_3rd_party_blog_override', 'kubio_allow_3rd_party_override_by_theme' );
