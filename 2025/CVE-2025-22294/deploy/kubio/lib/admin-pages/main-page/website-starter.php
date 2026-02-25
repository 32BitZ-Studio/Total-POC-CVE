<style>
	#kubio-website-starter{
		background-image: url(<?php echo esc_url( KUBIO_ROOT_URL . '/static/admin-assets/bg-dark.png' ); ?>);
	}
</style>
<div id="kubio-website-starter"></div>
<?php

wp_add_inline_script(
	'kubio-admin-area',
	sprintf(
		'wp.domReady( function() { kubio.adminArea.initSiteWizard(  %s );	} );',
		wp_json_encode(
			array()
		)
	),
	'after'
);
