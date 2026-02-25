<?php

function kubio_wp_compose_js_polyfill() {
	ob_start();
	?>
		<script>
			(function(compose){
				if(!compose.pipe){

					const basePipe =
								( reverse ) =>
								( ...funcs ) =>
								( ...args ) => {
									const functions = funcs.flat();
									if ( reverse ) {
										functions.reverse();
									}
									return functions.reduce(
										( prev, func ) => [ func( ...prev ) ],
										args
									)[ 0 ];
								};

					compose.pipe = basePipe();
				}
		})(wp.compose)
		</script>
	<?php
	$content = wp_strip_all_tags( ob_get_clean() );

	wp_add_inline_script( 'wp-compose', $content, 'after' );
}

add_filter( 'wp_enqueue_scripts', 'kubio_wp_compose_js_polyfill' );
add_filter( 'admin_enqueue_scripts', 'kubio_wp_compose_js_polyfill' );
