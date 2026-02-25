<?php

use IlluminateAgnostic\Arr\Support\Arr;

function kubio_ai_add_block_support( $args, $block_name ) {

	$attributes            = Arr::get( $args, 'attributes', array() );
	$attributes            = is_array( $attributes ) ? $attributes : array();
	$attributes['kubioAI'] = array( 'type' => 'object' );

	Arr::set( $args, 'attributes', $attributes );

	return $args;
}


add_filter( 'register_block_type_args', 'kubio_ai_add_block_support', 10, 2 );
