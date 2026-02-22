<?php
	//List Services shortcode
	//Used to display Services on a page.
	//Linked to single service pages. 
	defined( 'ABSPATH' ) || exit;

	function wc_list_services() { 
		global $WCRB_DEVICE_SERVICES;

		$content = '';
		$args = array( 'post_type' => 'rep_services' );

		$services_query = new WP_Query( $args );

		if($services_query->have_posts()) : 
		$content .= "<div class='grid-container grid-x grid-margin-x grid-padding-y'>";
		
		while ($services_query->have_posts()) : $services_query->the_post();
			$content .= '<div class="large-4 medium-6 small-12 cell">';
			$content .= "<div class='wc-product'>";
			$feat_image =   wp_get_attachment_image_src( get_post_thumbnail_id( $services_query->post->ID ), 'medium' );

			$content .= '<div class="wcrb_service_thumbwrap">';
			$imageSrc 	= ( empty( $feat_image ) ) ? WC_COMPUTER_REPAIR_DIR_URL . '/assets/images/placeholder.png' : $feat_image[0];
			$content .= '<a href="'.get_the_permalink().'"><img src="' . $imageSrc . '" class="thumbnail" /></a>';
			
			$_the_cost = $WCRB_DEVICE_SERVICES->return_price_range_of_service( $services_query->post->ID );
			$content .= ( ! empty( $_the_cost ) ) ? '<div class="wcrb_service_thumb_price">' . $_the_cost . '</div>' : '';

			$content .= '</div><!-- Thumb wrap ends /-->';
			$content .= "<h3 class='wc-product-title'><a href='" . get_the_permalink( $services_query->post->ID ) . "'>" . get_the_title( $services_query->post->ID ) . "</a></h3>";
			$content .= '</div></div>'; //Columns ends here.
		endwhile;
		
		//<!-- end of the loop -->
		$content .= "</div><!--row ends here.-->";
		//<!-- pagination here -->

		wp_reset_postdata();

		else :
			echo "<p>";
				esc_html_e( 'Sorry, no product matched your criteria.', "computer-repair-shop" );
			echo "</p>";
		endif;

		return $content;
	}//wc_list_services.
	add_shortcode('wc_list_services', 'wc_list_services');