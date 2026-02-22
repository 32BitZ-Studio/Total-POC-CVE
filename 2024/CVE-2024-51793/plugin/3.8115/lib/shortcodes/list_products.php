<?php
//List Products shortcode
//Used to display Products on a page.
//Linked to single product pages. 

function wc_list_products() { 
	$content = '';
	$args = array( 'post_type' => 'rep_products' );
		
	$products_query = new WP_Query( $args );
	
	if($products_query->have_posts()) : 
	$content .= "<div class='grid-container grid-x grid-margin-x grid-padding-y'>";
	
	while ($products_query->have_posts()) : $products_query->the_post();
		$content .= '<div class="large-4 medium-6 small-12 cell">';
		$content .= "<div class='wc-product'>";
		$feat_image =   wp_get_attachment_image_src( get_post_thumbnail_id( $products_query->ID ), 'thumbnail' );
		$imageSrc 	= ( empty( $feat_image ) ) ? WC_COMPUTER_REPAIR_DIR_URL . '/assets/images/placeholder.png' : $feat_image[0];
		$content .= '<a href="'.get_the_permalink().'"><img src="' . $imageSrc . '" class="thumbnail" /></a>';
		$content .= "<a href='".get_the_permalink()."'><h3 class='wc-product-title'>".get_the_title()."</h3></a>";
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
}//wc_list_products.
add_shortcode('wc_list_products', 'wc_list_products');
