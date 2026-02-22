<?php
defined( 'ABSPATH' ) || exit;

function wc_repair_shop_products_init() {
    $labels = array(
		'add_new_item' 			=> esc_html__('Add new Product', 'computer-repair-shop'),
		'singular_name' 		=> esc_html__('Product', 'computer-repair-shop'), 
		'menu_name' 			=> esc_html__('Products', 'computer-repair-shop'),
		'all_items' 			=> esc_html__('Products', 'computer-repair-shop'),
		'edit_item' 			=> esc_html__('Edit Product', 'computer-repair-shop'),
		'new_item' 				=> esc_html__('New Product', 'computer-repair-shop'),
		'view_item' 			=> esc_html__('View Product', 'computer-repair-shop'),
		'search_items' 			=> esc_html__('Search Products', 'computer-repair-shop'),
		'not_found' 			=> esc_html__('No product found', 'computer-repair-shop'),
		'not_found_in_trash' 	=> esc_html__('No product in trash', 'computer-repair-shop')
	);
	
	
	$args = array(
		'labels'             	=> $labels,
		'label'					=> esc_html__("Parts", "computer-repair-shop"),
		'description'        	=> esc_html__('Parts Section', 'computer-repair-shop'),
		'public'             	=> true,
		'publicly_queryable' 	=> true,
		'show_ui'            	=> true,
		'show_in_menu'       	=> false,
		'query_var'          	=> true,
		'rewrite'            	=> array('slug' => 'part'),
		'capability_type'    	=> array('rep_product', 'rep_products'),
		'has_archive'        	=> true,
		'menu_icon'			 	=> 'dashicons-clipboard',
		'menu_position'      	=> 30,
		'supports'           	=> array( 'title', 'editor', 'thumbnail'), 	
	  	'register_meta_box_cb' 	=> 'wc_parts_features',
		'taxonomies' 			=> array('brand_type')
    );
    register_post_type('rep_products', $args);
}
add_action( 'init', 'wc_repair_shop_products_init');
//registeration of post type ends here.

add_action( 'init', 'wc_create_parts_tax_brand');
function wc_create_parts_tax_brand() {
    $labels = array(
		'name'              => esc_html__('Brands', 'computer-repair-shop'),
		'singular_name'     => esc_html__('Brand', 'computer-repair-shop'),
		'search_items'      => esc_html__('Search Brands', 'computer-repair-shop'),
		'all_items'         => esc_html__('All Brands', 'computer-repair-shop'),
		'parent_item'       => esc_html__('Parent Brand', 'computer-repair-shop'),
		'parent_item_colon' => esc_html__('Parent Brand:', 'computer-repair-shop'),
		'edit_item'         => esc_html__('Edit Brand', 'computer-repair-shop'),
		'update_item'       => esc_html__('Update Brand', 'computer-repair-shop'),
		'add_new_item'      => esc_html__('Add New Brand', 'computer-repair-shop'),
		'new_item_name'     => esc_html__('New Brand Name', 'computer-repair-shop'),
		'menu_name'         => esc_html__('Brand', 'computer-repair-shop')
	);
	
	$args = array(
			'label' 		=> esc_html__( 'Brand', "computer-repair-shop"),
			'rewrite' 		=> array('slug' => 'brand'),
			'public' 		=> true,
			'labels' 		=> $labels,
			'hierarchical' 	=> true	
	);
	
	register_taxonomy(
        'brand_type',
        'rep_products',
		$args
    );
}
//Registration of Taxanomy Ends here. 

function wc_parts_features() { 
	$screens = array('rep_products');

	foreach ( $screens as $screen ) {
		add_meta_box(
			'myplugin_sectionid',
			'Product Details',
			'wc_parts_features_callback',
			$screen
		);
	}
} //Parts features post.
add_action( 'add_meta_boxes', 'wc_parts_features');



function wc_parts_features_callback( $post ) {

	wp_nonce_field( 'wc_meta_box_nonce', 'wc_parts_features_sub' );
	settings_errors();
	echo '<table class="form-table">';
	
	$value = get_post_meta( $post->ID, '_manufacturing_code', true );
	
	echo '<tr><td scope="row"><label for="manufacturing_code">'.esc_html__("Manufacturing Code", "computer-repair-shop").'</label></td><td>';
	echo '<input type="text" class="regular-text" name="manufacturing_code" id="manufacturing_code" value="'.esc_attr($value). '" />';
	echo '</td></tr>';
	
	$value = get_post_meta( $post->ID, '_stock_code', true );
	
	echo '<tr><td scope="row"><label for="stock_code">'.esc_html__("Stock Code", "computer-repair-shop").'</label></td><td>';
	echo '<input type="text" class="regular-text" name="stock_code" id="stock_code" value="'.esc_attr($value). '" />';
	echo '</td></tr>';
	
	$value = get_post_meta( $post->ID, '_core_features', true );
	
	echo '<tr><td scope="row"><label for="core_features">'.esc_html__("Core Features", "computer-repair-shop").'</label></td><td>';
	echo '<textarea class="large-text" name="core_features" id="core_features" rows="4">'.esc_attr($value).'</textarea>';
	echo '</td></tr>';
	
	$value = get_post_meta( $post->ID, '_capacity', true );
	
	echo '<tr><td scope="row"><label for="capacity">'.esc_html__("Capacity", "computer-repair-shop").'</label></td><td>';
	echo '<input type="text" class="regular-text" name="capacity" id="capacity" value="'.esc_attr($value). '" />';
	echo '</td></tr>';
	
	$value = get_post_meta( $post->ID, '_price', true );
	
	echo '<tr><td scope="row"><label for="price">'.esc_html__("Price", "computer-repair-shop").'</label></td><td>';
	echo '<input type="number" step="any" class="regular-text" name="price" id="wc_price" value="'.esc_attr($value). '" />';
	echo '<p class="description" id="tagline-description">'.esc_html__("Numbers only", "computer-repair-shop").'.</p>';
	echo '</td></tr>';

	//wc_use_tax
	$wc_use_taxes 		= get_option("wc_use_taxes");
	$wc_primary_tax		= get_option("wc_primary_tax");

	if($wc_use_taxes == "on"):
		$value = get_post_meta( $post->ID, '_wc_use_tax', true );

		if(empty($value)) {
			$value = $wc_primary_tax;
		}

		echo '<tr><td scope="row"><label for="wc_use_tax">'.esc_html__("Select Service Tax", "computer-repair-shop").'</label></td><td>';
		echo '<select class="regular-text form-control" name="wc_use_tax" id="wc_use_tax">';
		echo '<option value="">'.esc_html__("Select tax for service", "computer-repair-shop").'</option>';
		$allowed_html = wc_return_allowed_tags();
		$optionsGenerated = wc_generate_tax_options($value);
		echo wp_kses($optionsGenerated, $allowed_html);
		echo "</select>";
		echo '</td></tr>';

	endif; // Tax enabled
	
	$value = get_post_meta( $post->ID, '_warranty', true );
	
	echo '<tr><td scope="row"><label for="warranty">'.esc_html__("Warranty", "computer-repair-shop").'</label></td><td>';
	echo '<input type="text" class="regular-text" name="warranty" id="warranty" value="'.esc_attr($value). '" />';
	echo '</td></tr>';
	


	$value = get_post_meta( $post->ID, '_installation_charges', true );
	
	echo '<tr><td scope="row"><label for="installation_charges">'.esc_html__("Installation Charges", "computer-repair-shop").'</label></td><td>';
	echo '<input type="number" class="regular-text" step="any" name="installation_charges" id="installation_charges" value="'.esc_attr($value). '" />';
	echo '<p class="description" id="tagline-description">'.esc_html__("Leave blank to hide", "computer-repair-shop").'.</p>';
	echo '</td></tr>';
	
	$value = get_post_meta( $post->ID, '_installation_message', true );
	
	echo '<tr><td scope="row"><label for="installation_message">'.esc_html__("Installation Message", "computer-repair-shop").'</label></td><td>';
	echo '<input type="text" class="regular-text" name="installation_message" id="installation_message" value="'.esc_attr($value). '" />';
	echo '<p class="description" id="tagline-description">'.esc_html__("Leave blank to hide", "computer-repair-shop").'.</p>';
	echo '</td></tr>';
	
	echo '</table>';
}


/**
 * Save infor.
 *
 * @param int $post_id The ID of the post being saved.
 */
function wc_parts_features_save_box( $post_id ) {
	// Verify that the nonce is valid.
	if (!isset( $_POST['wc_parts_features_sub']) || ! wp_verify_nonce( $_POST['wc_parts_features_sub'], 'wc_meta_box_nonce' )) {
		return;
	}

	// If this is an autosave, our form has not been submitted, so we don't want to do anything.
	if ( defined('DOING_AUTOSAVE') && DOING_AUTOSAVE ) {
		return;
	}

	// Check the user's permissions.
	if ( isset( $_POST['post_type'] )) {
		if ( ! current_user_can( 'edit_post', $post_id ) ) {
			return;
		}
	}

	//Form PRocessing
	$submission_values = array(
						"manufacturing_code",
						"stock_code",
						"core_features",
						"capacity",
						"price",
						"warranty",
						"installation_charges",
						"installation_message",
						"wc_use_tax"
						);

	foreach($submission_values as $submit_value) {
		$my_value = ( isset( $_POST[$submit_value] ) ) ? sanitize_text_field( $_POST[$submit_value] ) : '';
		update_post_meta($post_id, '_'.$submit_value, $my_value);
	}
}
add_action( 'save_post', 'wc_parts_features_save_box' );


/*
*Add meta data to table fields post list.. 
*/
add_filter('manage_edit-rep_products_columns', 'wc_table_list_products_type_columns') ;

function wc_table_list_products_type_columns( $columns ) {
	$columns = array(
		'cb' 			=> '<input type="checkbox" />',
		'title' 		=> esc_html__('Part Name', "computer-repair-shop"),
		'stock_code' 	=> esc_html__('Stock Code', "computer-repair-shop"),
		'capacity' 		=> esc_html__('Capacity', "computer-repair-shop"),
		'price' 		=> esc_html__('Price', "computer-repair-shop"),
		'warranty' 		=> esc_html__('Warranty', "computer-repair-shop")
	);
	return $columns;
}

add_action( 'manage_rep_products_posts_custom_column', 'wc_table_list_meta_data', 10, 2 );

function wc_table_list_meta_data($column, $post_id) {
	global $post;
	
	switch( $column ) {
		case 'stock_code' :
			$stock_code = get_post_meta($post_id, '_stock_code', true );
			echo esc_html($stock_code);
		break;
		case 'capacity' :
			$capacity = get_post_meta($post_id, '_capacity', true);
			echo esc_html($capacity);
		break;
		
		case 'price' :
			$price = get_post_meta($post_id, '_price', true);
			$thePrice = wc_cr_currency_format( $price, TRUE );
			echo esc_html($thePrice);
		break;	
		case 'warranty' :
			$warranty = get_post_meta($post_id, '_warranty', true);
			echo esc_html($warranty);
		break;
		//Break for everything else to show default things.
		default :
			break;
	}
}


if(!function_exists("wc_extend_products_admin_search")):
	function wc_extend_products_admin_search( $query ) {

		// Extend search for document post type
		$_post_type = 'rep_products';
		// Custom fields to search for
		$custom_fields = array(
			"_stock_code",
			"_capacity"
		);

		if( ! is_admin() )
			return;

		if ( ! isset( $query->query_vars['post_type'] ) ) {
			return;
		}

		if ( $query->query_vars['post_type'] != $_post_type )  {
			return;
		}

		$search_term = $query->query_vars['s'];

		// Set to empty, otherwise it won't find anything
		$query->query_vars['s'] = '';

		$query->set('_meta_or_title', $search_term);

		if ( $search_term != '' ) {
			$meta_query = array( 'relation' => 'OR' );

			foreach( $custom_fields as $custom_field ) {
				array_push( $meta_query, array(
					'key' => $custom_field,
					'value' => $search_term,
					'compare' => 'LIKE'
				));
			}
			$query->set( 'meta_query', $meta_query );
		};
	}
	add_action( 'pre_get_posts', 'wc_extend_products_admin_search', 6, 2);

	add_action( 'pre_get_posts', function( $q )
	{
		if( $title = $q->get( '_meta_or_title' ) )
		{
			add_filter( 'get_meta_sql', function( $sql ) use ( $title )
			{
				global $wpdb;

				// Only run once:
				static $nr = 0; 
				if( 0 != $nr++ ) return $sql;

				// Modified WHERE
				$sql['where'] = sprintf(
					" AND ( %s OR %s ) ",
					$wpdb->prepare( "{$wpdb->posts}.post_title like '%%%s%%'", $title),
					mb_substr( $sql['where'], 5, mb_strlen( $sql['where'] ) )
				);

				return $sql;
			}, 12, 1);
		}
	}, 12, 1);
endif; 

//Add filter to show Meta Data in front end of post!
add_filter('the_content', 'wc_front_products_filter', 0);

function wc_front_products_filter($content) {
	if ( is_singular('rep_products') ) {
		global $post;
		
		$manufacturing_code 	= get_post_meta($post->ID, '_manufacturing_code', true);
		$stock_code 			= get_post_meta($post->ID, '_stock_code', true);
		$core_features 			= get_post_meta($post->ID, '_core_features', true);
		$capacity 				= get_post_meta($post->ID, '_capacity', true);
		$price 					= get_post_meta($post->ID, '_price', true);
		$warranty 				= get_post_meta($post->ID, '_warranty', true);
		$installation_charges 	= get_post_meta($post->ID, '_installation_charges', true);
		$installation_message 	= get_post_meta($post->ID, '_installation_message', true);
		
		$content = '<strong>'.esc_html__("Product Description", "computer-repair-shop").':</strong> '.$content;
		
		$content .= '<div class="grid-container grid-x grid-margin-x grid-margin-y">';
		$content .= '<h2 class="small-12 cell">'.esc_html__("Product Details", "computer-repair-shop").'</h2>';
		$content .= '<div class="large-4 medium-4 small-4 cell"><strong>'.esc_html__("Manufacturing Code", "computer-repair-shop").'</strong></div>';
		$content .= '<div class="large-8 medium-8 small-8 cell">'.$manufacturing_code.'</div>';
		$content .= "<hr class='rp-hr-line' />";
		
		$content .= '<div class="large-4 medium-4 small-4 cell"><strong>'.esc_html__("Stock Code", "computer-repair-shop").'</strong></div>';
		$content .= '<div class="large-8 medium-8 small-8 cell">'.$stock_code.'</div>';
		$content .= "<hr class='rp-hr-line' />";
		
		$content .= '<div class="large-4 medium-4 small-4 cell"><strong>'.esc_html__("Core Features", "computer-repair-shop").'</strong></div>';
		$content .= '<div class="large-8 medium-8 small-8 cell">'.$core_features.'</div>';
		$content .= "<hr class='rp-hr-line' />";
		
		$content .= '<div class="large-4 medium-4 small-4 cell"><strong>'.esc_html__("Capacity", "computer-repair-shop").'</strong></div>';
		$content .= '<div class="large-8 medium-8 small-8 cell">'.$capacity.'</div>';
		$content .= "<hr class='rp-hr-line' />";
		
		$content .= '<div class="large-4 medium-4 small-4 cell"><strong>'.esc_html__("Price", "computer-repair-shop").'</strong></div>';
		$content .= '<div class="large-8 medium-8 small-8 cell">' . wc_cr_currency_format( $price, TRUE ) . '</div>';
		$content .= "<hr class='rp-hr-line' />";
		
		if($installation_charges != '') { 
		$content .= '<div class="large-4 medium-4 small-4 cell"><strong>'.esc_html__("Installation Charges", "computer-repair-shop").'</strong></div>';
		$content .= '<div class="large-8 medium-8 small-8 cell">' . wc_cr_currency_format( $installation_charges, TRUE ) . ' '.$installation_message.'</div>';
		$content .= "<hr class='rp-hr-line' />";
		}
		
		$content .= '<div class="large-4 medium-4 small-4 cell"><strong>'.esc_html__("Warranty", "computer-repair-shop").'</strong></div>';
		$content .= '<div class="large-8 medium-8 small-8 cell">'.$warranty.'</div>';
		$content .= "<hr class='rp-hr-line' />";
		
		$content .= '<div class="large-4 medium-4 small-4 cell"><strong>'.esc_html__("Brand", "computer-repair-shop").'</strong></div>';
		$content .= '<div class="large-8 medium-8 small-8 cell">'.custom_taxonomies_terms_links($post->ID, $post->post_type).'</div>';
		$content .= "<hr class='rp-hr-line' />";
		
		$content .= '</div><!--row ends here.-->';
	}
	return $content;
}