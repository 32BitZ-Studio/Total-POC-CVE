<?php
	function wc_repair_shop_devices_init() {
		$wc_device_label        = ( empty( get_option( 'wc_device_label' ) ) ) ? esc_html__( 'Device', 'computer-repair-shop' ) : get_option( 'wc_device_label' );
		$wc_device_label_plural = ( empty( get_option( 'wc_device_label_plural' ) ) ) ? esc_html__( 'Devices', 'computer-repair-shop' ) : get_option( 'wc_device_label_plural' );
		$labels = array(
			'add_new' 			=> esc_html__('Add New ', 'computer-repair-shop') . $wc_device_label,
			'singular_name' 		=> $wc_device_label, 
			'menu_name' 			=> $wc_device_label_plural,
			'all_items' 			=> $wc_device_label_plural,
			'edit_item' 			=> esc_html__('Edit ', 'computer-repair-shop') . $wc_device_label,
			'new_item' 				=> esc_html__('New ', 'computer-repair-shop') . $wc_device_label,
			'view_item' 			=> esc_html__('View ', 'computer-repair-shop') . $wc_device_label,
			'search_items' 			=> esc_html__('Search ', 'computer-repair-shop') . $wc_device_label,
			'not_found' 			=> esc_html__('Nothing found', 'computer-repair-shop'),
			'not_found_in_trash' 	=> esc_html__('Nothing in trash', 'computer-repair-shop')
		);
		
		$args = array(
			'labels'             	=> $labels,
			'label'					=> $wc_device_label_plural,
			'description'        	=> $wc_device_label_plural . esc_html__(' Section', 'computer-repair-shop'),
			'public'             	=> true,
			'publicly_queryable' 	=> true,
			'show_ui'            	=> true,
			'show_in_menu'       	=> false,
			'query_var'          	=> true,
			'rewrite'            	=> array('slug' => 'device'),
			'capability_type'    	=> array('rep_device', 'rep_devices'),
			'has_archive'        	=> true,
			'menu_icon'			 	=> 'dashicons-clipboard',
			'menu_position'      	=> 30,
			'supports'           	=> array( 'title', 'editor', 'thumbnail' ), 	
			'taxonomies' 			=> array( 'device_type', 'device_brand' )
		);
		register_post_type('rep_devices', $args);
	}
	add_action( 'init', 'wc_repair_shop_devices_init');

	function wc_repair_shop_devices_other_init() {
		$wc_device_label        = ( empty( get_option( 'wc_device_label' ) ) ) ? esc_html__( 'Other', 'computer-repair-shop' ) . ' ' . esc_html__( 'Device', 'computer-repair-shop' ) : esc_html__( 'Other', 'computer-repair-shop' ) . ' ' . get_option( 'wc_device_label' );
		$wc_device_label_plural = ( empty( get_option( 'wc_device_label_plural' ) ) ) ? esc_html__( 'Other', 'computer-repair-shop' ) . ' ' . esc_html__( 'Devices', 'computer-repair-shop' ) : esc_html__( 'Other', 'computer-repair-shop' ) . ' ' . get_option( 'wc_device_label_plural' );
		$labels = array(
			'add_new' 				=> esc_html__('Add New ', 'computer-repair-shop') . $wc_device_label,
			'singular_name' 		=> $wc_device_label, 
			'menu_name' 			=> $wc_device_label_plural,
			'all_items' 			=> $wc_device_label_plural,
			'edit_item' 			=> esc_html__('Edit ', 'computer-repair-shop') . $wc_device_label,
			'new_item' 				=> esc_html__('New ', 'computer-repair-shop') . $wc_device_label,
			'view_item' 			=> esc_html__('View ', 'computer-repair-shop') . $wc_device_label,
			'search_items' 			=> esc_html__('Search ', 'computer-repair-shop') . $wc_device_label,
			'not_found' 			=> esc_html__('Nothing found', 'computer-repair-shop'),
			'not_found_in_trash' 	=> esc_html__('Nothing in trash', 'computer-repair-shop')
		);
		
		$args = array(
			'labels'             	=> $labels,
			'label'					=> $wc_device_label_plural,
			'description'        	=> $wc_device_label_plural . esc_html__( ' Section', 'computer-repair-shop' ),
			'public'             	=> false,
			'publicly_queryable' 	=> false,
			'show_ui'            	=> true,
			'show_in_menu'       	=> false,
			'query_var'          	=> true,
			'rewrite'            	=> array( 'slug' => 'device_other' ),
			'capability_type'    	=> array('rep_device', 'rep_devices'),
			'capabilities' 			=> array( 'create_post' => 'do_not_allow', 'create_posts' => 'do_not_allow' ),
			'map_meta_cap'       	=> true,
			'has_archive'        	=> false,
			'menu_icon'			 	=> 'dashicons-clipboard',
			'menu_position'      	=> 30,
			'supports'           	=> array( 'title' ), 	
			'taxonomies' 			=> array( 'device_type', 'device_brand' )
		);
		register_post_type( 'rep_devices_other', $args);
	}
	add_action( 'init', 'wc_repair_shop_devices_other_init' );
	//registeration of post type ends here.

	add_action( 'init', 'wc_create_device_tax_brand');
	function wc_create_device_tax_brand() {
		$wc_device_brand_label        = ( empty( get_option( 'wc_device_brand_label' ) ) ) ? esc_html__( 'Device Brand', 'computer-repair-shop' ) : get_option( 'wc_device_brand_label' );
		$wc_device_brand_label_plural = ( empty( get_option( 'wc_device_brand_label_plural' ) ) ) ? esc_html__( 'Device Brands', 'computer-repair-shop' ) : get_option( 'wc_device_brand_label_plural' );

		$labels = array(
			'name'              => $wc_device_brand_label_plural,
			'singular_name'     => $wc_device_brand_label,
			'search_items'      => esc_html__('Search ', 'computer-repair-shop') . $wc_device_brand_label_plural,
			'all_items'         => esc_html__('All ', 'computer-repair-shop') . $wc_device_brand_label_plural,
			'parent_item'       => esc_html__('Parent ', 'computer-repair-shop') . $wc_device_brand_label,
			'parent_item_colon' => esc_html__('Parent ', 'computer-repair-shop') . $wc_device_brand_label,
			'edit_item'         => esc_html__('Edit ', 'computer-repair-shop') . $wc_device_brand_label,
			'update_item'       => esc_html__('Update ', 'computer-repair-shop') . $wc_device_brand_label,
			'add_new_item'      => esc_html__('Add New ', 'computer-repair-shop') . $wc_device_brand_label,
			'new_item_name'     => esc_html__('New Name', 'computer-repair-shop'),
			'menu_name'         => $wc_device_brand_label,
		);
		
		$args = array(
				'label'   => $wc_device_brand_label,
				'rewrite' => array('slug' => 'device-brand'),
				'public'  => true,
				'labels'  => $labels,
				'hierarchical' => true,
				'show_admin_column' => true,	
		);
		
		register_taxonomy(
			'device_brand',
			array('rep_devices', 'rep_devices_other'),
			$args
		);
	} //Registration of Taxanomy Ends here.

	//Add image field in taxonomy page
	if( ! function_exists( 'wc_rp_add_custom_taxonomy_image' ) ) :
		add_action( 'device_brand_add_form_fields', 'wc_rp_add_custom_taxonomy_image', 10, 2 );
		function wc_rp_add_custom_taxonomy_image ( $taxonomy ) {
		?>
			<div class="form-field term-group">
				<label for="image_id"><?php echo esc_html__( 'Image', 'computer-repair-shop' ); ?></label>
				<input type="hidden" id="image_id" name="image_id" class="custom_media_url" value="">
				<div id="image_wrapper"></div>
				<p>
					<input type="button" class="button button-secondary taxonomy_media_button" id="taxonomy_media_button" name="taxonomy_media_button" value="<?php echo esc_html__( 'Add Image', 'computer-repair-shop' ); ?>">
					<input type="button" class="button button-secondary taxonomy_media_remove" id="taxonomy_media_remove" name="taxonomy_media_remove" value="<?php echo esc_html__( 'Remove Image', 'computer-repair-shop' ); ?>">
				</p>
			</div>
		<?php
		}
	endif;

	//Save the taxonomy image field
	if ( ! function_exists( 'wc_rp_save_custom_taxonomy_image' ) ) :
		add_action( 'created_device_brand', 'wc_rp_save_custom_taxonomy_image', 10, 2 );
		function wc_rp_save_custom_taxonomy_image ( $term_id, $tt_id ) {
			if( isset( $_POST['image_id'] ) && '' !== $_POST['image_id'] ) {
				$image = sanitize_text_field( $_POST['image_id'] );
				add_term_meta( $term_id, 'image_id', $image, true );
			}
		}
	endif;

	//Add the image field in edit form page
	if ( ! function_exists( 'wc_rb_update_custom_taxonomy_image' ) ) :
		add_action( 'device_brand_edit_form_fields', 'wc_rb_update_custom_taxonomy_image', 10, 2 );
		function wc_rb_update_custom_taxonomy_image ( $term, $taxonomy ) { ?>
			<tr class="form-field term-group-wrap">
				<th scope="row">
					<label for="image_id"><?php echo esc_html__( 'Image', 'computer-repair-shop' ); ?></label>
				</th>
				<td>
					<?php $image_id = get_term_meta ( $term -> term_id, 'image_id', true ); ?>
					<input type="hidden" id="image_id" name="image_id" value="<?php echo esc_html($image_id); ?>">

					<div id="image_wrapper">
					<?php 
						if ( $image_id ) {
							$the_rb_tx_img = wp_get_attachment_image ( $image_id, 'thumbnail' );
							echo wp_kses_post( $the_rb_tx_img );
						}
					?>
					</div>
					<p>
						<input type="button" class="button button-secondary taxonomy_media_button" id="taxonomy_media_button" name="taxonomy_media_button" value="<?php echo esc_html__( 'Add Image', 'computer-repair-shop' ); ?>">
						<input type="button" class="button button-secondary taxonomy_media_remove" id="taxonomy_media_remove" name="taxonomy_media_remove" value="<?php echo esc_html__( 'Remove Image', 'computer-repair-shop' ); ?>">
					</p>
				</div></td>
			</tr>
		<?php
		}
	endif;

	//Update the taxonomy image field
	if( ! function_exists( 'wc_rb_updated_custom_taxonomy_image' ) ) :
		add_action( 'edited_device_brand', 'wc_rb_updated_custom_taxonomy_image', 10, 2 );
		function wc_rb_updated_custom_taxonomy_image ( $term_id, $tt_id ) {
			if( isset( $_POST['image_id'] ) && '' !== $_POST['image_id'] ){
				$image = sanitize_text_field( $_POST['image_id'] );
				update_term_meta ( $term_id, 'image_id', $image );
			} else {
				update_term_meta ( $term_id, 'image_id', '' );
			}
		}
	endif;

	//Enqueue the wp_media library
	if( ! function_exists( 'wc_rb_custom_taxonomy_load_media' ) ) :
		add_action( 'admin_enqueue_scripts', 'wc_rb_custom_taxonomy_load_media' );
		function wc_rb_custom_taxonomy_load_media () {
			if( ! isset( $_GET['taxonomy'] ) || ( $_GET['taxonomy'] != 'device_brand' && $_GET['taxonomy'] != 'device_type' ) ) {
				return;
			}
			wp_enqueue_media();
		}
	endif;

	//Custom script
	if ( ! function_exists( 'wc_rb_add_custom_taxonomy_script' ) ) :
		add_action( 'admin_footer', 'wc_rb_add_custom_taxonomy_script' );
		function wc_rb_add_custom_taxonomy_script() {
			if( ! isset( $_GET['taxonomy'] ) || ( $_GET['taxonomy'] != 'device_brand' && $_GET['taxonomy'] != 'device_type' ) ) {
			return;
			}
			?> <script>jQuery(document).ready( function($) {
					function taxonomy_media_upload(button_class) {
						var custom_media = true,
						original_attachment = wp.media.editor.send.attachment;
						$('body').on('click', button_class, function(e) {
							var button_id = '#'+$(this).attr('id');
							var send_attachment = wp.media.editor.send.attachment;
							var button = $(button_id);
							custom_media = true;
							wp.media.editor.send.attachment = function(props, attachment){
								if ( custom_media ) {
									$('#image_id').val(attachment.id);
									$('#image_wrapper').html('<img class="custom_media_image" src="" style="margin:0;padding:0;max-height:100px;float:none;" />');
									$('#image_wrapper .custom_media_image').attr('src',attachment.url).css('display','block');
								} else {
									return original_attachment.apply( button_id, [props, attachment] );
								}
							}
							wp.media.editor.open(button);
							return false;
						});
					}
					taxonomy_media_upload('.taxonomy_media_button.button'); 
					$('body').on('click','.taxonomy_media_remove',function(){
						$('#image_id').val('');
						$('#image_wrapper').html('<img class="custom_media_image" src="" style="margin:0;padding:0;max-height:100px;float:none;" />');
					});

					$(document).ajaxComplete(function(event, xhr, settings) {
						var queryStringArr = settings.data.split('&');
						if( $.inArray('action=add-tag', queryStringArr) !== -1 ){
							var xml = xhr.responseXML;
							$response = $(xml).find('term_id').text();
							if($response!=""){
								$('#image_wrapper').html('');
							}
						}
					});
				});</script> <?php
		}
	endif;

	//Add new column heading
	if ( ! function_exists( 'wc_rb_display_custom_taxonomy_image_column_heading' ) ) :
		add_filter( 'manage_edit-device_brand_columns', 'wc_rb_display_custom_taxonomy_image_column_heading' ); 
		function wc_rb_display_custom_taxonomy_image_column_heading( $columns ) {
			$columns['category_image'] = esc_html__( 'Logo', 'computer-repair-shop' );
			return $columns;
		}
	endif;

	//Display new columns values
	if ( ! function_exists( 'wc_rb_display_custom_taxonomy_image_column_value' ) ) :
		add_action( 'manage_device_brand_custom_column', 'wc_rb_display_custom_taxonomy_image_column_value' , 10, 3); 
		function wc_rb_display_custom_taxonomy_image_column_value( $columns, $column, $id ) {
			if ( 'category_image' == $column ) {
				$image_id = esc_html( get_term_meta( $id, 'image_id', true ) );
				$columns = wp_get_attachment_image ( $image_id, array('50', '50') );
			}
			return $columns;
		}
	endif;

	add_action( 'init', 'wc_create_device_tax_type');
	function wc_create_device_tax_type() {
		$wc_device_type_label        = ( empty( get_option( 'wc_device_type_label' ) ) ) ? esc_html__( 'Device Type', 'computer-repair-shop' ) : get_option( 'wc_device_type_label' );
		$wc_device_type_label_plural = ( empty( get_option( 'wc_device_type_label_plural' ) ) ) ? esc_html__( 'Device Type', 'computer-repair-shop' ) : get_option( 'wc_device_type_label_plural' );

		$labels = array(
			'name'              => $wc_device_type_label_plural,
			'singular_name'     => $wc_device_type_label,
			'search_items'      => esc_html__('Search ', 'computer-repair-shop') . $wc_device_type_label_plural,
			'all_items'         => esc_html__('All ', 'computer-repair-shop') . $wc_device_type_label_plural,
			'parent_item'       => esc_html__('Parent ', 'computer-repair-shop') . $wc_device_type_label,
			'parent_item_colon' => esc_html__('Parent ', 'computer-repair-shop') . $wc_device_type_label,
			'edit_item'         => esc_html__('Edit ', 'computer-repair-shop') . $wc_device_type_label,
			'update_item'       => esc_html__('Update ', 'computer-repair-shop') . $wc_device_type_label,
			'add_new_item'      => esc_html__('Add New ', 'computer-repair-shop') . $wc_device_type_label,
			'new_item_name'     => esc_html__('New Name', 'computer-repair-shop'),
			'menu_name'         => $wc_device_type_label,
		);
		
		$args = array(
				'label'   => $wc_device_type_label,
				'rewrite' => array('slug' => 'device-type'),
				'public'  => true,
				'labels'  => $labels,
				'hierarchical' => true,
				'show_admin_column' => true,	
		);
		
		register_taxonomy(
			'device_type',
			array('rep_devices', 'rep_devices_other'),
			$args
		);
	} //Registration of Taxanomy Ends here.

	//Add image field in taxonomy page
	if( ! function_exists( 'wc_rp_add_custom_type_image' ) ) :
		add_action( 'device_type_add_form_fields', 'wc_rp_add_custom_type_image', 10, 2 );
		function wc_rp_add_custom_type_image ( $taxonomy ) {
		?>
			<div class="form-field term-group">
				<label for="image_id"><?php echo esc_html__( 'Image', 'computer-repair-shop' ); ?></label>
				<input type="hidden" id="image_id" name="image_id" class="custom_media_url" value="">
				<div id="image_wrapper"></div>
				<p>
					<input type="button" class="button button-secondary taxonomy_media_button" id="taxonomy_media_button" name="taxonomy_media_button" value="<?php echo esc_html__( 'Add Image', 'computer-repair-shop' ); ?>">
					<input type="button" class="button button-secondary taxonomy_media_remove" id="taxonomy_media_remove" name="taxonomy_media_remove" value="<?php echo esc_html__( 'Remove Image', 'computer-repair-shop' ); ?>">
				</p>
			</div>
		<?php
		}
	endif;

	//Save the taxonomy image field
	if ( ! function_exists( 'wc_rp_save_custom_type_image' ) ) :
		add_action( 'created_device_type', 'wc_rp_save_custom_type_image', 10, 2 );
		function wc_rp_save_custom_type_image ( $term_id, $tt_id ) {
			if( isset( $_POST['image_id'] ) && '' !== $_POST['image_id'] ) {
				$image = sanitize_text_field( $_POST['image_id'] );
				add_term_meta( $term_id, 'image_id', $image, true );
			}
		}
	endif;

	//Add the image field in edit form page
	if ( ! function_exists( 'wc_rb_update_custom_type_image' ) ) :
		add_action( 'device_type_edit_form_fields', 'wc_rb_update_custom_type_image', 10, 2 );
		function wc_rb_update_custom_type_image ( $term, $taxonomy ) { ?>
			<tr class="form-field term-group-wrap">
				<th scope="row">
					<label for="image_id"><?php echo esc_html__( 'Image', 'computer-repair-shop' ); ?></label>
				</th>
				<td>
					<?php $image_id = get_term_meta ( $term -> term_id, 'image_id', true ); ?>
					<input type="hidden" id="image_id" name="image_id" value="<?php echo esc_html($image_id); ?>">

					<div id="image_wrapper">
					<?php 
						if ( $image_id ) {
							$the_rb_tx_img = wp_get_attachment_image ( $image_id, 'thumbnail' );
							echo wp_kses_post( $the_rb_tx_img );
						}
					?>
					</div>
					<p>
						<input type="button" class="button button-secondary taxonomy_media_button" id="taxonomy_media_button" name="taxonomy_media_button" value="<?php echo esc_html__( 'Add Image', 'computer-repair-shop' ); ?>">
						<input type="button" class="button button-secondary taxonomy_media_remove" id="taxonomy_media_remove" name="taxonomy_media_remove" value="<?php echo esc_html__( 'Remove Image', 'computer-repair-shop' ); ?>">
					</p>
				</div></td>
			</tr>
		<?php
		}
	endif;

	//Update the taxonomy image field
	if( ! function_exists( 'wc_rb_updated_custom_type_image' ) ) :
		add_action( 'edited_device_type', 'wc_rb_updated_custom_type_image', 10, 2 );
		function wc_rb_updated_custom_type_image ( $term_id, $tt_id ) {
			if( isset( $_POST['image_id'] ) && '' !== $_POST['image_id'] ){
				$image = sanitize_text_field( $_POST['image_id'] );
				update_term_meta ( $term_id, 'image_id', $image );
			} else {
				update_term_meta ( $term_id, 'image_id', '' );
			}
		}
	endif;

	//Add new column heading
	if ( ! function_exists( 'wc_rb_display_custom_type_image_column_heading' ) ) :
		add_filter( 'manage_edit-device_type_columns', 'wc_rb_display_custom_type_image_column_heading' ); 
		function wc_rb_display_custom_type_image_column_heading( $columns ) {
			$columns['category_image'] = esc_html__( 'Icon', 'computer-repair-shop' );
			return $columns;
		}
	endif;

	//Display new columns values
	if ( ! function_exists( 'wc_rb_display_custom_type_image_column_value' ) ) :
		add_action( 'manage_device_type_custom_column', 'wc_rb_display_custom_type_image_column_value' , 10, 3); 
		function wc_rb_display_custom_type_image_column_value( $columns, $column, $id ) {
			if ( 'category_image' == $column ) {
				$image_id = esc_html( get_term_meta( $id, 'image_id', true ) );
				$columns = wp_get_attachment_image ( $image_id, array('50', '50') );
			}
			return $columns;
		}
	endif;

	if ( ! function_exists( 'other_device_link' ) ) :
		add_action( 'admin_head-edit.php','other_device_link' );
		function other_device_link() {
			global $current_screen;
			if ( 'rep_devices' == $current_screen->post_type ) {
				$wc_device_label_plural = ( empty( get_option( 'wc_device_label_plural' ) ) ) ? esc_html__( 'Other', 'computer-repair-shop' ) . ' ' . esc_html__( 'Devices', 'computer-repair-shop' ) : esc_html__( 'Other', 'computer-repair-shop' ) . ' ' . get_option( 'wc_device_label_plural' );
				$other_devices_link 	= 'edit.php?post_type=rep_devices_other';
			?>
				<script type="text/javascript">
					jQuery(function () { jQuery('hr.wp-header-end').before("<a id='doc_popup' href='<?php echo esc_url( $other_devices_link ); ?>' class='add-new-h2'><?php echo esc_html( $wc_device_label_plural ); ?></a>"); });
				</script>
			<?php
			}

			if ( 'rep_devices_other' == $current_screen->post_type ) {
				$wc_device_label_plural = ( empty( get_option( 'wc_device_label_plural' ) ) ) ? esc_html__( 'Devices', 'computer-repair-shop' ) : get_option( 'wc_device_label_plural' );
				$other_devices_link 	= 'edit.php?post_type=rep_devices';
			?>
				<script type="text/javascript">
					jQuery(function () { jQuery('hr.wp-header-end').before("<a id='doc_popup' href='<?php echo esc_url( $other_devices_link ); ?>' class='add-new-h2'><?php echo esc_html( $wc_device_label_plural ); ?></a>"); });
				</script>
			<?php
			}
		}
	endif;

	if ( ! function_exists( 'wcrb_add_other_device_return_id' ) ) :
		function wcrb_add_other_device_return_id( $new_device_name, $brand_id, $type_id ) {
			if ( empty( $new_device_name ) ) {
				return;
			}
			$device_post_id_h = '';

			$tax_query = array();
			if ( ! empty( $brand_id ) && ! empty( $type_id ) ) {
				$tax_query['relation'] = 'AND';
			}
			if ( ! empty( $brand_id ) ) {
				$tax_query[] = array(
					'taxonomy'	=> 'device_brand',
					'terms'		=> $brand_id,
					'field'		=> 'term_id',
				);
			}
			if ( ! empty( $type_id ) ) {
				$tax_query[] = array(
					'taxonomy'	=> 'device_type',
					'terms'		=> $type_id,
					'field'		=> 'term_id',
				);
			}
			$args = array(
				'post_type' => array('rep_devices', 'rep_devices_other'),
				'title'     => $new_device_name,
				'tax_query' => $tax_query,
				'posts_per_page' => '1',
			);
			$the_query = new WP_Query( $args );

			if ( $the_query->have_posts() ) {
				while ( $the_query->have_posts() ) {
					$the_query->the_post();

					$device_post_id_h = $the_query->post->ID;
				}
				wp_reset_postdata();
			} else {
				$device_data = array(
					'post_title' => esc_html( $new_device_name ),
					'post_status' => 'publish',
					'post_type'   => 'rep_devices_other',
					'tax_input'    => array(
											"device_brand" => $brand_id,
											"device_type" => $type_id
											),
				);
				$device_post_id_h = wp_insert_post( $device_data );
			}
			return $device_post_id_h;
		}
	endif;