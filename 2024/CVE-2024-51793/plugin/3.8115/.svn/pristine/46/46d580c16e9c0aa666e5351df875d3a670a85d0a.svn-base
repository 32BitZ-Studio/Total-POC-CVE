<?php
/**
  * Template for Single service page
  */

defined( 'ABSPATH' ) || exit;

get_header( 'header' ); 

$object_id = get_queried_object_id();

$allowedHTML = wc_return_allowed_tags(); 
?>

<?php if ( have_posts() ) : while( have_posts() ) : the_post(); ?>
<div class="grid-container conatiner wcrb_module">
  <div class="grid-x grid-margin-x">
    
    <div class="cell small-12 medium-8">
      <h2><?php the_title(); ?></h2>
      <?php the_content(); ?>
    </div>


    <div class="cell small-12 medium-4">
      <div class="wcrb_widget_wrap">
        <div class="wcrb_widget_title">
          <h2><?php echo esc_html__( 'Service Price', 'computer-repair-shop' ); ?></h2>
        </div>

        <div class="wcrb_widget_content">
        <?php
          $output = '';
          $price_range = $WCRB_DEVICE_SERVICES->return_price_range_of_service( $object_id );

          $default_description = esc_html__( 'Below you can check price by type or brand and to get accurate value check devices.', 'computer-repair-shop' );
          $wc_service_sidebar_description  = ( empty( get_option( 'wc_service_sidebar_description' ) ) ) ? $default_description : get_option( 'wc_service_sidebar_description' );

          $output .= '<p>' . wp_kses_post( $wc_service_sidebar_description ) . '</p>';
          $output .= ( ! empty( $price_range ) ) ? '<div class="priceRangeWCRB">' . $price_range . '</div>' : 'Are you also';
          
          $output .= '<ul class="accordion" data-accordion data-allow-all-closed="true">';
          $output .= $WCRB_DEVICE_SERVICES->return_device_type_accordion_price_front( $post->ID );
          $output .= $WCRB_DEVICE_SERVICES->return_device_brand_accordion_price_front( $post->ID );
          $output .= $WCRB_DEVICE_SERVICES->return_device_accordion_price_front( $post->ID );
          $output .= '</ul>';

          echo wp_kses( $output, $allowedHTML );
        ?>
        </div><!-- widget content /-->
      </div><!-- widget wrap /-->
    
    </div>
  </div><!-- Grid-x Row /-->

  <?php 
      /*if ( isset( $_GET['device_id'] ) && ! empty( $_GET['device_id'] ) ) {
        $theDeviceId = sanitize_text_field( $_GET['device_id'] );
        $brand_id    = wcrb_return_device_terms( $theDeviceId, 'device_brand' );

        $hidden_field = '<input type="text" id="wcrb_thebrand_id" value="' . $brand_id . '" />';
        echo wp_kses( $hidden_field, $allowedHTML );
      }*/

      $booking_status = get_option( 'wc_booking_on_service_page_status' );
      $booking_head   = get_option( 'wc_service_booking_heading' );
        
      if ( $booking_status != 'on' ) :
  ?>
  <div class="grid-x grid-margin-x">
    <div class="cell small-12 booking-on-service-page">
      <?php 
        $head_booking = ( ! empty( $booking_head ) ) ? '<h2 class="wc_service_booking_heading">' . $booking_head . ' ' . get_the_title( $object_id ) . '</h2>' : '';
        
        $output = $head_booking;

        $wc_service_booking_form = get_option( 'wc_service_booking_form' );
        
        if( $wc_service_booking_form == 'with_type' ) {
          $output .= WCRB_TYPE_GROUPED_SERVICE();
        } elseif ( $wc_service_booking_form == 'warranty_booking' ) {
          $output .= wc_book_my_warranty();
        } else {
          $output .= wc_book_my_service();
        }
       
        echo wp_kses( $output, $allowedHTML );
      ?>
    </div>
  </div><!-- Booking Row /-->
  <?php endif; ?>

</div>
<?php endwhile; else:  
  echo esc_html__( 'Nothing related found', 'computer-repair-shop' );
endif; ?>

<?php
  get_footer();