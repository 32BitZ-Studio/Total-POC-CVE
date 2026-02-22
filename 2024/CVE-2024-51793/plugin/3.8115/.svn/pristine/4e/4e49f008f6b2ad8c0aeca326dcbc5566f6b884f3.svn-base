<?php
/**
  * Template for Single service page
  */

defined( 'ABSPATH' ) || exit;

get_header( 'header' ); 

$object_id = get_queried_object_id();

$allowedHTML = wc_return_allowed_tags();
?>

<div class="grid-container conatiner wcrb_module wcrb_device_wrap">
<?php if ( have_posts() ) : while( have_posts() ) : the_post(); ?>
  <div class="grid-x grid-margin-x">
    
    <div class="cell small-12 medium-8">
      <h2><?php the_title(); ?></h2>
      <?php 
        $brand_terms = get_the_terms( get_the_ID(), 'device_brand' );
        $brand_terms = join(', ', wp_list_pluck( $brand_terms , 'name') );

        echo ( ! empty( $brand_terms ) ) ? '<div class="wcrb_brand_title">' . wp_kses( $brand_terms, $allowedHTML ) . '</div>' : '';
      ?>
      <?php the_content(); ?>
    </div>


    <div class="cell small-12 medium-4">
      <div class="wcrb_widget_wrap">
        <div class="wcrb_widget_content text-center">
          <?php the_post_thumbnail( get_the_ID(), 'thumbnail' ); ?>
        </div><!-- widget content /-->
      </div><!-- widget wrap /-->
    
    </div>
  </div><!-- Grid-x Row /-->
<?php endwhile; else:  
  echo esc_html__( 'Nothing related found', 'computer-repair-shop' );
endif; ?>


<?php 
        $booking_status = get_option( 'wc_booking_on_service_page_status' );
        $booking_head   = get_option( 'wc_service_booking_heading' );
        
        if ( $booking_status != 'on' ) :
  ?>
  <div class="grid-x grid-margin-x spacer-sixtypx">
    <div class="cell small-12 booking-on-service-page">
      <?php 
        $head_booking = ( ! empty( $booking_head ) ) ? '<h2 class="wc_service_booking_heading">' . $booking_head . ' ' . get_the_title( $object_id ) . '</h2>' : '';
        
        $output = $head_booking;
        $output .= $WCRB_DEVICE_SERVICES->return_service_html_by_device( $object_id );
        
        echo wp_kses( $output, $allowedHTML );
      ?>
    </div>
  </div><!-- Booking Row /-->
  <?php endif; ?>

</div><!-- Grid Container. /-->

<?php
  get_footer();