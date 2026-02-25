<article class="w2dc-listing-location w2dc-listing-has-location-<?php echo $location->id; ?>" id="post-<?php echo $location->id; ?>" data-location-id="<?php echo $location->id; ?>" style="height: auto;">
	<div class="w2dc-listing-location-content">
		<?php
		if ($listing->logo_image) {
			$img_src = $listing->get_logo_url('listing-location-thumbnail');
		} else {
			$img_src = get_option('w2dc_nologo_url');
		}
	
		?>
		<div class="w2dc-map-listing-logo-wrap">
			<figure class="w2dc-map-listing-logo">
				<div class="w2dc-map-listing-logo-img-wrap">
					<div style="background-image: url('<?php echo $img_src; ?>');" class="w2dc-map-listing-logo-img">
						<img src="<?php echo $img_src; ?>" />
					</div>
				</div>
			</figure>
		</div>
		<div class="w2dc-map-listing-content-wrap">
			<header class="w2dc-map-listing-header">
				<h2><?php echo $listing->title(); ?> <?php do_action('w2dc_listing_title_html', $listing, false); ?></h2>
			</header>
			<?php $listing->renderMapSidebarContentFields($location); ?>
		</div>
	</div>
	<?php 
		if ($show_directions_button || $show_readmore_button):
			if (!$show_directions_button || !$show_readmore_button) {
				$buttons_class = 'w2dc-map-info-window-buttons-single';
			} else {
				$buttons_class = 'w2dc-map-info-window-buttons';
			}
	?>
	<div class="<?php echo $buttons_class; ?> w2dc-clearfix">
		<?php if ($show_directions_button): ?>
			<?php if (w2dc_getMapEngine() == 'google'): ?>
			<a href="https://www.google.com/maps/dir/?api=1&destination=<?php echo urlencode($location->latitude.','.$location->longitude); ?>" target="_blank" class="w2dc-btn w2dc-btn-primary"><?php _e('« Directions', 'W2DC'); ?></a>
			<?php elseif (w2dc_getMapEngine() == 'mapbox'): ?>
			<a href="<?php the_permalink($listing->post->ID); ?>#addresses-tab" class="w2dc-btn w2dc-btn-primary w2dc-map-info-window-directions-button"><?php _e('« Directions', 'W2DC'); ?></a>
			<?php endif; ?>
		<?php endif; ?>
		<?php if ($show_readmore_button): ?>
		<a href="javascript:void(0);" data-location-id="<?php echo $location->id; ?>" class="w2dc-btn w2dc-btn-primary w2dc-show-on-map"><?php _e('View on map »', 'W2DC')?></a>
		<?php endif; ?>
	</div>
	<?php endif; ?>
</article>