<div class="w2dc-map-info-window">
	<div class="w2dc-map-info-window-inner">
		<div class="w2dc-map-info-window-inner-item">
			<div class="w2dc-map-info-window-title">
				<?php if ($listing->level->listings_own_page && $show_readmore_button): ?>
				<a class="w2dc-map-info-window-title-link" href="<?php echo get_permalink($listing->post->ID); ?>" <?php if ($listing->level->nofollow): ?>rel="nofollow"<?php endif; ?>>
					<?php echo $listing->title(); ?>
				</a>
				<?php else: ?>
				<?php echo $listing->title(); ?>
				<?php endif; ?>
				<span class="w2dc-close-info-window w2dc-fa w2dc-fa-close" onclick="w2dc_closeInfoWindow(&quot;<?php echo esc_attr($map_id); ?>&quot;);"></span>
			</div>
			<?php if ($logo_image): ?>
			<div class="w2dc-map-info-window-logo" style="width: <?php echo get_option('w2dc_map_infowindow_logo_width')+10; ?>px; min-height: <?php echo get_option('w2dc_map_infowindow_logo_width'); ?>px">
				<?php if ($listing->level->listings_own_page): ?>
				<a href="<?php echo get_permalink($listing->post->ID); ?>">
					<img src="<?php echo esc_attr($logo_image); ?>" width="<?php echo get_option('w2dc_map_infowindow_logo_width'); ?>px">
				</a>
				<?php else: ?>
				<img src="<?php echo esc_attr($logo_image); ?>" width="<?php echo get_option('w2dc_map_infowindow_logo_width'); ?>px">
				<?php endif; ?>
			</div>
			<?php endif; ?>
			<?php if ($content_fields_output): ?>
			<div class="w2dc-map-info-window-content w2dc-clearfix">
				<?php foreach ($content_fields_output AS $field_slug=>$field_content): ?>
				<?php if ($field_content): ?>
				<div class="w2dc-map-info-window-field">
					<?php if (!empty($map_content_fields_icons[$field_slug])): ?>
					<span class="w2dc-map-field-icon w2dc-fa <?php echo esc_attr($map_content_fields_icons[$field_slug]); ?>"></span>
					<?php endif; ?>
					<?php echo $field_content; ?>
				</div>
				<?php endif; ?>
				<?php endforeach; ?>
			</div>
			<?php endif; ?>
			<?php if ($show_summary_button || ($listing->level->listings_own_page && $show_readmore_button)): ?>
			<?php
			if (!$show_summary_button || !($listing->level->listings_own_page && $show_readmore_button)) {
				$button_class = 'w2dc-map-info-window-buttons-single';
			} else {
				$button_class = 'w2dc-map-info-window-buttons';
			}
			?>
			<div class="<?php echo $button_class; ?> w2dc-clearfix">
				<?php if ($show_summary_button): ?>
				<a href="javascript:void(0);" class="w2dc-btn w2dc-btn-primary w2dc-scroll-to-listing w2dc-info-window-summary-button" onClick="w2dc_scrollToListing(&quot;post-<?php echo esc_attr($listing->post->ID); ?>&quot;, &quot;<?php echo esc_attr($map_id); ?>&quot;);" data-listing-id="<?php echo esc_attr($listing->post->ID); ?>"><?php esc_html_e('« Summary', 'W2DC'); ?></a>
				<?php endif; ?>
				<?php if ($listing->level->listings_own_page && $show_readmore_button): ?>
				<a href="<?php echo apply_filters("w2dc_info_window_readmore_button", get_permalink($listing->post->ID)); ?>" class="w2dc-btn w2dc-btn-primary w2dc-scroll-to-listing w2dc-info-window-readmore-button"><?php esc_html_e('Read more »', 'W2DC'); ?></a>
				<?php endif; ?>
			</div>
			<?php else: ?>
			<div class="w2dc-clearfix"></div>
			<?php endif; ?>
		</div>
	</div>
	
	<?php if (w2dc_getMapEngine() == 'google'): ?>
	<?php $tongue_pos = round(get_option('w2dc_map_infowindow_width')/2); ?>
	<div style="position: absolute; left: <?php echo $tongue_pos-10; ?>px;"><div style="position: absolute; overflow: hidden; left: -6px; top: -1px; width: 16px; height: 30px;"><div class="w2dc-map-info-window-tongue" style="position: absolute; left: 6px; transform: skewX(22.6deg); transform-origin: 0px 0px 0px;  -webkit-transform: skewX(22.6deg); -webkit-transform-origin: 0px 0px 0px; height: 24px; width: 10px; box-shadow: 0px 1px 6px rgba(0, 0, 0, 0.6);"></div></div><div style="position: absolute; overflow: hidden; top: -1px; left: 10px; width: 16px; height: 30px;"><div class="w2dc-map-info-window-tongue" style="position: absolute; left: 0px; transform: skewX(-22.6deg); transform-origin: 10px 0px 0px; -webkit-transform: skewX(-22.6deg); -webkit-transform-origin: 10px 0px 0px; height: 24px; width: 10px; box-shadow: 0px 1px 6px rgba(0, 0, 0, 0.6);"></div></div></div>
	<?php endif; ?>
</div>