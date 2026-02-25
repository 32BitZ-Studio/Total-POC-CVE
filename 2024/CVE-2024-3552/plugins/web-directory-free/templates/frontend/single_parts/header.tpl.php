<?php if ($listing->title()): ?>
<header class="w2dc-content w2dc-listing-header">
	<?php do_action('w2dc_listing_pre_title_html', $listing, true); ?>
	<?php if (!get_option('w2dc_hide_listing_title')): ?>
	<h2 class="w2dc-listing-single-title" itemprop="name"><?php echo $title; ?></h2>
	<?php endif; ?>
	<?php do_action('w2dc_listing_title_html', $listing, true); ?>
	<?php if (!get_option('w2dc_hide_views_counter')): ?>
	<div class="w2dc-meta-data">
		<div class="w2dc-views-counter">
			<span class="w2dc-glyphicon w2dc-glyphicon-eye-open"></span> <?php _e('views', 'W2DC')?>: <?php echo get_post_meta($listing->post->ID, '_total_clicks', true); ?>
		</div>
	</div>
	<?php endif; ?>
	<?php if (!get_option('w2dc_hide_listings_creation_date')): ?>
	<div class="w2dc-meta-data">
		<div class="w2dc-listing-date" datetime="<?php echo date("Y-m-d", mysql2date('U', $listing->post->post_date)); ?>T<?php echo date("H:i", mysql2date('U', $listing->post->post_date)); ?>"><?php echo get_the_date(); ?> <?php echo get_the_time(); ?></div>
	</div>
	<?php endif; ?>
	<?php if (!get_option('w2dc_hide_author_link')): ?>
	<div class="w2dc-meta-data">
		<div class="w2dc-author-link">
			<?php _e('By', 'W2DC'); ?> <?php echo get_the_author_link(); ?>
		</div>
	</div>
	<?php endif; ?>
	<?php if (get_option('w2dc_share_buttons') && get_option('w2dc_share_buttons_place') == 'title'): ?>
	<?php w2dc_renderTemplate('frontend/single_parts/sharing_buttons_ajax_call.tpl.php', array('post_id' => $listing->post->ID, 'post_url' => get_permalink($listing->post->ID))); ?>
	<?php endif; ?>
</header>
<?php endif; ?>