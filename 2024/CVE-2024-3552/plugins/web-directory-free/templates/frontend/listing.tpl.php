		<?php if ($listing->isLogoOnExcerpt()): ?>
		<div class="w2dc-listing-logo-wrap <?php if ($listing->logo_animation_effect): ?>w2dc-anim-style<?php else: ?>w2dc-no-anim-style<?php endif; ?>">
			<?php do_action('w2dc_listing_pre_logo_wrap_html', $listing); ?>
			<figure class="w2dc-listing-logo <?php if ($listing->level->listings_own_page): ?>w2dc-listings-own-page<?php endif; ?>">
				<?php if (get_option('w2dc_listing_title_mode') == 'inside'): ?>
				<?php w2dc_renderTemplate('frontend/listing_header.tpl.php', array('listing' => $listing, 'frontend_controller' => $frontend_controller)); ?>
				<?php endif; ?>
				
				<?php if ($listing->level->listings_own_page): ?>
				<a href="<?php the_permalink(); ?>" class="w2dc-listing-logo-img-wrap" <?php if ($listing->level->nofollow): ?>rel="nofollow"<?php endif; ?>>
				<?php else: ?>
				<div class="w2dc-listing-logo-img-wrap">
				<?php endif; ?>
				<?php if ($listing->logo_image): ?>
					<?php $img_src = $listing->get_logo_url('listing-thumbnail'); ?>
				<?php else: ?>
					<?php $img_src = get_option('w2dc_nologo_url'); ?>
				<?php endif; ?>
					<div class="w2dc-listing-logo-img" style="background-image: url('<?php echo $img_src; ?>');">
						<img src="<?php echo $img_src; ?>" alt="<?php echo esc_attr($listing->title()); ?>" title="<?php echo esc_attr($listing->title()); ?>" />
					</div>
				<?php if ($listing->level->listings_own_page): ?>
				</a>
				<?php else: ?>
				</div>
				<?php endif; ?>
				
				<?php if ($listing->level->featured): ?>
				<div class="w2dc-featured-label"><?php echo w2dc_get_wpml_dependent_option('w2dc_featured_label'); ?></div>
				<?php endif; ?>
				
				<?php if ($listing->level->listings_own_page): ?>
				<figcaption class="w2dc-figcaption">
					<div class="w2dc-figcaption-middle">
						<ul class="w2dc-figcaption-options">
							<li class="w2dc-listing-figcaption-option">
								<a href="<?php the_permalink(); ?>" <?php if ($listing->level->nofollow): ?>rel="nofollow"<?php endif; ?>>
									<span class="w2dc-glyphicon w2dc-glyphicon-play" title="<?php esc_attr_e('more info >>', 'W2DC'); ?>"></span>
								</a>
							</li>
							<?php if (get_option('w2dc_map_on_single') && $listing->isMap()): ?>
							<li class="w2dc-listing-figcaption-option" style="display: none;">
								<a href="javascript:void(0);" class="w2dc-show-on-map" data-location-id="<?php echo $listing->locations[0]->id; ?>" data-scroll-to-map="1">
									<span class="w2dc-glyphicon w2dc-glyphicon-map-marker" title="<?php esc_attr_e('view on map', 'W2DC'); ?>"></span>
								</a>
							</li>
							<?php endif; ?>
							<?php if (w2dc_comments_open() && !get_option('w2dc_hide_comments_number_on_index')): ?>
							<li class="w2dc-listing-figcaption-option">
								<a href="<?php the_permalink(); ?>#comments-tab" <?php if ($listing->level->nofollow): ?>rel="nofollow"<?php endif; ?>>
									<span class="w2dc-glyphicon w2dc-glyphicon-comment" title="<?php echo w2dc_comments_reply_label($listing); ?>"></span>
								</a>
							</li>
							<?php endif; ?>
							<?php if ($listing->level->images_number && count($listing->images) > 1): ?>
							<li class="w2dc-listing-figcaption-option">
								<a href="<?php the_permalink(); ?>#images" <?php if ($listing->level->nofollow): ?>rel="nofollow"<?php endif; ?>>
									<span class="w2dc-glyphicon w2dc-glyphicon-picture" title="<?php echo sprintf(_n('%d image', '%d images', count($listing->images), 'W2DC'), count($listing->images)); ?>"></span>
								</a>
							</li>
							<?php endif; ?>
							<?php if ($listing->level->videos_number && $listing->videos): ?>
							<li class="w2dc-listing-figcaption-option">
								<a href="<?php the_permalink(); ?>#videos-tab" <?php if ($listing->level->nofollow): ?>rel="nofollow"<?php endif; ?>>
									<span class="w2dc-glyphicon w2dc-glyphicon-facetime-video" title="<?php echo sprintf(_n('%d video', '%d videos', count($listing->videos), 'W2DC'), count($listing->videos)); ?>"></span>
								</a>
							</li>
							<?php endif; ?>
							<?php if (get_option('w2dc_listing_contact_form') && (!$listing->is_claimable || !get_option('w2dc_hide_claim_contact_form')) && ($listing_owner = get_userdata($listing->post->post_author)) && $listing_owner->user_email): ?>
							<li class="w2dc-listing-figcaption-option">
								<a href="<?php the_permalink(); ?>#contact-tab" <?php if ($listing->level->nofollow): ?>rel="nofollow"<?php endif; ?>>
									<span class="w2dc-glyphicon w2dc-glyphicon-user" title="<?php esc_attr_e('contact us', 'W2DC'); ?>"></span>
								</a>
							</li>
							<?php endif; ?>
						</ul>
						<?php if (!empty($frontend_controller->args['summary_on_logo_hover'])): ?>
						<div class="w2dc-figcaption-summary">
							<?php $listing->renderSummary(); ?>
						</div>
						<?php endif; ?>
					</div>
				</figcaption>
				<?php endif; ?>
			</figure>
		</div>
		<?php endif; ?>

		<?php if ($listing->level->sticky && ($w2dc_instance->order_by_date || get_option('w2dc_orderby_sticky_featured'))): ?>
		<div class="w2dc-sticky-ribbon"><span><?php echo apply_filters('w2dc_sticky_label_filter', w2dc_get_wpml_dependent_option('w2dc_sticky_label'), $listing); ?></span></div>
		<?php endif; ?>

		<?php if ($w2dc_instance->getShortcodeProperty(W2DC_MAIN_SHORTCODE, 'is_favourites') && w2dc_checkQuickList($listing->post->ID)): ?>
		<div class="w2dc-remove-from-favourites-list w2dc-fa w2dc-fa-close" listingid="<?php the_ID(); ?>" title="<?php echo esc_attr(__('Remove from favourites list', 'W2DC')); ?>"></div>
		<?php endif; ?>

		<div class="<?php if ($listing->isLogoOnExcerpt()): ?>w2dc-listing-text-content-wrap<?php else: ?>w2dc-listing-text-content-wrap-nologo<?php endif; ?>">
		<?php if ($listing->isLogoOnExcerpt()): ?>
			<?php if (get_option('w2dc_listing_title_mode') == 'outside'): ?>
			<?php w2dc_renderTemplate('frontend/listing_header.tpl.php', array('listing' => $listing, 'frontend_controller' => $frontend_controller)); ?>
			<?php endif; ?>
		<?php else: ?>
			<?php if ($listing->level->featured): ?>
			<div class="w2dc-featured-label"><?php echo apply_filters('w2dc_featured_label_filter', w2dc_get_wpml_dependent_option('w2dc_featured_label'), $listing); ?></div>
			<?php endif; ?>
			<?php w2dc_renderTemplate('frontend/listing_header.tpl.php', array('listing' => $listing, 'frontend_controller' => $frontend_controller)); ?>
		<?php endif; ?>
			
			<?php do_action('w2dc_listing_pre_content_html', $listing); ?>

			<?php if (empty($frontend_controller->args['hide_content'])) $listing->renderContentFields(false); ?>

			<?php do_action('w2dc_listing_post_content_html', $listing); ?>
		</div>