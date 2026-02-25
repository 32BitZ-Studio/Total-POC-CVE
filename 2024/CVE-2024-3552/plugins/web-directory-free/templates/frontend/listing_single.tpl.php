		<div class="w2dc-content w2dc-listing-single">
			<?php w2dc_renderMessages(); ?>

			<?php if ($frontend_controller->listings): ?>
			<?php while ($frontend_controller->query->have_posts()): ?>
				<?php $frontend_controller->query->the_post(); ?>
				<?php $listing = $frontend_controller->listings[get_the_ID()]; ?>

				<div id="<?php echo $listing->post->post_name; ?>" itemscope itemtype="http://schema.org/LocalBusiness">
					<meta itemprop="priceRange" content="$$$" />
					<?php $hide_button_text = apply_filters('w2dc_hide_button_text_on_listing', true)?>
					<?php $frontpanel_buttons = new w2dc_frontpanel_buttons(array('hide_button_text' => $hide_button_text)); ?>
					<?php $frontpanel_buttons->display(); ?>
				
					<?php w2dc_renderTemplate("frontend/single_parts/header.tpl.php", array('listing' => $listing, 'title' => $frontend_controller->getPageTitle())); ?>
					
					<?php echo $frontend_controller->printBreadCrumbs(); ?>

					<article id="post-<?php the_ID(); ?>" class="w2dc-listing">
						
						<?php if ($listing->logo_image && (!get_option('w2dc_exclude_logo_from_listing') || count($listing->images) > 1)): ?>
						<div class="w2dc-listing-logo-wrap w2dc-single-listing-logo-wrap" id="images">
							<?php do_action('w2dc_listing_pre_logo_wrap_html', $listing); ?>
							<meta itemprop="image" content="<?php echo $listing->get_logo_url(); ?>" />
							
							<?php $listing->renderImagesGallery(); ?>
						</div>
						<?php endif; ?>

						<div class="w2dc-single-listing-text-content-wrap">
							<?php if (get_option('w2dc_share_buttons') && get_option('w2dc_share_buttons_place') == 'before_content'): ?>
							<?php w2dc_renderTemplate('frontend/single_parts/sharing_buttons_ajax_call.tpl.php', array('post_id' => $listing->post->ID, 'post_url' => get_permalink($listing->post->ID))); ?>
							<?php endif; ?>
						
							<?php do_action('w2dc_listing_pre_content_html', $listing); ?>
					
							<?php $listing->renderContentFields(true); ?>

							<?php do_action('w2dc_listing_post_content_html', $listing); ?>
							
							<?php if (get_option('w2dc_share_buttons') && get_option('w2dc_share_buttons_place') == 'after_content'): ?>
							<?php w2dc_renderTemplate('frontend/single_parts/sharing_buttons_ajax_call.tpl.php', array('post_id' => $listing->post->ID, 'post_url' => get_permalink($listing->post->ID))); ?>
							<?php endif; ?>
						</div>

						<?php if (
							($fields_groups = $listing->getFieldsGroupsOnTabs())
							|| (get_option('w2dc_map_on_single') && $listing->isMap())
							|| (w2dc_comments_open())
							|| ($listing->level->videos_number && $listing->videos)
							|| ($listing->isContactForm())
							|| (get_option('w2dc_report_form'))
							): ?>
						<ul class="w2dc-listing-tabs w2dc-nav w2dc-nav-tabs w2dc-clearfix" role="tablist">
							<?php if (get_option('w2dc_map_on_single') && $listing->isMap()): ?>
							<li><a href="javascript: void(0);" data-tab="#addresses-tab" data-toggle="w2dc-tab" role="tab"><?php _e('Map', 'W2DC'); ?></a></li>
							<?php endif; ?>
							<?php if (w2dc_comments_open()): ?>
							<li><a href="javascript: void(0);" data-tab="#comments-tab" data-toggle="w2dc-tab" role="tab"><?php echo w2dc_comments_label($listing); ?></a></li>
							<?php endif; ?>
							<?php if ($listing->level->videos_number && $listing->videos): ?>
							<li><a href="javascript: void(0);" data-tab="#videos-tab" data-toggle="w2dc-tab" role="tab"><?php echo _n('Video', 'Videos', count($listing->videos), 'W2DC'); ?> (<?php echo count($listing->videos); ?>)</a></li>
							<?php endif; ?>
							<?php if ($listing->isContactForm()): ?>
							<li><a href="javascript: void(0);" data-tab="#contact-tab" data-toggle="w2dc-tab" role="tab"><?php _e('Contact', 'W2DC'); ?></a></li>
							<?php endif; ?>
							<?php if (get_option('w2dc_report_form')): ?>
							<li><a href="javascript: void(0);" data-tab="#report-tab" data-toggle="w2dc-tab" role="tab"><?php _e('Report', 'W2DC'); ?></a></li>
							<?php endif; ?>
							<?php
							foreach ($fields_groups AS $fields_group): ?>
							<li><a href="javascript: void(0);" data-tab="#field-group-tab-<?php echo $fields_group->id; ?>" data-toggle="w2dc-tab" role="tab"><?php echo $fields_group->name; ?></a></li>
							<?php endforeach; ?>
							<?php do_action('w2dc_listing_single_tabs', $listing); ?>
						</ul>

						<div class="w2dc-tab-content">
							<?php if (get_option('w2dc_map_on_single') && $listing->isMap()): ?>
							<div id="addresses-tab" class="w2dc-tab-pane w2dc-fade" role="tabpanel">
								<?php do_action('w2dc_pre_addresses_tab'); ?>
								<?php $listing->renderMap($frontend_controller->hash, get_option('w2dc_show_directions'), false, get_option('w2dc_enable_radius_search_circle'), get_option('w2dc_enable_clusters'), false, false); ?>
							</div>
							<?php endif; ?>

							<?php if (w2dc_comments_open()): ?>
							<div id="comments-tab" class="w2dc-tab-pane w2dc-fade" role="tabpanel">
								<?php do_action('w2dc_pre_comments_tab'); ?>
								<?php w2dc_comments_system($listing); ?>
							</div>
							<?php endif; ?>

							<?php if ($listing->level->videos_number && $listing->videos): ?>
							<div id="videos-tab" class="w2dc-tab-pane w2dc-fade" role="tabpanel">
								<?php do_action('w2dc_pre_videos_tab'); ?>
								<?php w2dc_renderTemplate("frontend/single_parts/videos.tpl.php", array('listing' => $listing)); ?>
							</div>
							<?php endif; ?>

							<?php if ($listing->isContactForm()): ?>
							<div id="contact-tab" class="w2dc-tab-pane w2dc-fade" role="tabpanel">
								<?php do_action('w2dc_pre_contact_tab'); ?>
							<?php if (!get_option('w2dc_hide_anonymous_contact_form') || is_user_logged_in()): ?>
								<?php if (defined('WPCF7_VERSION') && w2dc_get_wpml_dependent_option('w2dc_listing_contact_form_7')): ?>
									<?php echo do_shortcode(w2dc_get_wpml_dependent_option('w2dc_listing_contact_form_7')); ?>
								<?php else: ?>
									<?php w2dc_renderTemplate('frontend/single_parts/contact_form.tpl.php', array('listing' => $listing)); ?>
								<?php endif; ?>
							<?php else: ?>
								<?php printf(__('You must be <a href="%s">logged in</a> to submit contact form', 'W2DC'), wp_login_url(get_permalink($listing->post->ID))); ?>
							<?php endif; ?>
							</div>
							<?php endif; ?>
							
							<?php if (get_option('w2dc_report_form')): ?>
							<div id="report-tab" class="w2dc-tab-pane w2dc-fade" role="tabpanel">
								<?php do_action('w2dc_pre_report_tab'); ?>
								<?php w2dc_renderTemplate('frontend/single_parts/report_form.tpl.php', array('listing' => $listing)); ?>
							</div>
							<?php endif; ?>
							
							<?php foreach ($fields_groups AS $fields_group): ?>
							<div id="field-group-tab-<?php echo $fields_group->id; ?>" class="w2dc-tab-pane w2dc-fade" role="tabpanel">
								<?php do_action('w2dc_pre_field-group_tab', $fields_group); ?>
								<?php echo $fields_group->renderOutput($listing, true); ?>
							</div>
							<?php endforeach; ?>
							
							<?php do_action('w2dc_listing_single_tabs_content', $listing); ?>
						</div>
						<?php endif; ?>
					</article>
				</div>
			<?php endwhile; endif; ?>
		</div>