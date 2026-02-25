		<?php if (empty($frontend_controller->custom_home) || (($frontend_controller->custom_home && get_option('w2dc_listings_on_index')) || !$frontend_controller->is_home)): ?>
		<div class="w2dc-content w2dc-controller" id="w2dc-controller-<?php echo $frontend_controller->hash; ?>" data-controller-hash="<?php echo $frontend_controller->hash; ?>" <?php if (!empty($frontend_controller->custom_home)): ?>data-custom-home="1"<?php endif; ?>>
			<style type="text/css">
				<?php if (!empty($frontend_controller->args['grid_view_logo_ratio'])): ?>
				#w2dc-controller-<?php echo $frontend_controller->hash; ?> .w2dc-listings-grid figure.w2dc-listing-logo .w2dc-listing-logo-img-wrap:before {
					padding-top: <?php echo $frontend_controller->args['grid_view_logo_ratio']; ?>%;
				}
				<?php endif; ?>
				<?php if ($frontend_controller->args['listing_thumb_width']): ?>
				#w2dc-controller-<?php echo $frontend_controller->hash; ?> .w2dc-listings-block figure.w2dc-listing-logo .w2dc-listing-logo-img img {
					width: <?php echo $frontend_controller->args['listing_thumb_width']; ?>px;
				}
				@media screen and (min-width: 769px) {
					<?php if (!is_rtl()): ?>
					#w2dc-controller-<?php echo $frontend_controller->hash; ?> .w2dc-listings-block .w2dc-listing-logo-wrap {
						width: <?php echo $frontend_controller->args['listing_thumb_width']; ?>px;
						<?php if ($frontend_controller->args['wrap_logo_list_view']): ?>
						margin-right: 20px;
						margin-bottom: 10px;
						<?php endif; ?>
					}
					<?php else: ?>
					#w2dc-controller-<?php echo $frontend_controller->hash; ?> .w2dc-listings-block .w2dc-listing-logo-wrap {
						margin-left: 20px;
						margin-right: 0;
					}
					<?php endif; ?>
					<?php if (!is_rtl()): ?>
					#w2dc-controller-<?php echo $frontend_controller->hash; ?> .w2dc-listings-block .w2dc-listing-text-content-wrap {
						<?php if (!$frontend_controller->args['wrap_logo_list_view']): ?>
						margin-left: <?php echo $frontend_controller->args['listing_thumb_width']; ?>px;
						margin-right: 0;
						<?php else: ?>
						margin-left: 0;
						<?php endif; ?>
					}
					<?php else: ?>
					#w2dc-controller-<?php echo $frontend_controller->hash; ?> .w2dc-listings-block .w2dc-listing-text-content-wrap {
						<?php if (!$frontend_controller->args['wrap_logo_list_view']): ?>
						margin-right: <?php echo $frontend_controller->args['listing_thumb_width']; ?>px;
						margin-left: 0;
						<?php else: ?>
						margin-right: 0;
						<?php endif; ?>
					}
					<?php endif; ?>
				}
				<?php endif; ?>
			</style>
			<script>
			w2dc_controller_args_array['<?php echo $frontend_controller->hash; ?>'] = <?php echo json_encode(array_merge(array('base_url' => $frontend_controller->base_url, 'page_url' => $frontend_controller->page_url), $frontend_controller->args)); ?>;
			</script>
			<?php if ($frontend_controller->do_initial_load): ?>
			<div class="<?php echo $frontend_controller->getListingsBlockClasses();  ?>">
				<div class="w2dc-row w2dc-visible-search-params">
					<?php $frontend_controller->printVisibleSearchParams(); ?>
				</div>
				<?php if (!empty($frontend_controller->query->found_posts)): ?>
				<?php if (!$frontend_controller->args['hide_count'] || (!$frontend_controller->args['hide_order'] && !w2dc_is_relevanssi_search()) || $frontend_controller->args['show_views_switcher']): ?>
				<div class="w2dc-row w2dc-listings-block-header">
					<?php if (!$frontend_controller->args['hide_count']): ?>
					<div class="w2dc-found-listings">
						<?php printf(__('Found', "W2DC") . ' <span class="w2dc-badge">%d</span> %s', $frontend_controller->query->found_posts, _n($frontend_controller->getListingsDirectory()->single, $frontend_controller->getListingsDirectory()->plural, $frontend_controller->query->found_posts)); ?>
					</div>
					<?php endif; ?>
		
					<div class="w2dc-listings-options-links">
						<?php if (!$frontend_controller->args['hide_order'] && !w2dc_is_relevanssi_search()): // adapted for Relevanssi ?>
						<?php $ordering = w2dc_orderLinks($frontend_controller->base_url, $frontend_controller->args, true, $frontend_controller->hash); ?>
						<?php if ($ordering && ($links = $ordering->getLinks('order_by', 'order'))): ?>
						<div class="w2dc-listings-orderby">
							<div class="w2dc-listings-orderby-dropbtn w2dc-btn w2dc-btn-primary"><?php _e('Sort by:', 'W2DC'); ?> <?php echo $ordering->active_link_name; ?></div>
							<div class="w2dc-listings-orderby-links-group" role="group">
								<?php foreach ($links AS $link): ?>
								<?php if ($link['field_slug'] != $ordering->active_link || $link['order'] != $ordering->active_link_order): ?>
								<a class="w2dc-listings-orderby-link w2dc-btn" href="<?php echo $link['url']; ?>" data-controller-hash="<?php echo $frontend_controller->hash; ?>" data-orderby="<?php echo $link['field_slug']; ?>" data-order="<?php echo $link['order']; ?>" rel="nofollow">
									<?php echo $link['field_name']; ?>
								</a>
								<?php endif; ?>
								<?php endforeach; ?>
							</div>
						</div>
						<?php endif; ?>
						<?php endif; ?>
						
						<?php if ($frontend_controller->args['show_views_switcher']): ?>
						<div class="w2dc-views-links w2dc-pull-right">
							<div class="w2dc-btn-group" role="group">
								<a class="w2dc-btn <?php if (($frontend_controller->args['listings_view_type'] == 'list' && !isset($_COOKIE['w2dc_listings_view_'.$frontend_controller->hash])) || (isset($_COOKIE['w2dc_listings_view_'.$frontend_controller->hash]) && $_COOKIE['w2dc_listings_view_'.$frontend_controller->hash] == 'list')): ?>w2dc-btn-primary<?php else: ?>w2dc-btn-default<?php endif; ?> w2dc-list-view-btn" href="javascript: void(0);" title="<?php _e('List View', 'W2DC'); ?>" data-shortcode-hash="<?php echo $frontend_controller->hash; ?>">
									<span class="w2dc-glyphicon w2dc-glyphicon-list" aria-hidden="true"></span>
								</a>
								<a class="w2dc-btn <?php if (($frontend_controller->args['listings_view_type'] == 'grid' && !isset($_COOKIE['w2dc_listings_view_'.$frontend_controller->hash])) || (isset($_COOKIE['w2dc_listings_view_'.$frontend_controller->hash]) && $_COOKIE['w2dc_listings_view_'.$frontend_controller->hash] == 'grid')): ?>w2dc-btn-primary<?php else: ?>w2dc-btn-default<?php endif; ?> w2dc-grid-view-btn" href="javascript: void(0);" title="<?php _e('Grid View', 'W2DC'); ?>" data-shortcode-hash="<?php echo $frontend_controller->hash; ?>" data-grid-columns="<?php echo $frontend_controller->args['listings_view_grid_columns']; ?>">
									<span class="w2dc-glyphicon w2dc-glyphicon-th-large" aria-hidden="true"></span>
								</a>
							</div>
						</div>
						<?php endif; ?>
					</div>
				</div>
				<?php endif; ?>
				<?php else: ?>
				<div class="w2dc-row w2dc-no-found-listings"><?php echo apply_filters("w2dc_no_listings_text", __("Sorry, no listings were found.", "W2DC")); ?></div>
				<?php endif; ?>

				<?php if ($frontend_controller->listings): ?>
				<div class="w2dc-listings-block-content">
					<?php do_action("w2dc_listings_block_content_start", $frontend_controller); ?>
					<?php while ($frontend_controller->query->have_posts()): ?>
					<?php $frontend_controller->query->the_post(); ?>
					<article id="post-<?php the_ID(); ?>" class="w2dc-row w2dc-listing <?php echo $frontend_controller->getListingClasses(); ?>">
						<?php $frontend_controller->listings[get_the_ID()]->display($frontend_controller); ?>
						<?php do_action("w2dc_listings_block_listing", $frontend_controller); ?>
					</article>
					<?php endwhile; ?>
					<?php do_action("w2dc_listings_block_content_end", $frontend_controller); ?>
				</div>

					<?php if (!$frontend_controller->args['hide_paginator']): ?>
					<?php w2dc_renderPaginator($frontend_controller->query, $frontend_controller->hash, get_option('w2dc_show_more_button'), $frontend_controller); ?>
					<?php endif; ?>
				<?php endif; ?>
			</div>
			<?php endif; ?>
		</div>
		<?php endif; ?>