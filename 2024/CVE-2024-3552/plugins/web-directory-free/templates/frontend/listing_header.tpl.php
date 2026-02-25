				<header class="w2dc-listing-header">
					<?php if (!$listing->level->listings_own_page): ?>
					<h2><?php echo $listing->title(); ?></h2><?php if (!isset($frontend_controller->args['rating_stars']) || $frontend_controller->args['rating_stars']) do_action('w2dc_listing_title_html', $listing, false); ?>
					<?php else: ?>
					<h2><a href="<?php the_permalink(); ?>" title="<?php echo esc_attr($listing->title()); ?>" <?php if ($listing->level->nofollow): ?>rel="nofollow"<?php endif; ?>><?php echo $listing->title(); ?></a> <?php if (!isset($frontend_controller->args['rating_stars']) || $frontend_controller->args['rating_stars']) do_action('w2dc_listing_title_html', $listing, false); ?></h2>
					<?php endif; ?>
					<?php if (!get_option('w2dc_hide_listings_creation_date')): ?>
					<em class="w2dc-listing-date" datetime="<?php echo date("Y-m-d", mysql2date('U', $listing->post->post_date)); ?>T<?php echo date("H:i", mysql2date('U', $listing->post->post_date)); ?>"><?php echo get_the_date(); ?> <?php echo get_the_time(); ?></em>
					<?php endif; ?>
				</header>