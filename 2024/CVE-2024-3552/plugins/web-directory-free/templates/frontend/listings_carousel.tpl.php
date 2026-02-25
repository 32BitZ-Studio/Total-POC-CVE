		<div class="w2dc-content w2dc-controller w2dc-listings-carousel-wrapper" id="w2dc-controller-<?php echo $frontend_controller->hash; ?>" data-controller-hash="<?php echo $frontend_controller->hash; ?>">
			<style type="text/css">
				#w2dc-controller-<?php echo $frontend_controller->hash; ?> article.w2dc-listing {
					width: <?php echo $frontend_controller->args['carousel_slide_width']; ?>px;
				}
				#w2dc-controller-<?php echo $frontend_controller->hash; ?>.w2dc-listings-carousel-wrapper {
					<?php if ($frontend_controller->args['carousel_full_width']): ?>
					width: calc(100% - 216px);
					<?php else: ?>
					max-width: <?php echo (($frontend_controller->args['carousel_slide_width'] * $frontend_controller->args['carousel_show_slides']) + (10 * ($frontend_controller->args['carousel_show_slides']-1))); ?>px;
					<?php endif; ?>
				}
				#w2dc-controller-<?php echo $frontend_controller->hash; ?> article.w2dc-listing .w2dc-listing-logo-img-wrap {
					height: <?php echo $frontend_controller->args['carousel_slide_height']; ?>px;
				}
			</style>
			<script>
			w2dc_controller_args_array['<?php echo $frontend_controller->hash; ?>'] = <?php echo json_encode(array_merge(array('base_url' => $frontend_controller->base_url, 'page_url' => $frontend_controller->page_url), $frontend_controller->args)); ?>;
			</script>
			<div class="w2dc-listings-carousel-button-left w2dc-fa w2dc-fa-arrow-left"></div>
			<div class="w2dc-listings-block w2dc-listings-carousel">
				<?php if ($frontend_controller->listings): ?>
				<div class="w2dc-listings-block-content">
					<?php while ($frontend_controller->query->have_posts()): ?>
					<?php $frontend_controller->query->the_post(); ?>
					<article id="post-<?php the_ID(); ?>" class="w2dc-listing <?php if ($frontend_controller->listings[get_the_ID()]->level->featured) echo 'w2dc-featured'; ?> <?php if ($frontend_controller->listings[get_the_ID()]->level->sticky) echo 'w2dc-sticky'; ?> <?php if ($frontend_controller->args['summary_on_logo_hover']) echo 'w2dc-summary-on-logo-hover'; ?>">
						<?php $frontend_controller->listings[get_the_ID()]->display($frontend_controller); ?>
					</article>
					<?php endwhile; ?>
				</div>
				<?php endif; ?>
			</div>
			<div class="w2dc-listings-carousel-button-right w2dc-fa w2dc-fa-arrow-right"></div>
		</div>