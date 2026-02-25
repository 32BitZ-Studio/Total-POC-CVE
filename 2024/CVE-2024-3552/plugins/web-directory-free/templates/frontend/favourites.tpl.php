		<div class="w2dc-content w2dc-favourites-page">
			<?php do_action('w2dc_favourites_page_header'); ?>
			
			<?php w2dc_renderMessages(); ?>

			<?php $frontpanel_buttons = new w2dc_frontpanel_buttons(); ?>
			<?php $frontpanel_buttons->display(); ?>
			
			<?php if ($frontend_controller->getPageTitle()): ?>
			<header class="w2dc-page-header">
				<?php echo $frontend_controller->printBreadCrumbs(); ?>
			</header>
			<?php endif; ?>

			<?php w2dc_renderTemplate('frontend/listings_block.tpl.php', array('frontend_controller' => $frontend_controller)); ?>
		</div>