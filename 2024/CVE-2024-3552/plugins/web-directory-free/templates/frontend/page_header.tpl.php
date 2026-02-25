<div class="w2dc-content">
	<div class="w2dc-page-header-widget" <?php if ($featured_image) echo 'style="background-image: url(' . $featured_image . ');"' ?>>
		<h1 class="w2dc-page-title-widget"><?php echo $page_title; ?></h1>
		<?php if (!empty($shortcode_controller->breadcrumbs)): ?>
		<?php echo $shortcode_controller->printBreadCrumbs(' / '); ?> 
		<?php endif; ?>
	</div>
</div>