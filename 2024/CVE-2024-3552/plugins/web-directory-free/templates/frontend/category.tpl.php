		<div class="w2dc-content w2dc-category-page">
			<?php do_action('w2dc_category_page_header'); ?>
		
			<?php w2dc_renderMessages(); ?>
			
			<?php $frontpanel_buttons = new w2dc_frontpanel_buttons(); ?>
			<?php $frontpanel_buttons->display(); ?>

			<?php if ($frontend_controller->getPageTitle()): ?>
			<header class="w2dc-page-header">
				<?php if (!get_option('w2dc_overwrite_page_title')): ?>
				<h2>
					<?php echo $frontend_controller->getPageTitle(); ?>
				</h2>
				<?php endif; ?>
				
				<?php echo $frontend_controller->printBreadCrumbs(); ?>

				<?php if (term_description($frontend_controller->category->term_id, W2DC_CATEGORIES_TAX)): ?>
				<div class="w2dc-term-description w2dc-clearfix"><?php echo term_description($frontend_controller->category->term_id, W2DC_CATEGORIES_TAX); ?></div>
				<?php endif; ?>
			</header>
			<?php endif; ?>
	
			<?php if (get_option('w2dc_main_search')): ?>
			<?php $frontend_controller->search_form->display(); ?>
			<?php endif; ?>

			<?php if ($parent_category = w2dc_isCategory()): ?>
			<?php w2dc_displayCategoriesTable($parent_category->term_id); ?>
			<?php endif; ?>

			<?php if (w2dc_is_maps_used() && get_option('w2dc_map_on_excerpt')): ?>
			<?php $frontend_controller->map->display(
						array(
								'show_directions' => false,
								'static_image' => false,
								'enable_radius_circle' => get_option('w2dc_enable_radius_search_circle'),
								'enable_clusters' => get_option('w2dc_enable_clusters'),
								'show_summary_button' => true,
								'show_readmore_button' => true,
								'width' => false,
								'height' => get_option('w2dc_default_map_height'),
								'sticky_scroll' => false,
								'sticky_scroll_toppadding' => 10,
								'map_style' => w2dc_getSelectedMapStyleName(),
								'search_form' => get_option('w2dc_search_on_map'),
								'draw_panel' => get_option('w2dc_enable_draw_panel'),
								'custom_home' => false,
								'enable_full_screen' => get_option('w2dc_enable_full_screen'),
								'enable_wheel_zoom' => get_option('w2dc_enable_wheel_zoom'),
								'enable_dragging_touchscreens' => get_option('w2dc_enable_dragging_touchscreens'),
								'center_map_onclick' => get_option('w2dc_center_map_onclick'),
						)
					); ?>
			<?php endif; ?>

			<?php w2dc_renderTemplate('frontend/listings_block.tpl.php', array('frontend_controller' => $frontend_controller)); ?>
		</div>