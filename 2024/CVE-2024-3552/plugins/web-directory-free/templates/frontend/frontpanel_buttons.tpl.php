<div class="w2dc-content w2dc-directory-frontpanel">
	<?php do_action('w2dc_directory_frontpanel', $frontpanel_buttons); ?>
	<?php if ($frontpanel_buttons->isFavouritesButton()): ?>
	<a class="w2dc-favourites-link w2dc-btn w2dc-btn-primary" href="<?php echo w2dc_directoryUrl(array('w2dc_action' => 'myfavourites')); ?>" rel="nofollow" <?php $frontpanel_buttons->tooltipMeta(__('My bookmarks', 'W2DC')); ?>><span class="w2dc-glyphicon w2dc-glyphicon-star"></span><?php if (!$frontpanel_buttons->hide_button_text): ?> <?php _e('My bookmarks', 'W2DC'); ?><?php endif; ?></a>
	<?php endif; ?>
	<?php if ($frontpanel_buttons->isEditButton()): ?>
	<a class="w2dc-edit-listing-link w2dc-btn w2dc-btn-primary" href="<?php echo w2dc_get_edit_listing_link($frontpanel_buttons->getListingId()); ?>" rel="nofollow" <?php $frontpanel_buttons->tooltipMeta(__('Edit listing', 'W2DC')); ?>><span class="w2dc-glyphicon w2dc-glyphicon-pencil"></span><?php if (!$frontpanel_buttons->hide_button_text): ?> <?php _e('Edit listing', 'W2DC'); ?><?php endif; ?></a>
	<?php endif; ?>
	<?php if ($frontpanel_buttons->isPrintButton()): ?>
	<script>
		var window_width = 860;
		var window_height = 800;
		var leftPosition, topPosition;
		(function($) {
			"use strict";
					$(function() {
				leftPosition = (window.screen.width / 2) - ((window_width / 2) + 10);
				topPosition = (window.screen.height / 2) - ((window_height / 2) + 50);
			});
		})(jQuery);
	</script>
	<a href="javascript:void(0);" class="w2dc-print-listing-link w2dc-btn w2dc-btn-primary" onClick="window.open('<?php echo add_query_arg('w2dc_action', 'printlisting', get_permalink($frontpanel_buttons->getListingId())); ?>', 'print_window', 'height='+window_height+',width='+window_width+',left='+leftPosition+',top='+topPosition+',menubar=yes,scrollbars=yes');" rel="nofollow" <?php $frontpanel_buttons->tooltipMeta(__('Print listing', 'W2DC')); ?>><span class="w2dc-glyphicon w2dc-glyphicon-print"></span> <?php if (!$frontpanel_buttons->hide_button_text): ?><?php _e('Print listing', 'W2DC'); ?><?php endif; ?></a>
	<?php endif; ?>
	<?php if ($frontpanel_buttons->isBookmarkButton()): ?>
	<a href="javascript:void(0);" class="add_to_favourites w2dc-btn w2dc-btn-primary" listingid="<?php echo $frontpanel_buttons->getListingId(); ?>" rel="nofollow" <?php $frontpanel_buttons->tooltipMeta(__('Add/Remove Bookmark', 'W2DC')); ?>><span class="w2dc-glyphicon w2dc-glyphicon-<?php if (w2dc_checkQuickList($frontpanel_buttons->getListingId())) echo 'heart'; else echo 'heart-empty'; ?>"></span> <?php if (!$frontpanel_buttons->hide_button_text): ?><span class="w2dc-bookmark-button"><?php if (w2dc_checkQuickList($frontpanel_buttons->getListingId())) _e('Remove Bookmark', 'W2DC'); else _e('Add Bookmark', 'W2DC'); ?></span><?php endif; ?></a>
	<?php endif; ?>
	<?php if ($frontpanel_buttons->isPdfButton()): ?>
	<a href="https://pdfmyurl.com/?orientation=<?php echo get_option('w2dc_pdf_page_orientation', 'portrait'); ?>&url=<?php echo add_query_arg('w2dc_action', 'pdflisting', get_permalink($frontpanel_buttons->getListingId())); ?>" target="_blank" class="w2dc-pdf-listing-link w2dc-btn w2dc-btn-primary" rel="nofollow" <?php $frontpanel_buttons->tooltipMeta(__('Save listing in PDF', 'W2DC')); ?>><span class="w2dc-glyphicon w2dc-glyphicon-save"></span> <?php if (!$frontpanel_buttons->hide_button_text): ?><?php _e('Save listing in PDF', 'W2DC'); ?><?php endif; ?></a>
	<?php endif; ?>
	<?php do_action('w2dc_directory_frontpanel_after', $frontpanel_buttons); ?>
</div>