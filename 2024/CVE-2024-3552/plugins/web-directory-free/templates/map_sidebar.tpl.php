<div class="w2dc-content w2dc-map-sidebar" id="w2dc-map-sidebar-<?php echo $uid; ?>" style="<?php if (!empty($height)) echo "height: ".$height."px;" ?>" >
	<div class="w2dc-map-sidebar-search-wrapper" id="w2dc-map-sidebar-search-wrapper-<?php echo $uid; ?>">
		<?php if (!empty($search_map->map_args['search_on_map_id'])): ?>
		<?php $search_form->display(); ?>
		<?php endif; ?>
		
		<?php if (!empty($map_args['search_on_map_listings']) && $map_args['search_on_map_listings'] == 'sidebar'): ?>
		<div class="w2dc-map-listings-panel" id="w2dc-map-listings-panel-<?php echo $uid; ?>">
			<?php echo $search_map->listings_content; ?>
		</div>
		<?php endif; ?>
	</div>
</div>
<div class="w2dc-map-sidebar-toggle-container w2dc-map-sidebar-toggle-container-<?php echo $uid; ?>" data-id="<?php echo $uid; ?>" title="<?php esc_attr_e("Search listings", "W2DC")?>">
	<span class="w2dc-map-sidebar-toggle"></span><span class="w2dc-fa w2dc-fa-search"></span>
</div>
<div class="w2dc-map-sidebar-toggle-container-mobile w2dc-map-sidebar-toggle-container-mobile-<?php echo $uid; ?>" data-id="<?php echo $uid; ?>" title="<?php esc_attr_e("Search panel", "W2DC"); ?>">
	<span class="w2dc-map-sidebar-toggle"></span>
</div>