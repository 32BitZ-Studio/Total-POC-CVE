<div class="w2dc-content">
<?php if (!$static_image): ?>
	<script>
		w2dc_map_markers_attrs_array.push(new w2dc_map_markers_attrs('<?php echo $map_id; ?>', eval(<?php echo $locations_options; ?>), <?php echo ($enable_radius_circle) ? 1 : 0; ?>, <?php echo ($enable_clusters) ? 1 : 0; ?>, <?php echo ($show_summary_button) ? 1 : 0; ?>, <?php echo ($show_readmore_button) ? 1 : 0; ?>, <?php echo ($draw_panel) ? 1 : 0; ?>, '<?php echo $map_style; ?>', <?php echo ($enable_full_screen) ? 1 : 0; ?>, <?php echo ($enable_wheel_zoom) ? 1 : 0; ?>, <?php echo ($enable_dragging_touchscreens) ? 1 : 0; ?>, <?php echo ($center_map_onclick) ? 1 : 0; ?>, <?php echo ($show_directions) ? 1 : 0; ?>, <?php echo ($enable_infowindow) ? 1 : 0; ?>, <?php echo ($close_infowindow_out_click) ? 1 : 0; ?>, <?php echo $map_args; ?>));
	</script>

	<div id="w2dc-map-wrapper-<?php echo $map_id; ?>" <?php echo $map_object->getWrapperAttributes(); ?>>
		<?php
		if (empty($args['search_on_map_right'])) {
			$map_sidebar = new w2dc_map_sidebar($map_id, $args, $listings_content);
	
			echo $map_sidebar->display($height);
		} ?>
		
		<div id="w2dc-map-canvas-wrapper-<?php echo $map_id; ?>" <?php echo $map_object->getCanvasWrapperAttributes(); ?>>
			<div id="w2dc-map-canvas-<?php echo $map_id; ?>" <?php echo $map_object->getCanvasAttributes(); ?>></div>
		</div>
		
		<?php
		if (!empty($args['search_on_map_right'])) {
			$map_sidebar = new w2dc_map_sidebar($map_id, $args, $listings_content);
	
			echo $map_sidebar->display($height);
		} ?>
	</div>
	<?php if (!empty($args['search_on_map_listings']) && $args['search_on_map_listings'] == 'bottom'): ?>
	<div class="w2dc-map-listings-panel" id="w2dc-map-listings-panel-<?php echo $map_id; ?>">
		<?php echo $listings_content; ?>
	</div>
	<?php endif; ?>

	<?php if ($show_directions && w2dc_getMapEngine() == 'google'): ?>
		<?php w2dc_renderTemplate('maps/google_directions.tpl.php', array('map_id' => $map_id, 'locations_array' => $locations_array))?>
	<?php endif; ?>
<?php else: ?>
	<?php echo $map_object->buildStaticMap(); ?>
<?php endif; ?>
</div>