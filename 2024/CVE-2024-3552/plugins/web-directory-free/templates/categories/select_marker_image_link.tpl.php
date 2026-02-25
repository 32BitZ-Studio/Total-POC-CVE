<div>
	<img class="w2dc-marker-image-png-tag w2dc-field-icon" src="<?php if ($image_png_name) echo esc_url(W2DC_MAP_ICONS_URL . 'icons/' . $image_png_name); ?>" <?php if (!$image_png_name): ?>style="display: none;" <?php endif; ?> />
	<input type="hidden" name="marker_png_image" class="marker_png_image" value="<?php if ($image_png_name) echo esc_attr($image_png_name); ?>">
	<input type="hidden" name="category_id" class="category_id" value="<?php echo esc_attr($term_id); ?>">
	<a class="select_marker_png_image" href="javascript: void(0);"><?php _e('Select image', 'W2DC'); ?></a>
</div>