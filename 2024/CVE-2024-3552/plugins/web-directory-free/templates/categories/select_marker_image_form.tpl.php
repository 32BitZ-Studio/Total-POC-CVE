<tr class="form-field hide-if-no-js">
	<th scope="row" valign="top"><label for="description"><?php print _e('Marker Image', 'W2DC') ?></label></th>
	<td>
		<?php echo $w2dc_instance->categories_manager->choose_marker_image($term->term_id); ?>
		<p class="description"><?php _e('Associate an image to this category', 'W2DC'); ?></p>
	</td>
</tr>