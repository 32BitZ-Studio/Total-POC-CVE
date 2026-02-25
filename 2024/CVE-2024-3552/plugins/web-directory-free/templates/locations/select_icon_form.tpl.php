<tr class="form-field hide-if-no-js">
	<th scope="row" valign="top"><label for="description"><?php print _e('Icon', 'W2DC') ?></label></th>
	<td>
		<?php echo $w2dc_instance->locations_manager->choose_icon_link($term->term_id); ?>
		<p class="description"><?php _e('Associate an icon to this location', 'W2DC'); ?></p>
	</td>
</tr>