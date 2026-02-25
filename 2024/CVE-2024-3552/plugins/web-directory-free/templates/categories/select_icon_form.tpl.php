<tr class="form-field hide-if-no-js">
	<th scope="row" valign="top"><label for="description"><?php print _e('Icon', 'W2DC') ?></label></th>
	<td>
		<?php echo $w2dc_instance->categories_manager->choose_icon_link($term->term_id); ?>
		<p class="description"><?php _e('Associate an icon to this category', 'W2DC'); ?></p>
	</td>
</tr>