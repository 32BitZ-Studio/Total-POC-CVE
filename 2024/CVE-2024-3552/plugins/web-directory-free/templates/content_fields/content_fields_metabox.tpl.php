<script>
		<?php
		foreach ($content_fields AS $content_field): 
			if (!$content_field->isCategories() || $content_field->categories === array()) { ?>
				w2dc_js_objects.fields_in_categories[<?php echo $content_field->id?>] = [];
			<?php } else { ?>
				w2dc_js_objects.fields_in_categories[<?php echo $content_field->id?>] = [<?php echo implode(',', $content_field->categories); ?>];
			<?php } ?>
		<?php endforeach; ?>
</script>

<div class="w2dc-content w2dc-content-fields-metabox">
	<div class="w2dc-form-horizontal">
		<p class="w2dc-description"><?php _e('Content fields may be dependent on selected categories', 'W2DC'); ?></p>
		<?php
		foreach ($content_fields AS $content_field) {
			if (
				!$content_field->is_core_field &&
				($content_field->filterForAdmins() || $post->post_author == get_current_user_id()) // this content field may be hidden from all users except admins and listing author
			) {
				$content_field->renderInput();
			}
		}
		?>
	</div>
</div>