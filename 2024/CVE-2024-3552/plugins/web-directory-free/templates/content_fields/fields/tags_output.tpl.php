<?php if (has_term('', W2DC_TAGS_TAX, $listing->post->ID)): ?>
<div class="w2dc-field w2dc-field-output-block <?php echo $content_field->printClasses($css_classes); ?>">
	<?php if ($content_field->icon_image || !$content_field->is_hide_name): ?>
	<span class="w2dc-field-caption <?php w2dc_is_any_field_name_in_group($group); ?>">
		<?php if ($content_field->icon_image): ?>
		<span <?php echo $content_field->getIconImageTagParams(); ?>></span>
		<?php endif; ?>
		<?php if (!$content_field->is_hide_name): ?>
		<span class="w2dc-field-name"><?php echo $content_field->name?>:</span>
		<?php endif; ?>
	</span>
	<?php endif; ?>
	<span class="w2dc-field-content">
		<?php
		$terms = get_the_terms($listing->post->ID, W2DC_TAGS_TAX);
		foreach ($terms as $term): ?>
			<a href="<?php echo get_term_link($term, W2DC_TAGS_TAX); ?>" rel="tag"><span class="w2dc-label w2dc-label-primary w2dc-tag-label"><?php echo $term->name; ?>&nbsp;&nbsp;<span class="w2dc-glyphicon w2dc-glyphicon-tag"></span></span></a>
		<?php endforeach; ?>
	</span>
</div>
<?php endif; ?>