<?php if ($file): ?>
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
		<a href="<?php echo esc_url(wp_get_attachment_url($file->ID)); ?>" target="_blank"><?php if ($content_field->value['text'] && $content_field->use_text) echo $content_field->value['text']; else echo basename(wp_get_attachment_url($file->ID)); ?></a>
	</span>
</div>
<?php endif; ?>