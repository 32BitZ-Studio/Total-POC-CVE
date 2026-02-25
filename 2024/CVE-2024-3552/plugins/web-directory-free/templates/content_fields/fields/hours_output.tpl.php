<?php if (array_filter($content_field->value)): ?>
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
	<?php if ($strings = $content_field->processStrings()): ?>
	<div class="w2dc-field-content w2dc-hours-field">
		<?php foreach ($strings AS $string): ?>
		<div><?php echo $string; ?></div>
		<?php endforeach; ?>
		<div class="w2dc-clearfix"></div>
	</div>
	<?php endif; ?>
</div>
<?php endif; ?>