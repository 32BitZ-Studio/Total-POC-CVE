<?php if ($content_field->value['url']): ?>
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
		<a itemprop="url"
			href="<?php echo esc_url($content_field->value['url']); ?>"
			<?php if ($content_field->is_blank) echo 'target="_blank"'; ?>
			<?php if ($content_field->is_nofollow) echo 'rel="nofollow"'; ?>
		><?php if ($content_field->value['text'] && $content_field->use_link_text) echo $content_field->value['text']; else echo $content_field->value['url']; ?></a>
	</span>
</div>
<?php endif; ?>