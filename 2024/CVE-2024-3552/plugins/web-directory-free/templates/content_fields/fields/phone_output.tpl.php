<?php if ($content_field->value): ?>
<div class="w2dc-field w2dc-field-output-block <?php echo $content_field->printClasses($css_classes); ?>">
	<?php if ($content_field->icon_image || !$content_field->is_hide_name): ?>
	<span class="w2dc-field-caption <?php w2dc_is_any_field_name_in_group($group); ?> w2dc-field-phone-caption">
		<?php if ($content_field->icon_image): ?>
		<span <?php echo $content_field->getIconImageTagParams(); ?>></span>
		<?php endif; ?>
		<?php if (!$content_field->is_hide_name): ?>
		<span class="w2dc-field-name"><?php echo $content_field->name?>:</span>
		<?php endif; ?>
	</span>
	<?php endif; ?>
	<span class="w2dc-field-content w2dc-field-phone-content">
		<?php if ($content_field->phone_mode == 'phone'): ?>
		<meta itemprop="telephone" content="<?php echo $content_field->value; ?>" />
		<a href="tel:<?php echo $content_field->value; ?>"><?php echo antispambot($content_field->value); ?></a>
		<?php elseif ($content_field->phone_mode == 'viber'): ?>
		<a href="viber://chat?number=<?php echo $content_field->value; ?>"><?php echo antispambot($content_field->value); ?></a>
		<?php elseif ($content_field->phone_mode == 'whatsapp'): ?>
		<a href="https://wa.me/<?php echo $content_field->value; ?>" target="_blank"><?php echo antispambot($content_field->value); ?></a>
		<?php elseif ($content_field->phone_mode == 'telegram'): ?>
		<a href="tg://resolve?domain=<?php echo $content_field->value; ?>"><?php echo antispambot($content_field->value); ?></a>
		<?php endif; ?>
	</span>
</div>
<?php endif; ?>