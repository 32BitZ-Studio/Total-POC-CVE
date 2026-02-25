<?php if ($content_field->value['url']): ?>
<a
	href="<?php echo esc_url($content_field->value['url']); ?>"
	<?php if ($content_field->is_blank) echo 'target="_blank"'; ?>
	<?php if ($content_field->is_nofollow) echo 'rel="nofollow"'; ?>
><?php if ($content_field->value['text'] && $content_field->use_link_text) echo $content_field->value['text']; else echo $content_field->value['url']; ?></a>
<?php endif; ?>