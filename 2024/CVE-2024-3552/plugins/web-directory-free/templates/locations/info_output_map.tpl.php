<?php if ($content_field->value): ?>
	<ul class="w2dc-field-content">
	<?php foreach ($content_field->value AS $key): ?>
		<li><?php echo $content_field->selection_items[$key]; ?></li>
	<?php endforeach; ?>
	</ul>
<?php endif; ?>