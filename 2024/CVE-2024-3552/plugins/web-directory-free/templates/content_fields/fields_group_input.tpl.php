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

<div class="w2dc-submit-section w2dc-content-fields-metabox">
	<h3 class="w2dc-submit-section-label"><?php echo $group->name; ?></h3>
	<div class="w2dc-submit-section-inside w2dc-form-horizontal">
		<?php
		foreach ($content_fields AS $content_field) {
			$content_field->renderInput();
		}
		?>
	</div>
</div>