<?php if (count($content_field->selection_items)): ?>
<div class="w2dc-form-group w2dc-field w2dc-field-input-block w2dc-field-input-block-<?php echo $content_field->id; ?>">
	<div class="w2dc-col-md-2">
		<label class="w2dc-control-label">
			<?php echo $content_field->name; ?><?php if ($content_field->canBeRequired() && $content_field->is_required): ?><span class="w2dc-red-asterisk">*</span><?php endif; ?>
		</label>
	</div>
	<div class="w2dc-col-md-10">
		<?php foreach ($content_field->selection_items AS $key=>$item): ?>
		<div class="w2dc-radio">
			<label>
				<input type="radio" name="w2dc-field-input-<?php echo $content_field->id; ?>" class="w2dc-field-input-radio" value="<?php echo esc_attr($key); ?>" <?php checked($content_field->value, $key, true); ?> />
				<?php echo $item; ?>
			</label>
		</div>
		<?php endforeach; ?>
	</div>
	<?php if ($content_field->description): ?>
	<div class="w2dc-col-md-12 w2dc-col-md-offset-2">
		<p class="description"><?php echo $content_field->description; ?></p>
	</div>
	<?php endif; ?>
</div>
<?php endif; ?>