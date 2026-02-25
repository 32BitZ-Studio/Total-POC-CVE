<?php if (count($content_field->selection_items)): ?>
<div class="w2dc-form-group w2dc-field w2dc-field-input-block w2dc-field-input-block-<?php echo $content_field->id; ?>">
	<div class="w2dc-col-md-2">
		<label class="w2dc-control-label">
			<?php echo $content_field->name; ?><?php if ($content_field->canBeRequired() && $content_field->is_required): ?><span class="w2dc-red-asterisk">*</span><?php endif; ?>
		</label>
	</div>
	<div class="w2dc-col-md-10">
		<?php foreach ($content_field->selection_items AS $key=>$item): ?>
		<div class="w2dc-checkbox w2dc-field-checkbox-input">
			<label>
				<?php if ($content_field->icon_images[$key]): ?>
				<span class="w2dc-field-icon w2dc-fa w2dc-fa-lg <?php echo $content_field->icon_images[$key]; ?>"></span>
				<?php endif; ?>
				<input type="checkbox" name="w2dc-field-input-<?php echo $content_field->id; ?>[]" class="w2dc-field-input-checkbox" value="<?php echo esc_attr($key); ?>" <?php if (in_array($key, $content_field->value)) echo 'checked'; ?> />
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