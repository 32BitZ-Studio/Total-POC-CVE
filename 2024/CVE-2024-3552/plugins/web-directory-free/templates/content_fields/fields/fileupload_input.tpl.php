<div class="w2dc-form-group w2dc-field w2dc-field-input-block w2dc-field-input-block-<?php echo $content_field->id; ?>">
	<div class="w2dc-col-md-2">
		<label class="w2dc-control-label">
			<?php echo $content_field->name; ?><?php if ($content_field->canBeRequired() && $content_field->is_required): ?><span class="w2dc-red-asterisk">*</span><?php endif; ?>
		</label>
	</div>
	<div class="w2dc-col-md-10">
		<div class="w2dc-row">
			<?php if ($file): ?>
			<div class="w2dc-col-md-6">
				<label><?php _e('Uploaded file:', 'W2DC'); ?></label>
				<a href="<?php echo esc_url($file->guid); ?>" target="_blank"><?php echo basename($file->guid); ?></a>
				<input type="hidden" name="w2dc-uploaded-file-<?php echo $content_field->id; ?>" value="<?php echo $file->ID; ?>" />
				<br />
				<label><input type="checkbox" name="w2dc-reset-file-<?php echo $content_field->id; ?>" value="1" /> <?php _e('reset uploaded file', 'W2DC'); ?></label>
			</div>
			<?php endif; ?>
			<div class="w2dc-col-md-6">
				<label><?php _e('Select file to upload:', 'W2DC'); ?></label>
				<input type="file" name="w2dc-field-input-<?php echo $content_field->id; ?>" class="w2dc-field-input-fileupload" />
			</div>
			<?php if ($content_field->use_text): ?>
			<div class="w2dc-col-md-12">
				<label><?php _e('File title:', 'W2DC'); ?></label>
				<input type="text" name="w2dc-field-input-text-<?php echo $content_field->id; ?>" class="w2dc-field-input-text w2dc-form-control regular-text" value="<?php echo esc_attr($content_field->value['text']); ?>" />
			</div>
			<?php endif; ?>
		</div>
		<?php if ($content_field->description): ?><p class="description"><?php echo $content_field->description; ?></p><?php endif; ?>
	</div>
</div>