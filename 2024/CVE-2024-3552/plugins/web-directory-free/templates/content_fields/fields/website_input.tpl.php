<div class="w2dc-form-group w2dc-field w2dc-field-input-block w2dc-field-input-block-<?php echo $content_field->id; ?>">
	<div class="w2dc-col-md-2">
		<label class="w2dc-control-label">
			<?php echo $content_field->name; ?><?php if ($content_field->canBeRequired() && $content_field->is_required): ?><span class="w2dc-red-asterisk">*</span><?php endif; ?>
		</label>
	</div>
	<div class="w2dc-col-md-10">
		<div class="w2dc-row">
			<div class="w2dc-col-md-12">
				<label><?php _e('URL:', 'W2DC'); ?></label>
				<input type="text" name="w2dc-field-input-url_<?php echo $content_field->id; ?>" class="w2dc-field-input-url w2dc-form-control regular-text" value="<?php echo esc_url($content_field->value['url']); ?>" />
			</div>
			<?php if ($content_field->use_link_text): ?>
			<div class="w2dc-col-md-12">
				<label><?php _e('Link text:', 'W2DC'); ?></label>
				<input type="text" name="w2dc-field-input-text_<?php echo $content_field->id; ?>" class="w2dc-field-input-text w2dc-form-control regular-text" value="<?php echo esc_attr($content_field->value['text']); ?>" />
			</div>
			<?php endif; ?>
		</div>
		<?php if ($content_field->description): ?><p class="description"><?php echo $content_field->description; ?></p><?php endif; ?>
	</div>
</div>