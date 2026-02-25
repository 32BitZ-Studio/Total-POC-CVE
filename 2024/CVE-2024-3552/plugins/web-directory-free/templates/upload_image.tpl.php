<div class="w2dc-content w2dc-upload-image-form w2dc-upload-image-form-<?php echo $upload->input_name; ?>" data-name="<?php echo $upload->input_name; ?>" data-action-url="<?php echo $upload->action_url; ?>">
	<div class="w2dc-upload-image w2dc-upload-image-<?php echo $upload->input_name; ?>" <?php if ($upload->default_url): ?>style="background-image: url(<?php echo esc_url($upload->default_url); ?>);"<?php endif; ?>></div>
	<input type="file" name="browse_file" multiple />
	<input type="hidden" name="w2dc-upload-image-input-<?php echo $upload->input_name; ?>" class="w2dc-upload-image-input-<?php echo $upload->input_name; ?>" <?php if ($upload->default_attachment_id): ?>value="<?php echo $upload->default_attachment_id; ?>"<?php endif; ?> />
	<button class="w2dc-upload-image-button w2dc-btn w2dc-btn-primary"><?php esc_html_e("Upload", "W2DC"); ?></button>
	<button class="w2dc-reset-image-button w2dc-btn w2dc-btn-primary"><?php esc_html_e("Reset", "W2DC"); ?></button>
</div>