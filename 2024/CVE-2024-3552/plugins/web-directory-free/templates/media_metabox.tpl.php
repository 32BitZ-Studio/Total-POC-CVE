<script>
	var w2dc_media_metabox_attrs = <?php echo json_encode(
		array(
			'object_id' => $object_id,
			'images_number' => $images_number,
			'images_input_placeholder' => esc_attr__('optional image title', 'W2DC'),
			'images_logo_enabled' => ($logo_enabled) ? 1 : 0,
			'images_input_label' => esc_attr__('set this image as logo', 'W2DC'),
			'images_remove_title' => esc_attr__('remove', 'W2DC'),
			'images_remove_image_nonce' => wp_create_nonce('remove_image'),
			'images_fileupload_url' => admin_url('admin-ajax.php?action=w2dc_upload_image&post_id='.$object_id.'&_wpnonce='.wp_create_nonce('upload_images')),
			'images_is_admin' => (is_admin() && current_user_can('upload_files')) ? 1 : 0,
			'images_upload_image_nonce' => wp_create_nonce('upload_images'),
			'images_upload_image_title' => esc_js(sprintf(__('Upload image (%d maximum)', 'W2DC'), $images_number)),
			'images_upload_image_button' => esc_js(__('Insert', 'W2DC')),
			'videos_number' => $videos_number,
			'videos_delete_title' => esc_attr__("delete", "W2DC"),
			'videos_error_alert' => esc_attr__('Wrong URL or this video is unavailable', 'W2DC'),
		)
	); ?>;
</script>

<?php if ($images_number): ?>
<div id="w2dc-images-upload-wrapper" class="w2dc-content w2dc-media-upload-wrapper <?php echo $classes; ?>">
	<input type="hidden" id="w2dc-attached-images-order" name="attached_images_order" value="<?php echo implode(',', array_keys($images)); ?>">
	<h4><?php _e('Attach images', 'W2DC'); ?></h4>

	<div id="w2dc-attached-images-wrapper">
		<?php foreach ($images AS $attachment_id=>$attachment): ?>
		<?php $src = wp_get_attachment_image_src($attachment_id, array(250, 250)); ?>
		<?php $src_full = wp_get_attachment_image_src($attachment_id, 'full'); ?>
		<?php $metadata = wp_get_attachment_metadata($attachment_id); ?>
		<?php $metadata['size'] = size_format(filesize(get_attached_file($attachment_id))); ?>
		<div class="w2dc-attached-item w2dc-move-label">
			<input type="hidden" name="attached_image_id[]" class="w2dc-attached-item-id" value="<?php echo $attachment_id; ?>" />
			<a href="<?php echo $src_full[0]; ?>" data-w2dc_lightbox="listing_images" class="w2dc-attached-item-img" style="background-image: url('<?php echo $src[0]; ?>')"></a>
			<div class="w2dc-attached-item-input">
				<input type="text" name="attached_image_title[]" class="w2dc-form-control" value="<?php esc_attr_e($attachment['post_title']); ?>" placeholder="<?php esc_attr_e('optional image title', 'W2DC'); ?>" />
			</div>
			<?php if ($logo_enabled): ?>
			<div class="w2dc-attached-item-logo w2dc-radio">
				<label>
					<input type="radio" name="attached_image_as_logo" value="<?php echo $attachment_id; ?>" <?php checked($logo_image, $attachment_id); ?>> <?php _e('set this image as logo', 'W2DC'); ?>
				</label>
			</div>
			<?php endif; ?>
			<div class="w2dc-attached-item-delete w2dc-fa w2dc-fa-trash-o" title="<?php esc_attr_e("delete", "W2DC"); ?>"></div>
			<div class="w2dc-attached-item-metadata"><?php echo $metadata['size']; ?> (<?php echo $metadata['width']; ?> x <?php echo $metadata['height']; ?>)</div>
		</div>
		<?php endforeach; ?>
		<?php if (!is_admin()): ?>
		<div class="w2dc-upload-item">
			<div class="w2dc-drop-attached-item">
				<div class="w2dc-drop-zone">
					<?php _e("Drop here", "W2DC"); ?>
					<button class="w2dc-upload-item-button w2dc-btn w2dc-btn-primary"><?php _e("Browse", "W2DC"); ?></button>
					<input type="file" name="browse_file" multiple />
				</div>
			</div>
		</div>
		<?php endif; ?>
	</div>
	<div class="w2dc-clearfix"></div>

	<?php if (is_admin() && current_user_can('upload_files')): ?>
	<div id="w2dc-admin-upload-functions">
		<div class="w2dc-upload-option">
			<input
				type="button"
				id="w2dc-admin-upload-image"
				class="w2dc-btn w2dc-btn-primary"
				value="<?php esc_attr_e('Upload image', 'W2DC'); ?>" />
		</div>
	</div>
	<?php endif; ?>
</div>
<?php endif; ?>


<?php if ($videos_number): ?>
<div id="w2dc-video-attach-wrapper" class="w2dc-content w2dc-media-upload-wrapper">
	<h4><?php _e("Attach videos", "W2DC"); ?></h4>
	
	<div id="w2dc-attached-videos-wrapper">
		<?php foreach ($videos AS $video): ?>
		<div class="w2dc-attached-item">
			<input type="hidden" name="attached_video_id[]" value="<?php echo $video['id']; ?>" />
			<?php
			$image_url = '';
			if (strlen($video['id']) == 11) {
				$image_url = "http://i.ytimg.com/vi/" . $video['id'] . "/0.jpg";
			} elseif (strlen($video['id']) == 8 || strlen($video['id']) == 9) {
				if ($data = @file_get_contents("http://vimeo.com/api/v2/video/" . $video['id'] . ".json")) {
					$data = json_decode($data);
					$image_url = $data[0]->thumbnail_medium;
				} else {
					$image_url = "data:image/jpeg;base64,/9j/4AAQSkZJRgABAQAAAQABAAD/2wCEAAUDBAcFBwUFBQUGBQgFBgUFBQUIBQUHBQgFBQUJBggJBQUTChwLBwgaCQgFDiEYGh0RHxMfEwsiGCIeGBwSExIBBQUFBwYHBQgIBRIIBQgSEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEv/AABEIAFoAeAMBIgACEQEDEQH/xAAbAAEAAgMBAQAAAAAAAAAAAAAAAQQCAwcGBf/EAD0QAAIBAgMDBwYNBQAAAAAAAAACAQMEBRESBhMhByIxMkFSYRRCcXKS0hVVgYSRlLHBwsPR0/AXUWJks//EABQBAQAAAAAAAAAAAAAAAAAAAAD/xAAUEQEAAAAAAAAAAAAAAAAAAAAA/9oADAMBAAIRAxEAPwDvQAAAAACYgnSBiDLQNAGIMtA0gYgmYIAAAAAAAAAQZqpipYoqASkbloHyNoNq7HBWWjcb2tWaFdrejEM6I3Vms8zCp4cc/A+RPKhar1cKum9Na3X9QPYbgbg8XPKnT83B3+W9SPyzH+qi/E0/Xl/aA9tuDFqB41eVOj52D1f8tN7Sn8uDbHKfaN04ZeJ6Ktq33wB6d6ZpZTTgG0VljUP5Izo9KNT29RVStCdGpeMwy+iS3WUCuAwAAAAAAMkLtouqVKSF+znioHCseuJuLzELhm1TVu7ltXTzVrMi/JpVIKZNSec7d56je08lvBLCcQurWyR4pTdVVpa24qurpnT28IYCmD023mysYFNpKXU3CXW9XnoqVVejplubE5SuTKXLrYbdYT8MeW6qi21O9a33S7ndOsTpWrnnryZfDMDxoPV7C7IRjqXVardzarRqLRVUpK7tVZNebcYyXKVPN4jbTaV7i1aYdrWrVt2deqzUnlJlfDgB9bk/rzRxTDW1aYq1Wt38VrIyZfTKnYLmDiey7acQwyV6VvLT/sp26784Ci5BLkAAAAAAEoXbRuMekowb6T6QOF3KSlWsjdKVaqN60VZifsMabykq6NKMkrKOrZSrLxiVbsnM+3tthNSxu7p2SdzdValxb1oXmStV5eVaexomWg+FqjvQBaxC/uL1lq3t1WunWNCPUqs7KnTkv9oJfErlqC2U3ddrdZ1LazVfcxpbOOZ0ZZ8SpmSBaw/Ermy1+SXde13saau7qsmpezV9JVmf5PFpbtlm7ZIzGqO9AH1Nkk14jhi/7ls3svDz9h2m4Y5dya4VUrXdK+ZJWjabx97K5K9aUlESl3pjVnOX3nS6jAamIEgAAAAAAErJAA2atXNZYaO7KrMeya2trd+va28+tb0Z/CBmBqbDLFuth9m3zWj7pj8EWHxZZ/VqP6G/MZga1wyyXq4fZr80o+6bVt6CdS1t09W3or+EjMZgbJfs7F6qxwWPVXsMJkgAAAAAAAAAAAAAAAAAAAAAAAAAAAB//9k=";
				}
			} ?>
			<div class="w2dc-attached-item-img" style="background-image: url('<?php echo $image_url; ?>')"></div>
			<div class="w2dc-attached-item-delete w2dc-fa w2dc-fa-trash-o" title="<?php esc_attr_e("delete", "W2DC"); ?>"></div>
		</div>
		<?php endforeach; ?>
	</div>
	<div class="w2dc-clearfix"></div>

	<div id="w2dc-attach-videos-functions">
		<div class="w2dc-upload-option">
			<label><?php _e('Enter full YouTube or Vimeo video link', 'W2DC'); ?></label>
		</div>
		<div class="w2dc-upload-option">
			<input type="text" id="w2dc-attach-video-input" class="w2dc-form-control" placeholder="https://youtu.be/XXXXXXXXXXXX" />
		</div>
		<div class="w2dc-upload-option">
			<input
				type="button"
				class="w2dc-btn w2dc-btn-primary"
				onclick="return attachVideo(); "
				value="<?php esc_attr_e('Attach video', 'W2DC'); ?>" />
		</div>
	</div>
</div>
<?php endif; ?>