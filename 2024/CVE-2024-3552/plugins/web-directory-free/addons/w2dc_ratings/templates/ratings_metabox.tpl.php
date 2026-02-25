<?php if (get_option('w2dc_manage_ratings') || current_user_can('edit_others_posts')): ?>
<script>
	jQuery(document).ready(function($) {
		$("#w2dc-reset-all-ratings").on('click', function() {
			if (confirm('<?php echo esc_js(__('Are you sure you want to reset all ratings of this listing?', 'W2DC')); ?>')) {
				w2dc_ajax_loader_show();
				$.ajax({
					type: "POST",
					url: w2dc_js_objects.ajaxurl,
					data: {'action': 'w2dc_reset_ratings', 'post_id': <?php echo $listing->post->ID; ?>},
					success: function(){
						$(".w2dc-ratings-counts").html('0');
						$(".w2dc-admin-avgvalue").remove();
					},
					complete: function() {
						w2dc_ajax_loader_hide();
					}
				});
			    
			}
		});
	});
</script>
<?php endif; ?>
<div class="w2dc-content w2dc-ratings-metabox">
	<?php w2dc_renderTemplate(array(W2DC_RATINGS_TEMPLATES_PATH, 'ratings_overall.tpl.php'), array('listing' => $listing, 'total_counts' => $total_counts)); ?>
	
	<?php if (get_option('w2dc_manage_ratings') || current_user_can('edit_others_posts')): ?>
	<input id="w2dc-reset-all-ratings" type="button" class="w2dc-btn w2dc-btn-primary" onClick="" value="<?php esc_attr_e('Reset all ratings', 'W2DC'); ?>" />
	<?php endif; ?>
</div>