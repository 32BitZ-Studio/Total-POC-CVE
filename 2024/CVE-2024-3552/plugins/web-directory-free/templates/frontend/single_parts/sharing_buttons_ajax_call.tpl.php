<?php if (get_option('w2dc_share_buttons')): ?>
<div class="w2dc-share-buttons">
	<script>
		(function($) {
			"use strict";
	
			$(function() {
				$('.w2dc-share-buttons').addClass('w2dc-ajax-loading');
				$.ajax({
					type: "POST",
					url: w2dc_js_objects.ajaxurl,
					data: {'action': 'w2dc_get_sharing_buttons', 'post_id': <?php echo $post_id; ?>, 'post_url': "<?php echo $post_url; ?>"},
					dataType: 'html',
					success: function(response_from_the_action_function){
						if (response_from_the_action_function != 0)
							$('.w2dc-share-buttons').html(response_from_the_action_function);
					},
					complete: function() {
						$('.w2dc-share-buttons').removeClass('w2dc-ajax-loading').css('height', 'auto');
					}
				});
			});
		})(jQuery);
	</script>
</div>
<?php endif; ?>