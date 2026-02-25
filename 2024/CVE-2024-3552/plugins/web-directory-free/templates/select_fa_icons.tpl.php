<script>
(function($) {
	"use strict";
	
	$(document).on('keyup', '#search_icon', function() {
		if ($(this).val()) {
			$(".w2dc-icons-theme-block .w2dc-fa-icon").hide();
			$(".w2dc-icons-theme-block .w2dc-fa-icon[id*='"+$(this).val()+"']").show();
		} else
			$(".w2dc-icons-theme-block .w2dc-fa-icon").show();
	});
})(jQuery);
</script>

<div class="w2dc-content">
	<div class="w2dc-row">
		<div class="w2dc-col-md-6 w2dc-form-group w2dc-pull-left">
			<input type="text" id="search_icon" class="w2dc-form-control" placeholder="<?php _e('Search Icon', 'W2DC'); ?>" />
		</div>
		<div class="w2dc-col-md-6 w2dc-form-group w2dc-pull-right w2dc-text-right">
			<input type="button" id="w2dc-reset-fa-icon" class="w2dc-btn w2dc-btn-primary" value="<?php esc_attr_e('Reset Icon', 'W2DC'); ?>" />
		</div>
		<div class="w2dc-clearfix"></div>
	</div>

	<div class="w2dc-icons-theme-block">
	<?php foreach ($icons AS $icon): ?>
		<span class="w2dc-fa-icon w2dc-fa w2dc-fa-lg <?php echo $icon; ?>" id="<?php echo $icon; ?>" title="<?php echo $icon; ?>"></span>
	<?php endforeach;?>
	</div>
	<div class="w2dc-clearfix"></div>
</div>