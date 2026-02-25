<?php

/**
 * [WCSEARCH_MAIN_SHORTCODE] works in this way:
 * $search_controller($args) {
 * 		$search_form = new wcsearch_search_form($args)
 * 		$search_form->display($args)
 * }
 * 
 */
$search_form->getSearchFormStyles();
?>
<div id="wcsearch-search-wrapper-<?php echo $search_form->search_form_id; ?>" class="wcsearch-content wcsearch-search-wrapper">
	<?php if ($search_form->args['sticky_scroll']): ?>
	<div class="wcsearch-sticky-scroll">
	<?php endif; ?>
	
	<?php if (current_user_can("manage_options") && !empty($args['id'])): ?>
	<?php wcsearch_getEditFormIcon($args['id']); ?>
	<?php endif; ?>
	<?php do_action("wcsearch_pre_search_form", $args); ?>
	<form <?php echo $search_form->getOptionsString(); ?>>
		<div class="wcsearch-search">
			<div class="wcsearch-search-column wcsearch-search-column-<?php echo esc_attr($search_form->args['columns_num']); ?>">
				<div class="wcsearch-search-grid <?php echo $search_form->getOverlayClasses(); ?>" <?php echo $search_form->getOverlayAttributes(); ?>>
					<?php $search_form_model->buildLayout(true); ?>
				</div>
			</div>
		</div>
		<?php $search_form->outputHiddenFields(); ?>
	</form>
	<?php do_action("wcsearch_post_search_form", $args); ?>
	
	<?php if ($search_form->args['sticky_scroll']): ?>
	</div>
	<?php endif; ?>
</div>