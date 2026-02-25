<?php
global $w2dc_instance;
$frontend_controller = new w2dc_directory_controller();
$frontend_controller->init();
w2dc_setFrontendController(W2DC_MAIN_SHORTCODE, $frontend_controller);

if ($w2dc_instance->action == 'pdflisting')
	$pdflisting = true;
else
	$pdflisting = false;

?>

<!DOCTYPE html>
<!--[if IE 7]>
<html class="ie ie7" <?php language_attributes(); ?>>
<![endif]-->
<!--[if IE 8]>
<html class="ie ie8" <?php language_attributes(); ?>>
<![endif]-->
<!--[if !(IE 7) | !(IE 8)  ]><!-->
<html <?php language_attributes(); ?>>
<!--<![endif]-->
<head>
	<meta charset="<?php bloginfo( 'charset' ); ?>" />
	<?php wp_head(); ?>
</head>

<body <?php body_class(); ?> style="background-color: #FFF">
	<div id="page" class="site w2dc-content w2dc-print">
		<div id="main" class="wrapper">
			<div class="w2dc-container-fluid entry-content">
				<?php the_custom_logo(); ?>
				
				<?php if (!$pdflisting): ?>
				<div class="w2dc-print-buttons w2dc-row w2dc-clearfix">
					<div class="w2dc-col-sm-12">
						<input type="button" class="w2dc-btn w2dc-btn-primary" onclick="window.print();" value="<?php esc_attr_e('Print listing', 'W2DC'); ?>" />
						<input type="button" class="w2dc-btn w2dc-btn-primary" onclick="window.close();" value="<?php esc_attr_e('Close window', 'W2DC'); ?>" />
					</div>
				</div>
				<?php endif; ?>

			<?php while ($frontend_controller->query->have_posts()): ?>
				<?php $frontend_controller->query->the_post(); ?>
				<?php $listing = $frontend_controller->listings[get_the_ID()]; ?>
				<?php if (get_the_title()): ?>
				<div class="w2dc-row w2dc-clearfix w2dc-listing-header">
					<div class="w2dc-col-sm-12">
						<h2><?php the_title(); ?> <?php do_action('w2dc_listing_title_html', $listing, false); ?></h2>
					</div>
				</div>
				<?php endif;?>

				<?php if ($listing->logo_image): ?>
				<div class="w2dc-listing-logo-wrap">
					<?php do_action('w2dc_listing_pre_logo_wrap_html', $listing); ?>
					<div class="w2dc-listing-logo">
						<img src="<?php echo $listing->get_logo_url(); ?>" />
					</div>
				</div>
				<?php endif; ?>

				<div class="w2dc-listing-text-content-wrap entry-content">
					<?php do_action('w2dc_listing_pre_content_html', $listing); ?>

					<em class="w2dc-listing-date"><?php echo get_the_date(); ?> <?php echo get_the_time(); ?></em>

					<?php $listing->renderContentFields(true); ?>
					
					<?php if ($fields_groups = $listing->getFieldsGroupsOnTabs()): ?>
					<?php foreach ($fields_groups AS $fields_group): ?>
						<?php echo $fields_group->renderOutput($listing, true); ?>
					<?php endforeach; ?>
					<?php endif; ?>
					
					<?php do_action('w2dc_listing_post_content_html', $listing); ?>
				</div>
				<div class="w2dc-clearfix"></div>

				<?php if (get_option('w2dc_map_on_single') && $listing->isMap()): ?>
				<h2><?php _e('Map', 'W2DC'); ?></h2>
				<?php $listing->renderMap($frontend_controller->hash, false, true); ?>
				<?php endif; ?>
				
				<?php if (count($listing->images) > 1): ?>
				<h2><?php _e('Images', 'W2DC'); ?> (<?php echo count($listing->images); ?>)</h2>
				<?php foreach ($listing->images AS $attachment_id=>$image): ?>
					<?php $src_thumbnail = wp_get_attachment_image_src($attachment_id, 'large'); ?>
					<div style="margin: 10px">
						<img src="<?php echo $src_thumbnail[0]; ?>"/>
					</div>
				<?php endforeach; ?>
				<?php endif; ?>

				<?php if (w2dc_comments_open()): ?>
				<?php w2dc_comments_system($listing); ?>
				<?php endif; ?>
			<?php endwhile; ?>

				<?php if (!$pdflisting): ?>
				<div class="w2dc-print-buttons w2dc-row">
					<div class="w2dc-col-sm-12">
						<input type="button" class="w2dc-btn w2dc-btn-primary" onclick="window.print();" value="<?php esc_attr_e('Print listing', 'W2DC'); ?>" />
						<input type="button" class="w2dc-btn w2dc-btn-primary" onclick="window.close();" value="<?php esc_attr_e('Close window', 'W2DC'); ?>" />
					</div>
				</div>
				<?php endif; ?>
			</div>
		</div>
	</div>
<?php wp_footer(); ?>
</body>
</html>