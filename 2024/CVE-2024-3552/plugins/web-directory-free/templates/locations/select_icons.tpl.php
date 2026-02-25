		<input type="button" id="reset_icon" class="button button-primary button-large w2dc-btn w2dc-button-primary" value="<?php esc_attr_e('Reset icon image', 'W2DC'); ?>" />

		<table width="100%" cellpadding="0" cellspacing="0">
			<tr>
			<?php $i = 0; ?>
			<?php foreach ($custom_map_icons AS $theme=>$dir): ?>
				<?php if (is_array($dir) && count($dir)): ?>
				<?php $columns = 1; ?>
				<td align="left" valign="top" width="<?php echo 100/$columns; ?>%">
					<div class="w2dc-icons-theme-block">
						<div class="w2dc-icons-theme-name"><?php echo $theme; ?></div>
						<?php foreach ($dir AS $icon): ?>
							<div class="w2dc-icon" icon_file="<?php echo $theme . '/' . $icon; ?>"><img src="<?php echo W2DC_MAP_ICONS_URL . 'icons/' . $theme . '/' . $icon; ?>" title="<?php echo $theme . '/' . $icon; ?>" /></div>
						<?php endforeach;?>
					</div>
					<div class="w2dc-clearfix"></div>
				</td>
				<?php if ($i++ == $columns-1): ?>
					</tr><tr>
					<?php $i = 0; ?>
				<?php endif;?>
				<?php endif;?>
			<?php endforeach;?>
			</tr>
		</table>