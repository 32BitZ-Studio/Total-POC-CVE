<?php
$kubio_ai_key = kubio_ai_get_key();
?>

<div class="tab-page kubio-ai-info-tab">
	<div class="get-started-with-kubio limited-width">
	<div class="kubio-admin-page-section">
			<div class="kubio-admin-page-section-header">
				<h2 class="kubio-admin-page-section-title"><?php echo esc_html( 'Kubio AI', 'kubio' ); ?></h2>
			</div>
			<div class="kubio-admin-page-section-content" id="kubio-ai-info-content">
				<p class="spinner-holder">
					<?php
					// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
					printf(
						// translators: %s: spinner icon
						esc_html__( '%s Retrieving data...', 'kubio' ),
						sprintf(
							'<span class="loader">%s</span>',
							// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
							kubio_get_iframe_loader(
								array(
									'size'  => '19px',
									'color' => '#2271B1',
								)
							)
						)
					);
					?>
				</p>
			</div>
	</div>
</div>

<?php
wp_add_inline_script(
	'kubio-admin-area',
	sprintf(
		'window.aiInfoInit(%s)',
		json_encode(
			array(
				'connected'     => ! ! $kubio_ai_key,
				'loader_iframe' => kubio_get_iframe_loader(
					array(
						'size'  => '19px',
						'color' => '#2271B1',
					)
				),
			)
		)
	)
);
?>
