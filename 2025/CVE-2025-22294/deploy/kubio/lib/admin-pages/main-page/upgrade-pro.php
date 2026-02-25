<?php

$kubio_upgrade_url = kubio_get_site_url_for(
	'upgrade',
	array(
		'source'      => 'upgrade',
		'content'     => 'no-license',
		'upgrade_key' => apply_filters( 'kubio/upgrade-key', '' ),
	)
);

?>
<div class="tab-page kubio-upgrade-to-pro-page">
	<div class="limited-width">
		<div class="kubio-admin-page-section">
			<div class="kubio-admin-page-section-content">
				

				<div class="kubio-upgrade-to-pro-columns">
				<div class="kubio-upgrade-to-pro-upgrade-column">
					<p>
					<span class="kubio-text-primary kubio-text-700"><?php esc_html_e( 'Thank you for your interest in Kubio!', 'kubio' ); ?></span>
					<?php esc_html_e( 'Upgrading to Kubio PRO gives you access to advanced features and tools to create a truly professional website—effortlessly.', 'kubio' ); ?>
					</p>
					<div>
					<h3><?php esc_html_e( 'How to Upgrade in 3 Simple Steps', 'kubio' ); ?></h3>
					<ol>
						<li>
							<?php
							printf(
								// translators: %s: Upgrade to Kubio PRO link.
								esc_html__( '%s - Select the plan that fits your needs.', 'kubio' ),
								'<a href="' . esc_url( $kubio_upgrade_url ) . '" target="_blank" class="kubio-text-primary kubio-text-700">' . esc_html__( 'Purchase a Kubio PRO License', 'kubio' ) . '</a>'
							);
							?>
						</li>
						<li>
							<?php
							printf(
								// translators: %s: Download the Kubio PRO Plugin link.
								esc_html__( '%s - A download link will be provided after purchase.', 'kubio' ),
								'<strong>' . esc_html__( 'Download the Kubio PRO Plugin', 'kubio' ) . '</strong>'
							);
							?>
						</li>
						<li>
							<?php
							printf(
								// Translators: %1$s: Install & Activate, %2$s: Add New.
								esc_html__( '%1$s - Upload the ZIP file via WordPress > Plugins > %2$s, then enter your license key to activate PRO features instantly.', 'kubio' ),
								'<strong>' . esc_html__( 'Install & Activate', 'kubio' ) . '</strong>',
								'<a href="' . esc_url( admin_url( 'plugin-install.php' ) ) . '" target="_blank" class="kubio-text-primary kubio-text-700">' . esc_html__( 'Add New', 'kubio' ) . '</a>'
							);

							?>
						</li>
					</ol>
					</div>

					<div class="upgrade-to-pro-button">
						<a href="<?php echo esc_url( $kubio_upgrade_url ); ?>" target="_blank" class="button button-primary button-hero">
							<?php esc_html_e( 'Upgrade to Kubio PRO', 'kubio' ); ?>
						</a>
					</div>
					</div>
					<div class="kubio-upgrade-to-pro-features-column" style="background-image: url(<?php echo esc_url( kubio_url( 'static/admin-pages/upgrade-side-background.jpg' ) ); ?>) ;">
						<h3><?php esc_html_e( 'Why Choose Kubio PRO?', 'kubio' ); ?></h3>
						<p><?php esc_html_e( 'Upgrade now and enjoy the full power of Kubio PRO!', 'kubio' ); ?></p>
						<ul class="ul-disc">
							<li><?php echo wp_kses( __( '<strong>AI-Powered Website Creation</strong> - Instantly generate pages, images, and text.', 'kubio' ), array( 'strong' => array() ) ); ?></li>
							<li><?php echo wp_kses( __( '<strong>50+ Advanced Blocks</strong> - Add sliders, pricing tables, carousels, and more.', 'kubio' ), array( 'strong' => array() ) ); ?></li>
							<li><?php echo wp_kses( __( '<strong>340+ Pre-Designed Sections</strong> - Choose from professionally crafted layouts for faster design.', 'kubio' ), array( 'strong' => array() ) ); ?></li>
							<li><?php echo wp_kses( __( '<strong>Multiple Headers & Footers</strong> - Fully customize headers, footers, and templates.', 'kubio' ), array( 'strong' => array() ) ); ?></li>
							<li><?php echo wp_kses( __( '<strong>Premium Support & Updates</strong> - We got you covered with priority support and continuous enhancements.', 'kubio' ), array( 'strong' => array() ) ); ?></li>
						</ul>
					</div>
					
				</div>

				
			</div>
		</div>
	</div>
</div>
