<?php

namespace Kubio;

use DateTime;

class NotificationsManager {

	private static $remote_data_url_base = 'https://kubiobuilder.com/wp-json/wp/v2/notification';

	public static function load() {
		add_action( 'admin_init', array( NotificationsManager::class, 'init' ) );
		if ( ! wp_next_scheduled( NotificationsManager::class . '::init' ) ) {
			wp_schedule_event( time(), 'twicedaily', NotificationsManager::class . '::init' );
		}
	}

	/**
	 * Checks if this WordPress instances is declared as a development environment.
	 * Relies on the `KUBIO_NOTIFICATIONS_DEV_MODE` constant.
	 *
	 * @return bool
	 */
	private static function isDevMode() {
		return ( defined( 'KUBIO_NOTIFICATIONS_DEV_MODE' ) && KUBIO_NOTIFICATIONS_DEV_MODE );
	}

	/**
	 * Verifies the data and displays remote notifications accordingly.
	 *
	 * @return void
	 */
	public static function init() {

		// check if we have cached data in transient
		$notifications = get_transient( static::getTransientKey() );

		if ( $notifications === false || self::isDevMode() ) {
			// No notifications, try to get them from remote and cache them.
			static::prepareRetrieveRemoteNotifications();
		}

		static::displayNotifications( $notifications );

		add_action( 'wp_ajax_kubio-remote-notifications-retrieve', array( NotificationsManager::class, 'updateNotificationsData' ) );
	}

	/**
	 * Adds a JavaScript code which fetches notifications asynchronously.
	 *
	 * @return void
	 */
	public static function prepareRetrieveRemoteNotifications() {

		add_action(
			'admin_footer',
			function () {
				$fetch_url = add_query_arg(
					array(
						'action'   => 'kubio-remote-notifications-retrieve',
						'_wpnonce' => wp_create_nonce( 'kubio-remote-notifications-retrieve-nonce' ),

					),
					admin_url( 'admin-ajax.php' )
				); ?>
					<script>
						window.fetch("<?php echo esc_url_raw( $fetch_url ); ?>")
					</script>
					<?php
			}
		);
	}

	/**
	 * Retrieves notifications and saves them in a transient.
	 *
	 * @return void
	 */
	public static function updateNotificationsData() {
		check_ajax_referer( 'kubio-remote-notifications-retrieve-nonce' );

		$url = add_query_arg(
			array(
				'_fields'             => 'acf,id',
				// phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_key
				'meta_key'            => 'license_type',
				// phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_value
				'meta_value'          => apply_filters( 'kubio/notifications/license_type', 'free' ),
				'kubio_version'       => KUBIO_VERSION,
				'kubio_build'         => KUBIO_BUILD_NUMBER,
				'kubio_theme_version' => wp_get_theme()->get( 'Version' ),
				'template'            => get_template(),
				'stylesheet'          => get_stylesheet(),
				'source'              => Flags::get( 'start_source', 'other' ),
				'f'                   => Flags::get( 'kubio_f' ),
				'activated_on'        => Flags::get( 'kubio_activation_time', '' ),
				'pro_activated_on'    => Flags::get( 'kubio_pro_activation_time', '' ),
			),
			self::$remote_data_url_base
		);

		$data = wp_remote_get( $url );

		$code = wp_remote_retrieve_response_code( $data );
		$body = wp_remote_retrieve_body( $data );

		$posts = json_decode( $body, true );

		if ( $code !== 200 ) {
			wp_send_json_error( $code );
		}

		$notifications = array();

		foreach ( $posts as $post ) {
			$notifications[ $post['id'] ] = $post;
		}

		$done = set_transient( static::getTransientKey(), $notifications, DAY_IN_SECONDS );

		wp_send_json_success( $done );
	}

	/**
	 * Adds the stack of notifications for display using `kubio_add_dismissable_notice`.
	 *
	 * @param array $notifications
	 * @return void
	 */
	private static function displayNotifications( $notifications ) {

		if ( empty( $notifications ) ) {
			return;
		}

		foreach ( $notifications as $notification ) {
			$params       = $notification['acf'];
			$params['id'] = $notification['id'];

			if ( $params['dev'] === true && ! self::isDevMode() ) {
				continue;
			}

			if ( ! self::isTimeToDisplay( $params ) ) {
				continue;
			}

			$classnames    = 'kubio-remote-notification';
			$allowed_types = array( 'info', 'warning', 'error', 'success' );

			if ( ! empty( $params['type'] ) && in_array( $params['type'], $allowed_types ) ) {
				$classnames .= ' notice-' . $params['type'] . ' kubio-remote-notification-' . $params['type'];
			}

			$notice_key = 'kubio-remote-notice-' . $params['id'];

			if ( self::isDevMode() ) {
				$notice_key .= '-' . time();
			}

			kubio_add_dismissable_notice(
				$notice_key,
				array( NotificationsManager::class, 'displayNotification' ),
				0,
				$params,
				$classnames
			);
		}
	}

	/**
	 * Prints the HTML of a notification for the given params.
	 *
	 * @param $params
	 * @return void
	 */
	public static function displayNotification( $params ) {
		$link  = $params['primary_link'];
		$slink = $params['secondary_link'];

		$args = array(
			'utm_theme'            => get_template(),
			'utm_childtheme'       => get_stylesheet(),
			'utm_install_source'   => Flags::get( 'start_source', 'other' ),
			'utm_activated_on'     => Flags::get( 'kubio_activation_time', '' ),
			'utm_pro_activated_on' => Flags::get( 'kubio_pro_activation_time', '' ),
			'utm_campaign'         => 'wp-notice',
			'utm_medium'           => 'wp',
		);

		if ( ! empty( $link ) ) {
			$link['url'] = add_query_arg( $args, $link['url'] );
		}

		if ( ! empty( $slink ) ) {
			$slink['url'] = add_query_arg( $args, $slink['url'] );
		}

		wp_enqueue_script( 'wp-util' ); // make sure to enqueue the admin ajax functions
		?>
		<div class="kubio-remote-notification-wrapper" id="kubio-remote-notification-<?php echo esc_attr( $params['id'] ); ?>">
			<div class="kubio-remote-notification-icon">
				<?php
				// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
				echo wp_kses_post( KUBIO_LOGO_SVG );
				?>
			</div>
			<?php if ( ! empty( $params['message'] ) ) { ?>
				<div class="kubio-remote-notification-message">
				<?php
					// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
					echo wpautop( $params['message'] );
				?>
					</div>
			<?php } ?>
			<div class="kubio-remote-notification-buttons">
				<?php if ( ! empty( $link ) ) { ?>
					<a target="_blank" href="<?php echo esc_url( $link['url'] ); ?>" class="button button-large kubio-remote-notification-primary"><?php echo esc_html( $link['title'] ); ?></a>
					<?php
				}

				if ( ! empty( $slink ) ) {
					?>
					<a target="_blank" href="<?php echo esc_url( $slink['url'] ); ?>" class="button button-link kubio-remote-notification-secondary"><?php echo esc_html( $slink['title'] ); ?></a>
				<?php } ?>
			</div>
		</div>
		<?php
	}

	/**
	 * Verify if the notification checks the time requirements.
	 *
	 * @param array $params Notification parameters.
	 * @return bool
	 */
	private static function isTimeToDisplay( array $params ) {

		if ( $params['has_time_boundary'] === true ) {
			return self::inTimeBoundaries( $params['start_date'], $params['date_end'] );
		}

		$install_time = Flags::get( 'kubio_activation_time', time() );

		$install_time = apply_filters( 'kubio/notifications/install_time', $install_time );

		$show_after = strtotime( '+' . $params['after'] . ' days', $install_time );
		$time       = new DateTime( 'NOW' );

		if ( $show_after <= $time->getTimeStamp() ) {
			return true;
		}

		return false;
	}

	/**
	 * Checks if the current time is between a given $start and $end date.
	 * If $start or $end are null that generally means there is no restrain for that edge.
	 *
	 * @param $start
	 * @param $end
	 * @return bool
	 */
	private static function inTimeBoundaries( $start, $end ) {
		$time       = new DateTime( 'today' );
		$start_date = \DateTime::createFromFormat( 'Ymd', $start );

		if ( $start === null || $start_date && $start_date <= $time ) {
			$end_date = \DateTime::createFromFormat( 'Ymd', $end );

			if ( $end === null || $end_date && $time <= $end_date ) {
				return true;
			}
		}

		return false;
	}

	private static function getTransientKey() {
		$transient = apply_filters( 'kubio/notifications/transient_key', 'kubio_remote_notifications' );
		return $transient;
	}
}
