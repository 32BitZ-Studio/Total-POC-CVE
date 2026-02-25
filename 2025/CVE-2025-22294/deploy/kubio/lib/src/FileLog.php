<?php

namespace Kubio;

/**
 * @method static info( string $location, string|array $message)
 * @method static error( string $location, string|array $message)
 * @method static warning( string $location, string|array $message)
 * @method static FileLog with_type( string $type )
 * @method info( string $location, string|array $message)
 * @method error( string $location, string|array $message)
 * @method warning( string $location, string|array $message)
 * @method FileLog with_type( string $type )
 */
class FileLog {

	const CLASSIC_LOG = 'classic';
	const JSONL_LOG   = 'jsonl';

	private $log_type = 'classic';



	private static function get_logs_root_path( $location ) {
		$upload_dir = wp_upload_dir();
		$base_dir   = untrailingslashit( $upload_dir['basedir'] ) . "/kubio-log/{$location}";

		return $base_dir;
	}

	private function prepare_file( $location, $type ) {
		$type = strtolower( $type );

		$base_dir = static::get_logs_root_path( $location );

		if ( ! file_exists( $base_dir ) ) {
			$result = wp_mkdir_p( $base_dir );

			if ( ! $result ) {
				return false;
			}
		}

		$date      = gmdate( 'Y-m-d' );
		$extension = 'log';

		switch ( $this->log_type ) {
			case static::JSONL_LOG:
				$extension = 'jsonl';
				break;
		}

		$file_path = "{$base_dir}/{$type}-{$date}.{$extension}";

		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_is_writable
		if ( file_exists( $file_path ) && ! is_writable( $file_path ) ) {
			return false;
		}

		return $file_path;
	}

	private function classic_log( $location, $message, $type = 'info' ) {

		$file_path = $this->prepare_file( $location, $type );

		if ( ! $file_path ) {
			return;
		}

		$response = file_put_contents(
			$file_path,
			sprintf(
				"LOG: %s ---------- %s ----------\n\n\n%s\n\n",
				str_pad( $type, 6 ),
				gmdate( 'Y-m-d H:i:s' ),
				// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_var_export
				is_string( $message ) ? trim( $message ) : var_export( $message, true )
			),
			FILE_APPEND
		);

		if ( $response === false ) {
			return false;
		}

		return true;
	}

	private function jsonl_log( $location, $message, $type = 'info' ) {
		$file_path = $this->prepare_file( $location, $type );

		if ( ! $file_path ) {
			return;
		}

		$content = array(
			'type' => $type,
			'date' => time(),
			'data' => $message,
		);

		$response = file_put_contents(
			$file_path,
			json_encode( $content ) . "\n",
			FILE_APPEND
		);

		if ( $response === false ) {
			return false;
		}

		return true;
	}

	private function store_log( $location, $message, $type = 'info' ) {

		switch ( $this->log_type ) {
			case static::JSONL_LOG:
				$result = $this->jsonl_log( $location, $message, $type );
				break;
			default:
				$result = $this->classic_log( $location, $message, $type );
		}

		return $result;
	}

	private function log_info( $location, $message ) {
		return $this->store_log( $location, $message, 'info' );
	}

	private function log_error( $location, $message ) {
		return $this->store_log( $location, $message, 'error' );
	}

	private function log_warning( $location, $message ) {
		return $this->store_log( $location, $message, 'warning' );
	}

	public function set_type( $type = FileLog::CLASSIC_LOG ) {
		$this->log_type = $type;
		return $this;
	}


	public function __call( $name, $arguments ) {
		switch ( $name ) {
			case 'with_type':
				return $this->set_type( ...$arguments );
			case 'info':
				return $this->log_info( ...$arguments );
			case 'warning':
				return $this->log_warning( ...$arguments );
			case 'error':
				return $this->log_error( ...$arguments );
		}
	}

	public static function __callStatic( $name, $arguments ) {
		$instance = new static();
		return call_user_func_array( array( $instance, $name ), $arguments );
	}

	public static function get_log_files( $location ) {
		$root = static::get_logs_root_path( $location );

		if ( ! file_exists( $root ) ) {
			return array();
		}

		$files = array_diff( scandir( $root ), array( '.', '..' ) );

		$log_files = array();
		foreach ( $files as $file ) {
			$key               = filemtime( "{$root}/{$file}" );
			$log_files[ $key ] = "{$root}/{$file}";
		}

		krsort( $log_files, SORT_NUMERIC );

		return $log_files;
	}
}
