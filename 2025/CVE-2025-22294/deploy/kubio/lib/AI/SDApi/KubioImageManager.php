<?php
namespace Kubio\Ai;

class KubioImageManager {
	private $folder = '/static/ai-assets/generated/';

	public function get_file_path_from_url( $url ) {
		return KUBIO_ROOT_DIR . $this->folder . basename( $url );
	}

	public function get_folder_path() {
		return $this->folder;
	}

	public function get_image_path( $output_file ) {
		return KUBIO_ROOT_DIR . $this->folder . $output_file;
	}

	public function save_from_base64( $base64_string, $filename = '' ) {
		if ( $filename === '' ) {
			$filename = wp_generate_uuid4() . '.png';
		}

		return $this->base64_to_image( $base64_string, $filename );
	}

	public function save_image_from_string( $image_string, $output_file = '' ) {
		if ( $output_file === '' ) {
			$output_file = wp_generate_uuid4() . '.png';
		}

		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen
		$filename = fopen( $this->get_image_path( $output_file ), 'wb' );

		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite
		fwrite( $filename, $image_string );

		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
		fclose( $filename );

		return kubio_url( $this->folder . $output_file );
	}


	public function base64_to_image( $base64_string, $output_file ) {

		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen
		$filename = fopen(
			$this->get_image_path( $output_file ),
			'wb'
		);

		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite
		fwrite(
			$filename,
			base64_decode(
				str_replace(
					'data:image/png;base64,',
					'',
					$base64_string
				)
			)
		);

		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
		fclose( $filename );

		return kubio_url( $this->folder . $output_file );
	}

	public function get_file_contents( $url ) {
		$path = $this->get_attachment_path( $url );

		if ( $path === false ) {
			return '';
		}

		return 'data:image/png;base64,' . base64_encode(
			file_get_contents(
				$path
			)
		);
	}

	public function save_image_from_url( $image_url, $output_file = '' ) {
		if ( $output_file === '' ) {
			$output_file = basename( $image_url );
		}

		$file_contents = file_get_contents( $image_url );

		//
	}


	public function get_attachment_path( $url ) {
		$path = false;

		$dir = wp_upload_dir();

		if ( false !== strpos( $url, $dir['baseurl'] . '/' ) ) {
			$file = basename( $url );
		}

		$query_args = array(
			'post_type'   => 'attachment',
			'post_status' => 'inherit',
			'fields'      => 'ids',
			// phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_query
			'meta_query'  => array(
				array(
					'value'   => $file,
					'compare' => 'LIKE',
					'key'     => '_wp_attachment_metadata',
				),
			),
		);

		$query      = new \WP_Query( $query_args );
		$upload_dir = wp_upload_dir();

		if ( $query->have_posts() ) {

			foreach ( $query->posts as $post_id ) {

				$meta = wp_get_attachment_metadata( $post_id );

				$original_file       = basename( $meta['file'] );
				$cropped_image_files = wp_list_pluck( $meta['sizes'], 'file' );

				if ( $original_file === $file || in_array( $file, $cropped_image_files ) ) {
					$path = $upload_dir['basedir'] . '/' . $meta['file'];
					break;
				}
			}
		}
		return $path;
	}
}
