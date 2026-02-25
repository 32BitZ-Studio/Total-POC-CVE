<?php

namespace Kubio\Blocks;

use Kubio\Core\Blocks\BlockBase;
use Kubio\Core\GlobalElements\Icon;
use Kubio\Core\LodashBasic;
use Kubio\Core\Registry;

class PostMetaBlock extends BlockBase {


	const CONTAINER = 'metaDataContainer';

	private $postId;
	private $metaFunctionsMap = array();

	public function __construct( $block, $autoload = true, $context = array() ) {
		parent::__construct( $block, $autoload, $context );
		$this->metaFunctionsMap = array(
			'author'   => array(
				'content' => 'getAuthorContent',
				'url'     => 'getAuthorUrl',
			),
			'date'     => array(
				'content' => 'getDateContent',
				'url'     => 'getDateUrl',
			),
			'time'     => array(
				'content' => 'getTimeContent',
				'url'     => 'getTimeUrl',
			),
			'comments' => array(
				'content' => 'getCommentsContent',
				'url'     => 'getCommentsUrl',
			),
		);
	}

	public function mapPropsToElements() {
		$this->postId           = LodashBasic::get( $this->block_context, 'postId' );
		$map                    = array();
		$map[ self::CONTAINER ] = array(
			'innerHTML' => $this->getMetaItems(),
		);

		return $map;
	}

	private function getMetaItems() {
		$meta          = $this->getAttribute( 'metadata' );
		$metadata      = $this->parseItems( $meta );
		$show_icons    = $this->getAttribute( 'showIcons' );
		$separator     = $this->getAttribute( 'separator' );
		$is_last_index = count( $metadata ) - 1;
		ob_start();

		foreach ( $metadata as $index => $item ) {

			$item_value = LodashBasic::get( $item, 'value' );
			$icon       = new Icon( 'span', array( 'name' => $item['icon'] ) );

			?>
			<span class="metadata-item">
					<?php if ( $item['prefix'] !== '' ) : ?>
						<span class="metadata-prefix"> <?php echo esc_html( $item['prefix'] ); ?> </span>
					<?php endif; ?>

					<a href="<?php echo esc_url( $this->getHref( $item_value ) ); ?>">
						<?php if ( $show_icons ) : ?>
							<?php echo wp_kses_post( $icon ); ?>
						<?php endif; ?>
						<?php echo wp_kses_post( $this->getItemContent( $item_value ) ); ?>
					</a>

					<?php if ( $item['suffix'] != '' ) : ?>
						<span class="metadata-suffix"> <?php echo esc_html( $item['suffix'] ); ?> </span>
					<?php endif; ?>
			</span>
			<?php if ( $is_last_index > $index && $separator != '' ) : ?>
				<span class="metadata-separator"> <?php echo esc_html( $separator ); ?> </span>
			<?php endif; ?>

			<?php
		}

		return ob_get_clean();
	}

	private function parseItems( $items ) {
		$sorted_items = array();
		foreach ( $items as $item ) {
			$check_value = LodashBasic::get( $item, 'check' );
			if ( $check_value === 'true' || $check_value === true ) {
				$sorted_items[] = $item;
			}
		}

		return $sorted_items;
	}

	private function getHref( $item_name ) {

		return $this->getUrl( $item_name );
	}

	public function getUrl( $type, $arg = array() ) {
		$function_name = LodashBasic::get( $this->metaFunctionsMap, array( $type, 'url' ) );
		if ( $function_name ) {
			return call_user_func( array( $this, $function_name ), $arg );
		}

		return '';
	}

	private function getItemContent( $item_name ) {

		$atts = array();
		if ( $item_name === 'date' ) {
			$atts['dateformat'] = $this->getAttribute( 'dateFormat' );
		}

		return $this->getContent( $item_name, $atts );
	}

	public function getContent( $type, $arg ) {
		$function_name = LodashBasic::get( $this->metaFunctionsMap, array( $type, 'content' ) );
		if ( $function_name ) {
			return call_user_func( array( $this, $function_name ), $arg );
		}
	}

	public function serverSideRender() {
		$this->postId = $this->getAttribute( 'editorContext.postId' );

		return $this->getMetaItems();
	}

	public function getAuthorContent() {
		$author_id = get_post_field( 'post_author', $this->postId );
		$content   = get_the_author_meta( 'display_name', $author_id );

		return apply_filters( 'kubio_post_meta_author_content', $content );
	}

	public function getAuthorUrl() {
		$author_id = get_post_field( 'post_author', $this->postId );
		$url       = get_author_posts_url( $author_id );

		return apply_filters( 'kubio_post_meta_author_url', $url );
	}

	public function getDateContent( $atts ) {
		$atts    = shortcode_atts(
			array(
				'dateformat' => '',
			),
			$atts
		);
		$format  = apply_filters( 'kubio_post_meta_date_format', $atts['dateformat'] );
		$date    = get_the_date( $format, $this->postId );
		$content = apply_filters( 'kubio_post_meta_date_content', $date, $format );

		return $content;
	}

	public function getDateUrl() {
		$id   = $this->postId;
		$link = get_day_link(
			get_post_time( 'Y', false, $id, true ),
			get_post_time( 'm', false, $id, true ),
			get_post_time( 'j', false, $id, true )
		);

		return apply_filters( 'kubio_post_meta_date_url', $link );
	}

	public function getTimeContent() {
		$time = get_the_time( '', $this->postId );

		return apply_filters( 'kubio_post_meta_time_content', $time );
	}

	public function getTimeUrl() {
		$time = '';

		return apply_filters( 'kubio_post_meta_time_url', $time );
	}

	public function getCommentsUrl() {
		$url = get_comments_link( $this->postId );

		return apply_filters( 'kubio_post_meta_comments_url', $url );
	}

	public function getCommentsContent() {
		$content = get_comments_number( $this->postId );

		return apply_filters( 'kubio_post_meta_comments_content', $content );
	}
}


Registry::registerBlock( __DIR__, PostMetaBlock::class );
