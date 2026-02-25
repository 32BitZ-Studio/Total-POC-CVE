<?php

namespace Kubio\Blocks;

use Kubio\Core\Blocks\BlockBase;
use Kubio\Core\Registry;

class LanguageSelector extends BlockBase {
	const OUTER = 'outer';

	public function mapPropsToElements() {
		//$name = $this->getAttribute( 'name' );
		$content = '';
		if ( $this->getAttribute( 'show', false ) ) {
			$content = $this->getContent();
		}

		return array(
			self::OUTER => array(
				'innerHTML' => $content,
			),
		);
	}

	public function serverSideRender() {
		$content = $this->getContent();

		return $content;
	}

	public function getContent() {

		$is_editor        = $this->getAttribute( 'isEditor', false );
		$display_as_flags = $this->getAttribute( 'displayAs', false ) === 'flags';
		$show_flags       = $this->getAttribute( 'showFlags', false );
		$show_names       = $this->getAttribute( 'showNames', false );

		if ( $is_editor ) {
			$post_id = $this->getAttribute( 'postId' );
		} else {
			$post_id = get_the_ID();
		}

		$languages = pll_get_post_translations( $post_id );

		ob_start();
		?>
		<div class="wp-block-kubio-language-selector__wrapper <?php echo $is_editor ? '--is-editor' : ''; ?>">
			<?php
			pll_the_languages(
				array(
					'dropdown'     => ! $display_as_flags,
					'show_flags'   => $display_as_flags && $show_flags,
					'show_names'   => $display_as_flags && $show_names,
					'hide_current' => true,
				)
			)
			?>
		</div>
		<?php
		$content = ob_get_clean();
		return $content;
	}
}


Registry::registerBlock(
	__DIR__,
	LanguageSelector::class
);
