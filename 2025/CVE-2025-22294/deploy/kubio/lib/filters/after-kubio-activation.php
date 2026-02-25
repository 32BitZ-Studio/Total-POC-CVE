<?php

use Kubio\Flags;

function kubio_set_editor_ui_version() {
	Flags::setSetting( 'editorUIVersion', 2 );
	Flags::setSetting( 'editorMode', 'advanced' );
	Flags::setSetting( 'activatedOnStage2', true );
	Flags::setSetting( 'aiStage2', apply_filters( 'kubio/ai_stage_2', false ) || ( defined( 'KUBIO_AI_STAGE_2' ) && KUBIO_AI_STAGE_2 ) );
	Flags::setSetting( 'advancedMode', apply_filters( 'kubio/advanced_mode_enabled', false ) );
	Flags::setSetting( 'featuresVersion', apply_filters( 'kubio/featuresVersion', 2 ) );
	Flags::setSetting( 'enableBlogAsFrontPageFromGeneralSettings', true );
}


//after the theme changes update the aiStage2 flag
add_filter(
	'after_switch_theme',
	function () {
		Flags::setSetting( 'aiStage2', apply_filters( 'kubio/ai_stage_2', false ) || ( defined( 'KUBIO_AI_STAGE_2' ) && KUBIO_AI_STAGE_2 ) );
	}
);

add_action( 'kubio/after_activation', 'kubio_set_editor_ui_version' );
add_action( 'kubio/after_activation', '_kubio_set_fresh_site' );

//For this issue. https://mantis.iconvert.pro/view.php?id=52025. On Bluehost all the rest api return 404 and needs a flush permalink to fix it
add_action( 'kubio/after_activation', 'flush_rewrite_rules' );
add_action(
	'kubio/after_activation',
	function () {
		Flags::setSetting( 'aiWizardDescriptionOptional', true );
	}
);
