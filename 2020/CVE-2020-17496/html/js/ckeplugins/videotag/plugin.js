/*!=======================================================================*\
|| ###################################################################### ||
|| # vBulletin 5.6.0
|| # ------------------------------------------------------------------ # ||
|| # Copyright 2000-2020 MH Sub I, LLC dba vBulletin. All Rights Reserved.  # ||
|| # This file may not be redistributed in whole or significant part.   # ||
|| # ----------------- VBULLETIN IS NOT FREE SOFTWARE ----------------- # ||
|| # http://www.vbulletin.com | http://www.vbulletin.com/license.html   # ||
|| ###################################################################### ||
\*========================================================================*/

CKEDITOR.plugins.add('videotag', {
	requires: 'dialog',
	init: function( editor ) {
		editor.addCommand( 'videotag', new CKEDITOR.dialogCommand( 'videotag' ) );
		editor.ui.addButton && editor.ui.addButton( 'Video', {
			label: vBulletin.phrase.get('insert_video'),
			command:  'videotag',
			// The 'default' bit in this path can change to 'dark' (or something else) based
			// on the ckeditor_image_path stylevar. It's automatically changed in ckeditor.js
			// in modifyImagePaths().
			icon: window.pageData.baseurl + '/js/ckeditor/images/default/vbulletin/video.png'
		});
		CKEDITOR.dialog.add( 'videotag', vBulletin.ckeditor.config.pluginPath + 'videotag/dialogs/videotag.js' );
	}
});

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
