/**
 * @license Copyright (c) 2003-2019, CKSource - Frederico Knabben. All rights reserved.
 * For licensing, see LICENSE.md or https://ckeditor.com/legal/ckeditor-oss-license
 */

/**
 * @fileOverview The Auto Grow plugin.
 */

'use strict';

( function() {
	CKEDITOR.plugins.add( 'autogrow', {
		init: function( editor ) {
			// This feature is available only for themed ui instance.
			if ( editor.elementMode == CKEDITOR.ELEMENT_MODE_INLINE )
				return;

			editor.on( 'instanceReady', function() {
				// Simply set auto height with div wysiwyg.
				if ( editor.editable().isInline() )
					editor.ui.space( 'contents' ).setStyle( 'height', 'auto' );
				// For classic (`iframe`-based) wysiwyg we need to resize the editor.
				else
					initIframeAutogrow( editor );
			} );
		}
	} );

	function initIframeAutogrow( editor ) {
		var lastHeight,
			doc,
			markerContainer,
			scrollable,
			marker,
			configBottomSpace = editor.config.autoGrow_bottomSpace || 0,
			configMinHeight = editor.config.autoGrow_minHeight !== undefined ? editor.config.autoGrow_minHeight : 200,
			configMaxHeight = editor.config.autoGrow_maxHeight || Infinity,
			maxHeightIsUnlimited = !editor.config.autoGrow_maxHeight;


		// vBulletin modification VBV-15666, VBV-16116
		var viewportLimitEnabled = editor.config.autoGrow_viewportLimit || false,
			viewportLimitHeight = configMaxHeight, // updated later via call to getViewportLimitHeight()
			autogrowDisabledByResize = false,
			autogrowDisabledRuntime = false;
		configMinHeight = typeof(editor.config.autoGrow_minHeight) !== 'undefined' ? editor.config.autoGrow_minHeight : 200;
		maxHeightIsUnlimited = !(viewportLimitEnabled || editor.config.autoGrow_maxHeight),
		// end vBulletin modification


		editor.addCommand( 'autogrow', {
			exec: resizeEditor,
			modes: { wysiwyg: 1 },
			readOnly: 1,
			canUndo: false,
			editorFocus: false
		} );


		// vBulletin modification
		editor.addCommand('autogrow_ifallowed', {
			exec: resizeEditorIfAllowed,
			modes: {wysiwyg: 1},
			readOnly: 1,
			canUndo: false,
			editorFocus: false
		});
		// end vBulletin modification


		var eventsList = { contentDom: 1, key: 1, selectionChange: 1, insertElement: 1, mode: 1 };
		for ( var eventName in eventsList ) {
			editor.on( eventName, function( evt ) {
				// Some time is required for insertHtml, and it gives other events better performance as well.
				if ( evt.editor.mode == 'wysiwyg' ) {
					setTimeout( function() {
						if ( isNotResizable() ) {
							lastHeight = null;
							return;
						}

						resizeEditor();

						// Second pass to make correction upon the first resize, e.g. scrollbar.
						// If height is unlimited vertical scrollbar was removed in the first
						// resizeEditor() call, so we don't need the second pass.
						if ( !maxHeightIsUnlimited )
							resizeEditor();
					}, 100 );
				}
			} );
		}

		// Coordinate with the "maximize" plugin. (https://dev.ckeditor.com/ticket/9311)
		editor.on( 'afterCommandExec', function( evt ) {
			if ( evt.data.name == 'maximize' && evt.editor.mode == 'wysiwyg' ) {
				if ( evt.data.command.state == CKEDITOR.TRISTATE_ON )
					scrollable.removeStyle( 'overflow-y' );
				else
					resizeEditor();
			}
		} );


		// vBulletin modification VBV-15666, VBV-15713

		// VBV-15713 Coordinate with the "resize" plugin. Requires the custom event fired by dragEndHandler.
		editor.on('dragResizeEnd', function(evt)
		{
			autogrowDisabledByResize = true;
			console.log("Autogrow disabled due to manual resize!");
			/*
				Instead of permanently disabling autogrow then dropping this listener like it's hot, we could
				potentially do things like only disable autogrow if resized outside of source mode, only disable
				autogrow in one direction (e.g. always allow growth upto limit but disallow shortening), or
				re-enable autogrow when changed from source->wysiwyg mode, etc. depending on review & feedback.

				We may also want to remove listeners and such to free up some memory if we're disabling autogrow
				permanently for this instance.
			 */
			evt.removeListener();
		});

		// Manual disable.
		editor.on('disableResize', function(evt)
		{
			autogrowDisabledRuntime = true;
			console.log("Autogrow disabled due to runtime disable!");
			evt.removeListener();
		});

		function getViewportLimitHeight()
		{
			if (!viewportLimitEnabled || isNotResizable())
			{
				// if we're in source mode, editor.window is undefined. And autogrow doesn't work with source mode, so
				// no point in trying to make this function work with it.
				return;
			}

			var editorHeight = editor.container.$.offsetHeight,
				currentHeight = editor.window.getViewPaneSize().height, // height of the editable, resizable area. The bit that autogrow grows
				noneditableUIHeight = editorHeight - currentHeight, // total height of extraneous editor stuff, like cke toolbar buttons at top, dragging bar at bottom...
				editorYRelativeToViewport = editor.container.$.getBoundingClientRect().top;

			/*
				To ensure that editor's bottom does not spill out of the viewport:
					Viewport Height >= editorYRelativeToViewport + editorHeight
				Where
					editorHeight = noneditableUIHeight + currentHeight
				So
					currentHeight <= Viewport Height - editorYRelativeToViewport - noneditableUIHeight
			 */
			 viewportLimitHeight = window.innerHeight - editorYRelativeToViewport - noneditableUIHeight;

			 // After a certain minimum, this becomes pointless. Obey the min config (default 200 if not specifically set by us).
			 if (viewportLimitHeight < configMinHeight)
			 {
				 viewportLimitHeight = configMinHeight;
			 }
		}

		// end vBulletin modification


		editor.on( 'contentDom', refreshCache );

		refreshCache();

		if ( editor.config.autoGrow_onStartup && editor.editable().isVisible() ) {
			editor.execCommand( 'autogrow' );
		}

		function refreshCache() {
			doc = editor.document;
			markerContainer = doc[ CKEDITOR.env.ie ? 'getBody' : 'getDocumentElement' ]();

			// Quirks mode overflows body, standards overflows document element.
			scrollable = CKEDITOR.env.quirks ? doc.getBody() : doc.getDocumentElement();

			// Reset scrollable body height and min-height css values.
			// While set by outside code it may break resizing. (https://dev.ckeditor.com/ticket/14620)
			var body = CKEDITOR.env.quirks ? scrollable : scrollable.findOne( 'body' );
			if ( body ) {
				body.setStyle( 'height', 'auto' );
				body.setStyle( 'min-height', CKEDITOR.env.safari ? '0%' : 'auto' ); // Safari does not support 'min-height: auto'.
			}

			marker = CKEDITOR.dom.element.createFromHtml(
				'<span style="margin:0;padding:0;border:0;clear:both;width:1px;height:1px;display:block;">' +
					( CKEDITOR.env.webkit ? '&nbsp;' : '' ) +
				'</span>',
				doc );
		}

		function isNotResizable() {
			var maximizeCommand = editor.getCommand( 'maximize' );

			return (

				// vBulletin modification VBV-16116
				autogrowDisabledRuntime ||
				autogrowDisabledByResize ||
				// end vBulletin modification

				!editor.window ||
				// Disable autogrow when the editor is maximized. (https://dev.ckeditor.com/ticket/6339)
				maximizeCommand && maximizeCommand.state == CKEDITOR.TRISTATE_ON
			);
		}

		// Actual content height, figured out by appending check the last element's document position.
		function contentHeight() {
			// Append a temporary marker element.
			markerContainer.append( marker );
			var height = marker.getDocumentPosition( doc ).y + marker.$.offsetHeight;
			marker.remove();

			return height;
		}


		// vBulletin modification
		function resizeEditorIfAllowed()
		{
			/*
				*Most* paths to resizeEditor() already calls isNotResizable(), so calling it again in resizeEditor() seemed like a waste.
				Added this wrapper called by a *different* function here to get around that.
			 */
			if (isNotResizable())
			{
				// There might be things (atm: resize plugin & disableResize bits in vB5) that disable resize.
				// We also want to make sure calling exec('autogrow') directly doesn't work when this happens.
				lastHeight = null;
				console.log("Autogrow cancelled - is not resizable!");

				return;
			}
			else
			{
				console.log("Autogrowing from direct call to autogrow_ifallowed!");

				return resizeEditor();
			}
		}
		// end vBulletin modification


		function resizeEditor() {

			// vBulletin modification
			getViewportLimitHeight();
			// end vBulletin modification

			// Hide scroll because we won't need it at all.
			// Thanks to that we'll need only one resizeEditor() call per change.
			if ( maxHeightIsUnlimited )
				scrollable.setStyle( 'overflow-y', 'hidden' );

			var currentHeight = editor.window.getViewPaneSize().height,
				newHeight = contentHeight();

			// Additional space specified by user.
			newHeight += configBottomSpace;
			newHeight = Math.max( newHeight, configMinHeight );
			newHeight = Math.min( newHeight, configMaxHeight );

			// vBulletin modification VBV-15666
			var limitHeight = Math.min(configMaxHeight, viewportLimitHeight);
			newHeight = Math.min(newHeight, limitHeight);
			// end vBulletin modification

			// https://dev.ckeditor.com/ticket/10196 Do not resize editor if new height is equal
			// to the one set by previous resizeEditor() call.
			if ( newHeight != currentHeight && lastHeight != newHeight ) {
				newHeight = editor.fire( 'autoGrow', { currentHeight: currentHeight, newHeight: newHeight } ).newHeight;
				editor.resize( editor.container.getStyle( 'width' ), newHeight, true );
				lastHeight = newHeight;
			}

			if ( !maxHeightIsUnlimited ) {
				// vBulletin modification-- limitHeight variable here VBV-15666
				if ( newHeight < limitHeight && scrollable.$.scrollHeight > scrollable.$.clientHeight )
					scrollable.setStyle( 'overflow-y', 'hidden' );
				else
					scrollable.removeStyle( 'overflow-y' );
			}
		}
	}
} )();

/**
 * The minimum height that the editor can assume when adjusting to content by using the Auto Grow
 * feature. This option accepts a value in pixels, without the unit (for example: `300`).
 *
 * Read more in the {@glink features/autogrow documentation}
 * and see the {@glink examples/autogrow example}.
 *
 *		config.autoGrow_minHeight = 300;
 *
 * @since 3.4.0
 * @cfg {Number} [autoGrow_minHeight=200]
 * @member CKEDITOR.config
 */

/**
 * The maximum height that the editor can assume when adjusting to content by using the Auto Grow
 * feature. This option accepts a value in pixels, without the unit (for example: `600`).
 * Zero (`0`) means that the maximum height is not limited and the editor will expand infinitely.
 *
 * Read more in the {@glink features/autogrow documentation}
 * and see the {@glink examples/autogrow example}.
 *
 *		config.autoGrow_maxHeight = 400;
 *
 * @since 3.4.0
 * @cfg {Number} [autoGrow_maxHeight=0]
 * @member CKEDITOR.config
 */

/**
 * Whether automatic editor height adjustment brought by the Auto Grow feature should happen on
 * editor creation.
 *
 * Read more in the {@glink features/autogrow documentation}
 * and see the {@glink examples/autogrow example}.
 *
 *		config.autoGrow_onStartup = true;
 *
 * @since 3.6.2
 * @cfg {Boolean} [autoGrow_onStartup=false]
 * @member CKEDITOR.config
 */

/**
 * Extra vertical space to be added between the content and the editor bottom bar when adjusting
 * editor height to content by using the Auto Grow feature. This option accepts a value in pixels,
 * without the unit (for example: `50`).
 *
 * Read more in the {@glink features/autogrow documentation}
 * and see the {@glink examples/autogrow example}.
 *
 *		config.autoGrow_bottomSpace = 50;
 *
 * @since 3.6.2
 * @cfg {Number} [autoGrow_bottomSpace=0]
 * @member CKEDITOR.config
 */

/**
 * Fired when the Auto Grow plugin is about to change the size of the editor.
 *
 * @event autogrow
 * @member CKEDITOR.editor
 * @param {CKEDITOR.editor} editor This editor instance.
 * @param data
 * @param {Number} data.currentHeight The current editor height (before resizing).
 * @param {Number} data.newHeight The new editor height (after resizing). It can be changed
 * to achieve a different height value to be used instead.
 */
