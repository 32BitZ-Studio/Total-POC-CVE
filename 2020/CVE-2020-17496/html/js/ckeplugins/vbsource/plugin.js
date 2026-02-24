/**
 * @license Copyright (c) 2003-2013, CKSource - Frederico Knabben. All rights reserved.
 * For licensing, see LICENSE.html or http://ckeditor.com/license
 */

/**
 * @fileOverview The "vbsource" plugin. It registers the "source" editing
 *		mode, which displays the raw data being edited in the editor.
 */

(function() {
	CKEDITOR.plugins.add( 'vbsource', {
		init: function( editor ) {
			// Source mode isn't available in inline mode yet.
			if ( editor.elementMode == CKEDITOR.ELEMENT_MODE_INLINE )
				return;

			var vbsource = CKEDITOR.plugins.vbsource;

			editor.addMode( 'source', function( callback )
			{
				var contentsSpace = editor.ui.space( 'contents' ),
					textarea = contentsSpace.getDocument().createElement( 'textarea' );

				textarea.setStyles(
					CKEDITOR.tools.extend({
						// IE7 has overflow the <textarea> from wrapping table cell.
						width: CKEDITOR.env.ie7Compat ? '99%' : '100%',
						height: '100%',
						resize: 'none',
						outline: 'none',
						// ensure the textarea inherits the correct alignment
						// from the 'dir' attr set below
						'text-align': 'inherit'
					},
					CKEDITOR.tools.cssVendorPrefix( 'tab-size', editor.config.vbsourceTabSize || 4 ) ) );

				// Make sure that source code is always displayed LTR,
				// regardless of editor language (#10105).
				//textarea.setAttribute( 'dir', 'ltr' );
				// Actually, since the source editor isn't really for editing
				// CODE, it's mainly text content with a bit of bbcode,
				// we DO want to show properly in ltr & rtl. See VBV-13490
				var isRTL = vBulletin.isRtl();
				textarea.setAttribute('dir', (isRTL ? 'rtl' : 'ltr'));


				textarea.addClass( 'cke_source').addClass('cke_reset').addClass('cke_enable_context_menu' );

				editor.ui.space( 'contents' ).append( textarea );

				var editable = editor.editable( new sourceEditable( editor, textarea ) );

				// Fill the textarea with the current editor data.
				editable.setData( editor.getData( 1 ) );

				// Having to make <textarea> fixed sized to conquer the following bugs:
				// 1. The textarea height/width='100%' doesn't constraint to the 'td' in IE6/7.
				// 2. Unexpected vertical-scrolling behavior happens whenever focus is moving out of editor
				// if text content within it has overflowed. (#4762)
				if ( CKEDITOR.env.ie ) {
					editable.attachListener( editor, 'resize', onResize, editable );
					editable.attachListener( CKEDITOR.document.getWindow(), 'resize', onResize, editable );
					CKEDITOR.tools.setTimeout( onResize, 0, editable );
				}

				editor.fire( 'ariaWidget', this );

				callback();
			});

			editor.addCommand( 'source', vbsource.commands.source );

			if ( editor.ui.addButton ) {
				editor.ui.addButton( 'Source', {
					label: editor.lang.sourcearea.toolbar,
					command: 'source',
					toolbar: 'mode,10'
				});
			}

			editor.on( 'mode', function() {
				editor.getCommand( 'source' ).setState( editor.mode == 'source' ? CKEDITOR.TRISTATE_ON : CKEDITOR.TRISTATE_OFF );
			});

			function onResize() {
				// Holder rectange size is stretched by textarea,
				// so hide it just for a moment.
				this.hide();
				this.setStyle( 'height', this.getParent().$.clientHeight + 'px' );
				this.setStyle( 'width', this.getParent().$.clientWidth + 'px' );
				// When we have proper holder size, show textarea again.
				this.show();
			}
		}
	});

	var sourceEditable = CKEDITOR.tools.createClass({
		base: CKEDITOR.editable,
		proto: {
			prevSourceText: '',
			prevWysiwygText: '',
			wysiwygText: '',
			sourceText:'',
			setData: function( data )
			{
				// If converting from source to WYSIWYG and disable_bbcode is ON, we don't want to do the conversion
				if (vBulletin.contentEntryBox && vBulletin.contentEntryBox.disable_bbcode)
				{
					this.setValue(data);
				}
				else
				{
					this.setValue(CKEDITOR.plugins.vbsource.commands.convertData.exec(data, 1));
				}

				this.editor.fire( 'dataReady' );
			},

			getData: function()
			{
				// If converting from source to WYSIWYG and disable_bbcode is ON, we don't want to do the conversion
				if (vBulletin.contentEntryBox && vBulletin.contentEntryBox.disable_bbcode)
				{
					return this.getValue();
				}
				else
				{
					return CKEDITOR.plugins.vbsource.commands.convertData.exec(this.getValue(), 0);
				}
			},

			// Insertions are not supported in source editable.
			insertHtml: function() {},
			insertElement: function() {},
			insertText: function() {},

			// Read-only support for textarea.
			setReadOnly: function( isReadOnly ) {
				this[ ( isReadOnly ? 'set' : 'remove' ) + 'Attribute' ]( 'readOnly', 'readonly' );
			},

			detach: function() {
				sourceEditable.baseProto.detach.call( this );
				this.clearCustomData();
				this.remove();
			}
		}
	});
})();

CKEDITOR.plugins.vbsource = {
	commands: {
		source: {
			modes: { wysiwyg:1,source:1 },
			editorFocus: false,
			readOnly: 1,
			exec: function( editor ) {
				if ( editor.mode == 'wysiwyg' )
					editor.fire( 'saveSnapshot' );
				editor.getCommand( 'source' ).setState( CKEDITOR.TRISTATE_DISABLED );
				editor.setMode( editor.mode == 'source' ? 'wysiwyg' : 'source' );
			},

			canUndo: false
		},
		convertData: {
			prevSourceText: '',
			prevWysiwygText: '',
			wysiwygText: '',
			sourceText: '',
			exec: function ( data, wysiwyg )
			{
				data = $.trim(data);
				if (data.length == 0)
				{
					return '';
				}

				var postData = {
					nodeid 		 : pageData.nodeid,
					data         : data,
					allowsmilie  : 1,
					securitytoken: pageData.securitytoken
				};

				if (wysiwyg == 1)
				{
					if (this.prevWysiwygText == data)
					{
						return this.sourceText;
					}
					var apipath = vBulletin.getAjaxBaseurl() + '/ajax/api/editor/convertHtmlToBbcode';
					this.prevWysiwygText = data;
				}
				else
				{
					if (this.prevSourceText == data)
					{
						return this.wysiwygText;
					}
					var apipath = vBulletin.getAjaxBaseurl() + '/create-content/parsewysiwyg';
					this.prevSourceText = data;
				}

				var output = '',
					me = this;

				vBulletin.AJAX(
				{
					async  : false,
					url    : apipath,
					data   : postData,
					success: function(result)
					{
						if (result && result.data)
						{
							output = result.data
							if (wysiwyg == 1)
							{
								me.sourceText = output;
							}
							else // going from source mode to wysiwyg mode
							{
								// Below used to be here for VBV-9493. I'm not sure what's changed, but I don't think this is still an issue,
								// and it screws with valid usage of &quot; (for ex. double quotes in an html attribute), so removing it.
								// replace &quot; back to " to match quotes in WYSIWYG mode
								//output = output.replace(/&quot;/g,'"');
								me.wysiwygText = output;
							}
						}
						else
						{
							console.log(apipath + ' was successful, but response was not an array');
							openAlertDialog({
								'title'    : vBulletin.phrase.get('error'),
								'message'  : vBulletin.phrase.get('invalid_server_response_please_try_again'),
								'iconType' : 'error'
							});
						}
					},
					error_phrase: 'error_converting_message'
				});

				return output;
			}
		}
	}
};

/**
 * Controls CSS tab-size property of the vbsource view.
 *
 * **Note:** Works only with {@link #dataIndentationChars}
 * set to `'\t'`. Please consider that not all browsers support CSS
 * `tab-size` property yet.
 *
 *		// Set tab-size to 20 characters.
 *		CKEDITOR.config.vbsourceTabSize = 20;
 *
 * @cfg {Number} [vbsourceTabSize=4]
 * @member CKEDITOR.config
 * @see CKEDITOR.config#dataIndentationChars
 */
