/**
 * @license Copyright (c) 2003-2019, CKSource - Frederico Knabben. All rights reserved.
 * For licensing, see LICENSE.md or https://ckeditor.com/legal/ckeditor-oss-license
 */

/**
 * @fileOverview Image plugin based on Widgets API
 */

'use strict';

CKEDITOR.dialog.add( 'image2', function( editor ) {

	// RegExp: 123, 123px, empty string ""
	var regexGetSizeOrEmpty = /(^\s*(\d+)(px)?\s*$)|^$/i,

		lockButtonId = CKEDITOR.tools.getNextId(),
		resetButtonId = CKEDITOR.tools.getNextId(),

		// vBulletin -- changed from editor.lang.image2 to editor.lang.image
		lang = editor.lang.image,
		commonLang = editor.lang.common,

		lockResetStyle = 'margin-top:18px;width:40px;height:20px;',
		lockResetHtml = new CKEDITOR.template(
			'<div>' +
				'<a href="javascript:void(0)" tabindex="-1" title="' + lang.lockRatio + '" class="cke_btn_locked" id="{lockButtonId}" role="checkbox">' +
					'<span class="cke_icon"></span>' +
					'<span class="cke_label">' + lang.lockRatio + '</span>' +
				'</a>' +

				'<a href="javascript:void(0)" tabindex="-1" title="' + lang.resetSize + '" class="cke_btn_reset" id="{resetButtonId}" role="button">' +
					'<span class="cke_label">' + lang.resetSize + '</span>' +
				'</a>' +
			'</div>' ).output( {
				lockButtonId: lockButtonId,
				resetButtonId: resetButtonId
			} ),

		helpers = CKEDITOR.plugins.image2,

		// Editor instance configuration.
		config = editor.config,

		hasFileBrowser = !!( config.filebrowserImageBrowseUrl || config.filebrowserBrowseUrl ),

		// Content restrictions defined by the widget which
		// impact on dialog structure and presence of fields.
		features = editor.widgets.registered.image.features,

		// Functions inherited from image2 plugin.
		getNatural = helpers.getNatural,

		// Global variables referring to the dialog's context.
		doc, widget, image,

		// Global variable referring to this dialog's image pre-loader.
		preLoader,

		// Global variables holding the original size of the image.
		domWidth, domHeight,

		// Global variables related to image pre-loading.
		preLoadedWidth, preLoadedHeight, srcChanged,

		// Global variables related to size locking.
		lockRatio, userDefinedLock,

		// Global variables referring to dialog fields and elements.
		lockButton, resetButton, widthField, heightField,

		natural;

	// Validates dimension. Allowed values are:
	// "123px", "123", "" (empty string)
	function validateDimension() {
		var match = this.getValue().match( regexGetSizeOrEmpty ),
			isValid = !!( match && parseInt( match[ 1 ], 10 ) !== 0 );

		if ( !isValid )
			alert( commonLang[ 'invalidLength' ].replace( '%1', commonLang[ this.id ] ).replace( '%2', 'px' ) ); // jshint ignore:line

		return isValid;
	}

	// Creates a function that pre-loads images. The callback function passes
	// [image, width, height] or null if loading failed.
	//
	// @returns {Function}
	function createPreLoader() {
		var image = doc.createElement( 'img' ),
			listeners = [];

		function addListener( event, callback ) {
			listeners.push( image.once( event, function( evt ) {
				removeListeners();
				callback( evt );
			} ) );
		}

		function removeListeners() {
			var l;

			while ( ( l = listeners.pop() ) )
				l.removeListener();
		}

		// @param {String} src.
		// @param {Function} callback.
		return function( src, callback, scope ) {
			addListener( 'load', function() {
				// Don't use image.$.(width|height) since it's buggy in IE9-10 (https://dev.ckeditor.com/ticket/11159)
				var dimensions = getNatural( image );

				callback.call( scope, image, dimensions.width, dimensions.height );
			} );

			addListener( 'error', function() {
				callback( null );
			} );

			addListener( 'abort', function() {
				callback( null );
			} );


			// vBulletin modification
			// We allow external images. As such we should only prepend this with a baseHref
			// if the SRC is a relative URL!
			// Note: without this, using an external image creates loading errors (404's on
			// baseHref + src resource) & the width & height fail to preload.
			var includeBaseHref = true;
			if (typeof vBulletin.isAbsoluteUrl == 'function')
			{
				includeBaseHref = !vBulletin.isAbsoluteUrl(src);
			}
			// end vBulletin modification


			// vBulletin addition-- added includeBaseHref below
			image.setAttribute( 'src',
				( (includeBaseHref && config.baseHref) || '' ) + src + '?' + Math.random().toString( 16 ).substring( 2 ) );
		};
	}

	// This function updates width and height fields once the
	// "src" field is altered. Along with dimensions, also the
	// dimensions lock is adjusted.
	function onChangeSrc() {
		var value = this.getValue();

		toggleDimensions( false );

		// Remember that src is different than default.
		if ( value !== widget.data.src ) {
			// Update dimensions of the image once it's preloaded.
			preLoader( value, function( image, width, height ) {
				// Re-enable width and height fields.
				toggleDimensions( true );

				// There was problem loading the image. Unlock ratio.
				if ( !image )
					return toggleLockRatio( false );

				// Fill width field with the width of the new image.
				widthField.setValue( editor.config.image2_prefillDimensions === false ? 0 : width );

				// Fill height field with the height of the new image.
				heightField.setValue( editor.config.image2_prefillDimensions === false ? 0 : height );

				// Cache the new width and update initial cache (#1348).
				preLoadedWidth = domWidth = width;

				// Cache the new height and update initial cache (#1348).
				preLoadedHeight = domHeight = height;

				// Check for new lock value if image exist.
				toggleLockRatio( helpers.checkHasNaturalRatio( image ) );
			} );

			srcChanged = true;
		}

		// Value is the same as in widget data but is was
		// modified back in time. Roll back dimensions when restoring
		// default src.
		else if ( srcChanged ) {
			// Re-enable width and height fields.
			toggleDimensions( true );

			// Restore width field with cached width.
			widthField.setValue( domWidth );

			// Restore height field with cached height.
			heightField.setValue( domHeight );

			// Src equals default one back again.
			srcChanged = false;
		}

		// Value is the same as in widget data and it hadn't
		// been modified.
		else {
			// Re-enable width and height fields.
			toggleDimensions( true );
		}


		// vBulletin
		/*
			This call is not strictly necessary at the moment, and possibly undesired in the future if we want to
			allow a user to double click an attachment image, then change the URL (instead of manually removing the
			embedded image & using the image dialog to insert the new image from URL).
			Upon uploading an image, one of the callbacks from the server, vBulletin.ckeditor.closeFileDialog(),
			will call checkUrlSrcAndRemoteCheckbox(). Also, we call this from src's onShow() to handle when the dialog
			is opened by double clicking the image. Other than those two routes, I'm not aware of any paths that needs
			to check & disable the src & remote checkboxes, so this is more an overabundance of caution than anything.
		 */
		checkUrlSrcAndRemoteCheckbox(this.getDialog());
	}

	function onChangeDimension() {
		// If ratio is un-locked, then we don't care what's next.
		if ( !lockRatio )
			return;

		var value = this.getValue();

		// No reason to auto-scale or unlock if the field is empty.
		if ( !value )
			return;

		// If the value of the field is invalid (e.g. with %), unlock ratio.
		if ( !value.match( regexGetSizeOrEmpty ) )
			toggleLockRatio( false );

		// No automatic re-scale when dimension is '0'.
		if ( value === '0' )
			return;

		var isWidth = this.id == 'width',
			// If dialog opened for the new image, domWidth and domHeight
			// will be empty. Use dimensions from pre-loader in such case instead.
			width = domWidth || preLoadedWidth,
			height = domHeight || preLoadedHeight;

		// If changing width, then auto-scale height.
		if ( isWidth )
			value = Math.round( height * ( value / width ) );

		// If changing height, then auto-scale width.
		else
			value = Math.round( width * ( value / height ) );

		// If the value is a number, apply it to the other field.
		if ( !isNaN( value ) )
			( isWidth ? heightField : widthField ).setValue( value );


		// vBulletin
		// switch to custom size
		var sizeRadio = this.getDialog().getContentElement('info', 'size');
		if (sizeRadio)
		{
			sizeRadio.setValue('custom');
		}
		// end vBulletin


	}

	// Set-up function for lock and reset buttons:
	// 	* Adds lock and reset buttons to focusables. Check if button exist first
	// 	  because it may be disabled e.g. due to ACF restrictions.
	// 	* Register mouseover and mouseout event listeners for UI manipulations.
	// 	* Register click event listeners for buttons.
	function onLoadLockReset() {
		var dialog = this.getDialog();

		function setupMouseClasses( el ) {
			el.on( 'mouseover', function() {
				this.addClass( 'cke_btn_over' );
			}, el );

			el.on( 'mouseout', function() {
				this.removeClass( 'cke_btn_over' );
			}, el );
		}

		// Create references to lock and reset buttons for this dialog instance.
		lockButton = doc.getById( lockButtonId );
		resetButton = doc.getById( resetButtonId );

		// Activate (Un)LockRatio button
		if ( lockButton ) {
			// Consider that there's an additional focusable field
			// in the dialog when the "browse" button is visible.
			dialog.addFocusable( lockButton, 4 + hasFileBrowser );

			lockButton.on( 'click', function( evt ) {
				toggleLockRatio();
				evt.data && evt.data.preventDefault();
			}, this.getDialog() );

			setupMouseClasses( lockButton );
		}

		// Activate the reset size button.
		if ( resetButton ) {
			// Consider that there's an additional focusable field
			// in the dialog when the "browse" button is visible.
			dialog.addFocusable( resetButton, 5 + hasFileBrowser );

			// Fills width and height fields with the original dimensions of the
			// image (stored in widget#data since widget#init).
			resetButton.on( 'click', function( evt ) {
				// If there's a new image loaded, reset button should revert
				// cached dimensions of pre-loaded DOM element.
				if ( srcChanged ) {
					widthField.setValue( preLoadedWidth );
					heightField.setValue( preLoadedHeight );
				}

				// If the old image remains, reset button should revert
				// dimensions as loaded when the dialog was first shown.
				else {
					widthField.setValue( domWidth );
					heightField.setValue( domHeight );
				}

				evt.data && evt.data.preventDefault();
			}, this );

			setupMouseClasses( resetButton );
		}
	}

	function toggleLockRatio( enable ) {
		// No locking if there's no radio (i.e. due to ACF).
		if ( !lockButton )
			return;

		if ( typeof enable == 'boolean' ) {
			// If user explicitly wants to decide whether
			// to lock or not, don't do anything.
			if ( userDefinedLock )
				return;

			lockRatio = enable;
		}

		// Undefined. User changed lock value.
		else {
			var width = widthField.getValue(),
				height;

			userDefinedLock = true;
			lockRatio = !lockRatio;

			// Automatically adjust height to width to match
			// the original ratio (based on dom- dimensions).
			if ( lockRatio && width ) {
				height = domHeight / domWidth * width;

				if ( !isNaN( height ) )
					heightField.setValue( Math.round( height ) );
			}
		}

		lockButton[ lockRatio ? 'removeClass' : 'addClass' ]( 'cke_btn_unlocked' );
		lockButton.setAttribute( 'aria-checked', lockRatio );

		// Ratio button hc presentation - WHITE SQUARE / BLACK SQUARE
		if ( CKEDITOR.env.hc ) {
			var icon = lockButton.getChild( 0 );
			icon.setHtml( lockRatio ? CKEDITOR.env.ie ? '\u25A0' : '\u25A3' : CKEDITOR.env.ie ? '\u25A1' : '\u25A2' );
		}
	}

	function toggleDimensions( enable ) {
		var method = enable ? 'enable' : 'disable';

		widthField[ method ]();
		heightField[ method ]();
	}


	// vBulletin function
	function checkUrlSrcAndRemoteCheckbox(dialog)
	{
		var srcInput = dialog && dialog.getContentElement('info', 'src'),
			remoteCheckbox = dialog && dialog.getContentElement('info', 'remote'),
			src = srcInput && srcInput.getValue() || widget && widget.data && widget.data.src || "",
			isInternalUrl = src && vBulletin.isInternalUrl(src),
			disabled = false;

		if (isInternalUrl && widget && widget.data && (widget.data.tempid != "" || widget.data.attachmentid != ""))
		{
			srcInput.disable();
			remoteCheckbox.setValue(false); // we're disabling this anyways, but just in case.
			remoteCheckbox.disable();
			disabled = true;
		}

		return disabled;
	}


	var srcBoxChildren = [
			{
				id: 'src',
				type: 'text',
				label: commonLang.url,
				onKeyup: onChangeSrc,
				onChange: onChangeSrc,
				setup: function( widget ) {
					this.setValue( widget.data.src );
				},
				commit: function( widget ) {
					widget.setData( 'src', this.getValue() );
				},


				// onShow handler added for vBulletin
				onShow: function()
				{
					/*
						1) for some reason the remote checkbox below's onShow() never fires...
						So let's take care of disabling stuff here.
						2) During edit post, onShow seems to be called *before* setup, so this.getValue() may return an empty string
						until you call it again. If so, check the widget data for src as well.
					 */
					var dialog = this.getDialog(),
						remoteCheckbox = dialog.getContentElement('info', 'remote');

					var srcAndCheckboxDisabled = checkUrlSrcAndRemoteCheckbox(dialog);
					if (!srcAndCheckboxDisabled && typeof config.image2_checkuploadbydefault != 'undefined' && config.image2_checkuploadbydefault == true)
					{
						// VBV-16673 Auto check the retrieve remote files and images and serve locally
						// VBV-17044 - However, do not change this if the SRC already exists. If src exists, that means that the user has already saved this widget &
						// possibly unchecked the checkbox, and we don't want to keep re-checking it because that's annoying. If they had previously checked the box &
						// clicked OK on the dialog, the remote.validate() will trigger the uploading & cause the src to eventually point to a local filedataid instead,
						// at which point the src input AND remote checkboxes are disabled via checkUrlSrcAndRemoteCheckbox()
						var alreadyHasSrc = (widget && widget.data && (typeof widget.data.src != 'undefined') && widget.data.src != "");
						if (!alreadyHasSrc)
						{
							remoteCheckbox.setValue(true);
						}
					}

					/*
						If user is not allowed to upload at all, let's just disable the checkbox
					 */
					if (typeof config.image2_showuploadcheckbox != 'undefined' && config.image2_showuploadcheckbox == false)
					{
						var $label = $("label[for='" + remoteCheckbox["_"]["checkbox"]["domId"] + "']");
						// uncheck & disable it.
						remoteCheckbox.setValue(false);
						remoteCheckbox.disable();
						// notify why this is disabled.
						if ($label.length)
						{
							$label.text(vBulletin.phrase.get('cannot_upload_attachments'));
						}

						// hide the "Upload" tab.
						this.getDialog().hidePage("Upload");
					}
				},


				validate: CKEDITOR.dialog.validate.notEmpty( lang.urlMissing )
			}
		];

	// vBulletin
	// add another item to srcBoxChildren for vBulletin
	srcBoxChildren.push({
		id: 'remote',
		type: 'checkbox',
		label: vBulletin.phrase.get('retrieve_remote_file_and_ref_local'),
		//'default': 'checked', // VBV-17044 - The default checking is handled via src onShow(), and this just interferes (& overwrites) the handling there.
		validate: function()
		{
			if (this.getValue())	// retrieve file..
			{
				// If source url is blank, just fall through and allow the #src validate() above to alert user
				var remoteCheckbox = this,
					dialog = remoteCheckbox.getDialog(),
					srcInput = dialog.getContentElement('info', 'src'),
					url = srcInput.getValue();

				if (!url)
				{
					return true;
				}

				dialog.disableButton('ok');
				dialog.disableButton('cancel');
				var success = false;
				var me = this;
				vBulletin.AJAX(
				{
					async  : false,
					url    : vBulletin.getAjaxBaseurl() + '/uploader/url',
					data   : {
						urlupload  : url,
						attachment : 1
					},
					skipdefaultsuccess : true,
					success: function(result)
					{
						if (result['errors'])
						{
							var error = result['errors'];
							if ($.isArray(error) && error.length > 0)
							{
								error = error[0];
							}
							alert(vBulletin.phrase.get('error_x', vBulletin.phrase.get(error)));
						}
						else if (result.imageUrl)
						{
							srcInput.setValue(result.imageUrl);


							/*
							 *	Previously, the upload from a remote URL would've added a hidden input. Now, the hidden input is only inserted
							 *	if the user changes the settings on the image. This way, it'll stay as an [IMG] bbcode rather than an [ATTACH]
							 *	bbcode, when the URL used was actually a locally uploaded filedata.
							 *	The reasoning for this that I don't think we have to create an attach record unless we need to save image settings.
							 *	Update: We need to create an attach record because non-owners cannot view images if it's using the filedataid query
							 *	string.
							 */
							/*
							 *	We need to add this as an attachment, so let's call closeFileDialog() to handle
							 *	that for us. We don't want to go through the default onOk handler for inserting
							 *	the <img> tag because there's no easy way to add custom data attributes with it,
							 *	and while we could override it with our own custom handler (which we do, but not
							 *	to insert our own <img> tag), we might as well reuse the exising code.
							 */
							var data = {
								"url" : result.imageUrl,
								"filedataid" : result.filedataid,
								"name" : result.filename,
							};
							var editorId = editor.name;
							vBulletin.ckeditor.closeFileDialog(editorId, new Array(data));

							success = true;
							// below doesn't work for some reason. We'll disable it onShow() if widget has tempid or attachid data.
							//remoteCheckbox.disable();
						}
					}, // end success
					fail: function (response)
					{
						var error = vBulletin.phrase.get('error_uploading_image');
						var iconType = 'error';
						if (response && response.files.length > 0)
						{
							switch (response.files[0].error)
							{
								case 'acceptFileTypes':
									error = vBulletin.phrase.get('invalid_image_allowed_filetypes_are');
									iconType = 'warning';
									break;
							}
						}

						alert(error);
					},//end fail
					complete: function()
					{
						dialog.enableButton('ok');
						dialog.enableButton('cancel');
					}
				});

				return success;
			}
		}
	});




	// Render the "Browse" button on demand to avoid an "empty" (hidden child)
	// space in dialog layout that distorts the UI.
	if ( hasFileBrowser ) {
		srcBoxChildren.push( {
			type: 'button',
			id: 'browse',
			// v-align with the 'txtUrl' field.
			// TODO: We need something better than a fixed size here.
			style: 'display:inline-block;margin-top:14px;',
			align: 'center',
			label: editor.lang.common.browseServer,
			hidden: true,
			filebrowser: 'info:src'
		} );
	}




	////////////////////////////////////////////////////
	// leftGroup and rightGroup added for vBulletin
	////////////////////////////////////////////////////
	var leftGroup = [
		{
			type: 'vbox',
			padding: 0,
			children: [
				{
					type: 'vbox',
					widths: [ '100%' ],
					children: srcBoxChildren
				}
			]
		},
		{
			id: 'title',
			type: 'text',
			label: editor.lang.vbulletin.title_tooltip,
			setup: function( widget ) {
				this.setValue( widget.data["title"] );
			},
			commit: function( widget ) {
				widget.setData( 'title', this.getValue() );
				//widget.setData( 'data-filename', this.getValue() ); // TODO
			}
		},
		{
			id: 'alt',
			type: 'text',
			label: editor.lang.vbulletin.description_alt,
			setup: function( widget ) {
				this.setValue( widget.data.alt );
			},
			commit: function( widget ) {
				widget.setData( 'alt', this.getValue() );
			},
			validate: editor.config.image2_altRequired === true ? CKEDITOR.dialog.validate.notEmpty( lang.altMissing ) : null
		},
		{
			id: 'style',
			type: 'text',
			label: editor.lang.vbulletin.style,
			setup: function( widget ) {
				this.setValue( widget.data.style );
			},
			commit: function( widget ) {
				widget.setData( 'style', this.getValue() );
			}
		},
		{
			// size / width/height
			type: 'vbox',
			onShow: function() {
				/*
					It seems like the children's onShow never get triggered, so we
					do the toggle on/off here...
				 */
				var dialog = this.getDialog(),
					sizePicker = dialog.getContentElement('info', 'size');
				if (widget && widget.data && (widget.data.tempid != "" || widget.data.attachmentid != ""))
				{
					sizePicker.enable();
				}
				else
				{
					sizePicker.setValue('custom');
					sizePicker.disable();
				}
			},
			children: [
				{
					id: 'size',
					type: 'select',
					items:[
							[editor.lang.vbulletin.icon, 'icon'],
							[editor.lang.vbulletin.thumbnail, 'thumb'],
							[editor.lang.vbulletin.small, 'small'],
							[editor.lang.vbulletin.medium, 'medium'],
							[editor.lang.vbulletin.large, 'large'],
							[editor.lang.vbulletin.fullsize, 'full'],
							[editor.lang.vbulletin.custom, 'custom']
					],
					label: editor.lang.vbulletin.size,
					setup: function( widget ) {
						this.setValue( widget.data.size );
					},
					commit: function( widget ) {
						var size = this.getValue(),
							width = widthField.getValue(),
							height = heightField.getValue();
						/*
						console.log({
							'width': widthField.getValue(),
							height: heightField.getValue(),
							domWidth: domWidth,
							domHeight: domHeight,
							preLoadedWidth: preLoadedWidth,
							preLoadedHeight: preLoadedHeight,
							size: size
						});
						*/
						if (size == 'custom')
						{
							widthField.setValue( width || domWidth );
							heightField.setValue( height || domHeight );
						}
						widget.setData( 'size', size );
					}
				},
				{
					type: 'hbox',
					widths: [ '25%', '25%', '50%' ],
					requiredContent: features.dimension.requiredContent,
					children: [
						{
							type: 'text',
							width: '45px',
							id: 'width',
							label: commonLang.width,
							validate: validateDimension,
							onKeyUp: onChangeDimension,
							onLoad: function() {
								widthField = this;
							},
							setup: function( widget ) {
								this.setValue( widget.data.width );
							},
							commit: function( widget ) {
								widget.setData( 'width', this.getValue() );
							}
						},
						{
							type: 'text',
							id: 'height',
							width: '45px',
							label: commonLang.height,
							validate: validateDimension,
							onKeyUp: onChangeDimension,
							onLoad: function() {
								heightField = this;
							},
							setup: function( widget ) {
								this.setValue( widget.data.height );
							},
							commit: function( widget ) {
								widget.setData( 'height', this.getValue() );
							}
						},
						{
							id: 'lock',
							type: 'html',
							style: lockResetStyle,
							onLoad: onLoadLockReset,
							setup: function( widget ) {
								toggleLockRatio( widget.data.lock );
							},
							commit: function( widget ) {
								widget.setData( 'lock', lockRatio );
							},
							html: lockResetHtml
						}
					]
				}
			]
		},
	],
	rightGroup = [
		{
			type: 'hbox',
			id: 'alignment',
			requiredContent: features.align.requiredContent,
			children: [
				{
					id: 'align',
					type: 'radio',
					items: [
						[ commonLang.alignNone, 'none' ],
						[ commonLang.alignLeft, 'left' ],
						[ commonLang.alignCenter, 'center' ],
						[ commonLang.alignRight, 'right' ]
					],
					label: commonLang.align,
					setup: function( widget ) {
						this.setValue( widget.data.align );
					},
					commit: function( widget ) {
						widget.setData( 'align', this.getValue() );
					}
				}
			]
		},
		{
			type: 'vbox',
			id: 'link',
			//requiredContent: features.align.requiredContent,
			children: [
				{
					id: 'linktype',
					type: 'radio',
					items:[
							[editor.lang.vbulletin['default'], '0'],
							[editor.lang.common.url, '1'],
							[editor.lang.vbulletin.none, '2']
					],
					label: editor.lang.vbulletin.linktype,
					setup: function( widget ) {
						this.setValue( widget.data.linktype );
					},
					commit: function( widget ) {
						widget.setData( 'linktype', this.getValue() );
					},
					onChange: function() {
						var dialog = this.getDialog(),
							me = dialog.getContentElement('info', 'linktype'),
							linkURLElement = dialog.getContentElement('info', 'linkurl'),
							linkTargetElement = dialog.getContentElement('info', 'linktarget');
						if (me.isEnabled() && me.getValue() == 1)
						{
							linkURLElement.enable();
							linkTargetElement.enable();
						}
						else
						{
							linkURLElement.disable();
							linkTargetElement.disable();
						}
					}
				},
				{
					id: 'linkurl',
					type: 'text',
					label: editor.lang.vbulletin.linkurl,
					setup: function( widget ) {
						// todo fetch this??
						this.setValue( widget.data.linkurl );
					},
					commit: function( widget ) {
						widget.setData( 'linkurl', this.getValue() );
					}
				},
				{
					type: 'select',
					id: 'linktarget',
					items:[
							[editor.lang.common.targetSelf, '0'],
							[editor.lang.common.targetNew, '1']
					],
					label: editor.lang.vbulletin.linktarget,
					setup: function( widget ) {
						// todo fetch this??
						this.setValue( widget.data.linktarget );
					},
					commit: function( widget ) {
						widget.setData( 'linktarget', this.getValue() );
					},
					onShow: function() {
						var dialog = this.getDialog();
						var linkTypeElement = dialog.getContentElement('info', 'linktype');
						if (linkTypeElement.isEnabled() && linkTypeElement.getValue() == 1)
						{
							this.enable();
						}
						else
						{
							this.disable();
						}
					}
				}
			]
		},
		{
			id: 'hasCaption',
			type: 'checkbox',
			label: lang.captioned,
			requiredContent: features.caption.requiredContent,
			setup: function( widget ) {
				this.setValue( widget.data.hasCaption );
			},
			commit: function( widget ) {
				widget.setData( 'hasCaption', this.getValue() );
			}
		}
	];


	return {
		title: lang.title,
		minWidth: 250,
		minHeight: 100,
		onLoad: function() {
			// Create a "global" reference to the document for this dialog instance.
			doc = this._.element.getDocument();

			// Create a pre-loader used for determining dimensions of new images.
			preLoader = createPreLoader();

			// vBulletin modification
			// "Expose" the function to allow our JS to call it.
			// All testing indicates that when onLoad is called, "this" is the dialog. However, just in case..
			if (this instanceof CKEDITOR.dialog)
			{
				this.checkUrlSrcAndRemoteCheckbox = function()
				{
					return checkUrlSrcAndRemoteCheckbox(this);
				};
			}

		},
		onShow: function() {

			// vBulletin comment
			// Note, this.widget is passed from plugin.js, look for this.on( 'dialog', function( evt ) ...

			// Create a "global" reference to edited widget.
			widget = this.widget;

			// Create a "global" reference to widget's image.
			image = widget.parts.image;


			// vBulletin modification
			// drag & dropped images won't have this class for some reason unless we force it
			image.addClass("bbcode-attachment");


			// Reset global variables.
			srcChanged = userDefinedLock = lockRatio = false;

			// Natural dimensions of the image.
			natural = getNatural( image );

			// Get the natural width of the image.
			preLoadedWidth = domWidth = natural.width;

			// Get the natural height of the image.
			preLoadedHeight = domHeight = natural.height;
		},
		contents: [
			{
				id: 'info',
				label: lang.infoTab,
				elements: [
					{
						// vBulletin -- changed from vbox to hbox
						type: 'hbox',
						padding: 0,
						// vBulletin -- added the class name here
						className: 'cke-image2-info-tab-wrapper',
						children: [
							{
								// vBulletin -- changed from hbox to vbox,
								// removed class name, and changed children to 'leftGroup'
								type: 'vbox',
								widths: [ '100%' ],
								children: leftGroup
							},
							// 'rightGroup' added for vBulletin
							{
								// nested vbox purely for stylistic padding, as it looks a bit nicer.
								type: 'vbox',
								padding: 10,
								widths: ['100%'],
								children: [{
									type: 'vbox',
									widths: ['100%'],
									children: rightGroup
								}]
							},

						]
					},

					// four more elements removed here for vBulletin
					// these elements are worked into the leftGroup
					// and rightGroup variables above

				]
			},
			// Note, this tab may be hidden based on config.image2_showuploadcheckbox
			{
				id: 'Upload',
				hidden: true,
				filebrowser: 'uploadButton',
				label: lang.uploadTab,
				elements: [
					{
						type: 'file',
						id: 'upload',
						label: lang.btnUpload,
						style: 'height:40px',
					},
					{
						type: 'fileButton',
						id: 'uploadButton',
						filebrowser: 'info:src',
						label: lang.btnUpload,
						'for': [ 'Upload', 'upload' ],
						// onClick function added for vBulletin
						onClick: function (evt)
						{
							// Vars Reference: https://github.com/ckeditor/ckeditor-dev/blob/master/plugins/filebrowser/plugin.js
							var sender = evt.sender,
								fileInput = sender.getDialog().getContentElement(this['for'][0], this['for'][1]).getInputElement(),
								// avoiding using .form shorthand in case minimizer dies on "special/almost-reserved" words
								$form = fileInput && fileInput.$ && fileInput.$['form'] && $(fileInput.$['form']);

							if ($form.length)
							{
								// vBulletin 5 - Add securitytoken to this POST
								var $input = $form.find('input[name="securitytoken"]');
								if ($input.length)
								{
									$input.val(pageData.securitytoken);
								}
								else
								{
									$form.append('<input type="hidden" name="securitytoken" value="' + pageData.securitytoken + '" />');
								}
							}
						},
					}
				]
			}
		]
	};
} );
