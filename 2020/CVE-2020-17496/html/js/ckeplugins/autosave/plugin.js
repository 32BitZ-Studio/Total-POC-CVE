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

//Pre-cache needed options
window.vBulletin = window.vBulletin || {};
window.vBulletin.options = window.vBulletin.options || {};
window.vBulletin.options.precache = $.merge(window.vBulletin.options.precache, [
	'autosave'
]);

CKEDITOR.plugins.add('autosave', {
	requires: 'vbsource',
	init: function(editor)
	{
		editor.vBulletin = editor.vBulletin || {};
		editor.vBulletin.autosave = editor.vBulletin.autosave || {};
		editor.vBulletin.autosave.delay = (window.vBulletin.options.get('autosave') < 20 ? 20 : window.vBulletin.options.get('autosave')) * 1000;

		// Debug to autosaves every 5 seconds
		// editor.vBulletin.autosave.delay = 5000;

		if (!editor.vBulletin.autosave.initialized)
		{
			editor.on('instanceReady', this.editorReady);
		}
		if (!editor.vBulletin.autosave.initialized)
		{
			editor.on('dataReady', this.dataReady);
		}
	},
	dataReady: function(event)
	{
		if (event.editor.vBulletin.autosave.initialized)
		{
			if (event.editor.vBulletin.autosave.dataReadyExecution == 0)
			{
				event.editor.vBulletin.autosave.dataReadyExecution++;
				CKEDITOR.plugins.autosave.commands.resetAutosave(event.editor);
			}
		}
		else
		{
			event.editor.vBulletin.autosave.dataReadyExecution = 0;
		}
	},
	editorReady: function(event)
	{
		var editor = event.editor;
		editor.vBulletin.autosave.initialized = true;
		editor.vBulletin.autosave.ajax_inprogress = false;
		// only start autosave timer if the option is not 0
		if (window.vBulletin.options.get('autosave'))
		{
			CKEDITOR.plugins.autosave.commands.saveTimer(editor, editor.vBulletin.autosave.delay);
		}
		editor.vBulletin.autosave.$parentform = $('.' + editor.id).closest('form');

		editor.vBulletin.autosave.$panel = editor.vBulletin.autosave.$parentform.find('.b-content-entry-panel--autosave');
		if (editor.vBulletin.autosave.$parentform.find('span.ckeditor-auto-load').length > 0)
		{
			editor.vBulletin.autosave.autoLoadText = editor.vBulletin.autosave.$parentform.find('span.ckeditor-auto-load').html();
			// Restore Link
			editor.vBulletin.autosave.$panel.find('a[data-action="restore"]').on('click', function(event){
				CKEDITOR.plugins.autosave.commands.restore(editor);
				return false;
			});
			// Discard Link
			editor.vBulletin.autosave.$panel.find('a[data-action="discard"]').on('click', function(event){
				CKEDITOR.plugins.autosave.commands.discard(editor);
				return false;
			});

			editor.vBulletin.autosave.$panel.removeClass('h-hide');
		}
		else
		{
			editor.vBulletin.autosave.$panel.hide();
		}

		// The parentid search calls first() to ensure that when creating a CMS article, the root
		// article category (channel) is used. This prevents "losing" autosave text when changing
		// the category, and is consistent with the UI where when creating an article, you are not
		// in any particular category, rather you assign a category as part of creating the article.
		// This is different from forums, where you create a topic "in" a forum.
		editor.vBulletin.autosave.parentid = parseInt(editor.vBulletin.autosave.$parentform.find('input[name="parentid"]').first().val(), 10) || 0;
		editor.vBulletin.autosave.nodeid = parseInt(editor.vBulletin.autosave.$parentform.find('input[name="nodeid"]').val(), 10) || 0;

		editor.vBulletin.autosave.$container = editor.vBulletin.autosave.$parentform.find('.b-editor').find('.cke_contents');
		editor.vBulletin.autosave.$indicator = editor.vBulletin.autosave.$parentform.find('.autosave-indicator');
		editor.vBulletin.autosave.$indicator.appendTo(editor.vBulletin.autosave.$container);

		var $dialog = editor.vBulletin.autosave.$container.closest('.dialog-container.dialog-box');
		if ($dialog.length)
		{	// If we are in a dialog, set autosave indicator's zindex to that of the dialog
			editor.vBulletin.autosave.$indicator.css('z-index', $dialog.css('z-index'));
		}
		editor.vBulletin.autosave.count = 0;
	}
});

CKEDITOR.plugins.autosave = {
	commands : {
		resetAutosave: function (editor)
		{
			editor.vBulletin.autosave.lastautosave_text_crc32 = this.crc32(this.getRawMessage(editor));
		},
		discard: function(editor)
		{
			editor.vBulletin.autosave.$panel.hide();
			if (!editor.vBulletin.autosave.ajax_inprogress && editor.vBulletin.autosave.count == 0)
			{
				var postData = {
					parentid : editor.vBulletin.autosave.parentid,
					nodeid   : editor.vBulletin.autosave.nodeid
				};

				vBulletin.AJAX(
				{
					url    : vBulletin.getAjaxBaseurl() + '/ajax/api/editor/discardAutosave',
					data   : postData,
					complete: function() {}
				});
			}
		},
		restore: function(editor)
		{
			editor.vBulletin.autosave.$parentform.find('.b-editor').find('.cke_contents').find('.b-editor__placeholder').addClass('h-hide');
			editor.vBulletin.autosave.$panel.hide();
			text = CKEDITOR.plugins.vbsource.commands.convertData.exec(editor.vBulletin.autosave.autoLoadText, false);
			editor.setData(text, function()
			{
				CKEDITOR.plugins.autosave.commands.resetAutosave(editor);
			});
			editor.focus();
		},
		saveTimer: function (editor, timeout)
		{
			var delay = typeof(timeout) != 'undefined' ? timeout : editor.vBulletin.autosave.delay;
			var thisC = this;
			setTimeout(function(){thisC.autoSave(editor);}, delay);
		},
		autoSave: function (editor)
		{
			if (pageData.userid == '0')
			{
				console.log("Auto save is disabled for guests");
				return;
			}

			if (editor.mode != 'source' && typeof editor.document == 'undefined')
			{
				return;
			}

			// editor.document == 'undefined' means this editor is not active
			if (!editor.vBulletin.autosave.initialized)
			{
				this.saveTimer(editor);
				return;
			}

			var raw_message = this.getRawMessage(editor);
			if (editor.mode == 'source')
			{
				var strippedmessage = (raw_message.length > 0) ? true : false;
			}
			else
			{
				var regex = new RegExp('(<br>|<br \/>|\\s|&nbsp;)', 'gi');
				var strippedmessage = (raw_message.replace(regex, '').length > 0) ? true : false;
			}
			var current_text_crc32 = this.crc32(raw_message);
			var changed = (editor.vBulletin.autosave.lastautosave_text_crc32 != current_text_crc32);
			editor.vBulletin.autosave.lastautosave_text_crc32 = current_text_crc32;

			// Editor can be active and not displayed in regards to the signature
			var visible = editor.vBulletin.autosave.$container.is(':visible');
			if (strippedmessage && changed && visible)
			{
				this.saveData(
					editor,
					editor.vBulletin.autosave.parentid,
					editor.vBulletin.autosave.nodeid,
					raw_message
				);
			}
			else
			{
				this.saveTimer(editor);
			}
		},
		getRawMessage: function (editor)
		{
			return $.trim(this.getData(editor));
		},
		getData: function (editor)
		{
			if (editor.document)
			{
				var data = editor.document.getBody().getHtml();
				// Strip off <br> at the end of the document
				if (CKEDITOR.env.gecko)
				{
					data = data.replace( /<br>(?=\s*(:?$|<\/body>))/, '' );
				}
				return data;
			}
			else
			{
				return editor.vBulletin.autosave.$parentform.find('textarea.cke_source').val();
			}
		},
		displayNotice: function(editor)
		{

			editor.vBulletin.autosave.$indicator.removeClass('h-hide');
			editor.vBulletin.autosave.$indicator.css('display', '');
			editor.vBulletin.autosave.$indicator.fadeOut({duration: 2000, easing: 'linear'});
		},
		saveData: function (editor, parentid, nodeid, pagetext)
		{
			var postData = {
				pagetext : pagetext,
				mode     : editor.mode,
				parentid : parentid,
				nodeid   : nodeid
			};

			var me = this;
			vBulletin.AJAX(
			{
				url    : vBulletin.getAjaxBaseurl() + '/ajax/api/editor/autosave',
				data   : postData,
				success: function(result)
				{
					if (result === true)
					{
						editor.vBulletin.autosave.count++;
						me.displayNotice(editor);
					}
				},
				emptyResponse: function()
				{
					console.log("/ajax/api/editor/autosave returned an empty response!");
					console.log("This might happen if autosave is turned off, or if the user is not logged in.");

				},
				error: function(jqXHR, textStatus, errorThrown)
				{
					// VBV-15000 - This is a background service, so just log the error details
					// to console, but do not show an overt error/interruption
					console.log("/ajax/api/editor/autosave failed!");
					console.log("----------------");
					console.log("jqXHR:");
					console.dir(jqXHR);
					console.log("text status:");
					console.dir(textStatus);
					console.log("error thrown:");
					console.dir(errorThrown);
					console.log("----------------");
				},
				beforeSend: function()
				{
					// if request is active, return
					if (editor.vBulletin.autosave.ajax_inprogress)
					{
						me.saveTimer(editor, 10000);
						return false;
					}
					// Show Ajax indicator here
					console.log('Auto-Save: Saving Text');
				},
				complete: function()
				{
					// Hide Ajax indicator here
					editor.vBulletin.autosave.ajax_inprogress = false;
					me.saveTimer(editor);
				}
			});
		},
		crc32: function(str)
		{
			var table = '00000000 77073096 EE0E612C 990951BA 076DC419 706AF48F E963A535 9E6495A3 0EDB8832 79DCB8A4 E0D5E91E 97D2D988 09B64C2B 7EB17CBD E7B82D07 90BF1D91 1DB71064 6AB020F2 F3B97148 84BE41DE 1ADAD47D 6DDDE4EB F4D4B551 83D385C7 136C9856 646BA8C0 FD62F97A 8A65C9EC 14015C4F 63066CD9 FA0F3D63 8D080DF5 3B6E20C8 4C69105E D56041E4 A2677172 3C03E4D1 4B04D447 D20D85FD A50AB56B 35B5A8FA 42B2986C DBBBC9D6 ACBCF940 32D86CE3 45DF5C75 DCD60DCF ABD13D59 26D930AC 51DE003A C8D75180 BFD06116 21B4F4B5 56B3C423 CFBA9599 B8BDA50F 2802B89E 5F058808 C60CD9B2 B10BE924 2F6F7C87 58684C11 C1611DAB B6662D3D 76DC4190 01DB7106 98D220BC EFD5102A 71B18589 06B6B51F 9FBFE4A5 E8B8D433 7807C9A2 0F00F934 9609A88E E10E9818 7F6A0DBB 086D3D2D 91646C97 E6635C01 6B6B51F4 1C6C6162 856530D8 F262004E 6C0695ED 1B01A57B 8208F4C1 F50FC457 65B0D9C6 12B7E950 8BBEB8EA FCB9887C 62DD1DDF 15DA2D49 8CD37CF3 FBD44C65 4DB26158 3AB551CE A3BC0074 D4BB30E2 4ADFA541 3DD895D7 A4D1C46D D3D6F4FB 4369E96A 346ED9FC AD678846 DA60B8D0 44042D73 33031DE5 AA0A4C5F DD0D7CC9 5005713C 270241AA BE0B1010 C90C2086 5768B525 206F85B3 B966D409 CE61E49F 5EDEF90E 29D9C998 B0D09822 C7D7A8B4 59B33D17 2EB40D81 B7BD5C3B C0BA6CAD EDB88320 9ABFB3B6 03B6E20C 74B1D29A EAD54739 9DD277AF 04DB2615 73DC1683 E3630B12 94643B84 0D6D6A3E 7A6A5AA8 E40ECF0B 9309FF9D 0A00AE27 7D079EB1 F00F9344 8708A3D2 1E01F268 6906C2FE F762575D 806567CB 196C3671 6E6B06E7 FED41B76 89D32BE0 10DA7A5A 67DD4ACC F9B9DF6F 8EBEEFF9 17B7BE43 60B08ED5 D6D6A3E8 A1D1937E 38D8C2C4 4FDFF252 D1BB67F1 A6BC5767 3FB506DD 48B2364B D80D2BDA AF0A1B4C 36034AF6 41047A60 DF60EFC3 A867DF55 316E8EEF 4669BE79 CB61B38C BC66831A 256FD2A0 5268E236 CC0C7795 BB0B4703 220216B9 5505262F C5BA3BBE B2BD0B28 2BB45A92 5CB36A04 C2D7FFA7 B5D0CF31 2CD99E8B 5BDEAE1D 9B64C2B0 EC63F226 756AA39C 026D930A 9C0906A9 EB0E363F 72076785 05005713 95BF4A82 E2B87A14 7BB12BAE 0CB61B38 92D28E9B E5D5BE0D 7CDCEFB7 0BDBDF21 86D3D2D4 F1D4E242 68DDB3F8 1FDA836E 81BE16CD F6B9265B 6FB077E1 18B74777 88085AE6 FF0F6A70 66063BCA 11010B5C 8F659EFF F862AE69 616BFFD3 166CCF45 A00AE278 D70DD2EE 4E048354 3903B3C2 A7672661 D06016F7 4969474D 3E6E77DB AED16A4A D9D65ADC 40DF0B66 37D83BF0 A9BCAE53 DEBB9EC5 47B2CF7F 30B5FFE9 BDBDF21C CABAC28A 53B39330 24B4A3A6 BAD03605 CDD70693 54DE5729 23D967BF B3667A2E C4614AB8 5D681B02 2A6F2B94 B40BBE37 C30C8EA1 5A05DF1B 2D02EF8D';
			var crc = -1;
			var x = 0, y = 0;
			for (var char_count = 0; char_count < str.length; char_count++)
			{
				y = (crc ^ str.charCodeAt(char_count)) & 0xFF;
				x = '0x' + table.substr(y * 9, 8);
				crc = (crc >>> 8) ^ x;
			}

			return crc ^ (-1);
		}
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 103793 $
|| #######################################################################
\*=========================================================================*/
