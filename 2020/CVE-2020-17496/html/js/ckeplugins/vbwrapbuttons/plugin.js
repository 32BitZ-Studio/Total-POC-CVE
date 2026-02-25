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

CKEDITOR.dom.range.prototype.wrapSelectionWith = function(start, end)
{
	var startNode, endNode;
	var clone;

	// make sure we are including bold/italic/underline/etc tags
	this.enlarge(CKEDITOR.ENLARGE_ELEMENT);

	startNode = CKEDITOR.dom.element.createFromHtml(start, this.document);
	endNode = CKEDITOR.dom.element.createFromHtml(end, this.document);

	// insert closing tag
	clone = this.clone();
	clone.collapse();
	clone.insertNode(endNode);
	if (this.collapsed)
	{
		this.moveToPosition(endNode, CKEDITOR.POSITION_BEFORE_START);
	}

	// insert start tag
	clone = this.clone();
	clone.collapse(true);
	clone.insertNode(startNode);
	if (this.collapsed)
	{
		this.moveToPosition( startNode, CKEDITOR.POSITION_AFTER_END );
	}

	// reselect ranges
	if (!this.collapsed)
	{
		this.setEndBefore(endNode);
		this.setStartAfter(startNode);
	}
}

CKEDITOR.editor.prototype.getSelectedText = function()
{
	if (CKEDITOR.env.ie)
	{
		return this.getSelection().document.$.selection.createRange().text;
	}
	else
	{
		return this.getSelection().getNative();
	}
}

CKEDITOR.editor.prototype.wrapSelectionWith = function(start, end)
{
	if (CKEDITOR.env.ie)
	{
		this.focus();
	}

	var ranges = this.getSelection().getRanges();
	for (var i = 0; i < ranges.length; i++)
	{
		ranges[i].wrapSelectionWith(start, end);
	}
	this.getSelection().selectRanges(ranges);
}

// add plugin
CKEDITOR.plugins.add('vbwrapbuttons',
{
	init: function(editor)
	{
		var addButtonCommand = function(buttonName, buttonLabel, tagName, option, image)
		{
			editor.addCommand(buttonName.toLowerCase(),
			{
				exec: function(editor)
				{
					if (option == '1')
					{
						var optionString = prompt(buttonLabel.replace(/\%1\$s/,'[' + tagName + ']'));
						if (typeof optionString == 'string' && optionString.length > 0)
						{
							editor.wrapSelectionWith('[' + tagName + '=' + optionString + ']', '[/' + tagName + ']');
						}
						else
						{
							editor.wrapSelectionWith('[' + tagName + ']', '[/' + tagName + ']');
						}
					}
					else
					{
						editor.wrapSelectionWith('[' + tagName + ']', '[/' + tagName + ']');
					}
				}
			});

			var buttonDefinition = {label : buttonLabel, command : buttonName.toLowerCase()};
			if (image)
			{
				buttonDefinition.icon = image;
			}

			editor.ui.addButton(buttonName, buttonDefinition);
		};

		var addPageBreakCommand = function(buttonName, buttonLabel, image)
		{
			editor.addCommand(buttonName.toLowerCase(),
			{
				exec: function(editor)
				{
					var selectedText = editor.getSelectedText();
					editor.insertHtml('<h3 class="wysiwyg_pagebreak">' + selectedText + '</h3>');

					// remove the <br> in the <h3> so an additional line is not inserted when you start typing
					if (editor.mode == 'wysiwyg')
					{
						var h3_tags = editor.document.getElementsByTag('h3');
						for (var i = 0; i < h3_tags.count(); i++)
						{
							var tag = h3_tags.getItem(i);
							if (tag.hasClass('wysiwyg_pagebreak'))
							{
								var tagHtml = tag.getHtml();
								if (tagHtml == '<br>' || tagHtml == '<br />')
								{
									tag.setHtml('&nbsp;');
								}
							}
						}
					}
				}
			});

			var buttonDefinition = {label : buttonLabel, command : buttonName.toLowerCase()};
			if (image)
			{
				buttonDefinition.icon = image;
			}

			editor.ui.addButton(buttonName, buttonDefinition);
		};

		var addPreviewBreakCommand = function(buttonName, buttonLabel, image)
		{
			editor.addCommand(buttonName.toLowerCase(),
			{
				exec: function(editor)
				{
					if (editor.mode == 'wysiwyg')
					{
						var hr_tags = editor.document.getElementsByTag('hr');
						for (var i = 0; i < hr_tags.count(); i++)
						{
							var tag = hr_tags.getItem(i);
							if (tag.hasClass('previewbreak'))
							{
								openAlertDialog({
									'title': vBulletin.phrase.get('vbulletin_message'),
									'message': vBulletin.phrase.get('this_message_already_contains_a_preview_break'),
									'iconType':'warning'
								});
								return;
							}
						}
					}
					editor.insertHtml('<hr class="previewbreak" />');
				}
			});

			var buttonDefinition = {label : buttonLabel, command : buttonName.toLowerCase()};
			if (image)
			{
				buttonDefinition.icon = image;
			}

			editor.ui.addButton(buttonName, buttonDefinition);
		};

		// The 'default' bit in this path can change to 'dark' (or something else) based
		// on the ckeditor_image_path stylevar. It's automatically changed in ckeditor.js
		// in modifyImagePaths().
		var imgpath = '/js/ckeditor/images/default/vbulletin/';

		addButtonCommand('Quote', vBulletin.phrase.get('wrap_x_tags', 'QUOTE'), 'QUOTE', 0, window.pageData.baseurl + imgpath + 'quote.png');
		addButtonCommand('Code', vBulletin.phrase.get('wrap_x_tags', 'CODE'), 'CODE', 0, window.pageData.baseurl + imgpath + 'code.png');
		addButtonCommand('Html', vBulletin.phrase.get('wrap_x_tags', 'HTML'), 'HTML', 0, window.pageData.baseurl + imgpath + 'html.png');
		addButtonCommand('Php', vBulletin.phrase.get('wrap_x_tags', 'PHP'), 'PHP', 0, window.pageData.baseurl + imgpath + 'php.png');

		addPageBreakCommand('PageBreak', vBulletin.phrase.get('insert_page_break'));
		addPreviewBreakCommand('PreviewBreak', vBulletin.phrase.get('insert_preview_break'), window.pageData.baseurl + imgpath + 'break.png');

		for (var bbcodetag in window.vBulletin.customBbcode)
		{
			if (!bbcodetag)
			{
				continue;
			}
			var bbcode = window.vBulletin.customBbcode[bbcodetag];
			var resource = bbcode.buttonimage;

			// By default addButtonCommand will end up appending ckeditor's basepath to any bbcode images that are relative
			// so we are preemptive here by adding baseHref
			//
			// If this is not a full or absolute path.
			if (resource.indexOf(':/') == -1 && resource.indexOf( '/' ) !== 0 )
			{
				resource = editor.config.baseHref + resource;
			}

			addButtonCommand(bbcode.title, vBulletin.phrase.get('wrap_x_tags', bbcodetag.toUpperCase()), bbcodetag.toUpperCase(), bbcode.twoparams, resource);
		}
	}
});

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
