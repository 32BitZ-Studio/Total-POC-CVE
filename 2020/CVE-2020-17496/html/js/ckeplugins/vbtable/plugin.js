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

window.vBulletin = window.vBulletin || {};
window.vBulletin.phrase = window.vBulletin.phrase || {};
window.vBulletin.phrase.precache = window.vBulletin.phrase.precache || [];
window.vBulletin.phrase.precache = $.merge(window.vBulletin.phrase.precache, [
	'add_table',
	'table_tools'
]);

CKEDITOR.plugins.add('vbtable',
{
	requires: 'table,menubutton',

	init : function( editor )
	{
		editor.ui.add( 'vBTable', CKEDITOR.UI_MENUBUTTON,
		{
			label : vBulletin.phrase.get('table_tools'),
			title : vBulletin.phrase.get('table_tools'),
			// The 'default' bit in this path can change to 'dark' (or something else) based
			// on the ckeditor_image_path stylevar. It's automatically changed in ckeditor.js
			// in modifyImagePaths().
			icon: window.pageData.baseurl + '/js/ckeditor/images/default/icons.png',
			iconOffset: -1776, // this offset is that of the table button, which we hide by default. Unhide it in ckeditor.js to get the offset
			toolbar : 'table,20',
			modes : { wysiwyg : 1 },
			onMenu : function()
			{
				// This is for when the table button is pressed before the cursor is active
				// in the editor. Without this, all of the table options appear in the dropdown
				var selection = editor.getSelection(),
					startElement = selection && selection.getStartElement(),
					table = startElement && startElement.getAscendant( 'table', 1 );

				if (!table)
				{
					return { 'table': CKEDITOR.TRISTATE_OFF };
				}
				else
				{
					return {
						'table': CKEDITOR.TRISTATE_OFF,
						'tableProperties': CKEDITOR.TRISTATE_OFF,
						'tableDelete': CKEDITOR.TRISTATE_OFF,
						'rowInsertBefore': CKEDITOR.TRISTATE_OFF,
						'rowInsertAfter': CKEDITOR.TRISTATE_OFF,
						'rowDelete': CKEDITOR.TRISTATE_OFF,
						'columnInsertBefore': CKEDITOR.TRISTATE_OFF,
						'columnInsertAfter': CKEDITOR.TRISTATE_OFF,
						'columnDelete': CKEDITOR.TRISTATE_OFF
					};
				}
			},
			onRender: function()
			{
				editor.addMenuGroup('vBtable', 1);
				editor.addMenuGroup('vBtablerow', 2);
				editor.addMenuGroup('vBtablecol', 3);
				editor.addMenuGroup('vBtableprop', 4);

				if (editor.addMenuItems)
				{
					editor.addMenuItems({
						table : {
							command : 'table',
							group : 'vBtable',
							label : vBulletin.phrase.get('add_table'),
							order : 8
						},
						rowInsertBefore : {
							command : 'rowInsertBefore',
							group : 'vBtablerow',
							label : editor.lang.table.row.insertBefore,
							order : 8
						},
						rowInsertAfter : {
							command : 'rowInsertAfter',
							group : 'vBtablerow',
							label : editor.lang.table.row.insertAfter,
							order : 8
						},
						rowDelete : {
							command : 'rowDelete',
							group : 'vBtablerow',
							label : editor.lang.table.row.deleteRow,
							order : 8
						},
						columnInsertBefore : {
							command : 'columnInsertBefore',
							group : 'vBtablecol',
							label : editor.lang.table.column.insertBefore,
							order : 8
						},
						columnInsertAfter : {
							command : 'columnInsertAfter',
							group : 'vBtablecol',
							label : editor.lang.table.column.insertAfter,
							order : 8
						},
						columnDelete : {
							command : 'columnDelete',
							group : 'vBtablecol',
							label : editor.lang.table.column.deleteColumn,
							order : 8
						},
						tableDelete : {
							command : 'tableDelete',
							group : 'vBtableprop',
							label : editor.lang.table.deleteTable,
							order : 8
						},
						tableProperties : {
							command : 'tableProperties',
							group : 'vBtableprop',
							label : editor.lang.table.menu,
							order : 8
						}
					});
				}
			}
		});
	}
});

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
