(function($){
	function create(sg)
	{
		tinymce.create('tinymce.plugins.' + sg.name, {
			init: function(ed, url) {
				var cmd_cb = function(name) {
					return function() {
						$('#' + name + '_modal').reveal({ animation: 'none' });
						$('#' + name + '_modal').css('top', parseInt($('#' + name + '_modal').css('top')) - window.scrollY);
						$('#' + name + '_modal').unbind('reveal:close.vp_w2dc_sc');
						$('#' + name + '_modal').bind('reveal:close.vp_w2dc_sc', function () {
							$('.vp-sc-menu-item.active').find('.vp-sc-form').scReset().vp_w2dc_slideUp();
							$('.vp-sc-menu-item.active').removeClass('active');
						});
						$('#' + name + '_modal').unbind('vp_w2dc_insert_shortcode.vp_w2dc_tinymce');
						$('#' + name + '_modal').bind('vp_w2dc_insert_shortcode.vp_w2dc_tinymce', function(event, code) {
							ed.selection.setContent(code);
							$(ed.getElement()).insertAtCaret(code);
						});
					}
				}
				ed.addCommand(sg.name + '_cmd', cmd_cb(sg.name));
				ed.addButton(sg.name, {title: sg.button_title, cmd: sg.name + '_cmd', image: sg.main_image});
			},
			getInfo: function() {
				return {
					longname: 'Vafpress Framework',
					author  : 'Vafpress'
				};
			}
		});
	}

	for (var i = 0; i < vp_w2dc_sg.length; i++){
		create(vp_w2dc_sg[i]);
	}

})(jQuery);

for (var i = 0; i < vp_w2dc_sg.length; i++){
	tinymce.PluginManager.add(vp_w2dc_sg[i].name, tinymce.plugins[vp_w2dc_sg[i].name]);
}
