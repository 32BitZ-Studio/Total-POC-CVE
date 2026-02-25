(function() {
	CodeMirror.vbulletinHints = {};
	CodeMirror.vbulletinHints['<vb:'] = ['comment','each','else','elseif','if','literal'];
	CodeMirror.vbulletinHints['<vb:if '] = ['condition=""'];
	CodeMirror.vbulletinHints['<vb:comment '] = ['>'];
	CodeMirror.vbulletinHints['<vb:literal '] = ['>'];
	CodeMirror.vbulletinHints['<vb:else '] = ['/ >'];
	CodeMirror.vbulletinHints['<vb:elseif '] = ['/ >'];
	CodeMirror.vbulletinHints['<vb:each '] = ['value=""'];
	CodeMirror.vbulletinHints['{vb:'] = [
		'action','compilesearch','concat','cssextra','csspath','customstylevar','data','date','datetime','debugtrace','debugvardump',
		'escapejs','headlink','hook','if','js','link','math','number','php','phrase','raw','rawdata','rawphrase','redirect',
		'schema','set','signature','strcat','strrepeat','stylevar','template','time','url','urladmincptemp','urlencode','var'
	];
	CodeMirror.vbulletinHints['{vb:php '] = [
		'array','array_fill_keys','array_intersect','array_intersect_key','array_keys','array_merge','array_pop','array_push','array_shift',
		'array_sum','array_unique','array_unshift','count','current','explode','implode','intval','json_decode','json_encode','range','str_pad',
		'str_repeat','strip_tags','strtolower','strtoupper','substr','trim','vB5_String::parseUrl','vbstrtolower'
	];

	CodeMirror.commands.autocomplete = function(cm) {
		CodeMirror.showHint(cm, CodeMirror.vbulletinHint);
	}
	  function passAndHint(cm) {
		setTimeout(function() {cm.execCommand("autocomplete");}, 100);
		return CodeMirror.Pass;
	  }

	CodeMirror.vbulletinHint = function(cm) {

		var cursor = cm.getCursor();

		if (cursor.ch > 0) {

			var text = cm.getRange(CodeMirror.Pos(0, 0), cursor);
			var typed = '';
			var simbol = '';
			var chr = '';
			for(var i = text.length - 1; i >= 0; i--) {
				if(text[i] == ' ')
				{
					simbol = ' ';
					break;
				}
				if (text.length >= 4 && text.slice(i-2,i+1) == 'vb:')
				{
					simbol = text[i-3];
					if (simbol == '<' || simbol == '{')
					{
						chr = simbol;
						break;
					}
				}
				typed = text[i] + typed;
			}

			text = text.slice(0, text.length - typed.length);

			var path = getActiveElement(text, chr) + (simbol == ' ' ? ' ' : '');
			var hints = CodeMirror.vbulletinHints[path];

			if(typeof hints === 'undefined')
				hints = [''];
			else {
				hints = hints.slice(0);
				for (var i = hints.length - 1; i >= 0; i--) {
					if(hints[i].indexOf(typed) != 0)
						hints.splice(i, 1);
				}
			}

			return {
				list: hints,
				from: CodeMirror.Pos(cursor.line, cursor.ch - typed.length),
				to: cursor
			};
		}
	};

	var getActiveElement = function(text) {

		var element = '';

		if(text.length >= 0) {
			var regex;
			if (text.lastIndexOf('<') > text.lastIndexOf('{'))
			{
				regex = new RegExp('<([^!?][^\\s/>]*).*?>', 'g');
				simbol = '<';
			}
			else
			{
				regex = new RegExp('{([^!?][^\\s}]*).*?}', 'g');
				simbol = '{';
			}

			var matches = [];
			var match;
			while ((match = regex.exec(text)) != null) {
				matches.push({
					tag: match[1],
					selfclose: simbol == '{' ? 1 : (match[0].slice(match[0].length - 2) === '/>')
				});
			}

			for (var i = matches.length - 1, skip = 0; i >= 0; i--) {

				var item = matches[i];

				if (item.tag[0] == '/')
				{
					skip++;
				}
				else if (item.selfclose == false)
				{
					if (skip > 0)
					{
						skip--;
					}
					else if(simbol == '{')
					{
						element = '{' + item.tag + '}' + element;
					}
					else
					{
						element = '<' + item.tag + '>' + element;
					}
				}
			}

			element += getOpenTag(text, simbol);
		}

		return element;
	};

	var getOpenTag = function(text, simbol) {
		var open;
		var close;
		var chr = '<';
		if (simbol == '{')
		{
			open = text.lastIndexOf('{');
			close = text.lastIndexOf('}');
			chr = '{';
		}
		else
		{
			open = text.lastIndexOf('<');
			close = text.lastIndexOf('>');
		}
		if (close < open)
		{
			text = text.slice(open);

			if(text != chr) {

				var space = text.indexOf(' ');
				if(space < 0)
					space = text.indexOf('\t');
				if(space < 0)
					space = text.indexOf('\n');

				if (space < 0)
					space = text.length;

				return text.slice(0, space);
			}
		}

		return '';
	};
})();
