CodeMirror.defineMode("vbulletin", function(config, parserConfig) {
	var vbmodeOverlay = {
		token: function(stream, state)
		{
			var isComment = false;
			var start = stream.start;
			if (stream.string.indexOf("<vb:comment>") != -1)
			{
				if (stream.match("<vb:comment>"))
				{
					state.commentOpen = true;
					isComment = true;
				}
				else
				{
					while ((ch = stream.next()) != null)
					{
						if (stream.match("<vb:comment>"))
						{
							state.commentOpen = true;
							isComment = true;
							break;
						}
					}
					if (!isComment)
					{
						stream.backUp(stream.pos - start);
					}
				}
			}

			if (state.commentOpen)
			{
				isComment = true;
				if (stream.match("</vb:comment>"))
				{
					state.commentOpen = false;
				}
				else
				{
					while ((ch = stream.next()) != null)
					{
						if (stream.match("</vb:comment>"))
						{
							state.commentOpen = false;
							break;
						}
					}
				}
			}
			if (isComment)
			{
				return "comment";
			}
			if (stream.match("{vb:")) {
				var open = 1;
				while ((ch = stream.next()) != null)
				{
					if (ch == "}")
					{
						if (open <= 1)break;
						open--;
					}
					if (stream.match("{vb:"))
					{
						open++;
					}
				}
				return "vbulletincurly";
			}

			while (stream.next() != null && !stream.match("{vb:", false)) {}
			return null;
		},
		startState: function() {
			return {commentOpen: false};
		},
	};
	return CodeMirror.overlayMode(CodeMirror.getMode(config, parserConfig.backdrop || "text/css"), vbmodeOverlay);
});