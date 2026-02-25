// defaults and polyfills
// eslint-disable-next-line no-undef
window = self;
// eslint-disable-next-line no-undef
top = self;
const kubioNoop = function () {};

document = {
	createElement() {
		return {
			style: [],
			setAttribute: kubioNoop,
			attachEvent: kubioNoop,
		};
	},
	attachEvent: kubioNoop,
	addEventListener: kubioNoop,
	querySelectorAll() {
		return [];
	},
};

// wp imported scripts need to load kubio-style-manager
// {{{importScriptsPlaceholder}}}

const fonts = {};

// eslint-disable-next-line no-undef
wp.hooks.addAction(
	'kubio.google-fonts.load',
	'kubio.google-fonts.load',
	function (nextFonts) {
		nextFonts.forEach(function (font) {
			fonts[font.family] = fonts[font.family] || [];
			// eslint-disable-next-line no-undef
			fonts[font.family] = lodash.uniq(
				fonts[font.family].concat(font.variants)
			);
		});
	}
);

const renderStyle = function (payload) {
	// eslint-disable-next-line no-undef
	const dynamicStyle = lodash.get(payload.data, 'dynamicStyle', {});

	// eslint-disable-next-line no-undef
	const renderer = new kubio.styleManager.BlockStyleRender(
		// eslint-disable-next-line no-undef
		lodash.omit(payload.data, 'dynamicStyle'),
		payload.parentDetails,
		payload.canUseHtml,
		payload.document || null
	);

	const styleRef = renderer.model ? renderer.model.styleRef : null;
	const localId = renderer.model ? renderer.model.id : null;

	return {
		css: renderer.export(),
		dynamicRules: renderer.exportDynamicStyle(dynamicStyle),
		styleRef,
		localId,
		responseHash: payload.hash,
		fonts: Object.keys(fonts).map((family) => ({
			family,
			variants: fonts[family],
		})),
	};
};

// actual web worker runner
// eslint-disable-next-line no-undef
self.addEventListener('message', (event) => {
	const action = event.data.action;
	const hash = event.data.hash;
	const payload = lodash.isObject(event.data.payload)
		? event.data.payload
		: JSON.parse(event.data.payload);

	let response = null;

	switch (action) {
		case 'EXPORT_CSS':
			response = renderStyle(payload);
			break;
		case 'TEST':
			response = 'test';
			break;
	}

	// eslint-disable-next-line no-undef
	self.postMessage({
		hash,
		payload: response,
	});
});

// eslint-disable-next-line no-undef
self.postMessage('WORKER_LOADED');
