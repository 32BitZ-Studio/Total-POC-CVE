pnpm := ./pnpm-linux-x64

npm: 
	npm install ./definitely_benign_package.tgz
	node words_of_affirmation.js

pnpm:
	$(pnpm) install ./definitely_benign_package.tgz
	node words_of_affirmation.js

clean: 
	rm -rf node_modules 
	rm -rf package-lock.json 
	rm -rf pnpm-lock.yaml package.json

