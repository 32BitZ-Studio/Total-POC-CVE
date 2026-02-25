Make the package in the other directory with the `make_tar.sh`.

Then, in this directory, installing the package with `npm install ./definitely_benign_package.tgz` and running with `node words_of_affirmation.js` will result in a happy message. 

installing with `pnpm install ./definitely_benign_package.tgz` and running with `node words_of_affirmation.js` will result in a mean message. 

Or you can use the automated `make npm` and `make pnpm`. You'll need to update the location of the vulnerable `pnpm` though. 
