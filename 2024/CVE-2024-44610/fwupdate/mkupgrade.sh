#!/bin/sh


cd contents
rm -f content.sha
rm -f mahi.tar
sha512sum * >content.sha
tar cvf runup.tar *
mv runup.tar ..
