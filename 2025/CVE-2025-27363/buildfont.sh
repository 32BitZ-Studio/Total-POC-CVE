#!/bin/bash
fonttools ttx "roboto-flex-fonts/fonts/variable/RobotoFlex[GRAD,XOPQ,XTRA,YOPQ,YTAS,YTDE,YTFI,YTLC,YTUC,opsz,slnt,wdth,wght].ttf" -o rf.xml
python3 givememore.py
fonttools ttx rf2.xml -o rf2.ttf
