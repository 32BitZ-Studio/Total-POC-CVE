# dnsmasq is Copyright (c) 2000-2007 Simon Kelley
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; version 2 dated June, 1991, or
#  (at your option) version 3 dated 29 June, 2007.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#    
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
# ---------------------

SRC = src

INSTALL = install

all :   dnsmasq

dnsmasq :
	cd $(SRC) && $(MAKE) -f ../bld/Makefile dnsmasq 

clean :
	rm -f *~ $(SRC)/*.mo contrib/*/*~ */*~ $(SRC)/*.pot 
	rm -f $(SRC)/*.o $(SRC)/dnsmasq.a $(SRC)/dnsmasq core */core

install : all install-common

install-common :
	install -m 755 $(SRC)/dnsmasq $(ROOT_FS)/sbin

