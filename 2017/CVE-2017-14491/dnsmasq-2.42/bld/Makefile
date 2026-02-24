CFLAGS += -Wall -W -Os

OBJS = cache.o rfc1035.o util.o option.o forward.o network.o \
       dnsmasq.o netlink.o bpf.o \
       log.o

DEPENDENCE_FILE = ../bld/Makefile

#ifeq ($(CONFIG_DNSMASQ_DHCP_SUPPORT),y)
#CFLAGS += -DHAVE_DHCP
#OBJS += dhcp.o lease.o rfc2131.o isc.o helper.o
#endif

#ifeq ($(CONFIG_DNSMASQ_OPENDNS),y)
#CFLAGS += -DOPENDNS
#endif

CFLAGS += -DCONFIG_WEB_404_REDIRECT

ifeq ($(ROOT_PATH),)
include $(shell pwd)/../../../.config
else
include $(ROOT_PATH)/.config
endif

ifneq ($(SUPPORT_IPv6),y)
CFLAGS += -DNO_IPV6
endif

.c.o: $(DEPENDENCE_FILE)
	$(CC) $(CFLAGS) $(DISABLE_IPV6) -c $<

dnsmasq : $(DEPENDENCE_FILE) $(OBJS)
	$(CC) $(LDFLAGS) -o $@  $(OBJS) $(LIBS) 
 
dnsmasq.pot : $(OBJS:.o=.c) dnsmasq.h config.h
	xgettext -d dnsmasq --foreign-user --keyword=_ -o dnsmasq.pot -i $(OBJS:.o=.c)

%.mo : ../po/%.po dnsmasq.pot
	msgmerge -o - ../po/$*.po dnsmasq.pot | msgfmt -o $*.mo -

%.o: %.c
	$(CC) $(CFLAGS) -g -c -o $@ $< -g -Wp,-MD,.$<.dep

