#!/usr/bin/perl

# Discover, for a host, if we may need to worry about CVE-2013-0229 / CVE-2013-0230 / CVE-2012-5958 / CVE-2012-5959
# Perl port of http://dev.metasploit.com/redmine/projects/framework/repository/entry/modules/auxiliary/scanner/upnp/ssdp_msearch.rb
# Copyright (C) 2006-2013, Rapid7 LLC - http://www.metasploit.com/license.jsp
# david.freedman@uk.clara.net - 201301292337

use IO::Socket::INET;

# flush after every write
$| = 1;

# Get IPv4 IP
my $ip = $ARGV[0] || die "Usage: $0 <ipv4 ip>\n";

my $data = "M-SEARCH * HTTP/1.1\r\nHost:239.255.255.250:1900\r\nST:upnp:rootdevice\r\nMan:\"ssdp:discover\"\r\nMX:3\r\n\r\n\r\n";

# Eval / Alarm wrapped query to avoid socket timeouts
eval {

  # Set up alarm handling
  local $SIG{ALRM} = sub { print "\n"; die 'Timed Out'; };
  alarm 2;

  # Start output
  print "$ip ";

  # Open socket
  my $sock = IO::Socket::INET->new( PeerAddr => $ip, PeerPort => 1900, Proto => 'udp' );
  $sock->autoflush;

  # Send M-Search Query
  $sock->send($data);

  # Read back from socket to see if we have anything to worry about in the response, print it
  while (my $data = <$sock>) {
        if ($data=~m/MiniUPnPd\/1\.0([\.\,\-\~\s]|$)/mi) {
                print " CVE-2013-0229";
        }
        elsif ($data=~m/MiniUPnPd\/1\.[0-3]([\.\,\-\~\s]|$)/mi) {
                print " CVE-2013-0230";
        }
        elsif ($data=~/Intel SDK for UPnP devices.*|Portable SDK for UPnP devices(\/?\s*$|\/1\.([0-5]\..*|8\.0.*|(6\.[0-9]|6\.1[0-7])([\.\,\-\~\s]|$)))/mi) {
                print " CVE-2012-5958 / CVE-2012-5959";
        }
        elsif ($data=~m/Location: (.*)/) {
                print " Location : $1";
        }
  }

  # Tidy up screen
  print "\n";

  # Close socket
  $sock->close();

  # Reset Alarm
  alarm 0;
};
alarm 0; # race condition protection 
