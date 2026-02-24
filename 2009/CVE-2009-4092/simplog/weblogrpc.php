<?php 
// Send updates to weblogs.com via XML-RPC "ping" interface.
// For more information, see:
//   http://newhome.weblogs.com/directory/11
//
// $Log: weblogrpc.php,v $
// Revision 1.2  2004/02/06 07:57:14  f-bomb
// changes for 0.9beta
//
// Revision 1.5  2003/10/09 06:58:41  f-bomb
// changes for 0.9 release
//
// Revision 1.4  2003/06/11 02:48:36  jbuberel
// Fixes problem with the blog URL not having the GET param 'blogid=n' appended to it. Also migrated to make use of BlogInfo class.
//
// Revision 1.3  2002/09/27 14:14:22  emc3
// Updated to work with API functions
//
// Revision 1.1  2002/02/04 17:27:50  emc3
// Initial add
//
//

include_once("xmlrpc.inc");

  // If you want to use something other than the title and url that
  // you set in lib.php, change these.

  // let's get the blogInfo object...
  $blogInfo = new BlogInfo($blogid);
  
  $f=new xmlrpcmsg('weblogUpdates.ping',
				array(new xmlrpcval($blogInfo->getBlogTitle(),'string'),
					new xmlrpcval($blogInfo->getBlogURL(),'string')));
  $c=new xmlrpc_client("/RPC2", "rpc.weblogs.com", 80);
  $c->setDebug(0);
  $r=$c->send($f);
  if ($r->val) { 
      $v=xmlrpc_decode($r->value());
      if (!$r->faultCode()) {
    	$result['message'] =  "<p class=\"rpcmsg\">";
    	$result['message'] = $result['message'] .  $v["message"] . "<br />\n";
    	$result['message'] = $result['message'] . "</p>";
      } else {
    	$result['err'] = $r->faultCode();
    	$result['message'] =  "<!--\n";
    	$result['message'] = $result['message'] . "Fault: ";
    	$result['message'] = $result['message'] . "Code: " . $r->faultCode();
    	$result['message'] = $result['message'] . " Reason '" .$r->faultString()."'<BR>";
    	$result['message'] = $result['message'] . "-->\n";
      }

      // Checking $act will prevent us from creating spurious output when 
      // called from the Blogger API functions.
        print $result['message'];
  }
?>
