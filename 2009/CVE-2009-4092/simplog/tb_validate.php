<?php
#echo "validating...";
#start with blacklist false
$blacklist = 0;
//Whitelist
//$whitelist_URLs = array("dimer.tamu.edu");
$whitelist_URLs = array();
$sql = "select * from blog_tb_whitelist";
$res = $db->Execute($sql);

while(!$res->EOF) {
	array_push($whitelist_URLs,$res->fields['host']);
	$res->MoveNext();
}

//$blacklist_keys = array("pics-videos.net","pictures-movies.org","pictures.org", "pics-db", "rape", "incest","learnhowtoplay.com", "psxtreme.com","freakycheats.com","chat-nett.com","terashells.com","crescentarian.net", "texasholdem","texas-hold-em","texashold-em", "holdem", "6q.org", "ronnieazza.com","phentermine", "viagra", "nutzu.com", "poker", "hold-em", "casino", "isacommie.com", "doobu.com","rohkalby.net", "bnetsol", "vrajitor", "ca-america.com", "buy-2005.com","buy-2004.com", "buy-2005-top.com", "win-2005.com", "vinhas.net", "conjuratia.com", "buy-", "pisangrebus.com", "-4u", "vnsoul", "top-ranked.com", "4hs8.com", "top-wins-2005.com","slot-machines", "hentai", "mature", "paranoyia", "gromozeka", "servepics", "flnet.org", "cialis", "levitra", "yaboo.dk", "sheevaburn", "porevo", "kakady", "darktech.org", "online-gambling", "gambling", "gardenaccentsllc", "bestiality","nudecelebs","instantgo.eu.com", "porn", "hardcore", "vegas-hair", "homebusiness", "gotravel", "whvc", "juris-net.com", "pirenea.org", "hopto.org", "isa-geek", "selection.eu", "ua-princeton.com", "gotdns", "bjob", "venezuela.com","tits", "homeunix.net", "alleghenydist.net", "servebeer", "racepointfunding", "analloverz","sexushost","ibusinessdot", "bigsitecity","hbsnwa.org","roulette","blackjack","epraha","money-4me","drugs-order");
$blacklist_keys = array();
$sql = "select * from blog_spam where field_id=".TB_URL;
$res = $db->Execute($sql);

while(!$res->EOF) {
	array_push($blacklist_keys,$res->fields['term']);
	$res->MoveNext();
}

//$blacklist_blog_names = array("roulette","free slots","blackjack","online poker");

$blacklist_blog_names = array();
$sql = "select * from blog_spam where field_id=".TB_BLOG_NAME;
$res = $db->Execute($sql);

while(!$res->EOF) {
       array_push($blacklist_blog_names,$res->fields['term']);
       $res->MoveNext();
}

//$blacklist_excerpt = array("check some helpful","check some information","check the pages","Please check out","check out the sites","some relevant pages","check the pages","check the sites","visit some helpful info","visit some information", "visit the sites about", "check out some information about","check out some helpful info","visit the sites dedicated","check out some information in the field","check out the pages","visit the pages about","visit the pages dedicated");

$blacklist_excerpt = array();
$sql = "select * from blog_spam where field_id=".TB_EXCERPT;
$res = $db->Execute($sql);

while(!$res->EOF) {
       array_push($blacklist_excerpt,$res->fields['term']);
       $res->MoveNext();
}

$temp = explode("/",$url);
$domain =  $temp[2];

#echo "url:$url<br>";
#echo "domain:$domain<br>";

if (!in_array($domain, $whitelist_URLs)){
	//Blacklist: process blacklist and set $blacklist to 1 if find something bad
	foreach ($blacklist_keys as $key){
		#look for the forbidden items in the url
		$test = stripos($url,$key);
		if ($test){
			$tb_error = "Forbidden key $key found in url $url<br>";
			$blacklist = 1;
			break;
		}
	}

	if ($blacklist == 0){
		$test_excerpt = " ".strtolower($excerpt); #so strpos will return + if key at position 0
		foreach ($blacklist_excerpt as $key){
			#look for the forbidden items in the excerpt
			$test = stripos($test_excerpt,$key);
			if ($test){
				$tb_error = "Forbidden key '$key' found in excerpt '$excerpt'<br>";
				$blacklist = 1;
				break;
			}
		}	
		#find urls in excerpt and test those
		preg_match_all("/(((http(s?):\/\/)|(www\.))([\-\_\w\.\/\#\?\+\&\=\%\;]+))/i",$test_excerpt,$matches);
		foreach($matches[0] as $url) {
			reset($blacklist_keys);
			foreach ($blacklist_keys as $key){
				$test = stripos($url,$key);
				if ($test){
					$tb_error = "Forbidden key '$key' found in excerpt url '$url'<br>";
					$blacklist = 1;
					break 2;
				}
			}	
		}	
	}
	if ($blacklist == 0){
		foreach ($blacklist_blog_names as $key){
			#look for the forbidden items in the blog name
			if ($blog_name == $key){
				$tb_error = "Forbidden blog name $key found in name $blog_name<br>";
				$blacklist = 1;
				break;
			}			
		}
	}
	if ($blacklist == 0){
		//test if can connect to url using function from php man pages for fsockopen
		if (!url_validate($url)){
			$blacklist = 1;
			$tb_error =  "invalid url";
		}
	}
	if ($blacklist == 0){
		if (!url_validate("http://$domain")){
			$blacklist = 1;
			$tb_error =  "invalid domain";
		}
	}	
}else{
	$tb_error =  "host found in whitelist";
}


/*
* @return boolean
* @param string $link
* @desc berprft die angegeben URL auf Erreichbarkeit (HTTP-Code: 200)
*/
function url_validate( $link ){ 
	global $http_response;
	$url_parts = @parse_url( $link );

	if ( empty( $url_parts["host"] ) ){
		#echo "host empty: $url<br>";
		return( false );
	}	

	if ( !empty( $url_parts["path"] ) ){
		$documentpath = $url_parts["path"];
	}else{
		$documentpath = "/";
	}

	if ( !empty( $url_parts["query"] ) ){
		$documentpath .= "?" . $url_parts["query"];
	}

	$host = $url_parts["host"];
	$port = @$url_parts["port"];
 
	// Now (HTTP-)GET $documentpath at $host";
	if (empty( $port ) ){
		$port = "80";
	}	

	$socket = @fsockopen( $host, $port, $errno, $errstr, 30 );
    if (!$socket){
    	#echo "Socket failed for $url<br>";

		return(false);
    }else{
		fwrite ($socket, "HEAD ".$documentpath." HTTP/1.0\r\nHost: $host\r\n\r\n");
		$http_response = fgets( $socket, 22 );
		#echo "response: $http_response<br>";
      if ( ereg("200 OK", $http_response, $regs ) ){
			return(true);
			fclose( $socket );
      }else{
		#echo "HTTP-Response: $http_response<br>";
		return(false);
      }
    }
  }
  #echo $tb_error;
?>
