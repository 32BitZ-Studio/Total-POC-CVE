<?PHP

session_start();
 
require_once("lib.php");
require_once("class.BlogInfo.php");
 
auth();

if(!isAdmin()) {
	header("Location: logout.php\n\n");
	exit(0);
}

$uid = getUID($_SESSION['login']);

if(!$_REQUEST['blogid']) {
    $sql = "SELECT blog_id from blog_acl where user_id=$uid";
    $res = $db->Execute($sql);

    $blogid = $res->fields[blog_id];
} else {
    $blogid = $_REQUEST['blogid'];
}

$blogInfo = new BlogInfo($blogid);

include("header.php");

?>

<script language="JavaScript">

function addNames() {
  mailList = window.document.modblog.elements['acl[]'];
  srcList = window.document.modblog.elements['luser[]'];
 
  if (mailList.options[0].text == "No Users Selected") {
    mailList.options[0] = null;
  }
  var len = mailList.length;
  for(var i = 0; i <srcList.length; i++) {
    if ((srcList.options[i] != null) && (srcList.options[i].selected)) {
      //Check if this value already exist in the destList or not
      //if not then add it, otherwise do not add it.
      var found = false;
      for(var count = 0; count <len; count++) {
        if (mailList.options[count] != null) {
          if (srcList.options[i].text == mailList.options[count].text) {
            found = true;
            break;
          }
        }
      }
      if (found != true) {
        mailList.options[len] = new Option(srcList.options[i].text);
		mailList.options[len].value = srcList.options[i].value;
        len++;
        }
      }
   }
}
 
function removeNames() {
  var minusList  = window.document.modblog.elements['acl[]'];
  var len = minusList.options.length;
  for(var i = (len-1); i >= 0; i--) {
    if ((minusList.options[i] != null) && (minusList.options[i].selected == true)) {
      minusList.options[i] = null;
    }
  }
 
  if(minusList.options.length == 0) {
          minusList.options[0] = new Option("No Users Selected");
          minusList.options[0].value = "null";
  }
}

function selectAll(act) {

	var type = window.document.modblog.elements['type'];
	var len;	

	if(act == 'add') {
		var acl = window.document.modblog.elements['luser[]'];
		len = acl.options.length;
		if(type.options[type.selectedIndex].text == "private") {
			var one = false;
			var two = false;
			for(var i=0; i<len; i++) {
				if(acl.options[i].selected == true) {
					if(one) {
						two = true;
					} else {
						one = true;
					}
				}
			}

			if(two) {
				alert('You can only choose one user!');
				return false;
			}

			if(!one) {
				alert('You must choose one user!');
				return false;
			}

		} else if(type.options[type.selectedIndex].text == "public") {
			len = acl.options.length;
                	for( var i = 0; i < len; i++) {
                        	acl.options[i].selected = true;
                	}
		} else {
			var one = false;
                        for(var i=0; i<len; i++) {
                                if(acl.options[i].selected == true) {
                                	one = true;
                                }
                        }

			if(!one) {
				alert('You must choose one user!');
                                return false;
			}
		}

	} else {
		var acl = window.document.modblog.elements['acl[]'];

		if(type.options[type.selectedIndex].text == "public") {
			var luser = window.document.modblog.elements['luser[]'];
			var luslen = luser.options.length;
			for(var i = (luslen-1); i >= 0; i--) {
        			luser.options[i].selected = true;
        		}

			addNames();

			for( i = (luslen-1); i >= 0; i--) {
                		luser.options[i].selected = false;
        		}
		}

		len = acl.options.length;
		for( i = (len-1); i >= 0; i--) {
    			if (acl.options[i].text != "No Users Selected"){
				acl.options[i].selected = true;
    			}
		}

	}
	return true;
}

function checkAll(check) {
         var iForm = check.form;
	for(var i = 0; i<iForm.length; i++) {
         	if(iForm[i].type == 'checkbox' && iForm[i].name != 'all') {
       			iForm[i].checked = check.checked;
       		}
         }
}

</script>
<table width=100%>

<?php 
	switch ($_REQUEST['adm']) {

	case "user": 
		include("user.admin.php");
		break;
	case "blog":
		include("blog.admin.php");
		break;
	case "tem":
		include("tem.admin.php");
		break;
	case "spam":
		include("spam.admin.php");
		break;
	case "ban":
		echo ip_ban($_REQUEST['ip']);
		echo " <a href=\"javascript: history.go(-1)\">Go Back</a>\n";
		break;
	default:
		include("user.admin.php");
		break;
	}

?>	

</table>
<?php 
	include("footer.php");
?>
