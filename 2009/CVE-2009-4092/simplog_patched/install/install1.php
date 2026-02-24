<b>New Installation</b> - Please choose a login/password for the admin user. 
<p>
<form method=POST action="install.php">
<center>
<table>
<?php if(in_array("alogin",$errors)): ?>
<tr><td colspan=2 style="color: red">You must provide a login</td></tr>
<?php endif; ?>
<tr>
<td align=right>Admin Login:</td><td><input type=text name=alogin value="<?=$_REQUEST['alogin']?>" maxlength=8></td>
</tr>
<?php if(in_array("apass",$errors)): ?>
<tr><td colspan=2 style="color: red">You must provide a password</td></tr>
<?php endif; ?>
<?php if(in_array("apasseq",$errors)): ?>
<tr><td colspan=2 style="color: red">Passwords must match!</td></tr>
<?php endif; ?>
<tr>
<td align=right>Password:</td><td><input type=password name=apass1></td>
</tr>
<tr>
<td align=right>Re-Enter Password:</td><td><input type=password name=apass2></td>
</tr>
<tr>
<td align=right>Admin Name:</td><td><input type=text name=aname value="<?=$_REQUEST['aname']?>"></td>
</tr>
<?php if(in_array("aemail",$errors)): ?>
<tr><td colspan=2 style="color: red">You must provide an email address</td></tr>
<?php endif; ?>
<tr>
<td align=right>Admin Email:</td><td><input type=text name=aemail value="<?=$_REQUEST['aemail']?>"></td>
</tr>
<tr>
<td align=right>Admin URL:</td><td><input type=text name=aurl value="<?=$_REQUEST['aurl']?>"></td>
</tr>
</table>
<input type=hidden name=dbtype value="<?=$_REQUEST['dbtype']?>">
<input type=hidden name=dbname value="<?=$_REQUEST['dbname']?>">
<input type=hidden name=dbhost value="<?=$_REQUEST['dbhost']?>">
<input type=hidden name=dbuser value="<?=$_REQUEST['dbuser']?>">
<input type=hidden name=dbpass value="<?=$_REQUEST['dbpass']?>">
<input type=hidden name=from value="install1">
<p>
Simplog will now install the database.<br>
<input class=search type=submit value="Install!">
</center>
</form>
