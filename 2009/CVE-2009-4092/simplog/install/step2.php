<b>Database Info</b> - Please enter your database info:
<center>
<?php if($error): ?>
<b>You must fill in the host and DB name!</b>
<?php endif; ?>
<form method=POST action="install.php">
<input type=hidden name=from value="step2">
<table>
<tr>
<td align=right>DB Host</td><td><input type=text name=dbhost value="localhost"></td>
</tr>
<tr>
<td align=right>DB User</td><td><input type=text name=dbuser value=""></td>
</tr>
<tr>
<td align=right>DB Password</td><td><input type=text name=dbpass value=""></td>
</tr>
<tr>
<td align=right>DB Name</td><td><input type=text name=dbname value=""></td>
</tr>
<td align=right>DB Type</td><td>
<select name=dbtype>
<option value="db2">DB2
<option value="firebird">Firebird
<option value="fbsql">FrontBase
<option value="informix">Informix
<option value="mssql">M$ SQL Server
<option value="mysql" selected>MySQL
<option value="odbc">ODBC
<option value="oci8">Oracle
<option value="postgres">PostgreSQL
<option value="sapdb">SAP DB
<option value="sqlite">SQLite
<option value="sybase">Sybase
</select>
</td></tr>
</table>
<input class=search type=submit value="Submit">
</form>
</center>
<p>
