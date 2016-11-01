<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<meta http-equiv="x-ua-compatible" content="IE=8" >
<HEAD>
<cfoutput>
	<TITLE>#application.title#</TITLE>
</cfoutput>
	<link rel="stylesheet" type="text/css" href="style/Main.css" />
	<link rel="stylesheet" type="text/css" href="Validate/demo/css/screen.css" />
	<script language="JavaScript" src="scripts/gen_validatorv4.js" type="text/javascript"></script>
	<script type="text/javascript" src="scripts/dateValidation.js"></script>
	<script type="text/javascript" src="Validate/dist/jquery.validate.js"></script>
	<script type="text/javascript" src="Validate/dist/additional-methods.js"></script>

</HEAD>

<script>
	$.validator.setDefaults({
		submitHandler: function() {
			alert("submitted!");
		}
	});

	$().ready(function() {
		// validate form on keyup and submit
		$("#formLogin").validate({

			rules: {
				auid: {
					required: true,
					minlength: 2
					}
			},
			messages: {
				
				auid: {
					required: "Please enter your AUID.",
					minlength: "AUID must be at least 2 characters long."

				}
				
			}
		
		});
});
		
</script>


<!--- use IP addr to get user's lastusedtime value --->
<cfquery name="data" datasource="SupportCenter" dbtype="ODBC">
			select ip, auid, lastusedtime, pw  from  SupportCenter..logins where ip =  '#CGI.REMOTE_ADDR#'
</cfquery>
<cfif data.auid GT ''>
	<!--- copy database values to form fields  and decrypt password --->
	<cfset form.auid = data.auid>
	<cfset form.password = decrypt(data.pw, APPLICATION.EMPLOYEE_ENCRYPTIONKEY, APPLICATION.ENCRYPTIONALGORITHM, APPLICATION.ENCRYPTIONENCODING)>
	
	<!--- is current time <= user's last used time plus 30 mins --->
	<cfif now() LE dateadd('n',+30,data.lastusedtime) >
		<!--- login still valid  so update timestamp with current time  --->
		<cfquery name="data" datasource="SupportCenter" dbtype="ODBC">
        update supportcenter..logins set lastusedtime= #now()# where ip =  '#CGI.REMOTE_ADDR#'  
</cfquery>
		<cfelse>
		<!--- login expired so blank form vars  --->
		<cfset form.auid = ''>
		<cfset form.password = ''>
		<!--- and delete user's record from table --->
		<cfquery name="data" datasource="SupportCenter" dbtype="ODBC">
            delete from supportcenter..logins where ip =  '#CGI.REMOTE_ADDR#' 
</cfquery>
	</cfif>
</cfif>

<!--- if form AUID entered then do AD & LDAP validation  --->
<cfif isdefined('form.auid')>
	<cfinvoke component="CustomCFC.LoginAuth" method="ADAuth" returnvariable="myADAuth">
	<cfinvokeargument name="username" value="#form.auid#">
	<cfinvokeargument name="password" value="#form.password#">
	</cfinvoke>
	<cfif #myADAuth# EQ "false">
		<cflocation url="index.cfm?eL=6">
	</cfif>
	<cfif #myADAuth# EQ "true">
		<cfinvoke component="CustomCFC.LoginAuth" method="LDAPQuery" returnvariable="LDAPQuery">
		<cfinvokeargument name="username" value="#form.auid#">
		</cfinvoke>
		
		<!--- check to see if user has access to the application --->
		
		<CFQUERY name="checkuser" datasource="#APPLICATION.DATASOURCE#" dbtype="ODBC">
        SELECT *
        FROM FSOTrainDBUsers
        WHERE UUPIC = <cfqueryparam cfsqltype="cf_sql_varchar" value="#LDAPQuery.employeeNumber#" maxlength="10">
 	</CFQUERY>
		
		<!---Set session variables--->
		<cfif #checkuser.recordcount# GT 0>
			<cfset session.IsAdmin = #checkuser.IsAdmin#>
			
			<!--- Update user login info --->
			<cfquery name="UpdateLogin" datasource="#APPLICATION.DATASOURCE#" dbtype="ODBC">
        	UPDATE FSOTrainDBUsers
            SET LastLoginDate = CURRENT_TIMESTAMP
            WHERE UUPIC = <cfqueryparam cfsqltype="cf_sql_varchar" value="#LDAPQuery.employeeNumber#" maxlength="10">
        </cfquery>
			<cfset session.auid = #form.auid#>
			<cfset session.name = #LDAPQuery.cn#>
			<cfset session.userfullname = #listfirst(LDAPQuery.cn)#>
			<cfset session.email = #listfirst(LDAPQuery.nasaPrimaryEmail)#>
			<cfset session.center = #LDAPQuery.ou#>
			<!--- delete user's record from logins table (this may fail because record may not exist)--->
			<cfquery name="data" datasource="SupportCenter" dbtype="ODBC">
		delete from supportcenter..logins where ip =  '#CGI.REMOTE_ADDR#'
     </cfquery>
			<!--- insert user record in logins table and encrypt password  --->
			<cfquery name="data" datasource="SupportCenter" dbtype="ODBC">
        insert supportcenter..logins values 
        ('#CGI.REMOTE_ADDR#','#form.auid#', '#Encrypt(form.password, APPLICATION.EMPLOYEE_ENCRYPTIONKEY, APPLICATION.ENCRYPTIONALGORITHM, APPLICATION.ENCRYPTIONENCODING)#' ,'#dateformat(now(), "yyyy-mm-dd")#T#TimeFormat(now(), "HH:nn:ss")#' ) 
    </cfquery>
			<cfelse>
			<cflocation url="index.cfm?u=6">
		</cfif>
		
		<!---jump to main.cfm page and pass AUID param--->
		<cflocation url="main.cfm?auid=#form.auid#">
	</cfif>
</cfif>

<!--- create logon window/form  --->
<body>
<h1 class="indextitle" align="center">FSO Training Database</h1>

<div align="center">
<!---	<form action="index.cfm" method="post" name="formLogin" class="form-container">
		<div class="form-title"><h2>LOGIN</h2></div>
		<div class="form-title">AUID</div>
			<input class="form-field" type="text" name="auid" />
		<br />
		<div class="form-title">PASSWORD</div>
			<input class="form-field" type="password" name="password" />
		<br />
		<div class="submit-container">
			<input type="submit" class="submit-button" value="Submit">
		</div>
		<cfif isdefined('url.el')>
			<div class="errorText">
			Your <b>Authentication</b> failed.  Did you enter correct AUID and password?  These are same credentials you use to log in to your computer.
			</div>
		</cfif>
		<cfif isdefined('url.u')>
			<div class="errorText">
			Your <b>Authorization</b> failed.  Have you submitted a NAMS request for access to this tool? Contact the FSO on 286-4436 opt 2.
			</div>
		</cfif>
	</form>--->

	<form action="index.cfm" method="post" name="formLogin" id="formLogin" class="form-container">
		<div class="form-title"><h2>LOGIN</h2></div>
		<div class="form-title">AUID</div>
			<input class="form-field" type="text" name="auid" />
		<br />
		<div class="form-title">PASSWORD</div>
			<input class="form-field" type="password" name="password" />
		<br />
		<div class="submit-container">
			<input type="submit" class="submit-button" value="Submit">
		</div>
		<cfif isdefined('url.el')>
			<div class="errorText">
			Your <b>Authentication</b> failed.  Did you enter correct AUID and password?  These are same credentials you use to log in to your computer.
			</div>
		</cfif>
		<cfif isdefined('url.u')>
			<div class="errorText">
			Your <b>Authorization</b> failed.  Have you submitted a NAMS request for access to this tool? Contact the FSO on 286-4436 opt 2.
			</div>
		</cfif>
<!---			<fieldset >
			<legend>Login</legend>
			<p>
			<label for="auid">Auid</label>
			<input type="text" name="auid" id="auid">
			</p>
			<p>
			<label for="password">Password</label>
			<input type="password" name="password" id="password">
			</p>
			<p>
			<input type="submit" value="Submit" class="submit-button">
			</p>			
		</fieldset>--->
		
	</form>

	
	
	
</div>

<br><br><br>
<br><br><br>

<cfinclude template='footer.cfm'>
</BODY>
</HTML>