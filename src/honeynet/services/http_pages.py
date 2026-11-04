"""Static/fake pages served by the HTTP honeypot. Reflected values are always escaped."""

from __future__ import annotations

import html
import time

SERVER_HEADER = "Apache/2.4.41 (Ubuntu)"


def esc(s: str) -> str:
    return html.escape(s, quote=True)


def apache_default() -> str:
    return """<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml"><head><meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
<title>Apache2 Ubuntu Default Page: It works</title></head><body>
<div class="main_page"><div class="page_header floating_element"><span class="floating_element">Apache2 Ubuntu Default Page</span></div>
<div class="content_section_text"><p>This is the default welcome page used to test the correct operation of the Apache2 server after installation on Ubuntu systems.
It is based on the equivalent page on Debian, from which the Ubuntu Apache packaging is derived. If you can read this page, it means that the Apache HTTP server installed at this site is working properly.</p></div>
<div class="section_header">Configuration Overview</div></div></body></html>
"""


def not_found(path: str) -> str:
    return (f"<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n<title>404 Not Found</title>\n</head><body>\n"
            f"<h1>Not Found</h1>\n<p>The requested URL {esc(path[:200])} was not found on this server.</p>\n<hr>\n"
            f"<address>{SERVER_HEADER} Server at localhost Port 80</address>\n</body></html>\n")


def forbidden(path: str) -> str:
    return (f"<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n<title>403 Forbidden</title>\n</head><body>\n"
            f"<h1>Forbidden</h1>\n<p>You don't have permission to access {esc(path[:200])} on this server.</p>\n</body></html>\n")


def wordpress_login(error: str = "", user: str = "") -> str:
    err = f'<div id="login_error"><strong>Error</strong>: {error}<br /></div>' if error else ""
    return f"""<!DOCTYPE html><html lang="en-US"><head><meta charset="UTF-8"><title>Log In &lsaquo; Acme Blog &#8212; WordPress</title>
<meta name='robots' content='max-image-preview:large, noindex, noarchive' /></head>
<body class="login login-action-login wp-core-ui"><div id="login"><h1><a href="https://wordpress.org/">Powered by WordPress</a></h1>{err}
<form name="loginform" id="loginform" action="/wp-login.php" method="post">
<p><label for="user_login">Username or Email Address</label><input type="text" name="log" id="user_login" value="{esc(user)}" size="20" autocapitalize="off" /></p>
<p><label for="user_pass">Password</label><input type="password" name="pwd" id="user_pass" value="" size="20" /></p>
<p class="forgetmenot"><input name="rememberme" type="checkbox" id="rememberme" value="forever" /> <label for="rememberme">Remember Me</label></p>
<p class="submit"><input type="submit" name="wp-submit" id="wp-submit" class="button button-primary button-large" value="Log In" />
<input type="hidden" name="redirect_to" value="/wp-admin/" /><input type="hidden" name="testcookie" value="1" /></p></form>
<p id="nav"><a href="/wp-login.php?action=lostpassword">Lost your password?</a></p></div></body></html>
"""


def phpmyadmin_login(error: str = "") -> str:
    err = f'<div class="error"><img src="themes/dot.gif" class="icon ic_s_error" alt="" /> {error}</div>' if error else ""
    return f"""<!DOCTYPE HTML><html lang="en" dir="ltr"><head><meta charset="utf-8" /><title>phpMyAdmin</title>
<meta name="generator" content="phpMyAdmin 4.9.5deb2" /></head><body class="loginform"><div class="container">
<a href="index.php" class="logo"><img src="themes/pmahomme/img/logo_right.png" alt="phpMyAdmin" /></a><h1>Welcome to phpMyAdmin</h1>{err}
<form method="post" action="index.php" name="login_form" class="disableAjax login">
<fieldset><legend>Log in</legend><div class="item"><label for="input_username">Username:</label><input type="text" name="pma_username" id="input_username" value="" size="24" class="textfield"/></div>
<div class="item"><label for="input_password">Password:</label><input type="password" name="pma_password" id="input_password" value="" size="24" class="textfield" /></div>
<input type="hidden" name="server" value="1" /></fieldset><fieldset class="tblFooters"><input value="Go" type="submit" id="input_go" /></fieldset></form></div></body></html>
"""


def router_login(error: str = "") -> str:
    err = f'<p style="color:red">{error}</p>' if error else ""
    return f"""<html><head><meta http-equiv="Content-Type" content="text/html; charset=utf-8"><title>Wireless Router - Login</title></head>
<body bgcolor="#e8e8e8"><center><table width="420" cellpadding="6"><tr><td><h2>AC1200 Dual Band Wireless Router</h2><p>Model: WR-1200N &nbsp; Firmware Version: 1.0.4 Build 190412</p></td></tr>
<tr><td>{err}<form method="post" action="/login.cgi"><table><tr><td>User Name:</td><td><input type="text" name="username" maxlength="31"></td></tr>
<tr><td>Password:</td><td><input type="password" name="password" maxlength="31"></td></tr>
<tr><td colspan="2"><input type="submit" value="Login"></td></tr></table></form></td></tr></table></center></body></html>
"""


def tomcat_401() -> str:
    return ("<!doctype html><html lang=\"en\"><head><title>HTTP Status 401 – Unauthorized</title></head><body>"
            "<h1>HTTP Status 401 – Unauthorized</h1><hr class=\"line\" /><p><b>Type</b> Status Report</p>"
            "<p><b>Message</b> This request requires HTTP authentication.</p><hr class=\"line\" />"
            "<h3>Apache Tomcat/9.0.31</h3></body></html>")


def fake_dotenv() -> str:
    # canary credentials: nothing here is real; they let us watch attackers try them on the fake DB services
    return ("APP_NAME=Laravel\nAPP_ENV=production\nAPP_KEY=base64:Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MGFiY2RlZmdoaWo=\nAPP_DEBUG=false\n"
            "DB_CONNECTION=mysql\nDB_HOST=127.0.0.1\nDB_PORT=3306\nDB_DATABASE=app_prod\nDB_USERNAME=app_admin\nDB_PASSWORD=Sup3rS3cret!2019\n"
            "REDIS_HOST=127.0.0.1\nREDIS_PASSWORD=null\nREDIS_PORT=6379\nMAIL_HOST=smtp.mailtrap.io\nMAIL_USERNAME=null\nMAIL_PASSWORD=null\n")


def fake_git_config() -> str:
    return ("[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n\tlogallrefupdates = true\n"
            "[remote \"origin\"]\n\turl = git@git.internal.example:web/app.git\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n"
            "[branch \"master\"]\n\tremote = origin\n\tmerge = refs/heads/master\n")


def robots() -> str:
    return "User-agent: *\nDisallow: /admin/\nDisallow: /backup/\nDisallow: /phpmyadmin/\nDisallow: /wp-admin/\n"


def http_date() -> str:
    return time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime())
