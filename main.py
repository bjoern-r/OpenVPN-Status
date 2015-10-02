import time, socket, re
from whois import *
from connexion import *
from mod_python import util
from mod_python import Session, Cookie
import json

username = "admin"
password = "admin"
host="127.0.0.1"
port=5555
vpnpasswd="openvpn-changeme"
version=4 # IPv4 or IPv6


main_page= """
 <html>
 <head><title>OpenVPN status</title>
 <meta http-equiv="Content-Type" content="text/html"; charset="iso-8859-1"/>
 <link rel="icon" href="../img/whois.png" type="image/png">
 <meta name="description" content="OpenVPN status">
 <meta http-equiv="refresh" content="300; URL=./main">
 <script type="text/javascript" src="../js/jquery.js"></script>
 <script type="text/javascript" src="../js/thickbox.js"></script>
 <link rel="stylesheet" href="../css/thickbox.css" type="text/css" media="screen" />
 <link href="../css/theme.css" rel="stylesheet" type="text/css">
 </head>
 <body>
 <div style="text-align:center;background:#ffffcc;">
 <br>
 <div align=\"left\"><img src=\"../img/openvpn_logo.png\"></div>
 <div align=\"center\"><h3>OpenVPN status</h3></div><div align=\"right\"> %s connected.</div>
 <div align=\"right\"><b><a href=\"./logout\">Logout</a></b></div><br>
 <table id=\"tasklist\"><thead><tr class=\"severity5\">
 <td class=\"severity\">Common Name</td>
 <td class=\"severity\">Real Address</td>
 <td class=\"severity\">Virtual Address</td>
 <td class=\"severity\">Bytes Sent</td>
 <td class=\"severity\">Bytes Received</td>
 <td class=\"severity\">Connected Since</td>
 <td class=\"severity\">Last Active</td>
 <td class=\"severity\">Some operation</td>
 </tr>
 """

def index(req): 

	req.content_type = 'text/html'
	s = """
<html>
<head><title>Login</title>
<meta http-equiv=\"Content-Type\" content=\"text/html\"; charset=utf-8\"iso-8859-1\"/>
<link rel=\"icon\" href=\"../img/whois.png\" type=\"image/png\">
<meta name=\"description\" content=\"OpenVPN status\">
<link href=\"../css/theme.css\" rel=\"stylesheet\" type=\"text/css\">

</head>
<body>
<center>
<form action=\"./login\" method=\"POST\">
<table class=\"login\" background=\"../img/header.jpg\">
<tr>
<td><label><font color=\"white\">Username</font>
<input type=\"text\" name=\"username\" value=\"admin\" size=\"20\" maxlength=\"20\"></label>
</td>
<td><label><font color=\"white\">Password </font>
<input type=\"password\" name=\"password\" value=\"admin\" size=\"20\" maxlength=\"20\"></label>
</td>
<td>
<br><br>
<label><font color=\"white\">Remember me? </font>
<input type=\"checkbox\" name=\"remember\"/> 
</td><td>
<br><br><br>
<input class=\"adminbutton\" type=\"submit\" value=\"Login!\">
</td>
</tr>
</form>
</table>
</center>
"""
	req.write(s)

footer="""
</body>
</html>
"""

popup="""
<html>
<head><title></title>
<style type=\"text/css\">
body ,th{
	margin              : 0px;
	padding             : 0px;
	background-color    : green;
	color               : #000;
	font-size           : 10px;
	font-family         : Arial, Helvetica, sans-serif;
}
</style>
</head>
<body>

"""

def headers(num):
	return main_page % num

def exception(req):
	req.write("</table></div>")
	req.write("</body></html>")
	exit

def parse(req):

	req.content_type="text/html"
	sock=connexion(host, port, vpnpasswd, 'status 2',version)
	data=sock.interact()
	tab1=re.findall("(.+),(\d+\.\d+\.\d+\.\d+\:\d+),(\d+),(\d+),(.+)", data)
#HEADER,CLIENT_LIST,Common Name,Real Address,Virtual Address,Bytes Received,Bytes Sent,Connected Since,Connected Since (time_t)
#CLIENT_LIST,client_i2cat_david,84.88.40.68:58004,10.252.55.50,708468,4313605,Tue Sep 29 16:35:33 2015,1443537333
	clients=re.findall("\nCLIENT_LIST,(.+),(.+),(.+),(.+),(.+),(.+),(.+)", data)
	tab2=re.findall("(\d+\.\d+\.\d+\.\d+),(.+),(\d+\.\d+\.\d+\.\d+\:\d+),(.+)", data)
#HEADER,ROUTING_TABLE,Virtual Address,Common Name,Real Address,Last Ref,Last Ref (time_t)
#ROUTING_TABLE,10.252.55.106,client_fokus_dc5,194.95.170.72:36573,Thu Oct  1 14:23:38 2015,1443702218
	routes=re.findall("\nROUTING_TABLE,(.+),(.+),(.+),(.+),(.+)", data)
#    routes=re.findall("(\d+\.\d+\.\d+\.\d+/\d+),(.+),(\d+\.\d+\.\d+\.\d+\:\d+),(.+)", data)

	num=(len(tab1)+len(tab2))/2
	num=len(clients)
	req.write(headers(num))

	routemap={}
	for i in xrange(len(clients)):
		routemap[clients[i][0]]=[]

	for i in xrange(len(routes)):
		cn=routes[i][1]
		#addr=routemap[cn]
		routemap[cn]+=[routes[i][0]]


				

	for i in xrange(len(clients)):
		sendv=float(clients[i][4])/1024
		receiv=float(clients[i][3])/1024
		cn=clients[i][0]
		addresses=clients[i][2]
		for addr in routemap[cn]:
			addresses+="<br/>\n"+addr
		req.write("<tr class=\"severity6\" ")
		req.write("onmouseover=\"this.className=\'severity6_over\'; ")
		req.write("this.style.cursor=\'hand\'\" ")
		req.write("onmouseout=\"this.className = \'severity6\'; ")
		req.write("this.style.cursor = \'default\'\">\n")
#Common Name  Real Address  Virtual Address Bytes Sent  Bytes Received  Connected Since Last Active Some operation
		req.write("<td class=\"severity\">%s</td>\n" % cn) # Common Name
		req.write("<td class=\"severity\">%s</td>\n" % clients[i][1]) # Real Address
		req.write("<td class=\"severity\">%s</td>\n" % addresses) # Virtual Address (routes)  -> clients[i][2]
		req.write("<td class=\"severity\">%.2f KB</td>\n" % sendv) # Bytes Sent
		req.write("<td class=\"severity\">%.2f KB</td>\n" % receiv) # Bytes Received
		req.write("<td class=\"severity\">%s</td>\n" % clients[i][6]) # Connected Since
		req.write("<td class=\"severity\">%s</td>\n" % clients[i][5]) # Last Active
		req.write("<td class=\"severity\">\n")
		req.write("<a href=\"./kill?cn=%s\">" % clients[i][0])
		req.write("<img src=../img/stop.png alt=\"kill\" title=\"kill\"></a>&nbsp;&nbsp\n")
		req.write("<a href=\"./whois?cn=%s\"  class=\"thickbox\">" % clients[i][1].split(':')[0])
		req.write("<img src=\"../img/whois.png\" alt=\"whois\" title=\"whois\">")
		req.write("</a>&nbsp;&nbsp\n</td>")
		req.write("</tr>\n") 
	req.write("</table></div>")

	req.write("<!-- Debug: \n")
	req.write("routemap:\n"+json.dumps(routemap,indent=4)+"\n")
	req.write("clients:\n"+json.dumps(clients,indent=4)+"\n")
	req.write("routes:\n"+json.dumps(routes,indent=4)+"\n")
	req.write("data:\n"+str(data)+"\n")
	req.write("\n-->\n")
	req.write("</body></html>")

def kill(req):
	req.content_type = 'text/html'
	if check(req):
		try:
			if req.form['cn'] is not None:
				 cmd="kill "+req.form['cn']
			sock=connexion(host, port, vpnpasswd, cmd)
			sock.interact()
			util.redirect(req,"./main")
		except Exception, e:
			raise(str(e)) 
	else:
	 util.redirect(req,'./login')

def check(req):
	req.content_type = 'text/html'
	session = Session.Session(req)
	if session.has_key('valid') and  session['valid'] == password:
		return True
	else:
		return False

def whois(req):
	req.content_type = 'text/html'
	if check(req):
		try:
			if req.form['cn'] is not None:
				ip=req.form['cn']
			obj=cwhois("whois.lacnic.net",ip,'4')
			data=obj.onWhois()
			data=data.replace('\n','<br>')
			req.write("%s" % popup)
			req.write("%s" % data)
			req.write("%s" % footer)
		except Exception, e:
			raise(str(e))
	else:
		 util.redirect(req,'./login')


def main(req):
	req.content_type = 'text/html'
	session = Session.Session(req)
	cookies = Cookie.get_cookies(req, Cookie.MarshalCookie,secret="cooks")
	if cookies.has_key('sessid'):
		cookie = cookies['sessid']
		if type(cookie) is Cookie.MarshalCookie:
			data = cookie.value
			session['valid'] = password
			session.save()
	else:
		if session.is_new():
			util.redirect(req,'./login')
		if session['valid'] != password:
			util.redirect(req,'./login')
	parse(req)

def login(req):
	req.content_type = "text/html"
	if req.method == 'POST':
		if req.form['username'] == username and req.form['password'] == password:
			session = Session.Session(req)
			session['valid'] = password
			session.save()
			if req.form.has_key('remember') and req.form['remember']:
				value = {'username': req.form['username'], 'passwword':req.form['password']}
				Cookie.add_cookie(req,Cookie.MarshalCookie('sessid', value,'cooks'),expires=time.time() + 3000000)
			util.redirect(req,'./main')
		else:
			index(req)
			req.write("<center><b><font color=\"white\">\
				login or password incorrect</b></font></center>")
			req.write(footer)
	else:
		index(req)
		req.write(footer)

def logout(req):
	req.content_type = "text/html"
	session = Session.Session(req)
	if session.has_key('valid'):
		session.delete()
	util.redirect(req,'./main')