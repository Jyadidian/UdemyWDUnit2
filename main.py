#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import webapp2
import cgi
import re

form="""
<h1>Enter some text into ROT13: MEOW</h1>
<form method="post">
	<textarea name="text" style="height:100px; width:400px;">%(translation)s</textarea>
	<br>
	<input type="submit">
</form>
"""

signUpForm="""
<head>
	<title>Sign Up</title>
	<style type="text/css">
	  .label {text-align: right}
	  .error {color: red}
	</style>
</head>

<body>
	<h2>Signup</h2>

	<form method="post">

	  <table>
	  <tbody>

		<tr>
		  <td class="label">Username</td>
		  <td><input type="text" name="username" value="%(username)s"></td>
		  <td class="error">%(usererror)s</td>
		</tr>

		<tr>
		  <td class="label">Password</td>
		  <td><input type="password" name="password" value=""></td>
		  <td class="error">%(passerror)s</td>
		</tr>

		<tr>
		  <td class="label">Verify Password</td>
		  <td><input type="password" name="verify" value=""></td>
		  <td class="error">%(verifyerror)s</td>
		</tr>

		<tr>
		  <td class="label">Email (optional)</td>
		  <td><input type="text" name="email" value="%(email)s"></td>
		  <td class="error">%(emailerror)s</td>
		</tr>

	  </tbody>
	  </table>

	  <input type="submit">
	</form>

</body>
"""

successForm = """
<html><head>
    <title>Unit 2 Signup</title>
  </head>

  <body>
    <h2>Welcome, %(username)s!</h2>
  
</body></html>
"""

def rot13(s):
	result = ""
	#s = escape_html(s)
	for char in s:

		value = ord(char)

		if 65<=value and value<=90:
			#uppercase case
			if value <= 77:
				result += chr(value+13)
			else:
				spillOver = (value+13) - 90
				result += chr(64+spillOver)
		elif 97<=value and value<=122:
			#lowercase case
			if value <=109:
				result += chr(value+13)
			else:
				spillOver = (value+13) - 122
				result += chr(96+spillOver)
		else:
			result+=char
	return result


def escape_html(s):
	# for (i, o) in (("&","&amp;"), #amp needs to be first because the rest include amps
	# 				(">","&gt;"),
	# 				("<", "&lt;"),
	# 				('"', '&quot;')):
	# 	s = s.replace((i,o))
	# return s
	return cgi.escape(s, quote = True)

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
	return USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
	return PASS_RE.match(password)

EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
def valid_email(email):
	if not email:
		return True
	return EMAIL_RE.match(email)

class MainHandler(webapp2.RequestHandler):
	def write_form(self, translation="Enter some text."):
		self.response.out.write(form %{'translation': translation})
	def get(self):
		self.write_form()
	def post(self):
		inputString = self.request.get('text')
		translation = escape_html(rot13(inputString))
		self.write_form(translation)

class SignUpHandler(webapp2.RequestHandler):
	def write_form(self, username="", usererror="", passerror="", verifyerror="", email="", emailerror=""):
		self.response.out.write(signUpForm %{'username':username, 'usererror':usererror, 'passerror':passerror, 'verifyerror':verifyerror, 'email': email, 'emailerror':emailerror})
	def get(self):
		self.write_form()
	def post(self):
		username = self.request.get('username')
		password = self.request.get('password')
		verify = self.request.get('verify')
		email = self.request.get('email')

		val_user = valid_username(username)
		val_pass = valid_password(password)
		val_email = valid_email(email)

		usererror=""
		passerror=""
		verifyerror=""
		emailerror=""

		if not val_user:
			usererror = "That's not a valid username."
		if not val_pass:
			passerror = "That wasn't a valid password."
		elif password != verify:
			verifyerror = "Your passwords didn't match."
		if not val_email:
			emailerror = "That's not a valid email."


		if (val_user and val_pass and val_email and not verifyerror):
			self.redirect("/signup/success?username="+username)
		else:
			self.write_form(username, usererror, passerror, verifyerror, email, emailerror)

class SuccessHandler(webapp2.RequestHandler):
	def get(self):
		username = self.request.get('username')
		self.response.out.write(successForm%{'username':username})




		


app = webapp2.WSGIApplication([('/', MainHandler),
								('/signup', SignUpHandler),
								('/signup/success', SuccessHandler)],
							  debug=True)
