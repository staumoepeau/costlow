# -*- coding: utf-8 -*-
# Copyright (c) 2021, Sione Taumoepeau and contributors
# For license information, please see license.txt

from __future__ import unicode_literals
import string
import frappe
from frappe import _
from frappe.utils import cstr, encode
from cryptography.fernet import Fernet, InvalidToken
from passlib.hash import pbkdf2_sha256, mysql41
from passlib.registry import register_crypt_handler
from passlib.context import CryptContext
from pymysql.constants.ER import DATA_TOO_LONG
from psycopg2.errorcodes import STRING_DATA_RIGHT_TRUNCATION


class LegacyPassword(pbkdf2_sha256):
	name = "frappe_legacy"
	ident = "$frappel$"

	def _calc_checksum(self, secret):
		# check if this is a mysql hash
		# it is possible that we will generate a false positive if the users password happens to be 40 hex chars proceeded
		# by an * char, but this seems highly unlikely
		if not (secret[0] == "*" and len(secret) == 41 and all(c in string.hexdigits for c in secret[1:])):
			secret = mysql41.hash(secret + self.salt.decode('utf-8'))
		return super(LegacyPassword, self)._calc_checksum(secret)


register_crypt_handler(LegacyPassword, force=True)
passlibctx = CryptContext(
	schemes=[
		"pbkdf2_sha256",
		"argon2",
		"frappe_legacy",
	],
	deprecated=[
		"frappe_legacy",
	],
)

@frappe.whitelist(allow_guest=True)
def check_password(user, pwd, doctype='User', fieldname='password'):
	'''Checks if user and password are correct, else raises frappe.AuthenticationError'''

	auth = frappe.db.sql("""select `name`, `password` from `__Auth`
		where `doctype`=%(doctype)s and `name`=%(name)s and `fieldname`=%(fieldname)s and `encrypted`=0""",
		{'doctype': doctype, 'name': user, 'fieldname': fieldname}, as_dict=True)

	if not auth or not passlibctx.verify(pwd, auth[0].password):
		frappe.msgprint("Incorrect User or Password", raise_exception=True)

	return user

# searches for leads which are not converted
@frappe.whitelist()
def get_all_supervisors(doctype, txt, searchfield, start, page_len, filters):
    return frappe.db.sql(""" SELECT tusr.name, thr.role
		FROM `tabHas Role` thr, `tabUser` tusr
		WHERE thr.parent = tusr.name
		AND thr.role = %s
		AND tusr.name <> "Administrator" """, ("System Manager",))