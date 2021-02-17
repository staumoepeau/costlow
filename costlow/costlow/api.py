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


@frappe.whitelist(allow_guest=True)
def check_password(user, pwd, doctype='User', fieldname='password'):
	'''Checks if user and password are correct, else raises frappe.AuthenticationError'''

	auth = frappe.db.sql("""select `name`, `password` from `__Auth`
		where `doctype`=%(doctype)s and `name`=%(name)s and `fieldname`=%(fieldname)s and `encrypted`=0""",
		{'doctype': doctype, 'name': user, 'fieldname': fieldname}, as_dict=True)

	if not auth or not passlibctx.verify(pwd, auth[0].password):
		raise frappe.AuthenticationError(_('Incorrect User or Password'))

	# lettercase agnostic
	user = auth[0].name
	delete_login_failed_cache(user)

	return user
# searches for leads which are not converted
@frappe.whitelist()
@frappe.validate_and_sanitize_search_inputs
def lead_query(doctype, txt, searchfield, start, page_len, filters):
    return frappe.db.sql("""
        SELECT name, lead_name, company_name
        FROM `tabLead`
        WHERE docstatus &lt; 2
            AND ifnull(status, '') != 'Converted'
            AND ({key} LIKE %(txt)s
                OR lead_name LIKE %(txt)s
                OR company_name LIKE %(txt)s)
            {mcond}
        ORDER BY
            IF(LOCATE(%(_txt)s, name), LOCATE(%(_txt)s, name), 99999),
            IF(LOCATE(%(_txt)s, lead_name), LOCATE(%(_txt)s, lead_name), 99999),
            IF(LOCATE(%(_txt)s, company_name), LOCATE(%(_txt)s, company_name), 99999),
            name, lead_name
        LIMIT %(start)s, %(page_len)s
    """)