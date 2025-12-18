app_name = "icici"
app_title = "ICICI IMPS API"
app_publisher = "Your Company"
app_description = "ICICI Bank IMPS Name Inquiry API Integration"
app_email = "support@example.com"
app_license = "MIT"

# Includes in <head>
# ------------------

# include js, css files in header of desk.html
# app_include_css = "/assets/icici/css/icici.css"
# app_include_js = "/assets/icici/js/icici.js"

# include js, css files in header of web template
# web_include_css = "/assets/icici/css/icici.css"
# web_include_js = "/assets/icici/js/icici.js"

# include custom scss in every website theme (without file extension ".scss")
# website_theme_scss = "icici/public/scss/website"

# include js, css files in header of web form
# webform_include_js = {"doctype": "public/js/doctype.js"}
# webform_include_css = {"doctype": "public/css/doctype.css"}

# include js in page
# page_js = {"page" : "public/js/file.js"}

# include js in doctype views
# doctype_js = {"doctype" : "public/js/doctype.js"}
# doctype_list_js = {"doctype" : "public/js/doctype_list.js"}
# doctype_tree_js = {"doctype" : "public/js/doctype_tree.js"}
# doctype_calendar_js = {"doctype" : "public/js/doctype_calendar.js"}

# Home Pages
# ----------

# application home page (will override Website Settings)
# home_page = "login"

# website user home page (by Role)
# role_home_page = {
#	"Role": "home_page"
# }

# Generators
# ----------

# automatically create page for each record of this doctype
# website_generators = ["Web Page"]

# Jinja
# ----------

# add methods and filters to jinja environment
# jinja = {
#	"methods": "icici.utils.jinja_methods",
#	"filters": "icici.utils.jinja_filters"
# }

# Installation
# ------------

# before_install = "icici.install.before_install"
# after_install = "icici.install.after_install"

# Uninstallation
# ------------

# before_uninstall = "icici.uninstall.before_uninstall"
# after_uninstall = "icici.uninstall.after_uninstall"

# Integration
# ------------

# scheduler_events = {
#	"all": [
#		"icici.tasks.all"
#	],
#	"daily": [
#		"icici.tasks.daily"
#	],
#	"hourly": [
#		"icici.tasks.hourly"
#	],
#	"weekly": [
#		"icici.tasks.weekly"
#	],
#	"monthly": [
#		"icici.tasks.monthly"
#	],
# }

# Testing
# -------

# before_tests = "icici.install.before_tests"

# Overriding Methods
# ------------------------------
#
# override_whitelisted_methods = {
#	"frappe.desk.doctype.event.event.get_events": "icici.event.get_events"
# }
#
# each overriding function accepts a `data` argument;
# generated from the base implementation of the doctype dashboard,
# along with any modifications made in other Frappe apps
# override_doctype_class = {
#	"ToDo": "custom_app.overrides.CustomToDo"
# }

# DocType Class
# ---------------
# override_doctype_class = {
#	"ToDo": "custom_app.overrides.CustomToDo"
# }

# Document Events
# ---------------
# doc_events = {
#	"*": {
#		"on_update": "method",
#		"on_cancel": "method",
#		"on_trash": "method"
#	}
# }

# Scheduled Tasks
# ---------------

# scheduler_events = {
#	"all": [
#		"icici.tasks.all"
#	],
#	"daily": [
#		"icici.tasks.daily"
#	],
#	"hourly": [
#		"icici.tasks.hourly"
#	],
#	"weekly": [
#		"icici.tasks.weekly"
#	],
#	"monthly": [
#		"icici.tasks.monthly"
#	],
# }

# Fixtures
# --------
# fixtures = [
#	{"dt": "Custom Field", "filters": [["name", "in", ["Custom Field 1", "Custom Field 2"]]]},
#	{"dt": "Property Setter", "filters": [["name", "in", ["Property Setter 1", "Property Setter 2"]]]},
# ]

# Permissions
# -----------
# Permissions evaluated in scripted ways

# permission_query_conditions = {
#	"Event": "frappe.desk.doctype.event.event.get_permission_query_conditions",
# }
#
# has_permission = {
#	"Event": "frappe.desk.doctype.event.event.has_permission",
# }

# Has Website Role
# ---------------
# has_website_permission = {
#	"Event": "frappe.desk.doctype.event.event.has_website_permission"
# }

# Auto Email Reports
# -------------------
# auto_email_reports = [
#	{"dt": "Sales Invoice", "report": "Sales Invoice Report", "frequency": "Daily"}
# ]

# Notification
# ------------
# notification_config = "icici.notifications.get_notification_config"

# API
# ---
api = {
	"name_inquiry": "icici.api.icici_api.name_inquiry",
}

# Website
# -------
# website_route_rules = [
#	{"from_route": "/custom-route", "to_route": "custom_route"}
# ]

