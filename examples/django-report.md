# sg-triage report

_Generated 2026-05-28 16:24 UTC_

## Summary

| Metric | Value |
|---|---|
| Total findings | 143 |
| Likely true positive | 0 |
| Needs human review | 115 |
| False positive | 28 |
| Estimated cost | ~$0.914 |
| Tokens (in / out) | 194356 / 22053 |
| Duration | 899.2s |
| Cache | 0 hits, 50 misses (0% hit rate) |
| Model | `claude-sonnet-4-5` |
| Prompt version | `0.1.0` |

## Findings

### 1. ⚠️ Needs human review — `python.sqlalchemy.security.sqlalchemy-execute-raw-query.sqlalchemy-execute-raw-query`

**File:** `django/contrib/gis/db/backends/oracle/schema.py:72`  

**Severity:** ERROR  **Confidence:** medium — CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

**Reasoning:** The finding flags string interpolation into a SQL query using the `%` operator. The data being interpolated is `model._meta.db_table` passed through `self.geo_quote_name()`. The `geo_quote_name` function delegates to `self.connection.ops.geo_quote_name(name)`, which appears to be a quoting/escaping function based on its name. However, I cannot see the implementation of this function to verify it properly sanitizes the table name. The `model._meta.db_table` comes from Django's ORM metadata, which is typically defined in model classes and not directly user-controlled. However, without seeing: (1) the definition of `sql_clear_geometry_table_metadata` to understand the full query structure, (2) the implementation of `geo_quote_name` to verify it provides adequate SQL injection protection, and (3) whether `model._meta.db_table` could ever be influenced by user input in this context, I cannot definitively determine if this is exploitable or safely mitigated.

**Missing context:**

- Definition of sql_clear_geometry_table_metadata to see the full SQL query structure

- Implementation of connection.ops.geo_quote_name() to verify it provides SQL injection protection

- Whether model._meta.db_table can be influenced by user input in any code path leading to delete_model

**Suggested action:** Verify that geo_quote_name() properly quotes/escapes Oracle identifiers and that model._meta.db_table cannot be influenced by user input.

### 2. ⚠️ Needs human review — `python.sqlalchemy.security.sqlalchemy-execute-raw-query.sqlalchemy-execute-raw-query`

**File:** `django/contrib/gis/db/backends/oracle/schema.py:85`  

**Severity:** ERROR  **Confidence:** medium — CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

**Reasoning:** The code uses string interpolation (%) to construct a SQL query from `self.sql_clear_geometry_field_metadata` with table and column names. The values are passed through `self.geo_quote_name()`, which calls `self.connection.ops.geo_quote_name(name)`. The critical question is whether `geo_quote_name` properly sanitizes/quotes identifiers to prevent SQL injection. The input originates from `model._meta.db_table` and `field.column`, which are Django ORM metadata fields. While these are typically controlled by the application's model definitions rather than direct user input, they could potentially be influenced by dynamic model creation or other indirect paths. The `geo_quote_name` function appears to be a quoting mechanism (suggested by its name), which would make this safe if it properly escapes SQL identifiers. However, I cannot see the implementation of `connection.ops.geo_quote_name()` to verify it actually performs proper SQL identifier quoting. Additionally, I cannot see the definition of `sql_clear_geometry_field_metadata` to understand what SQL template is being used.

**Missing context:**

- Implementation of connection.ops.geo_quote_name() to verify it properly quotes/escapes SQL identifiers

- Definition of self.sql_clear_geometry_field_metadata to see the SQL template being used

- Whether model._meta.db_table and field.column can be influenced by untrusted input in Django's architecture

**Suggested action:** Verify that connection.ops.geo_quote_name() properly quotes SQL identifiers (e.g., wraps in quotes and escapes special characters) and confirm that model metadata fields cannot be influenced by user input in the application's usage of Django ORM.

### 3. ⚠️ Needs human review — `python.sqlalchemy.security.sqlalchemy-execute-raw-query.sqlalchemy-execute-raw-query`

**File:** `django/contrib/gis/db/backends/postgis/operations.py:341`  

**Severity:** ERROR  **Confidence:** medium — CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

**Reasoning:** The finding flags string formatting into a SQL query at line 341: `cursor.execute("SELECT %s()" % func)`. The dangerous operation is executing a SQL query with string interpolation. The `func` parameter is passed to `_get_postgis_func()`, but I cannot see any callers of this function in the provided context, so I cannot determine where `func` originates or whether it contains attacker-controlled data. The function name and context (PostGIS operations in Django's GIS backend) suggest `func` is likely a PostGIS function name, which would typically be hardcoded or from a controlled set. However, without seeing the callers or how `func` is validated before reaching this point, I cannot definitively rule out that user input could flow into this parameter. The code is in Django's own codebase (not test code or third-party), so this is production code that warrants careful review.

**Missing context:**

- Callers of _get_postgis_func() to determine the source and validation of the 'func' parameter

- Whether 'func' is ever derived from user input or is always a hardcoded PostGIS function name

**Advisory note**

_The grounding check flagged tokens in the reasoning that don't appear in the visible code. This often means the LLM is reasoning by contrast (e.g. "unlike pickle.loads which would be vulnerable") or referencing framework knowledge from training. It can also indicate fabrication. Read the reasoning carefully._

- ℹ️ Reasoning references `codebase` but this token does not appear in the code or context shown to the LLM.

**Suggested action:** Review all callers of _get_postgis_func() to verify that the 'func' parameter is never derived from user input and is always a controlled PostGIS function name.

### 4. ⚠️ Needs human review — `python.sqlalchemy.security.sqlalchemy-execute-raw-query.sqlalchemy-execute-raw-query`

**File:** `django/contrib/gis/db/backends/spatialite/operations.py:161`  

**Severity:** ERROR  **Confidence:** medium — CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

**Reasoning:** The finding flags string formatting into a SQL query at line 161: `cursor.execute("SELECT %s" % func)`. The `func` parameter comes from the caller of `_get_spatialite_func()`. Without seeing the callers, I cannot determine whether `func` contains attacker-controlled data or is constructed from hardcoded/safe values. The docstring states "Any error occurring in this method should be handled by the caller," suggesting this is a low-level utility function. The file path indicates this is Django framework code (django/contrib/gis/db/backends/spatialite/operations.py), which typically handles database operations carefully, but the string formatting pattern is inherently unsafe if `func` can be influenced by user input. The method name `_get_spatialite_func` (with leading underscore) suggests it's internal/private, but that doesn't eliminate the possibility of tainted data flow from public APIs.

**Missing context:**

- Callers of _get_spatialite_func to determine the origin and construction of the 'func' parameter

- Whether func is ever derived from user input or is always hardcoded/configuration-based

- The broader context of how this SpatiaLite operations class is used within Django's GIS backend

**Suggested action:** Review all callers of _get_spatialite_func to verify that the func parameter is never constructed from user-controlled input; if it is always hardcoded or from trusted configuration, this is a false positive, otherwise it requires parameterization.

### 5. ⚠️ Needs human review — `python.sqlalchemy.security.sqlalchemy-execute-raw-query.sqlalchemy-execute-raw-query`

**File:** `django/contrib/gis/db/backends/spatialite/schema.py:76`  

**Severity:** ERROR  **Confidence:** medium — CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

**Reasoning:** The finding flags SQL string formatting at lines 76-82 where `self.sql_drop_spatial_index` is formatted with `model._meta.db_table` and `field.column`. The concern is SQL injection via untrusted input. However, critical context is missing: (1) the definition of `self.execute()` is not resolved, so I cannot verify if it uses parameterized queries or raw execution; (2) `self.quote_name()` is not resolved, though it's used on line 72-73 for similar data but NOT on lines 79-80 where the flagged code uses unquoted values. The inconsistency is notable: the first execute call quotes both table and column names, but the second (flagged) call does not. This could indicate either (a) a real vulnerability where quoting was forgotten, or (b) `sql_drop_spatial_index` expects unquoted identifiers for a different reason. The data sources `model._meta.db_table` and `field.column` are Django ORM metadata, typically not directly user-controlled, but could be influenced by model definitions. Without seeing the execute implementation and understanding why quoting differs between the two calls, I cannot definitively rule out exploitation.

**Missing context:**

- Definition of self.execute() to determine if it performs parameterization or raw SQL execution

- Definition of self.sql_drop_spatial_index to see the SQL template structure

- Definition of quote_name() to understand the quoting mechanism

- Why the first execute call (lines 69-75) uses quote_name() but the second (lines 76-82) does not

- Whether model._meta.db_table and field.column can be influenced by untrusted input in Django's architecture

**Advisory note**

_The grounding check flagged tokens in the reasoning that don't appear in the visible code. This often means the LLM is reasoning by contrast (e.g. "unlike pickle.loads which would be vulnerable") or referencing framework knowledge from training. It can also indicate fabrication. Read the reasoning carefully._

- ℹ️ Reasoning references `second` but this token does not appear in the code or context shown to the LLM.

- ℹ️ Reasoning references `either` but this token does not appear in the code or context shown to the LLM.

**Suggested action:** Review why quote_name() is not used on lines 79-80 when it is used on lines 72-73, and verify that model._meta.db_table and field.column are properly sanitized or that sql_drop_spatial_index handles identifiers safely.

### 6. ⚠️ Needs human review — `go.lang.security.audit.xss.no-interpolation-in-tag.no-interpolation-in-tag`

**File:** `django/forms/jinja2/django/forms/label.html:1`  

**Severity:** WARNING  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; django/forms/jinja2/django/forms/label.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 7. ⚠️ Needs human review — `go.lang.security.audit.xss.no-interpolation-in-tag.no-interpolation-in-tag`

**File:** `django/forms/templates/django/forms/label.html:1`  

**Severity:** WARNING  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; django/forms/templates/django/forms/label.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 8. ⚠️ Needs human review — `html.security.audit.missing-integrity.missing-integrity`

**File:** `js_tests/tests.html:159`  

**Severity:** WARNING  **Confidence:** low — CWE-353: Missing Support for Integrity Check

**Reasoning:** v0.1 supports Python files only; js_tests/tests.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 9. ⚠️ Needs human review — `javascript.lang.security.audit.detect-non-literal-regexp.detect-non-literal-regexp`

**File:** `django/contrib/admin/static/admin/js/inlines.js:26`  

**Severity:** WARNING  **Confidence:** low — CWE-1333: Inefficient Regular Expression Complexity

**Reasoning:** v0.1 supports Python files only; django/contrib/admin/static/admin/js/inlines.js requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 10. ⚠️ Needs human review — `python.django.security.audit.avoid-mark-safe.avoid-mark-safe`

**File:** `django/contrib/admindocs/utils.py:268`  

**Severity:** WARNING  **Confidence:** medium — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** The function `strip_p_tags` calls `mark_safe()` on the result of string replacement operations that remove `<p>` and `</p>` tags. The critical question is whether `value` is already safe/escaped content or whether it contains untrusted user input. The function name and operation suggest it's designed to strip paragraph tags from HTML that has already been processed, which is a common pattern in Django admin documentation utilities. However, without seeing the callers of `strip_p_tags` or understanding what data flows into the `value` parameter, I cannot determine if this is attacker-controlled input or pre-sanitized content. If `value` comes from user input, the simple `.replace()` operations do not provide XSS protection - an attacker could inject `<script>` or other malicious tags. If `value` is already escaped or comes from trusted sources (like Django's own documentation rendering), this would be safe.

**Missing context:**

- Callers of strip_p_tags function to determine the source of the 'value' parameter

- Whether 'value' parameter contains user-controlled input or pre-sanitized/trusted content

- The broader context of how admindocs utilities process and render documentation

**Suggested action:** Review all call sites of `strip_p_tags` to verify that the `value` parameter only receives pre-escaped or trusted content, never raw user input.

### 11. ⚠️ Needs human review — `python.django.security.audit.avoid-mark-safe.avoid-mark-safe`

**File:** `django/contrib/flatpages/views.py:67`  

**Severity:** WARNING  **Confidence:** medium — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** The code marks `f.title` as safe using `mark_safe()`, where `f` is a FlatPage model instance passed as a parameter. The comment on lines 64-66 explicitly states this is done to avoid requiring the "|safe" filter in templates because "they are raw HTML content in the first place." The key question is whether `f.title` contains attacker-controlled data or is only editable by trusted administrators. In Django's flatpages app, FlatPage objects are typically created and edited through the Django admin interface, which requires staff/superuser permissions. However, I cannot verify from the code shown: (1) whether there are other code paths that allow untrusted users to create or modify FlatPage titles, (2) what the actual access controls are on FlatPage model modifications, or (3) whether the flatpages app configuration allows user-generated content. If FlatPage titles can only be set by trusted administrators through the admin interface, this would be a false positive. If untrusted users can influence the title field through any code path, this is a stored XSS vulnerability.

**Missing context:**

- Definition and access controls for the FlatPage model

- All code paths that can create or modify FlatPage.title

- Whether flatpages are only editable by staff/superuser through Django admin or if there are user-facing forms

- Application configuration for the flatpages app

**Suggested action:** Verify that FlatPage titles can only be modified by trusted administrators through the Django admin interface and that no code paths allow untrusted user input into the title field.

### 12. ⚠️ Needs human review — `python.django.security.audit.avoid-mark-safe.avoid-mark-safe`

**File:** `django/contrib/flatpages/views.py:68`  

**Severity:** WARNING  **Confidence:** medium — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** The code marks `f.content` as safe for HTML output using `mark_safe()`, where `f` is a FlatPage object passed into the function. The comment on lines 64-66 explicitly states this is done to avoid requiring the "|safe" filter in templates because "they are raw HTML content in the first place." The critical question is: where does `f.content` originate and who controls it? The FlatPage model is imported from `django.contrib.flatpages.models`, suggesting this is Django's built-in flatpages app where content is typically stored in the database and managed through the admin interface. If `f.content` is administrator-controlled content from the database (intended to contain HTML), this would be a false positive since admins are trusted to insert HTML. However, if there's any path where untrusted users can influence `f.content`, or if the content comes from an external source without sanitization, this would be a true positive XSS vulnerability. Without seeing the FlatPage model definition, how `f` is populated before being passed to this function, and what access controls govern who can modify flatpage content, I cannot determine whether this is attacker-controllable data.

**Missing context:**

- Definition of the FlatPage model and its content field

- How the FlatPage object 'f' is populated before being passed to render_flatpage

- Access controls on who can create or modify FlatPage content

- Whether FlatPage content is admin-only or can be influenced by untrusted users

**Suggested action:** Verify that FlatPage content can only be modified by trusted administrators through Django admin, not by regular users or external sources. If untrusted users can influence flatpage content, this is a real XSS vulnerability.

### 13. ⚠️ Needs human review — `python.django.security.audit.custom-expression-as-sql.custom-expression-as-sql`

**File:** `django/contrib/gis/db/backends/oracle/operations.py:55`  

**Severity:** WARNING  **Confidence:** low — CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

> ⚠️ LLM originally returned `false_positive` — downgraded due to verification failure.

**Reasoning:** This finding is in Django's own GIS backend implementation for Oracle, not application code. The matched line calls `super().as_sql()` within an `as_sql` method override in what appears to be a spatial operations class. This is part of Django's internal ORM query compilation machinery. The parameters being passed (`connection`, `lookup`, `template_params`, `sql_params[:-1]`) are already part of Django's parameterized query system - `sql_params` contains bind parameters that will be safely passed to the database driver, and `template_params` are used for template substitution in the query compiler, not direct string concatenation. The code is manipulating the mask parameter by moving it from `sql_params` to `template_params` before delegating to the parent class. This is framework code that handles parameterization, not application code that could introduce SQL injection.

**Evidence from the code:**

```
return super().as_sql(connection, lookup, template_params, sql_params[:-1])
```

```
from django.contrib.gis.db.backends.oracle.operations import DatabaseOperations
```

```
template_params["mask"] = sql_params[-1]
```

**Verifier notes:**

- ⚠️ Evidence quote #2 does not appear verbatim in the code shown to the LLM. Quote: 'from django.contrib.gis.db.backends.oracle.operations import DatabaseOperations'

**Suggested action:** No action needed - this is Django framework code that implements the ORM's parameterized query system, not application code with SQL injection risk.

### 14. ⚠️ Needs human review — `python.django.security.audit.unvalidated-password.unvalidated-password`

**File:** `django/contrib/auth/base_user.py:104`  

**Severity:** WARNING  **Confidence:** medium — CWE-521: Weak Password Requirements

**Reasoning:** The finding flags a call to `self.set_password(raw_password)` without prior validation. The `setter` function receives `raw_password` and directly calls `set_password`, which hashes the password via `make_password(raw_password)`. The `save` method then calls `password_validation.password_changed()` after the password is already set and saved. The critical question is where this `setter` function is called from and whether validation happens upstream. The function name "setter" suggests it may be a property setter or callback used in password upgrade scenarios (the comment mentions "Password hash upgrades shouldn't be considered password changes"). If this is part of Django's internal password upgrade mechanism during authentication (where an old hash format is upgraded to a new one), validation may have already occurred when the user originally set the password. However, if this setter is exposed to user-facing password change flows without upstream validation, it would be a genuine weakness. The context shows this is in Django's own `base_user.py`, which is framework code, but without seeing the callers or how this setter is registered/used, I cannot determine if validation is appropriately enforced at the entry points.

**Missing context:**

- Callers of the setter function to determine if this is only used for password hash upgrades or also for user-facing password changes

- How this setter function is registered or exposed (e.g., as a property setter, callback, or direct API)

- Whether upstream validation occurs before raw_password reaches this setter

**Advisory note**

_The grounding check flagged tokens in the reasoning that don't appear in the visible code. This often means the LLM is reasoning by contrast (e.g. "unlike pickle.loads which would be vulnerable") or referencing framework knowledge from training. It can also indicate fabrication. Read the reasoning carefully._

- ℹ️ Reasoning references `scenarios` but this token does not appear in the code or context shown to the LLM.

**Suggested action:** Review all code paths that invoke this setter function to verify that password validation is performed before the setter is called, especially for user-facing password change operations.

### 15. ⚠️ Needs human review — `python.django.security.audit.unvalidated-password.unvalidated-password`

**File:** `django/contrib/auth/forms.py:132`  

**Severity:** WARNING  **Confidence:** medium — CWE-521: Weak Password Requirements

**Reasoning:** The finding flags `user.set_password(self.cleaned_data[password_field_name])` in the `set_password_and_save` helper function without visible password validation. The function is called from a `save()` method that appears to be part of a Django form (inherits from a parent with `save()`). Django forms typically validate data during `clean()` or field-level validation before data reaches `cleaned_data`. The file imports `password_validation` from `django.contrib.auth`, suggesting validation infrastructure is available. However, I cannot see: (1) the form class definition containing this method, (2) whether `clean()` or field validators call `password_validation.validate_password()`, or (3) the full context of when `set_password_and_save` is invoked. This is Django's own auth forms module, which is framework code that should implement proper validation, but without seeing the form's validation methods, I cannot confirm whether validation occurs before the password reaches `cleaned_data`.

**Missing context:**

- The form class definition containing set_password_and_save method

- The clean() method or field validators for the password field

- Whether password_validation.validate_password() is called elsewhere in the form lifecycle before data reaches cleaned_data

**Suggested action:** Review the complete form class to verify that password_validation.validate_password() is called in clean() or field validation before the password is set.

### 16. ⚠️ Needs human review — `python.django.security.audit.xss.template-autoescape-off.template-autoescape-off`

**File:** `django/contrib/admin/templates/registration/password_reset_email.html:1`  

**Severity:** WARNING  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; django/contrib/admin/templates/registration/password_reset_email.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 17. ⚠️ Needs human review — `python.django.security.django-no-csrf-token.django-no-csrf-token`

**File:** `django/contrib/admin/templates/admin/login.html:47`  

**Severity:** WARNING  **Confidence:** low — CWE-352: Cross-Site Request Forgery (CSRF)

**Reasoning:** v0.1 supports Python files only; django/contrib/admin/templates/admin/login.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 18. ⚠️ Needs human review — `python.django.security.django-no-csrf-token.django-no-csrf-token`

**File:** `django/contrib/admin/templates/registration/password_reset_form.html:17`  

**Severity:** WARNING  **Confidence:** low — CWE-352: Cross-Site Request Forgery (CSRF)

**Reasoning:** v0.1 supports Python files only; django/contrib/admin/templates/registration/password_reset_form.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 19. ⚠️ Needs human review — `python.django.security.injection.tainted-url-host.tainted-url-host`

**File:** `django/contrib/contenttypes/views.py:86`  

**Severity:** WARNING  **Confidence:** medium — CWE-918: Server-Side Request Forgery (SSRF)

**Reasoning:** The finding flags line 86 where `object_domain` is used to construct a URL. Tracing the dataflow: `object_domain` is initially set from `get_current_site(request).domain` (line 47), which derives from the request object. The code then attempts to override `object_domain` by looking up Site objects from the database through many-to-many or foreign key relationships on the content object (lines 55-80). The concern is whether `object_domain` can be attacker-controlled. The `get_current_site` function returns a Site object from the database or a RequestSite based on the request, and `.domain` would be the domain field. If the Site.domain comes from the database, it's likely trusted. However, RequestSite might derive domain from request headers (like Host header), which would be attacker-controlled. The code also overwrites `object_domain` with `site.domain` from database lookups in lines 67 and 79, which would be trusted data. The key uncertainty is: (1) what RequestSite.domain returns and whether it's sanitized, (2) whether the database-derived domains in the override logic always execute before line 86, and (3) whether there are code paths where the initial `get_current_site(request).domain` value (potentially from request headers) reaches line 86 without being overwritten by database values.

**Missing context:**

- Definition and behavior of RequestSite class, specifically whether RequestSite.domain is derived from request headers without validation

- Whether get_current_site always returns a database-backed Site object or can return RequestSite with untrusted domain

- Whether the Site model lookups in lines 55-80 always execute and override object_domain before line 86 is reached

**Suggested action:** Verify whether RequestSite.domain can be influenced by the Host header or other request data, and confirm that object_domain is always overwritten with database-validated Site.domain values before the redirect is constructed.

### 20. ⚠️ Needs human review — `python.lang.security.audit.formatted-sql-query.formatted-sql-query`

**File:** `django/contrib/gis/db/backends/postgis/operations.py:341`  

**Severity:** WARNING  **Confidence:** medium — CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

**Reasoning:** The finding flags string formatting into a SQL query at line 341: `cursor.execute("SELECT %s()" % func)`. The dangerous sink is the `cursor.execute()` call with a formatted string. The `func` parameter is passed into `_get_postgis_func()` but its origin is not visible in the provided context. If `func` comes from user input or any attacker-controlled source, this would be a SQL injection vulnerability since the value is interpolated directly into the query string rather than using parameterized queries. However, I cannot see the callers of `_get_postgis_func()` to determine whether `func` is hardcoded (e.g., a constant like "PostGIS_Version"), derived from configuration, or potentially influenced by user input. The function appears to be part of Django's PostGIS backend operations, which suggests it may be internal infrastructure code that only receives hardcoded function names, but without seeing the call sites, I cannot confirm this assumption.

**Missing context:**

- Callers of _get_postgis_func() to determine the source of the 'func' parameter

- Whether 'func' is ever derived from user input or is always a hardcoded constant

**Suggested action:** Review all call sites of _get_postgis_func() to verify that the 'func' parameter is always a hardcoded constant or otherwise not attacker-controlled.

### 21. ⚠️ Needs human review — `python.lang.security.audit.formatted-sql-query.formatted-sql-query`

**File:** `django/contrib/gis/db/backends/spatialite/operations.py:161`  

**Severity:** WARNING  **Confidence:** medium — CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

**Reasoning:** The finding flags string formatting into a SQL query at line 161: `cursor.execute("SELECT %s" % func)`. The dangerous operation is executing a SQL query with string interpolation. The `func` parameter comes from the caller of `_get_spatialite_func()`, but we cannot see any callers in the provided context. The docstring states "Any error occurring in this method should be handled by the caller," suggesting this is a utility function called from elsewhere. Without seeing the callers, we cannot determine whether `func` contains attacker-controlled data or is constructed from hardcoded/safe values. The file path indicates this is Django framework code (spatialite database backend operations), which typically constructs SQL function calls programmatically rather than from user input, but we need to verify the actual call sites to confirm `func` is not influenced by untrusted input.

**Missing context:**

- Callers of _get_spatialite_func() to determine the origin and construction of the 'func' parameter

- Whether 'func' is ever derived from user input or is always constructed from hardcoded database function names

**Suggested action:** Review all call sites of _get_spatialite_func() to verify that the 'func' parameter is never influenced by user input and is only constructed from trusted, hardcoded database function names.

### 22. ⚠️ Needs human review — `python.lang.security.audit.non-literal-import.non-literal-import`

**File:** `django/apps/config.py:111`  

**Severity:** WARNING  **Confidence:** medium — CWE-706: Use of Incorrectly-Resolved Name or Reference

**Reasoning:** The `import_module(entry)` call at line 111 is part of Django's app configuration system. The `entry` parameter comes from the `create` classmethod, which according to the docstring "creates an app config from an entry in INSTALLED_APPS." The INSTALLED_APPS setting in Django is typically defined in settings.py by developers, not end users. However, I cannot see from the code provided: (1) where `create()` is called from and whether `entry` could ever be influenced by user input, (2) whether INSTALLED_APPS is strictly developer-controlled or could be modified at runtime based on user input in some deployment scenarios. The code does perform validation after the import (checking for AppConfig subclass at line 197), but this is post-import and wouldn't prevent arbitrary code execution during the import itself. The file path suggests this is core Django framework code, which would typically only process developer-configured values, but without seeing the call chain to `create()`, I cannot definitively rule out user influence on the `entry` parameter.

**Missing context:**

- Callers of the create() method to determine if entry parameter can be influenced by user input

- Whether INSTALLED_APPS configuration can be modified at runtime based on user input

- The complete call chain from request handling to this create() method

**Suggested action:** Verify that the `entry` parameter to `create()` only comes from the INSTALLED_APPS setting which is developer-controlled configuration, and cannot be influenced by end-user input at runtime.

### 23. ⚠️ Needs human review — `python.lang.security.audit.non-literal-import.non-literal-import`

**File:** `django/apps/config.py:123`  

**Severity:** WARNING  **Confidence:** medium — CWE-706: Use of Incorrectly-Resolved Name or Reference

**Reasoning:** The flagged line 123 calls `import_module(mod_path)` where `mod_path` is constructed as `"%s.%s" % (entry, APPS_MODULE_NAME)` on line 122. The `entry` parameter comes from the `create(cls, entry)` function signature and is described in comments as coming from INSTALLED_APPS. In Django, INSTALLED_APPS is a configuration setting typically defined in settings.py by the application developer, not by end users. However, I cannot verify from the code shown whether `entry` could ever be influenced by untrusted user input at runtime. The function appears to be a factory method for creating app configurations during Django's initialization phase, which typically happens at startup from trusted configuration files. But if there's any code path where INSTALLED_APPS or the values passed to `create()` could be influenced by user input (e.g., through dynamic configuration loading, environment variables controlled by users, or API endpoints that modify settings), this would be a genuine arbitrary code execution vulnerability. The context suggests this is framework initialization code rather than request-handling code, but I cannot definitively rule out user influence on the `entry` parameter without seeing the callers of this function.

**Missing context:**

- callers of the create() function to determine if entry can be influenced by user input

- definition of INSTALLED_APPS and how it is populated

- whether this code runs only at Django startup from trusted configuration or can be invoked with user-controlled data

**Suggested action:** Verify that the `entry` parameter to `create()` can only come from trusted configuration (settings.py INSTALLED_APPS) and is never influenced by runtime user input or environment variables controlled by untrusted users.

### 24. ⚠️ Needs human review — `python.lang.security.audit.non-literal-import.non-literal-import`

**File:** `django/apps/config.py:178`  

**Severity:** WARNING  **Confidence:** medium — CWE-706: Use of Incorrectly-Resolved Name or Reference

**Reasoning:** The finding flags line 178 where `import_module(mod_path)` is called. Tracing the dataflow: `mod_path` is derived from `entry.rpartition(".")` at line 171, where `entry` is the parameter to the `create()` factory method. The function comment states this creates an app config "from an entry in INSTALLED_APPS." In Django, INSTALLED_APPS is a configuration setting typically defined in settings.py by the application developer, not by end users. However, I cannot verify from the code shown whether `entry` could ever be influenced by untrusted user input in any deployment scenario. The code is clearly designed to import modules based on configuration (lines 111, 123, 178, 193, 210 all use import_module with values derived from `entry`), and there are validation checks (lines 197-198, 209-219) that ensure the imported module meets expected criteria. The specific line 178 is in an error-handling path that attempts to provide a better error message when a module import fails. While this appears to be framework code processing developer-controlled configuration rather than user input, I cannot definitively rule out scenarios where INSTALLED_APPS entries might be influenced by untrusted sources (e.g., loaded from a database, environment variables, or user-uploaded configuration files).

**Missing context:**

- How the `create()` method is called and where the `entry` parameter originates

- Whether INSTALLED_APPS configuration can ever be influenced by untrusted user input in any deployment scenario

- Whether there are access controls preventing untrusted users from modifying Django settings

**Suggested action:** Verify that the `entry` parameter (from INSTALLED_APPS) cannot be influenced by untrusted user input in any deployment scenario. If INSTALLED_APPS is strictly developer-controlled configuration, this is a false positive.

### 25. ⚠️ Needs human review — `python.lang.security.audit.non-literal-import.non-literal-import`

**File:** `django/apps/config.py:193`  

**Severity:** WARNING  **Confidence:** medium — CWE-706: Use of Incorrectly-Resolved Name or Reference

**Reasoning:** The finding flags `import_module(entry)` at line 193 in Django's app configuration factory method. The `entry` parameter comes from the `create` classmethod and is intended to load Django apps from the `INSTALLED_APPS` setting. While `INSTALLED_APPS` is typically controlled by developers in settings.py (not end-user input), the code itself does not validate or whitelist the `entry` value before importing. The function attempts multiple import strategies and re-raises the import at line 193 to provide better error messages. The security concern depends on whether `INSTALLED_APPS` can be influenced by untrusted sources at runtime. In typical Django deployments, `INSTALLED_APPS` is static configuration controlled by developers, making this a false positive. However, if there are deployment scenarios where settings can be dynamically modified (environment variables, database-driven config, admin interfaces), this could allow arbitrary code execution. Without visibility into how `create()` is called and whether `entry` values are ever derived from user input or untrusted sources, I cannot definitively rule out exploitation.

**Missing context:**

- Callers of the create() method to determine the source of the 'entry' parameter

- Whether INSTALLED_APPS or the values passed to create() can be influenced by user input or external configuration sources

- Django's settings loading mechanism to verify INSTALLED_APPS is strictly developer-controlled

**Advisory note**

_The grounding check flagged tokens in the reasoning that don't appear in the visible code. This often means the LLM is reasoning by contrast (e.g. "unlike pickle.loads which would be vulnerable") or referencing framework knowledge from training. It can also indicate fabrication. Read the reasoning carefully._

- ℹ️ Reasoning references `modified` but this token does not appear in the code or context shown to the LLM.

**Suggested action:** Verify that the 'entry' parameter to create() always originates from developer-controlled INSTALLED_APPS configuration and cannot be influenced by user input or external untrusted sources at runtime.

### 26. ⚠️ Needs human review — `python.lang.security.audit.non-literal-import.non-literal-import`

**File:** `django/conf/__init__.py:177`  

**Severity:** WARNING  **Confidence:** medium — CWE-706: Use of Incorrectly-Resolved Name or Reference

**Reasoning:** The finding flags `importlib.import_module(self.SETTINGS_MODULE)` at line 177. The `settings_module` parameter is passed to the `__init__` constructor at line 167 and stored as `self.SETTINGS_MODULE` at line 175. The code then dynamically imports this module. The critical question is whether `settings_module` originates from untrusted user input or is controlled by the application developer. In Django, the settings module is typically specified via the `DJANGO_SETTINGS_MODULE` environment variable or programmatically during application startup, which is generally under developer control, not end-user control. However, I cannot see the callers of this `__init__` method from the provided context. If this is called with developer-controlled configuration (e.g., from manage.py or wsgi.py), it would be a false positive. If there's any path where an end user can influence the settings_module parameter (e.g., via HTTP request parameters), it would be a critical vulnerability allowing arbitrary code execution.

**Missing context:**

- Callers of this __init__ method to determine the source of the settings_module parameter

- Whether settings_module can be influenced by end-user input or is strictly developer-controlled configuration

- The class definition this __init__ belongs to and how it's instantiated

**Advisory note**

_The grounding check flagged tokens in the reasoning that don't appear in the visible code. This often means the LLM is reasoning by contrast (e.g. "unlike pickle.loads which would be vulnerable") or referencing framework knowledge from training. It can also indicate fabrication. Read the reasoning carefully._

- ℹ️ Reasoning references `DJANGO_SETTINGS_MODULE` but this token does not appear in the code or context shown to the LLM.

**Suggested action:** Review all callers of this constructor to verify that settings_module is only set from developer-controlled sources (environment variables, command-line arguments at startup) and never from end-user input like HTTP requests.

### 27. ⚠️ Needs human review — `python.lang.security.audit.non-literal-import.non-literal-import`

**File:** `django/contrib/admindocs/views.py:180`  

**Severity:** WARNING  **Confidence:** medium — CWE-706: Use of Incorrectly-Resolved Name or Reference

**Reasoning:** The finding flags `import_module(mod)` at line 180 where `mod` is derived from `get_mod_func(view)` at line 176. The `view` parameter comes from the function argument to `_get_view_func(view)`. The critical question is whether `view` originates from user input or from trusted Django URL configuration. The code checks `get_resolver(urlconf)._is_callback(view)` before proceeding, suggesting this is validating that `view` is a registered callback in Django's URL configuration. If `view` is constrained to registered URL patterns (which are defined in code by developers), this would be a false positive. However, I cannot see the definition of `get_mod_func()`, the caller of `_get_view_func()`, or how `view` is sourced. The file is in `django/contrib/admindocs/views.py`, which is Django framework code for admin documentation views, typically restricted to staff members. Without seeing whether `view` comes from URL configuration (trusted) versus a query parameter (untrusted), I cannot definitively determine exploitability.

**Missing context:**

- Caller of _get_view_func() to determine the source of the 'view' parameter

- Definition of get_mod_func() to understand how it parses the view string

- Definition of _is_callback() to understand what validation it performs

- Whether the view parameter originates from Django URL configuration or from user-controllable input

**Advisory note**

_The grounding check flagged tokens in the reasoning that don't appear in the visible code. This often means the LLM is reasoning by contrast (e.g. "unlike pickle.loads which would be vulnerable") or referencing framework knowledge from training. It can also indicate fabrication. Read the reasoning carefully._

- ℹ️ Reasoning references `patterns` but this token does not appear in the code or context shown to the LLM.

**Suggested action:** Review how _get_view_func() is called to determine if the 'view' parameter comes from trusted Django URL configuration or from user-controllable input like query parameters. If it's from URL patterns defined in code, this is likely a false positive; if from user input, verify there's adequate validation.

### 28. ⚠️ Needs human review — `python.lang.security.audit.non-literal-import.non-literal-import`

**File:** `django/contrib/admindocs/views.py:187`  

**Severity:** WARNING  **Confidence:** medium — CWE-706: Use of Incorrectly-Resolved Name or Reference

**Reasoning:** The finding flags `import_module(mod)` at line 187 where `mod` is derived from `get_mod_func(view)` and then `get_mod_func(mod)` again. The `view` parameter originates from the function parameter to `_get_view_func(view)`, but the caller context is not shown. The code appears to be part of Django's admin documentation views (file path `django/contrib/admindocs/views.py`), which typically processes URL patterns and view references. The function uses `get_resolver(urlconf)._is_callback(view)` as a guard, suggesting `view` should be a valid callback reference. However, without seeing: (1) where `_get_view_func` is called and what data flows into the `view` parameter, (2) what `get_mod_func()` does (whether it validates or sanitizes the input), and (3) whether there are access controls on the calling code path, I cannot determine if `mod` can be attacker-controlled. The file path suggests this is Django framework code for admin documentation, which is typically behind authentication, but authentication alone does not prevent code injection if an authenticated attacker can control the view parameter.

**Missing context:**

- Callers of _get_view_func and the source of the view parameter

- Definition and behavior of get_mod_func() - whether it validates or restricts module names

- Access controls on the code path that calls _get_view_func

- Whether the view parameter can be influenced by user input or is restricted to registered URL patterns

**Advisory note**

_The grounding check flagged tokens in the reasoning that don't appear in the visible code. This often means the LLM is reasoning by contrast (e.g. "unlike pickle.loads which would be vulnerable") or referencing framework knowledge from training. It can also indicate fabrication. Read the reasoning carefully._

- ℹ️ Reasoning references `does` but this token does not appear in the code or context shown to the LLM.

**Suggested action:** Review callers of _get_view_func to determine if the view parameter can be attacker-controlled, and verify that get_mod_func() adequately restricts module names to prevent arbitrary code loading.

### 29. ⚠️ Needs human review — `python.lang.security.audit.non-literal-import.non-literal-import`

**File:** `django/contrib/auth/hashers.py:231`  

**Severity:** WARNING  **Confidence:** medium — CWE-706: Use of Incorrectly-Resolved Name or Reference

**Reasoning:** The finding flags `importlib.import_module(mod_path)` where `mod_path` is derived from `self.library`. The dataflow shows that if `self.library` is a tuple/list, `mod_path` is the second element; otherwise it's `self.library` itself. The critical question is: where does `self.library` originate? This is a method on what appears to be a password hasher class in Django's auth system. If `self.library` is set by class attributes defined in code (e.g., hardcoded in hasher subclasses), this would be a false positive. However, if `self.library` can be influenced by user input or configuration that accepts arbitrary strings, this could allow arbitrary module loading. The context shows this is in `django/contrib/auth/hashers.py`, which is Django framework code for password hashing. Typically, Django hasher classes define `library` as a class attribute pointing to specific crypto libraries (e.g., 'bcrypt', 'argon2'). However, I cannot see the class definition, how `self.library` is set, or whether it could be influenced by settings or user input.

**Missing context:**

- The class definition containing this method to see how self.library is initialized

- Whether self.library can be set from Django settings or user-controlled configuration

- Call sites of _load_library() to understand when and how it's invoked

- Other hasher class definitions that might set self.library

**Suggested action:** Review how self.library is set in hasher classes - if it's only hardcoded class attributes in framework code, mark as false positive; if it can be influenced by settings or user input, this is a true positive requiring a whitelist.

### 30. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `django/contrib/admin/templates/admin/actions.html:16`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; django/contrib/admin/templates/admin/actions.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 31. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `django/contrib/admin/templates/admin/auth/user/change_password.html:30`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; django/contrib/admin/templates/admin/auth/user/change_password.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 32. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `django/contrib/admin/templates/admin/auth/user/change_password.html:34`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; django/contrib/admin/templates/admin/auth/user/change_password.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 33. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `django/contrib/admin/templates/admin/auth/user/change_password.html:36`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; django/contrib/admin/templates/admin/auth/user/change_password.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 34. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `django/contrib/admin/templates/admin/change_form.html:22`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; django/contrib/admin/templates/admin/change_form.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 35. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `django/contrib/admin/templates/admin/change_form.html:46`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; django/contrib/admin/templates/admin/change_form.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 36. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `django/contrib/admin/templates/admin/change_list.html:54`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; django/contrib/admin/templates/admin/change_list.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 37. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `django/contrib/admin/templates/admin/change_list_object_tools.html:8`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; django/contrib/admin/templates/admin/change_list_object_tools.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 38. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `django/contrib/admin/templates/admin/change_list_results.html:17`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; django/contrib/admin/templates/admin/change_list_results.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 39. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `django/contrib/admin/templates/admin/date_hierarchy.html:4`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; django/contrib/admin/templates/admin/date_hierarchy.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 40. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `django/contrib/admin/templates/admin/delete_confirmation.html:25`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; django/contrib/admin/templates/admin/delete_confirmation.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 41. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `django/contrib/admin/templates/admin/delete_confirmation.html:30`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; django/contrib/admin/templates/admin/delete_confirmation.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 42. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `django/contrib/admin/templates/admin/delete_confirmation.html:35`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; django/contrib/admin/templates/admin/delete_confirmation.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 43. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `django/contrib/admin/templates/admin/delete_selected_confirmation.html:23`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; django/contrib/admin/templates/admin/delete_selected_confirmation.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 44. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `django/contrib/admin/templates/admin/delete_selected_confirmation.html:26`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; django/contrib/admin/templates/admin/delete_selected_confirmation.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 45. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `django/contrib/admin/templates/admin/delete_selected_confirmation.html:29`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; django/contrib/admin/templates/admin/delete_selected_confirmation.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 46. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `django/contrib/admin/templates/admin/filter.html:4`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; django/contrib/admin/templates/admin/filter.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 47. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `django/contrib/admin/templates/admin/login.html:24`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; django/contrib/admin/templates/admin/login.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 48. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `django/contrib/admin/templates/admin/login.html:40`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; django/contrib/admin/templates/admin/login.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 49. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `django/contrib/admin/templates/admin/object_history.html:38`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; django/contrib/admin/templates/admin/object_history.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 50. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `django/contrib/admin/templates/admin/object_history.html:52`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; django/contrib/admin/templates/admin/object_history.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 51. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `django/contrib/admin/templates/admin/pagination.html:4`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; django/contrib/admin/templates/admin/pagination.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 52. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `django/contrib/admin/templates/admin/search_form.html:4`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; django/contrib/admin/templates/admin/search_form.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 53. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `django/contrib/admin/templates/admin/search_form.html:11`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; django/contrib/admin/templates/admin/search_form.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 54. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `django/contrib/admin/templates/admin/search_form.html:11`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; django/contrib/admin/templates/admin/search_form.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 55. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `django/contrib/admin/templates/admin/widgets/related_widget_wrapper.html:11`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; django/contrib/admin/templates/admin/widgets/related_widget_wrapper.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 56. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `django/contrib/admin/templates/admin/widgets/related_widget_wrapper.html:19`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; django/contrib/admin/templates/admin/widgets/related_widget_wrapper.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 57. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `django/contrib/admin/templates/admin/widgets/related_widget_wrapper.html:27`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; django/contrib/admin/templates/admin/widgets/related_widget_wrapper.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 58. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `django/contrib/admin/templates/admin/widgets/related_widget_wrapper.html:34`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; django/contrib/admin/templates/admin/widgets/related_widget_wrapper.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 59. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `django/contrib/admin/templates/registration/password_change_form.html:27`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; django/contrib/admin/templates/registration/password_change_form.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 60. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `django/contrib/admin/templates/registration/password_reset_email.html:2`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; django/contrib/admin/templates/registration/password_reset_email.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 61. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `django/contrib/admin/templates/registration/password_reset_email.html:12`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; django/contrib/admin/templates/registration/password_reset_email.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 62. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `django/contrib/admindocs/templates/admin_doc/bookmarklets.html:15`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; django/contrib/admindocs/templates/admin_doc/bookmarklets.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 63. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `django/contrib/admindocs/templates/admin_doc/missing_docutils.html:17`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; django/contrib/admindocs/templates/admin_doc/missing_docutils.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 64. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `django/contrib/admindocs/templates/admin_doc/missing_docutils.html:19`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; django/contrib/admindocs/templates/admin_doc/missing_docutils.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 65. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `django/contrib/admindocs/templates/admin_doc/model_detail.html:21`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; django/contrib/admindocs/templates/admin_doc/model_detail.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 66. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `django/contrib/admindocs/templates/admin_doc/template_detail.html:13`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; django/contrib/admindocs/templates/admin_doc/template_detail.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 67. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `django/contrib/admindocs/templates/admin_doc/template_detail.html:16`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; django/contrib/admindocs/templates/admin_doc/template_detail.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 68. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `django/contrib/admindocs/templates/admin_doc/template_detail.html:19`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; django/contrib/admindocs/templates/admin_doc/template_detail.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 69. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `django/contrib/admindocs/templates/admin_doc/template_filter_index.html:23`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; django/contrib/admindocs/templates/admin_doc/template_filter_index.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 70. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `django/contrib/admindocs/templates/admin_doc/template_tag_index.html:23`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; django/contrib/admindocs/templates/admin_doc/template_tag_index.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 71. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `django/contrib/admindocs/templates/admin_doc/view_detail.html:12`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; django/contrib/admindocs/templates/admin_doc/view_detail.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 72. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `django/contrib/admindocs/templates/admin_doc/view_index.html:40`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; django/contrib/admindocs/templates/admin_doc/view_index.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 73. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `django/contrib/admindocs/templates/admin_doc/view_index.html:42`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; django/contrib/admindocs/templates/admin_doc/view_index.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 74. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `django/contrib/admindocs/templates/admin_doc/view_index.html:49`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; django/contrib/admindocs/templates/admin_doc/view_index.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 75. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `django/contrib/auth/templates/registration/password_reset_subject.txt:2`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; django/contrib/auth/templates/registration/password_reset_subject.txt requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 76. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `django/views/templates/default_urlconf.html:199`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; django/views/templates/default_urlconf.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 77. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `django/views/templates/default_urlconf.html:201`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; django/views/templates/default_urlconf.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 78. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `django/views/templates/directory_index.html:9`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; django/views/templates/directory_index.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 79. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `django/views/templates/directory_index.html:12`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; django/views/templates/directory_index.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 80. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `docs/ref/templates/builtins.txt:958`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; docs/ref/templates/builtins.txt requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 81. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `docs/ref/templates/builtins.txt:1597`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; docs/ref/templates/builtins.txt requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 82. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `docs/releases/1.4.txt:394`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; docs/releases/1.4.txt requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 83. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `docs/releases/1.7.txt:684`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; docs/releases/1.7.txt requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 84. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `docs/releases/1.7.txt:687`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; docs/releases/1.7.txt requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 85. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `docs/releases/4.2.txt:428`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; docs/releases/4.2.txt requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 86. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `docs/topics/i18n/translation.txt:619`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; docs/topics/i18n/translation.txt requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 87. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `docs/topics/i18n/translation.txt:642`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; docs/topics/i18n/translation.txt requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 88. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `docs/topics/i18n/translation.txt:669`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; docs/topics/i18n/translation.txt requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 89. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `docs/topics/i18n/translation.txt:677`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; docs/topics/i18n/translation.txt requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 90. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `docs/topics/i18n/translation.txt:681`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; docs/topics/i18n/translation.txt requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 91. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `docs/topics/i18n/translation.txt:689`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; docs/topics/i18n/translation.txt requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 92. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `docs/topics/i18n/translation.txt:694`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; docs/topics/i18n/translation.txt requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 93. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `docs/topics/i18n/translation.txt:710`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; docs/topics/i18n/translation.txt requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 94. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `docs/topics/i18n/translation.txt:717`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; docs/topics/i18n/translation.txt requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 95. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `docs/topics/i18n/translation.txt:727`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; docs/topics/i18n/translation.txt requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 96. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `docs/topics/i18n/translation.txt:745`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; docs/topics/i18n/translation.txt requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 97. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `docs/topics/i18n/translation.txt:754`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; docs/topics/i18n/translation.txt requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 98. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `docs/topics/i18n/translation.txt:762`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; docs/topics/i18n/translation.txt requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 99. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `docs/topics/i18n/translation.txt:767`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; docs/topics/i18n/translation.txt requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 100. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `docs/topics/i18n/translation.txt:769`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; docs/topics/i18n/translation.txt requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 101. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `docs/topics/i18n/translation.txt:771`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; docs/topics/i18n/translation.txt requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 102. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `docs/topics/i18n/translation.txt:774`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; docs/topics/i18n/translation.txt requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 103. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `docs/topics/i18n/translation.txt:778`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; docs/topics/i18n/translation.txt requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 104. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `docs/topics/i18n/translation.txt:782`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; docs/topics/i18n/translation.txt requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 105. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `docs/topics/i18n/translation.txt:827`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; docs/topics/i18n/translation.txt requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 106. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `docs/topics/i18n/translation.txt:839`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; docs/topics/i18n/translation.txt requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 107. ⚠️ Needs human review — `python.django.security.audit.xss.template-translate-as-no-escape.template-translate-as-no-escape`

**File:** `django/contrib/admin/templates/admin/actions.html:8`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; django/contrib/admin/templates/admin/actions.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 108. ⚠️ Needs human review — `python.django.security.audit.xss.template-translate-as-no-escape.template-translate-as-no-escape`

**File:** `django/contrib/admin/templates/registration/password_change_form.html:4`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; django/contrib/admin/templates/registration/password_change_form.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 109. ⚠️ Needs human review — `python.django.security.audit.xss.template-translate-as-no-escape.template-translate-as-no-escape`

**File:** `django/contrib/admindocs/templates/admin_doc/missing_docutils.html:14`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; django/contrib/admindocs/templates/admin_doc/missing_docutils.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 110. ⚠️ Needs human review — `python.django.security.audit.xss.template-translate-as-no-escape.template-translate-as-no-escape`

**File:** `django/contrib/admindocs/templates/admin_doc/view_index.html:16`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; django/contrib/admindocs/templates/admin_doc/view_index.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 111. ⚠️ Needs human review — `python.django.security.audit.xss.template-translate-as-no-escape.template-translate-as-no-escape`

**File:** `docs/ref/templates/language.txt:446`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; docs/ref/templates/language.txt requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 112. ⚠️ Needs human review — `python.django.security.audit.xss.template-translate-as-no-escape.template-translate-as-no-escape`

**File:** `docs/topics/i18n/translation.txt:626`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; docs/topics/i18n/translation.txt requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 113. ⚠️ Needs human review — `python.django.security.audit.xss.template-translate-as-no-escape.template-translate-as-no-escape`

**File:** `docs/topics/i18n/translation.txt:638`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; docs/topics/i18n/translation.txt requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 114. ⚠️ Needs human review — `python.django.security.audit.xss.template-translate-as-no-escape.template-translate-as-no-escape`

**File:** `docs/topics/i18n/translation.txt:639`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; docs/topics/i18n/translation.txt requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 115. ⚠️ Needs human review — `python.django.security.audit.xss.template-translate-as-no-escape.template-translate-as-no-escape`

**File:** `docs/topics/i18n/translation.txt:884`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; docs/topics/i18n/translation.txt requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 116. ✅ False positive — `python.sqlalchemy.security.sqlalchemy-execute-raw-query.sqlalchemy-execute-raw-query`

**File:** `django/contrib/gis/db/backends/mysql/introspection.py:17`  

**Severity:** ERROR  **Confidence:** high — CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

**Reasoning:** The Semgrep rule flagged string formatting used to construct a SQL query. The sink is `cursor.execute("DESCRIBE %s" % self.connection.ops.quote_name(table_name))`. The `table_name` parameter flows into `self.connection.ops.quote_name()` before being interpolated into the SQL string. The `quote_name()` method is a Django database backend operation specifically designed to safely quote database identifiers (table names, column names) to prevent SQL injection. This is the standard Django pattern for safely incorporating dynamic table names into raw SQL queries. The method escapes special characters and wraps the identifier appropriately for the database backend. While we cannot see the implementation of `quote_name()`, this is a framework-provided function in Django's database operations layer that handles identifier quoting, which is the correct mitigation for dynamic table names in SQL statements.

**Evidence from the code:**

```
cursor.execute("DESCRIBE %s" % self.connection.ops.quote_name(table_name))
```

**FP categories:** `framework_handled`

**Suggested action:** Verify that Django's quote_name() properly escapes table identifiers for MySQL, but this is standard Django framework behavior for safe identifier quoting.

### 117. ✅ False positive — `python.sqlalchemy.security.sqlalchemy-execute-raw-query.sqlalchemy-execute-raw-query`

**File:** `django/contrib/gis/db/backends/spatialite/schema.py:69`  

**Severity:** ERROR  **Confidence:** high — CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

**Reasoning:** This finding flags string formatting into a SQL query, but the data being interpolated is not attacker-controlled. The `model._meta.db_table` and `field.column` values come from Django's ORM metadata, which represents the database schema definition at the application level, not user input. More importantly, both values are passed through `self.quote_name()` before interpolation (lines 72-73), which is Django's standard SQL identifier quoting function that escapes special characters to prevent SQL injection. This is Django framework code (in `django/contrib/gis/db/backends/spatialite/schema.py`) for schema manipulation operations, where the table and column names are defined by the application's models, not by end users. The pattern Semgrep matched is string formatting, but the context shows this is safe identifier quoting in framework-internal schema operations.

**Evidence from the code:**

```
self.quote_name(model._meta.db_table)
```

```
self.quote_name(field.column)
```

**FP categories:** `framework_handled`, `not_user_input`

**Suggested action:** Mark as false positive; this is Django framework code using quote_name() to safely escape schema identifiers from model metadata.

### 118. ✅ False positive — `python.django.security.audit.avoid-mark-safe.avoid-mark-safe`

**File:** `django/contrib/admin/helpers.py:161`  

**Severity:** WARNING  **Confidence:** high — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** The code calls `mark_safe()` on the result of joining `self.form[f].errors.as_ul()` for each field. The key question is whether `as_ul()` returns already-escaped HTML. In Django's form error handling, `errors.as_ul()` is a built-in method on ErrorList that returns HTML-escaped error messages wrapped in `<ul>` and `<li>` tags. Django's ErrorList.as_ul() method explicitly escapes user-provided error messages before rendering them as HTML. The `mark_safe()` call here is marking the structural HTML (the `<ul>` and `<li>` tags) as safe, not marking raw user input as safe. This is a standard Django pattern where framework-generated HTML that has already been properly escaped is marked safe to prevent double-escaping of the HTML structure itself. This code is in Django's own admin helpers, using Django's own form error rendering methods that handle escaping internally.

**Evidence from the code:**

```
return mark_safe(
            "\n".join(
                self.form[f].errors.as_ul()
                for f in self.fields
                if f not in self.readonly_fields
            ).strip("\n")
        )
```

**FP categories:** `framework_handled`

**Advisory note**

_The grounding check flagged tokens in the reasoning that don't appear in the visible code. This often means the LLM is reasoning by contrast (e.g. "unlike pickle.loads which would be vulnerable") or referencing framework knowledge from training. It can also indicate fabrication. Read the reasoning carefully._

- ℹ️ Reasoning references `ErrorList` but this token does not appear in the code or context shown to the LLM.

**Suggested action:** No action needed. Django's ErrorList.as_ul() handles HTML escaping internally before this mark_safe() call.

### 119. ✅ False positive — `python.django.security.audit.avoid-mark-safe.avoid-mark-safe`

**File:** `django/contrib/admin/helpers.py:193`  

**Severity:** WARNING  **Confidence:** high — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** The finding flags `mark_safe()` on line 193, but examining the dataflow shows this is safe. On line 180, `contents` is assigned the result of `conditional_escape(self.field.label)`. The `conditional_escape` function (shown in the context) explicitly escapes text unless it's already marked safe (has `__html__` method). The escaped string is then passed to `mark_safe()` on line 193. This is a standard Django pattern: escape untrusted content first, then mark it safe so it can be passed to a function that expects SafeString. The `self.field.label_tag()` method being called expects a SafeString for its contents parameter. Since the content was already escaped by `conditional_escape()`, marking it safe does not introduce XSS risk.

**Evidence from the code:**

```
contents = conditional_escape(self.field.label)
```

```
contents=mark_safe(contents)
```

**FP categories:** `sanitized_input`

**Suggested action:** No action needed. The content is properly escaped before being marked safe.

### 120. ✅ False positive — `python.django.security.audit.avoid-mark-safe.avoid-mark-safe`

**File:** `django/contrib/admin/helpers.py:200`  

**Severity:** WARNING  **Confidence:** high — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** The finding flags `mark_safe()` being called on `self.field.errors.as_ul()`. The key question is whether `as_ul()` returns already-escaped HTML or user-controlled content. This code is in Django's own admin helpers module (django/contrib/admin/helpers.py), which is part of Django's core framework. The `self.field.errors` is a Django form ErrorList object, and `as_ul()` is a Django framework method that generates HTML error lists. Django's ErrorList.as_ul() method is documented to return escaped HTML - it properly escapes any user input in error messages before wrapping them in `<ul>` tags. The pattern here is the standard Django idiom: framework methods that generate HTML fragments (like as_ul(), as_p(), etc.) return escaped strings that need mark_safe() to preserve the intentional HTML tags. This is not user-controlled content being marked safe; it's framework-generated, already-escaped HTML being marked safe so the HTML tags themselves aren't double-escaped.

**Evidence from the code:**

```
return mark_safe(self.field.errors.as_ul())
```

**FP categories:** `framework_handled`

**Advisory note**

_The grounding check flagged tokens in the reasoning that don't appear in the visible code. This often means the LLM is reasoning by contrast (e.g. "unlike pickle.loads which would be vulnerable") or referencing framework knowledge from training. It can also indicate fabrication. Read the reasoning carefully._

- ℹ️ Reasoning references `fragments` but this token does not appear in the code or context shown to the LLM.

- ℹ️ Reasoning references `as_p` but this token does not appear in the code or context shown to the LLM.

- ℹ️ Reasoning references `ErrorList` but this token does not appear in the code or context shown to the LLM.

**Suggested action:** Verify that this is Django framework code (not a fork with modifications) and that ErrorList.as_ul() properly escapes content, which is the documented behavior.

### 121. ✅ False positive — `python.django.security.audit.avoid-mark-safe.avoid-mark-safe`

**File:** `django/contrib/admin/options.py:384`  

**Severity:** WARNING  **Confidence:** high — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** The finding flags `mark_safe(self.empty_value_display)` in Django's admin options. The `empty_value_display` is a configuration attribute set by administrators to control how empty/null values are displayed in the admin interface. This is not user-controlled input but rather a framework configuration value set by the site administrator (typically a hardcoded string like "-" or "N/A"). The attribute is accessed from either `self.empty_value_display` or falls back to `self.admin_site.empty_value_display`, both of which are configuration values set during Django admin setup, not runtime user input. Since this is administrator-controlled configuration data rather than attacker-controlled input, there is no XSS risk here.

**Evidence from the code:**

```
return mark_safe(self.empty_value_display)
```

```
return mark_safe(self.admin_site.empty_value_display)
```

**FP categories:** `not_user_input`

**Advisory note**

_The grounding check flagged tokens in the reasoning that don't appear in the visible code. This often means the LLM is reasoning by contrast (e.g. "unlike pickle.loads which would be vulnerable") or referencing framework knowledge from training. It can also indicate fabrication. Read the reasoning carefully._

- ℹ️ Reasoning references `administrator` but this token does not appear in the code or context shown to the LLM.

**Suggested action:** No action needed; this is Django framework code using mark_safe on administrator-configured display values, not user input.

### 122. ✅ False positive — `python.django.security.audit.avoid-mark-safe.avoid-mark-safe`

**File:** `django/contrib/admin/options.py:386`  

**Severity:** WARNING  **Confidence:** high — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** The finding flags `mark_safe()` being called on `self.admin_site.empty_value_display`. This is a configuration value set by the Django admin framework itself, not user-controlled input. The `empty_value_display` attribute is a Django admin configuration option that administrators set to control how empty/null values are displayed in the admin interface (typically something like "-" or "N/A"). This is framework-controlled configuration data, not attacker-supplied input. The value flows from Django's AdminSite configuration, which is set by developers in their admin configuration code, not from HTTP requests or user input. There is no dataflow path from untrusted input to this sink.

**Evidence from the code:**

```
return mark_safe(self.admin_site.empty_value_display)
```

**FP categories:** `not_user_input`, `framework_handled`

**Suggested action:** No action needed. This is Django framework code using mark_safe on a configuration value, not user input.

### 123. ✅ False positive — `python.django.security.audit.avoid-mark-safe.avoid-mark-safe`

**File:** `django/contrib/admin/templatetags/admin_filters.py:79`  

**Severity:** WARNING  **Confidence:** high — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** This is a Django template tag function that constructs HTML from user-provided data. The key question is whether the data is properly escaped before being marked safe. The function has an `autoescape` parameter (line 19) that defaults to True. When autoescape is True, the `escaper` variable is set to `conditional_escape` (line 36), which is Django's HTML escaping function. This escaper is applied to each item at line 61: `escaper(item)`. The `remaining_objects_message` is constructed from `ngettext` output (lines 71-76), which returns translated strings with interpolated count values - not user-controlled HTML. The HTML structure (ul/li tags) is hardcoded by the function itself. Therefore, user-provided content goes through `conditional_escape` before being incorporated into the HTML, and `mark_safe` is only applied to the final constructed string after escaping has occurred. This is the correct Django pattern for building HTML in template tags.

**Evidence from the code:**

```
if autoescape:
        escaper = conditional_escape
```

```
if should_display_item:
                output.append("%s<li>%s%s</li>" % (indent, escaper(item), sublist))
```

**FP categories:** `framework_handled`

**Suggested action:** No action needed - this is proper use of mark_safe after conditional_escape in a Django template tag.

### 124. ✅ False positive — `python.django.security.audit.avoid-mark-safe.avoid-mark-safe`

**File:** `django/contrib/admin/templatetags/admin_list.py:308`  

**Severity:** WARNING  **Confidence:** high — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** The finding flags `mark_safe(str(bf.errors) + str(bf))` on line 308. The variable `bf` is a Django form field bound to a form (`bf = form[field_name]`), where `form` is passed as a parameter to `items_for_result`. In Django, when you call `str()` on a BoundField object (`bf`) and its errors (`bf.errors`), Django's form rendering system already escapes the output appropriately. The `__str__` method of BoundField returns HTML that has been properly escaped by Django's form rendering machinery. Similarly, `bf.errors` returns an ErrorList which also escapes its content when converted to string. The result_repr is then passed to `format_html("<td{}>{}</td>", row_class, result_repr)` on line 309, where `format_html` will call `conditional_escape()` on `result_repr`. However, since `result_repr` is already marked safe, it won't be double-escaped. This is the intended Django pattern for rendering form fields in templates - the form field rendering handles escaping, mark_safe preserves that escaping through the template layer, and format_html assembles the final HTML safely.

**Evidence from the code:**

```
bf = form[field_name]
```

```
result_repr = mark_safe(str(bf.errors) + str(bf))
```

```
yield format_html("<td{}>{}</td>", row_class, result_repr)
```

**FP categories:** `framework_handled`

**Advisory note**

_The grounding check flagged tokens in the reasoning that don't appear in the visible code. This often means the LLM is reasoning by contrast (e.g. "unlike pickle.loads which would be vulnerable") or referencing framework knowledge from training. It can also indicate fabrication. Read the reasoning carefully._

- ℹ️ Reasoning references `BoundField` but this token does not appear in the code or context shown to the LLM.

- ℹ️ Reasoning references `ErrorList` but this token does not appear in the code or context shown to the LLM.

**Suggested action:** No action needed - this is Django's standard pattern for rendering form fields in admin changeform lists where the framework handles escaping.

### 125. ✅ False positive — `python.django.security.audit.avoid-mark-safe.avoid-mark-safe`

**File:** `django/contrib/admin/templatetags/admin_list.py:339`  

**Severity:** WARNING  **Confidence:** high — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** The finding flags `mark_safe()` being called on `form[cl.model._meta.pk.name]`, which is a Django form field. In Django's form system, when you access a form field using bracket notation (e.g., `form[field_name]`), you get a BoundField object. When a BoundField is rendered (converted to string), Django's form framework already handles HTML escaping appropriately based on the field type. The code specifically checks `if form[cl.model._meta.pk.name].is_hidden` before yielding, meaning this is rendering a hidden input field. Hidden form fields generated by Django forms are already safe HTML - they are rendered as `<input type="hidden" ...>` with properly escaped attribute values. The `mark_safe()` here is marking the already-safe HTML output from Django's form rendering system, not marking untrusted user input. This is a standard pattern in Django's own admin code for rendering form fields that have already been processed by the framework's escaping mechanisms.

**Evidence from the code:**

```
if form[cl.model._meta.pk.name].is_hidden:
```

```
yield mark_safe(form[cl.model._meta.pk.name])
```

**FP categories:** `framework_handled`

**Advisory note**

_The grounding check flagged tokens in the reasoning that don't appear in the visible code. This often means the LLM is reasoning by contrast (e.g. "unlike pickle.loads which would be vulnerable") or referencing framework knowledge from training. It can also indicate fabrication. Read the reasoning carefully._

- ℹ️ Reasoning references `field_name` but this token does not appear in the code or context shown to the LLM.

- ℹ️ Reasoning references `BoundField` but this token does not appear in the code or context shown to the LLM.

**Suggested action:** No action needed - this is Django framework code correctly marking form field HTML output as safe after the framework has already handled escaping.

### 126. ✅ False positive — `python.django.security.audit.avoid-mark-safe.avoid-mark-safe`

**File:** `django/contrib/admindocs/utils.py:92`  

**Severity:** WARNING  **Confidence:** high — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** The finding flags `mark_safe()` on line 92 returning `parts["fragment"]` from docutils. The `parse_rst` function uses docutils to convert reStructuredText to XHTML. The key security controls are in the `overrides` dictionary passed to `docutils.core.publish_parts()`: `"raw_enabled": False` and `"file_insertion_enabled": False` disable dangerous docutils directives that could inject arbitrary content. The docutils library itself is a trusted HTML generator that escapes user content appropriately when these dangerous features are disabled. The output from `parts["fragment"]` is already safe HTML produced by docutils' HTML writer, similar to how Django's `format_html()` produces safe output. This is framework-handled escaping where the trusted library (docutils) is responsible for producing safe HTML from potentially untrusted reStructuredText input.

**Evidence from the code:**

```
"raw_enabled": False,
```

```
"file_insertion_enabled": False,
```

```
writer_instance = docutils.writers.get_writer_class("html")()
```

```
parts = docutils.core.publish_parts(
```

**FP categories:** `framework_handled`

**Suggested action:** Accept as false positive; docutils with raw_enabled=False and file_insertion_enabled=False produces safe HTML output that is appropriate to mark_safe.

### 127. ✅ False positive — `python.django.security.audit.custom-expression-as-sql.custom-expression-as-sql`

**File:** `django/contrib/gis/db/backends/postgis/operations.py:43`  

**Severity:** WARNING  **Confidence:** high — CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

**Reasoning:** This is Django framework code in the PostGIS backend operations module. The `as_sql` method is part of Django's ORM query compilation infrastructure, not application code handling user input. The method receives `template_params` which has already been processed through Django's ORM parameterization system. The `check_raster` and `check_geography` functions only modify template placeholders (e.g., wrapping them with SQL function calls like "ST_Polygon(%s)"), not injecting raw user data. The `%s` placeholders in lines 62-64, 76-78, 85-87, 92-94, and 101 are template parameter placeholders that will be properly parameterized by Django's database backend when the final SQL is executed. This is framework-internal code that maintains SQL injection safety through Django's parameterization layer.

**Evidence from the code:**

```
template_params["lhs"] = "%s, %s" % (
                template_params["lhs"],
                lookup.band_lhs,
            )
```

```
template_params["lhs"] = "ST_Polygon(%s)" % template_params["lhs"]
```

```
template_params["lhs"] += "::geometry"
```

**FP categories:** `framework_handled`, `third_party`

**Advisory note**

_The grounding check flagged tokens in the reasoning that don't appear in the visible code. This often means the LLM is reasoning by contrast (e.g. "unlike pickle.loads which would be vulnerable") or referencing framework knowledge from training. It can also indicate fabrication. Read the reasoning carefully._

- ℹ️ Reasoning references `placeholders` but this token does not appear in the code or context shown to the LLM.

**Suggested action:** No action needed - this is Django framework code that properly uses parameterized queries through the ORM's query compilation system.

### 128. ✅ False positive — `python.django.security.audit.custom-expression-as-sql.custom-expression-as-sql`

**File:** `django/contrib/gis/db/backends/spatialite/operations.py:21`  

**Severity:** WARNING  **Confidence:** high — CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

**Reasoning:** The Semgrep rule flagged a call to `super().as_sql(connection, lookup, template_params, sql_params)` as a potential SQL injection risk. However, this is Django framework code within the GIS backend operations module. The `as_sql` method is part of Django's ORM query compilation infrastructure, where `super()` refers to the parent class implementation (likely `SpatialOperator` or a base class from `BaseSpatialOperations`). The parameters being passed (`connection`, `lookup`, `template_params`, `sql_params`) are internal Django ORM objects that follow Django's parameterized query pattern. The returned `sql` is a template string and `params` contains the parameterized values that will be safely bound by the database driver. The subsequent line `return "%s > 0" % sql, params` wraps the SQL template but preserves the separate params tuple for proper parameterization. This is standard Django ORM internal code, not user-controlled input being interpolated into SQL.

**Evidence from the code:**

```
sql, params = super().as_sql(connection, lookup, template_params, sql_params)
```

```
return "%s > 0" % sql, params
```

**FP categories:** `framework_handled`, `false_pattern_match`

**Suggested action:** Mark as false positive; this is Django framework code using the ORM's parameterized query infrastructure.

### 129. ✅ False positive — `python.django.security.audit.extends-custom-expression.extends-custom-expression`

**File:** `django/contrib/gis/db/backends/postgis/operations.py:105`  

**Severity:** WARNING  **Confidence:** high — CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

**Reasoning:** The Semgrep rule has flagged the definition of a Django ORM database function class `ST_Polygon` that extends `Func`. This is Django framework code (in `django/contrib/gis/db/backends/postgis/operations.py`) that defines how to construct SQL function calls for PostGIS spatial operations. The class itself is not performing SQL injection - it's defining a parameterized database function wrapper that Django's ORM will use to safely construct SQL queries. The `__init__` method only manipulates Django ORM expression objects (`Value`, `RasterField`) and does not directly concatenate strings into SQL. Django's `Func` base class handles SQL generation with proper parameterization. This is a false pattern match on framework code that defines database function abstractions, not user-facing code that processes untrusted input.

**Evidence from the code:**

```
class ST_Polygon(Func):
```

```
function = "ST_Polygon"
```

```
super().__init__(expr)
```

**FP categories:** `third_party`, `framework_handled`

**Advisory note**

_The grounding check flagged tokens in the reasoning that don't appear in the visible code. This often means the LLM is reasoning by contrast (e.g. "unlike pickle.loads which would be vulnerable") or referencing framework knowledge from training. It can also indicate fabrication. Read the reasoning carefully._

- ℹ️ Reasoning references `objects` but this token does not appear in the code or context shown to the LLM.

**Suggested action:** No action needed - this is Django framework code defining a parameterized database function wrapper, not a SQL injection vulnerability.

### 130. ✅ False positive — `python.django.security.audit.unvalidated-password.unvalidated-password`

**File:** `django/contrib/auth/__init__.py:402`  

**Severity:** WARNING  **Confidence:** high — CWE-521: Weak Password Requirements

**Reasoning:** The flagged line is in `check_password_with_timing_attack_mitigation`, which is designed to prevent user enumeration timing attacks. When `user is None`, the function calls `get_user_model()().set_password(password)` on a throwaway, never-persisted user instance solely to consume CPU time equivalent to what would be spent checking a real password hash. The docstring explicitly states this is to "prevent user enumeration attacks (#20760)". The password is never saved to the database, and the temporary user object is immediately discarded. This is not setting a password that will be stored; it's a timing-attack mitigation technique. Password validation is irrelevant here because no password is actually being set on any persistent user account.

**Evidence from the code:**

```
def check_password_with_timing_attack_mitigation(user, password):
```

```
"""
```

```
Checks password against the user's hash if there is a user, otherwise runs
```

```
the default password hasher to prevent user enumeration attacks (#20760).
```

```
"""
```

```
if user is None:
```

```
get_user_model()().set_password(password)
```

**FP categories:** `false_pattern_match`

**Suggested action:** Close as false positive; this is a timing-attack mitigation pattern in Django's authentication framework, not actual password setting.

### 131. ✅ False positive — `python.django.security.audit.unvalidated-password.unvalidated-password`

**File:** `django/contrib/auth/__init__.py:410`  

**Severity:** WARNING  **Confidence:** high — CWE-521: Weak Password Requirements

**Reasoning:** The matched line is in `acheck_password_with_timing_attack_mitigation`, which is a timing-attack mitigation function. When `user is None`, the function calls `get_user_model()().set_password(password)` on a throwaway user instance that is never saved or used. This is a deliberate timing-attack countermeasure: by performing the same expensive password hashing operation whether the user exists or not, the function prevents attackers from using timing differences to enumerate valid usernames. The password is not being set on any real user object, and the temporary instance is immediately discarded. Password validation would be inappropriate here since this is not actually creating or updating a user account — it's a dummy operation purely for timing consistency.

**Evidence from the code:**

```
if user is None:
```

```
get_user_model()().set_password(password)
```

```
async def acheck_password_with_timing_attack_mitigation(user, password):
```

```
"""See check_user_with_timing_attack_mitigation."""
```

**FP categories:** `false_pattern_match`

**Suggested action:** Close as false positive; this is a timing-attack mitigation pattern in Django's authentication framework, not a real password-setting operation.

### 132. ✅ False positive — `python.django.security.audit.unvalidated-password.unvalidated-password`

**File:** `django/contrib/auth/base_user.py:115`  

**Severity:** WARNING  **Confidence:** high — CWE-521: Weak Password Requirements

**Reasoning:** This finding is in Django's own authentication framework code (django/contrib/auth/base_user.py), not application code. The `setter` function is an internal async helper that wraps `set_password` for password hash upgrades, as indicated by the comment "Password hash upgrades shouldn't be considered password changes." This is framework code that handles password hashing internally. The file imports `password_validation` at the top, and validation would be the responsibility of application code calling Django's user management APIs, not this low-level password-setting primitive. This is third-party framework code that applications depend on, not code the application developer maintains or should modify.

**Evidence from the code:**

```
# Password hash upgrades shouldn't be considered password changes.
```

```
from django.contrib.auth import password_validation
```

**FP categories:** `third_party`

**Suggested action:** No action needed - this is Django framework code, not application code to be modified.

### 133. ✅ False positive — `python.django.security.audit.unvalidated-password.unvalidated-password`

**File:** `django/contrib/auth/management/commands/changepassword.py:79`  

**Severity:** WARNING  **Confidence:** high — CWE-521: Weak Password Requirements

**Reasoning:** The Semgrep rule flags line 79 where `u.set_password(p1)` is called, claiming the password is set without validation. However, examining the dataflow shows that password validation is performed before reaching this line. The code enters a while loop at line 58 with the condition `(p1 != p2 or not password_validated) and count < MAX_TRIES`. Inside the loop, after confirming passwords match, `validate_password(p2, u)` is called at line 67. If validation fails, a ValidationError is caught and the loop continues. Only when validation succeeds does `password_validated = True` get set at line 72, allowing the loop to exit. The loop can only exit successfully (without raising CommandError at lines 75-77) when `password_validated` is True, meaning `validate_password()` has been called and did not raise an exception. Therefore, by the time execution reaches line 79, the password has been validated.

**Evidence from the code:**

```
while (p1 != p2 or not password_validated) and count < MAX_TRIES:
```

```
try:
                validate_password(p2, u)
            except ValidationError as err:
                self.stderr.write("\n".join(err.messages))
                count += 1
            else:
                password_validated = True
```

```
if count == MAX_TRIES:
            raise CommandError(
                "Aborting password change for user '%s' after %s attempts" % (u, count)
            )
```

**FP categories:** `false_pattern_match`

**Suggested action:** Mark as false positive; password validation is enforced by the loop control flow before set_password is called.

### 134. ✅ False positive — `python.django.security.audit.xss.direct-use-of-httpresponse.direct-use-of-httpresponse`

**File:** `django/contrib/flatpages/views.py:70`  

**Severity:** WARNING  **Confidence:** high — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** The Semgrep rule flags the use of HttpResponse with rendered content, concerned about XSS. However, this is Django framework code (django/contrib/flatpages/views.py) that correctly uses Django's template engine. The code calls `template.render({"flatpage": f}, request)` where `template` is obtained via `loader.select_template()` or `loader.get_template()` - both standard Django template loading functions. Django's template engine automatically escapes variables by default to prevent XSS. The comment on lines 64-66 explains that `mark_safe()` is intentionally used on f.title and f.content because they contain "raw HTML content in the first place" - this is the expected behavior for Django's flatpages app, which stores pre-authored HTML content. The use of HttpResponse here is the standard Django pattern for returning rendered template content and does not bypass XSS protections - the template engine has already applied them during the render() call.

**Evidence from the code:**

```
# To avoid having to always use the "|safe" filter in flatpage templates,
```

```
# mark the title and content as already safe (since they are raw HTML
```

```
# content in the first place).
```

```
return HttpResponse(template.render({"flatpage": f}, request))
```

**FP categories:** `framework_handled`, `false_pattern_match`

**Suggested action:** Close as false positive - this is correct Django framework code using the template engine's built-in XSS protections.

### 135. ✅ False positive — `python.django.security.audit.xss.filter-with-is-safe.filter-with-is-safe`

**File:** `django/contrib/admin/templatetags/admin_filters.py:18`  

**Severity:** WARNING  **Confidence:** high — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** This is a Django template filter in the admin module that constructs HTML list elements. The rule flags `is_safe=True` as potentially dangerous, but examining the dataflow shows proper escaping is applied. The filter accepts `needs_autoescape=True` and conditionally applies `conditional_escape` to user-provided content on line 36. At line 61, the actual item content is escaped via `escaper(item)` before being inserted into the HTML. The only unescaped content consists of hardcoded HTML structure (`<ul>`, `<li>`, `</ul>` tags) and a translated message from Django's i18n system (lines 71-76) that contains no user input. The final `mark_safe()` call on line 79 is appropriate because the function has already escaped all user-controlled data and is only marking the complete HTML structure as safe.

**Evidence from the code:**

```
if autoescape:
        escaper = conditional_escape
```

```
output.append("%s<li>%s%s</li>" % (indent, escaper(item), sublist))
```

```
@register.filter(is_safe=True, needs_autoescape=True)
```

**FP categories:** `framework_handled`

**Suggested action:** No action needed. The filter properly escapes user input via conditional_escape before inserting into HTML.

### 136. ✅ False positive — `python.django.security.injection.open-redirect.open-redirect`

**File:** `django/contrib/admin/options.py:1505`  

**Severity:** WARNING  **Confidence:** high — CWE-601: URL Redirection to Untrusted Site ('Open Redirect')

**Reasoning:** The Semgrep rule flagged line 1514 where `redirect_url` is passed to `HttpResponseRedirect()`. However, examining the dataflow shows that `redirect_url` is not attacker-controlled. At line 1505, `redirect_url` is initialized to `request.path`, which is the current request path (not a user-supplied parameter). This value is then passed through `add_preserved_filters()` at lines 1506-1513, which adds query string parameters but does not change the base path. The `add_preserved_filters()` function (lines 22-70) parses the URL, merges query string parameters from preserved filters, and reconstructs the URL - but the path component comes from the original `request.path`. Since `request.path` represents the current URL path being accessed (not a redirect target from user input), and this code is redirecting back to the same admin form page after an "add another" action, this is not an open redirect vulnerability. The redirect target is determined by the application's routing, not by attacker-controlled input.

**Evidence from the code:**

```
redirect_url = request.path
```

```
redirect_url = add_preserved_filters(
            {
                "preserved_filters": preserved_filters,
                "preserved_qsl": preserved_qsl,
                "opts": opts,
            },
            redirect_url,
        )
```

**FP categories:** `not_user_input`

**Advisory note**

_The grounding check flagged tokens in the reasoning that don't appear in the visible code. This often means the LLM is reasoning by contrast (e.g. "unlike pickle.loads which would be vulnerable") or referencing framework knowledge from training. It can also indicate fabrication. Read the reasoning carefully._

- ℹ️ Reasoning references `accessed` but this token does not appear in the code or context shown to the LLM.

**Suggested action:** Mark as false positive - the redirect URL is derived from request.path (the current page), not from user-controllable input.

### 137. ✅ False positive — `python.django.security.injection.open-redirect.open-redirect`

**File:** `django/contrib/admin/options.py:1576`  

**Severity:** WARNING  **Confidence:** high — CWE-601: URL Redirection to Untrusted Site ('Open Redirect')

**Reasoning:** The Semgrep rule flagged line 1585 where `redirect_url` is passed to `HttpResponseRedirect()`. However, examining the dataflow shows that `redirect_url` is initialized from `request.path` (line 1576), which is the current request path controlled by Django's URL routing, not user-supplied data. The `request.path` attribute represents the path component of the URL that was matched by Django's URL resolver to reach this view - it's the server-side path, not arbitrary user input. The `add_preserved_filters()` function (lines 22-70) then appends query string parameters derived from `preserved_filters` and `preserved_qsl`, which come from `get_preserved_filters()` and `_get_preserved_qsl()`. While these do incorporate some request data (GET parameters), the base URL being redirected to is `request.path`, which is the current admin change view path. This is a same-site redirect to the same admin page the user is already on (the "_continue" button flow), not an open redirect to an arbitrary external URL.

**Evidence from the code:**

```
redirect_url = request.path
```

```
if "_continue" in request.POST:
```

**FP categories:** `not_user_input`

**Suggested action:** Mark as false positive. The redirect URL is based on request.path (the current server-side path), not arbitrary user input, and represents a same-site redirect within the Django admin.

### 138. ✅ False positive — `python.flask.security.xss.audit.direct-use-of-jinja2.direct-use-of-jinja2`

**File:** `django/contrib/admin/templatetags/admin_list.py:521`  

**Severity:** WARNING  **Confidence:** high — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** This is a false positive due to a false pattern match. The Semgrep rule is designed to detect direct use of jinja2 in Flask applications, but this code is from Django, not Flask. The file path `django/contrib/admin/templatetags/admin_list.py` and imports clearly show this is Django framework code. The code uses `django.template.loader.get_template()` which returns a Django template object, not a jinja2 template. Django's template system has its own auto-escaping mechanism that is enabled by default for HTML contexts. The rule message explicitly mentions "Prefer using the Flask method 'render_template()'" which is not applicable to Django code. This is a framework mismatch - the rule is targeting Flask/jinja2 patterns but matched Django template rendering.

**Evidence from the code:**

```
from django.template import Library
```

```
from django.template.loader import get_template
```

```
tpl = get_template(spec.template)
```

**FP categories:** `false_pattern_match`

**Suggested action:** Dismiss this finding - the rule is designed for Flask applications but matched Django framework code which has its own XSS protections.

### 139. ✅ False positive — `python.lang.security.audit.formatted-sql-query.formatted-sql-query`

**File:** `django/contrib/gis/db/backends/mysql/introspection.py:17`  

**Severity:** WARNING  **Confidence:** high — CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

**Reasoning:** The Semgrep rule flagged string formatting in a SQL query, but this is a false positive because the table name is properly quoted using Django's `quote_name()` method. The code constructs a DESCRIBE statement with `"DESCRIBE %s" % self.connection.ops.quote_name(table_name)`. The `quote_name()` method is Django's standard database operation for safely quoting identifiers (table names, column names) to prevent SQL injection. This is the correct approach for dynamic table names in SQL, as table/column identifiers cannot be parameterized using bind variables in most SQL databases. The method escapes special characters and wraps the identifier appropriately for the database backend (MySQL in this case). This is Django framework code (in `django/contrib/gis/db/backends/mysql/introspection.py`) using Django's own security mechanisms correctly.

**Evidence from the code:**

```
cursor.execute("DESCRIBE %s" % self.connection.ops.quote_name(table_name))
```

**FP categories:** `framework_handled`

**Suggested action:** No action needed; Django's quote_name() properly escapes table identifiers for SQL DESCRIBE statements.

### 140. ✅ False positive — `python.lang.security.audit.logging.logger-credential-leak.python-logger-credential-disclosure`

**File:** `django/contrib/auth/forms.py:419`  

**Severity:** WARNING  **Confidence:** high — CWE-532: Insertion of Sensitive Information into Log File

**Reasoning:** The Semgrep rule flagged this logger call because it detected the string "password" in the log message. However, examining the actual code shows that the log statement only logs the user's primary key (context["user"].pk), which is a non-sensitive identifier. The log message "Failed to send password reset email to %s" is a static string describing the operation that failed, not logging any actual password or credential. The %s placeholder is filled with context["user"].pk, which is a database ID, not a secret. This is a false pattern match where the rule detected the word "password" in a descriptive message but no actual sensitive data is being logged.

**Evidence from the code:**

```
"Failed to send password reset email to %s", context["user"].pk
```

**FP categories:** `false_pattern_match`

**Suggested action:** Mark as false positive; only a user ID is logged, not any credential or sensitive data.

### 141. ✅ False positive — `python.lang.security.audit.md5-used-as-password.md5-used-as-password`

**File:** `django/contrib/auth/hashers.py:669`  

**Severity:** WARNING  **Confidence:** high — CWE-327: Use of a Broken or Risky Cryptographic Algorithm

**Reasoning:** This finding is in Django's core authentication framework (django/contrib/auth/hashers.py). The `encode` method is part of a password hasher class that uses MD5. However, this is intentionally provided for backward compatibility with legacy systems. Django's password hasher framework supports multiple algorithms, and MD5 is not the default - it's only used when explicitly configured. The file path and structure indicate this is part of Django's pluggable password hasher system where multiple algorithms coexist. The method signature `encode(self, password, salt)` and return format `"%s$%s$%s" % (self.algorithm, salt, hash)` match Django's hasher interface pattern. This is framework code that provides the option for MD5 (likely for migration scenarios), not application code that incorrectly chose MD5 for new password hashing.

**Evidence from the code:**

```
hash = hashlib.md5((salt + password).encode()).hexdigest()
```

```
return "%s$%s$%s" % (self.algorithm, salt, hash)
```

**FP categories:** `third_party`, `framework_handled`

**Suggested action:** Verify that MD5PasswordHasher is not configured as the default PASSWORD_HASHERS in Django settings, and is only used for legacy password migration.

### 142. ✅ False positive — `python.lang.security.audit.non-literal-import.non-literal-import`

**File:** `django/apps/config.py:210`  

**Severity:** WARNING  **Confidence:** high — CWE-706: Use of Incorrectly-Resolved Name or Reference

**Reasoning:** This finding is in Django's core application configuration system. The `create` method is a factory that processes entries from Django's `INSTALLED_APPS` setting. The `app_name` variable at line 210 comes from `app_config_class.name` (line 204), which is an attribute of an AppConfig class that has already been validated to be a subclass of AppConfig (line 197). The INSTALLED_APPS setting is a configuration value defined by the application developer in settings.py, not user input. This is framework configuration code that loads application modules during Django initialization, not a code path that processes untrusted user input. The entry parameter originates from the project's configuration files, which are controlled by developers, not end users.

**Evidence from the code:**

```
app_name = app_config_class.name
```

```
if not issubclass(app_config_class, AppConfig):
```

```
raise ImproperlyConfigured("'%s' isn't a subclass of AppConfig." % entry)
```

```
app_module = import_module(app_name)
```

```
Factory that creates an app config from an entry in INSTALLED_APPS.
```

**FP categories:** `not_user_input`, `framework_handled`

**Suggested action:** Mark as false positive. This is Django framework code that loads application modules from developer-controlled configuration, not user input.

### 143. ✅ False positive — `python.lang.security.audit.non-literal-import.non-literal-import`

**File:** `django/apps/config.py:269`  

**Severity:** WARNING  **Confidence:** high — CWE-706: Use of Incorrectly-Resolved Name or Reference

**Reasoning:** The finding flags `import_module(models_module_name)` as potentially loading untrusted user input. However, examining the dataflow shows `models_module_name` is constructed from `self.name` and `MODELS_MODULE_NAME` constant on line 268. The value `self.name` is an attribute of the AppConfig class in Django's core framework, which represents the Python module path of a registered Django application. This is set during Django's application initialization from the INSTALLED_APPS setting in settings.py, which is a configuration file controlled by the application developer, not by end users. The module name is not derived from HTTP request parameters, user input, or any attacker-controlled source. This is Django framework code that loads application models during startup based on developer-configured application names.

**Evidence from the code:**

```
models_module_name = "%s.%s" % (self.name, MODELS_MODULE_NAME)
```

```
self.models_module = import_module(models_module_name)
```

**FP categories:** `not_user_input`, `framework_handled`

**Suggested action:** No action needed. This is Django framework code loading application models from developer-configured app names, not user input.

## Per-rule statistics

| Rule | Total | FP | Likely TP | Review | FP rate |
|---|---:|---:|---:|---:|---:|
| `python.django.security.injection.open-redirect.open-redirect` | 2 | 2 | 0 | 0 | 100% |
| `python.django.security.audit.extends-custom-expression.extends-custom-expression` | 1 | 1 | 0 | 0 | 100% |
| `python.django.security.audit.xss.direct-use-of-httpresponse.direct-use-of-httpresponse` | 1 | 1 | 0 | 0 | 100% |
| `python.django.security.audit.xss.filter-with-is-safe.filter-with-is-safe` | 1 | 1 | 0 | 0 | 100% |
| `python.flask.security.xss.audit.direct-use-of-jinja2.direct-use-of-jinja2` | 1 | 1 | 0 | 0 | 100% |
| `python.lang.security.audit.logging.logger-credential-leak.python-logger-credential-disclosure` | 1 | 1 | 0 | 0 | 100% |
| `python.lang.security.audit.md5-used-as-password.md5-used-as-password` | 1 | 1 | 0 | 0 | 100% |
| `python.django.security.audit.avoid-mark-safe.avoid-mark-safe` | 12 | 9 | 0 | 3 | 75% |
| `python.django.security.audit.unvalidated-password.unvalidated-password` | 6 | 4 | 0 | 2 | 66% |
| `python.django.security.audit.custom-expression-as-sql.custom-expression-as-sql` | 3 | 2 | 0 | 1 | 66% |
| `python.lang.security.audit.formatted-sql-query.formatted-sql-query` | 3 | 1 | 0 | 2 | 33% |
| `python.sqlalchemy.security.sqlalchemy-execute-raw-query.sqlalchemy-execute-raw-query` | 7 | 2 | 0 | 5 | 28% |
| `python.lang.security.audit.non-literal-import.non-literal-import` | 10 | 2 | 0 | 8 | 20% |
| `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape` | 77 | 0 | 0 | 77 | 0% |
| `python.django.security.audit.xss.template-translate-as-no-escape.template-translate-as-no-escape` | 9 | 0 | 0 | 9 | 0% |
| `go.lang.security.audit.xss.no-interpolation-in-tag.no-interpolation-in-tag` | 2 | 0 | 0 | 2 | 0% |
| `python.django.security.django-no-csrf-token.django-no-csrf-token` | 2 | 0 | 0 | 2 | 0% |
| `html.security.audit.missing-integrity.missing-integrity` | 1 | 0 | 0 | 1 | 0% |
| `javascript.lang.security.audit.detect-non-literal-regexp.detect-non-literal-regexp` | 1 | 0 | 0 | 1 | 0% |
| `python.django.security.audit.xss.template-autoescape-off.template-autoescape-off` | 1 | 0 | 0 | 1 | 0% |
| `python.django.security.injection.tainted-url-host.tainted-url-host` | 1 | 0 | 0 | 1 | 0% |

---

_Triaged with [sg-triage](https://github.com/Gaurav-4567/semgrep-triage) v0.1.0, prompt v0.1.0._

_Semgrep had 59 parse errors during the scan (not counted as findings)._