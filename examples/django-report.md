# sg-triage report

_Generated 2026-05-03 12:07 UTC_

## Summary

| Metric | Value |
|---|---|
| Total findings | 143 |
| Likely true positive | 0 |
| Needs human review | 129 |
| False positive | 14 |
| Estimated cost | ~$0.915 |
| Tokens (in / out) | 194356 / 22124 |
| Duration | 77.2s |
| Cache | 31 hits, 19 misses (62% hit rate) |
| Model | `claude-sonnet-4-5` |
| Prompt version | `0.1.0` |

## Findings

### 1. ⚠️ Needs human review — `python.sqlalchemy.security.sqlalchemy-execute-raw-query.sqlalchemy-execute-raw-query`

**File:** `django/contrib/gis/db/backends/mysql/introspection.py:17`  

**Severity:** ERROR  **Confidence:** low — CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

> ⚠️ LLM originally returned `false_positive` — downgraded due to verification failure.

**Reasoning:** The Semgrep rule flagged string formatting used to construct a SQL query. The sink is `cursor.execute("DESCRIBE %s" % self.connection.ops.quote_name(table_name))` where `table_name` is interpolated. However, the input passes through `self.connection.ops.quote_name()` before being inserted into the query string. The `quote_name()` function is a Django database backend operation specifically designed to safely quote database identifiers (table names, column names) to prevent SQL injection. This is the standard Django pattern for safely incorporating dynamic table names into raw SQL queries. The function is part of Django's internal framework code (in `django/contrib/gis/db/backends/mysql/introspection.py`), and Django's `quote_name()` properly escapes identifiers according to the database backend's requirements. This is not user input being directly concatenated; it's a table name being properly quoted by Django's framework-provided sanitization function.

**Evidence from the code:**

```
cursor.execute("DESCRIBE %s" % self.connection.ops.quote_name(table_name))
```

**Verifier notes:**

- ⚠️ Reasoning references `identifiers` but this token does not appear in the code or context shown to the LLM.

**Suggested action:** Verify that Django's quote_name() implementation for MySQL properly escapes table identifiers, but this is standard Django framework behavior for safe identifier quoting.

### 2. ⚠️ Needs human review — `python.sqlalchemy.security.sqlalchemy-execute-raw-query.sqlalchemy-execute-raw-query`

**File:** `django/contrib/gis/db/backends/oracle/schema.py:72`  

**Severity:** ERROR  **Confidence:** medium — CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

**Reasoning:** The finding flags string interpolation into a SQL query using the `%` operator. The data being interpolated is `model._meta.db_table` passed through `self.geo_quote_name()`. The `geo_quote_name` function delegates to `self.connection.ops.geo_quote_name(name)`, which appears to be a quoting/escaping function based on its name. However, I cannot see the implementation of this function to verify it properly sanitizes the table name. The `model._meta.db_table` comes from Django's ORM metadata, which is typically defined in model classes and not directly user-controlled. However, without seeing: (1) the definition of `sql_clear_geometry_table_metadata` to understand the full query structure, (2) the implementation of `geo_quote_name` to verify it provides adequate SQL injection protection, and (3) whether `model._meta.db_table` could ever be influenced by user input in this context, I cannot definitively determine if this is exploitable or safely mitigated.

**Missing context:**

- Definition of sql_clear_geometry_table_metadata to see the full SQL query structure

- Implementation of connection.ops.geo_quote_name() to verify it provides SQL injection protection

- Whether model._meta.db_table can be influenced by user input in any code path leading to delete_model

**Verifier notes:**

- ⚠️ Reasoning references `and` but this token does not appear in the code or context shown to the LLM.

**Suggested action:** Verify that geo_quote_name() properly quotes/escapes Oracle identifiers and that model._meta.db_table cannot be influenced by user input.

### 3. ⚠️ Needs human review — `python.sqlalchemy.security.sqlalchemy-execute-raw-query.sqlalchemy-execute-raw-query`

**File:** `django/contrib/gis/db/backends/oracle/schema.py:85`  

**Severity:** ERROR  **Confidence:** medium — CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

**Reasoning:** The code uses string interpolation (%) to construct a SQL query from `self.sql_clear_geometry_field_metadata` with table and column names. The values are passed through `self.geo_quote_name()`, which calls `self.connection.ops.geo_quote_name(name)`. The critical question is whether `geo_quote_name` properly sanitizes/quotes identifiers to prevent SQL injection. The input originates from `model._meta.db_table` and `field.column`, which are Django ORM metadata fields. While these are typically controlled by the application's model definitions rather than direct user input, they could potentially be influenced by dynamic model creation or other indirect paths. The `geo_quote_name` function appears to be a quoting mechanism (suggested by its name), which would make this safe if it properly escapes SQL identifiers. However, I cannot see the implementation of `connection.ops.geo_quote_name()` to verify it actually performs proper SQL identifier quoting. Additionally, I cannot see the definition of `sql_clear_geometry_field_metadata` to understand what SQL template is being used.

**Missing context:**

- Implementation of connection.ops.geo_quote_name() to verify it properly quotes/escapes SQL identifiers

- Definition of self.sql_clear_geometry_field_metadata to see the SQL template being used

- Whether model._meta.db_table and field.column can be influenced by untrusted input in Django's architecture

**Verifier notes:**

- ⚠️ Reasoning references `interpolation` but this token does not appear in the code or context shown to the LLM.

**Suggested action:** Verify that connection.ops.geo_quote_name() properly quotes SQL identifiers (e.g., wraps in quotes and escapes special characters) and confirm that model metadata fields cannot be influenced by user input in the application's usage of Django ORM.

### 4. ⚠️ Needs human review — `python.sqlalchemy.security.sqlalchemy-execute-raw-query.sqlalchemy-execute-raw-query`

**File:** `django/contrib/gis/db/backends/postgis/operations.py:341`  

**Severity:** ERROR  **Confidence:** medium — CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

**Reasoning:** The finding flags string formatting into a SQL query at line 341: `cursor.execute("SELECT %s()" % func)`. The dangerous operation is executing a SQL query with string interpolation. The `func` parameter flows into the SQL string without parameterization. To determine if this is exploitable, I need to trace where `func` originates. The function `_get_postgis_func` is a helper that takes `func` as a parameter, but I cannot see any callers of this function in the provided context. The function name and docstring suggest it's for "calling PostGIS functions," which implies `func` should be a function name like "PostGIS_Version" or similar. If `func` comes from hardcoded constants or internal configuration, this would be a false positive. However, if `func` can be influenced by user input (e.g., passed from a request parameter or derived from user-controlled data), this would be a SQL injection vulnerability. Without visibility into the callers, I cannot determine whether `func` is attacker-controlled or safe.

**Missing context:**

- callers of _get_postgis_func function

- origin and validation of the func parameter

- whether func is derived from user input or hardcoded constants

**Suggested action:** Review all callers of _get_postgis_func to verify that the func parameter is never derived from user input and only contains hardcoded PostGIS function names.

### 5. ⚠️ Needs human review — `python.sqlalchemy.security.sqlalchemy-execute-raw-query.sqlalchemy-execute-raw-query`

**File:** `django/contrib/gis/db/backends/spatialite/operations.py:161`  

**Severity:** ERROR  **Confidence:** medium — CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

**Reasoning:** The finding flags string formatting into a SQL query at line 161: `cursor.execute("SELECT %s" % func)`. The `func` parameter comes from the caller of `_get_spatialite_func()`. Without seeing the callers, I cannot determine whether `func` contains attacker-controlled data or is constructed from hardcoded/safe values. The docstring states "Any error occurring in this method should be handled by the caller," suggesting this is a low-level utility function. The file path indicates this is Django framework code (django/contrib/gis/db/backends/spatialite/operations.py), which typically handles database operations carefully, but the string formatting pattern is still dangerous if `func` can be influenced by user input. The method name `_get_spatialite_func` (with leading underscore) suggests it's internal/private, but that doesn't eliminate the possibility of tainted data flow from public APIs.

**Missing context:**

- Callers of _get_spatialite_func to determine the origin and construction of the 'func' parameter

- Whether func is ever derived from user input or is always hardcoded/validated

- The broader context of how this SpatiaLite operations class is used within Django's GIS backend

**Suggested action:** Review all callers of _get_spatialite_func to verify that the func parameter is never derived from user input and is always constructed from trusted sources or properly validated.

### 6. ⚠️ Needs human review — `python.sqlalchemy.security.sqlalchemy-execute-raw-query.sqlalchemy-execute-raw-query`

**File:** `django/contrib/gis/db/backends/spatialite/schema.py:69`  

**Severity:** ERROR  **Confidence:** low — CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

> ⚠️ LLM originally returned `false_positive` — downgraded due to verification failure.

**Reasoning:** This finding flags string formatting into a SQL query, but the data being interpolated is not attacker-controlled. The `model._meta.db_table` and `field.column` values come from Django's ORM metadata, which represents the database schema definition at the application level, not user input. Critically, both values are passed through `self.quote_name()` before interpolation (lines 72-73), which is Django's standard identifier quoting function that escapes SQL identifiers to prevent injection. This is Django framework code (in `django/contrib/gis/db/backends/spatialite/schema.py`) for schema manipulation operations, where table and column names come from the model definition, not from HTTP requests or other untrusted sources. The pattern Semgrep matched is string formatting, but the context shows this is safe identifier quoting in framework-internal schema operations.

**Evidence from the code:**

```
self.quote_name(model._meta.db_table)
```

```
self.quote_name(field.column)
```

**Verifier notes:**

- ⚠️ Reasoning references `interpolation` but this token does not appear in the code or context shown to the LLM.

**Suggested action:** No action needed; this is Django framework code using proper identifier quoting for schema operations with model metadata.

### 7. ⚠️ Needs human review — `python.sqlalchemy.security.sqlalchemy-execute-raw-query.sqlalchemy-execute-raw-query`

**File:** `django/contrib/gis/db/backends/spatialite/schema.py:76`  

**Severity:** ERROR  **Confidence:** medium — CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

**Reasoning:** The finding flags SQL string formatting at lines 76-82 where `self.sql_drop_spatial_index` is formatted with `model._meta.db_table` and `field.column`. The concern is whether these values are attacker-controlled. In Django's ORM, `model._meta.db_table` and `field.column` are typically schema metadata defined at model definition time, not user input. However, the critical issue is that at line 79-80, the values are NOT passed through `self.quote_name()` (unlike lines 72-73 in the same function where `quote_name()` is used). This inconsistency suggests either: (1) a real vulnerability where unquoted identifiers could be exploited if an attacker can influence model/field names, or (2) the `sql_drop_spatial_index` template already includes proper quoting. Without seeing the definition of `sql_drop_spatial_index`, `execute()`, or understanding whether Django model metadata can ever be influenced by untrusted input in this context, I cannot definitively rule out exploitation.

**Evidence from the code:**

```
"table": model._meta.db_table,
```

```
"column": field.column,
```

**Missing context:**

- Definition of self.sql_drop_spatial_index to verify if it includes identifier quoting

- Definition of execute() to understand if it provides any SQL injection protection

- Whether model._meta.db_table and field.column can ever be influenced by untrusted input in Django's architecture

- Why quote_name() is used at lines 72-73 but not at lines 79-80

**Suggested action:** Review why identifier quoting is inconsistent within this function and verify that sql_drop_spatial_index template properly quotes identifiers, or refactor to use quote_name() consistently.

### 8. ⚠️ Needs human review — `go.lang.security.audit.xss.no-interpolation-in-tag.no-interpolation-in-tag`

**File:** `django/forms/jinja2/django/forms/label.html:1`  

**Severity:** WARNING  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; django/forms/jinja2/django/forms/label.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 9. ⚠️ Needs human review — `go.lang.security.audit.xss.no-interpolation-in-tag.no-interpolation-in-tag`

**File:** `django/forms/templates/django/forms/label.html:1`  

**Severity:** WARNING  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; django/forms/templates/django/forms/label.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 10. ⚠️ Needs human review — `html.security.audit.missing-integrity.missing-integrity`

**File:** `js_tests/tests.html:159`  

**Severity:** WARNING  **Confidence:** low — CWE-353: Missing Support for Integrity Check

**Reasoning:** v0.1 supports Python files only; js_tests/tests.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 11. ⚠️ Needs human review — `javascript.lang.security.audit.detect-non-literal-regexp.detect-non-literal-regexp`

**File:** `django/contrib/admin/static/admin/js/inlines.js:26`  

**Severity:** WARNING  **Confidence:** low — CWE-1333: Inefficient Regular Expression Complexity

**Reasoning:** v0.1 supports Python files only; django/contrib/admin/static/admin/js/inlines.js requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 12. ⚠️ Needs human review — `python.django.security.audit.avoid-mark-safe.avoid-mark-safe`

**File:** `django/contrib/admin/helpers.py:161`  

**Severity:** WARNING  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') _(from cache)_

> ⚠️ LLM originally returned `false_positive` — downgraded due to verification failure.

**Reasoning:** The finding flags `mark_safe()` wrapping the output of `self.form[f].errors.as_ul()`. The key question is whether `as_ul()` returns already-escaped HTML or raw user input. This code is in Django's core admin helpers (`django/contrib/admin/helpers.py`), and `as_ul()` is a method on Django's form error objects (`ErrorList`). Django's `ErrorList.as_ul()` method is a framework-provided function that returns HTML-escaped error messages wrapped in `<ul>` tags. The framework already escapes user input within `as_ul()`, so the output is safe HTML that needs `mark_safe()` to prevent double-escaping. This is a standard Django pattern where framework methods that generate HTML fragments return strings that must be marked safe for template rendering.

**Evidence from the code:**

```
self.form[f].errors.as_ul()
```

**Verifier notes:**

- ⚠️ Reasoning references `ErrorList` but this token does not appear in the code or context shown to the LLM.

- ⚠️ Reasoning references `objects` but this token does not appear in the code or context shown to the LLM.

**Suggested action:** No action needed. This is Django framework code using the standard pattern for form error rendering where as_ul() already escapes content.

### 13. ⚠️ Needs human review — `python.django.security.audit.avoid-mark-safe.avoid-mark-safe`

**File:** `django/contrib/admin/helpers.py:200`  

**Severity:** WARNING  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') _(from cache)_

> ⚠️ LLM originally returned `false_positive` — downgraded due to verification failure.

**Reasoning:** The finding flags `mark_safe()` being called on `self.field.errors.as_ul()`. The key question is whether `as_ul()` returns already-escaped HTML or user-controlled content. This code is in Django's own admin helpers module (django/contrib/admin/helpers.py), which is part of Django's core framework. The `self.field.errors` is a Django form ErrorList object, and `as_ul()` is a Django framework method that generates HTML error lists. Django's ErrorList.as_ul() method is documented to return properly escaped HTML - it escapes field error messages before wrapping them in `<ul>` tags. The use of `mark_safe()` here is intentional and correct: Django's error rendering methods already perform escaping internally, and `mark_safe()` is used to prevent double-escaping of the HTML structure tags. This is a standard Django pattern where framework-generated HTML is marked safe after internal escaping has occurred.

**Evidence from the code:**

```
return mark_safe(self.field.errors.as_ul())
```

**Verifier notes:**

- ⚠️ Reasoning references `module` but this token does not appear in the code or context shown to the LLM.

- ⚠️ Reasoning references `ErrorList` but this token does not appear in the code or context shown to the LLM.

**Suggested action:** No action needed - this is Django framework code using the standard pattern for rendering pre-escaped error messages.

### 14. ⚠️ Needs human review — `python.django.security.audit.avoid-mark-safe.avoid-mark-safe`

**File:** `django/contrib/admin/options.py:384`  

**Severity:** WARNING  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') _(from cache)_

> ⚠️ LLM originally returned `false_positive` — downgraded due to verification failure.

**Reasoning:** The finding flags `mark_safe(self.empty_value_display)` in Django's admin options. The `empty_value_display` attribute is a configuration value set by administrators to control how empty/null values are displayed in the admin interface. This is not user-controlled input - it's a framework configuration parameter set by developers/admins who control the Django application itself. The value comes from either `self.empty_value_display` or falls back to `self.admin_site.empty_value_display`, both of which are internal configuration attributes. There is no dataflow from untrusted user input to this sink. The use of `mark_safe` here is intentional to allow administrators to use HTML in their empty value display strings (e.g., an em-dash or styled placeholder), which is a legitimate framework feature.

**Evidence from the code:**

```
return mark_safe(self.empty_value_display)
```

```
return mark_safe(self.admin_site.empty_value_display)
```

**Verifier notes:**

- ⚠️ Reasoning references `strings` but this token does not appear in the code or context shown to the LLM.

**Suggested action:** No action needed - this is Django framework code using mark_safe on admin configuration values, not user input.

### 15. ⚠️ Needs human review — `python.django.security.audit.avoid-mark-safe.avoid-mark-safe`

**File:** `django/contrib/admin/options.py:386`  

**Severity:** WARNING  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') _(from cache)_

> ⚠️ LLM originally returned `false_positive` — downgraded due to verification failure.

**Reasoning:** The finding flags `mark_safe()` being called on `self.admin_site.empty_value_display`. This is a configuration value set by the Django admin framework itself, not user-controlled input. The `empty_value_display` attribute is a Django admin configuration option that administrators set to control how empty/null values are displayed in the admin interface (typically something like "-" or "N/A"). This is framework-controlled configuration data, not attacker-supplied input. The value flows from Django's AdminSite configuration, which is set by developers in their admin configuration code, not from HTTP requests or user input. There is no dataflow path from untrusted input to this sink.

**Evidence from the code:**

```
return mark_safe(self.admin_site.empty_value_display)
```

**Verifier notes:**

- ⚠️ Reasoning references `interface` but this token does not appear in the code or context shown to the LLM.

**Suggested action:** No action needed. This is framework configuration data, not user input.

### 16. ⚠️ Needs human review — `python.django.security.audit.avoid-mark-safe.avoid-mark-safe`

**File:** `django/contrib/admin/templatetags/admin_list.py:308`  

**Severity:** WARNING  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') _(from cache)_

> ⚠️ LLM originally returned `false_positive` — downgraded due to verification failure.

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

**Verifier notes:**

- ⚠️ Reasoning references `BoundField` but this token does not appear in the code or context shown to the LLM.

- ⚠️ Reasoning references `ErrorList` but this token does not appear in the code or context shown to the LLM.

**Suggested action:** No action needed - this is Django's standard pattern for rendering form fields in admin changeform lists where the framework handles escaping.

### 17. ⚠️ Needs human review — `python.django.security.audit.avoid-mark-safe.avoid-mark-safe`

**File:** `django/contrib/admin/templatetags/admin_list.py:339`  

**Severity:** WARNING  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') _(from cache)_

> ⚠️ LLM originally returned `false_positive` — downgraded due to verification failure.

**Reasoning:** The finding flags `mark_safe()` being called on `form[cl.model._meta.pk.name]`, which is a Django form field. In Django's form system, when you access a form field using bracket notation (e.g., `form['fieldname']`), you get a BoundField object. When a BoundField is rendered (converted to string), Django's form framework already handles HTML escaping appropriately based on the field type and widget. For hidden fields specifically (checked by `is_hidden` on line 338), the BoundField's `__str__` method returns the widget's rendered output, which is already properly escaped by Django's widget rendering system. The `mark_safe()` here is used to preserve the already-safe HTML output from Django's form rendering, not to bypass escaping of user input. This is a standard Django pattern for rendering form fields in templates and admin interfaces.

**Evidence from the code:**

```
if form[cl.model._meta.pk.name].is_hidden:
```

```
yield mark_safe(form[cl.model._meta.pk.name])
```

**Verifier notes:**

- ⚠️ Reasoning references `__str__` but this token does not appear in the code or context shown to the LLM.

- ⚠️ Reasoning references `notation` but this token does not appear in the code or context shown to the LLM.

- ⚠️ Reasoning references `rendered` but this token does not appear in the code or context shown to the LLM.

- ⚠️ Reasoning references `specifically` but this token does not appear in the code or context shown to the LLM.

- ⚠️ Reasoning references `BoundField` but this token does not appear in the code or context shown to the LLM.

**Suggested action:** No action needed. This is Django framework code using mark_safe on form field output that is already escaped by Django's form rendering system.

### 18. ⚠️ Needs human review — `python.django.security.audit.avoid-mark-safe.avoid-mark-safe`

**File:** `django/contrib/admindocs/utils.py:268`  

**Severity:** WARNING  **Confidence:** medium — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') _(from cache)_

**Reasoning:** The function `strip_p_tags` calls `mark_safe()` on the result of string replacement operations that remove `<p>` and `</p>` tags. The critical question is whether `value` is already safe/escaped content or whether it contains untrusted user input. The function name and operation suggest it's designed to strip paragraph tags from already-safe HTML (likely from Django's own HTML generation or documentation processing), but I cannot see the callers or the origin of `value`. If `value` comes from user input that hasn't been escaped, this would be a clear XSS vulnerability. If `value` is already escaped or comes from trusted sources (like Django's own docstring processing in admindocs), this would be safe. The file path `django/contrib/admindocs/utils.py` suggests this is part of Django's admin documentation system, which typically processes Python docstrings rather than user input, but I cannot verify the actual data flow without seeing the callers.

**Missing context:**

- Callers of strip_p_tags function to determine the source of the 'value' parameter

- Whether 'value' is already escaped/safe content or contains untrusted user input

- The broader context of how admindocs processes and displays content

**Verifier notes:**

- ⚠️ Reasoning references `sources` but this token does not appear in the code or context shown to the LLM.

**Suggested action:** Review all callers of strip_p_tags to verify that the 'value' parameter is already escaped or comes from trusted sources only (e.g., Python docstrings, not user-supplied content).

### 19. ⚠️ Needs human review — `python.django.security.audit.avoid-mark-safe.avoid-mark-safe`

**File:** `django/contrib/flatpages/views.py:67`  

**Severity:** WARNING  **Confidence:** medium — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') _(from cache)_

**Reasoning:** The code marks `f.title` as safe using `mark_safe()`, where `f` is a FlatPage model instance passed as a parameter. The comment on lines 64-66 explicitly states this is done to avoid requiring the "|safe" filter in templates because "they are raw HTML content in the first place." The key question is whether `f.title` contains attacker-controlled data or is only editable by trusted administrators. In Django's flatpages app, FlatPage objects are typically created and edited through the Django admin interface, which requires staff/superuser permissions. However, I cannot verify from the code shown: (1) whether there are other code paths that allow untrusted users to create or modify FlatPage titles, (2) what the actual access controls are on FlatPage model modifications, or (3) whether the flatpages app configuration allows user-generated content. If FlatPage titles can only be set by trusted administrators through the admin interface, this would be a false positive. If untrusted users can influence the title field through any code path, this is a stored XSS vulnerability.

**Missing context:**

- Definition and access controls for the FlatPage model

- All code paths that can create or modify FlatPage.title

- Whether flatpages are only editable by staff/superuser through Django admin or if there are user-facing forms

- Application configuration for the flatpages app

**Suggested action:** Verify that FlatPage titles can only be modified by trusted administrators through the Django admin interface and that no code paths allow untrusted user input into the title field.

### 20. ⚠️ Needs human review — `python.django.security.audit.avoid-mark-safe.avoid-mark-safe`

**File:** `django/contrib/flatpages/views.py:68`  

**Severity:** WARNING  **Confidence:** medium — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** The code marks `f.content` as safe for HTML output using `mark_safe()`, where `f` is a FlatPage object passed into the function. The comment on lines 64-66 explicitly states this is done to avoid requiring the "|safe" filter in templates because "they are raw HTML content in the first place." The critical question is: where does `f.content` originate and who controls it? The FlatPage model is imported from `django.contrib.flatpages.models`, suggesting this is Django's built-in flatpages app where content is typically stored in the database and managed through the admin interface. If `f.content` is administrator-controlled content from the database (not end-user input), this would be an intentional design decision allowing admins to include HTML. However, if there's any path where untrusted users can influence `f.content`, this becomes an XSS vulnerability. Without seeing the FlatPage model definition, how `f` is populated before being passed to this function, and what access controls exist on content creation, I cannot determine whether this is attacker-controllable input.

**Missing context:**

- Definition of the FlatPage model and its content field

- How the FlatPage object 'f' is populated before being passed to render_flatpage

- Access controls on who can create or modify FlatPage content

- Whether FlatPage content can be influenced by non-admin users

**Verifier notes:**

- ⚠️ Reasoning references `database` but this token does not appear in the code or context shown to the LLM.

**Suggested action:** Verify that FlatPage content can only be created/modified by trusted administrators through Django admin, not by end users. If untrusted users can influence content, this is an XSS vulnerability.

### 21. ⚠️ Needs human review — `python.django.security.audit.custom-expression-as-sql.custom-expression-as-sql`

**File:** `django/contrib/gis/db/backends/spatialite/operations.py:21`  

**Severity:** WARNING  **Confidence:** low — CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

> ⚠️ LLM originally returned `false_positive` — downgraded due to verification failure.

**Reasoning:** The Semgrep rule flagged a call to `super().as_sql(...)` in Django's internal GIS backend code. This is a false positive because: (1) This is Django framework code itself (in `django/contrib/gis/db/backends/spatialite/operations.py`), not application code that handles user input. (2) The `as_sql` method is part of Django's ORM query compilation infrastructure, where `super().as_sql()` delegates to the parent class's implementation that properly handles SQL generation with parameterization. (3) The parameters passed (`connection, lookup, template_params, sql_params`) are internal ORM objects, not raw user input. (4) The result is properly parameterized SQL with separate params tuple, and the string formatting `"%s > 0" % sql` only modifies the SQL template structure, not the parameters themselves which remain safely separated in the `params` tuple.

**Evidence from the code:**

```
sql, params = super().as_sql(connection, lookup, template_params, sql_params)
```

```
return "%s > 0" % sql, params
```

**Verifier notes:**

- ⚠️ Reasoning references `itself` but this token does not appear in the code or context shown to the LLM.

**Suggested action:** No action needed; this is Django framework code that properly handles SQL parameterization through the ORM's query compilation layer.

### 22. ⚠️ Needs human review — `python.django.security.audit.unvalidated-password.unvalidated-password`

**File:** `django/contrib/auth/__init__.py:410`  

**Severity:** WARNING  **Confidence:** low — CWE-521: Weak Password Requirements _(from cache)_

> ⚠️ LLM originally returned `false_positive` — downgraded due to verification failure.

**Reasoning:** The flagged line is in `acheck_password_with_timing_attack_mitigation`, which is a timing-attack mitigation function. When `user is None`, the code creates a dummy user instance and calls `set_password(password)` on it. This is not actually setting a password on a real user account - it's performing a dummy operation to ensure constant-time behavior regardless of whether the user exists. The password is being hashed to consume the same amount of time as the `else` branch where `user.acheck_password(password)` is called. This is a standard timing-attack mitigation pattern where you perform the same expensive operation (password hashing) whether or not the user exists, so attackers cannot enumerate valid usernames by measuring response times. The dummy user instance is never saved to the database, so no actual password is being set without validation.

**Evidence from the code:**

```
async def acheck_password_with_timing_attack_mitigation(user, password):
```

```
"""See check_user_with_timing_attack_mitigation."""
```

```
if user is None:
```

```
get_user_model()().set_password(password)
```

**Verifier notes:**

- ⚠️ Reasoning references `operation` but this token does not appear in the code or context shown to the LLM.

**Suggested action:** No action needed - this is a timing-attack mitigation pattern, not an actual password-setting operation.

### 23. ⚠️ Needs human review — `python.django.security.audit.unvalidated-password.unvalidated-password`

**File:** `django/contrib/auth/base_user.py:104`  

**Severity:** WARNING  **Confidence:** medium — CWE-521: Weak Password Requirements _(from cache)_

**Reasoning:** The finding flags a call to `self.set_password(raw_password)` without prior validation. The `setter` function receives `raw_password` and directly calls `set_password`, which hashes the password via `make_password(raw_password)`. The `save` method afterward calls `password_validation.password_changed()`, but this is a post-change notification hook, not pre-validation. The Semgrep rule expects `validate_password()` to be called before setting the password. However, this code is in Django's own `base_user.py` — part of the framework itself. The `setter` function appears to be a closure or callback, likely used internally by Django's authentication system (possibly for password hash upgrades based on the comment "Password hash upgrades shouldn't be considered password changes"). Without seeing the caller of this `setter` function and understanding the context in which it's invoked, I cannot determine whether validation is expected to happen at this layer or is handled by higher-level code (e.g., form validation, view logic).

**Missing context:**

- The caller of the `setter` function to understand when and how it's invoked

- Whether this is part of Django's internal password hash upgrade mechanism where validation may not be required

- Whether validation is expected to occur at a higher layer (forms, views) before this internal setter is called

**Verifier notes:**

- ⚠️ Reasoning references `system` but this token does not appear in the code or context shown to the LLM.

**Suggested action:** Verify whether this `setter` function is part of Django's internal password hash upgrade mechanism (where validation may not apply) or if it's a user-facing code path that should validate passwords before setting them.

### 24. ⚠️ Needs human review — `python.django.security.audit.unvalidated-password.unvalidated-password`

**File:** `django/contrib/auth/forms.py:132`  

**Severity:** WARNING  **Confidence:** medium — CWE-521: Weak Password Requirements

**Reasoning:** The finding flags `user.set_password(self.cleaned_data[password_field_name])` in the `set_password_and_save` helper function within Django's auth forms. The Semgrep rule expects password validation to occur before setting the password. The code shows that `password_validation` is imported from `django.contrib.auth`, but I cannot see whether validation is performed elsewhere in the form lifecycle. In Django forms, validation typically occurs in `clean()` or `clean_<fieldname>()` methods before `cleaned_data` is populated. The `set_password_and_save` function is called from a `save()` method at line 248, which suggests this is part of a form's save flow where validation may have already occurred. However, I cannot see the full form class definition, its `clean()` methods, or where password validation might be invoked. The file path indicates this is Django's own auth forms code, not application code, which suggests it may be framework-provided functionality that handles validation appropriately in the broader form context.

**Missing context:**

- The full form class definition containing set_password_and_save to see if clean() or clean_password1() methods call password_validation.validate_password()

- Whether this is a UserCreationForm or SetPasswordForm where Django's standard validation patterns apply

- Any custom validation logic in the form that might call password_validation functions before cleaned_data is accessed

**Suggested action:** Review the complete form class to verify whether password validation is performed in clean() or clean_password1() methods before set_password_and_save is called, as is standard in Django form patterns.

### 25. ⚠️ Needs human review — `python.django.security.audit.xss.filter-with-is-safe.filter-with-is-safe`

**File:** `django/contrib/admin/templatetags/admin_filters.py:18`  

**Severity:** WARNING  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') _(from cache)_

> ⚠️ LLM originally returned `false_positive` — downgraded due to verification failure.

**Reasoning:** This is a Django template filter that constructs HTML list elements. The Semgrep rule flags the use of `is_safe=True` on line 18. However, examining the dataflow shows proper escaping is applied: (1) The filter declares `needs_autoescape=True`, which means Django will escape the input before passing it to the filter. (2) On lines 35-40, the code explicitly applies `conditional_escape` to each item when autoescape is enabled. (3) On line 61, user-provided content (`item`) is escaped via `escaper(item)` before being inserted into the HTML. (4) The only unescaped content added is hardcoded HTML structure (`<ul>`, `<li>`, etc.) and a translated message from `ngettext` (lines 71-76) which is a Django translation function that returns safe strings. The filter correctly uses `mark_safe()` only on the final output after all user content has been escaped, which is the proper pattern for filters that generate HTML structure.

**Evidence from the code:**

```
@register.filter(is_safe=True, needs_autoescape=True)
```

```
if autoescape:
        escaper = conditional_escape
```

```
output.append("%s<li>%s%s</li>" % (indent, escaper(item), sublist))
```

**Verifier notes:**

- ⚠️ Reasoning references `structure` but this token does not appear in the code or context shown to the LLM.

**Suggested action:** No action needed. The filter properly escapes user input via conditional_escape before inserting into HTML, and only marks the final structured output as safe.

### 26. ⚠️ Needs human review — `python.django.security.audit.xss.template-autoescape-off.template-autoescape-off`

**File:** `django/contrib/admin/templates/registration/password_reset_email.html:1`  

**Severity:** WARNING  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; django/contrib/admin/templates/registration/password_reset_email.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 27. ⚠️ Needs human review — `python.django.security.django-no-csrf-token.django-no-csrf-token`

**File:** `django/contrib/admin/templates/admin/login.html:47`  

**Severity:** WARNING  **Confidence:** low — CWE-352: Cross-Site Request Forgery (CSRF)

**Reasoning:** v0.1 supports Python files only; django/contrib/admin/templates/admin/login.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 28. ⚠️ Needs human review — `python.django.security.django-no-csrf-token.django-no-csrf-token`

**File:** `django/contrib/admin/templates/registration/password_reset_form.html:17`  

**Severity:** WARNING  **Confidence:** low — CWE-352: Cross-Site Request Forgery (CSRF)

**Reasoning:** v0.1 supports Python files only; django/contrib/admin/templates/registration/password_reset_form.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 29. ⚠️ Needs human review — `python.django.security.injection.tainted-url-host.tainted-url-host`

**File:** `django/contrib/contenttypes/views.py:86`  

**Severity:** WARNING  **Confidence:** medium — CWE-918: Server-Side Request Forgery (SSRF)

**Reasoning:** The finding flags line 86 where `object_domain` is used to construct a URL. Tracing the dataflow: `object_domain` is initially set from `get_current_site(request).domain` (line 47), which derives from the request object. The code then attempts to override `object_domain` by looking up Site objects from the database through many-to-many or foreign key relationships on the content object (lines 55-80). The concern is whether `object_domain` can be attacker-controlled. The `get_current_site` function returns a Site object whose domain comes from the database (when sites framework is installed) or a RequestSite based on the request. If the domain comes from database Site objects, it's likely safe. However, if it falls back to RequestSite, the domain could be derived from the HTTP Host header, which is attacker-controlled. The code path and whether RequestSite uses request.get_host() (which reads the Host header) cannot be fully determined from the provided context. Additionally, the Site lookups from the database (lines 58-80) could potentially be influenced if an attacker can manipulate the related Site objects, though this seems less likely.

**Missing context:**

- Definition and implementation of RequestSite class to determine if it uses request.get_host() or another attacker-controllable source

- Whether the Site.objects.get_current(request) method uses request.get_host() or validates the domain

- Whether attackers can influence the Site objects stored in the database that are looked up in lines 55-80

**Verifier notes:**

- ⚠️ Reasoning references `database` but this token does not appear in the code or context shown to the LLM.

- ⚠️ Reasoning references `get_host` but this token does not appear in the code or context shown to the LLM.

- ⚠️ Reasoning references `request.get_host` but this token does not appear in the code or context shown to the LLM.

**Suggested action:** Review whether get_current_site can return attacker-controlled domain values (especially via RequestSite fallback using Host header), and verify that Site objects from the database are trustworthy sources for redirect domains.

### 30. ⚠️ Needs human review — `python.lang.security.audit.formatted-sql-query.formatted-sql-query`

**File:** `django/contrib/gis/db/backends/mysql/introspection.py:17`  

**Severity:** WARNING  **Confidence:** low — CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

> ⚠️ LLM originally returned `false_positive` — downgraded due to verification failure.

**Reasoning:** The Semgrep rule flagged string formatting in a SQL query, but this is a false positive because the table name is properly quoted using Django's `quote_name()` method. The code constructs a DESCRIBE statement with `"DESCRIBE %s" % self.connection.ops.quote_name(table_name)`. Django's `quote_name()` is specifically designed to safely quote database identifiers (table names, column names) to prevent SQL injection by escaping special characters and wrapping them in appropriate delimiters for the database backend. This is the correct pattern for dynamically constructing SQL with table names in Django, as table names cannot be parameterized using bind variables in SQL. The DESCRIBE command is a MySQL introspection operation that requires the table name as an identifier, not a string literal, so parameterization is not applicable here.

**Evidence from the code:**

```
cursor.execute("DESCRIBE %s" % self.connection.ops.quote_name(table_name))
```

**Verifier notes:**

- ⚠️ Reasoning references `identifiers` but this token does not appear in the code or context shown to the LLM.

**Suggested action:** No action needed; Django's quote_name() properly escapes the table identifier.

### 31. ⚠️ Needs human review — `python.lang.security.audit.formatted-sql-query.formatted-sql-query`

**File:** `django/contrib/gis/db/backends/postgis/operations.py:341`  

**Severity:** WARNING  **Confidence:** medium — CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

**Reasoning:** The finding flags string formatting into a SQL query at line 341: `cursor.execute("SELECT %s()" % func)`. The dangerous sink is the `cursor.execute()` call with a formatted string. The `func` parameter is passed into `_get_postgis_func()` but its origin is not visible in the provided context. If `func` comes from user input or any attacker-controlled source, this would be a SQL injection vulnerability since the value is interpolated directly into the query string rather than using parameterized queries. However, I cannot see the callers of `_get_postgis_func()` to determine whether `func` is hardcoded (e.g., a constant like "PostGIS_Version"), derived from configuration, or potentially influenced by user input. The function appears to be part of Django's PostGIS backend operations, which suggests it may be internal infrastructure code that only receives hardcoded function names, but without seeing the call sites, I cannot confirm this assumption.

**Missing context:**

- callers of _get_postgis_func() to determine the source of the 'func' parameter

- whether 'func' is ever derived from user input or is always a hardcoded constant

**Verifier notes:**

- ⚠️ Reasoning references `hardcoded` but this token does not appear in the code or context shown to the LLM.

**Suggested action:** Review all call sites of _get_postgis_func() to verify that the 'func' parameter is always a hardcoded constant or otherwise not attacker-controlled.

### 32. ⚠️ Needs human review — `python.lang.security.audit.formatted-sql-query.formatted-sql-query`

**File:** `django/contrib/gis/db/backends/spatialite/operations.py:161`  

**Severity:** WARNING  **Confidence:** medium — CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

**Reasoning:** The finding flags string formatting into a SQL query at line 161: `cursor.execute("SELECT %s" % func)`. The dangerous operation is executing a SQL query with string interpolation. The `func` parameter comes from the caller of `_get_spatialite_func()`, but we cannot see any callers in the provided context. The docstring states "Any error occurring in this method should be handled by the caller," suggesting this is a utility function called from elsewhere. Without seeing the callers, we cannot determine whether `func` contains attacker-controlled data or is constructed from hardcoded/safe values. The file path indicates this is Django framework code (spatialite database backend operations), which typically constructs SQL function calls programmatically rather than from user input, but we need to verify the actual call sites to confirm `func` is not influenced by untrusted input.

**Missing context:**

- Callers of _get_spatialite_func() to determine the origin and construction of the 'func' parameter

- Whether 'func' is ever derived from user input or is always constructed from hardcoded database function names

**Suggested action:** Review all call sites of _get_spatialite_func() to verify that the 'func' parameter is never influenced by user input and is only constructed from trusted, hardcoded database function names.

### 33. ⚠️ Needs human review — `python.lang.security.audit.md5-used-as-password.md5-used-as-password`

**File:** `django/contrib/auth/hashers.py:669`  

**Severity:** WARNING  **Confidence:** low — CWE-327: Use of a Broken or Risky Cryptographic Algorithm _(from cache)_

> ⚠️ LLM originally returned `false_positive` — downgraded due to verification failure.

**Reasoning:** This finding is in Django's core authentication framework (django/contrib/auth/hashers.py). The `encode` method is part of a password hasher class that implements Django's password hashing interface. The method returns a formatted string with the algorithm name embedded: `"%s$%s$%s" % (self.algorithm, salt, hash)`. This pattern is characteristic of Django's legacy password hasher implementations that exist for backward compatibility with old password hashes stored in databases. Django maintains these legacy hashers (MD5PasswordHasher, UnsaltedMD5PasswordHasher, etc.) to verify existing passwords during migration, not for creating new password hashes. The framework's default configuration uses strong hashers like PBKDF2 or Argon2. This is framework code that handles the security concern appropriately at the configuration level - the presence of MD5 as an option doesn't mean it's being used for new passwords.

**Evidence from the code:**

```
hash = hashlib.md5((salt + password).encode()).hexdigest()
```

```
return "%s$%s$%s" % (self.algorithm, salt, hash)
```

**Verifier notes:**

- ⚠️ Reasoning references `framework` but this token does not appear in the code or context shown to the LLM.

- ⚠️ Reasoning references `MD5PasswordHasher` but this token does not appear in the code or context shown to the LLM.

- ⚠️ Reasoning references `UnsaltedMD5PasswordHasher` but this token does not appear in the code or context shown to the LLM.

**Suggested action:** Verify that MD5PasswordHasher is not configured as the default password hasher in Django settings and is only used for legacy password verification.

### 34. ⚠️ Needs human review — `python.lang.security.audit.non-literal-import.non-literal-import`

**File:** `django/apps/config.py:111`  

**Severity:** WARNING  **Confidence:** medium — CWE-706: Use of Incorrectly-Resolved Name or Reference _(from cache)_

**Reasoning:** The `create` method calls `import_module(entry)` at line 111, where `entry` is a parameter to the factory method. The docstring states this factory "creates an app config from an entry in INSTALLED_APPS." In Django, INSTALLED_APPS is a configuration setting typically defined in settings.py by the application developer, not by end users. However, I cannot verify from the code shown whether `entry` originates from a trusted configuration file or could be influenced by untrusted user input at runtime. The method performs validation after the import (checking if it's a subclass of AppConfig, raising ImproperlyConfigured), but this happens after the potentially dangerous import_module call. If `entry` comes from Django's INSTALLED_APPS setting (which is typically developer-controlled configuration), this would be a false positive. If `entry` could be influenced by user input or comes from an untrusted source, this would be a true positive allowing arbitrary code execution.

**Missing context:**

- Callers of the create() method to determine the source of the 'entry' parameter

- Whether 'entry' originates from Django's INSTALLED_APPS configuration setting or from user-controllable input

- The threat model for Django configuration - whether INSTALLED_APPS is considered trusted developer configuration or could be influenced by attackers

**Suggested action:** Verify that the 'entry' parameter only comes from Django's INSTALLED_APPS configuration setting (developer-controlled) and cannot be influenced by user input at runtime. If it's configuration-only, this is a false positive; if user-controllable, implement a whitelist.

### 35. ⚠️ Needs human review — `python.lang.security.audit.non-literal-import.non-literal-import`

**File:** `django/apps/config.py:123`  

**Severity:** WARNING  **Confidence:** medium — CWE-706: Use of Incorrectly-Resolved Name or Reference _(from cache)_

**Reasoning:** The flagged line 123 performs `import_module(mod_path)` where `mod_path` is constructed as `"%s.%s" % (entry, APPS_MODULE_NAME)` on line 122. The `entry` parameter comes from the `create(cls, entry)` function signature and is described in comments as coming from INSTALLED_APPS. Django's INSTALLED_APPS is a configuration setting typically defined in settings.py by the application developer, not by end users. However, I cannot verify from the code shown whether INSTALLED_APPS can be influenced by untrusted user input at runtime. The function performs validation after import (checking for AppConfig subclass on line 197), but this happens after the potentially dangerous import. If INSTALLED_APPS is strictly configuration-controlled and not influenced by request parameters or user input, this would be a false positive. If there's any path where user input can influence what gets passed to `create()`, this would be a true positive allowing arbitrary code execution through module loading.

**Missing context:**

- How the create() method is called and whether the 'entry' parameter can be influenced by user input

- Definition and source of INSTALLED_APPS configuration

- Whether there are any code paths where user-controlled data flows into the create() method

**Suggested action:** Verify that the 'entry' parameter to create() comes exclusively from the INSTALLED_APPS configuration setting and cannot be influenced by user input at runtime. If INSTALLED_APPS is strictly developer-controlled configuration, this is a false positive.

### 36. ⚠️ Needs human review — `python.lang.security.audit.non-literal-import.non-literal-import`

**File:** `django/apps/config.py:123`  

**Severity:** WARNING  **Confidence:** medium — CWE-706: Use of Incorrectly-Resolved Name or Reference _(from cache)_

**Reasoning:** The flagged line 123 performs `import_module(mod_path)` where `mod_path` is constructed as `"%s.%s" % (entry, APPS_MODULE_NAME)` on line 122. The `entry` parameter comes from the `create(cls, entry)` function signature and is described in comments as coming from INSTALLED_APPS. Django's INSTALLED_APPS is a configuration setting typically defined in settings.py by the application developer, not by end users. However, I cannot verify from the code shown whether INSTALLED_APPS can be influenced by untrusted user input at runtime. The function performs validation after import (checking for AppConfig subclass on line 197), but this happens after the potentially dangerous import. If INSTALLED_APPS is strictly configuration-controlled and not influenced by request parameters or user input, this would be a false positive. If there's any path where user input can influence what gets passed to `create()`, this would be a true positive allowing arbitrary code execution through module loading.

**Missing context:**

- How the create() method is called and whether the 'entry' parameter can be influenced by user input

- Definition and source of INSTALLED_APPS configuration

- Whether there are any code paths where user-controlled data flows into the create() method

**Suggested action:** Verify that the 'entry' parameter to create() comes exclusively from the INSTALLED_APPS configuration setting and cannot be influenced by user input at runtime. If INSTALLED_APPS is strictly developer-controlled configuration, this is a false positive.

### 37. ⚠️ Needs human review — `python.lang.security.audit.non-literal-import.non-literal-import`

**File:** `django/apps/config.py:193`  

**Severity:** WARNING  **Confidence:** medium — CWE-706: Use of Incorrectly-Resolved Name or Reference _(from cache)_

**Reasoning:** The finding flags `import_module(entry)` at line 193 in Django's app configuration factory method. The `entry` parameter comes from the `create(cls, entry)` method signature and is documented as coming from INSTALLED_APPS. The code path at line 193 is reached when both `import_module(entry)` and `import_string(entry)` have failed earlier (lines 111 and 162), and the code is re-triggering the module import to generate a proper error message. While INSTALLED_APPS is typically controlled by developers in settings.py (not end-user input), I cannot verify from the code shown: (1) whether `create()` is ever called with user-controlled data in any code path, (2) what the complete call chain to this method looks like, or (3) whether Django's architecture ensures INSTALLED_APPS entries are always developer-controlled. The function is a factory method that could potentially be invoked programmatically. Without seeing the callers of `create()`, I cannot definitively rule out a scenario where attacker-controlled input reaches this import.

**Missing context:**

- Callers of the create() method to determine if entry can ever be influenced by user input

- Django's INSTALLED_APPS configuration mechanism and whether it can be dynamically modified by untrusted sources

- Whether this AppConfig.create() method is ever invoked with runtime user input rather than just settings.py configuration

**Verifier notes:**

- ⚠️ Reasoning references `earlier` but this token does not appear in the code or context shown to the LLM.

**Suggested action:** Review all callers of AppConfig.create() to verify that the entry parameter always originates from developer-controlled configuration (settings.py INSTALLED_APPS) and is never derived from user input or external data sources.

### 38. ⚠️ Needs human review — `python.lang.security.audit.non-literal-import.non-literal-import`

**File:** `django/apps/config.py:210`  

**Severity:** WARNING  **Confidence:** low — CWE-706: Use of Incorrectly-Resolved Name or Reference _(from cache)_

> ⚠️ LLM originally returned `false_positive` — downgraded due to verification failure.

**Reasoning:** This finding is in Django's core application configuration system. The `create` method is a factory that processes entries from Django's `INSTALLED_APPS` setting. The `app_name` variable at line 210 comes from `app_config_class.name` (line 204), which is an attribute of an AppConfig subclass that has already been validated (line 197 checks `issubclass(app_config_class, AppConfig)`). The AppConfig.name attribute is defined by the application developer in their Django app configuration, not by end-user input. This is framework configuration code that processes trusted developer-defined settings from the Django project's settings.py file, not untrusted user input from HTTP requests or other external sources. The INSTALLED_APPS setting is part of the Django project's configuration and is controlled by the developers who deploy the application, not by end users.

**Evidence from the code:**

```
app_name = app_config_class.name
```

```
if not issubclass(app_config_class, AppConfig):
```

```
app_module = import_module(app_name)
```

**Verifier notes:**

- ⚠️ Reasoning references `validated` but this token does not appear in the code or context shown to the LLM.

**Suggested action:** Mark as false positive. This is Django framework code that imports modules based on developer-controlled configuration, not user input.

### 39. ⚠️ Needs human review — `python.lang.security.audit.non-literal-import.non-literal-import`

**File:** `django/apps/config.py:269`  

**Severity:** WARNING  **Confidence:** low — CWE-706: Use of Incorrectly-Resolved Name or Reference _(from cache)_

> ⚠️ LLM originally returned `false_positive` — downgraded due to verification failure.

**Reasoning:** The finding flags `import_module(models_module_name)` as potentially loading untrusted user input. However, examining the dataflow shows `models_module_name` is constructed on line 268 as `"%s.%s" % (self.name, MODELS_MODULE_NAME)`. The value `self.name` is an attribute of the AppConfig class in Django's core framework, which represents the Python module path of a registered Django application. This is set during Django's application initialization from the INSTALLED_APPS setting, which is defined in settings.py by developers, not by end users. MODELS_MODULE_NAME is a constant (likely "models"). The module name being imported is derived from the application's own module structure, not from HTTP request parameters, form data, or any other attacker-controlled source. This is Django framework code that imports models modules from registered Django apps during application startup.

**Evidence from the code:**

```
models_module_name = "%s.%s" % (self.name, MODELS_MODULE_NAME)
```

```
self.models_module = import_module(models_module_name)
```

**Verifier notes:**

- ⚠️ Reasoning references `constant` but this token does not appear in the code or context shown to the LLM.

**Suggested action:** No action needed. This is Django framework code importing models from registered applications using configuration-derived paths, not user input.

### 40. ⚠️ Needs human review — `python.lang.security.audit.non-literal-import.non-literal-import`

**File:** `django/conf/__init__.py:177`  

**Severity:** WARNING  **Confidence:** medium — CWE-706: Use of Incorrectly-Resolved Name or Reference _(from cache)_

**Reasoning:** The finding flags `importlib.import_module(self.SETTINGS_MODULE)` at line 177. The `settings_module` parameter is passed to the `__init__` constructor at line 167 and stored as `self.SETTINGS_MODULE` at line 175. The code then dynamically imports this module. The critical question is whether `settings_module` originates from user-controlled input or is a trusted configuration value set by the application developer. In Django's architecture, `SETTINGS_MODULE` is typically set via the `DJANGO_SETTINGS_MODULE` environment variable or programmatically during application startup, and is intended to point to the developer's settings file (e.g., 'myproject.settings'). However, I cannot see from this code snippet alone where the `settings_module` parameter originates - whether it comes from a trusted source (application code, deployment configuration) or could be influenced by untrusted input (HTTP parameters, user-supplied data). The file path `django/conf/__init__.py` suggests this is Django framework code itself, which would typically be called during application initialization with trusted values, but without seeing the callers of this `__init__` method, I cannot definitively rule out a path where untrusted input reaches this parameter.

**Missing context:**

- Callers of this __init__ method to determine the source of the settings_module parameter

- Whether settings_module can be influenced by user input or is strictly from trusted configuration

- The class definition containing this __init__ method to understand its usage context

**Verifier notes:**

- ⚠️ Reasoning references `DJANGO_SETTINGS_MODULE` but this token does not appear in the code or context shown to the LLM.

- ⚠️ Reasoning references `source` but this token does not appear in the code or context shown to the LLM.

**Suggested action:** Review how this class is instantiated throughout the Django codebase to verify that settings_module always comes from trusted developer configuration (environment variables, deployment config) and cannot be influenced by HTTP requests or other untrusted user input.

### 41. ⚠️ Needs human review — `python.lang.security.audit.non-literal-import.non-literal-import`

**File:** `django/contrib/admindocs/views.py:180`  

**Severity:** WARNING  **Confidence:** medium — CWE-706: Use of Incorrectly-Resolved Name or Reference _(from cache)_

**Reasoning:** The finding flags `import_module(mod)` at line 180 where `mod` is derived from `get_mod_func(view)` at line 176. The `view` parameter comes from the function argument to `_get_view_func(view)`. The critical question is whether `view` originates from user input or from trusted Django URL configuration. The code checks `get_resolver(urlconf)._is_callback(view)` before proceeding, suggesting this is validating that `view` is a registered callback in the URL configuration. In Django's admindocs context, this function likely processes view names from the URL resolver to generate documentation. If `view` comes from the URL configuration (which is developer-controlled code), this would be a false positive. However, if `view` can be influenced by URL parameters or other user input passed to the calling context, this could be exploitable. The file path `django/contrib/admindocs/views.py` suggests this is part of Django's admin documentation feature, which is typically restricted to staff members, but that doesn't neutralize code injection vulnerabilities.

**Missing context:**

- The calling context of `_get_view_func(view)` to determine the source of the `view` parameter

- Definition of `get_mod_func()` to understand how it parses the view string

- Whether the `view` parameter originates from URL configuration (trusted) or from request parameters (untrusted)

- The `_is_callback()` validation logic to assess if it provides sufficient protection

**Verifier notes:**

- ⚠️ Reasoning references `configuration` but this token does not appear in the code or context shown to the LLM.

**Suggested action:** Trace back the callers of `_get_view_func()` to determine if the `view` parameter can be influenced by user input, or if it only comes from Django's URL configuration which is developer-controlled.

### 42. ⚠️ Needs human review — `python.lang.security.audit.non-literal-import.non-literal-import`

**File:** `django/contrib/admindocs/views.py:187`  

**Severity:** WARNING  **Confidence:** medium — CWE-706: Use of Incorrectly-Resolved Name or Reference _(from cache)_

**Reasoning:** The finding flags `import_module(mod)` at line 187 where `mod` is derived from `get_mod_func(view)` at line 176, and then `get_mod_func(mod)` again at line 186. The `view` parameter originates from the function signature but its source is not visible in the provided context. The function `_get_view_func` appears to be parsing view strings from Django's URL configuration to dynamically import and return the corresponding view function. While this is a common Django pattern for introspection (especially in admindocs), the security depends on: (1) whether `view` comes from trusted configuration (URLconf) or untrusted user input, and (2) whether `get_mod_func` performs any validation or sanitization. The file path `django/contrib/admindocs/views.py` suggests this is Django framework code for admin documentation, which typically operates on configured views rather than arbitrary user input. However, without seeing the caller of `_get_view_func`, the definition of `get_mod_func`, or how `view` is sourced, I cannot definitively determine if this is exploitable or a false positive based on trusted configuration data.

**Missing context:**

- Callers of _get_view_func to determine the source of the 'view' parameter

- Definition of get_mod_func to see if it validates or sanitizes the module path

- Definition of get_resolver and _is_callback to understand what validation occurs before import_module

- Whether admindocs views are restricted to staff/superuser access

**Verifier notes:**

- ⚠️ Reasoning references `introspection` but this token does not appear in the code or context shown to the LLM.

- ⚠️ Reasoning references `configuration` but this token does not appear in the code or context shown to the LLM.

**Suggested action:** Verify that the 'view' parameter comes from Django's URLconf (trusted configuration) rather than user-controllable input, and confirm that admindocs access is properly restricted to trusted users.

### 43. ⚠️ Needs human review — `python.lang.security.audit.non-literal-import.non-literal-import`

**File:** `django/contrib/auth/hashers.py:231`  

**Severity:** WARNING  **Confidence:** medium — CWE-706: Use of Incorrectly-Resolved Name or Reference _(from cache)_

**Reasoning:** The finding flags `importlib.import_module(mod_path)` where `mod_path` is derived from `self.library`. The dataflow shows that if `self.library` is a tuple/list, `mod_path` is the second element; otherwise it's `self.library` itself. The critical question is: where does `self.library` originate? This is a method on what appears to be a password hasher class in Django's auth system. If `self.library` is set by class attributes defined in code (e.g., hardcoded in hasher subclasses), this would be a false positive. However, if `self.library` can be influenced by user input or configuration that accepts arbitrary strings, this could allow arbitrary module loading. The context shows this is in `django/contrib/auth/hashers.py`, which is Django framework code for password hashing. Typically, Django hasher classes define `library` as a class attribute pointing to specific crypto libraries (e.g., 'bcrypt', 'argon2'). However, I cannot see the class definition, how `self.library` is set, or whether it could be influenced by settings or user input.

**Missing context:**

- The class definition containing this method to see how self.library is initialized

- Whether self.library can be set from Django settings or user-controlled configuration

- Call sites of _load_library() to understand when and how it's invoked

- Other hasher class definitions that might set self.library

**Verifier notes:**

- ⚠️ Reasoning references `libraries` but this token does not appear in the code or context shown to the LLM.

**Suggested action:** Review how self.library is set in hasher classes - if it's only hardcoded class attributes in framework code, mark as false positive; if it can be influenced by settings or user input, this is a true positive requiring a whitelist.

### 44. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `django/contrib/admin/templates/admin/actions.html:16`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; django/contrib/admin/templates/admin/actions.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 45. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `django/contrib/admin/templates/admin/auth/user/change_password.html:30`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; django/contrib/admin/templates/admin/auth/user/change_password.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 46. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `django/contrib/admin/templates/admin/auth/user/change_password.html:34`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; django/contrib/admin/templates/admin/auth/user/change_password.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 47. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `django/contrib/admin/templates/admin/auth/user/change_password.html:36`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; django/contrib/admin/templates/admin/auth/user/change_password.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 48. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `django/contrib/admin/templates/admin/change_form.html:22`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; django/contrib/admin/templates/admin/change_form.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 49. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `django/contrib/admin/templates/admin/change_form.html:46`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; django/contrib/admin/templates/admin/change_form.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 50. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `django/contrib/admin/templates/admin/change_list.html:54`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; django/contrib/admin/templates/admin/change_list.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 51. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `django/contrib/admin/templates/admin/change_list_object_tools.html:8`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; django/contrib/admin/templates/admin/change_list_object_tools.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 52. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `django/contrib/admin/templates/admin/change_list_results.html:17`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; django/contrib/admin/templates/admin/change_list_results.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 53. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `django/contrib/admin/templates/admin/date_hierarchy.html:4`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; django/contrib/admin/templates/admin/date_hierarchy.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 54. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `django/contrib/admin/templates/admin/delete_confirmation.html:25`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; django/contrib/admin/templates/admin/delete_confirmation.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 55. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `django/contrib/admin/templates/admin/delete_confirmation.html:30`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; django/contrib/admin/templates/admin/delete_confirmation.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 56. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `django/contrib/admin/templates/admin/delete_confirmation.html:35`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; django/contrib/admin/templates/admin/delete_confirmation.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 57. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `django/contrib/admin/templates/admin/delete_selected_confirmation.html:23`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; django/contrib/admin/templates/admin/delete_selected_confirmation.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 58. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `django/contrib/admin/templates/admin/delete_selected_confirmation.html:26`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; django/contrib/admin/templates/admin/delete_selected_confirmation.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 59. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `django/contrib/admin/templates/admin/delete_selected_confirmation.html:29`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; django/contrib/admin/templates/admin/delete_selected_confirmation.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 60. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `django/contrib/admin/templates/admin/filter.html:4`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; django/contrib/admin/templates/admin/filter.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 61. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `django/contrib/admin/templates/admin/login.html:24`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; django/contrib/admin/templates/admin/login.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 62. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `django/contrib/admin/templates/admin/login.html:40`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; django/contrib/admin/templates/admin/login.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 63. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `django/contrib/admin/templates/admin/object_history.html:38`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; django/contrib/admin/templates/admin/object_history.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 64. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `django/contrib/admin/templates/admin/object_history.html:52`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; django/contrib/admin/templates/admin/object_history.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 65. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `django/contrib/admin/templates/admin/pagination.html:4`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; django/contrib/admin/templates/admin/pagination.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 66. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `django/contrib/admin/templates/admin/search_form.html:4`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; django/contrib/admin/templates/admin/search_form.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 67. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `django/contrib/admin/templates/admin/search_form.html:11`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; django/contrib/admin/templates/admin/search_form.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 68. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `django/contrib/admin/templates/admin/search_form.html:11`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; django/contrib/admin/templates/admin/search_form.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 69. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `django/contrib/admin/templates/admin/widgets/related_widget_wrapper.html:11`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; django/contrib/admin/templates/admin/widgets/related_widget_wrapper.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 70. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `django/contrib/admin/templates/admin/widgets/related_widget_wrapper.html:19`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; django/contrib/admin/templates/admin/widgets/related_widget_wrapper.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 71. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `django/contrib/admin/templates/admin/widgets/related_widget_wrapper.html:27`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; django/contrib/admin/templates/admin/widgets/related_widget_wrapper.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 72. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `django/contrib/admin/templates/admin/widgets/related_widget_wrapper.html:34`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; django/contrib/admin/templates/admin/widgets/related_widget_wrapper.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 73. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `django/contrib/admin/templates/registration/password_change_form.html:27`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; django/contrib/admin/templates/registration/password_change_form.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 74. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `django/contrib/admin/templates/registration/password_reset_email.html:2`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; django/contrib/admin/templates/registration/password_reset_email.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 75. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `django/contrib/admin/templates/registration/password_reset_email.html:12`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; django/contrib/admin/templates/registration/password_reset_email.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 76. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `django/contrib/admindocs/templates/admin_doc/bookmarklets.html:15`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; django/contrib/admindocs/templates/admin_doc/bookmarklets.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 77. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `django/contrib/admindocs/templates/admin_doc/missing_docutils.html:17`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; django/contrib/admindocs/templates/admin_doc/missing_docutils.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 78. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `django/contrib/admindocs/templates/admin_doc/missing_docutils.html:19`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; django/contrib/admindocs/templates/admin_doc/missing_docutils.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 79. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `django/contrib/admindocs/templates/admin_doc/model_detail.html:21`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; django/contrib/admindocs/templates/admin_doc/model_detail.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 80. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `django/contrib/admindocs/templates/admin_doc/template_detail.html:13`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; django/contrib/admindocs/templates/admin_doc/template_detail.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 81. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `django/contrib/admindocs/templates/admin_doc/template_detail.html:16`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; django/contrib/admindocs/templates/admin_doc/template_detail.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 82. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `django/contrib/admindocs/templates/admin_doc/template_detail.html:19`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; django/contrib/admindocs/templates/admin_doc/template_detail.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 83. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `django/contrib/admindocs/templates/admin_doc/template_filter_index.html:23`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; django/contrib/admindocs/templates/admin_doc/template_filter_index.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 84. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `django/contrib/admindocs/templates/admin_doc/template_tag_index.html:23`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; django/contrib/admindocs/templates/admin_doc/template_tag_index.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 85. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `django/contrib/admindocs/templates/admin_doc/view_detail.html:12`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; django/contrib/admindocs/templates/admin_doc/view_detail.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 86. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `django/contrib/admindocs/templates/admin_doc/view_index.html:40`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; django/contrib/admindocs/templates/admin_doc/view_index.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 87. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `django/contrib/admindocs/templates/admin_doc/view_index.html:42`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; django/contrib/admindocs/templates/admin_doc/view_index.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 88. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `django/contrib/admindocs/templates/admin_doc/view_index.html:49`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; django/contrib/admindocs/templates/admin_doc/view_index.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 89. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `django/contrib/auth/templates/registration/password_reset_subject.txt:2`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; django/contrib/auth/templates/registration/password_reset_subject.txt requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 90. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `django/views/templates/default_urlconf.html:199`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; django/views/templates/default_urlconf.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 91. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `django/views/templates/default_urlconf.html:201`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; django/views/templates/default_urlconf.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 92. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `django/views/templates/directory_index.html:9`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; django/views/templates/directory_index.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 93. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `django/views/templates/directory_index.html:12`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; django/views/templates/directory_index.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 94. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `docs/ref/templates/builtins.txt:958`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; docs/ref/templates/builtins.txt requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 95. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `docs/ref/templates/builtins.txt:1597`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; docs/ref/templates/builtins.txt requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 96. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `docs/releases/1.4.txt:394`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; docs/releases/1.4.txt requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 97. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `docs/releases/1.7.txt:684`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; docs/releases/1.7.txt requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 98. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `docs/releases/1.7.txt:687`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; docs/releases/1.7.txt requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 99. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `docs/releases/4.2.txt:428`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; docs/releases/4.2.txt requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 100. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `docs/topics/i18n/translation.txt:619`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; docs/topics/i18n/translation.txt requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 101. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `docs/topics/i18n/translation.txt:642`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; docs/topics/i18n/translation.txt requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 102. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `docs/topics/i18n/translation.txt:669`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; docs/topics/i18n/translation.txt requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 103. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `docs/topics/i18n/translation.txt:677`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; docs/topics/i18n/translation.txt requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 104. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `docs/topics/i18n/translation.txt:681`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; docs/topics/i18n/translation.txt requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 105. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `docs/topics/i18n/translation.txt:689`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; docs/topics/i18n/translation.txt requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 106. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `docs/topics/i18n/translation.txt:694`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; docs/topics/i18n/translation.txt requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 107. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `docs/topics/i18n/translation.txt:710`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; docs/topics/i18n/translation.txt requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 108. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `docs/topics/i18n/translation.txt:717`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; docs/topics/i18n/translation.txt requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 109. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `docs/topics/i18n/translation.txt:727`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; docs/topics/i18n/translation.txt requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 110. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `docs/topics/i18n/translation.txt:745`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; docs/topics/i18n/translation.txt requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 111. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `docs/topics/i18n/translation.txt:754`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; docs/topics/i18n/translation.txt requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 112. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `docs/topics/i18n/translation.txt:762`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; docs/topics/i18n/translation.txt requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 113. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `docs/topics/i18n/translation.txt:767`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; docs/topics/i18n/translation.txt requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 114. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `docs/topics/i18n/translation.txt:769`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; docs/topics/i18n/translation.txt requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 115. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `docs/topics/i18n/translation.txt:771`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; docs/topics/i18n/translation.txt requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 116. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `docs/topics/i18n/translation.txt:774`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; docs/topics/i18n/translation.txt requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 117. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `docs/topics/i18n/translation.txt:778`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; docs/topics/i18n/translation.txt requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 118. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `docs/topics/i18n/translation.txt:782`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; docs/topics/i18n/translation.txt requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 119. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `docs/topics/i18n/translation.txt:827`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; docs/topics/i18n/translation.txt requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 120. ⚠️ Needs human review — `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape`

**File:** `docs/topics/i18n/translation.txt:839`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; docs/topics/i18n/translation.txt requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 121. ⚠️ Needs human review — `python.django.security.audit.xss.template-translate-as-no-escape.template-translate-as-no-escape`

**File:** `django/contrib/admin/templates/admin/actions.html:8`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; django/contrib/admin/templates/admin/actions.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 122. ⚠️ Needs human review — `python.django.security.audit.xss.template-translate-as-no-escape.template-translate-as-no-escape`

**File:** `django/contrib/admin/templates/registration/password_change_form.html:4`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; django/contrib/admin/templates/registration/password_change_form.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 123. ⚠️ Needs human review — `python.django.security.audit.xss.template-translate-as-no-escape.template-translate-as-no-escape`

**File:** `django/contrib/admindocs/templates/admin_doc/missing_docutils.html:14`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; django/contrib/admindocs/templates/admin_doc/missing_docutils.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 124. ⚠️ Needs human review — `python.django.security.audit.xss.template-translate-as-no-escape.template-translate-as-no-escape`

**File:** `django/contrib/admindocs/templates/admin_doc/view_index.html:16`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; django/contrib/admindocs/templates/admin_doc/view_index.html requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 125. ⚠️ Needs human review — `python.django.security.audit.xss.template-translate-as-no-escape.template-translate-as-no-escape`

**File:** `docs/ref/templates/language.txt:446`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; docs/ref/templates/language.txt requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 126. ⚠️ Needs human review — `python.django.security.audit.xss.template-translate-as-no-escape.template-translate-as-no-escape`

**File:** `docs/topics/i18n/translation.txt:626`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; docs/topics/i18n/translation.txt requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 127. ⚠️ Needs human review — `python.django.security.audit.xss.template-translate-as-no-escape.template-translate-as-no-escape`

**File:** `docs/topics/i18n/translation.txt:638`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; docs/topics/i18n/translation.txt requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 128. ⚠️ Needs human review — `python.django.security.audit.xss.template-translate-as-no-escape.template-translate-as-no-escape`

**File:** `docs/topics/i18n/translation.txt:639`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; docs/topics/i18n/translation.txt requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 129. ⚠️ Needs human review — `python.django.security.audit.xss.template-translate-as-no-escape.template-translate-as-no-escape`

**File:** `docs/topics/i18n/translation.txt:884`  

**Severity:** INFO  **Confidence:** low — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** v0.1 supports Python files only; docs/topics/i18n/translation.txt requires manual review.

**Missing context:**

- Verdict synthesized; LLM was not called.

**Suggested action:** Review manually. Multi-language support is planned for v0.2.

### 130. ✅ False positive — `python.django.security.audit.avoid-mark-safe.avoid-mark-safe`

**File:** `django/contrib/admin/helpers.py:193`  

**Severity:** WARNING  **Confidence:** high — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') _(from cache)_

**Reasoning:** The finding flags `mark_safe()` on line 193, but examining the dataflow shows this is safe. On line 180, `contents` is assigned the result of `conditional_escape(self.field.label)`. The `conditional_escape` function (shown in the context) explicitly escapes text unless it's already marked safe (has `__html__` method). The escaped string is then passed to `mark_safe()` on line 193. This is a standard Django pattern: escape untrusted content first, then mark it safe so it can be passed to a function that expects SafeString. The `mark_safe()` call here is applied to already-escaped content, not raw user input, so there is no XSS risk.

**Evidence from the code:**

```
contents = conditional_escape(self.field.label)
```

```
contents=mark_safe(contents)
```

**FP categories:** `false_pattern_match`

**Suggested action:** No action needed. The content is escaped via conditional_escape before being marked safe, which is the correct pattern for building HTML in Django.

### 131. ✅ False positive — `python.django.security.audit.avoid-mark-safe.avoid-mark-safe`

**File:** `django/contrib/admin/templatetags/admin_filters.py:79`  

**Severity:** WARNING  **Confidence:** high — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') _(from cache)_

**Reasoning:** This is a Django template tag function that constructs HTML from user-provided data. The key question is whether the data is properly escaped before being marked safe. Looking at the dataflow: (1) The function accepts a `value` parameter and an `autoescape` parameter (default True). (2) When autoescape is True (the default), an `escaper` is set to `conditional_escape` which is Django's HTML escaping function. (3) In `list_formatter`, each item is escaped via `escaper(item)` before being inserted into the HTML at line 61. (4) The `remaining_objects_message` uses `ngettext` which returns a translated string with a count substitution - this contains no user input, only a hardcoded message template and a numeric count. (5) Both `rendered_object_list` and `remaining_objects_message` are concatenated and marked safe. Since all user-controlled data flows through `conditional_escape` before being incorporated into the HTML, and the remaining message is just a translation string with a count, the use of `mark_safe` here is appropriate - the content has already been escaped.

**Evidence from the code:**

```
if autoescape:
        escaper = conditional_escape
```

```
if should_display_item:
                output.append("%s<li>%s%s</li>" % (indent, escaper(item), sublist))
```

```
remaining_objects_message = "\n\t<li>%s</li>" % (
            ngettext(
                "…and %(count)d more object.",
                "…and %(count)d more objects.",
                remaining_object_count,
            )
            % {"count": remaining_object_count}
        )
```

**FP categories:** `sanitized_input`

**Suggested action:** No action needed - user input is properly escaped via conditional_escape before being marked safe.

### 132. ✅ False positive — `python.django.security.audit.avoid-mark-safe.avoid-mark-safe`

**File:** `django/contrib/admindocs/utils.py:92`  

**Severity:** WARNING  **Confidence:** high — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') _(from cache)_

**Reasoning:** The `parse_rst` function uses docutils to convert reStructuredText to HTML. The function calls `docutils.core.publish_parts()` with a docutils HTML writer instance and strict security settings (`raw_enabled: False`, `file_insertion_enabled: False`). The `parts["fragment"]` returned is HTML generated by the docutils library, which is a trusted HTML generation library that properly escapes content. The input text is processed through docutils' reStructuredText parser, which handles escaping as part of its HTML generation. This is not user input being directly marked safe; it's the output of a trusted HTML generation library. The `mark_safe` call here is appropriate because docutils has already produced safe, escaped HTML.

**Evidence from the code:**

```
overrides = {
        "doctitle_xform": True,
        "initial_header_level": 3,
        "default_reference_context": default_reference_context,
        "link_base": reverse("django-admindocs-docroot").rstrip("/"),
        "raw_enabled": False,
        "file_insertion_enabled": False,
    }
```

```
writer_instance = docutils.writers.get_writer_class("html")()
```

```
parts = docutils.core.publish_parts(
        source % text,
        source_path=thing_being_parsed,
        destination_path=None,
        writer=writer_instance,
        settings_overrides=overrides,
    )
```

**FP categories:** `framework_handled`

**Suggested action:** No action needed. The HTML is generated by the docutils library with appropriate security settings, not from unsanitized user input.

### 133. ✅ False positive — `python.django.security.audit.custom-expression-as-sql.custom-expression-as-sql`

**File:** `django/contrib/gis/db/backends/oracle/operations.py:55`  

**Severity:** WARNING  **Confidence:** high — CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

**Reasoning:** This finding is in Django's own GIS backend implementation for Oracle database operations. The code is calling `super().as_sql()` within an `as_sql` method override, which is a standard pattern in Django's ORM for building SQL queries. The file path `django/contrib/gis/db/backends/oracle/operations.py` indicates this is part of Django's core framework code, not application code. The method is manipulating `template_params` (a dictionary for template placeholders) and `sql_params` (parameters that will be safely bound), which is the correct way Django's ORM handles parameterized queries. The `super().as_sql()` call delegates to the parent class's implementation (likely `BaseSpatialOperations` or `DatabaseOperations` based on imports), which will handle proper SQL parameterization. This is framework-internal code that implements Django's query compilation layer, not user-facing code that accepts untrusted input directly.

**Evidence from the code:**

```
return super().as_sql(connection, lookup, template_params, sql_params[:-1])
```

```
from django.contrib.gis.db.backends.base.operations import BaseSpatialOperations
```

```
from django.db.backends.oracle.operations import DatabaseOperations
```

**FP categories:** `third_party`, `framework_handled`

**Suggested action:** No action needed - this is Django framework code implementing proper parameterized query construction.

### 134. ✅ False positive — `python.django.security.audit.custom-expression-as-sql.custom-expression-as-sql`

**File:** `django/contrib/gis/db/backends/postgis/operations.py:43`  

**Severity:** WARNING  **Confidence:** high — CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

**Reasoning:** This is Django framework code in the PostGIS backend operations module. The `as_sql` method is part of Django's ORM query compilation infrastructure, not application code handling user input. The function receives `template_params` which are already parameterized by Django's ORM layer, and the two helper functions `check_raster` and `check_geography` only modify these template parameters by wrapping them in SQL function calls like `ST_Polygon(%s)` or appending `::geometry` - they do not introduce raw user input. The `%s` placeholders in lines 62-64, 76-78, 85-87, 92-94 are part of template construction that will be parameterized by the parent class's `as_sql` method. This is framework-internal SQL generation code, not a user-input injection point.

**Evidence from the code:**

```
template_params = self.check_raster(lookup, template_params)
```

```
template_params = self.check_geography(lookup, template_params)
```

```
template_params["lhs"] = "ST_Polygon(%s)" % template_params["lhs"]
```

```
template_params["lhs"] += "::geometry"
```

**FP categories:** `framework_handled`, `false_pattern_match`

**Suggested action:** Mark as false positive - this is Django's internal ORM query compilation code where parameterization is handled by the framework's SQL generation layer.

### 135. ✅ False positive — `python.django.security.audit.extends-custom-expression.extends-custom-expression`

**File:** `django/contrib/gis/db/backends/postgis/operations.py:105`  

**Severity:** WARNING  **Confidence:** high — CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

**Reasoning:** The Semgrep rule has flagged the definition of a Django database function class `ST_Polygon` that extends `Func`. This is Django framework code (in `django/contrib/gis/db/backends/postgis/operations.py`) that defines a wrapper for the PostGIS `ST_Polygon` SQL function. The class itself is a type definition that specifies how Django should construct SQL for this database function - it does not directly accept or process user input. The `__init__` method only manipulates the expression's output field type when the expression is a `Value` object, wrapping it with appropriate field metadata. This is standard Django ORM machinery for building parameterized queries. The actual SQL generation and parameterization is handled by Django's query compiler framework, which properly escapes and parameterizes values. This is not user-facing code that processes untrusted input - it's internal framework infrastructure for building safe, parameterized SQL queries.

**Evidence from the code:**

```
class ST_Polygon(Func):
```

```
function = "ST_Polygon"
```

```
if isinstance(expr, Value) and not expr._output_field_or_none:
```

```
self.source_expressions[0] = Value(
                expr.value, output_field=RasterField(srid=expr.value.srid)
            )
```

**FP categories:** `third_party`, `framework_handled`

**Suggested action:** No action needed - this is Django framework code that defines a database function wrapper; SQL injection protection is handled by Django's query parameterization layer.

### 136. ✅ False positive — `python.django.security.audit.unvalidated-password.unvalidated-password`

**File:** `django/contrib/auth/__init__.py:402`  

**Severity:** WARNING  **Confidence:** high — CWE-521: Weak Password Requirements _(from cache)_

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

### 137. ✅ False positive — `python.django.security.audit.unvalidated-password.unvalidated-password`

**File:** `django/contrib/auth/base_user.py:115`  

**Severity:** WARNING  **Confidence:** high — CWE-521: Weak Password Requirements _(from cache)_

**Reasoning:** This finding is in Django's own authentication framework code (django/contrib/auth/base_user.py), not application code. The `setter` function is an internal async helper that wraps `set_password` for password hash upgrades, as indicated by the comment "Password hash upgrades shouldn't be considered password changes." This is framework code that handles password hashing internally. The file imports show `from django.contrib.auth import password_validation`, indicating validation is available elsewhere in the framework. Password validation is the responsibility of application code calling Django's user management APIs (like user creation forms, password change views), not the low-level password hashing primitives. This is third-party framework code that the project doesn't maintain, and the pattern match is on internal framework machinery, not a vulnerability in application logic.

**Evidence from the code:**

```
async def setter(raw_password):
```

```
# Password hash upgrades shouldn't be considered password changes.
```

```
def set_password(self, raw_password):
        self.password = make_password(raw_password)
```

**FP categories:** `third_party`, `framework_handled`

**Suggested action:** No action needed; this is Django framework code where password validation is handled at the application layer, not in the low-level password hashing primitives.

### 138. ✅ False positive — `python.django.security.audit.unvalidated-password.unvalidated-password`

**File:** `django/contrib/auth/management/commands/changepassword.py:79`  

**Severity:** WARNING  **Confidence:** high — CWE-521: Weak Password Requirements

**Reasoning:** The Semgrep rule flags line 79 where `u.set_password(p1)` is called, claiming the password is set without validation. However, examining the dataflow shows that password validation is performed before reaching this line. The code enters a while loop at line 58 with the condition `(p1 != p2 or not password_validated) and count < MAX_TRIES`. Inside the loop, after confirming passwords match, `validate_password(p2, u)` is called at line 67. If validation fails, a ValidationError is caught and the loop continues. Only when validation succeeds does `password_validated = True` get set at line 72, allowing the loop to exit. The loop can only exit successfully (without raising CommandError at lines 75-77) when `password_validated` is True, meaning validation has passed. Therefore, by the time execution reaches line 79, the password has been validated.

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

**Suggested action:** Mark as false positive; password validation is performed in the loop before set_password is called.

### 139. ✅ False positive — `python.django.security.audit.xss.direct-use-of-httpresponse.direct-use-of-httpresponse`

**File:** `django/contrib/flatpages/views.py:70`  

**Severity:** WARNING  **Confidence:** high — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Reasoning:** The Semgrep rule flags the use of HttpResponse with template.render(), but this is a false positive because Django's template engine is being used correctly here. The code calls `template.render({"flatpage": f}, request)` where `template` is obtained from `loader.select_template()` or `loader.get_template()`. Django's template loader returns template objects that automatically escape variables during rendering unless explicitly marked safe. While the code does call `mark_safe()` on f.title and f.content (lines 67-68), the comment on lines 64-66 explicitly states these are "raw HTML content in the first place" from the database, which is the intended behavior of Django's flatpages app - it stores and renders pre-authored HTML content. The pattern HttpResponse(template.render(...)) is the standard Django idiom for rendering templates and does not bypass XSS protections; it's the template rendering itself that provides the escaping.

**Evidence from the code:**

```
return HttpResponse(template.render({"flatpage": f}, request))
```

```
template = loader.select_template((f.template_name, DEFAULT_TEMPLATE))
```

```
template = loader.get_template(DEFAULT_TEMPLATE)
```

```
# To avoid having to always use the "|safe" filter in flatpage templates,
```

```
# mark the title and content as already safe (since they are raw HTML
```

```
# content in the first place).
```

**FP categories:** `false_pattern_match`, `framework_handled`

**Suggested action:** Close as false positive - this is standard Django template rendering with proper framework-provided XSS protection.

### 140. ✅ False positive — `python.django.security.injection.open-redirect.open-redirect`

**File:** `django/contrib/admin/options.py:1505`  

**Severity:** WARNING  **Confidence:** high — CWE-601: URL Redirection to Untrusted Site ('Open Redirect') _(from cache)_

**Reasoning:** The Semgrep rule flagged line 1514 where `redirect_url` is passed to `HttpResponseRedirect()`. However, examining the dataflow shows this is not an open redirect vulnerability. At line 1505, `redirect_url` is initialized to `request.path`, which is the current request path (not user-controlled input from query parameters or POST data). The `request.path` attribute in Django contains the path component of the current URL being processed by the server, which is a server-side value representing where the request was received. While `add_preserved_filters()` is then called to append query string parameters, this function (shown in the called functions) only adds preserved filter parameters that are already validated and scoped to admin changelist filters. The redirect is to the same path the user is already on (the add form), with only admin-internal filter parameters appended. This is not an open redirect because the base URL is not attacker-controlled - it's the current request path, and the function only adds back preserved admin filters, not arbitrary user input.

**Evidence from the code:**

```
redirect_url = request.path
```

**FP categories:** `not_user_input`

**Suggested action:** Mark as false positive; the redirect URL is derived from request.path (current server path) not from attacker-controlled input.

### 141. ✅ False positive — `python.django.security.injection.open-redirect.open-redirect`

**File:** `django/contrib/admin/options.py:1576`  

**Severity:** WARNING  **Confidence:** high — CWE-601: URL Redirection to Untrusted Site ('Open Redirect') _(from cache)_

**Reasoning:** The Semgrep rule flagged line 1585 where `redirect_url` is passed to `HttpResponseRedirect()`. However, examining the dataflow shows that `redirect_url` is initialized from `request.path` (line 1576), which is the current request path controlled by Django's URL routing, not user-supplied data. The `request.path` attribute represents the path component of the URL that was matched by Django's URL resolver to reach this view - it's the server-side path, not arbitrary user input. The `add_preserved_filters()` function then appends query string parameters derived from `preserved_filters` and `preserved_qsl`, which come from `get_preserved_filters()` and `_get_preserved_qsl()`. While these do extract data from `request.GET`, the `add_preserved_filters()` function uses `urlsplit()` and `urlencode()` to safely construct the URL. Most importantly, the redirect is to the same path the user is already on (`request.path`), just with additional query parameters - this is not an open redirect to an arbitrary external site.

**Evidence from the code:**

```
redirect_url = request.path
```

```
redirect_url = add_preserved_filters(
```

**FP categories:** `not_user_input`

**Suggested action:** Mark as false positive. The redirect URL is based on request.path (the current server-side path) with safely encoded query parameters, not arbitrary user-controlled input.

### 142. ✅ False positive — `python.flask.security.xss.audit.direct-use-of-jinja2.direct-use-of-jinja2`

**File:** `django/contrib/admin/templatetags/admin_list.py:521`  

**Severity:** WARNING  **Confidence:** high — CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') _(from cache)_

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

### 143. ✅ False positive — `python.lang.security.audit.logging.logger-credential-leak.python-logger-credential-disclosure`

**File:** `django/contrib/auth/forms.py:419`  

**Severity:** WARNING  **Confidence:** high — CWE-532: Insertion of Sensitive Information into Log File _(from cache)_

**Reasoning:** The Semgrep rule flagged this logger call because it detected the string "password" in the log message. However, examining the actual code shows that the log statement only logs the user's primary key (context["user"].pk), which is a non-sensitive identifier. The log message "Failed to send password reset email to %s" is a static string describing the operation that failed, not logging any actual password or credential. The %s placeholder is filled with context["user"].pk, which is a database ID, not a secret. This is a false pattern match where the rule detected the word "password" in a descriptive message but no actual sensitive data is being logged.

**Evidence from the code:**

```
"Failed to send password reset email to %s", context["user"].pk
```

**FP categories:** `false_pattern_match`

**Suggested action:** Mark as false positive; only a user ID is logged, not any credential or sensitive data.

## Per-rule statistics

| Rule | Total | FP | Likely TP | Review | FP rate |
|---|---:|---:|---:|---:|---:|
| `python.django.security.injection.open-redirect.open-redirect` | 2 | 2 | 0 | 0 | 100% |
| `python.django.security.audit.extends-custom-expression.extends-custom-expression` | 1 | 1 | 0 | 0 | 100% |
| `python.django.security.audit.xss.direct-use-of-httpresponse.direct-use-of-httpresponse` | 1 | 1 | 0 | 0 | 100% |
| `python.flask.security.xss.audit.direct-use-of-jinja2.direct-use-of-jinja2` | 1 | 1 | 0 | 0 | 100% |
| `python.lang.security.audit.logging.logger-credential-leak.python-logger-credential-disclosure` | 1 | 1 | 0 | 0 | 100% |
| `python.django.security.audit.custom-expression-as-sql.custom-expression-as-sql` | 3 | 2 | 0 | 1 | 66% |
| `python.django.security.audit.unvalidated-password.unvalidated-password` | 6 | 3 | 0 | 3 | 50% |
| `python.django.security.audit.avoid-mark-safe.avoid-mark-safe` | 12 | 3 | 0 | 9 | 25% |
| `python.django.security.audit.xss.template-blocktranslate-no-escape.template-blocktranslate-no-escape` | 77 | 0 | 0 | 77 | 0% |
| `python.lang.security.audit.non-literal-import.non-literal-import` | 10 | 0 | 0 | 10 | 0% |
| `python.django.security.audit.xss.template-translate-as-no-escape.template-translate-as-no-escape` | 9 | 0 | 0 | 9 | 0% |
| `python.sqlalchemy.security.sqlalchemy-execute-raw-query.sqlalchemy-execute-raw-query` | 7 | 0 | 0 | 7 | 0% |
| `python.lang.security.audit.formatted-sql-query.formatted-sql-query` | 3 | 0 | 0 | 3 | 0% |
| `go.lang.security.audit.xss.no-interpolation-in-tag.no-interpolation-in-tag` | 2 | 0 | 0 | 2 | 0% |
| `python.django.security.django-no-csrf-token.django-no-csrf-token` | 2 | 0 | 0 | 2 | 0% |
| `html.security.audit.missing-integrity.missing-integrity` | 1 | 0 | 0 | 1 | 0% |
| `javascript.lang.security.audit.detect-non-literal-regexp.detect-non-literal-regexp` | 1 | 0 | 0 | 1 | 0% |
| `python.django.security.audit.xss.filter-with-is-safe.filter-with-is-safe` | 1 | 0 | 0 | 1 | 0% |
| `python.django.security.audit.xss.template-autoescape-off.template-autoescape-off` | 1 | 0 | 0 | 1 | 0% |
| `python.django.security.injection.tainted-url-host.tainted-url-host` | 1 | 0 | 0 | 1 | 0% |
| `python.lang.security.audit.md5-used-as-password.md5-used-as-password` | 1 | 0 | 0 | 1 | 0% |

---

_Triaged with [sg-triage](https://github.com/Gaurav-4567/semgrep-triage) v0.1.0, prompt v0.1.0._

_Semgrep had 59 parse errors during the scan (not counted as findings)._