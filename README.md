# MarkLogic Privilege Discovery

An XQuery library for discovering the privileges required by a function.

### <a name="func_privileges_1"/> priv:privileges\#1
```xquery
priv:privileges($fn as function(*)) as xs:string*
```

`priv:privileges()` accepts a zero-arity function. You'll get a sequence of privileges (and the roles that have them).

```xquery
priv:privileges(function() {
  xdmp:http-get("http://google.com")
})
```

returns

```xquery
(
  "http://marklogic.com/xdmp/privileges/xdmp-http-get",
  "network-access, appservices-internal"
)
```

### <a name="func_privileges_2"/> priv:privileges\#2
```xquery
priv:privileges(
  $fn as function(*),
  $database as xs:unsignedLong?
) as xs:string*
```

When passed a database ID, `priv:privileges()` will evaluate the provided function in the context of that database.

```xquery
priv:privileges(
  function() {
    let $page := xdmp:http-get("http://google.com")[2]
    return xdmp:document-insert("/google.html", $page)
  },
  xdmp:database("Documents"))
```

returns

```xquery
(
  "http://marklogic.com/xdmp/privileges/xdmp-http-get",
  "network-access, appservices-internal"
)
```

### Notes

- you should run this as an admin user
- the function argument is evaluated once for each privilege it requires, and then once more.
- The function evaluation is performed in a separate transaction, which is immediately rolled back. Database writes are not performed, but other side affects can still occur. In each of examples above, the HTTP request is made multiple times. However, nothing is persisted to the database.


### License Information

Copyright (c) 2014 Joseph Bryan. All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

[http://www.apache.org/licenses/LICENSE-2.0]
(http://www.apache.org/licenses/LICENSE-2.0)

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

The use of the Apache License does not indicate that this project is
affiliated with the Apache Software Foundation.
