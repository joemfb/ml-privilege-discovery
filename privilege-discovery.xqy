xquery version "1.0-ml";

(:~
 : This module provides a mechanism to discover the MarkLogic privileges that a given function requires.
 :
 : @author Joe Bryan
 :)
module namespace priv = "http://example.com/privilege-discover";

import module namespace sec = "http://marklogic.com/xdmp/security" at "/MarkLogic/security.xqy";

declare namespace error = "http://marklogic.com/xdmp/error";

declare function priv:query-security-db($param, $fn as function(*))
{
  xdmp:invoke-function(
    function() { $fn($param) },
    <options xmlns="xdmp:eval">
      <database>{ xdmp:database("Security") }</database>
    </options>)
};

declare function priv:update-security-db($fn as function(*))
{
  xdmp:invoke-function(
    function() { $fn(), xdmp:commit() },
    <options xmlns="xdmp:eval">
      <database>{ xdmp:database("Security") }</database>
      <transaction-mode>update</transaction-mode>
    </options>)
};

declare function priv:new-security-name(
  $prefix as xs:string,
  $exist-fn as function(item()) as xs:boolean
) as xs:string
{
  let $name := $prefix || xdmp:random(9)
  return
    if (priv:query-security-db($name, $exist-fn))
    then priv:new-security-name($prefix, $exist-fn)
    else $name
};

declare function priv:new-user-name() as xs:string
{
  priv:new-security-name("priv-test-user", sec:user-exists(?))
};

declare function priv:new-role-name() as xs:string
{
  priv:new-security-name("priv-test-role", sec:role-exists(?))
};

declare function priv:create-user($name as xs:string, $role as xs:string) as xs:unsignedLong
{
  priv:update-security-db(function() {
    sec:create-user($name, "Temp user for privilege testing", $name, $role, (), ())
  })
};

declare function priv:create-role($name as xs:string) as xs:unsignedLong
{
  priv:update-security-db(function() {
    sec:create-role($name, "Temp role for privilege testing", (), (), ())
  })
};

declare function priv:add-privilege($privilege as xs:string, $role as xs:string)
{
  priv:update-security-db(function() {
    sec:privilege-add-roles($privilege, "execute", $role)
  })
};

declare function priv:privilege-roles($privilege as xs:string) as xs:string*
{
  priv:query-security-db($privilege, sec:privilege-get-roles(?, "execute"))
};

declare function priv:prepare-test(
  $user-id as xs:unsignedLong,
  $database as xs:unsignedLong,
  $fn as function(*)
) as function(*)
{
  function() {
    xdmp:invoke-function(
      function() { $fn(), xdmp:rollback() },
      <options xmlns="xdmp:eval">
        <user-id>{ $user-id }</user-id>
        <database>{ $database }</database>
        <transaction-mode>update</transaction-mode>
      </options>)
  }
};

declare function priv:execute-test(
  $test as function(*),
  $user as xs:string,
  $role as xs:string,
  $privileges as xs:string*
) as xs:string*
{
  try {
    $test(),
    priv:cleanup($user, $role),
    $privileges
  }
  catch ($ex) {
    if ($ex/error:code eq "SEC-PRIV")
    then
      let $privilege := $ex/error:format-string/fn:substring-after(., "Need privilege: ")
      return (
        priv:add-privilege($privilege, $role),
        priv:execute-test($test, $user, $role, ($privileges, $privilege))
      )
    else (
      priv:cleanup($user, $role),
      xdmp:rethrow()
    )
  }
};

declare function priv:cleanup($user as xs:string, $role as xs:string)
{
  priv:update-security-db(function() {
    sec:remove-user($user)
  }),
  priv:update-security-db(function() {
    sec:remove-role($role)
  })
};

declare function priv:privileges($fn as function(*)) as xs:string*
{
  priv:privileges($fn, xdmp:database())
};

declare function priv:privileges($fn as function(*), $database as xs:unsignedLong?) as xs:string*
{
  let $user := priv:new-user-name()
  let $role := priv:new-role-name()
  let $user-id := (
    priv:create-role($role),
    priv:add-privilege("http://marklogic.com/xdmp/privileges/any-uri", $role),
    priv:create-user($user, $role)
  )[fn:last()]
  let $test := priv:prepare-test($user-id, $database, $fn)
  for $privilege in priv:execute-test($test, $user, $role, ())
  return (
    $privilege,
    fn:string-join(priv:privilege-roles($privilege), ", ")
  )
};
