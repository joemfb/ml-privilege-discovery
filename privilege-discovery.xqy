xquery version "1.0-ml";

module namespace priv = "http://example.com/discover-privileges";

import module namespace sec = "http://marklogic.com/xdmp/security" at "/MarkLogic/security.xqy";

declare namespace error = "http://marklogic.com/xdmp/error";

declare function priv:sec-query($param, $fn as function(*))
{
  xdmp:invoke-function(
    function() {
      $fn($param)
    },
    <options xmlns="xdmp:eval">
      <database>{xdmp:database("Security")}</database>
    </options>)
};

declare function priv:sec-update($fn as function(*))
{
  xdmp:invoke-function(
    function() {
      $fn(),
      xdmp:commit()
    },
    <options xmlns="xdmp:eval">
      <database>{xdmp:database("Security")}</database>
      <transaction-mode>update</transaction-mode>
    </options>)
};

declare function priv:sec-prop-name($prefix as xs:string, $exist-fn as function(*)) as xs:string
{
  let $name := $prefix || xdmp:random(9)
  return
    if (fn:exists(priv:sec-query($name, $exist-fn)))
    then priv:sec-prop-name($prefix, $exist-fn)
    else $name
};

declare function priv:user-name() as xs:string
{
  priv:sec-prop-name("priv-test-user", sec:user-exists(?))
};

declare function priv:role-name() as xs:string
{
  priv:sec-prop-name("priv-test-role", sec:role-exists(?))
};

declare function priv:create-user($name as xs:string, $role as xs:string) as xs:unsignedLong
{
  priv:sec-update(function() {
    sec:create-user($name, "Temp user for privilege testing", $name, $role, (), ())
  })
};

declare function priv:create-role($name as xs:string) as xs:unsignedLong
{
  priv:sec-update(function() {
    sec:create-role($name, "Temp role for privilege testing", (), (), ())
  })
};

declare function priv:add-privilege($privilege as xs:string, $role as xs:string)
{
  priv:sec-update(function() {
    sec:privilege-add-roles($privilege, "execute", $role)
  })
};

declare function priv:privilege-roles($privilege as xs:string)
{
  priv:sec-query($privilege, sec:privilege-get-roles(?, "execute"))
};

declare function priv:remove($user as xs:string, $role as xs:string)
{
  priv:sec-update(function() {
    sec:remove-user($user)
  }),
  priv:sec-update(function() {
    sec:remove-role($role)
  })
};

declare function priv:wrap-test($user-id as xs:unsignedLong, $fn as function(*)) as function(*)
{
  function() {
    xdmp:invoke-function(
      function() {
        $fn(),
        xdmp:rollback()
      },
      <options xmlns="xdmp:eval">
        <user-id>{ $user-id }</user-id>
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
    priv:remove($user, $role),
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
    else xdmp:rethrow()
  }
};

declare function priv:test($fn as function(*)) as xs:string*
{
  let $user := priv:user-name()
  let $role := priv:role-name()
  let $user-id := (
    priv:create-role($role),
    priv:add-privilege("http://marklogic.com/xdmp/privileges/any-uri", $role),
    priv:create-user($user, $role)
  )[fn:last()]
  let $test := priv:wrap-test($user-id, $fn)
  return
    try {
      for $privilege in priv:execute-test($test, $user, $role, ())
      return (
        $privilege,
        fn:string-join(priv:privilege-roles($privilege), ", ")
      )
    }
    catch ($ex) {
      priv:remove($user, $role),
      xdmp:rethrow()
    }
};
