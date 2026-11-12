// This ruleset is used for unit tests for hashing strings and condition - Modification will require test updates

rule Set001_Rule001
{
    strings:
        $a = "foobar"

    condition:
        $a
}

rule Set001_Rule002
{
    strings:
        $b = "foobar"

    condition:
        $b
}

// The following two any-of forms use equivalent string sets.
// The commented all-of rules remain distinct because any and all have different condition logic.

rule Set003_Rule001
{
    strings:
        $aaa = "foobar"

    condition:
        any of ($*)
}

rule Set003_Rule002
{
    strings:
        $ = "foobar"

    condition:
        any of them
}

/*
rule Set003_Rule003
{
    strings:
        $ = "foobar"

    condition:
        all of ($*)
}

rule Set003_Rule004
{
    strings:
        $ = "foobar"

    condition:
            all of them
}
*/

rule Set002_Rule001
{
    strings:
        $b = "foo"
        $a = "bar"

    condition:
        all of them
}

rule Set002_Rule002
{
    strings:
        $b = "bar"
        $a = "foo"

    condition:
        all of ($*)
}

rule Set002_Rule003
{
    strings:
        $ = "bar"
        $ = "foo"

    condition:
        all of ($*)
}

rule Set002_Rule004
{
    strings:
        $ = "bar"
        $ = "foo"

    condition:
        all of them
}
