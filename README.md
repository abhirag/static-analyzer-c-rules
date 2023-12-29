# datadog-static-analyzer-c-rules

Porting some rules from semgrep

1.
```
name
----
insecure-use-gets-fn

description
-----------
Avoid 'gets()'. This function does not consider buffer boundaries and can lead
to buffer overflows. Use 'fgets()' or 'gets_s()' instead.

cwe
---
'CWE-676: Use of Potentially Dangerous Function'

references
----------
https://us-cert.cisa.gov/bsi/articles/knowledge/coding-practices/fgets-and-gets_s

tree_sitter_query
----------------- 
(call_expression
            function: (identifier) @fn_name)

rule_code
---------
function visit(node, filename, code) {
    const functionName = node.captures["fn_name"];
    if (functionName) {
        const name = getCode(functionName.start, functionName.end, code);
        if (name == "gets") {
            const error = buildError(functionName.start.line, functionName.start.col, functionName.end.line, functionName.end.col,
                "Avoid gets", "CRITICAL", "security");
            const edit = buildEdit(functionName.start.line, functionName.start.col, functionName.end.line, functionName.end.col, "update", "bar");
            const fix = buildFix("Use fgets or gets_s", [edit]);
            addError(error.addFix(fix));
        }
    }
}

violating code
--------------
#include <stdio.h>

int DST_BUFFER_SIZE = 120;

int bad_code() {
    char str[DST_BUFFER_SIZE];
    // ruleid:insecure-use-gets-fn
    gets(str);
    printf("%s", str);
    return 0;
}

int main() {
    char str[DST_BUFFER_SIZE];
    // ok:insecure-use-gets-fn
    fgets(str);
    printf("%s", str);
    return 0;
}
``` 
