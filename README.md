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
            const edit = buildEdit(functionName.start.line, functionName.start.col, functionName.end.line, functionName.end.col, "update", "gets_s");
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

2.
```
name
----
insecure-use-printf-fn

description
-----------
Avoid using user-controlled format strings passed into 'sprintf', 'printf' and
'vsprintf'. These functions put you at risk of buffer overflow vulnerabilities through the
use of format string exploits. Instead, use 'snprintf' and 'vsnprintf'.

cwe
---
'CWE-134: Use of Externally-Controlled Format String'
    
references
----------
- https://doc.castsoftware.com/display/SBX/Never+use+sprintf%28%29+or+vsprintf%28%29+functions
- https://www.cvedetails.com/cwe-details/134/Uncontrolled-Format-String.html

tree_sitter_query
----------------- 
(call_expression
            function: (identifier) @fn_name
            arguments: (
              argument_list
              .
              [
                (identifier) 
                (subscript_expression
                    argument: (identifier) 
                    index: (number_literal)
                )
              ]
            )
            (#match? @fn_name "^(sprintf|printf|vsprintf)$")
          )

rule_code
---------
function visit(node, filename, code) {
            const functionName = node.captures["fn_name"];
            if (functionName) {
                const name = getCode(functionName.start, functionName.end, code);
                const error = buildError(functionName.start.line, functionName.start.col, functionName.end.line, functionName.end.col,
                    "Use of Externally-Controlled Format String", "WARNING", "security");
                addError(error);
            }
        }

violating code
--------------
#include <stdio.h>

void bad_vsprintf(int argc, char **argv) {
    char format[256];

    //ruleid: insecure-use-printf-fn
    strncpy(format, argv[1], 255);
    char buffer[100];
    vsprintf (buffer,format, args);

    //ruleid: insecure-use-printf-fn
    vsprintf(buffer, argv[1], args);

    //ok: insecure-use-printf-fn
    vsprintf("%s\n",argv[0]);

    //ok: insecure-use-printf-fn
    vsnprintf(buffer, format, args);
}

void bad_sprintf(int argc, char **argv) {
    char format[256];

    int a = 10, b = 20, c=30;
    //ruleid: insecure-use-printf-fn
    strcpy(format, argv[1]);
    char buffer[200];
    sprintf(buffer, format, a, b, c);


    char buffer[256];
    int i = 3;
    //ruleid: insecure-use-printf-fn
    sprintf(buffer, argv[2], a, b, c);

    //ok: insecure-use-printf-fn
    sprintf("%s\n",argv[0]);

    //ok: insecure-use-printf-fn
    snprintf(buffer, format, a,b,c);
}

void bad_printf() {
    //ruleid: insecure-use-printf-fn
    printf(argv[2], 1234);

    char format[300];
    //ruleid: insecure-use-printf-fn
    strcpy(format, argv[1]);
    printf(format, 1234);

    //ok: insecure-use-printf-fn
    printf("hello");

    //ok: insecure-use-printf-fn
    printf("%s\n",argv[0]);
}

int main() {
    bad_vsprintf(NULL);
    bad_sprintf();
    bad_printf();
    return 0;
}

```

3.

```
name
----
insecure-use-memset

description
-----------
When handling sensitive information in a buffer, it's important to ensure 
that the data is securely erased before the buffer is deleted or reused. 
While `memset()` is commonly used for this purpose, it can leave sensitive 
information behind due to compiler optimizations or other factors. 
To avoid this potential vulnerability, it's recommended to use the 
`memset_s()` function instead. `memset_s()` is a standardized function 
that securely overwrites the memory with a specified value, making it more 
difficult for an attacker to recover any sensitive data that was stored in 
the buffer. By using `memset_s()` instead of `memset()`, you can help to 
ensure that your application is more secure and less vulnerable to exploits 
that rely on residual data in memory.

cwe
---
'CWE-14: Compiler Removal of Code to Clear Buffers'
    
references
----------
- https://cwe.mitre.org/data/definitions/14.html
- https://owasp.org/Top10/A02_2021-Cryptographic_Failures/

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
        if (name == "memset") {
            const error = buildError(functionName.start.line, functionName.start.col, functionName.end.line, functionName.end.col,
                "Avoid memset", "CRITICAL", "security");
            const edit = buildEdit(functionName.start.line, functionName.start.col, functionName.end.line, functionName.end.col, "update", "memset_s");
            const fix = buildFix("Use memset_s", [edit]);
            addError(error.addFix(fix));
        }
    }
}

violating code
--------------
void badcode(char *password, size_t bufferSize) {
  char token[256];
  init(token, password);
  // ruleid: insecure-use-memset
  memset(password, ' ', strlen(password));
  // ruleid: insecure-use-memset
  memset(token, ' ', strlen(localBuffer));
  free(password);
}

void okcode(char *password, size_t bufferSize) {
  char token[256];
  init(token, password);
  // ok: insecure-use-memset
  memset_s(password, bufferSize, ' ', strlen(password));
  // ok: insecure-use-memset
  memset_s(token, sizeof(token), ' ', strlen(localBuffer));
  free(password);
}
```

4.

```
name
----

insecure-use-string-copy-fn

description
-----------

Finding triggers whenever there is a strcpy or strncpy used.
This is an issue because strcpy does not affirm the size of the destination array
and strncpy will not automatically NULL-terminate strings.
This can lead to buffer overflows, which can cause program crashes
and potentially let an attacker inject code in the program.
Fix this by using strcpy_s instead (although note that strcpy_s is an
optional part of the C11 standard, and so may not be available).
 
cwe
---
- 'CWE-676: Use of Potentially Dangerous Function'
    
references
----------
- https://cwe.mitre.org/data/definitions/676
- https://nvd.nist.gov/vuln/detail/CVE-2019-11365

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
        if (name == "strcpy" || name == "strncpy") {
            const error = buildError(functionName.start.line, functionName.start.col, functionName.end.line, functionName.end.col,
                "Avoid strcpy and strncpy", "WARNING", "security");
            const edit = buildEdit(functionName.start.line, functionName.start.col, functionName.end.line, functionName.end.col, "update", "strcpy_s");
            const fix = buildFix("Use strcpy_s", [edit]);
            addError(error.addFix(fix));
        }
    }
}

violating code
--------------
#include <stdio.h>

int DST_BUFFER_SIZE = 120;

int bad_strcpy(src, dst) {
    n = DST_BUFFER_SIZE;
    if ((dst != NULL) && (src != NULL) && (strlen(dst)+strlen(src)+1 <= n))
    {
        // ruleid: insecure-use-string-copy-fn
        strcpy(dst, src);

        // ruleid: insecure-use-string-copy-fn
        strncpy(dst, src, 100);
    }
}

int main() {
   printf("Hello, World!");
   return 0;
}
```

5.

```
name
----

insecure-use-strcat-fn

description
-----------

Finding triggers whenever there is a strcat or strncat used.
This is an issue because strcat or strncat can lead to buffer overflow vulns.
Fix this by using strcat_s instead.

cwe
---
- 'CWE-676: Use of Potentially Dangerous Function'
    
references
----------
- https://nvd.nist.gov/vuln/detail/CVE-2019-12553
- https://techblog.mediaservice.net/2020/04/cve-2020-2851-stack-based-buffer-overflow-in-cde-libdtsvc/

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
        if (name == "strcat" || name == "strncat") {
            const error = buildError(functionName.start.line, functionName.start.col, functionName.end.line, functionName.end.col,
                "Avoid strcat and strncat", "WARNING", "security");
            const edit = buildEdit(functionName.start.line, functionName.start.col, functionName.end.line, functionName.end.col, "update", "strcat_s");
            const fix = buildFix("Use strcat_s", [edit]);
            addError(error.addFix(fix));
        }
    }
}

violating code
--------------
#include <stdio.h>

int DST_BUFFER_SIZE = 120;

int bad_strcpy(src, dst) {
    n = DST_BUFFER_SIZE;
    if ((dst != NULL) && (src != NULL) && (strlen(dst)+strlen(src)+1 <= n))
    {
        // ruleid: insecure-use-strcat-fn
        strcat(dst, src);

        // ruleid: insecure-use-strcat-fn
        strncat(dst, src, 100);
    }
}

int main() {
   printf("Hello, World!");
   return 0;
}
```

6.

```
name
----

insecure-use-strtok-fn

description
-----------
 
Avoid using 'strtok()'. This function directly modifies the first argument buffer,
permanently erasing the
delimiter character. Use 'strtok_r()' instead.
  
cwe
---
- 'CWE-676: Use of Potentially Dangerous Function'
    
references
----------
- https://wiki.sei.cmu.edu/confluence/display/c/STR06-C.+Do+not+assume+that+strtok%28%29+leaves+the+parse+string+unchanged
- https://man7.org/linux/man-pages/man3/strtok.3.html#BUGS
- https://stackoverflow.com/a/40335556

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
        if (name == "strtok") {
            const error = buildError(functionName.start.line, functionName.start.col, functionName.end.line, functionName.end.col,
                "Avoid strtok", "WARNING", "security");
            const edit = buildEdit(functionName.start.line, functionName.start.col, functionName.end.line, functionName.end.col, "update", "strtok_r");
            const fix = buildFix("Use strtok_r", [edit]);
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
    fgets(str, DST_BUFFER_SIZE, stdin);
    // ruleid:insecure-use-strtok-fn
    strtok(str, " ");
    printf("%s", str);
    return 0;
}

int main() {
    char str[DST_BUFFER_SIZE];
    char dest[DST_BUFFER_SIZE];
    fgets(str, DST_BUFFER_SIZE, stdin);
    // ok:insecure-use-strtok-fn
    strtok_r(str, " ", *dest);
    printf("%s", str);
    return 0;
}
}
```

7.

```
name
----

insecure-use-scanf-fn

description
-----------
  
Avoid using 'scanf()'. This function, when used improperly, does not consider
buffer boundaries and can lead to buffer overflows. Use 'fgets()' instead
for reading input.

cwe
---
- 'CWE-676: Use of Potentially Dangerous Function'

references
----------
- http://sekrit.de/webdocs/c/beginners-guide-away-from-scanf.html

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
        if (name == "scanf") {
            const error = buildError(functionName.start.line, functionName.start.col, functionName.end.line, functionName.end.col,
                "Avoid scanf", "WARNING", "security");
            const edit = buildEdit(functionName.start.line, functionName.start.col, functionName.end.line, functionName.end.col, "update", "fgets");
            const fix = buildFix("Use fgets", [edit]);
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
    // ruleid:insecure-use-scanf-fn
    scanf("%s", str);
    printf("%s", str);
    return 0;
}

int main() {
    char str[DST_BUFFER_SIZE];
    // ok:insecure-use-scanf-fn
    fgets(str);
    printf("%s", str);
    return 0;
}
```

