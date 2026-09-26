# JOCKY v0.1 Language & Compiler Specification

This document is the authoritative specification for the **JOCKY v0.1** programming language and compiler frontend. JOCKY is a statically typed, consent-bound language engineered specifically for defensive Digital Forensics & Incident Response (DFIR) operations in adversarial and security-degraded host environments.

---

## 1. Design Principles & Safety Mandates

1. **Defensive-Only (Consent-Bound):** JOCKY executes exclusively inside its own agent process for authorized artifact collection, memory auditing, and threat detection.
2. **Language-Level Capability Denylist:** Primitives that enable offensive tradecraft (code injection, remote execution hijacking, persistence, credential harvesting, driver installation) are strictly barred at the language frontend before typechecking and LLVM IR generation.
3. **Deterministic Memory & Low Footprint:** Designed to run without heavy runtimes or garbage collectors, ensuring forensic analysis proceeds without altering host state or triggering false behavioral alerts.
4. **Attested Binary Modules (`.jkm`):** Module entry convention is `fn main() -> i32` (returning `0` on clean execution, non-zero on error). When a return type signature `-> TYPE` is omitted on a function, the default return type is `i32`.

---

## 2. Lexical Structure & Token Set

### 2.1 Character Set & Whitespace
JOCKY source files are UTF-8 encoded. Whitespace (spaces `\x20`, tabs `\t`, carriage returns `\r`, newlines `\n`, form feeds `\x0c`) separates tokens and is otherwise ignored.

### 2.2 Comments
- Single-line comments begin with `//` and extend to the end of the line.
- Block comments are delimited by `/*` and `*/`.

### 2.3 Keywords
```
fn      let     mut     struct  import  if      else
for     while   return  in      and     or      not
true    false
```

### 2.4 Operators & Delimiters
Multi-character tokens are matched greedily before single-character prefixes:
```
::      ->      ==      !=      <=      >=      &&      ||
=       :       ;       ,       .       +       -       *
/       %       !       <       >       (       )       {
}       [       ]
```

### 2.5 Literals
- **Integer Literals:** Decimal digits `[0-9]+`, parsed as 64-bit signed integers (`i64`).
- **Floating-Point Literals:** Decimal floats `[0-9]+\.[0-9]+`, parsed as 64-bit IEEE floats (`f64`).
- **Boolean Literals:** `true` and `false`.
- **String Literals:** Double-quoted strings `"..."` with support for standard escape sequences (`\n`, `\r`, `\t`, `\\`, `\"`, `\0`).

### 2.6 Identifiers
Identifiers start with an ASCII letter or underscore, followed by letters, digits, or underscores: `[a-zA-Z_][a-zA-Z0-9_]*`.

---

## 3. Formal EBNF Grammar

```ebnf
(* Metalanguage: { } = repetition, [ ] = optional, | = alternation, "..." = terminal *)

program         = { item } ;

item            = fn_decl | struct_decl | import_decl ;

import_decl     = "import" IDENT { "::" IDENT } ";" ;

struct_decl     = "struct" IDENT "{" [ struct_fields ] "}" ;
struct_fields   = struct_field { "," struct_field } [ "," ] ;
struct_field    = IDENT ":" type_spec ;

(* If return type is omitted, default is i32 *)
fn_decl         = "fn" IDENT "(" [ param_list ] ")" [ "->" type_spec ] block ;
param_list      = param { "," param } [ "," ] ;
param           = IDENT ":" type_spec ;

type_spec       = "i32" | "i64" | "u32" | "u64" | "f64" | "bool" | "string"
                | "[" type_spec "]"
                | IDENT ;

block           = "{" { stmt } "}" ;

stmt            = let_stmt
                | assign_stmt
                | if_stmt
                | for_stmt
                | while_stmt
                | return_stmt
                | expr_stmt ;

let_stmt        = "let" [ "mut" ] IDENT [ ":" type_spec ] [ "=" expr ] ";" ;

(* Compound assignment (+=, -=, etc.) is not in v0.1 *)
assign_stmt     = assign_target "=" expr ";" ;
assign_target   = IDENT { "." IDENT } ;

if_stmt         = "if" expr block [ "else" ( block | if_stmt ) ] ;

(* v0.1 for-bindings are single identifiers only; tuple destructuring is not supported *)
for_stmt        = "for" IDENT "in" expr block ;

while_stmt      = "while" expr block ;

return_stmt     = "return" [ expr ] ";" ;

expr_stmt       = expr ";" ;

expr            = logical_or ;

logical_or      = logical_and { ( "||" | "or" ) logical_and } ;

logical_and     = equality { ( "&&" | "and" ) equality } ;

equality        = relational { ( "==" | "!=" ) relational } ;

relational      = membership { ( "<" | "<=" | ">" | ">=" ) membership } ;

membership      = additive { "in" additive } ;

additive        = multiplicative { ( "+" | "-" ) multiplicative } ;

multiplicative  = unary { ( "*" | "/" | "%" ) unary } ;

unary           = ( "!" | "not" | "-" ) unary
                | postfix ;

postfix         = primary { call_suffix | method_suffix | field_suffix | index_suffix } ;
call_suffix     = "(" [ arg_list ] ")" ;
method_suffix   = "." IDENT "(" [ arg_list ] ")" ;
field_suffix    = "." IDENT ;
index_suffix    = "[" expr "]" ;

primary         = literal
                | path_expr
                | array_literal
                | struct_init
                | "(" expr ")" ;

path_expr       = IDENT { "::" IDENT } ;

struct_init     = IDENT "{" [ field_init_list ] "}" ;
field_init_list = field_init { "," field_init } [ "," ] ;
field_init      = IDENT ":" expr ;

array_literal   = "[" [ expr_list ] "]" ;
expr_list       = expr { "," expr } [ "," ] ;
arg_list        = expr { "," expr } [ "," ] ;

literal         = INT_LIT | FLOAT_LIT | STRING_LIT | "true" | "false" ;
```

---

## 4. Operator Precedence & Binding Power Hierarchy

JOCKY uses a 10-level precedence hierarchy for expression parsing. In Pratt parsing terms, each level has explicit left and right binding powers:

| Level | Operator Category | Operators | Binding Power `(l_bp, r_bp)` | Associativity | Description |
|:---|:---|:---|:---|:---|:---|
| **1** | Logical OR | `\|\|`, `or` | `(1, 2)` | Left-to-right | Short-circuit disjunction |
| **2** | Logical AND | `&&`, `and` | `(3, 4)` | Left-to-right | Short-circuit conjunction |
| **3** | Equality | `==`, `!=` | `(5, 6)` | Left-to-right | Structural value equality |
| **4** | Relational | `<`, `<=`, `>`, `>=` | `(7, 8)` | Left-to-right | Comparison ordering |
| **5** | **Membership** | **`in`** | **`(9, 10)`** | **Left-to-right** | **Array membership test** |
| **6** | Additive | `+`, `-` | `(11, 12)` | Left-to-right | Addition / subtraction |
| **7** | Multiplicative | `*`, `/`, `%` | `(13, 14)` | Left-to-right | Multiplication / division / remainder |
| **8** | Unary Prefix | `!`, `not`, `-` | `prefix: 15` | Right-to-left | Inversion and negation |
| **9** | Postfix | `()`, `.method()`, `.field`, `[]` | `postfix: 16` | Left-to-right | Invocations, projections, indexing |
| **10**| Primary / Atom | literals, paths, `(...)`, `[...]` | N/A | N/A | Atomic terms, literals, grouping |

### 4.1 Boundary Invariants
- **Test A (`in` vs `and`):** `x in [1, 2] and y` evaluates as `(x in [1, 2]) and y`.
- **Test B (`additive` vs `in`):** `x + 1 in [1, 2]` evaluates as `(x + 1) in [1, 2]`.
- **Test C (`in` vs `equality`):** `x in [1, 2] == true` evaluates as `(x in [1, 2]) == true`.
- **Test D (`relational` vs `in`):** `x < 5 in [true, false]` evaluates as `x < (5 in [true, false])`.

---

## 5. Diagnostic Architecture & Error Codes

The compiler issues structured diagnostics carrying an exact byte span `Span { start, end }`:

| Error Code | Stage | Description |
|:---|:---|:---|
| **`E0101`** | Lexer | Unrecognized character, unclosed string literal, or invalid escape. |
| **`E0201`** | Parser | Grammar syntax violation, unexpected token, unclosed delimiter, or invalid assignment target. |
| **`E0301`** | Semantic / Typecheck | Type mismatch, undeclared identifier, immutable assignment, or arity error. |
| **`E0401`** | Safety Denylist | Attempted invocation or reference to a forbidden offensive capability (§0.2). |

---

## 6. Capability Denylist Enforcement (§0.2)

The capability denylist check runs immediately after parsing and prior to typechecking. The constant `DENYLIST` represents the complete 23-entry union of forbidden offensive primitives across system specifications:

```rust
pub const DENYLIST: &[&str] = &[
    // Blueprint §0.2 Primitives
    "inject_remote_process",
    "write_process_memory",
    "create_service",
    "install_driver",
    "set_run_key",
    "schedule_task",
    "dump_lsass",
    "harvest_credentials",
    "read_browser_db",
    "exploit",
    "bypass_uac",
    "token_steal",
    "connect_arbitrary",
    // Prompt §1.5.6 & Design §5.2 Primitives
    "virtual_alloc_ex",
    "create_remote_thread",
    "set_registry_run_key",
    "lsass_dump",
    "minidump_write_dump",
    "load_driver",
    "impersonate_token",
    "adjust_token_privileges",
    "disable_etw",
    "patch_amsi",
];
```

Any invocation of these identifiers halts compilation with code `ErrorCode::E0401` and pinpoints the call site with exact line, column, and caret annotations.

---

## 7. Stdlib Syntax Validation Audit

All six standard library scripts located in `stdlib/jocky/` were audited against the formal grammar and parser:

| Script Name | Primary Constructs | Validated AST Mapping | Status |
|:---|:---|:---|:---|
| **`process.jky`** | `fn detect_suspicious_parents() -> [Finding]`, `scan_processes()`, `p.parent()`, `parent.name() in ["winword.exe", ...]`, `findings.push(Finding { ... })` | `FnDecl`, `Type::Array`, `MethodCall`, `Binary(In)`, `StructInit` | **VERIFIED** |
| **`network.jky`** | `fn trace_network_anomalies() -> [Finding]`, `trace_network_flows(Duration::from_secs(60))`, `flow.dest_port() == 443 && flow.is_unusual_frequency()` | `FnDecl`, `Call(Path)`, `Binary(And, Eq, MethodCall)` | **VERIFIED** |
| **`memory.jky`** | `fn detect_memory_anomalies() -> [Finding]`, `rwx_regions(p.pid())`, `!r.is_file_backed()`, nested loops | `FnDecl`, `Unary(Not, MethodCall)`, `For` | **VERIFIED** |
| **`detect_byovd.jky`** | `enum_kernel_drivers()`, `load_loldrivers_blocklist()`, `sha256(d.path())`, `blocklist.contains(h)` | `FnDecl`, `Call(MethodCall)`, `MethodCall` | **VERIFIED** |
| **`detect_inject.jky`**| `unbacked_pages(p.pid())`, `unbacked.len() > 0`, `Finding { ... }` | `FnDecl`, `Binary(Gt, MethodCall, Literal)` | **VERIFIED** |
| **`detect_syscall.jky`**| `let mut findings = []; return findings;` | `FnDecl`, `Let(Mut, Array)`, `Return` | **VERIFIED** |