# JOCKY v0.1: Typechecker & LLVM Codegen Design Document

## 1. Executive Summary & Purpose
This document specifies the design, semantics, and architecture of the JOCKY v0.1 typechecker and LLVM code generation pipeline (`STEP 2A`). JOCKY is a domain-specific, memory-safe, deterministic systems language tailored for blue-team digital forensics, incident response (DFIR), and kernel telemetry heuristics.

The compiler frontend (STEP 1.5) establishes lexing, parsing into an Abstract Syntax Tree (`ast::Program`), source span tracking (`ast::Span`), and capability denylist enforcement (`ErrorCode::E0401`). STEP 2A implements:
1. **Nominal & Primitive Type System**: Strict static typing with bidirectional inference for literals and collections.
2. **Built-in Security Telemetry Prelude**: Strong typing for runtime primitives (`scan_processes`, `trace_network_flows`, `sha256`, etc.) and domain entities (`Finding`, `Process`, `Region`, `Flow`, `Driver`, `Severity`).
3. **High-Level Intermediate Representation (`HIR`)**: Resolved, type-annotated, validated IR preserving exact source spans.
4. **LLVM Codegen via Inkwell**: Lowering HIR to LLVM 17 IR and compiling to relocatable x86_64 ELF object files (`.o`) adhering to System V AMD64 ABI.

---

## 2. Type System Specification

### 2.1 Primitive & Builtin Types
- **Integers**:
  - `i32`: Signed 32-bit integer (default entry return type).
  - `i64`: Signed 64-bit integer (default integer literal type).
  - `u32`, `u64`: Unsigned integer types.
- **Floats**:
  - `f64`: 64-bit IEEE 754 floating point.
- **Booleans**:
  - `bool`: Logical boolean (`true` or `false`). Required in conditional statements (`if`, `while`).
- **Strings**:
  - `string` / `String`: Immutable UTF-8 string reference/slice representation `{ i8*, i64 }`.
- **Arrays**:
  - `[T]`: Homogeneous dynamic slice represented as a pair `{ T*, i64 }` (pointer to elements, length). Empty array `[]` is typed as `[Unknown]` and unifies with the expected array type from context.
- **Nominal Struct Types**:
  - Declared via `struct Name { field: Type, ... }` or provided by the prelude (`Finding`, `Process`, `Driver`, `Region`, `Flow`, `Duration`, `Blocklist`, `Severity`).

### 2.2 Domain Aliases & Value Types
To maintain expressiveness and security invariants, domain-specific type aliases unify cleanly:
- `pid`: Alias for integer identifier / string representations.
- `path`: File path identifier representation (coercible to string).
- `hash`: Cryptographic hash string representation.
- `IpAddr`: Network IP address representation.
- `Severity`: Nominal enum/struct type with associated constants (`Severity::Critical`, `Severity::High`, `Severity::Medium`, `Severity::Low`, `Severity::Info`).

### 2.3 Type Inference & Unification Rules
1. **Bidirectional Typing**:
   - `infer(expr, scope)` synthesizes a type from sub-expressions.
   - `check(expr, expected_type, scope)` verifies expressions against contextual target types (e.g. variable declarations `let x: T = expr`, function returns, and array initialization `let mut findings: [Finding] = []`).
2. **Literals**:
   - Integer literals default to `i64` unless constrained by an explicit `i32` annotation or function return type.
   - String literals evaluate to `string`.
   - Array literals `[e1, e2, ...]` unify all elements against the first element's synthesized type.
3. **Control Flow**:
   - `if cond { then } else { ... }`: `cond` must strictly evaluate to `bool`.
   - `while cond { body }`: `cond` must strictly evaluate to `bool`.
   - `for var in iter { body }`: `iter` must be an array `[T]`, binding `var: T` within `body`.
4. **Binary & Relational Operators**:
   - Arithmetic (`+`, `-`, `*`, `/`, `%`): operands must have matching numeric types.
   - Relational (`==`, `!=`, `<`, `<=`, `>`, `>=`): operands must share compatible types; output is `bool`.
   - Membership (`x in array`): `array` must be `[T]` where `x` is type `T`. Output is `bool`.
   - Logical (`&&`, `||`): operands must be `bool`.
5. **Unary Operators**:
   - `!`: operand must be `bool`. Output is `bool`.
   - `-`: operand must be numeric (`i32`, `i64`, `f64`). Output matches operand type.
6. **Error Reporting**:
   - Every mismatch emits `Diagnostic::typecheck(...)` with `ErrorCode::E0301` and the exact byte span (`ast::Span`) of the offending expression or statement.

---

## 3. The JOCKY Telemetry Prelude

The prelude provides standard declarations accessible to all JOCKY modules without explicit `import` statements.

### 3.1 Runtime Primitives (Extern Functions)
```rust
scan_processes() -> [Process]
enum_kernel_drivers() -> [Driver]
load_loldrivers_blocklist() -> Blocklist
trace_network_flows(d: Duration) -> [Flow]
rwx_regions(pid: i64) -> [Region]
unbacked_pages(pid: i64) -> [Region]
sha256(p: string) -> string
```
All prelude runtime primitives are marked with `is_extern: true`. In LLVM IR, they are emitted as external declarations (`declare ...`), allowing the JOCKY agent runtime to supply the native symbol implementations at link or execution time.

### 3.2 Nominal Entity Types
- `Process`:
  - Fields: `pid: i64`, `name: string`, `parent_pid: i64`
  - Methods:
    - `p.pid() -> i64`
    - `p.name() -> string`
    - `p.parent() -> Process`
- `Driver`:
  - Fields: `name: string`, `path: string`
  - Methods:
    - `d.name() -> string`
    - `d.path() -> string`
- `Blocklist`:
  - Methods:
    - `blocklist.contains(hash: string) -> bool`
- `Flow`:
  - Fields: `dest_ip: string`, `dest_port: i32`
  - Methods:
    - `flow.dest_port() -> i32`
    - `flow.is_unusual_frequency() -> bool`
    - `flow.to_json() -> string`
- `Region`:
  - Fields: `base_address: string`, `size: i64`, `is_file_backed: bool`
  - Methods:
    - `r.address() -> string`
    - `r.is_file_backed() -> bool`
- `Duration`:
  - Associated functions / static methods:
    - `Duration::from_secs(secs: i64) -> Duration`
- `Severity`:
  - Constants / static access:
    - `Severity::Critical -> Severity`
    - `Severity::High -> Severity`
    - `Severity::Medium -> Severity`
    - `Severity::Low -> Severity`
    - `Severity::Info -> Severity`
- `Finding`:
  - Fields:
    - `severity: Severity`
    - `title: string`
    - `evidence: string`
    - `mitre: string`

### 3.3 Slice Methods
- `[T].len() -> i64`: Returns number of elements.
- `[T].push(elem: T) -> ()`: Appends an element to the slice.

---

## 4. High-Level Intermediate Representation (HIR)

The AST represents concrete syntactic structure, including optional type hints and unverified identifiers. The HIR (`compiler/src/hir.rs`) strips syntactic ambiguity and produces an explicitly typed graph:
- **`HirProgram`**: List of functions and struct definitions.
- **`HirFn`**: Function signature, typed parameters, explicit return type, and body block.
- **`HirBlock`**: Sequence of typed statements with local variable resolution.
- **`HirStmt`**:
  - `Let { id: LocalId, name: String, ty: HirType, init: Option<HirExpr>, is_mut: bool, span: Span }`
  - `Assign { target: HirAssignTarget, value: HirExpr, span: Span }`
  - `If { cond: HirExpr, then_branch: HirBlock, else_branch: Option<HirBlock>, span: Span }`
  - `For { var: LocalId, iter: HirExpr, body: HirBlock, span: Span }`
  - `While { cond: HirExpr, body: HirBlock, span: Span }`
  - `Return { value: Option<HirExpr>, span: Span }`
  - `Expr { expr: HirExpr, span: Span }`
- **`HirExpr`**: Every expression records `{ kind: HirExprKind, ty: HirType, span: Span }`.
  - `Literal(HirLiteral)`
  - `Local(LocalId)`
  - `Global(String)`
  - `Array(Vec<HirExpr>)`
  - `StructInit { struct_name: String, fields: Vec<(String, HirExpr)> }`
  - `Unary { op: UnaryOp, operand: Box<HirExpr> }`
  - `Binary { op: BinaryOp, left: Box<HirExpr>, right: Box<HirExpr> }`
  - `Call { callee: String, args: Vec<HirExpr> }`
  - `MethodCall { receiver: Box<HirExpr>, method: String, args: Vec<HirExpr> }`
  - `FieldAccess { receiver: Box<HirExpr>, field: String }`
  - `Index { receiver: Box<HirExpr>, index: Box<HirExpr> }`

---

## 5. Lowering Rules: AST → HIR → LLVM IR

### 5.1 Lowering to LLVM via Inkwell
1. **Context & Module**:
   - Create inkwell `Context` and `Module` named after source module.
   - Initialize LLVM target for `x86_64-unknown-linux-gnu` via `Target::initialize_x86(&InitializationConfig::default())`.
   - Obtain `TargetMachine` with Optimization Level `None` or `Default` and Reloc Mode `PIC`.
   - Set Target Triple and Data Layout on Module.
2. **Type Mapping**:
   - `i32` → `context.i32_type()`
   - `i64` → `context.i64_type()`
   - `bool` → `context.bool_type()` (`i1`)
   - `f64` → `context.f64_type()`
   - `string` → `context.i8_type().ptr_type(AddressSpace::default())` (null-terminated C-string / slice pointer)
   - `[T]` → Struct `{ T*, i64 }`
   - Named structs (`Finding`, `Process`, etc.) → Named LLVM Struct types `{ field_1, field_2, ... }`
3. **Function Signatures & Entry Convention**:
   - `fn main() -> i32` lowers to `@main() -> i32` with C calling convention.
   - If return type is `i32` and function ends without explicit return, lower an implicit `ret i32 0`.
   - Prelude extern functions lower to `module.add_function(name, fn_type, Some(Linkage::External))`.
4. **Strings & Constants**:
   - String literals are emitted as private global constants via `builder.build_global_string_ptr(s, "str")`.
5. **Control Flow**:
   - `if` expressions lower to basic blocks: `then`, `else`, `merge`.
   - `while` lowers to `cond`, `body`, `exit`.
   - `for var in array` lowers to an indexing loop over `0..len`.
6. **Object File Generation**:
   - Module verification with `module.verify()`.
   - Write relocatable ELF object file via `target_machine.write_to_file(module, FileType::Object, path)`.
   - If `--emit-ir` is requested, write LLVM IR text via `module.print_to_file(ir_path)`.

---

## 6. ABI & Calling Convention
- Target: `x86_64-unknown-linux-gnu`.
- ABI: System V AMD64 ABI.
- Register allocation and calling sequence handled natively by LLVM backend.
- Object format: Relocatable ELF 64-bit LSB (Machine: Advanced Micro Devices X86-64, Type: `ET_REL`).
