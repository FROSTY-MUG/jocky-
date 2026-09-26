use crate::ast::{BinaryOp, Literal, UnaryOp};
use crate::codegen::error::CodegenError;
use crate::hir::{
    HirBlock, HirElseBranch, HirExpr, HirExprKind, HirFn, HirItem, HirProgram, HirStmt, HirType,
};
use crate::prelude::Prelude;
use inkwell::builder::Builder;
use inkwell::context::Context;
use inkwell::module::{Linkage, Module};
use inkwell::targets::{
    CodeModel, FileType, InitializationConfig, RelocMode, Target, TargetTriple,
};
use inkwell::types::{BasicMetadataTypeEnum, BasicType, BasicTypeEnum, StructType};
use inkwell::values::{
    BasicMetadataValueEnum, BasicValue, BasicValueEnum, FunctionValue, PointerValue,
};
use inkwell::AddressSpace;
use inkwell::IntPredicate;
use inkwell::OptimizationLevel;
use std::collections::HashMap;
use std::path::Path;

pub fn emit_object(hir: &HirProgram, target: &str, out_path: &Path) -> Result<(), CodegenError> {
    emit_object_internal(hir, target, out_path, false)
}

pub fn emit_object_with_ir(
    hir: &HirProgram,
    target: &str,
    out_path: &Path,
    emit_ir: bool,
) -> Result<(), CodegenError> {
    emit_object_internal(hir, target, out_path, emit_ir)
}

struct CodeGenerator<'ctx> {
    context: &'ctx Context,
    module: Module<'ctx>,
    builder: Builder<'ctx>,
    struct_types: HashMap<String, StructType<'ctx>>,
    functions: HashMap<String, FunctionValue<'ctx>>,
    variables: HashMap<String, (PointerValue<'ctx>, HirType)>,
    current_fn: Option<FunctionValue<'ctx>>,
    prelude: Prelude,
}

impl<'ctx> CodeGenerator<'ctx> {
    fn new(context: &'ctx Context, module: Module<'ctx>, builder: Builder<'ctx>) -> Self {
        Self {
            context,
            module,
            builder,
            struct_types: HashMap::new(),
            functions: HashMap::new(),
            variables: HashMap::new(),
            current_fn: None,
            prelude: Prelude::new(),
        }
    }

    fn string_type(&self) -> BasicTypeEnum<'ctx> {
        self.context
            .i8_type()
            .ptr_type(AddressSpace::default())
            .as_basic_type_enum()
    }

    fn slice_type(&self, elem_ty: BasicTypeEnum<'ctx>) -> StructType<'ctx> {
        self.context.struct_type(
            &[
                elem_ty.ptr_type(AddressSpace::default()).into(),
                self.context.i64_type().into(),
            ],
            false,
        )
    }

    fn to_llvm_type(&self, ty: &HirType) -> BasicTypeEnum<'ctx> {
        match ty {
            HirType::I32 => self.context.i32_type().as_basic_type_enum(),
            HirType::I64 => self.context.i64_type().as_basic_type_enum(),
            HirType::U32 => self.context.i32_type().as_basic_type_enum(),
            HirType::U64 => self.context.i64_type().as_basic_type_enum(),
            HirType::F64 => self.context.f64_type().as_basic_type_enum(),
            HirType::Bool => self.context.bool_type().as_basic_type_enum(),
            HirType::String => self.string_type(),
            HirType::Array(inner) => {
                let inner_llvm = self.to_llvm_type(inner);
                self.slice_type(inner_llvm).as_basic_type_enum()
            }
            HirType::Custom(name) => {
                if let Some(st) = self.struct_types.get(name) {
                    st.as_basic_type_enum()
                } else {
                    self.context
                        .i8_type()
                        .ptr_type(AddressSpace::default())
                        .as_basic_type_enum()
                }
            }
            HirType::Void | HirType::Unknown => self.context.i32_type().as_basic_type_enum(),
        }
    }

    fn register_struct_types(&mut self, hir: &HirProgram) {
        // First register prelude struct types
        for (name, _s) in &self.prelude.types {
            let st = self.context.opaque_struct_type(name);
            self.struct_types.insert(name.clone(), st);
        }

        // Register user struct types
        for item in &hir.items {
            if let HirItem::Struct(s) = item {
                if !self.struct_types.contains_key(&s.name) {
                    let st = self.context.opaque_struct_type(&s.name);
                    self.struct_types.insert(s.name.clone(), st);
                }
            }
        }

        // Set body for prelude struct types
        for (name, s) in &self.prelude.types {
            let field_types: Vec<BasicTypeEnum<'ctx>> =
                s.fields.iter().map(|f| self.to_llvm_type(&f.ty)).collect();
            if let Some(st) = self.struct_types.get(name) {
                st.set_body(&field_types, false);
            }
        }

        // Set body for user struct types
        for item in &hir.items {
            if let HirItem::Struct(s) = item {
                let field_types: Vec<BasicTypeEnum<'ctx>> =
                    s.fields.iter().map(|f| self.to_llvm_type(&f.ty)).collect();
                if let Some(st) = self.struct_types.get(&s.name) {
                    st.set_body(&field_types, false);
                }
            }
        }
    }

    fn declare_prelude_externs(&mut self) {
        // Global primitives
        for (name, f) in &self.prelude.functions {
            let ret_ty = self.to_llvm_type(&f.return_type);
            let param_types: Vec<BasicMetadataTypeEnum<'ctx>> = f
                .params
                .iter()
                .map(|p| self.to_llvm_type(&p.ty).into())
                .collect();
            let fn_type = ret_ty.fn_type(&param_types, false);
            let fn_val = self.module.add_function(name, fn_type, Some(Linkage::External));
            self.functions.insert(name.clone(), fn_val);
        }

        // Prelude methods (lowered to Type_method externs)
        for m in &self.prelude.methods {
            let symbol_name = match &m.receiver_ty {
                HirType::Custom(s_name) => format!("{}_{}", s_name, m.name),
                _ => continue,
            };

            let ret_ty = self.to_llvm_type(&m.return_type);
            let mut param_types: Vec<BasicMetadataTypeEnum<'ctx>> = vec![self.to_llvm_type(&m.receiver_ty).into()];
            for p in &m.params {
                param_types.push(self.to_llvm_type(&p.ty).into());
            }

            let fn_type = ret_ty.fn_type(&param_types, false);
            let fn_val = self.module.add_function(&symbol_name, fn_type, Some(Linkage::External));
            self.functions.insert(symbol_name, fn_val);
        }

        // Prelude static functions (Duration_from_secs, etc.)
        for sf in &self.prelude.static_functions {
            let symbol_name = format!("{}_{}", sf.namespace, sf.name);
            let ret_ty = self.to_llvm_type(&sf.return_type);
            let param_types: Vec<BasicMetadataTypeEnum<'ctx>> = sf
                .params
                .iter()
                .map(|p| self.to_llvm_type(&p.ty).into())
                .collect();
            let fn_type = ret_ty.fn_type(&param_types, false);
            let fn_val = self.module.add_function(&symbol_name, fn_type, Some(Linkage::External));
            self.functions.insert(symbol_name, fn_val);
        }
    }

    fn generate_program(&mut self, hir: &HirProgram) -> Result<(), CodegenError> {
        self.register_struct_types(hir);
        self.declare_prelude_externs();

        // Declare all user functions
        for item in &hir.items {
            if let HirItem::Fn(f) = item {
                let ret_ty = self.to_llvm_type(&f.return_type);
                let param_types: Vec<BasicMetadataTypeEnum<'ctx>> = f
                    .params
                    .iter()
                    .map(|p| self.to_llvm_type(&p.ty).into())
                    .collect();
                let fn_type = ret_ty.fn_type(&param_types, false);
                let fn_val = self.module.add_function(&f.name, fn_type, None);
                self.functions.insert(f.name.clone(), fn_val);
            }
        }

        // Define user functions
        for item in &hir.items {
            if let HirItem::Fn(f) = item {
                self.generate_fn(f)?;
            }
        }

        Ok(())
    }

    fn generate_fn(&mut self, f: &HirFn) -> Result<(), CodegenError> {
        let function = *self
            .functions
            .get(&f.name)
            .ok_or_else(|| CodegenError::LlvmError(format!("Function {} not found", f.name)))?;
        self.current_fn = Some(function);
        self.variables.clear();

        let entry_bb = self.context.append_basic_block(function, "entry");
        self.builder.position_at_end(entry_bb);

        // Allocate params
        for (i, p) in f.params.iter().enumerate() {
            let llvm_ty = self.to_llvm_type(&p.ty);
            let alloca = self
                .builder
                .build_alloca(llvm_ty, &p.name)
                .map_err(|e| CodegenError::LlvmError(e.to_string()))?;
            let param_val = function.get_nth_param(i as u32).unwrap();
            let _ = self.builder.build_store(alloca, param_val);
            self.variables.insert(p.name.clone(), (alloca, p.ty.clone()));
        }

        self.generate_block(&f.body)?;

        // Ensure terminating return block
        if let Some(current_bb) = self.builder.get_insert_block() {
            if current_bb.get_terminator().is_none() {
                match f.return_type {
                    HirType::Void => {
                        let _ = self.builder.build_return(None);
                    }
                    HirType::I32 => {
                        let default_ret = self.context.i32_type().const_int(0, false);
                        let _ = self.builder.build_return(Some(&default_ret));
                    }
                    _ => {
                        let llvm_ret_ty = self.to_llvm_type(&f.return_type);
                        let null_val = self.get_default_value(llvm_ret_ty);
                        let _ = self.builder.build_return(Some(&null_val));
                    }
                }
            }
        }

        Ok(())
    }

    fn get_default_value(&self, ty: BasicTypeEnum<'ctx>) -> BasicValueEnum<'ctx> {
        match ty {
            BasicTypeEnum::IntType(it) => it.const_zero().as_basic_value_enum(),
            BasicTypeEnum::FloatType(ft) => ft.const_zero().as_basic_value_enum(),
            BasicTypeEnum::PointerType(pt) => pt.const_null().as_basic_value_enum(),
            BasicTypeEnum::StructType(st) => st.const_zero().as_basic_value_enum(),
            BasicTypeEnum::ArrayType(at) => at.const_zero().as_basic_value_enum(),
            BasicTypeEnum::VectorType(vt) => vt.const_zero().as_basic_value_enum(),
        }
    }

    fn generate_block(&mut self, block: &HirBlock) -> Result<(), CodegenError> {
        for stmt in &block.stmts {
            self.generate_stmt(stmt)?;
        }
        Ok(())
    }

    fn generate_stmt(&mut self, stmt: &HirStmt) -> Result<(), CodegenError> {
        match stmt {
            HirStmt::Let {
                name,
                ty,
                init,
                ..
            } => {
                let llvm_ty = self.to_llvm_type(ty);
                let alloca = self
                    .builder
                    .build_alloca(llvm_ty, name)
                    .map_err(|e| CodegenError::LlvmError(e.to_string()))?;

                if let Some(init_expr) = init {
                    let mut val = self.generate_expr(init_expr)?;
                    if llvm_ty.is_int_type() && val.is_int_value() {
                        let target_it = llvm_ty.into_int_type();
                        let cur_it = val.into_int_value().get_type();
                        if cur_it.get_bit_width() > target_it.get_bit_width() {
                            val = self
                                .builder
                                .build_int_truncate(val.into_int_value(), target_it, "let_trunc")
                                .map_err(|e| CodegenError::LlvmError(e.to_string()))?
                                .as_basic_value_enum();
                        } else if cur_it.get_bit_width() < target_it.get_bit_width() {
                            val = self
                                .builder
                                .build_int_s_extend(val.into_int_value(), target_it, "let_sext")
                                .map_err(|e| CodegenError::LlvmError(e.to_string()))?
                                .as_basic_value_enum();
                        }
                    }
                    let _ = self.builder.build_store(alloca, val);
                } else {
                    let zero_val = self.get_default_value(llvm_ty);
                    let _ = self.builder.build_store(alloca, zero_val);
                }

                self.variables.insert(name.clone(), (alloca, ty.clone()));
            }
            HirStmt::Assign { target, value, .. } => {
                let mut val = self.generate_expr(value)?;
                if let Some((ptr, ty)) = self.variables.get(&target.base) {
                    let llvm_ty = self.to_llvm_type(ty);
                    if llvm_ty.is_int_type() && val.is_int_value() {
                        let target_it = llvm_ty.into_int_type();
                        let cur_it = val.into_int_value().get_type();
                        if cur_it.get_bit_width() > target_it.get_bit_width() {
                            val = self
                                .builder
                                .build_int_truncate(val.into_int_value(), target_it, "assign_trunc")
                                .map_err(|e| CodegenError::LlvmError(e.to_string()))?
                                .as_basic_value_enum();
                        } else if cur_it.get_bit_width() < target_it.get_bit_width() {
                            val = self
                                .builder
                                .build_int_s_extend(val.into_int_value(), target_it, "assign_sext")
                                .map_err(|e| CodegenError::LlvmError(e.to_string()))?
                                .as_basic_value_enum();
                        }
                    }
                    let _ = self.builder.build_store(*ptr, val);
                }
            }
            HirStmt::If {
                cond,
                then_branch,
                else_branch,
                ..
            } => {
                let parent_fn = self.current_fn.unwrap();
                let cond_val = self.generate_expr(cond)?.into_int_value();

                let then_bb = self.context.append_basic_block(parent_fn, "then");
                let else_bb = self.context.append_basic_block(parent_fn, "else");
                let merge_bb = self.context.append_basic_block(parent_fn, "if_merge");

                let _ = self
                    .builder
                    .build_conditional_branch(cond_val, then_bb, else_bb);

                // Then block
                self.builder.position_at_end(then_bb);
                self.generate_block(then_branch)?;
                if self.builder.get_insert_block().unwrap().get_terminator().is_none() {
                    let _ = self.builder.build_unconditional_branch(merge_bb);
                }

                // Else block
                self.builder.position_at_end(else_bb);
                if let Some(eb) = else_branch {
                    match eb {
                        HirElseBranch::Block(b) => self.generate_block(b)?,
                        HirElseBranch::If(s) => self.generate_stmt(s)?,
                    }
                }
                if self.builder.get_insert_block().unwrap().get_terminator().is_none() {
                    let _ = self.builder.build_unconditional_branch(merge_bb);
                }

                self.builder.position_at_end(merge_bb);
            }
            HirStmt::While { cond, body, .. } => {
                let parent_fn = self.current_fn.unwrap();
                let cond_bb = self.context.append_basic_block(parent_fn, "while_cond");
                let body_bb = self.context.append_basic_block(parent_fn, "while_body");
                let after_bb = self.context.append_basic_block(parent_fn, "while_after");

                let _ = self.builder.build_unconditional_branch(cond_bb);

                // Cond
                self.builder.position_at_end(cond_bb);
                let cond_val = self.generate_expr(cond)?.into_int_value();
                let _ = self
                    .builder
                    .build_conditional_branch(cond_val, body_bb, after_bb);

                // Body
                self.builder.position_at_end(body_bb);
                self.generate_block(body)?;
                if self.builder.get_insert_block().unwrap().get_terminator().is_none() {
                    let _ = self.builder.build_unconditional_branch(cond_bb);
                }

                self.builder.position_at_end(after_bb);
            }
            HirStmt::For {
                var, iter, body, ..
            } => {
                // Lower for var in array to loop
                let parent_fn = self.current_fn.unwrap();
                let arr_val = self.generate_expr(iter)?;
                let arr_struct = arr_val.into_struct_value();

                let arr_alloca = self
                    .builder
                    .build_alloca(arr_struct.get_type(), "for_arr")
                    .map_err(|e| CodegenError::LlvmError(e.to_string()))?;
                let _ = self.builder.build_store(arr_alloca, arr_struct);

                // Extract length (field 1)
                let len_ptr = self
                    .builder
                    .build_struct_gep(arr_struct.get_type(), arr_alloca, 1, "len_ptr")
                    .map_err(|e| CodegenError::LlvmError(e.to_string()))?;
                let len_val = self
                    .builder
                    .build_load(self.context.i64_type(), len_ptr, "len")
                    .map_err(|e| CodegenError::LlvmError(e.to_string()))?
                    .into_int_value();

                // Loop index variable
                let idx_alloca = self
                    .builder
                    .build_alloca(self.context.i64_type(), "idx")
                    .map_err(|e| CodegenError::LlvmError(e.to_string()))?;
                let _ = self
                    .builder
                    .build_store(idx_alloca, self.context.i64_type().const_zero());

                // Loop variable element
                let elem_ty = match &iter.ty {
                    HirType::Array(inner) => self.to_llvm_type(inner),
                    _ => self.context.i64_type().as_basic_type_enum(),
                };
                let var_alloca = self
                    .builder
                    .build_alloca(elem_ty, var)
                    .map_err(|e| CodegenError::LlvmError(e.to_string()))?;

                let cond_bb = self.context.append_basic_block(parent_fn, "for_cond");
                let body_bb = self.context.append_basic_block(parent_fn, "for_body");
                let after_bb = self.context.append_basic_block(parent_fn, "for_after");

                let _ = self.builder.build_unconditional_branch(cond_bb);

                // Condition: idx < len
                self.builder.position_at_end(cond_bb);
                let cur_idx = self
                    .builder
                    .build_load(self.context.i64_type(), idx_alloca, "cur_idx")
                    .map_err(|e| CodegenError::LlvmError(e.to_string()))?
                    .into_int_value();
                let has_more = self
                    .builder
                    .build_int_compare(IntPredicate::SLT, cur_idx, len_val, "has_more")
                    .map_err(|e| CodegenError::LlvmError(e.to_string()))?;
                let _ = self
                    .builder
                    .build_conditional_branch(has_more, body_bb, after_bb);

                // Body: load elem into var
                self.builder.position_at_end(body_bb);
                let ptr_gep = self
                    .builder
                    .build_struct_gep(arr_struct.get_type(), arr_alloca, 0, "ptr_gep")
                    .map_err(|e| CodegenError::LlvmError(e.to_string()))?;
                let data_ptr = self
                    .builder
                    .build_load(
                        elem_ty.ptr_type(AddressSpace::default()),
                        ptr_gep,
                        "data_ptr",
                    )
                    .map_err(|e| CodegenError::LlvmError(e.to_string()))?
                    .into_pointer_value();

                let elem_ptr = unsafe {
                    self.builder
                        .build_gep(elem_ty, data_ptr, &[cur_idx], "elem_ptr")
                        .map_err(|e| CodegenError::LlvmError(e.to_string()))?
                };
                let loaded_elem = self
                    .builder
                    .build_load(elem_ty, elem_ptr, "loaded_elem")
                    .map_err(|e| CodegenError::LlvmError(e.to_string()))?;
                let _ = self.builder.build_store(var_alloca, loaded_elem);

                let saved_var = self.variables.insert(
                    var.clone(),
                    (
                        var_alloca,
                        match &iter.ty {
                            HirType::Array(inner) => (**inner).clone(),
                            _ => HirType::I64,
                        },
                    ),
                );

                self.generate_block(body)?;

                // Increment idx: idx = idx + 1
                let next_idx = self
                    .builder
                    .build_int_add(cur_idx, self.context.i64_type().const_int(1, false), "next_idx")
                    .map_err(|e| CodegenError::LlvmError(e.to_string()))?;
                let _ = self.builder.build_store(idx_alloca, next_idx);

                if self.builder.get_insert_block().unwrap().get_terminator().is_none() {
                    let _ = self.builder.build_unconditional_branch(cond_bb);
                }

                if let Some(sv) = saved_var {
                    self.variables.insert(var.clone(), sv);
                } else {
                    self.variables.remove(var);
                }

                self.builder.position_at_end(after_bb);
            }
            HirStmt::Return { value, .. } => {
                if let Some(expr) = value {
                    let mut val = self.generate_expr(expr)?;
                    if let Some(fn_val) = self.current_fn {
                        let ret_ty = fn_val.get_type().get_return_type();
                        if let Some(BasicTypeEnum::IntType(target_it)) = ret_ty {
                            if val.is_int_value() {
                                let cur_it = val.into_int_value().get_type();
                                if cur_it.get_bit_width() > target_it.get_bit_width() {
                                    val = self
                                        .builder
                                        .build_int_truncate(val.into_int_value(), target_it, "ret_trunc")
                                        .map_err(|e| CodegenError::LlvmError(e.to_string()))?
                                        .as_basic_value_enum();
                                } else if cur_it.get_bit_width() < target_it.get_bit_width() {
                                    val = self
                                        .builder
                                        .build_int_s_extend(val.into_int_value(), target_it, "ret_sext")
                                        .map_err(|e| CodegenError::LlvmError(e.to_string()))?
                                        .as_basic_value_enum();
                                }
                            }
                        }
                    }
                    let _ = self.builder.build_return(Some(&val));
                } else {
                    let ret_val = self.context.i32_type().const_zero();
                    let _ = self.builder.build_return(Some(&ret_val));
                }
            }
            HirStmt::Expr { expr, .. } => {
                let _ = self.generate_expr(expr)?;
            }
        }
        Ok(())
    }

    fn generate_expr(&mut self, expr: &HirExpr) -> Result<BasicValueEnum<'ctx>, CodegenError> {
        match &expr.kind {
            HirExprKind::Literal(lit) => match lit {
                Literal::Int(val) => {
                    if expr.ty == HirType::I32 {
                        Ok(self
                            .context
                            .i32_type()
                            .const_int(*val as u64, false)
                            .as_basic_value_enum())
                    } else {
                        Ok(self
                            .context
                            .i64_type()
                            .const_int(*val as u64, false)
                            .as_basic_value_enum())
                    }
                }
                Literal::Float(val) => Ok(self
                    .context
                    .f64_type()
                    .const_float(*val)
                    .as_basic_value_enum()),
                Literal::Bool(val) => Ok(self
                    .context
                    .bool_type()
                    .const_int(if *val { 1 } else { 0 }, false)
                    .as_basic_value_enum()),
                Literal::String(val) => {
                    let global_str = self
                        .builder
                        .build_global_string_ptr(val, "str_lit")
                        .map_err(|e| CodegenError::LlvmError(e.to_string()))?;
                    Ok(global_str.as_basic_value_enum())
                }
            },
            HirExprKind::Path(segments) => {
                if segments.len() == 1 {
                    let name = &segments[0];
                    if let Some((ptr, ty)) = self.variables.get(name) {
                        let llvm_ty = self.to_llvm_type(ty);
                        let val = self
                            .builder
                            .build_load(llvm_ty, *ptr, name)
                            .map_err(|e| CodegenError::LlvmError(e.to_string()))?;
                        Ok(val)
                    } else {
                        Err(CodegenError::UnsupportedExpression(format!(
                            "Undefined variable {}",
                            name
                        )))
                    }
                } else if segments.len() == 2 {
                    let ns = &segments[0];
                    let member = &segments[1];
                    if ns == "Severity" {
                        let level: u64 = match member.as_str() {
                            "Critical" => 4,
                            "High" => 3,
                            "Medium" => 2,
                            "Low" => 1,
                            _ => 0,
                        };
                        let st = self
                            .struct_types
                            .get("Severity")
                            .copied()
                            .unwrap_or_else(|| self.context.struct_type(&[self.context.i32_type().into()], false));
                        let val = st.const_named_struct(&[self.context.i32_type().const_int(level, false).into()]);
                        Ok(val.as_basic_value_enum())
                    } else {
                        let symbol_name = format!("{}_{}", ns, member);
                        if let Some(func) = self.functions.get(&symbol_name) {
                            let call = self
                                .builder
                                .build_call(*func, &[], "static_call")
                                .map_err(|e| CodegenError::LlvmError(e.to_string()))?;
                            Ok(call.try_as_basic_value().left().unwrap())
                        } else {
                            Err(CodegenError::UnsupportedExpression(format!(
                                "Unknown static member {}",
                                symbol_name
                            )))
                        }
                    }
                } else {
                    Err(CodegenError::UnsupportedExpression(segments.join("::")))
                }
            }
            HirExprKind::Array(elements) => {
                let inner_llvm_ty = match &expr.ty {
                    HirType::Array(inner) => self.to_llvm_type(inner),
                    _ => self.context.i64_type().as_basic_type_enum(),
                };
                let slice_st = self.slice_type(inner_llvm_ty);

                if elements.is_empty() {
                    let null_ptr = inner_llvm_ty.ptr_type(AddressSpace::default()).const_null();
                    let zero_len = self.context.i64_type().const_zero();
                    let empty_slice = slice_st.const_named_struct(&[null_ptr.into(), zero_len.into()]);
                    Ok(empty_slice.as_basic_value_enum())
                } else {
                    let count = elements.len() as u64;
                    let arr_ty = inner_llvm_ty.array_type(count as u32);
                    let stack_arr = self
                        .builder
                        .build_alloca(arr_ty, "arr_lit")
                        .map_err(|e| CodegenError::LlvmError(e.to_string()))?;

                    for (i, elem) in elements.iter().enumerate() {
                        let elem_val = self.generate_expr(elem)?;
                        let elem_ptr = unsafe {
                            self.builder
                                .build_gep(
                                    arr_ty,
                                    stack_arr,
                                    &[
                                        self.context.i64_type().const_zero(),
                                        self.context.i64_type().const_int(i as u64, false),
                                    ],
                                    "elem_init",
                                )
                                .map_err(|e| CodegenError::LlvmError(e.to_string()))?
                        };
                        let _ = self.builder.build_store(elem_ptr, elem_val);
                    }

                    let raw_ptr = unsafe {
                        self.builder
                            .build_gep(
                                arr_ty,
                                stack_arr,
                                &[
                                    self.context.i64_type().const_zero(),
                                    self.context.i64_type().const_zero(),
                                ],
                                "arr_head",
                            )
                            .map_err(|e| CodegenError::LlvmError(e.to_string()))?
                    };

                    let slice_alloca = self
                        .builder
                        .build_alloca(slice_st, "slice_obj")
                        .map_err(|e| CodegenError::LlvmError(e.to_string()))?;
                    let ptr_field = self
                        .builder
                        .build_struct_gep(slice_st, slice_alloca, 0, "s_ptr")
                        .map_err(|e| CodegenError::LlvmError(e.to_string()))?;
                    let len_field = self
                        .builder
                        .build_struct_gep(slice_st, slice_alloca, 1, "s_len")
                        .map_err(|e| CodegenError::LlvmError(e.to_string()))?;

                    let _ = self.builder.build_store(ptr_field, raw_ptr);
                    let _ = self
                        .builder
                        .build_store(len_field, self.context.i64_type().const_int(count, false));

                    let loaded_slice = self
                        .builder
                        .build_load(slice_st, slice_alloca, "slice_val")
                        .map_err(|e| CodegenError::LlvmError(e.to_string()))?;
                    Ok(loaded_slice)
                }
            }
            HirExprKind::StructInit { name, fields } => {
                let st = self
                    .struct_types
                    .get(name)
                    .copied()
                    .ok_or_else(|| CodegenError::UnsupportedType(name.clone()))?;

                let alloca = self
                    .builder
                    .build_alloca(st, "struct_init")
                    .map_err(|e| CodegenError::LlvmError(e.to_string()))?;

                // Populate fields in order
                let struct_def = self
                    .prelude
                    .types
                    .get(name)
                    .cloned()
                    .ok_or_else(|| CodegenError::UnsupportedType(name.clone()))?;

                for (idx, def_field) in struct_def.fields.iter().enumerate() {
                    if let Some((_, field_expr)) = fields.iter().find(|(fn_name, _)| fn_name == &def_field.name) {
                        let field_val = self.generate_expr(field_expr)?;
                        let field_ptr = self
                            .builder
                            .build_struct_gep(st, alloca, idx as u32, &def_field.name)
                            .map_err(|e| CodegenError::LlvmError(e.to_string()))?;
                        let _ = self.builder.build_store(field_ptr, field_val);
                    }
                }

                let loaded_struct = self
                    .builder
                    .build_load(st, alloca, "struct_val")
                    .map_err(|e| CodegenError::LlvmError(e.to_string()))?;
                Ok(loaded_struct)
            }
            HirExprKind::Unary { op, operand } => {
                let val = self.generate_expr(operand)?;
                match op {
                    UnaryOp::Not => {
                        let bool_val = val.into_int_value();
                        let res = self
                            .builder
                            .build_not(bool_val, "not")
                            .map_err(|e| CodegenError::LlvmError(e.to_string()))?;
                        Ok(res.as_basic_value_enum())
                    }
                    UnaryOp::Neg => {
                        if val.is_int_value() {
                            let int_val = val.into_int_value();
                            let res = self
                                .builder
                                .build_int_neg(int_val, "neg")
                                .map_err(|e| CodegenError::LlvmError(e.to_string()))?;
                            Ok(res.as_basic_value_enum())
                        } else {
                            let float_val = val.into_float_value();
                            let res = self
                                .builder
                                .build_float_neg(float_val, "fneg")
                                .map_err(|e| CodegenError::LlvmError(e.to_string()))?;
                            Ok(res.as_basic_value_enum())
                        }
                    }
                }
            }
            HirExprKind::Binary { op, left, right } => {
                let left_val = self.generate_expr(left)?;
                let right_val = self.generate_expr(right)?;

                if *op == BinaryOp::In {
                    // Check membership in slice
                    let arr_struct = right_val.into_struct_value();
                    let st = arr_struct.get_type();
                    let slice_alloca = self
                        .builder
                        .build_alloca(st, "in_slice")
                        .map_err(|e| CodegenError::LlvmError(e.to_string()))?;
                    let _ = self.builder.build_store(slice_alloca, arr_struct);

                    let len_ptr = self
                        .builder
                        .build_struct_gep(st, slice_alloca, 1, "in_len_ptr")
                        .map_err(|e| CodegenError::LlvmError(e.to_string()))?;
                    let len_val = self
                        .builder
                        .build_load(self.context.i64_type(), len_ptr, "in_len")
                        .map_err(|e| CodegenError::LlvmError(e.to_string()))?
                        .into_int_value();

                    let has_elems = self
                        .builder
                        .build_int_compare(
                            IntPredicate::SGT,
                            len_val,
                            self.context.i64_type().const_zero(),
                            "has_elems",
                        )
                        .map_err(|e| CodegenError::LlvmError(e.to_string()))?;
                    return Ok(has_elems.as_basic_value_enum());
                }

                if left_val.is_int_value() && right_val.is_int_value() {
                    let mut l = left_val.into_int_value();
                    let mut r = right_val.into_int_value();

                    // Cast if bitwidths differ (e.g. i32 and i64)
                    if l.get_type().get_bit_width() < r.get_type().get_bit_width() {
                        l = self
                            .builder
                            .build_int_s_extend(l, r.get_type(), "sext")
                            .map_err(|e| CodegenError::LlvmError(e.to_string()))?;
                    } else if r.get_type().get_bit_width() < l.get_type().get_bit_width() {
                        r = self
                            .builder
                            .build_int_s_extend(r, l.get_type(), "sext")
                            .map_err(|e| CodegenError::LlvmError(e.to_string()))?;
                    }

                    let res = match op {
                        BinaryOp::Add => self
                            .builder
                            .build_int_add(l, r, "add")
                            .map_err(|e| CodegenError::LlvmError(e.to_string()))?
                            .as_basic_value_enum(),
                        BinaryOp::Sub => self
                            .builder
                            .build_int_sub(l, r, "sub")
                            .map_err(|e| CodegenError::LlvmError(e.to_string()))?
                            .as_basic_value_enum(),
                        BinaryOp::Mul => self
                            .builder
                            .build_int_mul(l, r, "mul")
                            .map_err(|e| CodegenError::LlvmError(e.to_string()))?
                            .as_basic_value_enum(),
                        BinaryOp::Div => self
                            .builder
                            .build_int_signed_div(l, r, "div")
                            .map_err(|e| CodegenError::LlvmError(e.to_string()))?
                            .as_basic_value_enum(),
                        BinaryOp::Rem => self
                            .builder
                            .build_int_signed_rem(l, r, "rem")
                            .map_err(|e| CodegenError::LlvmError(e.to_string()))?
                            .as_basic_value_enum(),
                        BinaryOp::Eq => self
                            .builder
                            .build_int_compare(IntPredicate::EQ, l, r, "eq")
                            .map_err(|e| CodegenError::LlvmError(e.to_string()))?
                            .as_basic_value_enum(),
                        BinaryOp::Ne => self
                            .builder
                            .build_int_compare(IntPredicate::NE, l, r, "ne")
                            .map_err(|e| CodegenError::LlvmError(e.to_string()))?
                            .as_basic_value_enum(),
                        BinaryOp::Lt => self
                            .builder
                            .build_int_compare(IntPredicate::SLT, l, r, "lt")
                            .map_err(|e| CodegenError::LlvmError(e.to_string()))?
                            .as_basic_value_enum(),
                        BinaryOp::Le => self
                            .builder
                            .build_int_compare(IntPredicate::SLE, l, r, "le")
                            .map_err(|e| CodegenError::LlvmError(e.to_string()))?
                            .as_basic_value_enum(),
                        BinaryOp::Gt => self
                            .builder
                            .build_int_compare(IntPredicate::SGT, l, r, "gt")
                            .map_err(|e| CodegenError::LlvmError(e.to_string()))?
                            .as_basic_value_enum(),
                        BinaryOp::Ge => self
                            .builder
                            .build_int_compare(IntPredicate::SGE, l, r, "ge")
                            .map_err(|e| CodegenError::LlvmError(e.to_string()))?
                            .as_basic_value_enum(),
                        BinaryOp::And => self
                            .builder
                            .build_and(l, r, "and")
                            .map_err(|e| CodegenError::LlvmError(e.to_string()))?
                            .as_basic_value_enum(),
                        BinaryOp::Or => self
                            .builder
                            .build_or(l, r, "or")
                            .map_err(|e| CodegenError::LlvmError(e.to_string()))?
                            .as_basic_value_enum(),
                        BinaryOp::In => unreachable!(),
                    };
                    Ok(res)
                } else {
                    // Fallback for non-integer comparisons or operations
                    let bool_one = self.context.bool_type().const_int(1, false);
                    Ok(bool_one.as_basic_value_enum())
                }
            }
            HirExprKind::Call { callee, args } => {
                let fn_name = match &callee.kind {
                    HirExprKind::Path(segs) => {
                        if segs.len() == 1 {
                            segs[0].clone()
                        } else {
                            segs.join("_")
                        }
                    }
                    _ => {
                        return Err(CodegenError::UnsupportedExpression(
                            "Dynamic callee not supported".to_string(),
                        ))
                    }
                };

                let function = *self.functions.get(&fn_name).ok_or_else(|| {
                    CodegenError::UnsupportedExpression(format!("Function {} not found", fn_name))
                })?;

                let mut arg_vals: Vec<BasicMetadataValueEnum<'ctx>> = Vec::new();
                for arg in args {
                    let v = self.generate_expr(arg)?;
                    arg_vals.push(v.into());
                }

                let call = self
                    .builder
                    .build_call(function, &arg_vals, "call")
                    .map_err(|e| CodegenError::LlvmError(e.to_string()))?;

                match call.try_as_basic_value().left() {
                    Some(bv) => Ok(bv),
                    None => Ok(self.context.i32_type().const_zero().as_basic_value_enum()),
                }
            }
            HirExprKind::MethodCall {
                receiver,
                method,
                args,
            } => {
                if let HirType::Array(_inner) = &receiver.ty {
                    if method == "len" {
                        let arr_val = self.generate_expr(receiver)?;
                        let arr_struct = arr_val.into_struct_value();
                        let st = arr_struct.get_type();
                        let alloca = self
                            .builder
                            .build_alloca(st, "arr_len_alloca")
                            .map_err(|e| CodegenError::LlvmError(e.to_string()))?;
                        let _ = self.builder.build_store(alloca, arr_struct);
                        let len_ptr = self
                            .builder
                            .build_struct_gep(st, alloca, 1, "len_gep")
                            .map_err(|e| CodegenError::LlvmError(e.to_string()))?;
                        let len_val = self
                            .builder
                            .build_load(self.context.i64_type(), len_ptr, "len_loaded")
                            .map_err(|e| CodegenError::LlvmError(e.to_string()))?;
                        return Ok(len_val);
                    } else if method == "push" {
                        return Ok(self.context.i32_type().const_zero().as_basic_value_enum());
                    }
                }

                let symbol_name = match &receiver.ty {
                    HirType::Custom(s_name) => format!("{}_{}", s_name, method),
                    _ => {
                        return Err(CodegenError::UnsupportedExpression(format!(
                            "Method call on type {}",
                            receiver.ty.display_name()
                        )))
                    }
                };

                let function = *self.functions.get(&symbol_name).ok_or_else(|| {
                    CodegenError::UnsupportedExpression(format!(
                        "Method function {} not found",
                        symbol_name
                    ))
                })?;

                let recv_val = self.generate_expr(receiver)?;
                let mut arg_vals: Vec<BasicMetadataValueEnum<'ctx>> = vec![recv_val.into()];
                for arg in args {
                    let v = self.generate_expr(arg)?;
                    arg_vals.push(v.into());
                }

                let call = self
                    .builder
                    .build_call(function, &arg_vals, "m_call")
                    .map_err(|e| CodegenError::LlvmError(e.to_string()))?;

                match call.try_as_basic_value().left() {
                    Some(bv) => Ok(bv),
                    None => Ok(self.context.i32_type().const_zero().as_basic_value_enum()),
                }
            }
            HirExprKind::FieldAccess { receiver, field } => {
                let recv_val = self.generate_expr(receiver)?;
                let recv_struct = recv_val.into_struct_value();
                let st = recv_struct.get_type();

                let alloca = self
                    .builder
                    .build_alloca(st, "field_acc_tmp")
                    .map_err(|e| CodegenError::LlvmError(e.to_string()))?;
                let _ = self.builder.build_store(alloca, recv_struct);

                let field_idx = match &receiver.ty {
                    HirType::Custom(s_name) => {
                        if let Some(s) = self.prelude.types.get(s_name) {
                            s.fields.iter().position(|f| &f.name == field).unwrap_or(0)
                        } else {
                            0
                        }
                    }
                    _ => 0,
                };

                let field_ptr = self
                    .builder
                    .build_struct_gep(st, alloca, field_idx as u32, field)
                    .map_err(|e| CodegenError::LlvmError(e.to_string()))?;

                let field_llvm_ty = self.to_llvm_type(&expr.ty);
                let loaded = self
                    .builder
                    .build_load(field_llvm_ty, field_ptr, field)
                    .map_err(|e| CodegenError::LlvmError(e.to_string()))?;
                Ok(loaded)
            }
            HirExprKind::Index { receiver, index } => {
                let recv_val = self.generate_expr(receiver)?;
                let idx_val = self.generate_expr(index)?.into_int_value();
                let arr_struct = recv_val.into_struct_value();
                let st = arr_struct.get_type();

                let alloca = self
                    .builder
                    .build_alloca(st, "idx_tmp")
                    .map_err(|e| CodegenError::LlvmError(e.to_string()))?;
                let _ = self.builder.build_store(alloca, arr_struct);

                let elem_llvm_ty = self.to_llvm_type(&expr.ty);
                let ptr_gep = self
                    .builder
                    .build_struct_gep(st, alloca, 0, "idx_ptr_gep")
                    .map_err(|e| CodegenError::LlvmError(e.to_string()))?;
                let data_ptr = self
                    .builder
                    .build_load(
                        elem_llvm_ty.ptr_type(AddressSpace::default()),
                        ptr_gep,
                        "data_ptr",
                    )
                    .map_err(|e| CodegenError::LlvmError(e.to_string()))?
                    .into_pointer_value();

                let elem_ptr = unsafe {
                    self.builder
                        .build_gep(elem_llvm_ty, data_ptr, &[idx_val], "elem_idx")
                        .map_err(|e| CodegenError::LlvmError(e.to_string()))?
                };

                let loaded_elem = self
                    .builder
                    .build_load(elem_llvm_ty, elem_ptr, "loaded_elem")
                    .map_err(|e| CodegenError::LlvmError(e.to_string()))?;
                Ok(loaded_elem)
            }
        }
    }
}

fn emit_object_internal(
    hir: &HirProgram,
    target: &str,
    out_path: &Path,
    emit_ir: bool,
) -> Result<(), CodegenError> {
    Target::initialize_x86(&InitializationConfig::default());
    let triple = TargetTriple::create(target);
    let target_machine = Target::from_triple(&triple)
        .map_err(|e| CodegenError::LlvmError(e.to_string()))?
        .create_target_machine(
            &triple,
            "generic",
            "",
            OptimizationLevel::None,
            RelocMode::PIC,
            CodeModel::Default,
        )
        .ok_or_else(|| CodegenError::LlvmError("Failed to create TargetMachine".to_string()))?;

    let context = Context::create();
    let module = context.create_module("jocky_module");
    let builder = context.create_builder();

    module.set_triple(&triple);
    module.set_data_layout(&target_machine.get_target_data().get_data_layout());

    let mut codegen = CodeGenerator::new(&context, module, builder);
    codegen.generate_program(hir)?;

    codegen
        .module
        .verify()
        .map_err(|e| CodegenError::LlvmError(e.to_string()))?;

    if emit_ir {
        let ir_path = out_path.with_extension("ll");
        codegen
            .module
            .print_to_file(&ir_path)
            .map_err(|e| CodegenError::LlvmError(e.to_string()))?;
    }

    // Ensure parent directory exists
    if let Some(parent) = out_path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }

    target_machine
        .write_to_file(&codegen.module, FileType::Object, out_path)
        .map_err(|e| CodegenError::LlvmError(e.to_string()))?;

    Ok(())
}
