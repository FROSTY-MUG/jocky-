use crate::ast::Span;
use crate::hir::{HirFn, HirParam, HirStruct, HirStructField, HirType};
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq)]
pub struct MethodSignature {
    pub name: String,
    pub receiver_ty: HirType,
    pub params: Vec<HirParam>,
    pub return_type: HirType,
}

#[derive(Debug, Clone, PartialEq)]
pub struct StaticFunctionSignature {
    pub namespace: String,
    pub name: String,
    pub params: Vec<HirParam>,
    pub return_type: HirType,
}

pub struct Prelude {
    pub types: HashMap<String, HirStruct>,
    pub functions: HashMap<String, HirFn>,
    pub methods: Vec<MethodSignature>,
    pub static_functions: Vec<StaticFunctionSignature>,
}

impl Prelude {
    pub fn new() -> Self {
        let mut types = HashMap::new();
        let mut functions = HashMap::new();
        let mut methods = Vec::new();
        let mut static_functions = Vec::new();

        // 1. Nominal Struct Types
        types.insert(
            "Process".to_string(),
            HirStruct {
                name: "Process".to_string(),
                fields: vec![
                    HirStructField {
                        name: "pid".to_string(),
                        ty: HirType::I64,
                        span: Span::default(),
                    },
                    HirStructField {
                        name: "name".to_string(),
                        ty: HirType::String,
                        span: Span::default(),
                    },
                    HirStructField {
                        name: "parent_pid".to_string(),
                        ty: HirType::I64,
                        span: Span::default(),
                    },
                ],
                span: Span::default(),
            },
        );

        types.insert(
            "Driver".to_string(),
            HirStruct {
                name: "Driver".to_string(),
                fields: vec![
                    HirStructField {
                        name: "name".to_string(),
                        ty: HirType::String,
                        span: Span::default(),
                    },
                    HirStructField {
                        name: "path".to_string(),
                        ty: HirType::String,
                        span: Span::default(),
                    },
                ],
                span: Span::default(),
            },
        );

        types.insert(
            "Blocklist".to_string(),
            HirStruct {
                name: "Blocklist".to_string(),
                fields: vec![],
                span: Span::default(),
            },
        );

        types.insert(
            "Flow".to_string(),
            HirStruct {
                name: "Flow".to_string(),
                fields: vec![
                    HirStructField {
                        name: "dest_ip".to_string(),
                        ty: HirType::String,
                        span: Span::default(),
                    },
                    HirStructField {
                        name: "dest_port".to_string(),
                        ty: HirType::I32,
                        span: Span::default(),
                    },
                ],
                span: Span::default(),
            },
        );

        types.insert(
            "Region".to_string(),
            HirStruct {
                name: "Region".to_string(),
                fields: vec![
                    HirStructField {
                        name: "base_address".to_string(),
                        ty: HirType::String,
                        span: Span::default(),
                    },
                    HirStructField {
                        name: "size".to_string(),
                        ty: HirType::I64,
                        span: Span::default(),
                    },
                    HirStructField {
                        name: "is_file_backed".to_string(),
                        ty: HirType::Bool,
                        span: Span::default(),
                    },
                ],
                span: Span::default(),
            },
        );

        types.insert(
            "Severity".to_string(),
            HirStruct {
                name: "Severity".to_string(),
                fields: vec![HirStructField {
                    name: "level".to_string(),
                    ty: HirType::I32,
                    span: Span::default(),
                }],
                span: Span::default(),
            },
        );

        types.insert(
            "Duration".to_string(),
            HirStruct {
                name: "Duration".to_string(),
                fields: vec![HirStructField {
                    name: "secs".to_string(),
                    ty: HirType::I64,
                    span: Span::default(),
                }],
                span: Span::default(),
            },
        );

        types.insert(
            "IpAddr".to_string(),
            HirStruct {
                name: "IpAddr".to_string(),
                fields: vec![HirStructField {
                    name: "addr".to_string(),
                    ty: HirType::String,
                    span: Span::default(),
                }],
                span: Span::default(),
            },
        );

        types.insert(
            "Finding".to_string(),
            HirStruct {
                name: "Finding".to_string(),
                fields: vec![
                    HirStructField {
                        name: "severity".to_string(),
                        ty: HirType::Custom("Severity".to_string()),
                        span: Span::default(),
                    },
                    HirStructField {
                        name: "title".to_string(),
                        ty: HirType::String,
                        span: Span::default(),
                    },
                    HirStructField {
                        name: "evidence".to_string(),
                        ty: HirType::String,
                        span: Span::default(),
                    },
                    HirStructField {
                        name: "mitre".to_string(),
                        ty: HirType::String,
                        span: Span::default(),
                    },
                ],
                span: Span::default(),
            },
        );

        // 2. Global Runtime Primitives (is_extern: true)
        functions.insert(
            "scan_processes".to_string(),
            HirFn {
                name: "scan_processes".to_string(),
                params: vec![],
                return_type: HirType::Array(Box::new(HirType::Custom("Process".to_string()))),
                body: crate::hir::HirBlock {
                    stmts: vec![],
                    span: Span::default(),
                },
                is_extern: true,
                span: Span::default(),
            },
        );

        functions.insert(
            "enum_kernel_drivers".to_string(),
            HirFn {
                name: "enum_kernel_drivers".to_string(),
                params: vec![],
                return_type: HirType::Array(Box::new(HirType::Custom("Driver".to_string()))),
                body: crate::hir::HirBlock {
                    stmts: vec![],
                    span: Span::default(),
                },
                is_extern: true,
                span: Span::default(),
            },
        );

        functions.insert(
            "load_loldrivers_blocklist".to_string(),
            HirFn {
                name: "load_loldrivers_blocklist".to_string(),
                params: vec![],
                return_type: HirType::Custom("Blocklist".to_string()),
                body: crate::hir::HirBlock {
                    stmts: vec![],
                    span: Span::default(),
                },
                is_extern: true,
                span: Span::default(),
            },
        );

        functions.insert(
            "trace_network_flows".to_string(),
            HirFn {
                name: "trace_network_flows".to_string(),
                params: vec![HirParam {
                    name: "d".to_string(),
                    ty: HirType::Custom("Duration".to_string()),
                    span: Span::default(),
                }],
                return_type: HirType::Array(Box::new(HirType::Custom("Flow".to_string()))),
                body: crate::hir::HirBlock {
                    stmts: vec![],
                    span: Span::default(),
                },
                is_extern: true,
                span: Span::default(),
            },
        );

        functions.insert(
            "rwx_regions".to_string(),
            HirFn {
                name: "rwx_regions".to_string(),
                params: vec![HirParam {
                    name: "pid".to_string(),
                    ty: HirType::I64,
                    span: Span::default(),
                }],
                return_type: HirType::Array(Box::new(HirType::Custom("Region".to_string()))),
                body: crate::hir::HirBlock {
                    stmts: vec![],
                    span: Span::default(),
                },
                is_extern: true,
                span: Span::default(),
            },
        );

        functions.insert(
            "unbacked_pages".to_string(),
            HirFn {
                name: "unbacked_pages".to_string(),
                params: vec![HirParam {
                    name: "pid".to_string(),
                    ty: HirType::I64,
                    span: Span::default(),
                }],
                return_type: HirType::Array(Box::new(HirType::Custom("Region".to_string()))),
                body: crate::hir::HirBlock {
                    stmts: vec![],
                    span: Span::default(),
                },
                is_extern: true,
                span: Span::default(),
            },
        );

        functions.insert(
            "sha256".to_string(),
            HirFn {
                name: "sha256".to_string(),
                params: vec![HirParam {
                    name: "p".to_string(),
                    ty: HirType::String,
                    span: Span::default(),
                }],
                return_type: HirType::String,
                body: crate::hir::HirBlock {
                    stmts: vec![],
                    span: Span::default(),
                },
                is_extern: true,
                span: Span::default(),
            },
        );

        // 3. Methods on Primitives
        // Process methods
        methods.push(MethodSignature {
            name: "pid".to_string(),
            receiver_ty: HirType::Custom("Process".to_string()),
            params: vec![],
            return_type: HirType::I64,
        });
        methods.push(MethodSignature {
            name: "name".to_string(),
            receiver_ty: HirType::Custom("Process".to_string()),
            params: vec![],
            return_type: HirType::String,
        });
        methods.push(MethodSignature {
            name: "parent".to_string(),
            receiver_ty: HirType::Custom("Process".to_string()),
            params: vec![],
            return_type: HirType::Custom("Process".to_string()),
        });

        // Driver methods
        methods.push(MethodSignature {
            name: "name".to_string(),
            receiver_ty: HirType::Custom("Driver".to_string()),
            params: vec![],
            return_type: HirType::String,
        });
        methods.push(MethodSignature {
            name: "path".to_string(),
            receiver_ty: HirType::Custom("Driver".to_string()),
            params: vec![],
            return_type: HirType::String,
        });

        // Blocklist methods
        methods.push(MethodSignature {
            name: "contains".to_string(),
            receiver_ty: HirType::Custom("Blocklist".to_string()),
            params: vec![HirParam {
                name: "hash".to_string(),
                ty: HirType::String,
                span: Span::default(),
            }],
            return_type: HirType::Bool,
        });

        // Flow methods
        methods.push(MethodSignature {
            name: "dest_port".to_string(),
            receiver_ty: HirType::Custom("Flow".to_string()),
            params: vec![],
            return_type: HirType::I32,
        });
        methods.push(MethodSignature {
            name: "is_unusual_frequency".to_string(),
            receiver_ty: HirType::Custom("Flow".to_string()),
            params: vec![],
            return_type: HirType::Bool,
        });
        methods.push(MethodSignature {
            name: "to_json".to_string(),
            receiver_ty: HirType::Custom("Flow".to_string()),
            params: vec![],
            return_type: HirType::String,
        });

        // Region methods
        methods.push(MethodSignature {
            name: "address".to_string(),
            receiver_ty: HirType::Custom("Region".to_string()),
            params: vec![],
            return_type: HirType::String,
        });
        methods.push(MethodSignature {
            name: "is_file_backed".to_string(),
            receiver_ty: HirType::Custom("Region".to_string()),
            params: vec![],
            return_type: HirType::Bool,
        });

        // 4. Static Functions / Constants
        static_functions.push(StaticFunctionSignature {
            namespace: "Duration".to_string(),
            name: "from_secs".to_string(),
            params: vec![HirParam {
                name: "secs".to_string(),
                ty: HirType::I64,
                span: Span::default(),
            }],
            return_type: HirType::Custom("Duration".to_string()),
        });

        // Severity constants as static zero-arg functions or values
        for variant in ["Critical", "High", "Medium", "Low", "Info"] {
            static_functions.push(StaticFunctionSignature {
                namespace: "Severity".to_string(),
                name: variant.to_string(),
                params: vec![],
                return_type: HirType::Custom("Severity".to_string()),
            });
        }

        Self {
            types,
            functions,
            methods,
            static_functions,
        }
    }

    pub fn lookup_type(&self, name: &str) -> Option<&HirStruct> {
        self.types.get(name)
    }

    pub fn lookup_function(&self, name: &str) -> Option<&HirFn> {
        self.functions.get(name)
    }

    pub fn lookup_method(&self, receiver_ty: &HirType, method_name: &str) -> Option<&MethodSignature> {
        self.methods.iter().find(|m| {
            &m.receiver_ty == receiver_ty && m.name == method_name
        })
    }

    pub fn lookup_static(&self, namespace: &str, name: &str) -> Option<&StaticFunctionSignature> {
        self.static_functions.iter().find(|sf| {
            sf.namespace == namespace && sf.name == name
        })
    }
}

impl Default for Prelude {
    fn default() -> Self {
        Self::new()
    }
}
