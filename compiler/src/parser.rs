use crate::ast::*;
use crate::diag::Diagnostic;
use crate::lexer::Token;

pub struct Parser<'a> {
    source: &'a str,
    tokens: Vec<(Token, Span)>,
    pos: usize,
    allow_struct: bool,
}

impl<'a> Parser<'a> {
    pub fn new(source: &'a str, tokens: Vec<(Token, Span)>) -> Self {
        Self {
            source,
            tokens,
            pos: 0,
            allow_struct: true,
        }
    }

    pub fn parse_program(&mut self) -> Result<Program, Diagnostic> {
        let start = self.current_span().start;
        let mut items = Vec::new();
        while !self.is_at_end() {
            items.push(self.parse_item()?);
        }
        let end = if items.is_empty() {
            start
        } else {
            self.prev_span().end
        };
        Ok(Program {
            items,
            span: Span::new(start, end),
        })
    }

    pub fn parse_item(&mut self) -> Result<Item, Diagnostic> {
        match self.peek_token() {
            Some(Token::Fn) => Ok(Item::Fn(self.parse_fn_decl()?)),
            Some(Token::Struct) => Ok(Item::Struct(self.parse_struct_decl()?)),
            Some(Token::Import) => Ok(Item::Import(self.parse_import_decl()?)),
            _ => Err(self.error_expected("top-level declaration ('fn', 'struct', or 'import')")),
        }
    }

    pub fn parse_import_decl(&mut self) -> Result<ImportDecl, Diagnostic> {
        let start = self.expect(Token::Import)?.start;
        let first = self.expect_ident()?;
        let mut path = vec![first];
        while self.check(Token::ColonColon) {
            self.advance();
            path.push(self.expect_ident()?);
        }
        let end = self.expect(Token::Semi)?.end;
        Ok(ImportDecl {
            path,
            span: Span::new(start, end),
        })
    }

    pub fn parse_struct_decl(&mut self) -> Result<StructDecl, Diagnostic> {
        let start = self.expect(Token::Struct)?.start;
        let name = self.expect_ident()?;
        self.expect(Token::LBrace)?;
        let mut fields = Vec::new();
        while !self.check(Token::RBrace) && !self.is_at_end() {
            let f_start = self.current_span().start;
            let f_name = self.expect_ident()?;
            self.expect(Token::Colon)?;
            let f_ty = self.parse_type()?;
            let f_end = self.prev_span().end;
            fields.push(StructField {
                name: f_name,
                ty: f_ty,
                span: Span::new(f_start, f_end),
            });
            if self.check(Token::Comma) {
                self.advance();
            } else {
                break;
            }
        }
        let end = self.expect(Token::RBrace)?.end;
        Ok(StructDecl {
            name,
            fields,
            span: Span::new(start, end),
        })
    }

    pub fn parse_fn_decl(&mut self) -> Result<FnDecl, Diagnostic> {
        let start = self.expect(Token::Fn)?.start;
        let name = self.expect_ident()?;
        self.expect(Token::LParen)?;
        let params = self.parse_param_list()?;
        self.expect(Token::RParen)?;

        // Default return type in JOCKY v0.1 is i32
        let return_type = if self.check(Token::Arrow) {
            self.advance();
            self.parse_type()?
        } else {
            Type::I32
        };

        let body = self.parse_block()?;
        let end = body.span.end;

        Ok(FnDecl {
            name,
            params,
            return_type,
            body,
            span: Span::new(start, end),
        })
    }

    pub fn parse_param_list(&mut self) -> Result<Vec<Param>, Diagnostic> {
        let mut params = Vec::new();
        while !self.check(Token::RParen) && !self.is_at_end() {
            params.push(self.parse_param()?);
            if self.check(Token::Comma) {
                self.advance();
            } else {
                break;
            }
        }
        Ok(params)
    }

    pub fn parse_param(&mut self) -> Result<Param, Diagnostic> {
        let start = self.current_span().start;
        let name = self.expect_ident()?;
        self.expect(Token::Colon)?;
        let ty = self.parse_type()?;
        let end = self.prev_span().end;
        Ok(Param {
            name,
            ty,
            span: Span::new(start, end),
        })
    }

    pub fn parse_type(&mut self) -> Result<Type, Diagnostic> {
        if self.check(Token::LBracket) {
            self.advance();
            let inner = self.parse_type()?;
            self.expect(Token::RBracket)?;
            return Ok(Type::Array(Box::new(inner)));
        }

        let name = self.expect_ident()?;
        match name.as_str() {
            "i32" => Ok(Type::I32),
            "i64" => Ok(Type::I64),
            "u32" => Ok(Type::U32),
            "u64" => Ok(Type::U64),
            "f64" => Ok(Type::F64),
            "bool" => Ok(Type::Bool),
            "string" => Ok(Type::String),
            _ => Ok(Type::Custom(name)),
        }
    }

    pub fn parse_block(&mut self) -> Result<Block, Diagnostic> {
        let start = self.expect(Token::LBrace)?.start;
        let mut stmts = Vec::new();
        while !self.check(Token::RBrace) && !self.is_at_end() {
            stmts.push(self.parse_stmt()?);
        }
        let end = self.expect(Token::RBrace)?.end;
        Ok(Block {
            stmts,
            span: Span::new(start, end),
        })
    }

    pub fn parse_stmt(&mut self) -> Result<Stmt, Diagnostic> {
        match self.peek_token() {
            Some(Token::Let) => self.parse_let_stmt(),
            Some(Token::Return) => self.parse_return_stmt(),
            Some(Token::If) => self.parse_if_stmt(),
            Some(Token::For) => self.parse_for_stmt(),
            Some(Token::While) => self.parse_while_stmt(),
            _ => self.parse_expr_or_assign(),
        }
    }

    pub fn parse_let_stmt(&mut self) -> Result<Stmt, Diagnostic> {
        let start = self.expect(Token::Let)?.start;
        let is_mut = if self.check(Token::Mut) {
            self.advance();
            true
        } else {
            false
        };
        let name = self.expect_ident()?;
        let ty = if self.check(Token::Colon) {
            self.advance();
            Some(self.parse_type()?)
        } else {
            None
        };
        let init = if self.check(Token::Eq) {
            self.advance();
            Some(self.parse_expr()?)
        } else {
            None
        };
        let end = self.expect(Token::Semi)?.end;
        Ok(Stmt::Let {
            name,
            is_mut,
            ty,
            init,
            span: Span::new(start, end),
        })
    }

    pub fn parse_return_stmt(&mut self) -> Result<Stmt, Diagnostic> {
        let start = self.expect(Token::Return)?.start;
        let value = if self.check(Token::Semi) {
            None
        } else {
            Some(self.parse_expr()?)
        };
        let end = self.expect(Token::Semi)?.end;
        Ok(Stmt::Return {
            value,
            span: Span::new(start, end),
        })
    }

    pub fn parse_expr_no_struct(&mut self) -> Result<Expr, Diagnostic> {
        let old = self.allow_struct;
        self.allow_struct = false;
        let res = self.parse_expr();
        self.allow_struct = old;
        res
    }

    pub fn parse_if_stmt(&mut self) -> Result<Stmt, Diagnostic> {
        let start = self.expect(Token::If)?.start;
        let cond = self.parse_expr_no_struct()?;
        let then_branch = self.parse_block()?;
        let mut else_branch = None;

        if self.check(Token::Else) {
            self.advance();
            if self.check(Token::If) {
                let nested_if = self.parse_if_stmt()?;
                else_branch = Some(ElseBranch::If(Box::new(nested_if)));
            } else {
                let else_block = self.parse_block()?;
                else_branch = Some(ElseBranch::Block(else_block));
            }
        }

        let end = match &else_branch {
            Some(ElseBranch::Block(b)) => b.span.end,
            Some(ElseBranch::If(s)) => s.span().end,
            None => then_branch.span.end,
        };

        Ok(Stmt::If {
            cond,
            then_branch,
            else_branch,
            span: Span::new(start, end),
        })
    }

    pub fn parse_for_stmt(&mut self) -> Result<Stmt, Diagnostic> {
        let start = self.expect(Token::For)?.start;
        let var = self.expect_ident()?;
        self.expect(Token::In)?;
        let iter = self.parse_expr_no_struct()?;
        let body = self.parse_block()?;
        let end = body.span.end;

        Ok(Stmt::For {
            var,
            iter,
            body,
            span: Span::new(start, end),
        })
    }

    pub fn parse_while_stmt(&mut self) -> Result<Stmt, Diagnostic> {
        let start = self.expect(Token::While)?.start;
        let cond = self.parse_expr_no_struct()?;
        let body = self.parse_block()?;
        let end = body.span.end;

        Ok(Stmt::While {
            cond,
            body,
            span: Span::new(start, end),
        })
    }

    pub fn parse_expr_or_assign(&mut self) -> Result<Stmt, Diagnostic> {
        let expr = self.parse_expr()?;

        if self.check(Token::Eq) {
            self.advance(); // consume '='
            let target = self.extract_assign_target(&expr)?;
            let value = self.parse_expr()?;
            let end = self.expect(Token::Semi)?.end;
            let full_span = Span::new(target.span.start, end);
            Ok(Stmt::Assign {
                target,
                value,
                span: full_span,
            })
        } else {
            let end = self.expect(Token::Semi)?.end;
            let full_span = Span::new(expr.span().start, end);
            Ok(Stmt::Expr {
                expr,
                span: full_span,
            })
        }
    }

    pub fn extract_assign_target(&self, expr: &Expr) -> Result<AssignTarget, Diagnostic> {
        match expr {
            Expr::Path { segments, span } if segments.len() == 1 => Ok(AssignTarget {
                base: segments[0].clone(),
                fields: Vec::new(),
                span: *span,
            }),
            Expr::FieldAccess { .. } => {
                let mut current = expr;
                let mut fields = Vec::new();
                while let Expr::FieldAccess { receiver, field, .. } = current {
                    fields.push(field.clone());
                    current = receiver;
                }
                fields.reverse();
                if let Expr::Path { segments, .. } = current {
                    if segments.len() == 1 {
                        return Ok(AssignTarget {
                            base: segments[0].clone(),
                            fields,
                            span: expr.span(),
                        });
                    }
                }
                Err(Diagnostic::parser(
                    "invalid assignment target: field projection must root at a single identifier",
                    expr.span(),
                ))
            }
            _ => Err(Diagnostic::parser(
                "invalid assignment target: left-hand side must be an identifier or field projection",
                expr.span(),
            )),
        }
    }

    pub fn parse_expr(&mut self) -> Result<Expr, Diagnostic> {
        self.parse_expr_bp(0)
    }

    pub fn parse_expr_bp(&mut self, min_bp: u8) -> Result<Expr, Diagnostic> {
        // Prefix operators or primary
        let mut left = if let Some(tok) = self.peek_token() {
            match tok {
                Token::Bang | Token::Not => {
                    let start = self.advance().1.start;
                    let operand = self.parse_expr_bp(15)?;
                    let end = operand.span().end;
                    Expr::Unary {
                        op: UnaryOp::Not,
                        operand: Box::new(operand),
                        span: Span::new(start, end),
                    }
                }
                Token::Minus => {
                    let start = self.advance().1.start;
                    let operand = self.parse_expr_bp(15)?;
                    let end = operand.span().end;
                    Expr::Unary {
                        op: UnaryOp::Neg,
                        operand: Box::new(operand),
                        span: Span::new(start, end),
                    }
                }
                _ => self.parse_postfix()?,
            }
        } else {
            return Err(self.error_expected("expression"));
        };

        // Infix / binary operators
        while let Some(tok) = self.peek_token() {
            let (op, l_bp, r_bp) = match tok {
                Token::PipePipe | Token::Or => (BinaryOp::Or, 1, 2),
                Token::AmpAmp | Token::And => (BinaryOp::And, 3, 4),
                Token::EqEq => (BinaryOp::Eq, 5, 6),
                Token::BangEq => (BinaryOp::Ne, 5, 6),
                Token::Lt => (BinaryOp::Lt, 7, 8),
                Token::Le => (BinaryOp::Le, 7, 8),
                Token::Gt => (BinaryOp::Gt, 7, 8),
                Token::Ge => (BinaryOp::Ge, 7, 8),
                Token::In => (BinaryOp::In, 9, 10),
                Token::Plus => (BinaryOp::Add, 11, 12),
                Token::Minus => (BinaryOp::Sub, 11, 12),
                Token::Star => (BinaryOp::Mul, 13, 14),
                Token::Slash => (BinaryOp::Div, 13, 14),
                Token::Percent => (BinaryOp::Rem, 13, 14),
                _ => break,
            };

            if l_bp < min_bp {
                break;
            }

            self.advance(); // consume binary operator
            let right = self.parse_expr_bp(r_bp)?;
            let span = Span::new(left.span().start, right.span().end);
            left = Expr::Binary {
                op,
                left: Box::new(left),
                right: Box::new(right),
                span,
            };
        }

        Ok(left)
    }

    pub fn parse_postfix(&mut self) -> Result<Expr, Diagnostic> {
        let mut expr = self.parse_primary()?;

        loop {
            if self.check(Token::LParen) {
                // Call
                self.advance();
                let args = self.parse_args()?;
                let end = self.expect(Token::RParen)?.end;
                let span = Span::new(expr.span().start, end);
                expr = Expr::Call {
                    callee: Box::new(expr),
                    args,
                    span,
                };
            } else if self.check(Token::Dot) {
                self.advance();
                let field_name = self.expect_ident()?;
                if self.check(Token::LParen) {
                    // Method call
                    self.advance();
                    let args = self.parse_args()?;
                    let end = self.expect(Token::RParen)?.end;
                    let span = Span::new(expr.span().start, end);
                    expr = Expr::MethodCall {
                        receiver: Box::new(expr),
                        method: field_name,
                        args,
                        span,
                    };
                } else {
                    // Field access
                    let end = self.prev_span().end;
                    let span = Span::new(expr.span().start, end);
                    expr = Expr::FieldAccess {
                        receiver: Box::new(expr),
                        field: field_name,
                        span,
                    };
                }
            } else if self.check(Token::LBracket) {
                // Index
                self.advance();
                let index = self.parse_expr()?;
                let end = self.expect(Token::RBracket)?.end;
                let span = Span::new(expr.span().start, end);
                expr = Expr::Index {
                    receiver: Box::new(expr),
                    index: Box::new(index),
                    span,
                };
            } else {
                break;
            }
        }

        Ok(expr)
    }

    pub fn parse_primary(&mut self) -> Result<Expr, Diagnostic> {
        let (tok, span) = match self.peek() {
            Some(t) => t.clone(),
            None => return Err(self.error_expected("expression")),
        };

        match tok {
            Token::IntLit(val) => {
                self.advance();
                Ok(Expr::Literal {
                    lit: Literal::Int(val),
                    span,
                })
            }
            Token::FloatLit(val) => {
                self.advance();
                Ok(Expr::Literal {
                    lit: Literal::Float(val),
                    span,
                })
            }
            Token::StringLit(val) => {
                self.advance();
                Ok(Expr::Literal {
                    lit: Literal::String(val),
                    span,
                })
            }
            Token::True => {
                self.advance();
                Ok(Expr::Literal {
                    lit: Literal::Bool(true),
                    span,
                })
            }
            Token::False => {
                self.advance();
                Ok(Expr::Literal {
                    lit: Literal::Bool(false),
                    span,
                })
            }
            Token::LBracket => self.parse_array_literal(),
            Token::LParen => {
                self.advance();
                let expr = self.parse_expr()?;
                let end = self.expect(Token::RParen)?.end;
                let full_span = Span::new(span.start, end);
                // Return grouped expression with parenthesized span
                Ok(match expr {
                    Expr::Literal { lit, .. } => Expr::Literal { lit, span: full_span },
                    Expr::Path { segments, .. } => Expr::Path { segments, span: full_span },
                    Expr::Array { elements, .. } => Expr::Array { elements, span: full_span },
                    Expr::StructInit { name, fields, .. } => Expr::StructInit { name, fields, span: full_span },
                    Expr::Unary { op, operand, .. } => Expr::Unary { op, operand, span: full_span },
                    Expr::Binary { op, left, right, .. } => Expr::Binary { op, left, right, span: full_span },
                    Expr::Call { callee, args, .. } => Expr::Call { callee, args, span: full_span },
                    Expr::MethodCall { receiver, method, args, .. } => Expr::MethodCall { receiver, method, args, span: full_span },
                    Expr::FieldAccess { receiver, field, .. } => Expr::FieldAccess { receiver, field, span: full_span },
                    Expr::Index { receiver, index, .. } => Expr::Index { receiver, index, span: full_span },
                })
            }
            Token::Ident(name) => {
                self.advance();
                let mut segments = vec![name.clone()];
                while self.check(Token::ColonColon) {
                    self.advance();
                    segments.push(self.expect_ident()?);
                }

                // If single identifier followed by '{' and struct init is permitted in this context
                if self.allow_struct && segments.len() == 1 && self.check(Token::LBrace) {
                    self.parse_struct_init(name, span)
                } else {
                    let end = self.prev_span().end;
                    Ok(Expr::Path {
                        segments,
                        span: Span::new(span.start, end),
                    })
                }
            }
            _ => Err(self.error_expected("expression (literal, identifier, path, array, or parenthesized term)")),
        }
    }

    pub fn parse_array_literal(&mut self) -> Result<Expr, Diagnostic> {
        let start = self.expect(Token::LBracket)?.start;
        let mut elements = Vec::new();
        while !self.check(Token::RBracket) && !self.is_at_end() {
            elements.push(self.parse_expr()?);
            if self.check(Token::Comma) {
                self.advance();
            } else {
                break;
            }
        }
        let end = self.expect(Token::RBracket)?.end;
        Ok(Expr::Array {
            elements,
            span: Span::new(start, end),
        })
    }

    pub fn parse_struct_init(&mut self, name: String, start_span: Span) -> Result<Expr, Diagnostic> {
        self.expect(Token::LBrace)?;
        let mut fields = Vec::new();
        while !self.check(Token::RBrace) && !self.is_at_end() {
            let f_name = self.expect_ident()?;
            self.expect(Token::Colon)?;
            let f_val = self.parse_expr()?;
            fields.push((f_name, f_val));
            if self.check(Token::Comma) {
                self.advance();
            } else {
                break;
            }
        }
        let end = self.expect(Token::RBrace)?.end;
        Ok(Expr::StructInit {
            name,
            fields,
            span: Span::new(start_span.start, end),
        })
    }

    pub fn parse_args(&mut self) -> Result<Vec<Expr>, Diagnostic> {
        let mut args = Vec::new();
        while !self.check(Token::RParen) && !self.is_at_end() {
            args.push(self.parse_expr()?);
            if self.check(Token::Comma) {
                self.advance();
            } else {
                break;
            }
        }
        Ok(args)
    }

    // Helper methods
    fn peek(&self) -> Option<&(Token, Span)> {
        self.tokens.get(self.pos)
    }

    fn peek_token(&self) -> Option<&Token> {
        self.tokens.get(self.pos).map(|(t, _)| t)
    }

    fn check(&self, expected: Token) -> bool {
        match self.peek_token() {
            Some(t) => *t == expected,
            None => false,
        }
    }

    fn advance(&mut self) -> (Token, Span) {
        let tok = self.tokens[self.pos].clone();
        self.pos += 1;
        tok
    }

    fn is_at_end(&self) -> bool {
        self.pos >= self.tokens.len()
    }

    fn current_span(&self) -> Span {
        self.tokens
            .get(self.pos)
            .map(|(_, s)| *s)
            .unwrap_or_else(|| self.prev_span())
    }

    fn prev_span(&self) -> Span {
        if self.pos > 0 && self.pos - 1 < self.tokens.len() {
            self.tokens[self.pos - 1].1
        } else {
            Span::new(self.source.len(), self.source.len())
        }
    }

    fn expect(&mut self, expected: Token) -> Result<Span, Diagnostic> {
        if self.check(expected.clone()) {
            Ok(self.advance().1)
        } else {
            Err(self.error_expected(&format!("{:?}", expected)))
        }
    }

    fn expect_ident(&mut self) -> Result<String, Diagnostic> {
        match self.peek_token() {
            Some(Token::Ident(name)) => {
                let name = name.clone();
                self.advance();
                Ok(name)
            }
            _ => Err(self.error_expected("identifier")),
        }
    }

    fn error_expected(&self, expected: &str) -> Diagnostic {
        let (span, found_desc) = match self.peek() {
            Some((tok, span)) => (*span, format!("{:?}", tok)),
            None => {
                let len = self.source.len();
                (Span::new(len, len), "end of file".to_string())
            }
        };

        let (line, col, _) = crate::diag::get_line_and_col(self.source, span.start);
        Diagnostic::parser(
            format!(
                "line {}:{}: expected {}, found {}",
                line, col, expected, found_desc
            ),
            span,
        )
    }
}
