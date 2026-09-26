use crate::ast::Program;

pub fn diversify_ast(ast: &mut Program, seed: u64) {
    // Reverse function order or permute statements based on seed
    if seed % 2 == 1 {
        ast.functions.reverse();
    }
}
