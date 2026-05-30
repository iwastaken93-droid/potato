import {
  ASTNode,
  ASTVisitor,
  Expression,
  ExpressionVisitor,
  IdentifierExpr,
  ConstantExpr,
  BinaryExpr,
  AssignExpr,
  MemoryExpr,
  StackExpr,
  CallExpr,
  BlockNode,
  StatementNode,
  IfNode,
  WhileNode,
  DoWhileNode,
  ReturnNode,
} from './ast.js';

// AST and Expression Printer implementing Visitor Pattern
export class ASTPrinter
  implements ASTVisitor<string>, ExpressionVisitor<string>
{
  private indent(level: number): string {
    return '  '.repeat(level);
  }

  public render(node: ASTNode, level: number = 0): string {
    return this.visitNode(node, level);
  }

  private visitNode(node: ASTNode, level: number): string {
    switch (node.type) {
      case 'Block':
        return this.visitBlock(node, level);
      case 'Statement':
        return this.visitStatement(node, level);
      case 'If':
        return this.visitIf(node, level);
      case 'While':
        return this.visitWhile(node, level);
      case 'DoWhile':
        return this.visitDoWhile(node, level);
      case 'Return':
        return this.visitReturn(node, level);
    }
  }

  public renderExpr(expr: Expression): string {
    switch (expr.type) {
      case 'Identifier':
        return this.visitIdentifier(expr);
      case 'Constant':
        return this.visitConstant(expr);
      case 'Binary':
        return this.visitBinary(expr);
      case 'Assign':
        return this.visitAssign(expr);
      case 'Memory':
        return this.visitMemory(expr);
      case 'Stack':
        return this.visitStack(expr);
      case 'Call':
        return this.visitCall(expr);
    }
  }

  visitBlock(node: BlockNode, level: number): string {
    return node.statements
      .map((s) => this.visitNode(s, level))
      .filter((s) => s.trim().length > 0)
      .join('\n');
  }

  visitStatement(node: StatementNode, level: number): string {
    return `${this.indent(level)}${this.renderExpr(node.expr)};`;
  }

  visitIf(node: IfNode, level: number): string {
    const cond = this.renderExpr(node.condition);
    let result = `${this.indent(level)}if (${cond}) {\n${this.visitNode(node.thenBranch, level + 1)}\n${this.indent(level)}}`;
    if (
      node.elseBranch &&
      node.elseBranch.type === 'Block' &&
      node.elseBranch.statements.length > 0
    ) {
      result += ` else {\n${this.visitNode(node.elseBranch, level + 1)}\n${this.indent(level)}}`;
    }
    return result;
  }

  visitWhile(node: WhileNode, level: number): string {
    return `${this.indent(level)}while (${this.renderExpr(node.condition)}) {\n${this.visitNode(node.body, level + 1)}\n${this.indent(level)}}`;
  }

  visitDoWhile(node: DoWhileNode, level: number): string {
    return `${this.indent(level)}do {\n${this.visitNode(node.body, level + 1)}\n${this.indent(level)}} while (${this.renderExpr(node.condition)});`;
  }

  visitReturn(node: ReturnNode, level: number): string {
    return `${this.indent(level)}return${node.value ? ` ${this.renderExpr(node.value)}` : ''};`;
  }

  visitIdentifier(expr: IdentifierExpr): string {
    return expr.name;
  }

  visitConstant(expr: ConstantExpr): string {
    return expr.value;
  }

  visitBinary(expr: BinaryExpr): string {
    return `${this.renderExpr(expr.left)} ${expr.operator} ${this.renderExpr(expr.right)}`;
  }

  visitAssign(expr: AssignExpr): string {
    return `${this.renderExpr(expr.left)} = ${this.renderExpr(expr.right)}`;
  }

  visitMemory(expr: MemoryExpr): string {
    if (expr.index && expr.scale) {
      return `${expr.base}[${expr.index}]`;
    }
    if (expr.isStructAccess) {
      return `${expr.base}->field_${expr.offset}`;
    }
    return `*( ${expr.base} + ${expr.offset} )`;
  }

  visitStack(expr: StackExpr): string {
    return `local_${Math.abs(expr.offset || 0)}`;
  }

  visitCall(expr: CallExpr): string {
    return `${expr.callee}(${expr.args.map((a) => this.renderExpr(a)).join(', ')})`;
  }
}
