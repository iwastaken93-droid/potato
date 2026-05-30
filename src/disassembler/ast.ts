// Expression AST Nodes
export interface IdentifierExpr {
  type: 'Identifier';
  name: string;
}

export interface ConstantExpr {
  type: 'Constant';
  value: string;
}

export interface BinaryExpr {
  type: 'Binary';
  operator: string;
  left: Expression;
  right: Expression;
}

export interface AssignExpr {
  type: 'Assign';
  left: Expression;
  right: Expression;
}

export interface MemoryExpr {
  type: 'Memory';
  base: string;
  index?: string;
  scale?: number;
  offset: number;
  isStructAccess: boolean;
  structName?: string;
}

export interface StackExpr {
  type: 'Stack';
  offset: number;
}

export interface CallExpr {
  type: 'Call';
  callee: string;
  args: Expression[];
}

export type Expression =
  | IdentifierExpr
  | ConstantExpr
  | BinaryExpr
  | AssignExpr
  | MemoryExpr
  | StackExpr
  | CallExpr;

export interface ExpressionVisitor<R> {
  visitIdentifier(expr: IdentifierExpr): R;
  visitConstant(expr: ConstantExpr): R;
  visitBinary(expr: BinaryExpr): R;
  visitAssign(expr: AssignExpr): R;
  visitMemory(expr: MemoryExpr): R;
  visitStack(expr: StackExpr): R;
  visitCall(expr: CallExpr): R;
}

// AST Nodes for Structured Control Flow
export interface BlockNode {
  type: 'Block';
  statements: ASTNode[];
}

export interface StatementNode {
  type: 'Statement';
  expr: Expression;
}

export interface IfNode {
  type: 'If';
  condition: Expression;
  thenBranch: ASTNode;
  elseBranch?: ASTNode;
}

export interface WhileNode {
  type: 'While';
  condition: Expression;
  body: ASTNode;
}

export interface DoWhileNode {
  type: 'DoWhile';
  condition: Expression;
  body: ASTNode;
}

export interface ReturnNode {
  type: 'Return';
  value?: Expression;
}

export type ASTNode =
  | BlockNode
  | StatementNode
  | IfNode
  | WhileNode
  | DoWhileNode
  | ReturnNode;

export interface ASTVisitor<R> {
  visitBlock(node: BlockNode, level: number): R;
  visitStatement(node: StatementNode, level: number): R;
  visitIf(node: IfNode, level: number): R;
  visitWhile(node: WhileNode, level: number): R;
  visitDoWhile(node: DoWhileNode, level: number): R;
  visitReturn(node: ReturnNode, level: number): R;
}
