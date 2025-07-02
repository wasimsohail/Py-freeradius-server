import pytest
from pyfreeradius.unlang.ast import ResultCode, Policy, IfStatement, BinaryOp, AcceptStatement, ModuleCall, AttributeRef, StringLiteral, NumberLiteral
from pyfreeradius.unlang.interpreter import RequestContext, evaluate_policy
from pyfreeradius.unlang.parser import parse_policy


class TestUnlangParser:
    """Test the unlang parser."""

    def test_simple_accept(self):
        policy = parse_policy("accept")
        assert isinstance(policy, Policy)
        assert len(policy.statements) == 1
        assert isinstance(policy.statements[0], AcceptStatement)

    def test_simple_reject(self):
        policy = parse_policy("reject")
        assert isinstance(policy, Policy)
        assert len(policy.statements) == 1
        from pyfreeradius.unlang.ast import RejectStatement
        assert isinstance(policy.statements[0], RejectStatement)

    def test_if_statement(self):
        policy = parse_policy('if (&request:User-Name == "alice") accept')
        assert isinstance(policy, Policy)
        assert len(policy.statements) == 1
        if_stmt = policy.statements[0]
        assert isinstance(if_stmt, IfStatement)
        assert isinstance(if_stmt.condition, BinaryOp)
        assert isinstance(if_stmt.then_stmt, AcceptStatement)

    def test_if_else_statement(self):
        policy = parse_policy('''
        if (&request:User-Name == "alice") {
            accept
        } else {
            reject
        }
        ''')
        assert isinstance(policy, Policy)
        if_stmt = policy.statements[0]
        assert isinstance(if_stmt, IfStatement)
        assert if_stmt.else_stmt is not None

    def test_module_call(self):
        policy = parse_policy("pap")
        assert isinstance(policy, Policy)
        assert len(policy.statements) == 1
        module_call = policy.statements[0]
        assert isinstance(module_call, ModuleCall)
        assert module_call.name == "pap"

    def test_attribute_reference(self):
        policy = parse_policy('if (&request:User-Name) accept')
        if_stmt = policy.statements[0]
        assert isinstance(if_stmt, IfStatement)
        attr_ref = if_stmt.condition
        assert isinstance(attr_ref, AttributeRef)
        assert attr_ref.path == ["request", "User-Name"]

    def test_string_literal(self):
        policy = parse_policy('if ("test" == "test") accept')
        if_stmt = policy.statements[0]
        assert isinstance(if_stmt, IfStatement)
        binary_op = if_stmt.condition
        assert isinstance(binary_op, BinaryOp)
        assert isinstance(binary_op.left, StringLiteral)
        assert binary_op.left.value == "test"

    def test_number_literal(self):
        policy = parse_policy('if (42 == 42) accept')
        if_stmt = policy.statements[0]
        assert isinstance(if_stmt, IfStatement)
        binary_op = if_stmt.condition
        assert isinstance(binary_op, BinaryOp)
        assert isinstance(binary_op.left, NumberLiteral)
        assert binary_op.left.value == 42

    def test_complex_expression(self):
        policy = parse_policy('if (&request:User-Name == "alice" && &request:NAS-IP-Address) accept')
        if_stmt = policy.statements[0]
        assert isinstance(if_stmt, IfStatement)
        and_expr = if_stmt.condition
        assert isinstance(and_expr, BinaryOp)
        assert and_expr.operator == "&&"


class TestUnlangInterpreter:
    """Test the unlang interpreter."""

    def setup_method(self):
        self.context = RequestContext()
        self.context.request["User-Name"] = "alice"
        self.context.request["User-Password"] = "secret"
        self.context.request["NAS-IP-Address"] = "192.168.1.1"

    def test_simple_accept(self):
        policy = parse_policy("accept")
        result = evaluate_policy(policy, self.context)
        assert result == ResultCode.ACCEPT

    def test_simple_reject(self):
        policy = parse_policy("reject")
        result = evaluate_policy(policy, self.context)
        assert result == ResultCode.REJECT

    def test_if_true_accept(self):
        policy = parse_policy('if (&request:User-Name == "alice") accept')
        result = evaluate_policy(policy, self.context)
        assert result == ResultCode.ACCEPT

    def test_if_false_continue(self):
        policy = parse_policy('if (&request:User-Name == "bob") accept')
        result = evaluate_policy(policy, self.context)
        assert result == ResultCode.OK

    def test_if_else_true_branch(self):
        policy = parse_policy('''
        if (&request:User-Name == "alice") {
            accept
        } else {
            reject
        }
        ''')
        result = evaluate_policy(policy, self.context)
        assert result == ResultCode.ACCEPT

    def test_if_else_false_branch(self):
        policy = parse_policy('''
        if (&request:User-Name == "bob") {
            accept
        } else {
            reject
        }
        ''')
        result = evaluate_policy(policy, self.context)
        assert result == ResultCode.REJECT

    def test_logical_and_true(self):
        policy = parse_policy('if (&request:User-Name == "alice" && &request:User-Password) accept')
        result = evaluate_policy(policy, self.context)
        assert result == ResultCode.ACCEPT

    def test_logical_and_false(self):
        policy = parse_policy('if (&request:User-Name == "bob" && &request:User-Password) accept')
        result = evaluate_policy(policy, self.context)
        assert result == ResultCode.OK

    def test_logical_or_true(self):
        policy = parse_policy('if (&request:User-Name == "alice" || &request:User-Name == "bob") accept')
        result = evaluate_policy(policy, self.context)
        assert result == ResultCode.ACCEPT

    def test_logical_or_false(self):
        policy = parse_policy('if (&request:User-Name == "bob" || &request:User-Name == "charlie") accept')
        result = evaluate_policy(policy, self.context)
        assert result == ResultCode.OK

    def test_regex_match(self):
        policy = parse_policy('if (&request:User-Name =~ "^a.*") accept')
        result = evaluate_policy(policy, self.context)
        assert result == ResultCode.ACCEPT

    def test_regex_no_match(self):
        policy = parse_policy('if (&request:User-Name =~ "^b.*") accept')
        result = evaluate_policy(policy, self.context)
        assert result == ResultCode.OK

    def test_module_call_pap(self):
        policy = parse_policy("pap")
        result = evaluate_policy(policy, self.context)
        assert result == ResultCode.OK  # PAP module returns OK when User-Password present

    def test_module_call_sql(self):
        policy = parse_policy("sql")
        result = evaluate_policy(policy, self.context)
        assert result == ResultCode.OK  # SQL module returns OK when User-Name present

    def test_update_statement(self):
        policy = parse_policy('update reply { &Reply-Message := "Welcome" }')
        result = evaluate_policy(policy, self.context)
        assert result == ResultCode.OK
        assert self.context.reply["Reply-Message"] == "Welcome"

    def test_assignment(self):
        policy = parse_policy('&control:Auth-Type := "Accept"')
        result = evaluate_policy(policy, self.context)
        assert result == ResultCode.OK
        assert self.context.control["Auth-Type"] == "Accept"

    def test_complex_policy(self):
        policy = parse_policy('''
        if (&request:User-Name == "alice") {
            &reply:Reply-Message := "Hello Alice"
            accept
        } elsif (&request:User-Name == "bob") {
            &reply:Reply-Message := "Hello Bob"
            accept
        } else {
            &reply:Reply-Message := "Access Denied"
            reject
        }
        ''')
        result = evaluate_policy(policy, self.context)
        assert result == ResultCode.ACCEPT
        assert self.context.reply["Reply-Message"] == "Hello Alice"

    def test_arithmetic_operations(self):
        policy = parse_policy('if (1 + 1 == 2) accept')
        result = evaluate_policy(policy, self.context)
        assert result == ResultCode.ACCEPT

    def test_comparison_operations(self):
        policy = parse_policy('if (10 > 5) accept')
        result = evaluate_policy(policy, self.context)
        assert result == ResultCode.ACCEPT

    def test_unary_not(self):
        policy = parse_policy('if (!(&request:User-Name == "bob")) accept')
        result = evaluate_policy(policy, self.context)
        assert result == ResultCode.ACCEPT
