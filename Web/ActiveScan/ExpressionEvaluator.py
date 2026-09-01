#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""插件表达式求值器

采用 Python 抽象语法树(AST)实现受控求值，不使用 eval/exec，
避免插件中的恶意表达式对主程序造成安全影响。

支持 nuclei 风格的表达式，例如：
    response.status == 200 && response.body.bcontains(b"uid") && "root:[x*]:0:0:".bmatches(response.body)
"""
import ast
import re
import operator
from ClassCongregation import ErrorLog


class ExpressionError(Exception):  # 表达式求值异常，由调用方降级处理
    pass


def _to_bytes(value) -> bytes:  # 统一转换为字节类型，便于做包含与正则匹配
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    if value is None:
        return b""
    if isinstance(value, int):
        return str(value).encode("utf-8")
    return str(value).encode("utf-8", "ignore")


def _to_text(value) -> str:  # 统一转换为文本类型，正则匹配在文本上进行
    if isinstance(value, bytes):
        return value.decode("utf-8", "ignore")
    return str(value)


def bcontains(target, match) -> bool:  # 目标字节串中是否包含指定内容
    return _to_bytes(match) in _to_bytes(target)


def bmatches(pattern, target) -> bool:  # 用正则匹配目标，命中返回True
    try:
        return re.search(_to_text(pattern), _to_text(target)) is not None
    except re.error as e:
        raise ExpressionError("正则表达式非法: %s" % e)


def bsubmatch(pattern, target) -> bytes:  # 返回正则第一个捕获组，未命中返回空字节串
    try:
        match = re.search(_to_text(pattern), _to_text(target))
    except re.error as e:
        raise ExpressionError("正则表达式非法: %s" % e)
    if match and match.groups():
        return (match.group(1) or "").encode("utf-8", "ignore")
    return b""


def icontains(target, match) -> bool:  # 忽略大小写包含判断
    return _to_text(match).lower() in _to_text(target).lower()


def contains(target, match) -> bool:  # 文本包含判断
    return _to_text(match) in _to_text(target)


def matches(pattern, target) -> bool:  # 文本正则匹配
    return bmatches(pattern, target)


class ResponseContext:  # 供表达式访问的响应上下文
    def __init__(self, status_code, body, headers, url=""):
        self.status = status_code
        self.body = _to_bytes(body)
        self.headers = headers if isinstance(headers, dict) else {}
        self.url = url

    def GetHeader(self, name):  # 按名称读取响应头，不区分大小写
        if not self.headers:
            return ""
        for key, value in self.headers.items():
            if str(key).lower() == str(name).lower():
                return value
        return ""


# 表达式中允许调用的函数白名单
FUNCTION_TABLE = {
    "bcontains": bcontains,
    "bmatches": bmatches,
    "bsubmatch": bsubmatch,
    "icontains": icontains,
    "contains": contains,
    "matches": matches,
}

# 比较运算符映射
COMPARE_OPERATORS = {
    ast.Eq: operator.eq,
    ast.NotEq: operator.ne,
    ast.Lt: operator.lt,
    ast.LtE: operator.le,
    ast.Gt: operator.gt,
    ast.GtE: operator.ge,
    ast.In: lambda a, b: a in b,
    ast.NotIn: lambda a, b: a not in b,
}


class ExpressionEvaluator:
    """插件命中表达式求值器

    求值失败时返回 False，由扫描执行器跳过该插件，
    确保单个异常插件不会中断整个扫描任务。
    """

    def __init__(self):
        self.cache = {}  # 表达式 -> 已编译AST，避免重复解析

    @staticmethod
    def Normalize(expression: str) -> str:
        """将 nuclei 风格运算符转换为 Python 语法"""
        if not expression:
            return ""
        result = expression.replace("&&", " and ").replace("||", " or ")
        # 将单目取反 ! 转换为 not，需排除 != 的情况
        result = re.sub(r'(?<!=)!(?!=)', ' not ', result)
        # 必须去除首尾空格，否则表达式以 not 开头时会被AST判定为非法缩进
        return result.strip()

    def Compile(self, expression: str):
        """编译表达式为AST，失败时抛出 ExpressionError"""
        if expression in self.cache:
            return self.cache[expression]
        normalized = self.Normalize(expression)
        if not normalized.strip():
            raise ExpressionError("表达式为空")
        try:
            tree = ast.parse(normalized, mode="eval")
        except SyntaxError as e:
            raise ExpressionError("表达式语法错误: %s" % e)
        self.cache[expression] = tree
        return tree

    def evaluate(self, expression: str, response_ctx: ResponseContext) -> bool:
        """求值表达式，返回True表示插件命中"""
        try:
            tree = self.Compile(expression)
            result = self._EvalNode(tree.body, response_ctx)
            return bool(result)
        except ExpressionError as e:
            ErrorLog().Write("插件表达式求值失败(已跳过该插件): %s | 表达式: %s" % (e, expression))
            return False
        except Exception as e:
            ErrorLog().Write("插件表达式求值异常(已跳过该插件): %s | 表达式: %s" % (e, expression))
            return False

    def _EvalNode(self, node, ctx):
        if isinstance(node, ast.Constant):
            return node.value

        if isinstance(node, ast.Name):
            if node.id == "response":
                return ctx
            raise ExpressionError("不允许使用变量: %s" % node.id)

        if isinstance(node, ast.Attribute):
            owner = self._EvalNode(node.value, ctx)
            attr = node.attr
            if isinstance(owner, ResponseContext):
                if attr in ("status", "body", "headers", "url"):
                    return getattr(owner, attr)
                if attr == "text":
                    return _to_text(owner.body)
                raise ExpressionError("response 不支持属性: %s" % attr)
            if isinstance(owner, dict) and attr in owner:
                return owner[attr]
            raise ExpressionError("不支持的属性访问: %s" % attr)

        if isinstance(node, ast.Subscript):
            owner = self._EvalNode(node.value, ctx)
            key = self._EvalNode(node.slice, ctx)
            try:
                return owner[key]
            except Exception:
                return ""

        if isinstance(node, ast.Call):
            return self._EvalCall(node, ctx)

        if isinstance(node, ast.BoolOp):
            values = [self._EvalNode(v, ctx) for v in node.values]
            if isinstance(node.op, ast.And):
                return all(bool(v) for v in values)
            if isinstance(node.op, ast.Or):
                return any(bool(v) for v in values)
            raise ExpressionError("不支持的布尔运算")

        if isinstance(node, ast.UnaryOp):
            operand = self._EvalNode(node.operand, ctx)
            if isinstance(node.op, ast.Not):
                return not bool(operand)
            if isinstance(node.op, ast.USub):
                return -operand
            raise ExpressionError("不支持的一元运算")

        if isinstance(node, ast.Compare):
            left = self._EvalNode(node.left, ctx)
            for op, comparator in zip(node.ops, node.comparators):
                right = self._EvalNode(comparator, ctx)
                func = COMPARE_OPERATORS.get(type(op))
                if func is None:
                    raise ExpressionError("不支持的比较运算符")
                # 字节与文本混合时统一为文本比较，避免类型差异导致误判
                if isinstance(left, (bytes, bytearray)) or isinstance(right, (bytes, bytearray)):
                    left = _to_text(left)
                    right = _to_text(right)
                if not func(left, right):
                    return False
                left = right
            return True

        if isinstance(node, ast.BinOp):
            left = self._EvalNode(node.left, ctx)
            right = self._EvalNode(node.right, ctx)
            if isinstance(node.op, ast.Add):
                return _to_text(left) + _to_text(right)
            raise ExpressionError("不支持的二元运算")

        raise ExpressionError("不支持的语法结构: %s" % type(node).__name__)

    def _EvalCall(self, node, ctx):
        """支持两类调用：白名单函数调用与 response.xxx() 成员调用"""
        func = node.func
        args = [self._EvalNode(a, ctx) for a in node.args]

        if isinstance(func, ast.Attribute):
            owner = self._EvalNode(func.value, ctx)
            name = func.attr
            if name == "GetHeader" and isinstance(owner, ResponseContext):
                return owner.GetHeader(args[0]) if args else ""
            handler = FUNCTION_TABLE.get(name)
            if handler is None:
                raise ExpressionError("不允许调用函数: %s" % name)
            return handler(owner, *args)

        if isinstance(func, ast.Name):
            handler = FUNCTION_TABLE.get(func.id)
            if handler is None:
                raise ExpressionError("不允许调用函数: %s" % func.id)
            return handler(*args)

        raise ExpressionError("不支持的调用形式")
