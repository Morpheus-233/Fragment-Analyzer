"""Core data model: SourceRange, FragmentInput, Token, Diagnostic, semantic types.

Offset convention: [start, end) in Unicode code points (Python str indices).
Lines and columns are 1-based. Column counts code points, not bytes.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class SourceRange:
    start_offset: int
    end_offset: int
    start_line: int
    start_column: int
    end_line: int
    end_column: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "start": self.start_offset,
            "end": self.end_offset,
            "start_line": self.start_line,
            "start_column": self.start_column,
            "end_line": self.end_line,
            "end_column": self.end_column,
        }

    def contains(self, other: "SourceRange") -> bool:
        return self.start_offset <= other.start_offset and other.end_offset <= self.end_offset

    def is_valid(self, source_len: int) -> bool:
        return (
            0 <= self.start_offset <= self.end_offset <= source_len
            and self.start_line >= 1
            and self.start_column >= 1
            and self.end_line >= 1
            and self.end_column >= 1
        )


@dataclass
class FragmentInput:
    source: str
    source_id: str = "<fragment>"
    start_offset: int = 0
    end_offset: Optional[int] = None
    context: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.end_offset is None:
            self.end_offset = len(self.source)
        if not (0 <= self.start_offset <= self.end_offset <= len(self.source)):
            raise ValueError("invalid start/end offsets for given source")

    @property
    def text(self) -> str:
        return self.source[self.start_offset:self.end_offset]


# ---- Tokens ----

class TokenKind:
    EOF = "EOF"
    IDENTIFIER = "IDENTIFIER"
    NUMBER = "NUMBER"
    STRING = "STRING"
    TRUE = "TRUE"
    FALSE = "FALSE"
    NULL = "NULL"
    LET = "LET"
    FN = "FN"
    IF = "IF"
    ELSE = "ELSE"
    RETURN = "RETURN"
    PLUS = "PLUS"
    MINUS = "MINUS"
    STAR = "STAR"
    SLASH = "SLASH"
    PERCENT = "PERCENT"
    EQUAL = "EQUAL"
    EQUAL_EQUAL = "EQUAL_EQUAL"
    NOT_EQUAL = "NOT_EQUAL"
    LESS = "LESS"
    LESS_EQUAL = "LESS_EQUAL"
    GREATER = "GREATER"
    GREATER_EQUAL = "GREATER_EQUAL"
    AND = "AND"
    OR = "OR"
    NOT = "NOT"
    OPEN_PAREN = "OPEN_PAREN"
    CLOSE_PAREN = "CLOSE_PAREN"
    OPEN_BRACKET = "OPEN_BRACKET"
    CLOSE_BRACKET = "CLOSE_BRACKET"
    OPEN_BRACE = "OPEN_BRACE"
    CLOSE_BRACE = "CLOSE_BRACE"
    COMMA = "COMMA"
    DOT = "DOT"
    COLON = "COLON"
    SEMICOLON = "SEMICOLON"
    COMMENT = "COMMENT"
    UNKNOWN = "UNKNOWN"


KEYWORDS: Dict[str, str] = {
    "let": TokenKind.LET,
    "fn": TokenKind.FN,
    "if": TokenKind.IF,
    "else": TokenKind.ELSE,
    "return": TokenKind.RETURN,
    "true": TokenKind.TRUE,
    "false": TokenKind.FALSE,
    "null": TokenKind.NULL,
}


@dataclass
class Token:
    kind: str
    lexeme: str
    range: SourceRange
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "kind": self.kind,
            "lexeme": self.lexeme,
            "range": self.range.to_dict(),
        }
        if self.metadata:
            d["metadata"] = dict(sorted(self.metadata.items()))
        return d


# ---- Diagnostics ----

class Severity:
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


class DiagCode:
    UNEXPECTED_CHARACTER = "FRAG001"
    UNEXPECTED_TOKEN = "FRAG002"
    UNTERMINATED_STRING = "FRAG003"
    UNCLOSED_DELIMITER = "FRAG004"
    MISSING_OPERAND = "FRAG005"
    MISSING_EXPRESSION = "FRAG006"
    INVALID_LITERAL = "FRAG007"
    UNKNOWN_CONSTRUCT = "FRAG008"
    INCOMPLETE_FRAGMENT = "FRAG009"
    UNEXPECTED_CLOSING_DELIMITER = "FRAG010"
    MISMATCHED_DELIMITER = "FRAG011"


@dataclass
class Diagnostic:
    severity: str
    code: str
    message: str
    range: SourceRange
    expected: List[str] = field(default_factory=list)
    actual: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "severity": self.severity,
            "code": self.code,
            "message": self.message,
            "range": self.range.to_dict(),
            "expected": list(self.expected),
            "actual": self.actual,
        }


# ---- Classification / status ----

class FragmentType:
    EMPTY = "empty"
    IDENTIFIER = "identifier"
    LITERAL = "literal"
    EXPRESSION = "expression"
    CALL_EXPRESSION = "call_expression"
    MEMBER_EXPRESSION = "member_expression"
    STATEMENT = "statement"
    DECLARATION = "declaration"
    BLOCK = "block"
    COMMENT = "comment"
    UNKNOWN = "unknown"
    INVALID = "invalid"


class AnalysisStatus:
    COMPLETE = "complete"
    INCOMPLETE = "incomplete"
    INVALID = "invalid"
    UNKNOWN = "unknown"


@dataclass
class SymbolReference:
    name: str
    kind: str
    range: SourceRange

    def to_dict(self) -> Dict[str, Any]:
        return {"name": self.name, "kind": self.kind, "range": self.range.to_dict()}


@dataclass
class OperatorInfo:
    operator: str
    range: SourceRange
    depth: int

    def to_dict(self) -> Dict[str, Any]:
        return {"operator": self.operator, "range": self.range.to_dict(), "depth": self.depth}


@dataclass
class Relationship:
    kind: str
    source: str
    target: str
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {"kind": self.kind, "source": self.source, "target": self.target,
                "metadata": dict(sorted(self.metadata.items()))}


@dataclass
class AnalysisEvidence:
    kind: str
    description: str
    range: Optional[SourceRange] = None
    value: str = ""
    related_node: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "kind": self.kind,
            "description": self.description,
            "range": self.range.to_dict() if self.range else None,
            "value": self.value,
            "related_node": self.related_node,
        }
