from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

import yaml


@dataclass(frozen=True)
class SigmaMatch:
    rule_id: str
    rule_title: str
    level: str
    description: str
    tags: List[str]
    rule_path: str


@dataclass(frozen=True)
class SigmaRule:
    rule_id: str
    title: str
    description: str
    level: str
    tags: List[str]
    logsource: Dict[str, Any]
    detection: Dict[str, Any]
    path: str


class SigmaConditionError(ValueError):
    pass


class SigmaEngine:

    def __init__(
        self,
        rules_dir: str | Path,
        enabled: bool = True,
    ) -> None:
        self.rules_dir = Path(rules_dir)
        self.enabled = enabled
        self.rules: List[SigmaRule] = []
        self.load_rules()

    def load_rules(self) -> None:
        self.rules.clear()

        if not self.enabled:
            return

        if not self.rules_dir.exists():
            return

        for path in sorted(self.rules_dir.rglob("*.yml")):
            rule = self._load_rule(path)
            if rule is not None:
                self.rules.append(rule)

        for path in sorted(self.rules_dir.rglob("*.yaml")):
            rule = self._load_rule(path)
            if rule is not None:
                self.rules.append(rule)

    def evaluate(self, ecs_doc: Dict[str, Any]) -> Dict[str, Any]:
        if not self.enabled:
            self._set_no_match(ecs_doc, reason="sigma engine disabled")
            return ecs_doc

        flat_doc = self.flatten(ecs_doc)
        matches = [
            self._build_match(rule)
            for rule in self.rules
            if self._rule_matches(rule, flat_doc)
        ]

        if not matches:
            self._set_no_match(ecs_doc)
            return ecs_doc

        ecs_doc.setdefault("event", {})
        ecs_doc["event"]["kind"] = "alert"

        first_match = matches[0]

        ecs_doc["rule"] = {
            "id": first_match.rule_id,
            "name": first_match.rule_title,
            "level": first_match.level,
            "ruleset": "local-sigma",
        }

        ecs_doc.setdefault("edr", {})
        ecs_doc["edr"]["detection"] = {
            "matched": True,
            "engine": "sigma_edge",
            "ruleset": "local-sigma",
            "rule_id": first_match.rule_id,
            "rule_title": first_match.rule_title,
            "severity": first_match.level,
            "matches": [
                {
                    "rule_id": match.rule_id,
                    "rule_title": match.rule_title,
                    "level": match.level,
                    "description": match.description,
                    "tags": match.tags,
                    "rule_path": match.rule_path,
                }
                for match in matches
            ],
        }

        return ecs_doc

    def flatten(self, value: Dict[str, Any]) -> Dict[str, Any]:
        return self._flatten(value)

    def _load_rule(self, path: Path) -> Optional[SigmaRule]:
        try:
            with path.open("r", encoding="utf-8") as file:
                raw = yaml.safe_load(file)
        except Exception:
            return None

        if not isinstance(raw, dict):
            return None

        detection = raw.get("detection")
        if not isinstance(detection, dict):
            return None

        condition = detection.get("condition")
        if not isinstance(condition, str) or not condition.strip():
            return None

        tags = raw.get("tags", [])
        if isinstance(tags, str):
            tags = [tags]
        elif not isinstance(tags, list):
            tags = []

        return SigmaRule(
            rule_id=str(raw.get("id") or path.stem),
            title=str(raw.get("title") or path.stem),
            description=str(raw.get("description") or ""),
            level=str(raw.get("level") or "informational"),
            tags=[str(tag) for tag in tags],
            logsource=raw.get("logsource") if isinstance(raw.get("logsource"), dict) else {},
            detection=detection,
            path=str(path),
        )

    def _rule_matches(self, rule: SigmaRule, flat_doc: Dict[str, Any]) -> bool:
        selection_results: Dict[str, bool] = {}

        for name, selection in rule.detection.items():
            if name == "condition":
                continue
            selection_results[name] = self._selection_matches(selection, flat_doc)

        try:
            return self._evaluate_condition(
                condition=str(rule.detection["condition"]),
                selection_results=selection_results,
            )
        except SigmaConditionError:
            return False

    def _selection_matches(self, selection: Any, flat_doc: Dict[str, Any]) -> bool:
        if isinstance(selection, list):
            return any(self._selection_matches(item, flat_doc) for item in selection)

        if not isinstance(selection, dict):
            return False

        for field_expr, expected in selection.items():
            field_name, modifiers = self._parse_field_expression(str(field_expr))
            actual = flat_doc.get(field_name)

            if not self._field_matches(actual=actual, expected=expected, modifiers=modifiers):
                return False

        return True

    def _field_matches(self, actual: Any, expected: Any, modifiers: Sequence[str]) -> bool:
        if actual is None:
            return False

        expected_values = self._as_list(expected)
        match_all = "all" in modifiers
        effective_modifiers = [modifier for modifier in modifiers if modifier != "all"]

        if match_all:
            return all(
                self._single_value_matches(actual=actual, expected=item, modifiers=effective_modifiers)
                for item in expected_values
            )

        return any(
            self._single_value_matches(actual=actual, expected=item, modifiers=effective_modifiers)
            for item in expected_values
        )

    def _single_value_matches(
        self,
        actual: Any,
        expected: Any,
        modifiers: Sequence[str],
    ) -> bool:
        actual_values = self._as_list(actual)
        operator = self._operator_from_modifiers(modifiers)

        return any(
            self._compare(
                actual=str(actual_value),
                expected=str(expected),
                operator=operator,
            )
            for actual_value in actual_values
            if actual_value is not None
        )

    def _compare(self, actual: str, expected: str, operator: str) -> bool:
        actual_cmp = actual.lower()
        expected_cmp = expected.lower()

        if operator == "equals":
            return actual_cmp == expected_cmp

        if operator == "contains":
            return expected_cmp in actual_cmp

        if operator == "startswith":
            return actual_cmp.startswith(expected_cmp)

        if operator == "endswith":
            return actual_cmp.endswith(expected_cmp)

        if operator == "re":
            try:
                return re.search(expected, actual, flags=re.IGNORECASE) is not None
            except re.error:
                return False

        return False

    def _operator_from_modifiers(self, modifiers: Sequence[str]) -> str:
        for candidate in ("contains", "startswith", "endswith", "re"):
            if candidate in modifiers:
                return candidate
        return "equals"

    def _parse_field_expression(self, field_expr: str) -> Tuple[str, List[str]]:
        parts = [part.strip() for part in field_expr.split("|") if part.strip()]
        if not parts:
            return field_expr, []

        return parts[0], parts[1:]

    def _evaluate_condition(
        self,
        condition: str,
        selection_results: Dict[str, bool],
    ) -> bool:
        tokens = self._tokenize_condition(condition)
        parser = _ConditionParser(
            tokens=tokens,
            selection_results=selection_results,
        )
        return parser.parse()

    def _tokenize_condition(self, condition: str) -> List[str]:
        normalized = condition.replace("(", " ( ").replace(")", " ) ")
        return [token for token in normalized.split() if token]

    def _set_no_match(self, ecs_doc: Dict[str, Any], reason: Optional[str] = None) -> None:
        ecs_doc.setdefault("edr", {})
        ecs_doc["edr"]["detection"] = {
            "matched": False,
            "engine": "sigma_edge",
            "ruleset": "local-sigma",
        }

        if reason:
            ecs_doc["edr"]["detection"]["reason"] = reason

    def _build_match(self, rule: SigmaRule) -> SigmaMatch:
        return SigmaMatch(
            rule_id=rule.rule_id,
            rule_title=rule.title,
            level=rule.level,
            description=rule.description,
            tags=rule.tags,
            rule_path=rule.path,
        )

    def _flatten(self, value: Any, prefix: str = "") -> Dict[str, Any]:
        if not isinstance(value, dict):
            return {}

        flat: Dict[str, Any] = {}

        for key, item in value.items():
            full_key = f"{prefix}.{key}" if prefix else str(key)

            if isinstance(item, dict):
                flat.update(self._flatten(item, full_key))
            else:
                flat[full_key] = item

        return flat

    def _as_list(self, value: Any) -> List[Any]:
        if isinstance(value, list):
            return value
        return [value]


class _ConditionParser:
    def __init__(self, tokens: Sequence[str], selection_results: Dict[str, bool]) -> None:
        self.tokens = list(tokens)
        self.selection_results = selection_results
        self.index = 0

    def parse(self) -> bool:
        if not self.tokens:
            raise SigmaConditionError("empty condition")

        result = self._parse_or()

        if self.index != len(self.tokens):
            raise SigmaConditionError("unexpected tokens at end")

        return result

    def _parse_or(self) -> bool:
        result = self._parse_and()

        while self._peek_lower() == "or":
            self._consume()
            result = result or self._parse_and()

        return result

    def _parse_and(self) -> bool:
        result = self._parse_not()

        while self._peek_lower() == "and":
            self._consume()
            result = result and self._parse_not()

        return result

    def _parse_not(self) -> bool:
        if self._peek_lower() == "not":
            self._consume()
            return not self._parse_not()

        return self._parse_primary()

    def _parse_primary(self) -> bool:
        token = self._peek()

        if token is None:
            raise SigmaConditionError("unexpected end of condition")

        if token == "(":
            self._consume()
            result = self._parse_or()
            self._expect(")")
            return result

        if token.lower() in {"1", "all"} and self._peek_offset_lower(1) == "of":
            quantifier = self._consume().lower()
            self._consume()  # of
            pattern = self._consume()
            return self._evaluate_of_expression(quantifier, pattern)

        self._consume()
        return bool(self.selection_results.get(token, False))

    def _evaluate_of_expression(self, quantifier: str, pattern: str) -> bool:
        matched_names = [
            name
            for name in self.selection_results
            if fnmatch.fnmatch(name, pattern)
        ]

        if not matched_names:
            return False

        if quantifier == "all":
            return all(self.selection_results[name] for name in matched_names)

        return any(self.selection_results[name] for name in matched_names)

    def _expect(self, expected: str) -> None:
        token = self._consume()
        if token != expected:
            raise SigmaConditionError(f"expected {expected}")

    def _peek(self) -> Optional[str]:
        if self.index >= len(self.tokens):
            return None
        return self.tokens[self.index]

    def _peek_lower(self) -> Optional[str]:
        token = self._peek()
        return token.lower() if token is not None else None

    def _peek_offset_lower(self, offset: int) -> Optional[str]:
        position = self.index + offset
        if position >= len(self.tokens):
            return None
        return self.tokens[position].lower()

    def _consume(self) -> str:
        token = self._peek()
        if token is None:
            raise SigmaConditionError("unexpected end of condition")
        self.index += 1
        return token
