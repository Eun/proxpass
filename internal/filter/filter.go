// Package filter implements a small JSON-based list-filter language for the
// admin API's list endpoints.
//
// A filter is a URL-encoded JSON object whose keys are field names and whose
// values are operator objects, e.g.
//
//	{"guest_id": {"$eq": "5"}}
//
// Tokenize turns the raw JSON into a flat, singly-linked token list; Walk then
// drives an entity-specific FieldMapper and Combiner to build query objects of
// any type Q. The core here is intentionally database-agnostic -- the SQL
// adapter lives in sql.go. Comparison operators ($eq, $ieq, $contains,
// $icontains, $startswith, $endswith) match a field against a scalar; logical
// operators ($and, $or, $nor, $not) combine conditions on the same field. A
// per-field allow-list in the SQL adapter can restrict which operators actually
// reach the database.
package filter

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Comparison and logical operator keys, as written in the JSON filter.
const (
	OpEq         = "$eq"
	OpIeq        = "$ieq"
	OpContains   = "$contains"
	OpIContains  = "$icontains"
	OpStartsWith = "$startswith"
	OpEndsWith   = "$endswith"

	OpAnd = "$and"
	OpOr  = "$or"
	OpNor = "$nor"
	OpNot = "$not"
)

// TokenKind classifies what a token represents in the filter expression.
type TokenKind int

const (
	TokenField    TokenKind = iota // a field name, e.g. "guest_id"
	TokenOperator                  // an operator, e.g. "$eq", "$or"
	TokenValue                     // a scalar value
	TokenArray                     // an array of sub-expression token lists (for $or/$and/$nor)
	TokenObject                    // a nested operator object (for $not)
)

// Token is one node in the singly-linked token list produced by Tokenize.
type Token struct {
	Kind TokenKind
	Key  string // for TokenField and TokenOperator: the key string
	// Value holds:
	//   - TokenValue  -> the scalar (string, float64, bool, nil) from JSON
	//   - TokenArray  -> []*TokenList  (sub-expression lists)
	//   - TokenObject -> *TokenList    (single sub-expression list)
	Value any
	Next  *Token
}

// TokenList is the head/tail of a singly-linked token list.
type TokenList struct {
	Head *Token
	Tail *Token
}

func (tl *TokenList) append(t *Token) {
	if tl.Head == nil {
		tl.Head = t
		tl.Tail = t
		return
	}
	tl.Tail.Next = t
	tl.Tail = t
}

// Tokenize parses the raw JSON filter string into a TokenList.
//
// The top-level JSON must be an object:
//
//	{ "field": { "$operator": value, ... }, ... }
//
// A field object may hold multiple operators; each is emitted as a separate
// operator->value pair after the field token (implicit AND over all operators
// for the same field).
func Tokenize(raw string) (*TokenList, error) {
	var root map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &root); err != nil {
		return nil, fmt.Errorf("filter must be a JSON object: %w", err)
	}
	tl := &TokenList{}
	for field, exprRaw := range root {
		tl.append(&Token{Kind: TokenField, Key: field})

		var ops map[string]json.RawMessage
		if err := json.Unmarshal(exprRaw, &ops); err != nil {
			return nil, fmt.Errorf("value for field %q must be an operator object: %w", field, err)
		}
		for op, valRaw := range ops {
			tl.append(&Token{Kind: TokenOperator, Key: op})

			valTok, err := tokenizeValue(op, valRaw)
			if err != nil {
				return nil, fmt.Errorf("parsing value for %q %q: %w", field, op, err)
			}
			tl.append(valTok)
		}
	}
	return tl, nil
}

// tokenizeValue converts a raw JSON value into a Token, using the operator to
// decide the structural shape (scalar, array, nested object).
func tokenizeValue(op string, raw json.RawMessage) (*Token, error) {
	switch strings.ToLower(op) {
	case OpOr, OpAnd, OpNor:
		return tokenizeLogicalArray(op, raw)
	case OpNot:
		return tokenizeNotObject(raw)
	default:
		return tokenizeScalar(op, raw)
	}
}

// tokenizeLogicalArray handles $or / $and / $nor: value must be an array of
// operator objects.
func tokenizeLogicalArray(op string, raw json.RawMessage) (*Token, error) {
	var arr []json.RawMessage
	if err := json.Unmarshal(raw, &arr); err != nil {
		return nil, fmt.Errorf("value for %q must be a JSON array: %w", op, err)
	}
	subLists := make([]*TokenList, 0, len(arr))
	for i, item := range arr {
		var ops map[string]json.RawMessage
		if err := json.Unmarshal(item, &ops); err != nil {
			return nil, fmt.Errorf("%q array element %d must be an operator object: %w", op, i, err)
		}
		subList := &TokenList{}
		for subOp, subValRaw := range ops {
			subList.append(&Token{Kind: TokenOperator, Key: subOp})
			subValTok, err := tokenizeValue(subOp, subValRaw)
			if err != nil {
				return nil, fmt.Errorf("parsing sub-value for %q: %w", subOp, err)
			}
			subList.append(subValTok)
		}
		subLists = append(subLists, subList)
	}
	return &Token{Kind: TokenArray, Key: op, Value: subLists}, nil
}

// tokenizeNotObject handles $not: value must be a single operator object.
func tokenizeNotObject(raw json.RawMessage) (*Token, error) {
	var ops map[string]json.RawMessage
	if err := json.Unmarshal(raw, &ops); err != nil {
		return nil, fmt.Errorf("value for $not must be an operator object: %w", err)
	}
	subList := &TokenList{}
	for subOp, subValRaw := range ops {
		subList.append(&Token{Kind: TokenOperator, Key: subOp})
		subValTok, err := tokenizeValue(subOp, subValRaw)
		if err != nil {
			return nil, fmt.Errorf("parsing $not/%q value: %w", subOp, err)
		}
		subList.append(subValTok)
	}
	return &Token{Kind: TokenObject, Key: OpNot, Value: subList}, nil
}

// tokenizeScalar handles all non-logical operators: value must be a scalar.
func tokenizeScalar(op string, raw json.RawMessage) (*Token, error) {
	var scalar any
	if err := json.Unmarshal(raw, &scalar); err != nil {
		return nil, fmt.Errorf("cannot parse scalar value for %q: %w", op, err)
	}
	return &Token{Kind: TokenValue, Value: scalar}, nil
}

// FieldMapper converts a single scalar (field, operator, value) leaf into an
// entity-specific query object Q. It is called only for comparison operators,
// never for logical operators.
type FieldMapper[Q any] func(field, op string, value any) (Q, error)

// Combiner provides entity-specific logical combining of query objects.
type Combiner[Q any] interface {
	Or(queries []Q) Q
	And(queries []Q) Q
	Nor(queries []Q) Q
	Not(query Q) Q
}

// Walk traverses the TokenList produced by Tokenize and builds a slice of
// entity-specific query objects. The resulting slice represents an implicit
// top-level AND (all conditions must hold).
func Walk[Q any](tl *TokenList, mapper FieldMapper[Q], combiner Combiner[Q]) ([]Q, error) {
	var queries []Q

	cur := tl.Head
	for cur != nil {
		if cur.Kind != TokenField {
			return nil, fmt.Errorf("expected field token, got kind %d (key=%q)", cur.Kind, cur.Key)
		}
		field := cur.Key

		var fieldQueries []Q
		cur = cur.Next
		for cur != nil && cur.Kind == TokenOperator {
			opTok := cur
			valTok := opTok.Next
			if valTok == nil {
				return nil, fmt.Errorf("expected value token after operator %q on field %q", opTok.Key, field)
			}

			q, err := walkQuery(field, opTok, valTok, mapper, combiner)
			if err != nil {
				return nil, fmt.Errorf("building query for field %q operator %q: %w", field, opTok.Key, err)
			}
			fieldQueries = append(fieldQueries, q)

			cur = valTok.Next
		}

		if len(fieldQueries) == 0 {
			return nil, fmt.Errorf("field %q has no operator tokens", field)
		}

		if len(fieldQueries) == 1 {
			queries = append(queries, fieldQueries[0])
		} else {
			queries = append(queries, combiner.And(fieldQueries))
		}
	}

	return queries, nil
}

// walkQuery converts a single (field, operator-token, value-token) triplet into Q.
func walkQuery[Q any](field string, opTok, valTok *Token, mapper FieldMapper[Q], combiner Combiner[Q]) (Q, error) {
	op := strings.ToLower(opTok.Key)

	switch op {
	case OpOr:
		return walkLogical(field, valTok, mapper, combiner, combiner.Or)
	case OpAnd:
		return walkLogical(field, valTok, mapper, combiner, combiner.And)
	case OpNor:
		return walkLogical(field, valTok, mapper, combiner, combiner.Nor)
	case OpNot:
		return walkNot(field, valTok, mapper, combiner)
	default:
		if valTok.Kind != TokenValue {
			var zero Q
			return zero, fmt.Errorf("operator %q requires a scalar value token, got kind %d", opTok.Key, valTok.Kind)
		}
		return mapper(field, opTok.Key, valTok.Value)
	}
}

func walkLogical[Q any](
	field string,
	valTok *Token,
	mapper FieldMapper[Q],
	combiner Combiner[Q],
	combine func([]Q) Q,
) (Q, error) {
	var zero Q
	if valTok.Kind != TokenArray {
		return zero, errors.New("logical operator requires an array value token")
	}
	subLists, ok := valTok.Value.([]*TokenList)
	if !ok {
		return zero, errors.New("logical operator value is not a []*TokenList")
	}

	inner := make([]Q, 0, len(subLists))
	for _, subList := range subLists {
		subQ, err := walkSubList(field, subList, mapper, combiner)
		if err != nil {
			return zero, fmt.Errorf("building logical sub-query: %w", err)
		}
		inner = append(inner, subQ)
	}

	return combine(inner), nil
}

func walkNot[Q any](field string, valTok *Token, mapper FieldMapper[Q], combiner Combiner[Q]) (Q, error) {
	var zero Q
	if valTok.Kind != TokenObject {
		return zero, errors.New("$not requires a nested operator object value")
	}
	subList, ok := valTok.Value.(*TokenList)
	if !ok {
		return zero, errors.New("$not value is not a *TokenList")
	}
	inner, err := walkSubList(field, subList, mapper, combiner)
	if err != nil {
		return zero, fmt.Errorf("building $not inner query: %w", err)
	}
	return combiner.Not(inner), nil
}

func walkSubList[Q any](field string, subList *TokenList, mapper FieldMapper[Q], combiner Combiner[Q]) (Q, error) {
	var zero Q
	var subQueries []Q

	cur := subList.Head
	for cur != nil {
		if cur.Kind != TokenOperator {
			return zero, fmt.Errorf("sub-expression token must be an operator, got kind %d", cur.Kind)
		}
		subOpTok := cur
		subValTok := subOpTok.Next
		if subValTok == nil {
			return zero, fmt.Errorf("sub-expression operator %q is missing a value token", subOpTok.Key)
		}
		sq, err := walkQuery(field, subOpTok, subValTok, mapper, combiner)
		if err != nil {
			return zero, err
		}
		subQueries = append(subQueries, sq)
		cur = subValTok.Next
	}

	if len(subQueries) == 0 {
		return zero, fmt.Errorf("sub-expression for field %q is empty", field)
	}
	if len(subQueries) == 1 {
		return subQueries[0], nil
	}
	return combiner.And(subQueries), nil
}
